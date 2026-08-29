use enginefs::hls::{HlsEngine, ProbeResult};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn is_counting() -> bool {
    COUNTING
        .try_with(|counting| counting.get())
        .unwrap_or(false)
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if is_counting() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if is_counting() {
            REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn start_counting() {
    COUNTING.with(|counting| counting.set(false));
    ALLOCATIONS.store(0, Ordering::SeqCst);
    REALLOCATIONS.store(0, Ordering::SeqCst);
    COUNTING.with(|counting| counting.set(true));
}

fn stop_counting() -> (usize, usize) {
    COUNTING.with(|counting| counting.set(false));
    (
        ALLOCATIONS.load(Ordering::SeqCst),
        REALLOCATIONS.load(Ordering::SeqCst),
    )
}

#[test]
fn two_hour_playlist_avoids_per_segment_temporary_allocations() {
    let allocation_started = Arc::new(Barrier::new(2));
    let allocation_finished = Arc::new(Barrier::new(2));
    let worker = {
        let allocation_started = Arc::clone(&allocation_started);
        let allocation_finished = Arc::clone(&allocation_finished);
        std::thread::spawn(move || {
            allocation_started.wait();
            let unrelated = Box::new([0_u8; 1_024]);
            std::hint::black_box(&unrelated);
            allocation_finished.wait();
        })
    };

    start_counting();
    allocation_started.wait();
    allocation_finished.wait();
    let unrelated_counts = stop_counting();
    worker.join().expect("allocation worker must finish");
    assert_eq!(
        unrelated_counts,
        (0, 0),
        "allocator measurements must ignore unrelated test-harness threads"
    );

    let probe = ProbeResult {
        duration: 7_200.0,
        container: "test".to_string(),
        streams: Vec::new(),
    };
    let query = format!("q={}", "x".repeat(126));
    assert_eq!(query.len(), 128);

    drop(HlsEngine::get_stream_playlist(
        &probe, 0, "./", None, &query,
    ));

    start_counting();
    let segments = HlsEngine::get_segments(probe.duration);
    let (segment_allocations, segment_reallocations) = stop_counting();
    assert_eq!(segments.len(), 1_800);
    drop(segments);

    start_counting();
    let playlist = HlsEngine::get_stream_playlist(&probe, 0, "./", None, &query);
    let (allocations, reallocations) = stop_counting();

    assert_eq!(playlist.len(), 281_603);
    assert!(
        allocations <= segment_allocations.saturating_add(1),
        "expected only the segment vector and final string allocations, got {allocations} versus {segment_allocations} for segments alone"
    );
    assert!(
        reallocations <= segment_reallocations,
        "expected no final-string growth, got {reallocations} reallocations versus {segment_reallocations} for segments alone"
    );
}
