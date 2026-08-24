use enginefs::hls::{HlsEngine, ProbeResult};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct CountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn start_counting() {
    COUNTING.store(false, Ordering::SeqCst);
    ALLOCATIONS.store(0, Ordering::SeqCst);
    REALLOCATIONS.store(0, Ordering::SeqCst);
    COUNTING.store(true, Ordering::SeqCst);
}

fn stop_counting() -> (usize, usize) {
    COUNTING.store(false, Ordering::SeqCst);
    (
        ALLOCATIONS.load(Ordering::SeqCst),
        REALLOCATIONS.load(Ordering::SeqCst),
    )
}

#[test]
fn two_hour_playlist_avoids_per_segment_temporary_allocations() {
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
