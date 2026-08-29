use std::ops::Range;

use stream_server::transcoding::{SourceActivitySnapshot, SourceProtocolPolicy};

#[test]
fn source_activity_snapshot_starts_monotonic_and_unblocked() {
    let snapshot = SourceActivitySnapshot::default();

    assert_eq!(snapshot.sequence, 0);
    assert_eq!(snapshot.delivered_bytes_total, 0);
    assert_eq!(snapshot.active_requests, 0);
    assert!(snapshot.waiting_for_pieces.is_empty());
    assert!(!snapshot.all_active_requests_piece_blocked);
}

#[test]
fn source_protocol_policies_are_closed_and_source_specific() {
    assert_eq!(
        SourceProtocolPolicy::CompletedFile.ffmpeg_allowlist(),
        "file,pipe"
    );
    assert_eq!(
        SourceProtocolPolicy::SyntheticFixture.ffmpeg_allowlist(),
        "file,pipe"
    );
    assert_eq!(
        SourceProtocolPolicy::EngineLoopback.ffmpeg_allowlist(),
        "http,tcp"
    );
    assert_eq!(
        SourceProtocolPolicy::ApprovedRemote.ffmpeg_allowlist(),
        "http,tcp"
    );
}

#[test]
fn activity_snapshot_keeps_exact_half_open_ranges() {
    let range: Range<u64> = 16..32;
    let snapshot = SourceActivitySnapshot {
        sequence: 7,
        delivered_bytes_total: 16,
        active_requests: 1,
        waiting_for_pieces: vec![range.clone()],
        all_active_requests_piece_blocked: true,
    };

    assert_eq!(snapshot.waiting_for_pieces, vec![range]);
}
