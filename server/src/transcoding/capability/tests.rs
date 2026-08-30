use super::key::{
    BitDepth, CapabilityDirection, CapabilityKey, CodecLevel, InputVideoSignature,
    KeyValidationError, OutputVideoSignature, PrivateSourceDigest, SegmentationContract,
    test_common, test_input, test_output, test_requirements,
};
use super::state::{
    EvidenceOutcome, EvidenceReason, EvidenceRecord, EvidenceTarget, EvidenceTimestamp,
    ProjectionContext, StateError, StateNow, VerificationMode, VerificationResult, WorkState,
};
use super::storage::{
    SeedStorageError, SeedStorageEvent, load_or_create_device_seed,
    load_or_create_device_seed_with_observer,
};
use crate::transcoding::{
    CapabilityState, ChromaSubsampling, FrameRateClass, InputVideoCodec, KeyframeStrategy,
    OutputVideoCodec, PixelFormat, RationalRate, VideoProfile,
};
use std::{
    collections::HashSet,
    fs,
    num::NonZeroU32,
    sync::{Arc, Barrier, Mutex},
};
use tokio_util::sync::CancellationToken;

static_assertions::assert_not_impl_any!(CapabilityKey: serde::Serialize);
static_assertions::assert_not_impl_any!(PrivateSourceDigest: serde::Serialize);

fn new_config_directory() -> tempfile::TempDir {
    tempfile::tempdir().expect("isolated config directory")
}

#[test]
fn every_capability_key_field_is_identity_bearing() {
    let keys = CapabilityKey::complete_test_keys();
    assert_eq!(keys.len(), 5);
    assert_eq!(keys[0].direction(), CapabilityDirection::Decode);
    for key in keys {
        let evidence = HashSet::from([key.clone()]);
        for mutation in key.all_identity_mutations_for_test() {
            assert_ne!(mutation, key);
            assert!(!evidence.contains(&mutation));
        }
    }
}

#[test]
fn capability_key_buckets_are_finite_bounded_and_direction_validated() {
    use super::key::{
        BitDepth, BoundaryAlgorithmVersion, CodecLevel, FrameRateBucket, HdrMode,
        KeyValidationError, OutputContainerContract, RequiredFilter, RequiredTransfer,
        RequiredTransform,
    };
    use crate::transcoding::RationalRate;

    let all_levels = [
        CodecLevel::L20,
        CodecLevel::L21,
        CodecLevel::L30,
        CodecLevel::L31,
        CodecLevel::L40,
        CodecLevel::L41,
        CodecLevel::L42,
        CodecLevel::L50,
        CodecLevel::L51,
        CodecLevel::L52,
        CodecLevel::L60,
        CodecLevel::L61,
        CodecLevel::L62,
        CodecLevel::Mpeg2Low,
        CodecLevel::Mpeg2Main,
        CodecLevel::Mpeg2High1440,
        CodecLevel::Mpeg2High,
        CodecLevel::Vc1Low,
        CodecLevel::Vc1Medium,
        CodecLevel::Vc1High,
    ];
    assert_eq!(all_levels.len(), 20);
    assert_eq!([BitDepth::Eight, BitDepth::Ten, BitDepth::Twelve].len(), 3);
    assert_eq!(
        [
            HdrMode::Sdr,
            HdrMode::Hdr10,
            HdrMode::Hlg,
            HdrMode::DolbyVision
        ]
        .len(),
        4
    );
    assert_eq!(
        [
            RequiredTransform::Scale,
            RequiredTransform::Deinterlace,
            RequiredTransform::Rotate90,
            RequiredTransform::Rotate180,
            RequiredTransform::Rotate270,
            RequiredTransform::ToneMap,
            RequiredTransform::SubtitleBurnIn,
            RequiredTransform::PixelFormat,
        ]
        .len(),
        8
    );
    assert_eq!(
        [
            RequiredTransfer::Upload,
            RequiredTransfer::Download,
            RequiredTransfer::HardwareMap,
        ]
        .len(),
        3
    );
    assert_eq!(
        [
            RequiredFilter::Format,
            RequiredFilter::Scale,
            RequiredFilter::Deinterlace,
            RequiredFilter::ToneMap,
            RequiredFilter::Subtitles,
            RequiredFilter::HardwareUpload,
            RequiredFilter::HardwareDownload,
            RequiredFilter::HardwareMap,
        ]
        .len(),
        8
    );
    assert_eq!(
        [
            OutputContainerContract::MpegTsHls,
            OutputContainerContract::Fmp4Hls,
            OutputContainerContract::MpegTsStream,
            OutputContainerContract::Matroska,
            OutputContainerContract::MovMp4,
        ]
        .len(),
        5
    );
    assert_ne!(BoundaryAlgorithmVersion::V1, BoundaryAlgorithmVersion::V2);

    let expected = [
        FrameRateBucket::UpTo24,
        FrameRateBucket::UpTo25,
        FrameRateBucket::UpTo30,
        FrameRateBucket::UpTo50,
        FrameRateBucket::UpTo60,
        FrameRateBucket::UpTo120,
        FrameRateBucket::UpTo144,
        FrameRateBucket::UpTo240,
    ];
    for (rate, bucket) in [24_u32, 25, 30, 50, 60, 120, 144, 240]
        .into_iter()
        .zip(expected)
    {
        let rate = RationalRate::new(rate, NonZeroU32::new(1).unwrap()).unwrap();
        assert_eq!(FrameRateBucket::from_rate(rate), Ok(bucket));
    }
    let too_fast = RationalRate::new(241, NonZeroU32::new(1).unwrap()).unwrap();
    assert_eq!(
        FrameRateBucket::from_rate(too_fast),
        Err(KeyValidationError::UnsupportedFrameRate)
    );
}

#[test]
fn capability_key_constructors_reject_mismatched_signatures_and_keep_required_distinctions() {
    let input = test_input();
    assert_eq!(
        InputVideoSignature::new(
            input.codec,
            input.profile,
            input.level,
            PixelFormat::Yuv420p10le,
            BitDepth::Ten,
            ChromaSubsampling::Cs420,
            input.color,
            input.field_order,
            input.resolution,
            input.frame_rate,
            input.frame_rate_class,
        ),
        Err(KeyValidationError::NonFiniteSignature)
    );
    assert!(
        InputVideoSignature::new(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            CodecLevel::L51,
            PixelFormat::Yuv444p12le,
            BitDepth::Twelve,
            ChromaSubsampling::Cs444,
            input.color,
            input.field_order,
            input.resolution,
            input.frame_rate,
            input.frame_rate_class,
        )
        .is_ok()
    );
    assert_eq!(
        InputVideoSignature::new(
            InputVideoCodec::Mpeg2,
            VideoProfile::Mpeg2Main,
            CodecLevel::L41,
            PixelFormat::Yuv420p,
            BitDepth::Eight,
            ChromaSubsampling::Cs420,
            input.color,
            input.field_order,
            input.resolution,
            input.frame_rate,
            input.frame_rate_class,
        ),
        Err(KeyValidationError::NonFiniteSignature)
    );

    let output = test_output();
    assert_eq!(
        OutputVideoSignature::new(
            OutputVideoCodec::Hevc,
            VideoProfile::HevcMain10,
            output.level,
            PixelFormat::Yuv420p,
            BitDepth::Eight,
            ChromaSubsampling::Cs420,
            output.color,
            output.resolution,
            output.frame_rate,
            output.frame_rate_class,
        ),
        Err(KeyValidationError::NonFiniteSignature)
    );

    let (runtime, device, driver, backend) = test_common();
    assert_eq!(
        CapabilityKey::decode(
            runtime,
            device,
            driver,
            backend,
            input,
            test_requirements(true),
        ),
        Err(KeyValidationError::InvalidDirectionFields)
    );
    assert!(
        SegmentationContract::new(
            RationalRate::new(24_000, NonZeroU32::new(1001).unwrap()).unwrap(),
            FrameRateClass::Unknown,
            NonZeroU32::new(4_000).unwrap(),
            RationalRate::new(1, NonZeroU32::new(90_000).unwrap()).unwrap(),
            KeyframeStrategy::TimeForced {
                segment_duration_ms: NonZeroU32::new(4_000).unwrap(),
            },
        )
        .is_ok()
    );

    let ordered = CapabilityKey::complete_test_keys()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ordered.len(), 5);
    let debug = format!("{:?}", ordered.last().unwrap());
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains(&"66".repeat(32)));
    assert!(!debug.contains(&"77".repeat(32)));
}

#[test]
fn codec_depth_and_chroma_signatures_never_alias() {
    let base = test_input();
    let make = |codec, profile, pixel_format, bit_depth, chroma| {
        InputVideoSignature::new(
            codec,
            profile,
            CodecLevel::L51,
            pixel_format,
            bit_depth,
            chroma,
            base.color,
            base.field_order,
            base.resolution,
            base.frame_rate,
            base.frame_rate_class,
        )
        .unwrap()
    };
    let signatures = [
        make(
            InputVideoCodec::H264,
            VideoProfile::H264High,
            PixelFormat::Yuv420p,
            BitDepth::Eight,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::H264,
            VideoProfile::H264High10,
            PixelFormat::Yuv420p10le,
            BitDepth::Ten,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::Hevc,
            VideoProfile::HevcMain,
            PixelFormat::Yuv420p,
            BitDepth::Eight,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::Hevc,
            VideoProfile::HevcMain10,
            PixelFormat::Yuv420p10le,
            BitDepth::Ten,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            PixelFormat::Yuv420p,
            BitDepth::Eight,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            PixelFormat::Yuv420p10le,
            BitDepth::Ten,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            PixelFormat::Yuv420p12le,
            BitDepth::Twelve,
            ChromaSubsampling::Cs420,
        ),
    ];
    assert_eq!(
        signatures
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        7
    );

    let chroma = [
        make(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            PixelFormat::Yuv420p12le,
            BitDepth::Twelve,
            ChromaSubsampling::Cs420,
        ),
        make(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            PixelFormat::Yuv422p12le,
            BitDepth::Twelve,
            ChromaSubsampling::Cs422,
        ),
        make(
            InputVideoCodec::Av1,
            VideoProfile::Av1Main,
            PixelFormat::Yuv444p12le,
            BitDepth::Twelve,
            ChromaSubsampling::Cs444,
        ),
    ];
    assert_eq!(
        chroma
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
}

fn state_now(minutes: u64) -> StateNow {
    StateNow::from_test_minutes(minutes)
}

fn verification(
    target: EvidenceTarget,
    outcome: EvidenceOutcome,
    minute: u64,
) -> VerificationResult {
    let reason = match outcome {
        EvidenceOutcome::NotPresent => EvidenceReason::VerificationNotImplemented,
        EvidenceOutcome::Unsupported => EvidenceReason::Unsupported,
        EvidenceOutcome::PermanentFailure => EvidenceReason::PermanentFailure,
        _ => EvidenceReason::VerificationFailed,
    };
    VerificationResult::for_test(target, outcome, reason, minute)
}

#[test]
fn evidence_state_transition_table_is_fail_closed_and_dependency_aware() {
    let key = CapabilityKey::complete_test_keys().remove(3);
    let mut record = EvidenceRecord::new(key);
    let absent = ProjectionContext::new(false, false);
    let listed = ProjectionContext::new(false, true);

    assert_eq!(record.project(state_now(0), absent), None);
    assert_eq!(
        record.project(state_now(0), listed),
        Some(CapabilityState::Listed)
    );
    assert_eq!(
        record.apply(
            verification(EvidenceTarget::Realtime, EvidenceOutcome::RealtimePassed, 1),
            VerificationMode::Active,
            state_now(1),
        ),
        Err(StateError::MissingCorrectness)
    );
    assert_eq!(
        record.apply(
            verification(
                EvidenceTarget::Segmented,
                EvidenceOutcome::CorrectnessPassed,
                1,
            ),
            VerificationMode::Active,
            state_now(1),
        ),
        Err(StateError::MissingCorrectness)
    );

    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::CorrectnessPassed,
                2,
            ),
            VerificationMode::Active,
            state_now(2),
        )
        .unwrap();
    record
        .apply(
            verification(EvidenceTarget::Realtime, EvidenceOutcome::RealtimePassed, 3),
            VerificationMode::Active,
            state_now(3),
        )
        .unwrap();
    record
        .apply(
            verification(
                EvidenceTarget::Segmented,
                EvidenceOutcome::CorrectnessPassed,
                4,
            ),
            VerificationMode::Active,
            state_now(4),
        )
        .unwrap();
    assert_eq!(
        record.project(state_now(4), absent),
        Some(CapabilityState::RealtimeQualified)
    );

    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::TemporaryFailure,
                5,
            ),
            VerificationMode::Active,
            state_now(5),
        )
        .unwrap();
    assert_eq!(
        record.project(state_now(6), absent),
        Some(CapabilityState::CircuitOpen)
    );
    assert_eq!(record.failure_streak_for_test(), Some(1));
    assert_eq!(record.cooldown_minutes_for_test(state_now(5)), Some(10));
    record.clear_cooldown_after_refresh(state_now(6));
    assert_eq!(record.failure_streak_for_test(), Some(1));
    assert_eq!(
        record.project(state_now(6), absent),
        Some(CapabilityState::RealtimeQualified)
    );

    for (minute, streak, cooldown) in [(7, 2, 20), (8, 3, 40), (9, 4, 60), (10, 4, 60)] {
        record
            .apply(
                verification(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::TemporaryFailure,
                    minute,
                ),
                VerificationMode::Active,
                state_now(minute),
            )
            .unwrap();
        assert_eq!(record.failure_streak_for_test(), Some(streak));
        assert_eq!(
            record.cooldown_minutes_for_test(state_now(minute)),
            Some(cooldown)
        );
        record.clear_cooldown_after_refresh(state_now(minute));
    }

    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::CorrectnessPassed,
                11,
            ),
            VerificationMode::Active,
            state_now(11),
        )
        .unwrap();
    assert_eq!(record.failure_streak_for_test(), None);

    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::Unsupported,
                12,
            ),
            VerificationMode::Active,
            state_now(12),
        )
        .unwrap();
    assert!(!record.has_positive_observations_for_test());
    assert_eq!(
        record.project(state_now(12), listed),
        Some(CapabilityState::Failed)
    );
    assert_eq!(
        record.last_observed_at().unwrap().milliseconds(),
        state_now(12).wall().milliseconds()
    );
    assert_eq!(
        record.project(state_now(12), ProjectionContext::new(true, true)),
        Some(CapabilityState::AdministrativelyDisabled)
    );
}

#[test]
fn evidence_expiry_history_not_present_unknown_and_cancellation_are_exact() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let mut record = EvidenceRecord::new(key);
    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::CorrectnessPassed,
                0,
            ),
            VerificationMode::Active,
            state_now(0),
        )
        .unwrap();
    record
        .apply(
            verification(EvidenceTarget::Realtime, EvidenceOutcome::RealtimePassed, 1),
            VerificationMode::Active,
            state_now(1),
        )
        .unwrap();
    let before = record.clone();
    record
        .apply(
            verification(EvidenceTarget::Correctness, EvidenceOutcome::Cancelled, 2),
            VerificationMode::Active,
            state_now(2),
        )
        .unwrap();
    assert_eq!(record, before);
    record
        .apply(
            verification(EvidenceTarget::Correctness, EvidenceOutcome::NotPresent, 2),
            VerificationMode::Unknown,
            state_now(2),
        )
        .unwrap();
    assert_eq!(record, before);
    assert!(
        record
            .apply(
                verification(EvidenceTarget::Correctness, EvidenceOutcome::NotPresent, 2),
                VerificationMode::Active,
                state_now(2),
            )
            .unwrap()
            .remove_record()
    );

    let mut history = EvidenceRecord::new(CapabilityKey::complete_test_keys().remove(0));
    history
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::TemporaryFailure,
                0,
            ),
            VerificationMode::Active,
            state_now(0),
        )
        .unwrap();
    assert_eq!(history.failure_streak_for_test(), Some(1));
    assert_eq!(
        history.project(state_now(1_441), ProjectionContext::new(false, false)),
        None
    );
    assert_eq!(history.failure_streak_for_test(), None);

    history
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::TemporaryFailure,
                1_441,
            ),
            VerificationMode::Active,
            state_now(1_441),
        )
        .unwrap();
    assert_eq!(history.failure_streak_for_test(), Some(1));
}

#[test]
fn monotonic_expiry_prevents_wall_clock_rollback_from_extending_evidence() {
    let mut record = EvidenceRecord::new(CapabilityKey::complete_test_keys().remove(0));
    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::CorrectnessPassed,
                0,
            ),
            VerificationMode::Active,
            state_now(0),
        )
        .unwrap();
    let before_unknown = record.clone();
    record
        .apply(
            verification(
                EvidenceTarget::Correctness,
                EvidenceOutcome::NotPresent,
                1_441,
            ),
            VerificationMode::Unknown,
            state_now(1_441),
        )
        .unwrap();
    assert_eq!(record, before_unknown);
    assert_eq!(
        record.project(
            StateNow::from_test_times(0, 1_441),
            ProjectionContext::new(false, false),
        ),
        None
    );
}

#[test]
fn bounded_transition_sequences_preserve_record_invariants() {
    let transitions = [
        (
            EvidenceTarget::Correctness,
            EvidenceOutcome::CorrectnessPassed,
        ),
        (EvidenceTarget::Realtime, EvidenceOutcome::RealtimePassed),
        (
            EvidenceTarget::Segmented,
            EvidenceOutcome::CorrectnessPassed,
        ),
        (
            EvidenceTarget::Correctness,
            EvidenceOutcome::TemporaryFailure,
        ),
        (EvidenceTarget::Correctness, EvidenceOutcome::Unsupported),
        (
            EvidenceTarget::Correctness,
            EvidenceOutcome::PermanentFailure,
        ),
        (EvidenceTarget::Correctness, EvidenceOutcome::Cancelled),
    ];
    for first in transitions {
        for second in transitions {
            for third in transitions {
                let mut record = EvidenceRecord::new(CapabilityKey::complete_test_keys().remove(3));
                for (minute, (target, outcome)) in [first, second, third].into_iter().enumerate() {
                    let now = state_now(u64::try_from(minute).unwrap());
                    let _ = record.apply(
                        verification(target, outcome, u64::try_from(minute).unwrap()),
                        VerificationMode::Active,
                        now,
                    );
                    record.prune_expired(now);
                    assert_eq!(record.validate(now), Ok(()));
                }
            }
        }
    }
}

#[test]
fn verification_time_bounds_reject_future_expired_and_overlong_results() {
    let now = state_now(0);
    let future = VerificationResult::new(
        EvidenceTarget::Correctness,
        EvidenceOutcome::CorrectnessPassed,
        None,
        EvidenceTimestamp::new(6 * 60_000).unwrap(),
        1,
        EvidenceTimestamp::new(24 * 60 * 60_000).unwrap(),
    )
    .unwrap();
    let mut record = EvidenceRecord::new(CapabilityKey::complete_test_keys().remove(0));
    assert_eq!(
        record.apply(future, VerificationMode::Active, now),
        Err(StateError::FutureObservation)
    );

    assert_eq!(
        VerificationResult::new(
            EvidenceTarget::Correctness,
            EvidenceOutcome::CorrectnessPassed,
            None,
            EvidenceTimestamp::new(0).unwrap(),
            1,
            EvidenceTimestamp::new(24 * 60 * 60_000 + 1).unwrap(),
        ),
        Err(StateError::Bounds)
    );

    let expired = VerificationResult::new(
        EvidenceTarget::Correctness,
        EvidenceOutcome::CorrectnessPassed,
        None,
        EvidenceTimestamp::new(0).unwrap(),
        1,
        EvidenceTimestamp::new(60_000).unwrap(),
    )
    .unwrap();
    assert_eq!(
        record.apply(expired, VerificationMode::Active, state_now(2)),
        Err(StateError::ExpiredResult)
    );
}

#[test]
fn work_state_never_projects_external_success_and_records_reject_impossible_shapes() {
    for work in [WorkState::Absent, WorkState::Queued, WorkState::Verifying] {
        assert_eq!(work.external_state(), None);
    }
    assert_eq!(
        EvidenceRecord::impossible_for_test(),
        Err(StateError::ImpossibleState)
    );
    assert_ne!(
        EvidenceReason::VerificationTimeout,
        EvidenceReason::VerificationFailed
    );
    assert_ne!(
        EvidenceOutcome::PermanentFailure,
        EvidenceOutcome::Unsupported
    );
}

#[test]
fn seed_create_reload_and_fresh_install_namespaces_are_stable_and_distinct() {
    let first_config = new_config_directory();
    let cancellation = CancellationToken::new();
    let first = load_or_create_device_seed(first_config.path(), &cancellation)
        .expect("create protected seed");
    let reloaded = load_or_create_device_seed(first_config.path(), &cancellation)
        .expect("reload protected seed");
    assert_eq!(first.as_test_bytes(), reloaded.as_test_bytes());
    assert_eq!(
        fs::read(first_config.path().join("transcoding/device-id.key"))
            .expect("read seed fixture")
            .len(),
        32
    );

    let second_config = new_config_directory();
    let second = load_or_create_device_seed(second_config.path(), &cancellation)
        .expect("create independent seed");
    assert_ne!(first.as_test_bytes(), second.as_test_bytes());
}

#[test]
fn seed_concurrent_creators_all_reopen_the_same_complete_winner() {
    const WORKERS: usize = 8;
    let config = Arc::new(new_config_directory());
    let barrier = Arc::new(Barrier::new(WORKERS));
    let workers = (0..WORKERS)
        .map(|_| {
            let config = Arc::clone(&config);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                load_or_create_device_seed(config.path(), &CancellationToken::new())
                    .expect("race participant loads winner")
                    .as_test_bytes()
            })
        })
        .collect::<Vec<_>>();
    let seeds = workers
        .into_iter()
        .map(|worker| worker.join().expect("seed worker completes"))
        .collect::<Vec<_>>();

    assert!(seeds.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        fs::read(config.path().join("transcoding/device-id.key"))
            .expect("read race winner")
            .len(),
        32
    );
}

#[test]
fn seed_race_losers_wait_for_an_in_progress_winner_instead_of_reading_partial_bytes() {
    let config = Arc::new(new_config_directory());
    let (created_sender, created_receiver) = std::sync::mpsc::sync_channel(1);
    let writer_config = Arc::clone(&config);
    let writer = std::thread::spawn(move || {
        load_or_create_device_seed_with_observer(
            writer_config.path(),
            &CancellationToken::new(),
            |event| {
                if event == SeedStorageEvent::SeedCreatedBeforeWrite {
                    created_sender.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            },
        )
        .expect("delayed creator completes")
        .as_test_bytes()
    });
    created_receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("writer reached the pre-write checkpoint");

    let readers = (0..4)
        .map(|_| {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                load_or_create_device_seed(config.path(), &CancellationToken::new())
                    .expect("race loser reopens complete winner")
                    .as_test_bytes()
            })
        })
        .collect::<Vec<_>>();
    let winner = writer.join().unwrap();
    for reader in readers {
        assert_eq!(reader.join().unwrap(), winner);
    }
}

#[test]
fn seed_short_long_and_empty_winners_are_rejected_without_overwrite() {
    for malformed in [Vec::new(), vec![0x41; 31], vec![0x42; 33]] {
        let config = new_config_directory();
        let cancellation = CancellationToken::new();
        load_or_create_device_seed(config.path(), &cancellation).expect("create protected fixture");
        let path = config.path().join("transcoding/device-id.key");
        fs::write(&path, &malformed).expect("replace fixture contents");

        let error = load_or_create_device_seed(config.path(), &cancellation)
            .expect_err("malformed winner must fail closed");
        assert_eq!(error, SeedStorageError::Invalid);
        assert_eq!(fs::read(path).unwrap(), malformed);
    }
}

#[test]
fn seed_requires_a_regular_file_and_never_replaces_the_wrong_type() {
    let config = new_config_directory();
    let cancellation = CancellationToken::new();
    load_or_create_device_seed(config.path(), &cancellation).expect("create protected fixture");
    let path = config.path().join("transcoding/device-id.key");
    fs::remove_file(&path).expect("remove seed fixture");
    fs::create_dir(&path).expect("install wrong-type fixture");

    assert_eq!(
        load_or_create_device_seed(config.path(), &cancellation).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(path.is_dir());
}

#[test]
fn seed_cancellation_before_creation_leaves_no_key() {
    let config = new_config_directory();
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    assert_eq!(
        load_or_create_device_seed(config.path(), &cancellation).unwrap_err(),
        SeedStorageError::Cancelled
    );
    assert!(!config.path().join("transcoding/device-id.key").exists());
}

#[test]
fn seed_cancellation_after_root_validation_leaves_no_key() {
    let config = new_config_directory();
    let cancellation = CancellationToken::new();
    let error = load_or_create_device_seed_with_observer(config.path(), &cancellation, |event| {
        if event == SeedStorageEvent::RootReady {
            cancellation.cancel();
        }
    })
    .unwrap_err();

    assert_eq!(error, SeedStorageError::Cancelled);
    assert!(!config.path().join("transcoding/device-id.key").exists());
}

#[test]
fn seed_creation_reports_file_and_parent_durability_checkpoints() {
    let config = new_config_directory();
    let events = Mutex::new(Vec::new());
    load_or_create_device_seed_with_observer(config.path(), &CancellationToken::new(), |event| {
        events.lock().unwrap().push(event)
    })
    .expect("durable seed creation");

    let events = events.into_inner().unwrap();
    let file_sync = events
        .iter()
        .position(|event| *event == SeedStorageEvent::SeedFileSynced)
        .expect("seed file was flushed");
    let directory_sync = events
        .iter()
        .position(|event| *event == SeedStorageEvent::ParentDirectorySyncAttempted)
        .expect("parent synchronization was attempted");
    assert!(file_sync < directory_sync);
}

#[cfg(unix)]
#[test]
fn seed_unix_objects_use_private_modes_and_reject_symlink_parents() {
    use std::os::unix::fs::{MetadataExt, symlink};

    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let root = config.path().join("transcoding");
    let seed = root.join("device-id.key");
    assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&seed).unwrap().mode() & 0o777, 0o600);

    let namespace = new_config_directory();
    let real = namespace.path().join("real");
    let linked = namespace.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();
    assert_eq!(
        load_or_create_device_seed(&linked, &CancellationToken::new()).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(!real.join("transcoding").exists());
}

#[cfg(windows)]
#[test]
fn seed_windows_objects_use_protected_dacls_and_reject_reparse_parents() {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let root = config.path().join("transcoding");
    let seed = root.join("device-id.key");
    assert!(super::storage::windows::dacl_is_protected_for_test(&root));
    assert!(super::storage::windows::dacl_is_protected_for_test(&seed));

    let namespace = new_config_directory();
    let real = namespace.path().join("real");
    let linked = namespace.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink_dir(&real, &linked).expect("create reparse parent fixture");
    assert_eq!(
        load_or_create_device_seed(&linked, &CancellationToken::new()).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(!real.join("transcoding").exists());

    let linked_seed_config = new_config_directory();
    load_or_create_device_seed(linked_seed_config.path(), &CancellationToken::new()).unwrap();
    let linked_seed = linked_seed_config.path().join("transcoding/device-id.key");
    fs::remove_file(&linked_seed).unwrap();
    let outside_seed = linked_seed_config.path().join("outside.key");
    fs::write(&outside_seed, [0x5a; 32]).unwrap();
    symlink_file(&outside_seed, &linked_seed).expect("create seed reparse fixture");
    assert_eq!(
        load_or_create_device_seed(linked_seed_config.path(), &CancellationToken::new())
            .unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert_eq!(fs::read(outside_seed).unwrap(), [0x5a; 32]);

    let linked_object_config = new_config_directory();
    load_or_create_device_seed(linked_object_config.path(), &CancellationToken::new()).unwrap();
    let linked_object = linked_object_config
        .path()
        .join("transcoding/device-id.key");
    fs::remove_file(&linked_object).unwrap();
    let outside_object = linked_object_config.path().join("outside-hardlink.key");
    fs::write(&outside_object, [0x33; 32]).unwrap();
    fs::hard_link(&outside_object, &linked_object).unwrap();
    assert_eq!(
        load_or_create_device_seed(linked_object_config.path(), &CancellationToken::new())
            .unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert_eq!(fs::read(outside_object).unwrap(), [0x33; 32]);
}

#[cfg(windows)]
#[test]
fn seed_windows_rejects_a_preexisting_unprotected_root_without_modifying_it() {
    let config = new_config_directory();
    let root = config.path().join("transcoding");
    fs::create_dir(&root).unwrap();
    assert!(!super::storage::windows::dacl_is_protected_for_test(&root));

    assert_eq!(
        load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap_err(),
        SeedStorageError::Untrusted
    );
    assert!(!root.join("device-id.key").exists());
    assert!(!super::storage::windows::dacl_is_protected_for_test(&root));
}
