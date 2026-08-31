use super::key::{
    BitDepth, CapabilityDirection, CapabilityKey, CodecLevel, InputVideoSignature,
    KeyValidationError, OutputVideoSignature, PrivateSourceDigest, SegmentationContract,
    test_common, test_input, test_output, test_requirements,
};
use super::registry::{
    CapabilityRegistry, CapabilityVerifier, PlaybackPriority, RefreshState, RegistryReason,
    SnapshotFreshness, UnknownVerifier, VerificationRequest, cache_identity_filter_matrix_for_test,
    snapshot_validation_matrix_for_test,
};
use super::state::{
    EvidenceOutcome, EvidenceReason, EvidenceRecord, EvidenceTarget, EvidenceTimestamp,
    ProjectionContext, StateError, StateNow, VerificationMode, VerificationResult, VerifierMode,
    WorkState,
};
use super::storage::{
    CacheSchemaError, EvidenceStorage, PersistenceTestHooks, SeedStorageError, SeedStorageEvent,
    StorageStatus, create_cache_temporary_for_test, decode_evidence_cache, encode_evidence_cache,
    load_or_create_device_seed, load_or_create_device_seed_with_observer,
};
use crate::transcoding::{
    CapabilityState, ChromaSubsampling, FrameRateClass, InputVideoCodec, KeyframeStrategy,
    OutputVideoCodec, PixelFormat, RationalRate, VideoProfile,
};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    num::NonZeroU32,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

static_assertions::assert_not_impl_any!(CapabilityKey: serde::Serialize);
static_assertions::assert_not_impl_any!(PrivateSourceDigest: serde::Serialize);

#[test]
fn service_owns_one_registry() {
    use crate::transcoding::{process::ProcessSupervisor, runtime::TranscodingService};

    let registry = Arc::new(CapabilityRegistry::new(Arc::new(UnknownVerifier)));
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let service = TranscodingService::unavailable(supervisor, Arc::clone(&registry));

    assert!(Arc::ptr_eq(
        service.capability_registry_for_test(),
        &registry
    ));
}

#[derive(Clone, Copy)]
struct EmptyDeviceEnumerator;

#[async_trait::async_trait]
impl crate::transcoding::device::DeviceEnumerator for EmptyDeviceEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, crate::transcoding::device::DeviceError>
    {
        if cancellation.is_cancelled() {
            Err(crate::transcoding::device::DeviceError::Cancelled)
        } else {
            Ok(crate::transcoding::device::DeviceDiscovery::supported(
                Vec::new(),
            ))
        }
    }
}

#[derive(Clone)]
struct PanickingDeviceEnumerator {
    cancelled: Arc<Semaphore>,
}

impl PanickingDeviceEnumerator {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(Semaphore::new(0)),
        }
    }

    async fn wait_until_cancelled(&self) {
        self.cancelled
            .acquire()
            .await
            .expect("panic cancellation semaphore remains open")
            .forget();
    }
}

#[async_trait::async_trait]
impl crate::transcoding::device::DeviceEnumerator for PanickingDeviceEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, crate::transcoding::device::DeviceError>
    {
        let cancelled = Arc::clone(&self.cancelled);
        tokio::spawn(async move {
            cancellation.cancelled().await;
            cancelled.add_permits(1);
        });
        panic!("injected device-enumerator panic")
    }
}

#[derive(Clone)]
struct PanicAfterCancellationEnumerator {
    entered: Arc<Semaphore>,
}

impl PanicAfterCancellationEnumerator {
    fn new() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
        }
    }

    async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("shutdown-panic entry semaphore remains open")
            .forget();
    }
}

#[async_trait::async_trait]
impl crate::transcoding::device::DeviceEnumerator for PanicAfterCancellationEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, crate::transcoding::device::DeviceError>
    {
        self.entered.add_permits(1);
        cancellation.cancelled().await;
        panic!("injected shutdown-time device-enumerator panic")
    }
}

#[derive(Clone, Copy)]
struct UnexpectedInventorySource;

#[async_trait::async_trait]
impl crate::transcoding::inventory::StaticInventorySource for UnexpectedInventorySource {
    async fn collect(
        &self,
        _session: &crate::transcoding::runtime::VerifiedRuntimeSession,
        _cancellation: CancellationToken,
    ) -> Result<
        crate::transcoding::inventory::RuntimeInventory,
        crate::transcoding::inventory::InventoryError,
    > {
        panic!("runtime-unavailable refresh must not execute inventory")
    }
}

#[derive(Clone)]
struct PausedDeviceEnumerator {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl PausedDeviceEnumerator {
    fn new() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }

    async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("enumerator entry semaphore remains open")
            .forget();
    }

    fn release_one(&self) {
        self.release.add_permits(1);
    }
}

#[async_trait::async_trait]
impl crate::transcoding::device::DeviceEnumerator for PausedDeviceEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, crate::transcoding::device::DeviceError>
    {
        self.entered.add_permits(1);
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(crate::transcoding::device::DeviceError::Cancelled),
            permit = self.release.acquire() => {
                permit.expect("enumerator release semaphore remains open").forget();
                Ok(crate::transcoding::device::DeviceDiscovery::supported(Vec::new()))
            }
        }
    }
}

#[derive(Clone, Default)]
struct FailAfterFirstEnumerator(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl crate::transcoding::device::DeviceEnumerator for FailAfterFirstEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, crate::transcoding::device::DeviceError>
    {
        if cancellation.is_cancelled() {
            return Err(crate::transcoding::device::DeviceError::Cancelled);
        }
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(crate::transcoding::device::DeviceDiscovery::supported(
                Vec::new(),
            ))
        } else {
            Err(crate::transcoding::device::DeviceError::Invalid)
        }
    }
}

#[derive(Clone)]
struct FixedDeviceEnumerator(Vec<crate::transcoding::device::PlatformDeviceRecord>);

#[async_trait::async_trait]
impl crate::transcoding::device::DeviceEnumerator for FixedDeviceEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, crate::transcoding::device::DeviceError>
    {
        if cancellation.is_cancelled() {
            Err(crate::transcoding::device::DeviceError::Cancelled)
        } else {
            Ok(crate::transcoding::device::DeviceDiscovery::supported(
                self.0.clone(),
            ))
        }
    }
}

fn refresh_test_device(
    availability: crate::transcoding::device::DeviceAvailability,
) -> crate::transcoding::device::PlatformDeviceRecord {
    use crate::transcoding::{
        BackendKind, DeviceClass,
        device::{
            DeviceLocator, DriverField, DriverRecord, PlatformDeviceRecord, Vendor,
            identity::{PlatformTag, PrivateDeviceIdentity},
        },
    };

    PlatformDeviceRecord {
        platform: PlatformTag::Windows,
        display_name: b"Refresh Test GPU".to_vec(),
        vendor: Vendor::Intel,
        class: DeviceClass::Integrated,
        availability,
        persistent_identity: PrivateDeviceIdentity::new(b"refresh-test-gpu".to_vec())
            .expect("bounded test identity"),
        locator: DeviceLocator::Unavailable,
        driver: DriverRecord::Complete(vec![DriverField::new(1, b"test-driver".to_vec())]),
        backends: vec![BackendKind::Qsv],
    }
}

#[tokio::test]
async fn runtime_unavailable_refresh_publishes_fresh_empty() {
    use super::registry::{RefreshAdmission, RefreshCause};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(EmptyDeviceEnumerator),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x31; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x41; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));

    let admission = service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    assert_eq!(admission, RefreshAdmission::Started { id: 1 });
    registry.wait_for_refresh_for_test().await;

    let publication = registry.publication().await;
    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Fresh);
    assert_eq!(publication.snapshot.identity_epoch(), 1);
    assert_eq!(publication.snapshot.publication_revision(), 2);
    assert!(publication.snapshot.devices_for_test().is_empty());
    assert_eq!(publication.refresh.state, RefreshState::Succeeded);
}

#[tokio::test]
async fn refresh_is_single_flight_and_startup_does_not_consume_manual_rate_window() {
    use super::registry::{RefreshAdmission, RefreshCause};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let enumerator = PausedDeviceEnumerator::new();
    let (registry, clock) = CapabilityRegistry::with_refresh_dependencies_and_clock_for_test(
        Arc::new(enumerator.clone()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x32; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x42; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));

    assert_eq!(
        service
            .start_capability_refresh(RefreshCause::Startup)
            .await,
        RefreshAdmission::Started { id: 1 }
    );
    enumerator.wait_until_entered().await;
    assert_eq!(
        service.start_capability_refresh(RefreshCause::Manual).await,
        RefreshAdmission::Existing { id: 1 }
    );
    enumerator.release_one();
    registry.wait_for_refresh_for_test().await;
    assert_eq!(
        service
            .start_capability_refresh(RefreshCause::Startup)
            .await,
        RefreshAdmission::Existing { id: 1 }
    );

    assert_eq!(
        service.start_capability_refresh(RefreshCause::Manual).await,
        RefreshAdmission::Started { id: 2 }
    );
    enumerator.wait_until_entered().await;
    enumerator.release_one();
    registry.wait_for_refresh_for_test().await;
    assert_eq!(
        service.start_capability_refresh(RefreshCause::Manual).await,
        RefreshAdmission::RateLimited {
            retry_after_seconds: 60
        }
    );
    clock.set_minutes(1);
    assert_eq!(
        service.start_capability_refresh(RefreshCause::Manual).await,
        RefreshAdmission::Started { id: 3 }
    );
    enumerator.wait_until_entered().await;
    enumerator.release_one();
    registry.wait_for_refresh_for_test().await;
}

#[tokio::test]
async fn failed_refresh_republishes_previous_data_stale_without_mutating_old_arc() {
    use super::registry::{RefreshAdmission, RefreshCause};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(FailAfterFirstEnumerator::default()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x33; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x43; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));
    assert_eq!(
        service
            .start_capability_refresh(RefreshCause::Startup)
            .await,
        RefreshAdmission::Started { id: 1 }
    );
    registry.wait_for_refresh_for_test().await;
    let old = registry.snapshot().await;
    assert_eq!(old.freshness(), SnapshotFreshness::Fresh);

    assert_eq!(
        service.start_capability_refresh(RefreshCause::Manual).await,
        RefreshAdmission::Started { id: 2 }
    );
    registry.wait_for_refresh_for_test().await;
    let publication = registry.publication().await;

    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Stale);
    assert_eq!(publication.snapshot.identity_epoch(), 2);
    assert_eq!(publication.snapshot.publication_revision(), 4);
    assert_eq!(publication.refresh.state, RefreshState::Failed);
    assert_eq!(old.freshness(), SnapshotFreshness::Fresh);
    assert_eq!(old.identity_epoch(), 1);
    assert!(!Arc::ptr_eq(&old, &publication.snapshot));
}

#[tokio::test]
async fn failed_manual_refresh_does_not_clear_existing_circuit_history() {
    use super::registry::{RefreshCause, RefreshOutcomeReason};
    use crate::transcoding::{process::ProcessSupervisor, runtime::TranscodingService};

    let key = CapabilityKey::complete_test_keys().remove(0);
    let failing = FailAfterFirstEnumerator(Arc::new(AtomicUsize::new(1)));
    let registry = CapabilityRegistry::circuit_open_with_refresh_dependencies_for_test(
        key.clone(),
        Arc::new(failing),
        Arc::new(UnexpectedInventorySource),
    );
    let before = registry.snapshot().await;
    let before_record = before.evidence().get(&key).expect("fixture evidence");
    assert_eq!(before_record.failure_streak_for_test(), Some(1));
    assert_eq!(
        before_record.cooldown_minutes_for_test(StateNow::from_test_minutes(0)),
        Some(10)
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));

    let _ = service.start_capability_refresh(RefreshCause::Manual).await;
    registry.wait_for_refresh_for_test().await;
    let publication = registry.publication().await;
    let after_record = publication
        .snapshot
        .evidence()
        .get(&key)
        .expect("failed refresh retains circuit evidence");

    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Stale);
    assert_eq!(publication.refresh.state, RefreshState::Failed);
    assert_eq!(
        publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::DeviceEnumerationFailed)
    );
    assert_eq!(after_record.failure_streak_for_test(), Some(1));
    assert_eq!(
        after_record.cooldown_minutes_for_test(StateNow::from_test_minutes(0)),
        Some(10)
    );
}

#[tokio::test]
async fn dropping_refresh_caller_does_not_cancel_registry_owned_work() {
    use super::registry::{RefreshAdmission, RefreshCause};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let enumerator = PausedDeviceEnumerator::new();
    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(enumerator.clone()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x34; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x44; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));
    assert_eq!(
        service
            .start_capability_refresh(RefreshCause::Startup)
            .await,
        RefreshAdmission::Started { id: 1 }
    );
    enumerator.wait_until_entered().await;
    enumerator.release_one();
    registry.wait_for_refresh_for_test().await;

    assert_eq!(
        registry.snapshot().await.freshness(),
        SnapshotFreshness::Fresh
    );
}

#[tokio::test]
async fn seed_failure_and_identity_ambiguity_publish_fresh_zero_hardware() {
    use super::registry::{RefreshCause, RefreshOutcomeReason};
    use crate::transcoding::{
        device::{DeviceAvailability, DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let seedless = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(FixedDeviceEnumerator(vec![refresh_test_device(
            DeviceAvailability::Available,
        )])),
        Arc::new(UnexpectedInventorySource),
        None,
        Some(DriverRunEpoch::from_test_bytes([0x45; 32])),
    );
    let seedless_service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&seedless),
    ));
    let _ = seedless_service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    seedless.wait_for_refresh_for_test().await;
    let seedless_publication = seedless.publication().await;
    assert_eq!(
        seedless_publication.snapshot.freshness(),
        SnapshotFreshness::Fresh
    );
    assert!(seedless_publication.snapshot.devices_for_test().is_empty());
    assert_eq!(
        seedless_publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::DeviceIdentityUnavailable)
    );

    let duplicate = refresh_test_device(DeviceAvailability::Available);
    let ambiguous = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(FixedDeviceEnumerator(vec![duplicate.clone(), duplicate])),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x35; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x46; 32])),
    );
    let ambiguous_service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&ambiguous),
    ));
    let _ = ambiguous_service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    ambiguous.wait_for_refresh_for_test().await;
    let ambiguous_publication = ambiguous.publication().await;
    assert_eq!(
        ambiguous_publication.snapshot.freshness(),
        SnapshotFreshness::Fresh
    );
    assert!(ambiguous_publication.snapshot.devices_for_test().is_empty());
    assert_eq!(
        ambiguous_publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::DeviceMappingAmbiguous)
    );
}

#[tokio::test]
async fn permission_unavailable_device_keeps_stable_public_identity() {
    use super::registry::RefreshCause;
    use crate::transcoding::{
        device::{DeviceAvailability, DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(FixedDeviceEnumerator(vec![refresh_test_device(
            DeviceAvailability::PermissionDenied,
        )])),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x36; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x47; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));
    let _ = service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    registry.wait_for_refresh_for_test().await;

    let snapshot = registry.snapshot().await;
    assert_eq!(snapshot.freshness(), SnapshotFreshness::Fresh);
    assert_eq!(snapshot.devices_for_test().len(), 1);
    assert_eq!(
        snapshot.devices_for_test()[0].availability,
        DeviceAvailability::PermissionDenied
    );
}

#[tokio::test]
async fn refresh_worker_deadline_cancels_and_reaps_enumeration_before_stale_publish() {
    use super::registry::{RefreshCause, RefreshOutcomeReason};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let enumerator = PausedDeviceEnumerator::new();
    let registry = CapabilityRegistry::with_refresh_dependencies_and_deadline_for_test(
        Arc::new(enumerator.clone()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x37; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x48; 32])),
        Duration::from_millis(20),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));
    let _ = service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    enumerator.wait_until_entered().await;
    tokio::time::timeout(Duration::from_secs(1), registry.wait_for_refresh_for_test())
        .await
        .expect("bounded refresh worker must finish after cancellation");

    let publication = registry.publication().await;
    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Stale);
    assert_eq!(publication.refresh.state, RefreshState::Failed);
    assert_eq!(
        publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::InventoryTimeout)
    );
}

#[tokio::test]
async fn refresh_worker_panic_fails_closed_and_releases_single_flight() {
    use super::registry::{RefreshAdmission, RefreshCause, RefreshOutcomeReason};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let enumerator = PanickingDeviceEnumerator::new();
    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(enumerator.clone()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x72; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x73; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));

    assert_eq!(
        service
            .start_capability_refresh(RefreshCause::Startup)
            .await,
        RefreshAdmission::Started { id: 1 }
    );
    tokio::time::timeout(Duration::from_secs(1), registry.wait_for_refresh_for_test())
        .await
        .expect("panicked refresh must release single-flight admission");
    tokio::time::timeout(Duration::from_secs(1), enumerator.wait_until_cancelled())
        .await
        .expect("panicked refresh must cancel dependency-owned work");

    let publication = registry.publication().await;
    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Stale);
    assert_eq!(publication.refresh.state, RefreshState::Failed);
    assert_eq!(
        publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::RefreshFailed)
    );
}

#[tokio::test]
async fn shutdown_time_refresh_panic_remains_cancelled() {
    use super::registry::{RefreshCause, RefreshOutcomeReason};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let enumerator = PanicAfterCancellationEnumerator::new();
    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(enumerator.clone()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x74; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x75; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));

    let _ = service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    enumerator.wait_until_entered().await;
    service.shutdown_capabilities().await;

    let publication = registry.publication().await;
    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Stale);
    assert_eq!(publication.refresh.state, RefreshState::Cancelled);
    assert_eq!(
        publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::RefreshCancelled)
    );
}

#[tokio::test]
async fn capability_shutdown_cancels_refresh_and_joins_owned_work() {
    use super::registry::{RefreshCause, RefreshOutcomeReason};
    use crate::transcoding::{
        device::{DriverRunEpoch, identity::DeviceIdSeed},
        process::ProcessSupervisor,
        runtime::TranscodingService,
    };

    let enumerator = PausedDeviceEnumerator::new();
    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(enumerator.clone()),
        Arc::new(UnexpectedInventorySource),
        Some(DeviceIdSeed::from_test_bytes([0x38; 32])),
        Some(DriverRunEpoch::from_test_bytes([0x49; 32])),
    );
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));
    let _ = service
        .start_capability_refresh(RefreshCause::Startup)
        .await;
    enumerator.wait_until_entered().await;
    tokio::time::timeout(Duration::from_secs(1), service.shutdown_capabilities())
        .await
        .expect("capability shutdown must join cancelled enumeration");

    let publication = registry.publication().await;
    assert_eq!(publication.snapshot.freshness(), SnapshotFreshness::Stale);
    assert_eq!(publication.refresh.state, RefreshState::Cancelled);
    assert_eq!(
        publication.refresh.outcome_reason,
        Some(RefreshOutcomeReason::RefreshCancelled)
    );
}

#[tokio::test]
async fn refresh_counter_exhaustion_closes_admission_without_publication() {
    use super::registry::{RefreshAdmission, RefreshCause};
    use crate::transcoding::{process::ProcessSupervisor, runtime::TranscodingService};

    let registry = CapabilityRegistry::ephemeral_for_test();
    registry.exhaust_refresh_counter_for_test();
    let service = Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        Arc::clone(&registry),
    ));

    assert_eq!(
        service
            .start_capability_refresh(RefreshCause::Startup)
            .await,
        RefreshAdmission::Rejected {
            reason: RegistryReason::CapacityExhausted
        }
    );
    let snapshot = registry.snapshot().await;
    assert_eq!(snapshot.freshness(), SnapshotFreshness::Uninitialized);
    assert_eq!(snapshot.identity_epoch(), 0);
    assert_eq!(snapshot.publication_revision(), 0);
}

#[tokio::test]
async fn production_unknown_verifier_never_records_or_spawns() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let registry = CapabilityRegistry::fresh_for_test(key.clone(), UnknownVerifier);
    let before = registry.verifier_invocations_for_test();

    let result = registry
        .ensure_evidence(key, EvidenceTarget::Correctness)
        .await;

    assert!(result.is_non_passing());
    assert_eq!(
        result.reason(),
        Some(RegistryReason::VerificationNotImplemented)
    );
    assert_eq!(registry.verifier_invocations_for_test(), before);
    assert!(registry.snapshot().await.evidence().is_empty());
    assert_eq!(registry.in_flight_count_for_test().await, 0);
}

#[derive(Clone)]
struct PausedVerifier {
    calls: Arc<AtomicUsize>,
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl PausedVerifier {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }

    async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("test semaphore remains open")
            .forget();
    }

    fn release_one(&self) {
        self.release.add_permits(1);
    }
}

#[async_trait::async_trait]
impl CapabilityVerifier for PausedVerifier {
    fn mode(&self) -> VerifierMode {
        VerifierMode::ActiveInjected
    }

    async fn verify(
        &self,
        request: VerificationRequest,
        cancellation: CancellationToken,
    ) -> VerificationResult {
        assert_eq!(request.identity_epoch, 1);
        let _ = &request.key;
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.add_permits(1);
        tokio::select! {
            _ = cancellation.cancelled() => VerificationResult::for_test(
                request.target,
                EvidenceOutcome::Cancelled,
                EvidenceReason::VerificationFailed,
                0,
            ),
            permit = self.release.acquire() => {
                permit.expect("test semaphore remains open").forget();
                VerificationResult::for_test(
                    request.target,
                    if request.target == EvidenceTarget::Realtime {
                        EvidenceOutcome::RealtimePassed
                    } else {
                        EvidenceOutcome::CorrectnessPassed
                    },
                    EvidenceReason::VerificationFailed,
                    0,
                )
            }
        }
    }
}

#[derive(Clone)]
struct ImmediateVerifier {
    calls: Arc<AtomicUsize>,
    minute: u64,
}

impl ImmediateVerifier {
    fn at_minute(minute: u64) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            minute,
        }
    }
}

#[async_trait::async_trait]
impl CapabilityVerifier for ImmediateVerifier {
    fn mode(&self) -> VerifierMode {
        VerifierMode::ActiveInjected
    }

    async fn verify(
        &self,
        request: VerificationRequest,
        _cancellation: CancellationToken,
    ) -> VerificationResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        VerificationResult::for_test(
            request.target,
            if request.target == EvidenceTarget::Realtime {
                EvidenceOutcome::RealtimePassed
            } else {
                EvidenceOutcome::CorrectnessPassed
            },
            EvidenceReason::VerificationFailed,
            self.minute,
        )
    }
}

#[derive(Clone)]
struct TerminatingVerifier {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl TerminatingVerifier {
    fn new() -> Self {
        Self {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl CapabilityVerifier for TerminatingVerifier {
    fn mode(&self) -> VerifierMode {
        VerifierMode::ActiveInjected
    }

    async fn verify(
        &self,
        _request: VerificationRequest,
        _cancellation: CancellationToken,
    ) -> VerificationResult {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .expect("test semaphore remains open")
            .forget();
        panic!("injected verifier termination")
    }
}

#[derive(Clone, Copy)]
struct WrongTargetVerifier;

#[async_trait::async_trait]
impl CapabilityVerifier for WrongTargetVerifier {
    fn mode(&self) -> VerifierMode {
        VerifierMode::ActiveInjected
    }

    async fn verify(
        &self,
        _request: VerificationRequest,
        _cancellation: CancellationToken,
    ) -> VerificationResult {
        VerificationResult::for_test(
            EvidenceTarget::Segmented,
            EvidenceOutcome::CorrectnessPassed,
            EvidenceReason::VerificationFailed,
            0,
        )
    }
}

#[derive(Default)]
struct TogglePlayback(AtomicBool);

impl TogglePlayback {
    fn set(&self, active: bool) {
        self.0.store(active, Ordering::SeqCst);
    }
}

impl PlaybackPriority for TogglePlayback {
    fn playback_active(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn spawn_ensure(
    registry: &Arc<CapabilityRegistry>,
    key: CapabilityKey,
    target: EvidenceTarget,
) -> tokio::task::JoinHandle<super::registry::EnsureEvidenceResult> {
    let registry = Arc::clone(registry);
    tokio::spawn(async move { registry.ensure_evidence(key, target).await })
}

async fn wait_for_in_flight(registry: &CapabilityRegistry, expected: usize) {
    for _ in 0..1_000 {
        if registry.in_flight_count_for_test().await == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("in-flight count did not reach {expected}");
}

#[tokio::test]
async fn registry_starts_uninitialized_and_publication_is_revision_consistent() {
    let registry = CapabilityRegistry::new(Arc::new(UnknownVerifier));
    let publication = registry.publication().await;
    assert_eq!(
        publication.snapshot.freshness(),
        SnapshotFreshness::Uninitialized
    );
    assert_eq!(publication.snapshot.identity_epoch(), 0);
    assert_eq!(publication.snapshot.publication_revision(), 0);
    assert_eq!(publication.refresh.state, RefreshState::Idle);
    assert!(publication.snapshot.evidence().is_empty());

    assert_eq!(
        [
            SnapshotFreshness::Uninitialized,
            SnapshotFreshness::Refreshing,
            SnapshotFreshness::Fresh,
            SnapshotFreshness::Stale,
        ]
        .len(),
        4
    );
    assert_eq!(
        [
            RefreshState::Idle,
            RefreshState::Running,
            RefreshState::Succeeded,
            RefreshState::Failed,
            RefreshState::Cancelled,
        ]
        .len(),
        5
    );
    for (reason, code) in [
        (
            RegistryReason::VerificationNotImplemented,
            "verification_not_implemented",
        ),
        (RegistryReason::VerificationStale, "verification_stale"),
        (
            RegistryReason::VerificationPrerequisiteMissing,
            "verification_prerequisite_missing",
        ),
        (
            RegistryReason::VerificationCapacity,
            "verification_capacity",
        ),
        (
            RegistryReason::VerificationQueueTimeout,
            "verification_queue_timeout",
        ),
        (
            RegistryReason::VerificationDeferredForPlayback,
            "verification_deferred_for_playback",
        ),
        (RegistryReason::CapacityExhausted, "capacity_exhausted"),
        (RegistryReason::ServerShutdown, "server_shutdown"),
    ] {
        assert_eq!(reason.safe_code(), code);
    }
}

#[test]
fn snapshot_order_bounds_and_cross_references_are_strict() {
    for (case, accepted) in snapshot_validation_matrix_for_test() {
        assert!(accepted, "snapshot invariant failed: {case}");
    }
}

#[test]
fn cached_evidence_requires_exact_current_identity_and_prerequisites() {
    for (case, accepted) in cache_identity_filter_matrix_for_test() {
        assert!(accepted, "cache identity filter failed: {case}");
    }
}

#[tokio::test]
async fn verifier_admission_rejects_every_noncurrent_or_missing_prerequisite_before_queue() {
    let key = CapabilityKey::complete_test_keys().remove(2);
    let cases = [
        CapabilityRegistry::with_freshness_for_test(
            key.clone(),
            PausedVerifier::new(),
            SnapshotFreshness::Refreshing,
        ),
        CapabilityRegistry::with_freshness_for_test(
            key.clone(),
            PausedVerifier::new(),
            SnapshotFreshness::Stale,
        ),
        CapabilityRegistry::fresh_for_test(key.clone(), PausedVerifier::new()),
        CapabilityRegistry::fresh_for_test(key.clone(), PausedVerifier::new()),
        CapabilityRegistry::fresh_for_test(key.clone(), PausedVerifier::new()),
        CapabilityRegistry::fresh_for_test(key.clone(), PausedVerifier::new()),
        CapabilityRegistry::without_candidates_for_test(key.clone(), PausedVerifier::new()),
        CapabilityRegistry::without_filters_for_test(key.clone(), PausedVerifier::new()),
    ];
    let rejected_keys = [
        key.clone(),
        key.clone(),
        key.with_test_runtime(0x90),
        key.with_test_physical_identity(0x91),
        key.with_test_driver(0x92),
        key.with_test_backend(crate::transcoding::BackendKind::Cuda),
        key.clone(),
        key.invalid_for_test(),
    ];

    for (registry, rejected) in cases.into_iter().zip(rejected_keys) {
        let result = registry
            .ensure_evidence(rejected, EvidenceTarget::Correctness)
            .await;
        assert_eq!(
            result.reason(),
            Some(RegistryReason::VerificationPrerequisiteMissing)
        );
        assert_eq!(registry.verifier_invocations_for_test(), 0);
        assert_eq!(registry.in_flight_count_for_test().await, 0);
        assert!(registry.snapshot().await.evidence().is_empty());
        registry.shutdown().await;
    }

    let registry = CapabilityRegistry::without_filters_for_test(key.clone(), PausedVerifier::new());
    let result = registry
        .ensure_evidence(key, EvidenceTarget::Correctness)
        .await;
    assert_eq!(
        result.reason(),
        Some(RegistryReason::VerificationPrerequisiteMissing)
    );
    assert_eq!(registry.verifier_invocations_for_test(), 0);
    registry.shutdown().await;
}

#[tokio::test]
async fn closed_registry_rejects_before_queue_or_verifier_call() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let registry = CapabilityRegistry::fresh_for_test(key.clone(), PausedVerifier::new());
    registry.shutdown().await;

    let result = registry
        .ensure_evidence(key, EvidenceTarget::Correctness)
        .await;
    assert_eq!(result.reason(), Some(RegistryReason::ServerShutdown));
    assert_eq!(registry.verifier_invocations_for_test(), 0);
    assert_eq!(registry.in_flight_count_for_test().await, 0);
}

#[tokio::test]
async fn same_key_is_single_flight_caller_drop_is_independent_and_old_arc_is_immutable() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test(
        key.clone(),
        verifier.clone(),
    ));
    let old_snapshot = registry.snapshot().await;

    let first = tokio::spawn({
        let registry = Arc::clone(&registry);
        let key = key.clone();
        async move {
            registry
                .ensure_evidence(key, EvidenceTarget::Correctness)
                .await
        }
    });
    verifier.wait_until_entered().await;
    let follower = tokio::spawn({
        let registry = Arc::clone(&registry);
        let key = key.clone();
        async move {
            registry
                .ensure_evidence(key, EvidenceTarget::Correctness)
                .await
        }
    });
    tokio::task::yield_now().await;
    assert_eq!(registry.in_flight_count_for_test().await, 1);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    first.abort();

    let snapshot_while_paused = registry.snapshot().await;
    assert!(Arc::ptr_eq(&snapshot_while_paused, &old_snapshot));
    verifier.release_one();
    let result = follower.await.unwrap();
    assert!(result.is_passing());

    let current = registry.snapshot().await;
    assert_eq!(current.evidence().len(), 1);
    assert_eq!(current.publication_revision(), 2);
    assert!(old_snapshot.evidence().is_empty());
    assert_eq!(old_snapshot.publication_revision(), 1);
    assert_eq!(registry.in_flight_count_for_test().await, 0);
    registry.shutdown().await;
}

#[tokio::test]
async fn different_key_completions_merge_at_the_same_epoch() {
    let base = CapabilityKey::complete_test_keys().remove(0);
    let keys = vec![
        base.with_test_physical_identity(0x21),
        base.with_test_physical_identity(0x31),
    ];
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test_keys(
        keys.clone(),
        verifier.clone(),
    ));
    let tasks = keys
        .iter()
        .cloned()
        .map(|key| spawn_ensure(&registry, key, EvidenceTarget::Correctness))
        .collect::<Vec<_>>();
    verifier.wait_until_entered().await;
    verifier.wait_until_entered().await;
    verifier.release.add_permits(2);

    for task in tasks {
        assert!(task.await.unwrap().is_passing());
    }
    wait_for_in_flight(&registry, 0).await;
    let snapshot = registry.snapshot().await;
    assert_eq!(snapshot.evidence().len(), 2);
    assert!(keys.iter().all(|key| snapshot.evidence().contains_key(key)));
    assert_eq!(snapshot.publication_revision(), 3);
    registry.shutdown().await;
}

#[tokio::test]
async fn verifier_capacity_is_one_per_device_and_four_globally() {
    let same_device = CapabilityKey::distinct_copy_keys_for_test(2);
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test_keys(
        same_device.clone(),
        verifier.clone(),
    ));
    let first = spawn_ensure(
        &registry,
        same_device[0].clone(),
        EvidenceTarget::Correctness,
    );
    let second = spawn_ensure(
        &registry,
        same_device[1].clone(),
        EvidenceTarget::Correctness,
    );
    verifier.wait_until_entered().await;
    tokio::task::yield_now().await;
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    verifier.release_one();
    verifier.wait_until_entered().await;
    verifier.release_one();
    assert!(first.await.unwrap().is_passing());
    assert!(second.await.unwrap().is_passing());
    registry.shutdown().await;

    let base = CapabilityKey::complete_test_keys().remove(0);
    let different_devices = (1..=5)
        .map(|marker| base.with_test_physical_identity(marker))
        .collect::<Vec<_>>();
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test_keys(
        different_devices.clone(),
        verifier.clone(),
    ));
    let tasks = different_devices
        .into_iter()
        .map(|key| spawn_ensure(&registry, key, EvidenceTarget::Correctness))
        .collect::<Vec<_>>();
    for _ in 0..4 {
        verifier.wait_until_entered().await;
    }
    tokio::task::yield_now().await;
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 4);
    verifier.release_one();
    verifier.wait_until_entered().await;
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 5);
    verifier.release.add_permits(4);
    for task in tasks {
        assert!(task.await.unwrap().is_passing());
    }
    registry.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn queued_verification_times_out_at_five_seconds_without_invocation() {
    let keys = CapabilityKey::distinct_copy_keys_for_test(2);
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test_keys(
        keys.clone(),
        verifier.clone(),
    ));
    let active = spawn_ensure(&registry, keys[0].clone(), EvidenceTarget::Correctness);
    verifier.wait_until_entered().await;
    let queued = spawn_ensure(&registry, keys[1].clone(), EvidenceTarget::Correctness);
    wait_for_in_flight(&registry, 2).await;
    while registry.queued_count_for_test().await != 1 {
        tokio::task::yield_now().await;
    }
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;

    let timed_out = queued.await.unwrap();
    assert_eq!(
        timed_out.reason(),
        Some(RegistryReason::VerificationQueueTimeout)
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    verifier.release_one();
    assert!(active.await.unwrap().is_passing());
    wait_for_in_flight(&registry, 0).await;
    registry.shutdown().await;
}

#[tokio::test]
async fn sixty_five_distinct_flights_are_rejected_without_unbounded_queue_growth() {
    let keys = CapabilityKey::distinct_copy_keys_for_test(65);
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test_keys(
        keys.clone(),
        verifier.clone(),
    ));
    let tasks = keys[..64]
        .iter()
        .cloned()
        .map(|key| spawn_ensure(&registry, key, EvidenceTarget::Correctness))
        .collect::<Vec<_>>();
    wait_for_in_flight(&registry, 64).await;

    let refused = registry
        .ensure_evidence(keys[64].clone(), EvidenceTarget::Correctness)
        .await;
    assert_eq!(refused.reason(), Some(RegistryReason::VerificationCapacity));
    assert_eq!(registry.in_flight_count_for_test().await, 64);
    assert!(registry.queued_count_for_test().await <= 64);
    registry.begin_shutdown();
    for task in tasks {
        assert_eq!(
            task.await.unwrap().reason(),
            Some(RegistryReason::ServerShutdown)
        );
    }
    registry.shutdown().await;
    assert_eq!(registry.in_flight_count_for_test().await, 0);
    assert_eq!(registry.device_semaphore_count_for_test().await, 0);
}

#[tokio::test]
async fn playback_priority_is_checked_before_queue_and_again_before_verifier() {
    let keys = CapabilityKey::distinct_copy_keys_for_test(2);
    let verifier = PausedVerifier::new();
    let playback = Arc::new(TogglePlayback::default());
    playback.set(true);
    let registry = Arc::new(CapabilityRegistry::fresh_for_test_keys_with(
        keys.clone(),
        verifier.clone(),
        playback.clone(),
    ));
    let refused = registry
        .ensure_evidence(keys[0].clone(), EvidenceTarget::Correctness)
        .await;
    assert_eq!(
        refused.reason(),
        Some(RegistryReason::VerificationDeferredForPlayback)
    );
    assert_eq!(registry.in_flight_count_for_test().await, 0);

    playback.set(false);
    let active = spawn_ensure(&registry, keys[0].clone(), EvidenceTarget::Correctness);
    verifier.wait_until_entered().await;
    let queued = spawn_ensure(&registry, keys[1].clone(), EvidenceTarget::Correctness);
    wait_for_in_flight(&registry, 2).await;
    playback.set(true);
    verifier.release_one();
    assert!(active.await.unwrap().is_passing());
    let deferred = queued.await.unwrap();
    assert_eq!(
        deferred.reason(),
        Some(RegistryReason::VerificationDeferredForPlayback)
    );
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot().await.evidence().len(), 1);
    registry.shutdown().await;
}

#[tokio::test]
async fn refresh_invalidation_and_shutdown_wake_all_waiters_and_reap_flights() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test(
        key.clone(),
        verifier.clone(),
    ));
    let old = registry.snapshot().await;
    let leader = spawn_ensure(&registry, key.clone(), EvidenceTarget::Correctness);
    verifier.wait_until_entered().await;
    let follower = spawn_ensure(&registry, key.clone(), EvidenceTarget::Correctness);
    while registry.waiter_count_for_test(&key).await != 2 {
        tokio::task::yield_now().await;
    }
    assert_eq!(registry.begin_refresh_invalidation().await.unwrap(), 2);
    for task in [leader, follower] {
        assert_eq!(
            task.await.unwrap().reason(),
            Some(RegistryReason::VerificationStale)
        );
    }
    let refreshing = registry.snapshot().await;
    assert_eq!(refreshing.freshness(), SnapshotFreshness::Refreshing);
    assert_eq!(refreshing.identity_epoch(), 2);
    assert_eq!(refreshing.publication_revision(), 2);
    assert_eq!(old.freshness(), SnapshotFreshness::Fresh);
    assert_eq!(old.identity_epoch(), 1);
    assert_eq!(registry.in_flight_count_for_test().await, 0);
    assert_eq!(registry.queued_count_for_test().await, 0);
    assert_eq!(registry.device_semaphore_count_for_test().await, 0);
    registry.shutdown().await;

    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test(
        key.clone(),
        verifier.clone(),
    ));
    let leader = spawn_ensure(&registry, key.clone(), EvidenceTarget::Correctness);
    verifier.wait_until_entered().await;
    let follower = spawn_ensure(&registry, key, EvidenceTarget::Correctness);
    registry.begin_shutdown();
    for task in [leader, follower] {
        assert_eq!(
            task.await.unwrap().reason(),
            Some(RegistryReason::ServerShutdown)
        );
    }
    registry.shutdown().await;
    assert_eq!(registry.in_flight_count_for_test().await, 0);
    assert_eq!(registry.device_semaphore_count_for_test().await, 0);
}

#[tokio::test]
async fn evidence_capacity_prunes_expired_rows_then_uses_deterministic_oldest_key_eviction() {
    let keys = CapabilityKey::distinct_copy_keys_for_test(3_073);
    let verifier = ImmediateVerifier::at_minute(0);
    let (registry, _clock) =
        CapabilityRegistry::at_evidence_capacity_for_test(keys.clone(), verifier);
    let result = registry
        .ensure_evidence(keys[3_072].clone(), EvidenceTarget::Correctness)
        .await;
    assert!(result.is_passing());
    wait_for_in_flight(&registry, 0).await;
    let snapshot = registry.snapshot().await;
    assert_eq!(snapshot.evidence().len(), 3_072);
    assert!(snapshot.evidence().contains_key(&keys[3_072]));
    let oldest_tie = keys[..3_072].iter().min().unwrap();
    assert!(!snapshot.evidence().contains_key(oldest_tie));
    registry.shutdown().await;

    let verifier = ImmediateVerifier::at_minute(1_441);
    let (registry, clock) =
        CapabilityRegistry::at_evidence_capacity_for_test(keys.clone(), verifier);
    clock.set_minutes(1_441);
    let result = registry
        .ensure_evidence(keys[3_072].clone(), EvidenceTarget::Correctness)
        .await;
    assert!(result.is_passing());
    wait_for_in_flight(&registry, 0).await;
    let snapshot = registry.snapshot().await;
    assert_eq!(snapshot.evidence().len(), 1);
    assert!(snapshot.evidence().contains_key(&keys[3_072]));
    registry.shutdown().await;
}

#[tokio::test]
async fn checked_counter_exhaustion_closes_verifier_admission_without_mutation() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let verifier = ImmediateVerifier::at_minute(0);
    let calls = Arc::clone(&verifier.calls);
    let registry = CapabilityRegistry::fresh_for_test(key.clone(), verifier);
    registry.exhaust_invocation_counter_for_test();
    let result = registry
        .ensure_evidence(key.clone(), EvidenceTarget::Correctness)
        .await;
    assert_eq!(result.reason(), Some(RegistryReason::CapacityExhausted));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(registry.snapshot().await.evidence().is_empty());
    assert_eq!(
        registry
            .ensure_evidence(key, EvidenceTarget::Correctness)
            .await
            .reason(),
        Some(RegistryReason::CapacityExhausted)
    );
    registry.shutdown().await;

    let key = CapabilityKey::complete_test_keys().remove(0);
    let verifier = PausedVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test(
        key.clone(),
        verifier.clone(),
    ));
    registry.exhaust_publication_revision_for_test().await;
    let task = spawn_ensure(&registry, key.clone(), EvidenceTarget::Correctness);
    verifier.wait_until_entered().await;
    verifier.release_one();
    assert_eq!(
        task.await.unwrap().reason(),
        Some(RegistryReason::CapacityExhausted)
    );
    assert!(registry.snapshot().await.evidence().is_empty());
    assert_eq!(
        registry
            .ensure_evidence(key, EvidenceTarget::Correctness)
            .await
            .reason(),
        Some(RegistryReason::CapacityExhausted)
    );
    registry.shutdown().await;

    let key = CapabilityKey::complete_test_keys().remove(0);
    let registry = CapabilityRegistry::fresh_for_test(key.clone(), PausedVerifier::new());
    registry.exhaust_identity_epoch_for_test().await;
    assert_eq!(
        registry.begin_refresh_invalidation().await,
        Err(RegistryReason::CapacityExhausted)
    );
    assert_eq!(
        registry
            .ensure_evidence(key, EvidenceTarget::Correctness)
            .await
            .reason(),
        Some(RegistryReason::CapacityExhausted)
    );
    registry.shutdown().await;
}

#[tokio::test]
async fn verifier_termination_and_malformed_target_wake_waiters_without_evidence() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let verifier = TerminatingVerifier::new();
    let registry = Arc::new(CapabilityRegistry::fresh_for_test(
        key.clone(),
        verifier.clone(),
    ));
    let leader = spawn_ensure(&registry, key.clone(), EvidenceTarget::Correctness);
    verifier
        .entered
        .acquire()
        .await
        .expect("test semaphore remains open")
        .forget();
    let follower = spawn_ensure(&registry, key.clone(), EvidenceTarget::Correctness);
    while registry.waiter_count_for_test(&key).await != 2 {
        tokio::task::yield_now().await;
    }
    verifier.release.add_permits(1);
    for task in [leader, follower] {
        assert_eq!(
            task.await.unwrap().reason(),
            Some(RegistryReason::ServerShutdown)
        );
    }
    wait_for_in_flight(&registry, 0).await;
    assert!(registry.snapshot().await.evidence().is_empty());
    registry.shutdown().await;

    let registry = CapabilityRegistry::fresh_for_test(key.clone(), WrongTargetVerifier);
    let result = registry
        .ensure_evidence(key, EvidenceTarget::Correctness)
        .await;
    assert_eq!(
        result.reason(),
        Some(RegistryReason::VerificationPrerequisiteMissing)
    );
    assert!(registry.snapshot().await.evidence().is_empty());
    registry.shutdown().await;
}

#[tokio::test]
async fn current_exact_evidence_is_reused_without_a_second_verifier_invocation() {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let verifier = ImmediateVerifier::at_minute(0);
    let calls = Arc::clone(&verifier.calls);
    let registry = CapabilityRegistry::fresh_for_test(key.clone(), verifier);

    assert!(
        registry
            .ensure_evidence(key.clone(), EvidenceTarget::Correctness)
            .await
            .is_passing()
    );
    assert!(
        registry
            .ensure_evidence(key, EvidenceTarget::Correctness)
            .await
            .is_passing()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot().await.evidence().len(), 1);
    registry.shutdown().await;
}

fn cache_record(key: CapabilityKey, outcome: EvidenceOutcome, minute: u64) -> EvidenceRecord {
    let mut record = EvidenceRecord::new(key);
    record
        .apply(
            verification(EvidenceTarget::Correctness, outcome, minute),
            VerifierMode::ActiveInjected,
            state_now(minute),
        )
        .unwrap();
    record
}

#[test]
fn cache_schema_round_trips_complete_evidence_and_excludes_memory_only_keys() {
    let (runtime, _, _, _) = test_common();
    let key = CapabilityKey::complete_test_keys().remove(0);
    let record = cache_record(key.clone(), EvidenceOutcome::CorrectnessPassed, 0);
    let records = BTreeMap::from([(key.clone(), record.clone())]);
    let bytes = encode_evidence_cache(&runtime, &records, state_now(0)).unwrap();
    assert!(bytes.len() < 8 * 1024 * 1024);
    let decoded = decode_evidence_cache(&bytes, &runtime, state_now(0)).unwrap();
    assert_eq!(decoded, records);
    assert!(!bytes.windows(7).any(|window| window == b"workState"));
    assert!(!bytes.windows(6).any(|window| window == b"listed"));
    assert!(!bytes.windows(14).any(|window| window == b"administrative"));
    assert!(!bytes.windows(15).any(|window| window == b"selectedStreams"));

    let keys = CapabilityKey::complete_test_keys();
    let copy = keys[4].clone();
    let incomplete = keys[0]
        .all_identity_mutations_for_test()
        .into_iter()
        .find(|candidate| !candidate.driver().is_persistable())
        .expect("mutation corpus includes incomplete driver identity");
    let memory_only = BTreeMap::from([
        (
            copy.clone(),
            cache_record(copy, EvidenceOutcome::CorrectnessPassed, 0),
        ),
        (
            incomplete.clone(),
            cache_record(incomplete, EvidenceOutcome::CorrectnessPassed, 0),
        ),
    ]);
    let bytes = encode_evidence_cache(&runtime, &memory_only, state_now(0)).unwrap();
    assert!(
        decode_evidence_cache(&bytes, &runtime, state_now(0))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cache_schema_rejects_unknown_duplicate_overflow_and_identity_mutations() {
    let (runtime, _, _, _) = test_common();
    let key = CapabilityKey::complete_test_keys().remove(0);
    let record = cache_record(key.clone(), EvidenceOutcome::CorrectnessPassed, 0);
    let bytes =
        encode_evidence_cache(&runtime, &BTreeMap::from([(key, record)]), state_now(0)).unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rejects = |value: serde_json::Value, now: StateNow| {
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(decode_evidence_cache(&encoded, &runtime, now).is_err());
    };

    let mut value = original.clone();
    value["unexpected"] = serde_json::json!(true);
    rejects(value, state_now(0));

    let duplicate_top = String::from_utf8(bytes.clone()).unwrap().replacen(
        "{\"schemaVersion\":1,",
        "{\"schemaVersion\":1,\"schemaVersion\":1,",
        1,
    );
    assert_eq!(
        decode_evidence_cache(duplicate_top.as_bytes(), &runtime, state_now(0)),
        Err(CacheSchemaError::Invalid)
    );

    let mut value = original.clone();
    let duplicate = value["records"][0].clone();
    value["records"].as_array_mut().unwrap().push(duplicate);
    rejects(value, state_now(0));

    let mut value = original.clone();
    value["schemaVersion"] = serde_json::json!(2);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["evidenceVersion"] = serde_json::json!(2);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["writerServerVersion"] = serde_json::json!("../unsafe");
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["runtimeId"] = serde_json::json!("00".repeat(32));
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["key"]["runtimeId"] = serde_json::json!("00".repeat(32));
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["key"]["backend"] = serde_json::json!("unknownBackend");
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["key"]["recipeVersion"] = serde_json::json!(99);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["key"]["operation"]["requirements"]["unexpected"] = serde_json::json!(true);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["key"]["operation"]["requirements"]["transforms"] =
        serde_json::Value::Array(vec![serde_json::json!("scale"); 17]);
    rejects(value, state_now(0));

    let duplicate_nested = String::from_utf8(bytes.clone()).unwrap().replacen(
        "\"transforms\":[",
        "\"transforms\":[],\"transforms\":[",
        1,
    );
    assert_eq!(
        decode_evidence_cache(duplicate_nested.as_bytes(), &runtime, state_now(0)),
        Err(CacheSchemaError::Invalid)
    );

    assert_eq!(
        decode_evidence_cache(&vec![b' '; 8 * 1024 * 1024 + 1], &runtime, state_now(0)),
        Err(CacheSchemaError::Bounds)
    );

    let mut value = original;
    let row = value["records"][0].clone();
    value["records"] = serde_json::Value::Array(vec![row; 3_073]);
    rejects(value, state_now(0));
}

#[test]
fn cache_schema_rejects_invalid_times_shapes_and_wall_clock_rollback() {
    let (runtime, _, _, _) = test_common();
    let key = CapabilityKey::complete_test_keys().remove(0);
    let record = cache_record(key.clone(), EvidenceOutcome::CorrectnessPassed, 0);
    let bytes = encode_evidence_cache(
        &runtime,
        &BTreeMap::from([(key.clone(), record)]),
        state_now(0),
    )
    .unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rejects = |value: serde_json::Value, now: StateNow| {
        assert!(
            decode_evidence_cache(&serde_json::to_vec(&value).unwrap(), &runtime, now).is_err()
        );
    };

    let mut value = original.clone();
    value["records"][0]["correctness"]["target"] = serde_json::json!("realtime");
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["correctness"]["outcome"] = serde_json::json!("unknown");
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["correctness"]["durationMs"] = serde_json::json!(9_007_199_254_740_992_u64);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["correctness"]["observedAt"] = serde_json::json!(5 * 60_000);
    assert!(
        decode_evidence_cache(&serde_json::to_vec(&value).unwrap(), &runtime, state_now(0)).is_ok()
    );
    let mut value = original.clone();
    value["records"][0]["correctness"]["observedAt"] = serde_json::json!(6 * 60_000);
    value["records"][0]["correctness"]["expiresAt"] = serde_json::json!(7 * 60_000);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["correctness"]["expiresAt"] = serde_json::json!(0);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["correctness"]["expiresAt"] = serde_json::json!(24 * 60 * 60_000_u64 + 1);
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["correctness"] = serde_json::Value::Null;
    value["records"][0]["realtime"] = serde_json::json!({
        "target": "realtime",
        "outcome": "realtimePassed",
        "observedAt": 0,
        "durationMs": 100,
        "expiresAt": 24 * 60 * 60_000_u64
    });
    rejects(value, state_now(0));
    let mut value = original.clone();
    value["records"][0]["terminal"] = serde_json::json!({
        "target": "correctness",
        "outcome": "unsupported",
        "reason": "unsupported",
        "observedAt": 0,
        "durationMs": 100,
        "expiresAt": 24 * 60 * 60_000_u64
    });
    rejects(value, state_now(0));
    let mut value = original.clone();
    for field in [
        "correctness",
        "realtime",
        "segmented",
        "terminal",
        "failureHistory",
    ] {
        value["records"][0][field] = serde_json::Value::Null;
    }
    rejects(value, state_now(0));
    rejects(original.clone(), state_now(1_441));

    let failure = cache_record(key.clone(), EvidenceOutcome::TemporaryFailure, 0);
    let failure_bytes = encode_evidence_cache(
        &runtime,
        &BTreeMap::from([(key.clone(), failure)]),
        state_now(5),
    )
    .unwrap();
    let decoded = decode_evidence_cache(&failure_bytes, &runtime, state_now(5)).unwrap();
    assert_eq!(
        decoded[&key].cooldown_minutes_for_test(state_now(5)),
        Some(5)
    );
    assert_eq!(
        decode_evidence_cache(&failure_bytes, &runtime, StateNow::from_test_times(0, 5),),
        Err(CacheSchemaError::Invalid)
    );

    let mut value: serde_json::Value = serde_json::from_slice(&failure_bytes).unwrap();
    value["records"][0]["failureHistory"]["streak"] = serde_json::json!(0);
    rejects(value, state_now(5));
    let mut value: serde_json::Value = serde_json::from_slice(&failure_bytes).unwrap();
    value["records"][0]["failureHistory"]["streak"] = serde_json::json!(5);
    rejects(value, state_now(5));
    let mut value: serde_json::Value = serde_json::from_slice(&failure_bytes).unwrap();
    value["records"][0]["failureHistory"]["cooldownUntil"] =
        value["records"][0]["failureHistory"]["lastFailureAt"].clone();
    rejects(value, state_now(5));
    let mut value: serde_json::Value = serde_json::from_slice(&failure_bytes).unwrap();
    value["records"][0]["failureHistory"]["cooldownUntil"] = serde_json::json!(61 * 60_000_u64);
    rejects(value, state_now(5));
}

#[tokio::test]
async fn cache_storage_lifetime_lock_is_read_only_for_a_second_owner_and_releases_after_join() {
    let config = new_config_directory();
    let owner = EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(owner.status(), StorageStatus::Writable);

    let (runtime, _, _, _) = test_common();
    let key = CapabilityKey::complete_test_keys().remove(0);
    let record = cache_record(key.clone(), EvidenceOutcome::CorrectnessPassed, 0);
    let records = BTreeMap::from([(key, record)]);
    assert!(owner.request_persist(1, runtime.clone(), records.clone(), state_now(0)));
    assert!(owner.wait_for_persisted(1).await);

    let reader = EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(reader.status(), StorageStatus::ReadOnlyLocked);
    assert_eq!(
        reader.load_evidence(runtime.clone(), state_now(0)).await,
        records
    );
    assert_eq!(reader.status(), StorageStatus::ReadOnlyLocked);
    assert!(!reader.request_persist(2, runtime, BTreeMap::new(), state_now(0)));
    reader.shutdown().await;

    owner.shutdown().await;
    let replacement =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(replacement.status(), StorageStatus::Writable);
    replacement.shutdown().await;
}

#[tokio::test]
async fn cache_storage_replaces_trusted_malformed_content_but_not_an_untrusted_object() {
    let config = new_config_directory();
    let owner = EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    let (runtime, _, _, _) = test_common();
    assert!(owner.request_persist(1, runtime.clone(), BTreeMap::new(), state_now(0)));
    assert!(owner.wait_for_persisted(1).await);
    let cache = config.path().join("transcoding/capabilities-v1.json");
    fs::write(&cache, b"{malformed").unwrap();
    assert!(
        owner
            .load_evidence(runtime.clone(), state_now(0))
            .await
            .is_empty()
    );
    assert_eq!(owner.status(), StorageStatus::Invalid);
    assert!(owner.request_persist(2, runtime.clone(), BTreeMap::new(), state_now(0)));
    assert!(owner.wait_for_persisted(2).await);
    assert_eq!(owner.status(), StorageStatus::Writable);
    owner.shutdown().await;

    fs::remove_file(&cache).unwrap();
    fs::create_dir(&cache).unwrap();
    let blocked =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert!(
        blocked
            .load_evidence(runtime.clone(), state_now(0))
            .await
            .is_empty()
    );
    assert_eq!(blocked.status(), StorageStatus::Untrusted);
    assert!(!blocked.request_persist(3, runtime, BTreeMap::new(), state_now(0)));
    assert!(cache.is_dir());
    blocked.shutdown().await;
}

#[tokio::test]
async fn cache_storage_recovers_only_bounded_exact_prefix_temporaries() {
    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let temporary = "capabilities-v1.tmp-00112233445566778899aabbccddeeff";
    create_cache_temporary_for_test(config.path(), temporary, b"interrupted").unwrap();
    let unrelated = config.path().join("transcoding/keep-me.txt");
    fs::write(&unrelated, b"preserve").unwrap();

    let storage =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(storage.status(), StorageStatus::Writable);
    assert!(!config.path().join("transcoding").join(temporary).exists());
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserve");
    storage.shutdown().await;

    let suspicious = "capabilities-v1.tmp-not-a-random-suffix";
    fs::write(config.path().join("transcoding").join(suspicious), b"x").unwrap();
    let disabled =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(disabled.status(), StorageStatus::Untrusted);
    assert!(config.path().join("transcoding").join(suspicious).exists());
    disabled.shutdown().await;
}

#[tokio::test]
async fn cache_storage_recovery_overflow_preserves_every_entry_and_disables_writes() {
    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let mut names = Vec::new();
    for index in 0_u128..17 {
        let name = format!("capabilities-v1.tmp-{index:032x}");
        create_cache_temporary_for_test(config.path(), &name, b"interrupted").unwrap();
        names.push(name);
    }

    let storage =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(storage.status(), StorageStatus::Untrusted);
    assert!(
        names
            .iter()
            .all(|name| config.path().join("transcoding").join(name).exists())
    );
    storage.shutdown().await;
}

#[tokio::test]
async fn cache_storage_coalesces_pending_revisions_without_blocking_tokio_workers() {
    let config = new_config_directory();
    let hooks = Arc::new(PersistenceTestHooks::new());
    let storage = EvidenceStorage::open_with_test_hooks(
        config.path().to_path_buf(),
        CancellationToken::new(),
        Arc::clone(&hooks),
    )
    .await;
    let (runtime, _, _, _) = test_common();
    assert!(storage.request_persist(1, runtime.clone(), BTreeMap::new(), state_now(0)));
    hooks.wait_until_entered().await;

    assert!(storage.request_persist(2, runtime.clone(), BTreeMap::new(), state_now(0)));
    let key = CapabilityKey::complete_test_keys().remove(0);
    let records = BTreeMap::from([(
        key.clone(),
        cache_record(key, EvidenceOutcome::CorrectnessPassed, 0),
    )]);
    assert!(storage.request_persist(3, runtime.clone(), records.clone(), state_now(0)));
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::task::yield_now().await;
    })
    .await
    .expect("paused native persistence does not block Tokio workers");

    hooks.release_one();
    hooks.wait_until_entered().await;
    hooks.release_one();
    assert!(storage.wait_for_persisted(3).await);
    assert_eq!(storage.load_evidence(runtime, state_now(0)).await, records);
    assert!(
        fs::read_dir(config.path().join("transcoding"))
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with("capabilities-v1.tmp-"))
    );
    storage.shutdown().await;
}

#[tokio::test]
async fn cache_storage_shutdown_joins_native_work_before_releasing_lifetime_lock() {
    let config = new_config_directory();
    let hooks = Arc::new(PersistenceTestHooks::new());
    let storage = Arc::new(
        EvidenceStorage::open_with_test_hooks(
            config.path().to_path_buf(),
            CancellationToken::new(),
            Arc::clone(&hooks),
        )
        .await,
    );
    let (runtime, _, _, _) = test_common();
    assert!(storage.request_persist(1, runtime, BTreeMap::new(), state_now(0)));
    hooks.wait_until_entered().await;

    let shutdown_owner = Arc::clone(&storage);
    let shutdown = tokio::spawn(async move { shutdown_owner.shutdown().await });
    let second_shutdown_owner = Arc::clone(&storage);
    let second_shutdown = tokio::spawn(async move { second_shutdown_owner.shutdown().await });
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    assert!(!second_shutdown.is_finished());
    let contender =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(contender.status(), StorageStatus::ReadOnlyLocked);

    hooks.release_one();
    shutdown.await.unwrap();
    second_shutdown.await.unwrap();
    assert!(
        !config
            .path()
            .join("transcoding/capabilities-v1.json")
            .exists()
    );
    assert!(
        fs::read_dir(config.path().join("transcoding"))
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| !entry
                .file_name()
                .to_string_lossy()
                .starts_with("capabilities-v1.tmp-"))
    );
    let replacement =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(replacement.status(), StorageStatus::Writable);
    contender.shutdown().await;
    replacement.shutdown().await;
}

const CACHE_STORAGE_HELPER_CONFIG: &str = "STREAM_SERVER_TEST_CACHE_CONFIG";
const CACHE_STORAGE_HELPER_STATUS: &str = "STREAM_SERVER_TEST_CACHE_STATUS";

#[test]
fn cache_storage_cross_process_helper() {
    let Ok(config) = std::env::var(CACHE_STORAGE_HELPER_CONFIG) else {
        return;
    };
    let expected = std::env::var(CACHE_STORAGE_HELPER_STATUS).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let storage = EvidenceStorage::open(config.into(), CancellationToken::new()).await;
        let expected = match expected.as_str() {
            "writable" => StorageStatus::Writable,
            "readOnlyLocked" => StorageStatus::ReadOnlyLocked,
            _ => panic!("invalid closed helper expectation"),
        };
        assert_eq!(storage.status(), expected);
        storage.shutdown().await;
    });
}

#[tokio::test]
async fn cache_storage_lifetime_lock_is_exclusive_across_processes() {
    async fn run_helper(config: std::path::PathBuf, expected: &'static str) {
        let status = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "transcoding::capability::tests::cache_storage_cross_process_helper",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CACHE_STORAGE_HELPER_CONFIG, config)
                .env(CACHE_STORAGE_HELPER_STATUS, expected)
                .status()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(status.success());
    }

    let config = new_config_directory();
    let parent_cancellation = CancellationToken::new();
    let owner =
        EvidenceStorage::open(config.path().to_path_buf(), parent_cancellation.clone()).await;
    assert_eq!(owner.status(), StorageStatus::Writable);
    run_helper(config.path().to_path_buf(), "readOnlyLocked").await;
    owner.shutdown().await;
    assert!(!parent_cancellation.is_cancelled());
    run_helper(config.path().to_path_buf(), "writable").await;
}

#[tokio::test]
async fn cache_storage_rejects_a_wrong_type_lifetime_lock_without_replacing_it() {
    let config = new_config_directory();
    load_or_create_device_seed(config.path(), &CancellationToken::new()).unwrap();
    let lock = config.path().join("transcoding/capabilities.lock");
    fs::create_dir(&lock).unwrap();
    let storage =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    assert_eq!(storage.status(), StorageStatus::Untrusted);
    assert!(lock.is_dir());
    storage.shutdown().await;
}

#[cfg(windows)]
#[tokio::test]
async fn cache_storage_windows_lifetime_lock_cannot_be_replaced_while_owned() {
    let config = new_config_directory();
    let storage =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    let lock = config.path().join("transcoding/capabilities.lock");
    assert!(fs::remove_file(&lock).is_err());
    storage.shutdown().await;
    fs::remove_file(lock).unwrap();
}

#[tokio::test]
async fn cache_storage_bounded_read_rejects_oversize_content_and_can_replace_it() {
    let config = new_config_directory();
    let storage =
        EvidenceStorage::open(config.path().to_path_buf(), CancellationToken::new()).await;
    let (runtime, _, _, _) = test_common();
    assert!(storage.request_persist(1, runtime.clone(), BTreeMap::new(), state_now(0)));
    assert!(storage.wait_for_persisted(1).await);
    let cache = config.path().join("transcoding/capabilities-v1.json");
    fs::write(&cache, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    assert!(
        storage
            .load_evidence(runtime.clone(), state_now(0))
            .await
            .is_empty()
    );
    assert_eq!(storage.status(), StorageStatus::Invalid);
    assert!(storage.request_persist(2, runtime, BTreeMap::new(), state_now(0)));
    assert!(storage.wait_for_persisted(2).await);
    assert_eq!(storage.status(), StorageStatus::Writable);
    assert!(fs::metadata(cache).unwrap().len() < 8 * 1024 * 1024);
    storage.shutdown().await;
}

#[tokio::test]
async fn cache_storage_replacement_failure_is_closed_and_preserves_the_wrong_object() {
    let config = new_config_directory();
    let hooks = Arc::new(PersistenceTestHooks::new());
    let storage = EvidenceStorage::open_with_test_hooks(
        config.path().to_path_buf(),
        CancellationToken::new(),
        Arc::clone(&hooks),
    )
    .await;
    let (runtime, _, _, _) = test_common();
    assert!(storage.request_persist(1, runtime, BTreeMap::new(), state_now(0)));
    hooks.wait_until_entered().await;
    let cache = config.path().join("transcoding/capabilities-v1.json");
    fs::create_dir(&cache).unwrap();
    hooks.release_one();
    assert!(!storage.wait_for_persisted(1).await);
    assert_eq!(storage.status(), StorageStatus::PersistFailed);
    assert!(cache.is_dir());
    storage.shutdown().await;
}

fn new_config_directory() -> tempfile::TempDir {
    #[cfg(windows)]
    {
        // Windows hosted-runner temp roots can contain reparse aliases. The
        // production storage policy correctly rejects those paths, so keep
        // protected-storage fixtures under the checked-out workspace.
        tempfile::Builder::new()
            .prefix(".stream-server-protected-test-")
            .tempdir_in(std::env::current_dir().expect("test workspace directory"))
            .expect("isolated protected config directory")
    }
    #[cfg(not(windows))]
    {
        tempfile::tempdir().expect("isolated config directory")
    }
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
