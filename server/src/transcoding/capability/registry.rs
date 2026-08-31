use std::{
    collections::BTreeMap,
    panic::AssertUnwindSafe,
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::FutureExt;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::transcoding::{
    CapabilityState,
    device::{
        DeviceAvailability, DeviceDiscoveryStatus, DeviceEnumerator, DeviceError, DriverRunEpoch,
        identity::DeviceIdSeed, normalize_platform_records, production_device_enumerator,
    },
    inventory::{
        InventoryError, PairedRuntimeInventorySource, StaticInventorySource, coarse_candidates,
    },
    runtime::TranscodingService,
    runtime_manifest::RuntimeError,
};

#[cfg(test)]
use std::collections::BTreeSet;

use super::{
    key::{CapabilityKey, RequiredFilter, RequiredTransfer, StaticPrerequisites},
    state::{
        EvidenceOutcome, EvidenceReason, EvidenceRecord, EvidenceTarget, EvidenceTimestamp,
        StateNow, VerificationResult, VerifierMode,
    },
    storage::{EvidenceStorage, StorageStatus, load_or_create_device_seed},
};
use crate::transcoding::{
    device::TranscodingDevice,
    inventory::{CoarseCandidate, FilterComponent, ListedDirection, RuntimeInventory},
};

#[cfg(test)]
use crate::transcoding::inventory::{InventoryUnknownCounts, SafeRuntimeVersion};

const MAX_DEVICES: usize = 32;
const MAX_CANDIDATES: usize = 1_024;
const MAX_EVIDENCE: usize = 3_072;
const MAX_COMBINED_ROWS: usize = 4_096;
const MAX_IN_FLIGHT_KEYS: usize = 64;
const MAX_QUEUED_KEYS: usize = 64;
const MAX_ACTIVE_GLOBAL: usize = 4;
const QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MANUAL_REFRESH_WINDOW: Duration = Duration::from_secs(60);
const REFRESH_WORKER_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotFreshness {
    Uninitialized,
    Refreshing,
    Fresh,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RefreshMetadata {
    pub(super) state: RefreshState,
    pub(super) id: Option<u64>,
    pub(super) cause: Option<RefreshCause>,
    pub(super) started_at: Option<EvidenceTimestamp>,
    pub(super) completed_at: Option<EvidenceTimestamp>,
    pub(super) outcome_reason: Option<RefreshOutcomeReason>,
    pub(super) persistence_status: StorageStatus,
}

impl RefreshMetadata {
    fn idle(persistence_status: StorageStatus) -> Self {
        Self {
            state: RefreshState::Idle,
            id: None,
            cause: None,
            started_at: None,
            completed_at: None,
            outcome_reason: None,
            persistence_status,
        }
    }

    #[cfg(test)]
    fn succeeded_for_test() -> Self {
        Self {
            state: RefreshState::Succeeded,
            id: Some(1),
            cause: Some(RefreshCause::Startup),
            started_at: Some(EvidenceTimestamp::new(0).expect("zero is bounded")),
            completed_at: Some(EvidenceTimestamp::new(1).expect("one is bounded")),
            outcome_reason: None,
            persistence_status: StorageStatus::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RefreshState {
    Idle,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshCause {
    Startup,
    Manual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RefreshOutcomeReason {
    PlatformUnsupported,
    DeviceIdentityUnavailable,
    DeviceMappingAmbiguous,
    DeviceEnumerationFailed,
    RuntimeUnavailable,
    InventoryTimeout,
    InventoryOverflow,
    InventoryMalformed,
    InventoryProcessFailed,
    RefreshCancelled,
    RefreshFailed,
}

impl RefreshOutcomeReason {
    #[allow(dead_code)]
    pub(super) const fn safe_code(self) -> &'static str {
        match self {
            Self::PlatformUnsupported => "platform_unsupported",
            Self::DeviceIdentityUnavailable => "device_identity_unavailable",
            Self::DeviceMappingAmbiguous => "device_mapping_ambiguous",
            Self::DeviceEnumerationFailed => "device_enumeration_failed",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::InventoryTimeout => "inventory_timeout",
            Self::InventoryOverflow => "inventory_overflow",
            Self::InventoryMalformed => "inventory_malformed",
            Self::InventoryProcessFailed => "inventory_process_failed",
            Self::RefreshCancelled => "refresh_cancelled",
            Self::RefreshFailed => "refresh_failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshAdmission {
    Started { id: u64 },
    Existing { id: u64 },
    RateLimited { retry_after_seconds: u64 },
    Rejected { reason: RegistryReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefreshFailure {
    Cancelled,
    Device(DeviceError),
    Inventory(InventoryError),
    RuntimeUnavailable,
    SnapshotInvalid,
}

impl RefreshFailure {
    const fn outcome_reason(self) -> RefreshOutcomeReason {
        match self {
            Self::Cancelled | Self::Device(DeviceError::Cancelled) => {
                RefreshOutcomeReason::RefreshCancelled
            }
            Self::Device(DeviceError::Ambiguous) => RefreshOutcomeReason::DeviceMappingAmbiguous,
            Self::Device(DeviceError::Overflow) => RefreshOutcomeReason::InventoryOverflow,
            Self::Device(DeviceError::Invalid) => RefreshOutcomeReason::DeviceEnumerationFailed,
            Self::Inventory(InventoryError::Timeout) => RefreshOutcomeReason::InventoryTimeout,
            Self::Inventory(InventoryError::Bounds) => RefreshOutcomeReason::InventoryOverflow,
            Self::Inventory(InventoryError::IdentityMismatch | InventoryError::Malformed) => {
                RefreshOutcomeReason::InventoryMalformed
            }
            Self::Inventory(InventoryError::ProcessFailed) => {
                RefreshOutcomeReason::InventoryProcessFailed
            }
            Self::Inventory(InventoryError::RuntimeChanged) | Self::RuntimeUnavailable => {
                RefreshOutcomeReason::RuntimeUnavailable
            }
            Self::Inventory(InventoryError::Cancelled) => RefreshOutcomeReason::RefreshCancelled,
            Self::SnapshotInvalid => RefreshOutcomeReason::RefreshFailed,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CapabilitySnapshot {
    freshness: SnapshotFreshness,
    identity_epoch: u64,
    publication_revision: u64,
    runtime: Option<RuntimeInventory>,
    devices: Vec<TranscodingDevice>,
    candidates: Vec<CoarseCandidate>,
    evidence: BTreeMap<CapabilityKey, EvidenceRecord>,
}

impl CapabilitySnapshot {
    fn uninitialized() -> Self {
        Self {
            freshness: SnapshotFreshness::Uninitialized,
            identity_epoch: 0,
            publication_revision: 0,
            runtime: None,
            devices: Vec::new(),
            candidates: Vec::new(),
            evidence: BTreeMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        freshness: SnapshotFreshness,
        identity_epoch: u64,
        publication_revision: u64,
        runtime: Option<RuntimeInventory>,
        devices: Vec<TranscodingDevice>,
        candidates: Vec<CoarseCandidate>,
        evidence: BTreeMap<CapabilityKey, EvidenceRecord>,
        now: StateNow,
    ) -> Result<Self, SnapshotError> {
        let snapshot = Self {
            freshness,
            identity_epoch,
            publication_revision,
            runtime,
            devices,
            candidates,
            evidence,
        };
        snapshot.validate(now)?;
        Ok(snapshot)
    }

    pub(super) fn evidence(&self) -> &BTreeMap<CapabilityKey, EvidenceRecord> {
        &self.evidence
    }

    pub(crate) const fn freshness(&self) -> SnapshotFreshness {
        self.freshness
    }

    pub(super) const fn identity_epoch(&self) -> u64 {
        self.identity_epoch
    }

    pub(super) const fn publication_revision(&self) -> u64 {
        self.publication_revision
    }

    #[cfg(test)]
    pub(super) fn devices_for_test(&self) -> &[TranscodingDevice] {
        &self.devices
    }

    #[cfg(test)]
    pub(crate) fn runtime_for_test(&self) -> Option<&RuntimeInventory> {
        self.runtime.as_ref()
    }

    fn validate(&self, now: StateNow) -> Result<(), SnapshotError> {
        if self.identity_epoch > MAX_SAFE_INTEGER
            || self.publication_revision > MAX_SAFE_INTEGER
            || self.devices.len() > MAX_DEVICES
            || self.candidates.len() > MAX_CANDIDATES
            || self.evidence.len() > MAX_EVIDENCE
            || self
                .candidates
                .len()
                .checked_add(self.evidence.len())
                .is_none_or(|rows| rows > MAX_COMBINED_ROWS)
        {
            return Err(SnapshotError::Bounds);
        }
        if self.freshness == SnapshotFreshness::Uninitialized
            && (self.identity_epoch != 0
                || self.publication_revision != 0
                || self.runtime.is_some()
                || !self.devices.is_empty()
                || !self.candidates.is_empty()
                || !self.evidence.is_empty())
        {
            return Err(SnapshotError::Invalid);
        }
        if self.freshness != SnapshotFreshness::Uninitialized
            && (self.identity_epoch == 0 || self.publication_revision == 0)
        {
            return Err(SnapshotError::Invalid);
        }
        if self.runtime.is_none() && (!self.candidates.is_empty() || !self.evidence.is_empty()) {
            return Err(SnapshotError::CrossReference);
        }
        if self
            .devices
            .windows(2)
            .any(|pair| pair[0].id.as_str() >= pair[1].id.as_str())
            || self.candidates.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(SnapshotError::Ordering);
        }
        for candidate in &self.candidates {
            let Some(device) = self
                .devices
                .iter()
                .find(|device| device.id == candidate.device)
            else {
                return Err(SnapshotError::CrossReference);
            };
            if !device.backends.contains(&candidate.backend) {
                return Err(SnapshotError::CrossReference);
            }
        }
        for (key, record) in &self.evidence {
            if key != &record.key
                || !key.is_valid()
                || !self.key_identity_matches(key)
                || !self.has_static_prerequisites(key)
                || record.validate(now).is_err()
            {
                return Err(SnapshotError::CrossReference);
            }
        }
        Ok(())
    }

    fn key_is_current(&self, key: &CapabilityKey) -> bool {
        self.freshness == SnapshotFreshness::Fresh && self.key_identity_matches(key)
    }

    fn key_identity_matches(&self, key: &CapabilityKey) -> bool {
        if self
            .runtime
            .as_ref()
            .is_none_or(|runtime| &runtime.runtime_id != key.runtime())
        {
            return false;
        }
        self.devices.iter().any(|device| {
            &device.id == key.device()
                && &device.driver_identity == key.driver()
                && device.availability == DeviceAvailability::Available
                && device.backends.contains(&key.backend())
        })
    }

    fn admits(&self, key: &CapabilityKey) -> bool {
        key.is_valid() && self.key_is_current(key) && self.has_static_prerequisites(key)
    }

    fn has_static_prerequisites(&self, key: &CapabilityKey) -> bool {
        let StaticPrerequisites {
            decode,
            encode,
            requirements,
        } = key.static_prerequisites();
        let has = |codec, direction| {
            self.candidates.binary_search(&CoarseCandidate {
                device: key.device().clone(),
                backend: key.backend(),
                codec,
                direction,
            })
        };
        decode.is_none_or(|codec| has(codec, ListedDirection::Decode).is_ok())
            && encode.is_none_or(|codec| has(codec, ListedDirection::Encode).is_ok())
            && requirements.is_none_or(|requirements| {
                let Some(runtime) = &self.runtime else {
                    return false;
                };
                requirements.filters.iter().all(|filter| {
                    required_filter_components(*filter).is_none_or(|components| {
                        components
                            .iter()
                            .any(|component| runtime.filters.contains(component))
                    })
                }) && requirements.transfers.iter().all(|transfer| {
                    required_transfer_component(*transfer)
                        .is_none_or(|component| runtime.filters.contains(&component))
                })
            })
    }
}

fn required_filter_components(filter: RequiredFilter) -> Option<&'static [FilterComponent]> {
    match filter {
        RequiredFilter::Format => Some(&[FilterComponent::Format]),
        RequiredFilter::Scale => Some(&[
            FilterComponent::ScaleSoftware,
            FilterComponent::ScaleCuda,
            FilterComponent::ScaleQsv,
            FilterComponent::ScaleVaapi,
        ]),
        RequiredFilter::Deinterlace => Some(&[
            FilterComponent::DeinterlaceSoftware,
            FilterComponent::DeinterlaceQsv,
            FilterComponent::DeinterlaceVaapi,
        ]),
        RequiredFilter::ToneMap => Some(&[
            FilterComponent::ToneMapSoftware,
            FilterComponent::ToneMapOpenCl,
            FilterComponent::ToneMapVaapi,
        ]),
        RequiredFilter::Subtitles => None,
        RequiredFilter::HardwareUpload => Some(&[FilterComponent::HardwareUpload]),
        RequiredFilter::HardwareDownload => Some(&[FilterComponent::HardwareDownload]),
        RequiredFilter::HardwareMap => Some(&[FilterComponent::HardwareMap]),
    }
}

const fn required_transfer_component(transfer: RequiredTransfer) -> Option<FilterComponent> {
    match transfer {
        RequiredTransfer::Upload => Some(FilterComponent::HardwareUpload),
        RequiredTransfer::Download => Some(FilterComponent::HardwareDownload),
        RequiredTransfer::HardwareMap => Some(FilterComponent::HardwareMap),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotError {
    Bounds,
    CrossReference,
    Invalid,
    Ordering,
}

#[derive(Clone)]
pub(super) struct RegistryPublication {
    pub(super) snapshot: Arc<CapabilitySnapshot>,
    pub(super) refresh: RefreshMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryReason {
    VerificationNotImplemented,
    VerificationStale,
    VerificationPrerequisiteMissing,
    VerificationCapacity,
    VerificationQueueTimeout,
    VerificationDeferredForPlayback,
    CapacityExhausted,
    ServerShutdown,
}

impl RegistryReason {
    pub(super) const fn safe_code(self) -> &'static str {
        match self {
            Self::VerificationNotImplemented => "verification_not_implemented",
            Self::VerificationStale => "verification_stale",
            Self::VerificationPrerequisiteMissing => "verification_prerequisite_missing",
            Self::VerificationCapacity => "verification_capacity",
            Self::VerificationQueueTimeout => "verification_queue_timeout",
            Self::VerificationDeferredForPlayback => "verification_deferred_for_playback",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::ServerShutdown => "server_shutdown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EnsureEvidenceResult {
    passing: bool,
    reason: Option<RegistryReason>,
}

impl EnsureEvidenceResult {
    const fn non_passing(reason: RegistryReason) -> Self {
        Self {
            passing: false,
            reason: Some(reason),
        }
    }

    pub(super) const fn is_non_passing(&self) -> bool {
        !self.passing
    }

    pub(super) const fn is_passing(&self) -> bool {
        self.passing
    }

    pub(super) const fn reason(&self) -> Option<RegistryReason> {
        self.reason
    }

    const fn from_outcome(outcome: EvidenceOutcome) -> Self {
        Self {
            passing: matches!(
                outcome,
                EvidenceOutcome::CorrectnessPassed | EvidenceOutcome::RealtimePassed
            ),
            reason: None,
        }
    }

    const fn evidence_non_passing() -> Self {
        Self {
            passing: false,
            reason: None,
        }
    }
}

#[derive(Clone)]
pub(super) struct VerificationRequest {
    pub(super) key: CapabilityKey,
    pub(super) target: EvidenceTarget,
    pub(super) identity_epoch: u64,
}

#[async_trait]
pub(super) trait CapabilityVerifier: Send + Sync {
    fn mode(&self) -> VerifierMode;

    async fn verify(
        &self,
        request: VerificationRequest,
        cancellation: CancellationToken,
    ) -> VerificationResult;
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct UnknownVerifier;

#[async_trait]
impl CapabilityVerifier for UnknownVerifier {
    fn mode(&self) -> VerifierMode {
        VerifierMode::ObservationalOnly
    }

    async fn verify(
        &self,
        request: VerificationRequest,
        _cancellation: CancellationToken,
    ) -> VerificationResult {
        let _ = request.key;
        let observed_at = EvidenceTimestamp::new(0).expect("zero is bounded");
        VerificationResult::new(
            request.target,
            EvidenceOutcome::NotPresent,
            Some(EvidenceReason::VerificationNotImplemented),
            observed_at,
            0,
            EvidenceTimestamp::new(1).expect("one is bounded"),
        )
        .expect("closed unknown-verifier result")
    }
}

pub(super) trait PlaybackPriority: Send + Sync {
    fn playback_active(&self) -> bool;
}

#[derive(Default)]
struct NoPlaybackPriority;

impl PlaybackPriority for NoPlaybackPriority {
    fn playback_active(&self) -> bool {
        false
    }
}

trait RegistryClock: Send + Sync {
    fn now(&self) -> Result<StateNow, RegistryReason>;
}

struct SystemRegistryClock {
    started: Instant,
}

impl SystemRegistryClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl RegistryClock for SystemRegistryClock {
    fn now(&self) -> Result<StateNow, RegistryReason> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RegistryReason::CapacityExhausted)?
            .as_millis();
        let wall = u64::try_from(wall).map_err(|_| RegistryReason::CapacityExhausted)?;
        let monotonic = u64::try_from(self.started.elapsed().as_millis())
            .map_err(|_| RegistryReason::CapacityExhausted)?;
        StateNow::new(
            EvidenceTimestamp::new(wall).map_err(|_| RegistryReason::CapacityExhausted)?,
            monotonic,
        )
        .map_err(|_| RegistryReason::CapacityExhausted)
    }
}

struct Flight {
    target: EvidenceTarget,
    epoch: u64,
    sender: watch::Sender<Option<EnsureEvidenceResult>>,
    cancellation: CancellationToken,
}

struct FlightState {
    terminal_reason: Option<RegistryReason>,
    admission_paused: bool,
    identity_epoch: u64,
    queued: usize,
    flights: BTreeMap<CapabilityKey, Arc<Flight>>,
    device_semaphores: BTreeMap<crate::transcoding::DeviceId, Arc<Semaphore>>,
}

impl FlightState {
    fn new(identity_epoch: u64) -> Self {
        Self {
            terminal_reason: None,
            admission_paused: false,
            identity_epoch,
            queued: 0,
            flights: BTreeMap::new(),
            device_semaphores: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct EmptyDeviceEnumerator;

#[async_trait]
impl DeviceEnumerator for EmptyDeviceEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<crate::transcoding::device::DeviceDiscovery, DeviceError> {
        if cancellation.is_cancelled() {
            Err(DeviceError::Cancelled)
        } else {
            Ok(crate::transcoding::device::DeviceDiscovery::supported(
                Vec::new(),
            ))
        }
    }
}

struct RefreshDependencies {
    enumerator: Arc<dyn DeviceEnumerator>,
    inventory: Arc<dyn StaticInventorySource>,
    seed: Option<DeviceIdSeed>,
    driver_run_epoch: Option<DriverRunEpoch>,
    storage: Arc<EvidenceStorage>,
    worker_deadline: Duration,
}

impl RefreshDependencies {
    fn ephemeral() -> Self {
        Self {
            enumerator: Arc::new(EmptyDeviceEnumerator),
            inventory: Arc::new(PairedRuntimeInventorySource),
            seed: None,
            driver_run_epoch: None,
            storage: Arc::new(EvidenceStorage::disabled(
                StorageStatus::Unavailable,
                CancellationToken::new(),
            )),
            worker_deadline: REFRESH_WORKER_DEADLINE,
        }
    }
}

#[derive(Clone, Copy)]
struct RunningRefresh {
    id: u64,
    cause: RefreshCause,
    epoch: u64,
    admitted_revision: u64,
}

#[derive(Default)]
struct RefreshControl {
    next_id: u64,
    running: Option<RunningRefresh>,
    startup_id: Option<u64>,
    last_manual_monotonic_ms: Option<u64>,
}

struct RefreshInvalidation {
    epoch: u64,
    admitted_revision: u64,
    previous: Arc<CapabilitySnapshot>,
}

struct RefreshCandidate {
    runtime: Option<RuntimeInventory>,
    devices: Vec<TranscodingDevice>,
    candidates: Vec<CoarseCandidate>,
    evidence: BTreeMap<CapabilityKey, EvidenceRecord>,
    outcome_reason: Option<RefreshOutcomeReason>,
}

struct RegistryShared {
    publication: RwLock<RegistryPublication>,
    flights: Mutex<FlightState>,
    verifier: Arc<dyn CapabilityVerifier>,
    playback: Arc<dyn PlaybackPriority>,
    clock: Arc<dyn RegistryClock>,
    verifier_invocations: AtomicU64,
    capacity_exhausted: CancellationToken,
    global_semaphore: Arc<Semaphore>,
    tasks: TaskTracker,
    flights_changed: Notify,
    refresh: Mutex<RefreshControl>,
    refresh_changed: Notify,
    refresh_dependencies: RefreshDependencies,
    lifecycle_gate: StdMutex<()>,
    shutdown: CancellationToken,
}

pub(crate) struct CapabilityRegistry {
    shared: Arc<RegistryShared>,
}

impl CapabilityRegistry {
    pub(super) fn new(verifier: Arc<dyn CapabilityVerifier>) -> Self {
        Self::with_publication(
            verifier,
            Arc::new(NoPlaybackPriority),
            Arc::new(SystemRegistryClock::new()),
            RegistryPublication {
                snapshot: Arc::new(CapabilitySnapshot::uninitialized()),
                refresh: RefreshMetadata::idle(StorageStatus::Unavailable),
            },
            0,
        )
    }

    pub(crate) fn uninitialized() -> Arc<Self> {
        Arc::new(Self::new(Arc::new(UnknownVerifier)))
    }

    pub(crate) async fn production(config_directory: PathBuf) -> Arc<Self> {
        let seed_directory = config_directory.clone();
        let seed_cancellation = CancellationToken::new();
        let seed_worker_cancellation = seed_cancellation.clone();
        let seed = tokio::task::spawn_blocking(move || {
            load_or_create_device_seed(&seed_directory, &seed_worker_cancellation)
        })
        .await
        .ok()
        .and_then(Result::ok);
        let driver_run_epoch = DriverRunEpoch::generate().ok();
        let storage = Arc::new(
            EvidenceStorage::open(config_directory, seed_cancellation.child_token()).await,
        );
        Arc::new(Self::with_publication_and_dependencies(
            Arc::new(UnknownVerifier),
            Arc::new(NoPlaybackPriority),
            Arc::new(SystemRegistryClock::new()),
            RegistryPublication {
                snapshot: Arc::new(CapabilitySnapshot::uninitialized()),
                refresh: RefreshMetadata::idle(storage.status()),
            },
            0,
            RefreshDependencies {
                enumerator: production_device_enumerator(),
                inventory: Arc::new(PairedRuntimeInventorySource),
                seed,
                driver_run_epoch,
                storage,
                worker_deadline: REFRESH_WORKER_DEADLINE,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn ephemeral_for_test() -> Arc<Self> {
        Self::uninitialized()
    }

    #[cfg(test)]
    pub(crate) fn with_refresh_dependencies_for_test(
        enumerator: Arc<dyn DeviceEnumerator>,
        inventory: Arc<dyn StaticInventorySource>,
        seed: Option<DeviceIdSeed>,
        driver_run_epoch: Option<DriverRunEpoch>,
    ) -> Arc<Self> {
        Self::with_refresh_dependencies_and_deadline_for_test(
            enumerator,
            inventory,
            seed,
            driver_run_epoch,
            REFRESH_WORKER_DEADLINE,
        )
    }

    #[cfg(test)]
    pub(super) fn with_refresh_dependencies_and_clock_for_test(
        enumerator: Arc<dyn DeviceEnumerator>,
        inventory: Arc<dyn StaticInventorySource>,
        seed: Option<DeviceIdSeed>,
        driver_run_epoch: Option<DriverRunEpoch>,
    ) -> (Arc<Self>, TestRegistryClock) {
        let clock = TestRegistryClock::new();
        let registry = Arc::new(Self::with_publication_and_dependencies(
            Arc::new(UnknownVerifier),
            Arc::new(NoPlaybackPriority),
            Arc::new(clock.clone()),
            RegistryPublication {
                snapshot: Arc::new(CapabilitySnapshot::uninitialized()),
                refresh: RefreshMetadata::idle(StorageStatus::Unavailable),
            },
            0,
            RefreshDependencies {
                enumerator,
                inventory,
                seed,
                driver_run_epoch,
                storage: Arc::new(EvidenceStorage::disabled(
                    StorageStatus::Unavailable,
                    CancellationToken::new(),
                )),
                worker_deadline: REFRESH_WORKER_DEADLINE,
            },
        ));
        (registry, clock)
    }

    #[cfg(test)]
    pub(crate) fn with_refresh_dependencies_and_storage_status_for_test(
        enumerator: Arc<dyn DeviceEnumerator>,
        inventory: Arc<dyn StaticInventorySource>,
        seed: Option<DeviceIdSeed>,
        driver_run_epoch: Option<DriverRunEpoch>,
        storage_status: StorageStatus,
    ) -> Arc<Self> {
        Arc::new(Self::with_publication_and_dependencies(
            Arc::new(UnknownVerifier),
            Arc::new(NoPlaybackPriority),
            Arc::new(FixedRegistryClock),
            RegistryPublication {
                snapshot: Arc::new(CapabilitySnapshot::uninitialized()),
                refresh: RefreshMetadata::idle(storage_status),
            },
            0,
            RefreshDependencies {
                enumerator,
                inventory,
                seed,
                driver_run_epoch,
                storage: Arc::new(EvidenceStorage::disabled(
                    storage_status,
                    CancellationToken::new(),
                )),
                worker_deadline: REFRESH_WORKER_DEADLINE,
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn with_persist_failed_storage_for_test(
        enumerator: Arc<dyn DeviceEnumerator>,
        inventory: Arc<dyn StaticInventorySource>,
        seed: Option<DeviceIdSeed>,
        driver_run_epoch: Option<DriverRunEpoch>,
    ) -> Arc<Self> {
        Self::with_refresh_dependencies_and_storage_status_for_test(
            enumerator,
            inventory,
            seed,
            driver_run_epoch,
            StorageStatus::PersistFailed,
        )
    }

    #[cfg(test)]
    pub(super) fn with_refresh_dependencies_and_deadline_for_test(
        enumerator: Arc<dyn DeviceEnumerator>,
        inventory: Arc<dyn StaticInventorySource>,
        seed: Option<DeviceIdSeed>,
        driver_run_epoch: Option<DriverRunEpoch>,
        worker_deadline: Duration,
    ) -> Arc<Self> {
        Arc::new(Self::with_publication_and_dependencies(
            Arc::new(UnknownVerifier),
            Arc::new(NoPlaybackPriority),
            Arc::new(FixedRegistryClock),
            RegistryPublication {
                snapshot: Arc::new(CapabilitySnapshot::uninitialized()),
                refresh: RefreshMetadata::idle(StorageStatus::Unavailable),
            },
            0,
            RefreshDependencies {
                enumerator,
                inventory,
                seed,
                driver_run_epoch,
                storage: Arc::new(EvidenceStorage::disabled(
                    StorageStatus::Unavailable,
                    CancellationToken::new(),
                )),
                worker_deadline,
            },
        ))
    }

    fn with_publication(
        verifier: Arc<dyn CapabilityVerifier>,
        playback: Arc<dyn PlaybackPriority>,
        clock: Arc<dyn RegistryClock>,
        publication: RegistryPublication,
        identity_epoch: u64,
    ) -> Self {
        Self::with_publication_and_dependencies(
            verifier,
            playback,
            clock,
            publication,
            identity_epoch,
            RefreshDependencies::ephemeral(),
        )
    }

    fn with_publication_and_dependencies(
        verifier: Arc<dyn CapabilityVerifier>,
        playback: Arc<dyn PlaybackPriority>,
        clock: Arc<dyn RegistryClock>,
        publication: RegistryPublication,
        identity_epoch: u64,
        refresh_dependencies: RefreshDependencies,
    ) -> Self {
        Self {
            shared: Arc::new(RegistryShared {
                publication: RwLock::new(publication),
                flights: Mutex::new(FlightState::new(identity_epoch)),
                verifier,
                playback,
                clock,
                verifier_invocations: AtomicU64::new(0),
                capacity_exhausted: CancellationToken::new(),
                global_semaphore: Arc::new(Semaphore::new(MAX_ACTIVE_GLOBAL)),
                tasks: TaskTracker::new(),
                flights_changed: Notify::new(),
                refresh: Mutex::new(RefreshControl::default()),
                refresh_changed: Notify::new(),
                refresh_dependencies,
                lifecycle_gate: StdMutex::new(()),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    pub(crate) async fn snapshot(&self) -> Arc<CapabilitySnapshot> {
        Arc::clone(&self.shared.publication.read().await.snapshot)
    }

    pub(super) async fn publication(&self) -> RegistryPublication {
        self.shared.publication.read().await.clone()
    }

    pub(super) async fn ensure_evidence(
        &self,
        key: CapabilityKey,
        target: EvidenceTarget,
    ) -> EnsureEvidenceResult {
        if self.shared.shutdown.is_cancelled() {
            return EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown);
        }
        if self.shared.capacity_exhausted.is_cancelled() {
            return EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted);
        }
        if self.shared.verifier.mode() == VerifierMode::ObservationalOnly {
            return EnsureEvidenceResult::non_passing(RegistryReason::VerificationNotImplemented);
        }
        if self.shared.playback.playback_active() {
            return EnsureEvidenceResult::non_passing(
                RegistryReason::VerificationDeferredForPlayback,
            );
        }

        let snapshot = self.snapshot().await;
        if !snapshot.admits(&key) {
            return EnsureEvidenceResult::non_passing(
                RegistryReason::VerificationPrerequisiteMissing,
            );
        }
        let now = match self.shared.clock.now() {
            Ok(now) => now,
            Err(reason) => return EnsureEvidenceResult::non_passing(reason),
        };
        if let Some(existing) = snapshot.evidence.get(&key) {
            let mut existing = existing.clone();
            if matches!(
                existing.project(now, super::state::ProjectionContext::new(false, false),),
                Some(CapabilityState::CircuitOpen | CapabilityState::Failed)
            ) {
                return EnsureEvidenceResult::evidence_non_passing();
            }
            if existing.target_is_current(target, now) {
                return EnsureEvidenceResult::from_outcome(match target {
                    EvidenceTarget::Realtime => EvidenceOutcome::RealtimePassed,
                    EvidenceTarget::Correctness | EvidenceTarget::Segmented => {
                        EvidenceOutcome::CorrectnessPassed
                    }
                });
            }
        }
        let epoch = snapshot.identity_epoch;
        let mut flights = self.shared.flights.lock().await;
        if self.shared.shutdown.is_cancelled() {
            return EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown);
        }
        if self.shared.capacity_exhausted.is_cancelled() {
            return EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted);
        }
        if let Some(reason) = flights.terminal_reason {
            return EnsureEvidenceResult::non_passing(reason);
        }
        if flights.admission_paused || flights.identity_epoch != epoch {
            return EnsureEvidenceResult::non_passing(RegistryReason::VerificationStale);
        }
        if let Some(flight) = flights.flights.get(&key) {
            if flight.target != target {
                return EnsureEvidenceResult::non_passing(RegistryReason::VerificationCapacity);
            }
            let receiver = flight.sender.subscribe();
            drop(flights);
            return wait_for_flight(receiver, self.shared.shutdown.clone()).await;
        }
        if flights.flights.len() >= MAX_IN_FLIGHT_KEYS || flights.queued >= MAX_QUEUED_KEYS {
            return EnsureEvidenceResult::non_passing(RegistryReason::VerificationCapacity);
        }
        flights.queued = match flights.queued.checked_add(1) {
            Some(queued) => queued,
            None => {
                return EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted);
            }
        };
        let (sender, receiver) = watch::channel(None);
        let flight = Arc::new(Flight {
            target,
            epoch,
            sender,
            cancellation: CancellationToken::new(),
        });
        let device_semaphore = flights
            .device_semaphores
            .entry(key.device().clone())
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone();
        flights.flights.insert(key.clone(), Arc::clone(&flight));
        drop(flights);

        let mut pending_task = Some((key, flight, device_semaphore));
        let spawned = {
            let _lifecycle = self
                .shared
                .lifecycle_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.shared.shutdown.is_cancelled() {
                false
            } else {
                let (task_key, task_flight, task_device_semaphore) = pending_task
                    .take()
                    .expect("verification task ownership is present");
                let shared = Arc::clone(&self.shared);
                self.shared.tasks.spawn(async move {
                    run_verification(shared, task_key, task_flight, task_device_semaphore).await;
                });
                true
            }
        };
        if !spawned {
            let (key, flight, device_semaphore) = pending_task
                .take()
                .expect("unspawned verification ownership is present");
            decrement_queued(&self.shared).await;
            let result = EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown);
            finish_flight(
                &self.shared,
                &key,
                &flight,
                &device_semaphore,
                result.clone(),
            )
            .await;
            return result;
        }
        wait_for_flight(receiver, self.shared.shutdown.clone()).await
    }

    pub(crate) fn begin_shutdown(&self) {
        let _lifecycle = self
            .shared
            .lifecycle_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.shared.shutdown.cancel();
        self.shared.tasks.close();
        self.shared.refresh_dependencies.storage.begin_shutdown();
        self.shared.refresh_changed.notify_waiters();
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        let cancellations = {
            let mut flights = self.shared.flights.lock().await;
            flights.terminal_reason = Some(RegistryReason::ServerShutdown);
            flights
                .flights
                .values()
                .map(|flight| flight.cancellation.clone())
                .collect::<Vec<_>>()
        };
        for cancellation in cancellations {
            cancellation.cancel();
        }
        self.shared.tasks.wait().await;
        self.shared.refresh_dependencies.storage.shutdown().await;
    }

    #[cfg(test)]
    pub(super) fn fresh_for_test(
        key: CapabilityKey,
        verifier: impl CapabilityVerifier + 'static,
    ) -> Self {
        Self::fresh_for_test_with(key, verifier, Arc::new(NoPlaybackPriority))
    }

    #[cfg(test)]
    pub(super) fn circuit_open_with_refresh_dependencies_for_test(
        key: CapabilityKey,
        enumerator: Arc<dyn DeviceEnumerator>,
        inventory: Arc<dyn StaticInventorySource>,
    ) -> Arc<Self> {
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(key.clone());
        record
            .apply(
                VerificationResult::for_test(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::TemporaryFailure,
                    EvidenceReason::VerificationFailed,
                    0,
                ),
                VerifierMode::ActiveInjected,
                now,
            )
            .expect("valid circuit-open fixture");
        snapshot.evidence.insert(key, record);
        snapshot.validate(now).expect("valid circuit-open snapshot");
        Arc::new(Self::with_publication_and_dependencies(
            Arc::new(UnknownVerifier),
            Arc::new(NoPlaybackPriority),
            Arc::new(FixedRegistryClock),
            RegistryPublication {
                snapshot: Arc::new(snapshot),
                refresh: RefreshMetadata::succeeded_for_test(),
            },
            1,
            RefreshDependencies {
                enumerator,
                inventory,
                seed: None,
                driver_run_epoch: None,
                storage: Arc::new(EvidenceStorage::disabled(
                    StorageStatus::Unavailable,
                    CancellationToken::new(),
                )),
                worker_deadline: REFRESH_WORKER_DEADLINE,
            },
        ))
    }

    #[cfg(test)]
    pub(super) fn fresh_for_test_with(
        key: CapabilityKey,
        verifier: impl CapabilityVerifier + 'static,
        playback: Arc<dyn PlaybackPriority>,
    ) -> Self {
        Self::fresh_for_test_keys_with(vec![key], verifier, playback)
    }

    #[cfg(test)]
    pub(super) fn fresh_for_test_keys(
        keys: Vec<CapabilityKey>,
        verifier: impl CapabilityVerifier + 'static,
    ) -> Self {
        Self::fresh_for_test_keys_with(keys, verifier, Arc::new(NoPlaybackPriority))
    }

    #[cfg(test)]
    pub(super) fn fresh_for_test_keys_with(
        keys: Vec<CapabilityKey>,
        verifier: impl CapabilityVerifier + 'static,
        playback: Arc<dyn PlaybackPriority>,
    ) -> Self {
        let snapshot = test_snapshot_for_keys(&keys);
        Self::from_test_snapshot(snapshot, verifier, playback)
    }

    #[cfg(test)]
    pub(super) fn with_freshness_for_test(
        key: CapabilityKey,
        verifier: impl CapabilityVerifier + 'static,
        freshness: SnapshotFreshness,
    ) -> Self {
        let snapshot = test_snapshot_for_keys(&[key]);
        let snapshot = CapabilitySnapshot::from_parts(
            freshness,
            snapshot.identity_epoch,
            snapshot.publication_revision,
            snapshot.runtime,
            snapshot.devices,
            snapshot.candidates,
            snapshot.evidence,
            StateNow::from_test_minutes(0),
        )
        .expect("valid non-authorizing test snapshot");
        Self::from_test_snapshot(snapshot, verifier, Arc::new(NoPlaybackPriority))
    }

    #[cfg(test)]
    pub(super) fn without_candidates_for_test(
        key: CapabilityKey,
        verifier: impl CapabilityVerifier + 'static,
    ) -> Self {
        let snapshot = test_snapshot_for_keys(&[key]);
        let snapshot = CapabilitySnapshot::from_parts(
            snapshot.freshness,
            snapshot.identity_epoch,
            snapshot.publication_revision,
            snapshot.runtime,
            snapshot.devices,
            Vec::new(),
            snapshot.evidence,
            StateNow::from_test_minutes(0),
        )
        .expect("valid candidate-free test snapshot");
        Self::from_test_snapshot(snapshot, verifier, Arc::new(NoPlaybackPriority))
    }

    #[cfg(test)]
    pub(super) fn without_filters_for_test(
        key: CapabilityKey,
        verifier: impl CapabilityVerifier + 'static,
    ) -> Self {
        let snapshot = test_snapshot_for_keys(&[key]);
        let mut runtime = snapshot.runtime.expect("fresh fixture runtime");
        runtime.filters.clear();
        let snapshot = CapabilitySnapshot::from_parts(
            snapshot.freshness,
            snapshot.identity_epoch,
            snapshot.publication_revision,
            Some(runtime),
            snapshot.devices,
            snapshot.candidates,
            snapshot.evidence,
            StateNow::from_test_minutes(0),
        )
        .expect("valid filter-free test snapshot");
        Self::from_test_snapshot(snapshot, verifier, Arc::new(NoPlaybackPriority))
    }

    #[cfg(test)]
    fn from_test_snapshot(
        snapshot: CapabilitySnapshot,
        verifier: impl CapabilityVerifier + 'static,
        playback: Arc<dyn PlaybackPriority>,
    ) -> Self {
        Self::with_publication(
            Arc::new(verifier),
            playback,
            Arc::new(FixedRegistryClock),
            RegistryPublication {
                snapshot: Arc::new(snapshot),
                refresh: RefreshMetadata::succeeded_for_test(),
            },
            1,
        )
    }

    #[cfg(test)]
    pub(super) fn at_evidence_capacity_for_test(
        keys: Vec<CapabilityKey>,
        verifier: impl CapabilityVerifier + 'static,
    ) -> (Self, TestRegistryClock) {
        assert_eq!(keys.len(), MAX_EVIDENCE + 1);
        let base = test_snapshot_for_keys(&keys);
        let now = StateNow::from_test_minutes(0);
        let mut evidence = BTreeMap::new();
        for key in &keys[..MAX_EVIDENCE] {
            let mut record = EvidenceRecord::new(key.clone());
            record
                .apply(
                    VerificationResult::for_test(
                        EvidenceTarget::Correctness,
                        EvidenceOutcome::CorrectnessPassed,
                        EvidenceReason::VerificationFailed,
                        0,
                    ),
                    VerifierMode::ActiveInjected,
                    now,
                )
                .expect("valid capacity fixture evidence");
            evidence.insert(key.clone(), record);
        }
        let snapshot = CapabilitySnapshot::from_parts(
            base.freshness,
            base.identity_epoch,
            base.publication_revision,
            base.runtime,
            base.devices,
            base.candidates,
            evidence,
            now,
        )
        .expect("valid full evidence snapshot");
        let clock = TestRegistryClock::new();
        let registry = Self::with_publication(
            Arc::new(verifier),
            Arc::new(NoPlaybackPriority),
            Arc::new(clock.clone()),
            RegistryPublication {
                snapshot: Arc::new(snapshot),
                refresh: RefreshMetadata::succeeded_for_test(),
            },
            1,
        );
        (registry, clock)
    }

    #[cfg(test)]
    pub(super) fn exhaust_invocation_counter_for_test(&self) {
        self.shared
            .verifier_invocations
            .store(MAX_SAFE_INTEGER, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(super) async fn exhaust_publication_revision_for_test(&self) {
        let now = self.shared.clock.now().expect("test clock is bounded");
        let mut publication = self.shared.publication.write().await;
        let snapshot = CapabilitySnapshot::from_parts(
            publication.snapshot.freshness,
            publication.snapshot.identity_epoch,
            MAX_SAFE_INTEGER,
            publication.snapshot.runtime.clone(),
            publication.snapshot.devices.clone(),
            publication.snapshot.candidates.clone(),
            publication.snapshot.evidence.clone(),
            now,
        )
        .expect("maximum safe revision is valid");
        publication.snapshot = Arc::new(snapshot);
    }

    #[cfg(test)]
    pub(super) fn verifier_invocations_for_test(&self) -> u64 {
        self.shared.verifier_invocations.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) async fn in_flight_count_for_test(&self) -> usize {
        self.shared.flights.lock().await.flights.len()
    }

    #[cfg(test)]
    pub(super) async fn queued_count_for_test(&self) -> usize {
        self.shared.flights.lock().await.queued
    }

    #[cfg(test)]
    pub(super) async fn device_semaphore_count_for_test(&self) -> usize {
        self.shared.flights.lock().await.device_semaphores.len()
    }

    #[cfg(test)]
    pub(super) async fn waiter_count_for_test(&self, key: &CapabilityKey) -> usize {
        self.shared
            .flights
            .lock()
            .await
            .flights
            .get(key)
            .map_or(0, |flight| flight.sender.receiver_count())
    }

    #[cfg(test)]
    pub(super) async fn exhaust_identity_epoch_for_test(&self) {
        let now = self.shared.clock.now().expect("test clock is bounded");
        let mut publication = self.shared.publication.write().await;
        let mut flights = self.shared.flights.lock().await;
        let snapshot = CapabilitySnapshot::from_parts(
            publication.snapshot.freshness,
            MAX_SAFE_INTEGER,
            publication.snapshot.publication_revision,
            publication.snapshot.runtime.clone(),
            publication.snapshot.devices.clone(),
            publication.snapshot.candidates.clone(),
            publication.snapshot.evidence.clone(),
            now,
        )
        .expect("maximum safe epoch is valid");
        flights.identity_epoch = MAX_SAFE_INTEGER;
        publication.snapshot = Arc::new(snapshot);
    }

    pub(crate) async fn start_refresh(
        self: &Arc<Self>,
        service: Weak<TranscodingService>,
        cause: RefreshCause,
    ) -> RefreshAdmission {
        if self.shared.shutdown.is_cancelled() {
            return RefreshAdmission::Rejected {
                reason: RegistryReason::ServerShutdown,
            };
        }
        if self.shared.capacity_exhausted.is_cancelled() {
            return RefreshAdmission::Rejected {
                reason: RegistryReason::CapacityExhausted,
            };
        }
        let now = match self.shared.clock.now() {
            Ok(now) => now,
            Err(reason) => return RefreshAdmission::Rejected { reason },
        };
        let mut refresh = self.shared.refresh.lock().await;
        if let Some(running) = refresh.running {
            return RefreshAdmission::Existing { id: running.id };
        }
        if cause == RefreshCause::Startup
            && let Some(id) = refresh.startup_id
        {
            return RefreshAdmission::Existing { id };
        }
        if cause == RefreshCause::Manual
            && let Some(last) = refresh.last_manual_monotonic_ms
        {
            let elapsed = now.monotonic_milliseconds().saturating_sub(last);
            let window_ms =
                u64::try_from(MANUAL_REFRESH_WINDOW.as_millis()).unwrap_or(MAX_SAFE_INTEGER);
            if elapsed < window_ms {
                return RefreshAdmission::RateLimited {
                    retry_after_seconds: window_ms.saturating_sub(elapsed).div_ceil(1_000),
                };
            }
        }
        let Some(id) = refresh
            .next_id
            .checked_add(1)
            .filter(|id| *id <= MAX_SAFE_INTEGER)
        else {
            self.shared.capacity_exhausted.cancel();
            return RefreshAdmission::Rejected {
                reason: RegistryReason::CapacityExhausted,
            };
        };
        let invalidation = match self.admit_refresh_invalidation(id, cause).await {
            Ok(invalidation) => invalidation,
            Err(reason) => return RefreshAdmission::Rejected { reason },
        };
        refresh.next_id = id;
        if cause == RefreshCause::Startup {
            refresh.startup_id = Some(id);
        } else {
            refresh.last_manual_monotonic_ms = Some(now.monotonic_milliseconds());
        }
        let running = RunningRefresh {
            id,
            cause,
            epoch: invalidation.epoch,
            admitted_revision: invalidation.admitted_revision,
        };
        refresh.running = Some(running);
        drop(refresh);

        let spawned = {
            let _lifecycle = self
                .shared
                .lifecycle_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.shared.shutdown.is_cancelled() {
                false
            } else {
                let shared = Arc::clone(&self.shared);
                let previous = Arc::clone(&invalidation.previous);
                self.shared.tasks.spawn(async move {
                    run_refresh(shared, service, running, previous).await;
                });
                true
            }
        };
        if !spawned {
            publish_failed_refresh(
                &self.shared,
                running,
                &invalidation.previous,
                true,
                RefreshOutcomeReason::RefreshCancelled,
            )
            .await;
            return RefreshAdmission::Rejected {
                reason: RegistryReason::ServerShutdown,
            };
        }
        RefreshAdmission::Started { id }
    }

    async fn admit_refresh_invalidation(
        &self,
        refresh_id: u64,
        cause: RefreshCause,
    ) -> Result<RefreshInvalidation, RegistryReason> {
        if self.shared.shutdown.is_cancelled() {
            return Err(RegistryReason::ServerShutdown);
        }
        if self.shared.capacity_exhausted.is_cancelled() {
            return Err(RegistryReason::CapacityExhausted);
        }
        let mut publication = self.shared.publication.write().await;
        let mut flights = self.shared.flights.lock().await;
        if self.shared.shutdown.is_cancelled() {
            return Err(RegistryReason::ServerShutdown);
        }
        if self.shared.capacity_exhausted.is_cancelled() {
            return Err(RegistryReason::CapacityExhausted);
        }
        if let Some(reason) = flights.terminal_reason {
            return Err(reason);
        }
        let cancellations = flights
            .flights
            .values()
            .map(|flight| flight.cancellation.clone())
            .collect::<Vec<_>>();
        let next_epoch = flights
            .identity_epoch
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_INTEGER);
        let Some(next_epoch) = next_epoch else {
            self.shared.capacity_exhausted.cancel();
            flights.terminal_reason = Some(RegistryReason::CapacityExhausted);
            let cancellations = flights
                .flights
                .values()
                .map(|flight| flight.cancellation.clone())
                .collect::<Vec<_>>();
            drop(flights);
            for cancellation in cancellations {
                cancellation.cancel();
            }
            return Err(RegistryReason::CapacityExhausted);
        };
        let next_revision = publication
            .snapshot
            .publication_revision
            .checked_add(1)
            .filter(|value| *value <= MAX_SAFE_INTEGER);
        let Some(next_revision) = next_revision else {
            self.shared.capacity_exhausted.cancel();
            flights.terminal_reason = Some(RegistryReason::CapacityExhausted);
            drop(publication);
            drop(flights);
            for cancellation in cancellations {
                cancellation.cancel();
            }
            return Err(RegistryReason::CapacityExhausted);
        };
        let now = self.shared.clock.now()?;
        let previous = Arc::clone(&publication.snapshot);
        let refreshing = CapabilitySnapshot::from_parts(
            SnapshotFreshness::Refreshing,
            next_epoch,
            next_revision,
            publication.snapshot.runtime.clone(),
            publication.snapshot.devices.clone(),
            publication.snapshot.candidates.clone(),
            publication.snapshot.evidence.clone(),
            now,
        )
        .map_err(|_| RegistryReason::VerificationPrerequisiteMissing)?;
        flights.admission_paused = true;
        flights.identity_epoch = next_epoch;
        publication.snapshot = Arc::new(refreshing);
        publication.refresh = RefreshMetadata {
            state: RefreshState::Running,
            id: Some(refresh_id),
            cause: Some(cause),
            started_at: Some(now.wall()),
            completed_at: None,
            outcome_reason: None,
            persistence_status: self.shared.refresh_dependencies.storage.status(),
        };
        drop(publication);
        drop(flights);
        for cancellation in cancellations {
            cancellation.cancel();
        }
        Ok(RefreshInvalidation {
            epoch: next_epoch,
            admitted_revision: next_revision,
            previous,
        })
    }

    pub(super) async fn begin_refresh_invalidation(&self) -> Result<u64, RegistryReason> {
        let invalidation = self
            .admit_refresh_invalidation(1, RefreshCause::Startup)
            .await?;
        wait_for_all_flights(&self.shared).await;
        Ok(invalidation.epoch)
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_refresh_for_test(&self) {
        loop {
            let changed = self.shared.refresh_changed.notified();
            if self.shared.refresh.lock().await.running.is_none() {
                return;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    pub(super) fn exhaust_refresh_counter_for_test(&self) {
        if let Ok(mut refresh) = self.shared.refresh.try_lock() {
            refresh.next_id = MAX_SAFE_INTEGER;
        } else {
            panic!("test refresh control unexpectedly locked");
        }
    }

    #[cfg(test)]
    pub(crate) async fn refresh_persistence_status_for_test(&self) -> StorageStatus {
        self.shared
            .publication
            .read()
            .await
            .refresh
            .persistence_status
    }

    #[cfg(test)]
    pub(crate) async fn refresh_persistence_failed_for_test(&self) -> bool {
        self.refresh_persistence_status_for_test().await == StorageStatus::PersistFailed
    }
}

async fn run_refresh(
    shared: Arc<RegistryShared>,
    service: Weak<TranscodingService>,
    running: RunningRefresh,
    previous: Arc<CapabilitySnapshot>,
) {
    let cancellation = shared.shutdown.child_token();
    let completed = AssertUnwindSafe(run_refresh_inner(
        &shared,
        service,
        running,
        previous.as_ref(),
        cancellation.clone(),
    ))
    .catch_unwind()
    .await;
    if completed.is_err() {
        cancellation.cancel();
        let cancelled = shared.shutdown.is_cancelled();
        publish_failed_refresh(
            &shared,
            running,
            &previous,
            cancelled,
            if cancelled {
                RefreshOutcomeReason::RefreshCancelled
            } else {
                RefreshOutcomeReason::RefreshFailed
            },
        )
        .await;
    }
}

async fn run_refresh_inner(
    shared: &RegistryShared,
    service: Weak<TranscodingService>,
    running: RunningRefresh,
    previous: &CapabilitySnapshot,
    cancellation: CancellationToken,
) {
    let deadline_at = tokio::time::Instant::now() + shared.refresh_dependencies.worker_deadline;
    let work = async {
        wait_for_all_flights(shared).await;
        build_refresh_candidate(shared, service, running, previous, cancellation.clone()).await
    };
    tokio::pin!(work);
    let deadline = tokio::time::sleep_until(deadline_at);
    tokio::pin!(deadline);
    let result = tokio::select! {
        result = &mut work => result,
        () = shared.shutdown.cancelled() => {
            cancellation.cancel();
            let _ = work.await;
            Err(RefreshFailure::Cancelled)
        }
        () = &mut deadline => {
            cancellation.cancel();
            let _ = work.await;
            Err(RefreshFailure::Inventory(InventoryError::Timeout))
        }
    };
    match result {
        Ok(candidate) if !shared.shutdown.is_cancelled() => {
            publish_fresh_refresh(shared, running, previous, candidate, deadline_at).await;
        }
        Ok(_) | Err(RefreshFailure::Cancelled | RefreshFailure::Device(DeviceError::Cancelled)) => {
            publish_failed_refresh(
                shared,
                running,
                previous,
                true,
                RefreshOutcomeReason::RefreshCancelled,
            )
            .await;
        }
        Err(failure) => {
            let reason = failure.outcome_reason();
            publish_failed_refresh(shared, running, previous, false, reason).await;
        }
    }
}

async fn build_refresh_candidate(
    shared: &RegistryShared,
    service: Weak<TranscodingService>,
    running: RunningRefresh,
    previous: &CapabilitySnapshot,
    cancellation: CancellationToken,
) -> Result<RefreshCandidate, RefreshFailure> {
    if cancellation.is_cancelled() {
        return Err(RefreshFailure::Cancelled);
    }
    let service = service.upgrade().ok_or(RefreshFailure::Cancelled)?;
    let session_result = service.runtime_for_session().await;
    drop(service);
    let session = match session_result {
        Ok(session) => Some(session),
        Err(RuntimeError::Unavailable) => None,
        Err(_) => return Err(RefreshFailure::RuntimeUnavailable),
    };
    if cancellation.is_cancelled() {
        return Err(RefreshFailure::Cancelled);
    }
    let discovery = shared
        .refresh_dependencies
        .enumerator
        .enumerate(cancellation.child_token())
        .await
        .map_err(RefreshFailure::Device)?;
    if cancellation.is_cancelled() {
        return Err(RefreshFailure::Cancelled);
    }

    let discovery_status = discovery.status;
    let mut outcome_reason =
        (session.is_none()).then_some(RefreshOutcomeReason::RuntimeUnavailable);
    let devices = match (
        &shared.refresh_dependencies.seed,
        &shared.refresh_dependencies.driver_run_epoch,
    ) {
        (Some(seed), Some(run_epoch)) => {
            match normalize_platform_records(discovery.records, seed, run_epoch) {
                Ok(devices) => devices,
                Err(DeviceError::Ambiguous) => {
                    outcome_reason = Some(RefreshOutcomeReason::DeviceMappingAmbiguous);
                    Vec::new()
                }
                Err(error) => return Err(RefreshFailure::Device(error)),
            }
        }
        _ => {
            outcome_reason = Some(RefreshOutcomeReason::DeviceIdentityUnavailable);
            Vec::new()
        }
    };
    if outcome_reason.is_none() && discovery_status == DeviceDiscoveryStatus::PlatformUnsupported {
        outcome_reason = Some(RefreshOutcomeReason::PlatformUnsupported);
    }
    let runtime = match session.as_ref() {
        Some(session) => Some(
            shared
                .refresh_dependencies
                .inventory
                .collect(session, cancellation.child_token())
                .await
                .map_err(RefreshFailure::Inventory)?,
        ),
        None => None,
    };
    if cancellation.is_cancelled() {
        return Err(RefreshFailure::Cancelled);
    }
    let candidates = match (session.as_ref(), runtime.as_ref()) {
        (Some(session), Some(runtime)) => {
            coarse_candidates(session, runtime, &devices).map_err(RefreshFailure::Inventory)?
        }
        _ => Vec::new(),
    };
    let now = shared
        .clock
        .now()
        .map_err(|_| RefreshFailure::SnapshotInvalid)?;
    let identity_snapshot = CapabilitySnapshot::from_parts(
        SnapshotFreshness::Fresh,
        running.epoch,
        running.admitted_revision,
        runtime.clone(),
        devices.clone(),
        candidates.clone(),
        BTreeMap::new(),
        now,
    )
    .map_err(|_| RefreshFailure::SnapshotInvalid)?;
    let mut evidence = previous.evidence.clone();
    evidence.retain(|key, record| evidence_record_is_current(&identity_snapshot, key, record, now));
    if let Some(runtime) = &runtime {
        for (key, mut record) in shared
            .refresh_dependencies
            .storage
            .load_evidence(runtime.runtime_id.clone(), now)
            .await
        {
            let current = evidence_record_is_current(&identity_snapshot, &key, &mut record, now);
            if current && (evidence.contains_key(&key) || evidence.len() < MAX_EVIDENCE) {
                evidence.entry(key).or_insert(record);
            }
        }
    } else {
        evidence.clear();
    }
    if running.cause == RefreshCause::Manual {
        for record in evidence.values_mut() {
            record.clear_cooldown_after_refresh(now);
        }
    }
    Ok(RefreshCandidate {
        runtime,
        devices,
        candidates,
        evidence,
        outcome_reason,
    })
}

fn evidence_record_is_current(
    snapshot: &CapabilitySnapshot,
    key: &CapabilityKey,
    record: &mut EvidenceRecord,
    now: StateNow,
) -> bool {
    record.prune_expired(now);
    &record.key == key
        && snapshot.key_identity_matches(key)
        && snapshot.has_static_prerequisites(key)
        && record.last_observed_at().is_some()
        && record.validate(now).is_ok()
}

async fn publish_fresh_refresh(
    shared: &RegistryShared,
    running: RunningRefresh,
    previous: &CapabilitySnapshot,
    candidate: RefreshCandidate,
    deadline_at: tokio::time::Instant,
) {
    if tokio::time::Instant::now() >= deadline_at {
        publish_failed_refresh(
            shared,
            running,
            previous,
            false,
            RefreshOutcomeReason::InventoryTimeout,
        )
        .await;
        return;
    }
    let now = match shared.clock.now() {
        Ok(now) => now,
        Err(_) => {
            publish_failed_refresh(
                shared,
                running,
                previous,
                false,
                RefreshOutcomeReason::RefreshFailed,
            )
            .await;
            return;
        }
    };
    let Some(revision) = running
        .admitted_revision
        .checked_add(1)
        .filter(|revision| *revision <= MAX_SAFE_INTEGER)
    else {
        shared.capacity_exhausted.cancel();
        publish_failed_refresh(
            shared,
            running,
            previous,
            false,
            RefreshOutcomeReason::RefreshFailed,
        )
        .await;
        return;
    };
    let snapshot = match CapabilitySnapshot::from_parts(
        SnapshotFreshness::Fresh,
        running.epoch,
        revision,
        candidate.runtime,
        candidate.devices,
        candidate.candidates,
        candidate.evidence,
        now,
    ) {
        Ok(snapshot) => Arc::new(snapshot),
        Err(_) => {
            publish_failed_refresh(
                shared,
                running,
                previous,
                false,
                RefreshOutcomeReason::RefreshFailed,
            )
            .await;
            return;
        }
    };
    if let Some(runtime) = &snapshot.runtime {
        let requested = shared.refresh_dependencies.storage.request_persist(
            revision,
            runtime.runtime_id.clone(),
            snapshot.evidence.clone(),
            now,
        );
        if requested {
            tokio::select! {
                biased;
                () = shared.shutdown.cancelled() => {
                    publish_failed_refresh(
                        shared,
                        running,
                        previous,
                        true,
                        RefreshOutcomeReason::RefreshCancelled,
                    ).await;
                    return;
                }
                () = tokio::time::sleep_until(deadline_at) => {
                    publish_failed_refresh(
                        shared,
                        running,
                        previous,
                        false,
                        RefreshOutcomeReason::InventoryTimeout,
                    ).await;
                    return;
                }
                _ = shared.refresh_dependencies.storage.wait_for_persisted(revision) => {}
            }
        }
    }
    if shared.shutdown.is_cancelled() {
        publish_failed_refresh(
            shared,
            running,
            previous,
            true,
            RefreshOutcomeReason::RefreshCancelled,
        )
        .await;
        return;
    }
    let mut publication = shared.publication.write().await;
    if publication.snapshot.identity_epoch != running.epoch
        || publication.snapshot.publication_revision != running.admitted_revision
    {
        drop(publication);
        finish_refresh_control(shared, running).await;
        return;
    }
    publication.snapshot = snapshot;
    publication.refresh.state = RefreshState::Succeeded;
    publication.refresh.completed_at = Some(now.wall());
    publication.refresh.outcome_reason = candidate.outcome_reason;
    publication.refresh.persistence_status = shared.refresh_dependencies.storage.status();
    drop(publication);
    resume_after_refresh(shared, running.epoch).await;
    finish_refresh_control(shared, running).await;
}

async fn publish_failed_refresh(
    shared: &RegistryShared,
    running: RunningRefresh,
    previous: &CapabilitySnapshot,
    cancelled: bool,
    reason: RefreshOutcomeReason,
) {
    let now = shared.clock.now().ok();
    let revision = running
        .admitted_revision
        .checked_add(1)
        .filter(|revision| *revision <= MAX_SAFE_INTEGER);
    if let (Some(now), Some(revision)) = (now, revision) {
        let stale = CapabilitySnapshot::from_parts(
            SnapshotFreshness::Stale,
            running.epoch,
            revision,
            previous.runtime.clone(),
            previous.devices.clone(),
            previous.candidates.clone(),
            previous.evidence.clone(),
            now,
        );
        if let Ok(stale) = stale {
            let mut publication = shared.publication.write().await;
            if publication.snapshot.identity_epoch == running.epoch
                && publication.snapshot.publication_revision == running.admitted_revision
            {
                publication.snapshot = Arc::new(stale);
                publication.refresh.state = if cancelled {
                    RefreshState::Cancelled
                } else {
                    RefreshState::Failed
                };
                publication.refresh.completed_at = Some(now.wall());
                publication.refresh.outcome_reason = Some(reason);
                publication.refresh.persistence_status =
                    shared.refresh_dependencies.storage.status();
            }
        }
    } else {
        shared.capacity_exhausted.cancel();
    }
    resume_after_refresh(shared, running.epoch).await;
    finish_refresh_control(shared, running).await;
}

async fn resume_after_refresh(shared: &RegistryShared, epoch: u64) {
    let mut flights = shared.flights.lock().await;
    if flights.identity_epoch == epoch && !shared.shutdown.is_cancelled() {
        flights.admission_paused = false;
    }
}

async fn finish_refresh_control(shared: &RegistryShared, running: RunningRefresh) {
    let mut refresh = shared.refresh.lock().await;
    if refresh
        .running
        .is_some_and(|current| current.id == running.id)
    {
        refresh.running = None;
    }
    drop(refresh);
    shared.refresh_changed.notify_waiters();
}

impl Drop for CapabilityRegistry {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

async fn wait_for_flight(
    mut receiver: watch::Receiver<Option<EnsureEvidenceResult>>,
    shutdown: CancellationToken,
) -> EnsureEvidenceResult {
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result;
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                return EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown);
            }
            changed = receiver.changed() => {
                if changed.is_err() {
                    return EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown);
                }
            }
        }
    }
}

async fn run_verification(
    shared: Arc<RegistryShared>,
    key: CapabilityKey,
    flight: Arc<Flight>,
    device_semaphore: Arc<Semaphore>,
) {
    let permits = acquire_verification_permits(
        &shared,
        Arc::clone(&device_semaphore),
        flight.cancellation.clone(),
    )
    .await;
    decrement_queued(&shared).await;
    let result = match permits {
        Ok(permits) => {
            let result = if shared.playback.playback_active() {
                EnsureEvidenceResult::non_passing(RegistryReason::VerificationDeferredForPlayback)
            } else if !flight_is_current(&shared, &key, flight.epoch).await {
                cancellation_result(&shared).await
            } else if increment_invocations(&shared.verifier_invocations).is_err() {
                shared.capacity_exhausted.cancel();
                EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted)
            } else {
                let request = VerificationRequest {
                    key: key.clone(),
                    target: flight.target,
                    identity_epoch: flight.epoch,
                };
                let verifier =
                    AssertUnwindSafe(shared.verifier.verify(request, flight.cancellation.clone()))
                        .catch_unwind();
                tokio::select! {
                    biased;
                    _ = shared.shutdown.cancelled() => {
                        EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown)
                    }
                    _ = shared.capacity_exhausted.cancelled() => {
                        EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted)
                    }
                    _ = flight.cancellation.cancelled() => cancellation_result(&shared).await,
                    verified = verifier => match verified {
                        Ok(verified) if verified.target() == flight.target => {
                            merge_verification(&shared, &key, flight.epoch, verified).await
                        }
                        Ok(_) => EnsureEvidenceResult::non_passing(
                            RegistryReason::VerificationPrerequisiteMissing,
                        ),
                        Err(_) => EnsureEvidenceResult::non_passing(RegistryReason::ServerShutdown),
                    }
                }
            };
            drop(permits);
            result
        }
        Err(reason) => EnsureEvidenceResult::non_passing(reason),
    };
    finish_flight(&shared, &key, &flight, &device_semaphore, result).await;
}

async fn acquire_verification_permits(
    shared: &RegistryShared,
    device_semaphore: Arc<Semaphore>,
    cancellation: CancellationToken,
) -> Result<
    (
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    ),
    RegistryReason,
> {
    let acquire = async {
        let device = tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => return Err(RegistryReason::ServerShutdown),
            _ = shared.capacity_exhausted.cancelled() => {
                return Err(RegistryReason::CapacityExhausted)
            },
            _ = cancellation.cancelled() => return Err(RegistryReason::VerificationStale),
            permit = device_semaphore.acquire_owned() => {
                permit.map_err(|_| RegistryReason::ServerShutdown)?
            }
        };
        let global = tokio::select! {
            biased;
            _ = shared.shutdown.cancelled() => return Err(RegistryReason::ServerShutdown),
            _ = shared.capacity_exhausted.cancelled() => {
                return Err(RegistryReason::CapacityExhausted)
            },
            _ = cancellation.cancelled() => return Err(RegistryReason::VerificationStale),
            permit = Arc::clone(&shared.global_semaphore).acquire_owned() => {
                permit.map_err(|_| RegistryReason::ServerShutdown)?
            }
        };
        Ok((device, global))
    };
    tokio::time::timeout(QUEUE_TIMEOUT, acquire)
        .await
        .unwrap_or(Err(RegistryReason::VerificationQueueTimeout))
}

async fn decrement_queued(shared: &RegistryShared) {
    let mut flights = shared.flights.lock().await;
    if let Some(queued) = flights.queued.checked_sub(1) {
        flights.queued = queued;
        return;
    }
    shared.capacity_exhausted.cancel();
    flights.terminal_reason = Some(RegistryReason::CapacityExhausted);
    let cancellations = flights
        .flights
        .values()
        .map(|flight| flight.cancellation.clone())
        .collect::<Vec<_>>();
    drop(flights);
    for cancellation in cancellations {
        cancellation.cancel();
    }
}

async fn flight_is_current(shared: &RegistryShared, key: &CapabilityKey, epoch: u64) -> bool {
    let flights = shared.flights.lock().await;
    if shared.capacity_exhausted.is_cancelled()
        || flights.terminal_reason.is_some()
        || flights.admission_paused
        || flights.identity_epoch != epoch
    {
        return false;
    }
    drop(flights);
    let publication = shared.publication.read().await;
    publication.snapshot.identity_epoch == epoch && publication.snapshot.admits(key)
}

async fn cancellation_result(shared: &RegistryShared) -> EnsureEvidenceResult {
    let flights = shared.flights.lock().await;
    let reason = if shared.capacity_exhausted.is_cancelled() {
        RegistryReason::CapacityExhausted
    } else {
        flights.terminal_reason.unwrap_or_else(|| {
            if shared.shutdown.is_cancelled() {
                RegistryReason::ServerShutdown
            } else {
                RegistryReason::VerificationStale
            }
        })
    };
    EnsureEvidenceResult::non_passing(reason)
}

fn increment_invocations(counter: &AtomicU64) -> Result<(), RegistryReason> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value
                .checked_add(1)
                .filter(|next| *next <= MAX_SAFE_INTEGER)
        })
        .map(|_| ())
        .map_err(|_| RegistryReason::CapacityExhausted)
}

async fn merge_verification(
    shared: &RegistryShared,
    key: &CapabilityKey,
    epoch: u64,
    verified: VerificationResult,
) -> EnsureEvidenceResult {
    if shared.capacity_exhausted.is_cancelled() {
        return EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted);
    }
    let now = match shared.clock.now() {
        Ok(now) => now,
        Err(reason) => return EnsureEvidenceResult::non_passing(reason),
    };
    let outcome = verified.outcome();
    let mut publication = shared.publication.write().await;
    if publication.snapshot.identity_epoch != epoch || !publication.snapshot.admits(key) {
        return EnsureEvidenceResult::non_passing(RegistryReason::VerificationStale);
    }
    let mut evidence = publication.snapshot.evidence.clone();
    for record in evidence.values_mut() {
        record.prune_expired(now);
    }
    evidence.retain(|candidate, record| {
        publication.snapshot.key_is_current(candidate) && record.last_observed_at().is_some()
    });
    let existed = evidence.contains_key(key);
    let mut record = evidence
        .remove(key)
        .unwrap_or_else(|| EvidenceRecord::new(key.clone()));
    let transition = match record.apply(verified, VerifierMode::ActiveInjected, now) {
        Ok(transition) => transition,
        Err(_) => {
            return EnsureEvidenceResult::non_passing(
                RegistryReason::VerificationPrerequisiteMissing,
            );
        }
    };
    if transition.remove_record() {
        if !existed {
            return EnsureEvidenceResult::from_outcome(outcome);
        }
    } else if transition.changes_record() {
        if !existed && evidence.len() >= MAX_EVIDENCE {
            let evict = evidence
                .iter()
                .min_by_key(|(candidate, record)| (record.last_observed_at(), *candidate))
                .map(|(candidate, _)| candidate.clone());
            if let Some(evict) = evict {
                evidence.remove(&evict);
            } else {
                return EnsureEvidenceResult::non_passing(RegistryReason::VerificationCapacity);
            }
        }
        evidence.insert(key.clone(), record);
    } else {
        return EnsureEvidenceResult::from_outcome(outcome);
    }
    let revision = match publication.snapshot.publication_revision.checked_add(1) {
        Some(revision) if revision <= MAX_SAFE_INTEGER => revision,
        _ => {
            shared.capacity_exhausted.cancel();
            return EnsureEvidenceResult::non_passing(RegistryReason::CapacityExhausted);
        }
    };
    let snapshot = match CapabilitySnapshot::from_parts(
        publication.snapshot.freshness,
        epoch,
        revision,
        publication.snapshot.runtime.clone(),
        publication.snapshot.devices.clone(),
        publication.snapshot.candidates.clone(),
        evidence,
        now,
    ) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return EnsureEvidenceResult::non_passing(
                RegistryReason::VerificationPrerequisiteMissing,
            );
        }
    };
    let snapshot = Arc::new(snapshot);
    let persistence = snapshot
        .runtime
        .as_ref()
        .map(|runtime| (runtime.runtime_id.clone(), snapshot.evidence.clone()));
    publication.snapshot = snapshot;
    drop(publication);
    if let Some((runtime, evidence)) = persistence {
        let _ = shared
            .refresh_dependencies
            .storage
            .request_persist(revision, runtime, evidence, now);
    }
    EnsureEvidenceResult::from_outcome(outcome)
}

async fn finish_flight(
    shared: &RegistryShared,
    key: &CapabilityKey,
    flight: &Arc<Flight>,
    device_semaphore: &Arc<Semaphore>,
    result: EnsureEvidenceResult,
) {
    flight.sender.send_replace(Some(result));
    let mut flights = shared.flights.lock().await;
    if flights
        .flights
        .get(key)
        .is_some_and(|candidate| Arc::ptr_eq(candidate, flight))
    {
        flights.flights.remove(key);
    }
    if device_semaphore.available_permits() == 1 && Arc::strong_count(device_semaphore) == 2 {
        flights.device_semaphores.remove(key.device());
    }
    drop(flights);
    shared.flights_changed.notify_waiters();
}

async fn wait_for_all_flights(shared: &RegistryShared) {
    loop {
        let changed = shared.flights_changed.notified();
        if shared.flights.lock().await.flights.is_empty() {
            return;
        }
        changed.await;
    }
}

#[cfg(test)]
struct FixedRegistryClock;

#[cfg(test)]
impl RegistryClock for FixedRegistryClock {
    fn now(&self) -> Result<StateNow, RegistryReason> {
        Ok(StateNow::from_test_minutes(0))
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestRegistryClock(Arc<AtomicU64>);

#[cfg(test)]
impl TestRegistryClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    pub(super) fn set_minutes(&self, minutes: u64) {
        self.0.store(minutes, Ordering::SeqCst);
    }
}

#[cfg(test)]
impl RegistryClock for TestRegistryClock {
    fn now(&self) -> Result<StateNow, RegistryReason> {
        Ok(StateNow::from_test_minutes(self.0.load(Ordering::SeqCst)))
    }
}

#[cfg(test)]
fn test_snapshot_for_keys(keys: &[CapabilityKey]) -> CapabilitySnapshot {
    build_test_snapshot_for_keys(keys).expect("valid test snapshot")
}

#[cfg(test)]
fn build_test_snapshot_for_keys(
    keys: &[CapabilityKey],
) -> Result<CapabilitySnapshot, SnapshotError> {
    let first = keys.first().expect("test snapshot needs an identity");
    assert!(keys.iter().all(|key| key.runtime() == first.runtime()));
    let runtime = RuntimeInventory {
        runtime_id: first.runtime().clone(),
        safe_version: SafeRuntimeVersion {
            ffmpeg: Some("7.1.4".to_owned()),
            jellyfin_revision: Some("3".to_owned()),
        },
        accelerators: BTreeSet::new(),
        decoders: BTreeSet::new(),
        encoders: BTreeSet::new(),
        filters: [FilterComponent::ScaleSoftware, FilterComponent::HardwareMap]
            .into_iter()
            .collect(),
        unknown_counts: InventoryUnknownCounts::default(),
    };
    let mut devices = BTreeMap::<_, TranscodingDevice>::new();
    for key in keys {
        let device = devices.entry(key.device().clone()).or_insert_with(|| {
            TranscodingDevice::from_test_identity(
                key.device().clone(),
                key.driver().clone(),
                key.backend(),
            )
        });
        assert_eq!(&device.driver_identity, key.driver());
        device.backends.insert(key.backend());
    }
    let mut candidates = keys
        .iter()
        .flat_map(|key| {
            let StaticPrerequisites { decode, encode, .. } = key.static_prerequisites();
            decode
                .map(|codec| CoarseCandidate {
                    device: key.device().clone(),
                    backend: key.backend(),
                    codec,
                    direction: ListedDirection::Decode,
                })
                .into_iter()
                .chain(encode.map(|codec| CoarseCandidate {
                    device: key.device().clone(),
                    backend: key.backend(),
                    codec,
                    direction: ListedDirection::Encode,
                }))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    CapabilitySnapshot::from_parts(
        SnapshotFreshness::Fresh,
        1,
        1,
        Some(runtime),
        devices.into_values().collect(),
        candidates,
        BTreeMap::new(),
        StateNow::from_test_minutes(0),
    )
}

#[cfg(test)]
pub(super) fn snapshot_validation_matrix_for_test() -> Vec<(&'static str, bool)> {
    let base = CapabilityKey::complete_test_keys().remove(0);
    let ordered_keys = vec![
        base.with_test_physical_identity(0x20),
        base.with_test_physical_identity(0x10),
    ];
    let mut reversed_keys = ordered_keys.clone();
    reversed_keys.reverse();
    let ordered = test_snapshot_for_keys(&ordered_keys);
    let reversed = test_snapshot_for_keys(&reversed_keys);
    let deterministic = ordered
        .devices
        .iter()
        .map(|device| &device.id)
        .eq(reversed.devices.iter().map(|device| &device.id))
        && ordered.candidates == reversed.candidates;

    let too_many_devices = (1_u8..=33)
        .map(|marker| base.with_test_physical_identity(marker))
        .collect::<Vec<_>>();
    let rejects_device_overflow = matches!(
        build_test_snapshot_for_keys(&too_many_devices),
        Err(SnapshotError::Bounds)
    );

    let single = test_snapshot_for_keys(std::slice::from_ref(&base));
    let mut duplicate_candidates = single.candidates.clone();
    duplicate_candidates.push(
        duplicate_candidates
            .first()
            .expect("decode fixture has a candidate")
            .clone(),
    );
    duplicate_candidates.sort();
    let rejects_duplicate_candidate = matches!(
        CapabilitySnapshot::from_parts(
            single.freshness,
            single.identity_epoch,
            single.publication_revision,
            single.runtime.clone(),
            single.devices.clone(),
            duplicate_candidates,
            single.evidence.clone(),
            StateNow::from_test_minutes(0),
        ),
        Err(SnapshotError::Ordering)
    );

    let mut bad_cross_reference = single.candidates.clone();
    bad_cross_reference[0].backend = crate::transcoding::BackendKind::Cuda;
    let rejects_cross_reference = matches!(
        CapabilitySnapshot::from_parts(
            single.freshness,
            single.identity_epoch,
            single.publication_revision,
            single.runtime.clone(),
            single.devices.clone(),
            bad_cross_reference,
            single.evidence.clone(),
            StateNow::from_test_minutes(0),
        ),
        Err(SnapshotError::CrossReference)
    );
    let rejects_missing_runtime = matches!(
        CapabilitySnapshot::from_parts(
            single.freshness,
            single.identity_epoch,
            single.publication_revision,
            None,
            single.devices.clone(),
            single.candidates.clone(),
            single.evidence.clone(),
            StateNow::from_test_minutes(0),
        ),
        Err(SnapshotError::CrossReference)
    );

    let keys = CapabilityKey::distinct_copy_keys_for_test(MAX_EVIDENCE + 1);
    let evidence_base = test_snapshot_for_keys(&keys);
    let now = StateNow::from_test_minutes(0);
    let evidence = keys
        .into_iter()
        .map(|key| {
            let mut record = EvidenceRecord::new(key.clone());
            record
                .apply(
                    VerificationResult::for_test(
                        EvidenceTarget::Correctness,
                        EvidenceOutcome::CorrectnessPassed,
                        EvidenceReason::VerificationFailed,
                        0,
                    ),
                    VerifierMode::ActiveInjected,
                    now,
                )
                .expect("valid overflow fixture record");
            (key, record)
        })
        .collect();
    let rejects_evidence_overflow = matches!(
        CapabilitySnapshot::from_parts(
            evidence_base.freshness,
            evidence_base.identity_epoch,
            evidence_base.publication_revision,
            evidence_base.runtime,
            evidence_base.devices,
            evidence_base.candidates,
            evidence,
            now,
        ),
        Err(SnapshotError::Bounds)
    );

    vec![
        ("deterministic_order", deterministic),
        ("device_overflow", rejects_device_overflow),
        ("duplicate_candidate", rejects_duplicate_candidate),
        ("candidate_cross_reference", rejects_cross_reference),
        ("missing_runtime", rejects_missing_runtime),
        ("evidence_overflow", rejects_evidence_overflow),
    ]
}

#[cfg(test)]
pub(super) fn cache_identity_filter_matrix_for_test() -> Vec<(&'static str, bool)> {
    let key = CapabilityKey::complete_test_keys().remove(0);
    let snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
    let now = StateNow::from_test_minutes(0);
    let cases = [
        ("exact", key.clone(), true),
        ("runtime", key.with_test_runtime(0x71), false),
        ("device", key.with_test_physical_identity(0x72), false),
        ("driver", key.with_test_driver(0x73), false),
        (
            "backend",
            key.with_test_backend(crate::transcoding::BackendKind::Cuda),
            false,
        ),
    ];
    let mut results = cases
        .into_iter()
        .map(|(name, candidate, expected)| {
            let mut record = EvidenceRecord::new(candidate.clone());
            record
                .apply(
                    VerificationResult::for_test(
                        EvidenceTarget::Correctness,
                        EvidenceOutcome::TemporaryFailure,
                        EvidenceReason::VerificationFailed,
                        0,
                    ),
                    VerifierMode::ActiveInjected,
                    now,
                )
                .expect("valid cache-filter fixture");
            (
                name,
                evidence_record_is_current(&snapshot, &candidate, &mut record, now) == expected,
            )
        })
        .collect::<Vec<_>>();
    let mut missing_prerequisite = snapshot.clone();
    missing_prerequisite
        .runtime
        .as_mut()
        .expect("cache-filter fixture has a runtime")
        .filters
        .clear();
    let mut record = EvidenceRecord::new(key.clone());
    record
        .apply(
            VerificationResult::for_test(
                EvidenceTarget::Correctness,
                EvidenceOutcome::TemporaryFailure,
                EvidenceReason::VerificationFailed,
                0,
            ),
            VerifierMode::ActiveInjected,
            now,
        )
        .expect("valid cache-filter prerequisite fixture");
    results.push((
        "static_prerequisite",
        !evidence_record_is_current(&missing_prerequisite, &key, &mut record, now),
    ));
    results
}
