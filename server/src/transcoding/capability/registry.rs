use std::{
    collections::BTreeMap,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures_util::FutureExt;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::transcoding::{CapabilityState, device::DeviceAvailability};

#[cfg(test)]
use std::collections::BTreeSet;

use super::{
    key::{CapabilityKey, RequiredFilter, RequiredTransfer, StaticPrerequisites},
    state::{
        EvidenceOutcome, EvidenceReason, EvidenceRecord, EvidenceTarget, EvidenceTimestamp,
        StateNow, VerificationResult, VerifierMode,
    },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotFreshness {
    Uninitialized,
    Refreshing,
    Fresh,
    Stale,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RefreshMetadata {
    pub(super) state: RefreshState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RefreshState {
    Idle,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug)]
pub(super) struct CapabilitySnapshot {
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

    pub(super) const fn freshness(&self) -> SnapshotFreshness {
        self.freshness
    }

    pub(super) const fn identity_epoch(&self) -> u64 {
        self.identity_epoch
    }

    pub(super) const fn publication_revision(&self) -> u64 {
        self.publication_revision
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
pub(super) enum RegistryReason {
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
    shutdown: CancellationToken,
}

pub(super) struct CapabilityRegistry {
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
                refresh: RefreshMetadata {
                    state: RefreshState::Idle,
                },
            },
            0,
        )
    }

    fn with_publication(
        verifier: Arc<dyn CapabilityVerifier>,
        playback: Arc<dyn PlaybackPriority>,
        clock: Arc<dyn RegistryClock>,
        publication: RegistryPublication,
        identity_epoch: u64,
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
                shutdown: CancellationToken::new(),
            }),
        }
    }

    pub(super) async fn snapshot(&self) -> Arc<CapabilitySnapshot> {
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

        let shared = Arc::clone(&self.shared);
        self.shared.tasks.spawn(async move {
            run_verification(shared, key, flight, device_semaphore).await;
        });
        wait_for_flight(receiver, self.shared.shutdown.clone()).await
    }

    pub(super) fn begin_shutdown(&self) {
        self.shared.shutdown.cancel();
    }

    pub(super) async fn shutdown(&self) {
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
        self.shared.tasks.close();
        self.shared.tasks.wait().await;
    }

    #[cfg(test)]
    pub(super) fn fresh_for_test(
        key: CapabilityKey,
        verifier: impl CapabilityVerifier + 'static,
    ) -> Self {
        Self::fresh_for_test_with(key, verifier, Arc::new(NoPlaybackPriority))
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
                refresh: RefreshMetadata {
                    state: RefreshState::Succeeded,
                },
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
                refresh: RefreshMetadata {
                    state: RefreshState::Succeeded,
                },
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

    pub(super) async fn begin_refresh_invalidation(&self) -> Result<u64, RegistryReason> {
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
        publication.refresh.state = RefreshState::Running;
        drop(publication);
        drop(flights);
        for cancellation in cancellations {
            cancellation.cancel();
        }
        wait_for_all_flights(&self.shared).await;
        Ok(next_epoch)
    }
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
    publication.snapshot = Arc::new(snapshot);
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
