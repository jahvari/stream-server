use serde::Serialize;
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::transcoding::{device::identity::DeviceIdSeed, inventory::RuntimeEvidenceId};

use super::{
    key::CapabilityKey,
    state::{EvidenceRecord, StateNow},
};

mod schema;
use schema::MAX_CACHE_BYTES;
pub(super) use schema::{CacheSchemaError, decode_evidence_cache, encode_evidence_cache};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
pub(super) mod windows;
#[cfg(windows)]
use windows as platform;

const DEVICE_ID_SEED_BYTES: usize = 32;
const WINNER_REOPEN_ATTEMPTS: usize = 200;
const WINNER_REOPEN_DELAY: Duration = Duration::from_millis(5);
const MAX_SAFE_REVISION: u64 = 9_007_199_254_740_991;
const CACHE_TEMPORARY_PREFIX: &str = "capabilities-v1.tmp-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SeedStorageError {
    Cancelled,
    Invalid,
    Untrusted,
    Unavailable,
}

impl fmt::Display for SeedStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "refresh_cancelled",
            Self::Invalid | Self::Untrusted | Self::Unavailable => "device_identity_unavailable",
        })
    }
}

impl std::error::Error for SeedStorageError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SeedStorageEvent {
    RootReady,
    SeedCreatedBeforeWrite,
    SeedFileSynced,
    ParentDirectorySyncAttempted,
}

pub(super) fn load_or_create_device_seed(
    config_directory: &Path,
    cancellation: &CancellationToken,
) -> Result<DeviceIdSeed, SeedStorageError> {
    load_or_create_device_seed_with_observer(config_directory, cancellation, |_| {})
}

pub(super) fn load_or_create_device_seed_with_observer(
    config_directory: &Path,
    cancellation: &CancellationToken,
    mut observer: impl FnMut(SeedStorageEvent),
) -> Result<DeviceIdSeed, SeedStorageError> {
    if cancellation.is_cancelled() {
        return Err(SeedStorageError::Cancelled);
    }
    let directory = platform::prepare_storage_directory(config_directory)?;
    observer(SeedStorageEvent::RootReady);
    if cancellation.is_cancelled() {
        return Err(SeedStorageError::Cancelled);
    }

    for _ in 0..WINNER_REOPEN_ATTEMPTS {
        if cancellation.is_cancelled() {
            return Err(SeedStorageError::Cancelled);
        }
        match platform::open_seed(&directory)? {
            platform::SeedOpen::File(file) => return read_seed(file),
            platform::SeedOpen::Busy => {
                thread::sleep(WINNER_REOPEN_DELAY);
                continue;
            }
            platform::SeedOpen::Missing => {}
        }

        let mut bytes = [0_u8; DEVICE_ID_SEED_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| SeedStorageError::Unavailable)?;
        match platform::create_seed(&directory)? {
            platform::SeedCreate::Created(mut file) => {
                observer(SeedStorageEvent::SeedCreatedBeforeWrite);
                file.write_all(&bytes)
                    .map_err(|_| SeedStorageError::Unavailable)?;
                file.sync_all().map_err(|_| SeedStorageError::Unavailable)?;
                observer(SeedStorageEvent::SeedFileSynced);
                drop(file);
                observer(SeedStorageEvent::ParentDirectorySyncAttempted);
                platform::sync_directory(&directory)?;
                return Ok(DeviceIdSeed::from_storage_bytes(bytes));
            }
            platform::SeedCreate::Exists => continue,
        }
    }
    Err(SeedStorageError::Unavailable)
}

fn read_seed(mut file: File) -> Result<DeviceIdSeed, SeedStorageError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SeedStorageError::Unavailable)?;
    let mut bytes = [0_u8; DEVICE_ID_SEED_BYTES];
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            SeedStorageError::Invalid
        } else {
            SeedStorageError::Unavailable
        }
    })?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| SeedStorageError::Unavailable)?
        != 0
    {
        return Err(SeedStorageError::Invalid);
    }
    Ok(DeviceIdSeed::from_storage_bytes(bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "camelCase")]
pub(crate) enum StorageStatus {
    Uninitialized = 0,
    Writable = 1,
    ReadOnlyLocked = 2,
    Unavailable = 3,
    Invalid = 4,
    Untrusted = 5,
    PersistFailed = 6,
}

impl StorageStatus {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Writable,
            2 => Self::ReadOnlyLocked,
            3 => Self::Unavailable,
            4 => Self::Invalid,
            5 => Self::Untrusted,
            6 => Self::PersistFailed,
            _ => Self::Uninitialized,
        }
    }
}

struct WriteAuthority {
    directory: Arc<platform::ProtectedDirectory>,
    lock: platform::LifetimeLock,
}

struct PersistenceRequest {
    revision: u64,
    runtime: RuntimeEvidenceId,
    records: BTreeMap<CapabilityKey, EvidenceRecord>,
    now: StateNow,
}

#[derive(Default)]
struct PersistenceQueue {
    latest_revision: u64,
    pending: Option<PersistenceRequest>,
    closing: bool,
}

struct StorageShared {
    base_status: StorageStatus,
    status: AtomicU8,
    persisted_revision: AtomicU64,
    queue: StdMutex<PersistenceQueue>,
    notify: Notify,
    completion: Notify,
    cancellation: CancellationToken,
    observer: Option<Arc<dyn PersistenceObserver>>,
    tracker: TaskTracker,
}

impl StorageShared {
    fn new(
        base_status: StorageStatus,
        cancellation: CancellationToken,
        observer: Option<Arc<dyn PersistenceObserver>>,
    ) -> Self {
        Self {
            base_status,
            status: AtomicU8::new(base_status as u8),
            persisted_revision: AtomicU64::new(0),
            queue: StdMutex::new(PersistenceQueue::default()),
            notify: Notify::new(),
            completion: Notify::new(),
            cancellation,
            observer,
            tracker: TaskTracker::new(),
        }
    }

    fn set_status(&self, status: StorageStatus) {
        self.status.store(status as u8, Ordering::Release);
    }

    fn status(&self) -> StorageStatus {
        StorageStatus::from_u8(self.status.load(Ordering::Acquire))
    }
}

trait PersistenceObserver: Send + Sync {
    fn before_replace(&self);
}

#[cfg(test)]
pub(super) struct PersistenceTestHooks {
    entered: tokio::sync::Semaphore,
    release: StdMutex<usize>,
    released: std::sync::Condvar,
}

#[cfg(test)]
impl PersistenceTestHooks {
    pub(super) fn new() -> Self {
        Self {
            entered: tokio::sync::Semaphore::new(0),
            release: StdMutex::new(0),
            released: std::sync::Condvar::new(),
        }
    }

    pub(super) async fn wait_until_entered(&self) {
        self.entered
            .acquire()
            .await
            .expect("persistence test hook remains open")
            .forget();
    }

    pub(super) fn release_one(&self) {
        let mut releases = self.release.lock().unwrap();
        *releases += 1;
        self.released.notify_one();
    }
}

#[cfg(test)]
impl PersistenceObserver for PersistenceTestHooks {
    fn before_replace(&self) {
        self.entered.add_permits(1);
        let mut releases = self.release.lock().unwrap();
        while *releases == 0 {
            releases = self.released.wait(releases).unwrap();
        }
        *releases -= 1;
    }
}

enum PreparedStorage {
    Writer(Arc<WriteAuthority>),
    LockedDisabled(Arc<WriteAuthority>, StorageStatus),
    Reader(Arc<platform::ProtectedDirectory>),
    Disabled(StorageStatus),
}

/// Owns protected cache access and the single bounded persistence worker.
///
/// Call `shutdown` before dropping the last owner. The explicit join keeps the
/// lifetime lock held until any blocking native write has completed.
pub(super) struct EvidenceStorage {
    shared: Arc<StorageShared>,
    directory: Option<Arc<platform::ProtectedDirectory>>,
    authority: StdMutex<Option<Arc<WriteAuthority>>>,
    worker: StdMutex<Option<JoinHandle<()>>>,
    shutdown_gate: tokio::sync::Mutex<()>,
}

impl EvidenceStorage {
    pub(super) async fn open(config_directory: PathBuf, cancellation: CancellationToken) -> Self {
        Self::open_with_observer(config_directory, cancellation, None).await
    }

    #[cfg(test)]
    pub(super) async fn open_with_test_hooks(
        config_directory: PathBuf,
        cancellation: CancellationToken,
        hooks: Arc<PersistenceTestHooks>,
    ) -> Self {
        Self::open_with_observer(config_directory, cancellation, Some(hooks)).await
    }

    async fn open_with_observer(
        config_directory: PathBuf,
        cancellation: CancellationToken,
        observer: Option<Arc<dyn PersistenceObserver>>,
    ) -> Self {
        let storage_cancellation = cancellation.child_token();
        if cancellation.is_cancelled() {
            return Self::disabled(StorageStatus::Unavailable, storage_cancellation);
        }
        let open_cancellation = storage_cancellation.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            prepare_evidence_storage(&config_directory, &open_cancellation)
        })
        .await
        .unwrap_or(PreparedStorage::Disabled(StorageStatus::Unavailable));

        match prepared {
            PreparedStorage::Writer(authority) => {
                let directory = Arc::clone(&authority.directory);
                let shared = Arc::new(StorageShared::new(
                    StorageStatus::Writable,
                    storage_cancellation,
                    observer,
                ));
                let worker = shared.tracker.spawn(persistence_worker(
                    Arc::clone(&shared),
                    Arc::clone(&authority),
                ));
                Self {
                    shared,
                    directory: Some(directory),
                    authority: StdMutex::new(Some(authority)),
                    worker: StdMutex::new(Some(worker)),
                    shutdown_gate: tokio::sync::Mutex::new(()),
                }
            }
            PreparedStorage::LockedDisabled(authority, status) => Self {
                shared: Arc::new(StorageShared::new(status, storage_cancellation, None)),
                directory: Some(Arc::clone(&authority.directory)),
                authority: StdMutex::new(Some(authority)),
                worker: StdMutex::new(None),
                shutdown_gate: tokio::sync::Mutex::new(()),
            },
            PreparedStorage::Reader(directory) => Self {
                shared: Arc::new(StorageShared::new(
                    StorageStatus::ReadOnlyLocked,
                    storage_cancellation,
                    None,
                )),
                directory: Some(directory),
                authority: StdMutex::new(None),
                worker: StdMutex::new(None),
                shutdown_gate: tokio::sync::Mutex::new(()),
            },
            PreparedStorage::Disabled(status) => Self::disabled(status, storage_cancellation),
        }
    }

    pub(super) fn disabled(status: StorageStatus, cancellation: CancellationToken) -> Self {
        Self {
            shared: Arc::new(StorageShared::new(status, cancellation, None)),
            directory: None,
            authority: StdMutex::new(None),
            worker: StdMutex::new(None),
            shutdown_gate: tokio::sync::Mutex::new(()),
        }
    }

    pub(super) fn status(&self) -> StorageStatus {
        self.shared.status()
    }

    pub(super) async fn load_evidence(
        &self,
        runtime: RuntimeEvidenceId,
        now: StateNow,
    ) -> BTreeMap<CapabilityKey, EvidenceRecord> {
        if self.shared.cancellation.is_cancelled() {
            return BTreeMap::new();
        }
        let Some(directory) = self.directory.as_ref().map(Arc::clone) else {
            return BTreeMap::new();
        };
        let cancellation = self.shared.cancellation.clone();
        let loaded = self
            .shared
            .tracker
            .spawn_blocking(move || read_evidence_cache(&directory, &runtime, now, &cancellation))
            .await;
        match loaded {
            Ok(Ok(records)) => {
                if !matches!(
                    self.shared.status(),
                    StorageStatus::PersistFailed | StorageStatus::Untrusted
                ) {
                    self.shared.set_status(self.shared.base_status);
                }
                records
            }
            Ok(Err(CacheLoadError::IdentityMismatch | CacheLoadError::Cancelled)) => {
                BTreeMap::new()
            }
            Ok(Err(CacheLoadError::Invalid)) => {
                self.shared.set_status(StorageStatus::Invalid);
                BTreeMap::new()
            }
            Ok(Err(CacheLoadError::Untrusted)) => {
                self.shared.set_status(StorageStatus::Untrusted);
                BTreeMap::new()
            }
            Ok(Err(CacheLoadError::Unavailable)) | Err(_) => {
                self.shared.set_status(StorageStatus::Unavailable);
                BTreeMap::new()
            }
        }
    }

    /// Replaces the not-yet-started request with this newer revision.
    pub(super) fn request_persist(
        &self,
        revision: u64,
        runtime: RuntimeEvidenceId,
        records: BTreeMap<CapabilityKey, EvidenceRecord>,
        now: StateNow,
    ) -> bool {
        if revision == 0
            || revision > MAX_SAFE_REVISION
            || self
                .authority
                .lock()
                .map_or(true, |authority| authority.is_none())
            || matches!(
                self.shared.status(),
                StorageStatus::Untrusted
                    | StorageStatus::Unavailable
                    | StorageStatus::ReadOnlyLocked
                    | StorageStatus::Uninitialized
            )
        {
            return false;
        }
        let Ok(mut queue) = self.shared.queue.lock() else {
            self.shared.set_status(StorageStatus::PersistFailed);
            return false;
        };
        if queue.closing || revision <= queue.latest_revision {
            return false;
        }
        queue.latest_revision = revision;
        queue.pending = Some(PersistenceRequest {
            revision,
            runtime,
            records,
            now,
        });
        drop(queue);
        self.shared.notify.notify_one();
        true
    }

    pub(super) fn begin_shutdown(&self) {
        self.shared.cancellation.cancel();
        if let Ok(mut queue) = self.shared.queue.lock() {
            queue.closing = true;
            queue.pending = None;
        } else {
            self.shared.set_status(StorageStatus::PersistFailed);
        }
        self.shared.notify.notify_waiters();
        self.shared.completion.notify_waiters();
    }

    pub(super) async fn wait_for_persisted(&self, revision: u64) -> bool {
        loop {
            let completed = self.shared.completion.notified();
            if self.shared.persisted_revision.load(Ordering::Acquire) >= revision {
                return true;
            }
            if self.shared.queue.lock().map_or(true, |queue| queue.closing) {
                return false;
            }
            completed.await;
        }
    }

    pub(super) async fn shutdown(&self) {
        let _shutdown = self.shutdown_gate.lock().await;
        self.begin_shutdown();
        let worker = self.worker.lock().ok().and_then(|mut worker| worker.take());
        if let Some(worker) = worker
            && worker.await.is_err()
        {
            self.shared.set_status(StorageStatus::PersistFailed);
        }
        self.shared.tracker.close();
        self.shared.tracker.wait().await;
        if let Ok(mut authority) = self.authority.lock() {
            authority.take();
        }
    }
}

impl Drop for EvidenceStorage {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

fn prepare_evidence_storage(
    config_directory: &Path,
    cancellation: &CancellationToken,
) -> PreparedStorage {
    if cancellation.is_cancelled() {
        return PreparedStorage::Disabled(StorageStatus::Unavailable);
    }
    let directory = match platform::prepare_storage_directory(config_directory) {
        Ok(directory) => Arc::new(directory),
        Err(SeedStorageError::Untrusted | SeedStorageError::Invalid) => {
            return PreparedStorage::Disabled(StorageStatus::Untrusted);
        }
        Err(SeedStorageError::Cancelled | SeedStorageError::Unavailable) => {
            return PreparedStorage::Disabled(StorageStatus::Unavailable);
        }
    };
    match platform::acquire_lifetime_lock(&directory) {
        Ok(platform::LifetimeLockOpen::Contended) => PreparedStorage::Reader(directory),
        Ok(platform::LifetimeLockOpen::Acquired(lock)) => {
            let authority = Arc::new(WriteAuthority { directory, lock });
            match recover_cache_temporaries(&authority, cancellation) {
                Ok(()) => PreparedStorage::Writer(authority),
                Err(SeedStorageError::Untrusted | SeedStorageError::Invalid) => {
                    PreparedStorage::LockedDisabled(authority, StorageStatus::Untrusted)
                }
                Err(SeedStorageError::Cancelled | SeedStorageError::Unavailable) => {
                    PreparedStorage::LockedDisabled(authority, StorageStatus::Unavailable)
                }
            }
        }
        Err(SeedStorageError::Untrusted | SeedStorageError::Invalid) => {
            PreparedStorage::Disabled(StorageStatus::Untrusted)
        }
        Err(SeedStorageError::Cancelled | SeedStorageError::Unavailable) => {
            PreparedStorage::Disabled(StorageStatus::Unavailable)
        }
    }
}

fn recover_cache_temporaries(
    authority: &WriteAuthority,
    cancellation: &CancellationToken,
) -> Result<(), SeedStorageError> {
    platform::validate_lifetime_lock(&authority.directory, &authority.lock)?;
    let names = platform::list_cache_temporaries(&authority.directory)?;
    for name in names {
        if cancellation.is_cancelled() {
            return Err(SeedStorageError::Cancelled);
        }
        let file = platform::open_cache_temporary(&authority.directory, &name)?;
        platform::discard_temporary(&authority.directory, &file, &name)?;
    }
    platform::sync_directory(&authority.directory)
}

enum CacheLoadError {
    Cancelled,
    IdentityMismatch,
    Invalid,
    Unavailable,
    Untrusted,
}

fn read_evidence_cache(
    directory: &platform::ProtectedDirectory,
    runtime: &RuntimeEvidenceId,
    now: StateNow,
    cancellation: &CancellationToken,
) -> Result<BTreeMap<CapabilityKey, EvidenceRecord>, CacheLoadError> {
    if cancellation.is_cancelled() {
        return Err(CacheLoadError::Cancelled);
    }
    let Some(mut file) = platform::open_cache(directory).map_err(map_load_storage_error)? else {
        return Ok(BTreeMap::new());
    };
    let length = usize::try_from(
        file.metadata()
            .map_err(|_| CacheLoadError::Untrusted)?
            .len(),
    )
    .map_err(|_| CacheLoadError::Invalid)?;
    if length > MAX_CACHE_BYTES {
        return Err(CacheLoadError::Invalid);
    }
    let mut bytes = Vec::with_capacity(length);
    Read::by_ref(&mut file)
        .take((MAX_CACHE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CacheLoadError::Unavailable)?;
    if bytes.len() > MAX_CACHE_BYTES {
        return Err(CacheLoadError::Invalid);
    }
    if cancellation.is_cancelled() {
        return Err(CacheLoadError::Cancelled);
    }
    decode_evidence_cache(&bytes, runtime, now).map_err(|error| match error {
        CacheSchemaError::IdentityMismatch => CacheLoadError::IdentityMismatch,
        CacheSchemaError::Bounds | CacheSchemaError::Invalid => CacheLoadError::Invalid,
    })
}

fn map_load_storage_error(error: SeedStorageError) -> CacheLoadError {
    match error {
        SeedStorageError::Cancelled => CacheLoadError::Cancelled,
        SeedStorageError::Invalid => CacheLoadError::Invalid,
        SeedStorageError::Untrusted => CacheLoadError::Untrusted,
        SeedStorageError::Unavailable => CacheLoadError::Unavailable,
    }
}

async fn persistence_worker(shared: Arc<StorageShared>, authority: Arc<WriteAuthority>) {
    loop {
        let request = match shared.queue.lock() {
            Ok(mut queue) => {
                if queue.closing {
                    return;
                }
                queue.pending.take()
            }
            Err(_) => {
                shared.set_status(StorageStatus::PersistFailed);
                return;
            }
        };
        let Some(request) = request else {
            shared.notify.notified().await;
            continue;
        };
        let worker_shared = Arc::clone(&shared);
        let worker_authority = Arc::clone(&authority);
        match shared
            .tracker
            .spawn_blocking(move || persist_one(&worker_shared, &worker_authority, request))
            .await
        {
            Ok(PersistOutcome::Installed(revision)) => {
                shared.persisted_revision.store(revision, Ordering::Release);
                shared.set_status(StorageStatus::Writable);
                shared.completion.notify_waiters();
            }
            Ok(PersistOutcome::Stale | PersistOutcome::Cancelled) => {}
            Ok(PersistOutcome::Failed) | Err(_) => {
                shared.set_status(StorageStatus::PersistFailed);
                if let Ok(mut queue) = shared.queue.lock() {
                    queue.closing = true;
                    queue.pending = None;
                }
                shared.completion.notify_waiters();
                return;
            }
        }
    }
}

enum PersistOutcome {
    Installed(u64),
    Stale,
    Cancelled,
    Failed,
}

fn persist_one(
    shared: &StorageShared,
    authority: &WriteAuthority,
    request: PersistenceRequest,
) -> PersistOutcome {
    if shared.cancellation.is_cancelled() {
        return PersistOutcome::Cancelled;
    }
    if platform::validate_lifetime_lock(&authority.directory, &authority.lock).is_err() {
        return PersistOutcome::Failed;
    }
    let bytes = match encode_evidence_cache(&request.runtime, &request.records, request.now) {
        Ok(bytes) => bytes,
        Err(_) => return PersistOutcome::Failed,
    };
    if shared.cancellation.is_cancelled() {
        return PersistOutcome::Cancelled;
    }
    let mut random = [0_u8; 16];
    if getrandom::fill(&mut random).is_err() {
        return PersistOutcome::Failed;
    }
    let name = format!("{CACHE_TEMPORARY_PREFIX}{}", hex::encode(random));
    let mut temporary = match platform::create_cache_temporary(&authority.directory, &name) {
        Ok(file) => file,
        Err(_) => return PersistOutcome::Failed,
    };
    let written = temporary
        .write_all(&bytes)
        .and_then(|()| temporary.sync_all());
    if written.is_err() {
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        return PersistOutcome::Failed;
    }
    if shared.cancellation.is_cancelled() {
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        return PersistOutcome::Cancelled;
    }
    if let Some(observer) = &shared.observer {
        observer.before_replace();
    }

    let Ok(queue) = shared.queue.lock() else {
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        return PersistOutcome::Failed;
    };
    if queue.closing || shared.cancellation.is_cancelled() {
        drop(queue);
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        return PersistOutcome::Cancelled;
    }
    if queue.latest_revision != request.revision {
        drop(queue);
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        return PersistOutcome::Stale;
    }
    if platform::validate_lifetime_lock(&authority.directory, &authority.lock).is_err() {
        drop(queue);
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        return PersistOutcome::Failed;
    }
    let replaced = platform::replace_cache_temporary(&authority.directory, &temporary, &name);
    drop(queue);
    if replaced
        .and_then(|()| platform::sync_directory(&authority.directory))
        .is_ok()
    {
        PersistOutcome::Installed(request.revision)
    } else {
        let _ = platform::discard_temporary(&authority.directory, &temporary, &name);
        PersistOutcome::Failed
    }
}

#[cfg(test)]
pub(super) fn create_cache_temporary_for_test(
    config_directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), SeedStorageError> {
    let directory = platform::prepare_storage_directory(config_directory)?;
    let mut file = platform::create_cache_temporary(&directory, name)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| SeedStorageError::Unavailable)?;
    platform::sync_directory(&directory)
}

#[cfg(not(any(unix, windows)))]
compile_error!("protected device seed storage is unsupported on this target");
