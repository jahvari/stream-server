#[cfg(all(test, windows))]
use std::sync::atomic::{AtomicU32, AtomicUsize};
use std::{
    collections::{BTreeMap, HashMap},
    ffi::OsString,
    fmt,
    path::PathBuf,
    process::ExitStatus,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
mod windows;

const DEFAULT_MAX_CONCURRENT_PROCESSES: usize = 8;
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WALL_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);
const CANCELLATION_GRACE: Duration = Duration::from_secs(2);
const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);

#[cfg(test)]
pub(super) static PROCESS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(all(test, windows))]
#[derive(Default)]
pub(super) struct WindowsLifecycleHooks {
    pause_owner_complete: AtomicBool,
    owner_complete_reached: AtomicBool,
    pause_reader_handoff: AtomicBool,
    reader_handoff_reached: AtomicBool,
    pause_reader_completion: AtomicBool,
    reader_completion_reached: AtomicUsize,
    pause_after_resume: AtomicBool,
    after_resume_reached: AtomicBool,
    last_created_pid: AtomicU32,
}

#[cfg(all(test, windows))]
impl WindowsLifecycleHooks {
    fn set_owner_complete_pause(&self, paused: bool) {
        self.pause_owner_complete.store(paused, Ordering::Release);
        if paused {
            self.owner_complete_reached.store(false, Ordering::Release);
        }
    }

    fn owner_complete_reached(&self) -> bool {
        self.owner_complete_reached.load(Ordering::Acquire)
    }

    async fn pause_owner_complete(&self) {
        self.owner_complete_reached.store(true, Ordering::Release);
        while self.pause_owner_complete.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn set_reader_handoff_pause(&self, paused: bool) {
        self.pause_reader_handoff.store(paused, Ordering::Release);
        if paused {
            self.reader_handoff_reached.store(false, Ordering::Release);
        }
    }

    fn reader_handoff_reached(&self) -> bool {
        self.reader_handoff_reached.load(Ordering::Acquire)
    }

    async fn pause_reader_handoff(&self) {
        self.reader_handoff_reached.store(true, Ordering::Release);
        while self.pause_reader_handoff.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn set_reader_completion_pause(&self, paused: bool) {
        self.pause_reader_completion
            .store(paused, Ordering::Release);
        if paused {
            self.reader_completion_reached.store(0, Ordering::Release);
        }
    }

    fn reader_completion_reached(&self) -> bool {
        self.reader_completion_reached.load(Ordering::Acquire) >= 2
    }

    fn pause_reader_completion(&self) {
        self.reader_completion_reached
            .fetch_add(1, Ordering::AcqRel);
        while self.pause_reader_completion.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn set_after_resume_pause(&self, paused: bool) {
        self.pause_after_resume.store(paused, Ordering::Release);
        if paused {
            self.after_resume_reached.store(false, Ordering::Release);
        }
    }

    fn after_resume_reached(&self) -> bool {
        self.after_resume_reached.load(Ordering::Acquire)
    }

    fn pause_after_resume(&self) {
        self.after_resume_reached.store(true, Ordering::Release);
        while self.pause_after_resume.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn clear_last_created_pid(&self) {
        self.last_created_pid.store(0, Ordering::Release);
    }

    fn record_created_pid(&self, pid: u32) {
        self.last_created_pid.store(pid, Ordering::Release);
    }

    fn last_created_pid(&self) -> u32 {
        self.last_created_pid.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StdoutPolicy {
    Null,
    Capture { byte_limit: usize },
    Stream { queue_bytes: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdinPolicy {
    Null,
}

#[derive(Clone, Debug)]
pub struct ProcessSpec {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub current_dir: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub stdin: StdinPolicy,
    pub stdout: StdoutPolicy,
    pub stderr_byte_limit: usize,
    pub wall_deadline: Duration,
}

#[derive(Debug)]
pub struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessErrorCode {
    InvalidSpec,
    UnsupportedPolicy,
    SpawnFailed,
    Cancelled,
    DeadlineExceeded,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    WaitFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessError {
    code: ProcessErrorCode,
}

impl ProcessError {
    pub fn code(&self) -> ProcessErrorCode {
        self.code
    }

    fn new(code: ProcessErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.code {
            ProcessErrorCode::InvalidSpec => "invalid process specification",
            ProcessErrorCode::UnsupportedPolicy => "process policy is not supported",
            ProcessErrorCode::SpawnFailed => "process could not be started",
            ProcessErrorCode::Cancelled => "process cancelled",
            ProcessErrorCode::DeadlineExceeded => "process deadline exceeded",
            ProcessErrorCode::StdoutLimitExceeded => "process stdout limit exceeded",
            ProcessErrorCode::StderrLimitExceeded => "process stderr limit exceeded",
            ProcessErrorCode::WaitFailed => "process wait failed",
        })
    }
}

impl std::error::Error for ProcessError {}

#[derive(Clone)]
pub struct ProcessSupervisor {
    inner: Arc<SupervisorInner>,
}

struct SupervisorInner {
    cancellation: CancellationToken,
    permits: Arc<Semaphore>,
    accepting: AtomicBool,
    admission_gate: Mutex<()>,
    registry: Arc<ProcessRegistry>,
    #[cfg(all(test, windows))]
    failure_point: Option<FailurePoint>,
}

struct ProcessRegistry {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, RegisteredEntry>>,
    idle: Notify,
    #[cfg(all(test, windows))]
    test_hooks: Arc<WindowsLifecycleHooks>,
    #[cfg(all(test, windows))]
    test_resources: Arc<windows::NativeResourceTracker>,
}

#[cfg(windows)]
type WindowsReaderTask = tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>;

struct RegisteredEntry {
    target: RegisteredTarget,
    retained: bool,
    cleanup_started: bool,
    permit: Option<OwnedSemaphorePermit>,
    #[cfg(unix)]
    unix_killable: bool,
    #[cfg(windows)]
    readers_expected: bool,
    #[cfg(windows)]
    cleanup_tasks: Vec<WindowsReaderTask>,
}

#[derive(Clone)]
enum RegisteredTarget {
    #[cfg(windows)]
    WindowsProcessTree {
        job: Arc<windows::TrackedHandle>,
        process: Arc<windows::TrackedHandle>,
    },
    #[cfg(unix)]
    UnixProcessGroup(i32),
}

#[cfg(any(unix, test))]
struct UnixGroupIdentity {
    process_group: i32,
    final_signal_sent: bool,
    leader_reaped: bool,
}

#[cfg(any(unix, test))]
impl UnixGroupIdentity {
    fn new(process_group: i32) -> Self {
        Self {
            process_group,
            final_signal_sent: false,
            leader_reaped: false,
        }
    }

    fn final_signal_target(&self) -> Option<i32> {
        (!self.final_signal_sent && !self.leader_reaped).then_some(self.process_group)
    }

    fn mark_final_signal_sent(&mut self) {
        self.final_signal_sent = true;
    }

    fn record_final_signal_result(
        &mut self,
        result: Result<(), ProcessError>,
    ) -> Result<(), ProcessError> {
        result?;
        self.mark_final_signal_sent();
        Ok(())
    }

    fn mark_leader_reaped(&mut self) -> Result<(), ProcessError> {
        if !self.final_signal_sent {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
        self.leader_reaped = true;
        Ok(())
    }

    fn killable_for_retention(&self) -> bool {
        self.final_signal_target().is_some()
    }
}

#[cfg(any(unix, test))]
struct UnixDurableOwnership {
    final_signal_sent: bool,
    child_reaped: bool,
    readers_joined: usize,
}

#[cfg(any(unix, test))]
impl UnixDurableOwnership {
    fn new() -> Self {
        Self {
            final_signal_sent: false,
            child_reaped: false,
            readers_joined: 0,
        }
    }

    fn mark_final_signal_sent(&mut self) {
        self.final_signal_sent = true;
    }

    fn mark_child_reaped(&mut self) {
        self.child_reaped = true;
    }

    fn mark_reader_joined(&mut self) {
        self.readers_joined = self.readers_joined.saturating_add(1).min(2);
    }

    fn record_reader_join_result<T>(
        &mut self,
        result: Result<T, ProcessError>,
    ) -> Result<T, ProcessError> {
        self.mark_reader_joined();
        result
    }

    fn can_release(&self) -> bool {
        self.final_signal_sent && self.child_reaped && self.readers_joined == 2
    }
}

pub(super) struct Registration {
    registry: Arc<ProcessRegistry>,
    id: u64,
    completed: bool,
    #[cfg(windows)]
    owner_started: bool,
    #[cfg(windows)]
    owner_signal: Option<tokio::sync::oneshot::Sender<WindowsOwnerAction>>,
}

#[cfg(windows)]
enum WindowsOwnerAction {
    Complete(tokio::sync::oneshot::Sender<WindowsOwnerResult>),
}

#[cfg(windows)]
type WindowsReaderResults = [Result<Vec<u8>, ProcessError>; 2];
#[cfg(windows)]
type WindowsOwnerResult = Result<WindowsReaderResults, ProcessError>;

impl ProcessRegistry {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: Mutex::new(HashMap::new()),
            idle: Notify::new(),
            #[cfg(all(test, windows))]
            test_hooks: Arc::new(WindowsLifecycleHooks::default()),
            #[cfg(all(test, windows))]
            test_resources: Arc::new(windows::NativeResourceTracker::default()),
        }
    }

    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(windows)]
    fn register_windows(
        self: &Arc<Self>,
        job: Arc<windows::TrackedHandle>,
        process: Arc<windows::TrackedHandle>,
    ) -> Registration {
        self.register(RegisteredTarget::WindowsProcessTree { job, process })
    }

    #[cfg(unix)]
    fn register_unix(self: &Arc<Self>, process_group: i32) -> Registration {
        self.register(RegisteredTarget::UnixProcessGroup(process_group))
    }

    fn register(self: &Arc<Self>, target: RegisteredTarget) -> Registration {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                id,
                RegisteredEntry {
                    target,
                    retained: false,
                    cleanup_started: false,
                    permit: None,
                    #[cfg(unix)]
                    unix_killable: true,
                    #[cfg(windows)]
                    readers_expected: false,
                    #[cfg(windows)]
                    cleanup_tasks: Vec::new(),
                },
            );
        Registration {
            registry: self.clone(),
            id,
            completed: false,
            #[cfg(windows)]
            owner_started: false,
            #[cfg(windows)]
            owner_signal: None,
        }
    }

    fn complete(&self, id: u64) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let became_idle = entries.remove(&id).is_some() && entries.is_empty();
        drop(entries);
        if became_idle {
            self.idle.notify_waiters();
        }
    }

    #[cfg(windows)]
    fn mark_cleanup_stopped(&self, id: u64) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&id)
        {
            entry.cleanup_started = false;
        }
        self.idle.notify_waiters();
    }

    #[cfg(windows)]
    fn mark_retained(&self, id: u64) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&id)
        {
            entry.retained = true;
        }
    }

    #[cfg(windows)]
    fn terminate_windows_fallback(&self, id: u64) {
        let target = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&id)
            .map(|entry| entry.target.clone());
        if let Some(RegisteredTarget::WindowsProcessTree { job, .. }) = target {
            let _ = windows::terminate(&job);
        }
    }

    #[cfg(windows)]
    fn begin_retained_cleanup(self: &Arc<Self>, id: u64) {
        let should_start = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(entry) = entries.get_mut(&id) else {
                return;
            };
            entry.retained = true;
            if entry.cleanup_started {
                false
            } else {
                entry.cleanup_started = true;
                true
            }
        };
        if !should_start {
            return;
        }
        if !spawn_abandoned_windows_cleanup(self.clone(), id) {
            self.terminate_windows_fallback(id);
            self.mark_cleanup_stopped(id);
        }
    }

    #[cfg(unix)]
    fn mark_unix_final_signal_sent(&self, id: u64) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = entries.get_mut(&id) else {
            return;
        };
        entry.unix_killable = false;
    }

    #[cfg(unix)]
    fn retain_unix(&self, id: u64, killable: bool) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = entries.get_mut(&id) else {
            return;
        };
        entry.unix_killable = killable;
        entry.retained = true;
        entry.cleanup_started = false;
    }

    fn force_terminate_all(&self) -> Result<(), ProcessError> {
        let entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut failed = false;
        for entry in entries.values() {
            let result = match &entry.target {
                #[cfg(windows)]
                RegisteredTarget::WindowsProcessTree { job, .. } => windows::terminate(job),
                #[cfg(unix)]
                RegisteredTarget::UnixProcessGroup(process_group) if entry.unix_killable => {
                    terminate_unix_group(*process_group)
                }
                #[cfg(unix)]
                RegisteredTarget::UnixProcessGroup(_) => Ok(()),
            };
            failed |= result.is_err();
        }
        if failed {
            Err(ProcessError::new(ProcessErrorCode::WaitFailed))
        } else {
            Ok(())
        }
    }

    fn reap_retained(&self) -> Result<(), ProcessError> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut failed = false;
        entries.retain(|_, entry| {
            if !entry.retained {
                return true;
            }
            if entry.cleanup_started {
                return true;
            }
            #[cfg(windows)]
            let cleanup_finished = entry.cleanup_tasks.iter().all(|task| task.is_finished());
            #[cfg(not(windows))]
            let cleanup_finished = true;
            let drained = match &entry.target {
                #[cfg(windows)]
                RegisteredTarget::WindowsProcessTree { job, process } => {
                    windows::is_process_tree_drained(job, process)
                }
                #[cfg(unix)]
                RegisteredTarget::UnixProcessGroup(process_group) => {
                    unix_group_is_empty(*process_group)
                }
            };
            match drained {
                Ok(drained) => !(drained && cleanup_finished),
                Err(_) => {
                    failed = true;
                    true
                }
            }
        });
        let idle = entries.is_empty();
        drop(entries);
        if idle {
            self.idle.notify_waiters();
        }
        if failed {
            Err(ProcessError::new(ProcessErrorCode::WaitFailed))
        } else {
            Ok(())
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if !self.completed {
            #[cfg(windows)]
            {
                if self.owner_started {
                    self.registry.mark_retained(self.id);
                } else {
                    self.registry.begin_retained_cleanup(self.id);
                }
            }
            #[cfg(unix)]
            self.registry.retain_unix(self.id, true);
            #[cfg(windows)]
            drop(self.owner_signal.take());
        }
    }
}

impl Registration {
    fn bind_permit(&self, permit: OwnedSemaphorePermit) {
        let mut permit = Some(permit);
        if let Some(entry) = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&self.id)
        {
            entry.permit = permit.take();
        }
    }

    fn complete(mut self) {
        self.completed = true;
        self.registry.complete(self.id);
    }

    #[cfg(windows)]
    async fn finish_windows(mut self) -> WindowsOwnerResult {
        let signal = self
            .owner_signal
            .take()
            .ok_or_else(|| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        let (result, receiver) = tokio::sync::oneshot::channel();
        signal
            .send(WindowsOwnerAction::Complete(result))
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        let output = receiver
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        self.completed = true;
        output
    }

    #[cfg(all(windows, test))]
    fn retain(mut self) {
        self.registry.begin_retained_cleanup(self.id);
        self.completed = true;
    }

    #[cfg(unix)]
    fn mark_unix_final_signal_sent(&self) {
        self.registry.mark_unix_final_signal_sent(self.id);
    }

    #[cfg(unix)]
    fn retain(mut self, killable: bool) {
        self.registry.retain_unix(self.id, killable);
        self.completed = true;
    }

    #[cfg(windows)]
    fn set_windows_readers(
        &self,
        stdout: tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
        stderr: tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
    ) {
        if let Some(entry) = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&self.id)
        {
            entry.readers_expected = true;
            entry.cleanup_tasks.extend([stdout, stderr]);
        }
    }

    #[cfg(windows)]
    fn start_windows_owner(&mut self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.start_windows_owner_on(&runtime);
    }

    #[cfg(windows)]
    fn start_windows_owner_on(&mut self, runtime: &tokio::runtime::Handle) {
        if self.owner_signal.is_some() {
            return;
        }
        let (signal, receiver) = tokio::sync::oneshot::channel();
        self.owner_signal = Some(signal);
        self.owner_started = true;
        if let Some(entry) = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&self.id)
        {
            entry.cleanup_started = true;
        }
        spawn_windows_owner(self.registry.clone(), self.id, receiver, runtime);
    }
}

#[cfg(unix)]
struct UnixOwnedProcess {
    child: Option<tokio::process::Child>,
    registration: Option<Registration>,
    identity: UnixGroupIdentity,
    ownership: UnixDurableOwnership,
}

#[cfg(unix)]
impl UnixOwnedProcess {
    fn new(child: tokio::process::Child, process_group: i32, registration: Registration) -> Self {
        Self {
            child: Some(child),
            registration: Some(registration),
            identity: UnixGroupIdentity::new(process_group),
            ownership: UnixDurableOwnership::new(),
        }
    }

    fn process_group(&self) -> i32 {
        self.identity.process_group
    }

    fn child_mut(&mut self) -> Result<&mut tokio::process::Child, ProcessError> {
        self.child
            .as_mut()
            .ok_or_else(|| ProcessError::new(ProcessErrorCode::WaitFailed))
    }

    fn send_final_signal(&mut self) -> Result<(), ProcessError> {
        let Some(process_group) = self.identity.final_signal_target() else {
            return Ok(());
        };
        self.identity
            .record_final_signal_result(terminate_unix_group(process_group))?;
        self.ownership.mark_final_signal_sent();
        if let Some(registration) = &self.registration {
            registration.mark_unix_final_signal_sent();
        }
        Ok(())
    }

    fn mark_leader_reaped(&mut self) -> Result<(), ProcessError> {
        self.identity.mark_leader_reaped()?;
        self.ownership.mark_child_reaped();
        Ok(())
    }

    fn complete(mut self) -> Result<(), ProcessError> {
        if !self.ownership.can_release() {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
        self.registration
            .take()
            .ok_or_else(|| ProcessError::new(ProcessErrorCode::WaitFailed))?
            .complete();
        drop(self.child.take());
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for UnixOwnedProcess {
    fn drop(&mut self) {
        let _ = self.send_final_signal();
        let killable = self.identity.killable_for_retention();
        if let Some(registration) = self.registration.take() {
            registration.retain(killable);
        }
        drop(self.child.take());
    }
}

impl ProcessSupervisor {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self::with_max_concurrency(cancellation, DEFAULT_MAX_CONCURRENT_PROCESSES)
    }

    pub fn with_max_concurrency(cancellation: CancellationToken, maximum: usize) -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                cancellation,
                permits: Arc::new(Semaphore::new(maximum.max(1))),
                accepting: AtomicBool::new(true),
                admission_gate: Mutex::new(()),
                registry: Arc::new(ProcessRegistry::new()),
                #[cfg(all(test, windows))]
                failure_point: None,
            }),
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    pub fn active_processes(&self) -> usize {
        self.inner.registry.len()
    }

    #[cfg(all(test, windows))]
    fn test_hooks(&self) -> Arc<WindowsLifecycleHooks> {
        self.inner.registry.test_hooks.clone()
    }

    #[cfg(all(test, windows))]
    fn test_resource_snapshot(&self) -> windows::ResourceSnapshot {
        self.inner.registry.test_resources.snapshot()
    }

    #[cfg(all(test, windows))]
    fn test_native_handle_count(&self) -> usize {
        self.inner.registry.test_resources.handle_count()
    }

    pub fn cancel(&self) {
        let _gate = self
            .inner
            .admission_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.inner.accepting.store(false, Ordering::Release);
        self.inner.cancellation.cancel();
    }

    pub fn force_terminate_registered(&self) -> Result<(), ProcessError> {
        self.inner.registry.force_terminate_all()
    }

    pub async fn wait_for_idle(&self, deadline: Duration) -> Result<(), ProcessError> {
        let expires = tokio::time::Instant::now() + deadline;
        loop {
            let notified = self.inner.registry.idle.notified();
            self.inner.registry.reap_retained()?;
            if self.active_processes() == 0 {
                return Ok(());
            }
            let tick = tokio::time::sleep(Duration::from_millis(5));
            tokio::pin!(tick);
            if tokio::time::timeout_at(expires, async {
                tokio::select! {
                    _ = notified => {},
                    _ = &mut tick => {},
                }
            })
            .await
            .is_err()
            {
                self.inner.registry.reap_retained()?;
                return if self.active_processes() == 0 {
                    Ok(())
                } else {
                    Err(ProcessError::new(ProcessErrorCode::WaitFailed))
                };
            }
        }
    }

    pub async fn run_bounded(&self, spec: ProcessSpec) -> Result<BoundedOutput, ProcessError> {
        self.run_bounded_with_cancellation(spec, &CancellationToken::new())
            .await
    }

    pub(super) async fn run_bounded_with_cancellation(
        &self,
        spec: ProcessSpec,
        operation_cancellation: &CancellationToken,
    ) -> Result<BoundedOutput, ProcessError> {
        validate_common_spec(&spec)?;
        if operation_cancellation.is_cancelled() {
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }
        if self.inner.cancellation.is_cancelled() || !self.inner.accepting.load(Ordering::Acquire) {
            self.cancel();
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }
        let permit = tokio::select! {
            biased;
            _ = operation_cancellation.cancelled() => {
                return Err(ProcessError::new(ProcessErrorCode::Cancelled));
            },
            _ = self.inner.cancellation.cancelled() => {
                self.cancel();
                return Err(ProcessError::new(ProcessErrorCode::Cancelled));
            },
            permit = self.inner.permits.clone().acquire_owned() => permit.map_err(|_| ProcessError::new(ProcessErrorCode::Cancelled))?,
        };
        if operation_cancellation.is_cancelled() {
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }
        if self.inner.cancellation.is_cancelled() || !self.inner.accepting.load(Ordering::Acquire) {
            self.cancel();
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }

        #[cfg(windows)]
        let result = self.run_windows(spec, permit, operation_cancellation).await;
        #[cfg(unix)]
        let result = self.run_unix(spec, permit, operation_cancellation).await;
        #[cfg(not(any(windows, unix)))]
        let result = Err(ProcessError::new(ProcessErrorCode::SpawnFailed));

        result
    }

    #[cfg(all(test, windows))]
    fn with_failure_point(cancellation: CancellationToken, point: FailurePoint) -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                cancellation,
                permits: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_PROCESSES)),
                accepting: AtomicBool::new(true),
                admission_gate: Mutex::new(()),
                registry: Arc::new(ProcessRegistry::new()),
                failure_point: Some(point),
            }),
        }
    }

    #[cfg(windows)]
    async fn run_windows(
        &self,
        spec: ProcessSpec,
        permit: OwnedSemaphorePermit,
        operation_cancellation: &CancellationToken,
    ) -> Result<BoundedOutput, ProcessError> {
        use std::os::windows::process::ExitStatusExt;
        let wall_expires = tokio::time::Instant::now() + spec.wall_deadline;

        let failure_point = {
            #[cfg(test)]
            {
                self.inner.failure_point
            }
            #[cfg(not(test))]
            {
                None
            }
        };
        let inner = self.inner.clone();
        let operation_cancellation_for_spawn = operation_cancellation.clone();
        let owner_runtime = tokio::runtime::Handle::current();
        let (spec, spawned) = tokio::task::spawn_blocking(move || {
            let _gate = inner
                .admission_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if operation_cancellation_for_spawn.is_cancelled()
                || inner.cancellation.is_cancelled()
                || !inner.accepting.load(Ordering::Acquire)
            {
                return (spec, Err(ProcessError::new(ProcessErrorCode::Cancelled)));
            }
            let mut spawned = windows::spawn(&spec, inner.registry.clone(), failure_point);
            if let Ok(spawned) = &mut spawned {
                spawned.registration.bind_permit(permit);
                spawned.registration.start_windows_owner_on(&owner_runtime);
                #[cfg(test)]
                if failure_point == Some(FailurePoint::PauseAfterResume) {
                    inner.registry.test_hooks.pause_after_resume();
                }
            }
            (spec, spawned)
        })
        .await
        .map_err(|_| ProcessError::new(ProcessErrorCode::SpawnFailed))?;
        let spawned = spawned?;
        let windows::SpawnedProcess {
            process,
            job,
            stdout,
            stderr,
            mut registration,
        } = spawned;
        let (limit_tx, mut limit_rx) = tokio::sync::mpsc::unbounded_channel();
        let stdout_limit = match spec.stdout {
            StdoutPolicy::Null => None,
            StdoutPolicy::Capture { byte_limit } => Some(byte_limit),
            StdoutPolicy::Stream { queue_bytes } => Some(queue_bytes),
        };
        let keep_stdout = !matches!(spec.stdout, StdoutPolicy::Null);
        let stdout_reader = windows::read_pipe(
            stdout,
            stdout_limit,
            keep_stdout,
            ProcessErrorCode::StdoutLimitExceeded,
            limit_tx.clone(),
            #[cfg(test)]
            self.inner.registry.test_hooks.clone(),
        );
        let stderr_reader = windows::read_pipe(
            stderr,
            Some(spec.stderr_byte_limit),
            true,
            ProcessErrorCode::StderrLimitExceeded,
            limit_tx,
            #[cfg(test)]
            self.inner.registry.test_hooks.clone(),
        );
        registration.set_windows_readers(stdout_reader, stderr_reader);
        registration.start_windows_owner();

        #[cfg(test)]
        let injected_stop = match failure_point {
            Some(FailurePoint::Resume) => Some(ProcessErrorCode::SpawnFailed),
            Some(FailurePoint::ResumeAfterDescendant) => {
                wait_for_test_descendant_marker(&spec).await?;
                Some(ProcessErrorCode::SpawnFailed)
            }
            _ => None,
        };
        #[cfg(not(test))]
        let injected_stop = None;

        #[cfg(test)]
        if failure_point == Some(FailurePoint::WaitAfterReaders) {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }

        let mut wait_process = Box::pin(wait_windows_process(process.clone()));
        let deadline = tokio::time::sleep_until(wall_expires);
        tokio::pin!(deadline);

        enum Completion {
            Exited(Result<u32, ProcessError>),
            Stop(ProcessErrorCode),
        }
        let completion = if let Some(code) = injected_stop {
            Completion::Stop(code)
        } else {
            tokio::select! {
                biased;
                _ = operation_cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
                wait = &mut wait_process => Completion::Exited(wait),
                _ = self.inner.cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
                _ = &mut deadline => Completion::Stop(ProcessErrorCode::DeadlineExceeded),
                limit = limit_rx.recv() => match limit {
                    Some(code) => Completion::Stop(code),
                    None => Completion::Exited((&mut wait_process).await),
                },
            }
        };

        let (exit_code, terminal_error) = match completion {
            Completion::Exited(result) => match result {
                Ok(exit_code) => (exit_code, None),
                Err(_) => {
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
            },
            Completion::Stop(ProcessErrorCode::Cancelled) => {
                match tokio::time::timeout(CANCELLATION_GRACE, &mut wait_process).await {
                    Ok(Ok(waited)) => {
                        (waited, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                    Ok(Err(_)) => {
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                    Err(_) => {
                        if windows::terminate(&job).is_err() {
                            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                        }
                        let waited =
                            match tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_process).await {
                                Ok(Ok(waited)) => waited,
                                Ok(Err(_)) => {
                                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                                }
                                Err(_) => {
                                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                                }
                            };
                        (waited, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                }
            }
            Completion::Stop(code) => {
                if windows::terminate(&job).is_err() {
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
                let waited = match tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_process).await {
                    Ok(Ok(waited)) => waited,
                    Ok(Err(_)) => {
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                    Err(_) => {
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                };
                (waited, Some(ProcessError::new(code)))
            }
        };

        let cleanup_job = job.clone();
        let cleanup_result = match tokio::task::spawn_blocking(move || {
            windows::terminate_and_wait(&cleanup_job, CLEANUP_DEADLINE)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
            }
        };
        if cleanup_result.is_err() {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }

        drop(job);
        drop(process);

        let [stdout, stderr] = registration.finish_windows().await?;
        if let Some(error) = terminal_error {
            return Err(error);
        }
        Ok(BoundedOutput {
            status: ExitStatus::from_raw(exit_code),
            stdout: stdout?,
            stderr: stderr?,
        })
    }

    #[cfg(unix)]
    async fn run_unix(
        &self,
        spec: ProcessSpec,
        permit: OwnedSemaphorePermit,
        operation_cancellation: &CancellationToken,
    ) -> Result<BoundedOutput, ProcessError> {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        let wall_expires = std::time::Instant::now() + spec.wall_deadline;

        let stdout_limit = match spec.stdout {
            StdoutPolicy::Null => None,
            StdoutPolicy::Capture { byte_limit } => Some(byte_limit),
            StdoutPolicy::Stream { queue_bytes } => Some(queue_bytes),
        };
        let keep_stdout = !matches!(spec.stdout, StdoutPolicy::Null);
        let mut command = tokio::process::Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&spec.current_dir)
            .env_clear()
            .envs(&spec.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        configure_unix_descriptor_inheritance(&mut command, &spec.executable)?;
        let (child, pid, registration) = {
            let _gate = self
                .inner
                .admission_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if operation_cancellation.is_cancelled()
                || self.inner.cancellation.is_cancelled()
                || !self.inner.accepting.load(Ordering::Acquire)
            {
                return Err(ProcessError::new(ProcessErrorCode::Cancelled));
            }
            let child = command
                .spawn()
                .map_err(|_| ProcessError::new(ProcessErrorCode::SpawnFailed))?;
            let pid = child
                .id()
                .ok_or_else(|| ProcessError::new(ProcessErrorCode::SpawnFailed))?
                as i32;
            let registration = self.inner.registry.register_unix(pid);
            registration.bind_permit(permit);
            (child, pid, registration)
        };
        let mut owner = UnixOwnedProcess::new(child, pid, registration);
        let stdout_pipe = owner
            .child_mut()?
            .stdout
            .take()
            .and_then(|pipe| pipe.into_owned_fd().ok())
            .map(std::fs::File::from);
        let stderr_pipe = owner
            .child_mut()?
            .stderr
            .take()
            .and_then(|pipe| pipe.into_owned_fd().ok())
            .map(std::fs::File::from);
        let (limit_tx, limit_rx) = std::sync::mpsc::channel();
        let (stdout_reader, stdout_setup_failed) = spawn_unix_reader(
            stdout_pipe,
            stdout_limit,
            keep_stdout,
            ProcessErrorCode::StdoutLimitExceeded,
            limit_tx.clone(),
        );
        let (stderr_reader, stderr_setup_failed) = spawn_unix_reader(
            stderr_pipe,
            Some(spec.stderr_byte_limit),
            true,
            ProcessErrorCode::StderrLimitExceeded,
            limit_tx,
        );
        let setup_failed = stdout_setup_failed || stderr_setup_failed;
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let cancellation = self.inner.cancellation.clone();
        let operation_cancellation = operation_cancellation.clone();
        let owner_state = Arc::new(Mutex::new(Some((
            owner,
            stdout_reader,
            stderr_reader,
            limit_rx,
            cancellation,
            operation_cancellation,
            wall_expires,
            setup_failed,
            result_tx,
        ))));
        let thread_state = owner_state.clone();
        if std::thread::Builder::new()
            .name("transcoding-process-owner".to_owned())
            .spawn(move || {
                if let Some(arguments) = thread_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    own_unix_process(arguments);
                }
            })
            .is_err()
            && let Some(arguments) = owner_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        {
            // Thread exhaustion is exceptional, but successful spawn ownership
            // still cannot be abandoned. Perform the same durable cleanup
            // synchronously rather than dropping the child/registration.
            own_unix_process(arguments);
        }
        result_rx
            .await
            .unwrap_or_else(|_| Err(ProcessError::new(ProcessErrorCode::WaitFailed)))
    }
}

#[cfg(any(unix, test))]
fn unix_bound_execution_descriptor(path: &std::path::Path) -> Option<i32> {
    let path = path.to_str()?;
    let descriptor = path
        .strip_prefix("/proc/self/fd/")
        .or_else(|| path.strip_prefix("/dev/fd/"))?;
    if descriptor.is_empty() || descriptor.contains('/') {
        return None;
    }
    descriptor
        .parse::<i32>()
        .ok()
        .filter(|descriptor| *descriptor >= 0)
}

#[cfg(unix)]
fn configure_unix_descriptor_inheritance(
    command: &mut tokio::process::Command,
    path: &std::path::Path,
) -> Result<(), ProcessError> {
    use std::os::unix::process::CommandExt as _;

    let Some(descriptor) = unix_bound_execution_descriptor(path) else {
        return Ok(());
    };
    let original_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if original_flags < 0 {
        return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
    }
    // `pre_exec` runs after fork in the child. The parent's sealed runtime
    // descriptor remains CLOEXEC at every point, including while unrelated
    // components concurrently spawn their own children.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::fcntl(
                descriptor,
                libc::F_SETFD,
                original_flags & !libc::FD_CLOEXEC,
            ) != 0
            {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    Ok(())
}

#[cfg(unix)]
type UnixOwnerArguments = (
    UnixOwnedProcess,
    DurableUnixReader,
    DurableUnixReader,
    std::sync::mpsc::Receiver<ProcessErrorCode>,
    CancellationToken,
    CancellationToken,
    std::time::Instant,
    bool,
    tokio::sync::oneshot::Sender<Result<BoundedOutput, ProcessError>>,
);

#[cfg(unix)]
fn own_unix_process(arguments: UnixOwnerArguments) {
    let (
        mut owner,
        stdout_reader,
        stderr_reader,
        limit_rx,
        cancellation,
        operation_cancellation,
        wall_expires,
        setup_failed,
        result_tx,
    ) = arguments;
    enum Completion {
        Exited,
        Stop(ProcessErrorCode),
    }
    let process_group = owner.process_group();
    let completion = 'completion: loop {
        if setup_failed {
            break 'completion Completion::Stop(ProcessErrorCode::SpawnFailed);
        }
        match unix_leader_is_waitable_without_reap(process_group) {
            Ok(true) => break Completion::Exited,
            Ok(false) => {}
            Err(_) => break Completion::Stop(ProcessErrorCode::WaitFailed),
        }
        if cancellation.is_cancelled()
            || operation_cancellation.is_cancelled()
            || result_tx.is_closed()
        {
            break Completion::Stop(ProcessErrorCode::Cancelled);
        }
        if std::time::Instant::now() >= wall_expires {
            break Completion::Stop(ProcessErrorCode::DeadlineExceeded);
        }
        match limit_rx.try_recv() {
            Ok(code) => break Completion::Stop(code),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {}
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let terminal_error = match completion {
        Completion::Exited => None,
        Completion::Stop(ProcessErrorCode::Cancelled) => {
            if graceful_terminate_unix_group(process_group).is_err() {
                Some(ProcessError::new(ProcessErrorCode::WaitFailed))
            } else {
                let grace_expires = std::time::Instant::now() + CANCELLATION_GRACE;
                while std::time::Instant::now() < grace_expires {
                    match unix_leader_is_waitable_without_reap(process_group) {
                        Ok(true) => break,
                        Ok(false) => std::thread::sleep(Duration::from_millis(5)),
                        Err(_) => break,
                    }
                }
                Some(ProcessError::new(ProcessErrorCode::Cancelled))
            }
        }
        Completion::Stop(code) => Some(ProcessError::new(code)),
    };

    // The durable owner never relinquishes the real Child or reader handles
    // after a cleanup error. It reports a bounded error once, then continues
    // retrying while retaining registry ownership and the admission permit.
    let cleanup_expires = std::time::Instant::now() + CLEANUP_DEADLINE;
    let mut result_tx = Some(result_tx);
    loop {
        match owner.send_final_signal() {
            Ok(()) => break,
            Err(_) if std::time::Instant::now() < cleanup_expires => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => {
                if let Some(sender) = result_tx.take() {
                    let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    #[cfg(target_os = "linux")]
    let descendant_identities = loop {
        match linux_terminal_group_descendants(process_group) {
            Ok(Some(descendants)) => break descendants,
            Ok(None) | Err(_) => {}
        }
        if std::time::Instant::now() >= cleanup_expires {
            if let Some(sender) = result_tx.take() {
                let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    #[cfg(target_os = "macos")]
    let descendant_identities = loop {
        match macos_terminal_group_descendants(process_group) {
            Ok(Some(descendants)) => break descendants,
            Ok(None) | Err(_) => {}
        }
        if std::time::Instant::now() >= cleanup_expires {
            if let Some(sender) = result_tx.take() {
                let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    while !unix_group_descendants_drained(process_group).unwrap_or(false) {
        if std::time::Instant::now() >= cleanup_expires {
            if let Some(sender) = result_tx.take() {
                let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let status = loop {
        match owner.child_mut().and_then(|child| {
            child
                .try_wait()
                .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))
        }) {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < cleanup_expires => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(None) | Err(_) => {
                if let Some(sender) = result_tx.take() {
                    let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };
    if let Err(error) = owner.mark_leader_reaped() {
        owner.ownership.mark_child_reaped();
        if let Some(sender) = result_tx.take() {
            let _ = sender.send(Err(error));
        }
    }
    #[cfg(target_os = "linux")]
    while !linux_process_identities_are_gone(&descendant_identities) {
        if std::time::Instant::now() >= cleanup_expires {
            if let Some(sender) = result_tx.take() {
                let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    #[cfg(target_os = "macos")]
    while !macos_process_identities_are_gone(&descendant_identities) {
        if std::time::Instant::now() >= cleanup_expires {
            if let Some(sender) = result_tx.take() {
                let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let stdout = join_unix_reader_durably(stdout_reader, &mut owner, &mut result_tx);
    let stderr = join_unix_reader_durably(stderr_reader, &mut owner, &mut result_tx);
    let completed = owner.complete();
    if let Some(sender) = result_tx.take() {
        let outcome = completed.and_then(|_| {
            let stdout = stdout?;
            let stderr = stderr?;
            if let Some(error) = terminal_error {
                return Err(error);
            }
            Ok(BoundedOutput {
                status,
                stdout,
                stderr,
            })
        });
        let _ = sender.send(outcome);
    }
}

#[cfg(windows)]
async fn wait_windows_process(process: Arc<windows::TrackedHandle>) -> Result<u32, ProcessError> {
    loop {
        if let Some(exit_code) = windows::poll_exit(&process)? {
            return Ok(exit_code);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[cfg(all(test, windows))]
async fn wait_for_test_descendant_marker(spec: &ProcessSpec) -> Result<(), ProcessError> {
    let marker = spec
        .environment
        .get(&OsString::from("STREAM_SERVER_TEST_DESCENDANT_MARKER"))
        .map(PathBuf::from)
        .ok_or_else(|| ProcessError::new(ProcessErrorCode::SpawnFailed))?;
    let expires = tokio::time::Instant::now() + Duration::from_secs(2);
    while !marker.is_file() {
        if tokio::time::Instant::now() >= expires {
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

#[cfg(windows)]
fn spawn_abandoned_windows_cleanup(registry: Arc<ProcessRegistry>, id: u64) -> bool {
    let (_signal, receiver) = tokio::sync::oneshot::channel();
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return false;
    };
    spawn_windows_owner(registry, id, receiver, &runtime);
    true
}

#[cfg(windows)]
fn spawn_windows_owner(
    registry: Arc<ProcessRegistry>,
    id: u64,
    receiver: tokio::sync::oneshot::Receiver<WindowsOwnerAction>,
    runtime: &tokio::runtime::Handle,
) {
    let target = registry
        .entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&id)
        .map(|entry| entry.target.clone());
    let Some(RegisteredTarget::WindowsProcessTree { job, process }) = target else {
        return;
    };
    struct RuntimeDropFallback {
        job: Option<Arc<windows::TrackedHandle>>,
        registry: Arc<ProcessRegistry>,
        id: u64,
    }
    impl Drop for RuntimeDropFallback {
        fn drop(&mut self) {
            if let Some(job) = self.job.take() {
                let _ = windows::terminate(&job);
                self.registry.mark_cleanup_stopped(self.id);
            }
        }
    }
    let fallback = RuntimeDropFallback {
        job: Some(job.clone()),
        registry: registry.clone(),
        id,
    };
    runtime.spawn(async move {
        let mut fallback = fallback;
        if let Ok(WindowsOwnerAction::Complete(result)) = receiver.await {
            #[cfg(test)]
            registry.test_hooks.pause_owner_complete().await;
            #[cfg(test)]
            registry.test_hooks.pause_reader_handoff().await;
            let output = await_registered_windows_readers(&registry, id, true).await;
            if output.is_err() {
                registry.mark_retained(id);
                drop(process);
                drop(job);
                drop(fallback);
                let _ = result.send(output);
                return;
            }
            fallback.job = None;
            drop(fallback);
            drop(process);
            drop(job);
            registry.complete(id);
            let _ = result.send(output);
            return;
        }
        let mut wait_process = Box::pin(wait_windows_process(process.clone()));
        let primary_exited = matches!(
            tokio::time::timeout(CANCELLATION_GRACE, &mut wait_process).await,
            Ok(Ok(_))
        );
        let cleanup_job = job.clone();
        let cleanup = tokio::task::spawn_blocking(move || {
            windows::terminate_and_wait(&cleanup_job, CLEANUP_DEADLINE)
        });
        let Ok(Ok(())) = cleanup.await else {
            return;
        };
        if !primary_exited
            && tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_process)
                .await
                .ok()
                .and_then(Result::ok)
                .is_none()
        {
            return;
        }
        if await_registered_windows_readers(&registry, id, false)
            .await
            .is_err()
        {
            return;
        }
        fallback.job = None;
        drop(wait_process);
        drop(fallback);
        drop(process);
        drop(job);
        registry.complete(id);
    });
}

#[cfg(windows)]
async fn await_registered_windows_readers(
    registry: &ProcessRegistry,
    id: u64,
    require_output: bool,
) -> WindowsOwnerResult {
    let expires = tokio::time::Instant::now() + CLEANUP_DEADLINE;
    loop {
        let finished = {
            let entries = registry
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(entry) = entries.get(&id) else {
                return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
            };
            if !entry.readers_expected {
                if require_output {
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
                return Ok([Ok(Vec::new()), Ok(Vec::new())]);
            }
            entry.cleanup_tasks.len() == 2
                && entry
                    .cleanup_tasks
                    .iter()
                    .all(tokio::task::JoinHandle::is_finished)
        };
        if finished {
            break;
        }
        if tokio::time::Instant::now() >= expires {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let [stdout_reader, stderr_reader] = {
        let mut entries = registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tasks = &mut entries
            .get_mut(&id)
            .ok_or_else(|| ProcessError::new(ProcessErrorCode::WaitFailed))?
            .cleanup_tasks;
        if tasks.len() != 2 {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
        [tasks.remove(0), tasks.remove(0)]
    };
    let stdout = stdout_reader
        .await
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
    let stderr = stderr_reader
        .await
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
    Ok([stdout, stderr])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_leader_is_waitable_without_reap(process_group: i32) -> Result<bool, ProcessError> {
    let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            process_group as libc::id_t,
            information.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
    }
    let information = unsafe { information.assume_init() };
    Ok(unsafe { information.si_pid() } == process_group)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn unix_leader_is_waitable_without_reap(_process_group: i32) -> Result<bool, ProcessError> {
    Err(ProcessError::new(ProcessErrorCode::WaitFailed))
}

#[cfg(unix)]
fn terminate_unix_group(process_group: i32) -> Result<(), ProcessError> {
    signal_unix_group(process_group, libc::SIGKILL)
}

#[cfg(unix)]
fn graceful_terminate_unix_group(process_group: i32) -> Result<(), ProcessError> {
    signal_unix_group(process_group, libc::SIGTERM)
}

#[cfg(unix)]
fn signal_unix_group(process_group: i32, signal: i32) -> Result<(), ProcessError> {
    let result = unsafe { libc::kill(-process_group, signal) };
    if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(ProcessError::new(ProcessErrorCode::WaitFailed))
    }
}

#[cfg(unix)]
fn unix_group_is_empty(process_group: i32) -> Result<bool, ProcessError> {
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        Ok(false)
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
        Ok(true)
    } else {
        Err(ProcessError::new(ProcessErrorCode::WaitFailed))
    }
}

#[cfg(unix)]
struct UnixReaderInput {
    pipe: Option<std::fs::File>,
    limit: Option<usize>,
    keep: bool,
    limit_code: ProcessErrorCode,
    limit_tx: std::sync::mpsc::Sender<ProcessErrorCode>,
}

#[cfg(unix)]
enum DurableUnixReader {
    Thread(std::thread::JoinHandle<Result<Vec<u8>, ProcessError>>),
    Inline(UnixReaderInput),
}

#[cfg(unix)]
fn spawn_unix_reader(
    pipe: Option<std::fs::File>,
    limit: Option<usize>,
    keep: bool,
    limit_code: ProcessErrorCode,
    limit_tx: std::sync::mpsc::Sender<ProcessErrorCode>,
) -> (DurableUnixReader, bool) {
    let missing_pipe = pipe.is_none();
    let input = Arc::new(Mutex::new(Some(UnixReaderInput {
        pipe,
        limit,
        keep,
        limit_code,
        limit_tx,
    })));
    let thread_input = input.clone();
    match std::thread::Builder::new()
        .name("transcoding-pipe-reader".to_owned())
        .spawn(move || {
            let input = thread_input
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .ok_or_else(|| ProcessError::new(ProcessErrorCode::SpawnFailed))?;
            let Some(pipe) = input.pipe else {
                let _ = input.limit_tx.send(ProcessErrorCode::SpawnFailed);
                return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
            };
            read_sync_pipe(
                pipe,
                input.limit,
                input.keep,
                input.limit_code,
                input.limit_tx,
            )
        }) {
        Ok(reader) => (DurableUnixReader::Thread(reader), missing_pipe),
        Err(_) => {
            let input = input
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_else(|| UnixReaderInput {
                    pipe: None,
                    limit: None,
                    keep: false,
                    limit_code: ProcessErrorCode::WaitFailed,
                    limit_tx: std::sync::mpsc::channel().0,
                });
            (DurableUnixReader::Inline(input), true)
        }
    }
}

#[cfg(unix)]
fn read_sync_pipe(
    mut pipe: std::fs::File,
    limit: Option<usize>,
    keep: bool,
    limit_code: ProcessErrorCode,
    limit_tx: std::sync::mpsc::Sender<ProcessErrorCode>,
) -> Result<Vec<u8>, ProcessError> {
    use std::io::Read as _;

    let mut output = Vec::with_capacity(limit.unwrap_or(0).min(8_192));
    let mut buffer = [0_u8; 8_192];
    let mut total = 0_usize;
    let mut exceeded = false;
    loop {
        let count = pipe
            .read(&mut buffer)
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        if let Some(limit) = limit {
            if total > limit && !exceeded {
                exceeded = true;
                let _ = limit_tx.send(limit_code);
            }
            if keep && output.len() < limit {
                let remaining = limit - output.len();
                output.extend_from_slice(&buffer[..count.min(remaining)]);
            }
        }
    }
    if exceeded {
        Err(ProcessError::new(limit_code))
    } else if keep {
        Ok(output)
    } else {
        Ok(Vec::new())
    }
}

#[cfg(unix)]
fn join_unix_reader_durably(
    reader: DurableUnixReader,
    owner: &mut UnixOwnedProcess,
    result_tx: &mut Option<tokio::sync::oneshot::Sender<Result<BoundedOutput, ProcessError>>>,
) -> Result<Vec<u8>, ProcessError> {
    let reader = match reader {
        DurableUnixReader::Thread(reader) => reader,
        DurableUnixReader::Inline(input) => {
            let result = match input.pipe {
                Some(pipe) => read_sync_pipe(
                    pipe,
                    input.limit,
                    input.keep,
                    input.limit_code,
                    input.limit_tx,
                ),
                None => Err(ProcessError::new(ProcessErrorCode::SpawnFailed)),
            };
            owner.ownership.mark_reader_joined();
            return result;
        }
    };
    let expires = std::time::Instant::now() + CLEANUP_DEADLINE;
    while !reader.is_finished() {
        if std::time::Instant::now() >= expires {
            if let Some(sender) = result_tx.take() {
                let _ = sender.send(Err(ProcessError::new(ProcessErrorCode::WaitFailed)));
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let result = reader
        .join()
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))
        .and_then(|result| result);
    owner.ownership.record_reader_join_result(result)
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxProcessIdentity {
    process_group: i32,
    start_time: u64,
    terminal: bool,
}

#[cfg(any(test, target_os = "linux"))]
fn parse_linux_process_identity(statistics: &str) -> Option<LinuxProcessIdentity> {
    let fields = statistics.rsplit_once(") ")?.1;
    let mut fields = fields.split_ascii_whitespace();
    let terminal = fields.next()? == "Z";
    let process_group = fields.nth(1)?.parse::<i32>().ok()?;
    let start_time = fields.nth(16)?.parse::<u64>().ok()?;
    Some(LinuxProcessIdentity {
        process_group,
        start_time,
        terminal,
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct LinuxDescendantIdentity {
    pid: i32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
fn linux_terminal_group_descendants(
    process_group: i32,
) -> Result<Option<Vec<LinuxDescendantIdentity>>, ProcessError> {
    let mut descendants = Vec::new();
    for entry in
        std::fs::read_dir("/proc").map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == process_group {
            continue;
        }
        let Ok(statistics) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(identity) = parse_linux_process_identity(&statistics) else {
            continue;
        };
        if identity.process_group == process_group {
            if !identity.terminal {
                return Ok(None);
            }
            descendants.push(LinuxDescendantIdentity {
                pid,
                start_time: identity.start_time,
            });
        }
    }
    Ok(Some(descendants))
}

#[cfg(target_os = "linux")]
fn linux_process_identities_are_gone(descendants: &[LinuxDescendantIdentity]) -> bool {
    descendants.iter().all(|descendant| {
        let statistics = std::fs::read_to_string(format!("/proc/{}/stat", descendant.pid));
        match statistics
            .ok()
            .as_deref()
            .and_then(parse_linux_process_identity)
        {
            Some(identity) => identity.start_time != descendant.start_time,
            None => true,
        }
    })
}

#[cfg(any(test, target_os = "macos"))]
fn macos_process_status_is_terminal(status: u32) -> bool {
    const SZOMB: u32 = 5;
    status == SZOMB
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct MacosDescendantIdentity {
    pid: i32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[cfg(target_os = "macos")]
fn macos_process_info(pid: i32) -> Option<libc::proc_bsdinfo> {
    let mut information = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast(),
            expected,
        )
    };
    (written == expected).then(|| unsafe { information.assume_init() })
}

#[cfg(target_os = "macos")]
fn macos_terminal_group_descendants(
    process_group: i32,
) -> Result<Option<Vec<MacosDescendantIdentity>>, ProcessError> {
    let required = unsafe { libc::proc_listpgrppids(process_group, std::ptr::null_mut(), 0) };
    if required < 0 {
        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
    }
    let mut pids = vec![0_i32; (required as usize / std::mem::size_of::<i32>()) + 8];
    let buffer_size = i32::try_from(pids.len() * std::mem::size_of::<i32>())
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
    let written =
        unsafe { libc::proc_listpgrppids(process_group, pids.as_mut_ptr().cast(), buffer_size) };
    if written < 0 {
        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
    }
    pids.truncate(written as usize / std::mem::size_of::<i32>());
    let mut descendants = Vec::new();
    for pid in pids
        .into_iter()
        .filter(|pid| *pid != 0 && *pid != process_group)
    {
        let Some(information) = macos_process_info(pid) else {
            continue;
        };
        if information.pbi_pgid != process_group as u32 {
            continue;
        }
        if !macos_process_status_is_terminal(information.pbi_status) {
            return Ok(None);
        }
        descendants.push(MacosDescendantIdentity {
            pid,
            start_seconds: information.pbi_start_tvsec,
            start_microseconds: information.pbi_start_tvusec,
        });
    }
    Ok(Some(descendants))
}

#[cfg(target_os = "macos")]
fn macos_process_identities_are_gone(descendants: &[MacosDescendantIdentity]) -> bool {
    descendants.iter().all(|descendant| {
        macos_process_info(descendant.pid).is_none_or(|information| {
            information.pbi_start_tvsec != descendant.start_seconds
                || information.pbi_start_tvusec != descendant.start_microseconds
        })
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn unix_group_descendants_drained(_process_group: i32) -> Result<bool, ProcessError> {
    Err(ProcessError::new(ProcessErrorCode::WaitFailed))
}

fn validate_common_spec(spec: &ProcessSpec) -> Result<(), ProcessError> {
    let valid_stdout = match spec.stdout {
        StdoutPolicy::Null => true,
        StdoutPolicy::Capture { byte_limit } => (1..=MAX_CAPTURE_BYTES).contains(&byte_limit),
        StdoutPolicy::Stream { .. } => {
            return Err(ProcessError::new(ProcessErrorCode::UnsupportedPolicy));
        }
    };
    if !spec.executable.is_absolute()
        || !spec.executable.is_file()
        || !spec.current_dir.is_absolute()
        || !spec.current_dir.is_dir()
        || !valid_stdout
        || !(1..=MAX_CAPTURE_BYTES).contains(&spec.stderr_byte_limit)
        || spec.wall_deadline.is_zero()
        || spec.wall_deadline > MAX_WALL_DEADLINE
    {
        return Err(ProcessError::new(ProcessErrorCode::InvalidSpec));
    }
    Ok(())
}

#[cfg(windows)]
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    PipeSetup,
    AttributeListUpdate,
    AttributeListSetup,
    SuspendedCreate,
    JobAssignment,
    RegistryInsertion,
    Resume,
    ResumeAfterDescendant,
    PauseAfterResume,
    WaitAfterReaders,
}

#[cfg(windows)]
type NativeFailurePoint = Option<FailurePoint>;

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
#[path = "process/unix_tests.rs"]
mod unix_tests;
