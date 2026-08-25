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

pub(super) struct Registration {
    registry: Arc<ProcessRegistry>,
    id: u64,
    completed: bool,
    #[cfg(windows)]
    owner_signal: Option<tokio::sync::oneshot::Sender<WindowsOwnerAction>>,
}

#[cfg(windows)]
enum WindowsOwnerAction {
    Complete(tokio::sync::oneshot::Sender<()>),
}

impl ProcessRegistry {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: Mutex::new(HashMap::new()),
            idle: Notify::new(),
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
                    cleanup_tasks: Vec::new(),
                },
            );
        Registration {
            registry: self.clone(),
            id,
            completed: false,
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
        spawn_abandoned_windows_cleanup(self.clone(), id);
    }

    #[cfg(unix)]
    fn retain_unix_after_final_signal(&self, id: u64) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = entries.get_mut(&id) else {
            return;
        };
        let RegisteredTarget::UnixProcessGroup(process_group) = &entry.target;
        let _ = terminate_unix_group(*process_group);
        entry.unix_killable = false;
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
                let owner_started = self.owner_signal.is_some();
                if owner_started {
                    self.registry.mark_retained(self.id);
                } else {
                    self.registry.begin_retained_cleanup(self.id);
                    self.registry.terminate_windows_fallback(self.id);
                }
            }
            #[cfg(unix)]
            self.registry.retain_unix_after_final_signal(self.id);
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
    async fn finish_windows(mut self) {
        self.completed = true;
        if let Some(signal) = self.owner_signal.take() {
            let (acknowledge, acknowledged) = tokio::sync::oneshot::channel();
            if signal
                .send(WindowsOwnerAction::Complete(acknowledge))
                .is_ok()
            {
                let _ = acknowledged.await;
            }
        }
        self.registry.complete(self.id);
    }

    #[cfg(all(windows, test))]
    fn retain(mut self) {
        self.registry.begin_retained_cleanup(self.id);
        self.completed = true;
    }

    #[cfg(unix)]
    fn retain(mut self) {
        self.registry.retain_unix_after_final_signal(self.id);
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

    #[cfg(windows)]
    fn take_windows_readers(&self) -> Option<[WindowsReaderTask; 2]> {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tasks = &mut entries.get_mut(&self.id)?.cleanup_tasks;
        if tasks.len() != 2 {
            return None;
        }
        Some([tasks.remove(0), tasks.remove(0)])
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
        validate_common_spec(&spec)?;
        if self.inner.cancellation.is_cancelled() || !self.inner.accepting.load(Ordering::Acquire) {
            self.cancel();
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }
        let permit = tokio::select! {
            biased;
            _ = self.inner.cancellation.cancelled() => {
                self.cancel();
                return Err(ProcessError::new(ProcessErrorCode::Cancelled));
            },
            permit = self.inner.permits.clone().acquire_owned() => permit.map_err(|_| ProcessError::new(ProcessErrorCode::Cancelled))?,
        };
        if self.inner.cancellation.is_cancelled() || !self.inner.accepting.load(Ordering::Acquire) {
            self.cancel();
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }

        #[cfg(windows)]
        let result = self.run_windows(spec, permit).await;
        #[cfg(unix)]
        let result = self.run_unix(spec, permit).await;
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
        let owner_runtime = tokio::runtime::Handle::current();
        let (spec, spawned) = tokio::task::spawn_blocking(move || {
            let _gate = inner
                .admission_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if inner.cancellation.is_cancelled() || !inner.accepting.load(Ordering::Acquire) {
                return (spec, Err(ProcessError::new(ProcessErrorCode::Cancelled)));
            }
            let mut spawned = windows::spawn(&spec, inner.registry.clone(), failure_point);
            if let Ok(spawned) = &mut spawned {
                spawned.registration.bind_permit(permit);
                spawned.registration.start_windows_owner_on(&owner_runtime);
                #[cfg(test)]
                if failure_point == Some(FailurePoint::PauseAfterResume) {
                    windows::pause_after_resume();
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
        );
        let stderr_reader = windows::read_pipe(
            stderr,
            Some(spec.stderr_byte_limit),
            true,
            ProcessErrorCode::StderrLimitExceeded,
            limit_tx,
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

        let [stdout_reader, stderr_reader] = registration
            .take_windows_readers()
            .ok_or_else(|| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        let stdout_result = stdout_reader
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed));
        let stderr_result = stderr_reader
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed));

        registration.finish_windows().await;
        let stdout = stdout_result??;
        let stderr = stderr_result??;
        if let Some(error) = terminal_error {
            return Err(error);
        }
        Ok(BoundedOutput {
            status: ExitStatus::from_raw(exit_code),
            stdout,
            stderr,
        })
    }

    #[cfg(unix)]
    async fn run_unix(
        &self,
        spec: ProcessSpec,
        permit: OwnedSemaphorePermit,
    ) -> Result<BoundedOutput, ProcessError> {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        let wall_expires = tokio::time::Instant::now() + spec.wall_deadline;

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
        let (mut child, pid, registration) = {
            let _gate = self
                .inner
                .admission_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.inner.cancellation.is_cancelled()
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
        let Some(stdout_pipe) = child.stdout.take() else {
            cleanup_failed_unix_spawn(&mut child, pid, registration).await?;
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        };
        let Some(stderr_pipe) = child.stderr.take() else {
            cleanup_failed_unix_spawn(&mut child, pid, registration).await?;
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        };
        let (limit_tx, limit_rx) = tokio::sync::mpsc::unbounded_channel();
        let stdout_reader = tokio::spawn({
            let limit_tx = limit_tx.clone();
            async move {
                read_async_pipe(
                    stdout_pipe,
                    stdout_limit,
                    keep_stdout,
                    ProcessErrorCode::StdoutLimitExceeded,
                    limit_tx,
                )
                .await
            }
        });
        let stderr_reader = tokio::spawn(async move {
            read_async_pipe(
                stderr_pipe,
                Some(spec.stderr_byte_limit),
                true,
                ProcessErrorCode::StderrLimitExceeded,
                limit_tx,
            )
            .await
        });
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let cancellation = self.inner.cancellation.clone();
        tokio::spawn(own_unix_process(
            child,
            pid,
            registration,
            stdout_reader,
            stderr_reader,
            limit_rx,
            cancellation,
            wall_expires,
            result_tx,
        ));
        result_rx
            .await
            .unwrap_or_else(|_| Err(ProcessError::new(ProcessErrorCode::WaitFailed)))
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn own_unix_process(
    mut child: tokio::process::Child,
    process_group: i32,
    registration: Registration,
    mut stdout_reader: tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
    mut stderr_reader: tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
    mut limit_rx: tokio::sync::mpsc::UnboundedReceiver<ProcessErrorCode>,
    cancellation: CancellationToken,
    wall_expires: tokio::time::Instant,
    mut result_tx: tokio::sync::oneshot::Sender<Result<BoundedOutput, ProcessError>>,
) {
    enum Completion {
        Exited(Result<std::process::ExitStatus, std::io::Error>),
        Stop(ProcessErrorCode),
    }

    let mut registration = Some(registration);
    let outcome = async {
        let mut wait_child = Box::pin(child.wait());
        let deadline = tokio::time::sleep_until(wall_expires);
        tokio::pin!(deadline);
        let completion = tokio::select! {
            result = &mut wait_child => Completion::Exited(result),
            _ = cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
            _ = result_tx.closed() => Completion::Stop(ProcessErrorCode::Cancelled),
            _ = &mut deadline => Completion::Stop(ProcessErrorCode::DeadlineExceeded),
            limit = limit_rx.recv() => match limit {
                Some(code) => Completion::Stop(code),
                None => Completion::Exited((&mut wait_child).await),
            },
        };
        let (status, terminal_error) = match completion {
            Completion::Exited(result) => (
                result.map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?,
                None,
            ),
            Completion::Stop(ProcessErrorCode::Cancelled) => {
                graceful_terminate_unix_group(process_group)?;
                match tokio::time::timeout(CANCELLATION_GRACE, &mut wait_child).await {
                    Ok(Ok(status)) => {
                        (status, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                    Ok(Err(_)) => return Err(ProcessError::new(ProcessErrorCode::WaitFailed)),
                    Err(_) => {
                        terminate_unix_group(process_group)?;
                        let status = tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_child)
                            .await
                            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
                            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                        (status, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                }
            }
            Completion::Stop(code) => {
                terminate_unix_group(process_group)?;
                let status = tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_child)
                    .await
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                (status, Some(ProcessError::new(code)))
            }
        };

        terminate_unix_group(process_group)?;
        wait_for_unix_group_drain(process_group, CLEANUP_DEADLINE).await?;
        let stdout = await_unix_reader(&mut stdout_reader).await?;
        let stderr = await_unix_reader(&mut stderr_reader).await?;
        if let Some(error) = terminal_error {
            return Err(error);
        }
        Ok(BoundedOutput {
            status,
            stdout,
            stderr,
        })
    }
    .await;

    match &outcome {
        Ok(_) => {
            registration.take().expect("registration owner").complete();
        }
        Err(_) => {
            abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
            registration.take().expect("registration owner").retain();
        }
    }
    let _ = result_tx.send(outcome);
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
fn spawn_abandoned_windows_cleanup(registry: Arc<ProcessRegistry>, id: u64) {
    let (_signal, receiver) = tokio::sync::oneshot::channel();
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    spawn_windows_owner(registry, id, receiver, &runtime);
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
        if let Ok(WindowsOwnerAction::Complete(acknowledge)) = receiver.await {
            fallback.job = None;
            drop(fallback);
            drop(process);
            drop(job);
            let _ = acknowledge.send(());
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
        let readers = {
            let mut entries = registry
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(entry) = entries.get_mut(&id) else {
                return;
            };
            std::mem::take(&mut entry.cleanup_tasks)
        };
        for mut reader in readers {
            if tokio::time::timeout(CLEANUP_DEADLINE, &mut reader)
                .await
                .is_err()
            {
                reader.abort();
                let _ = reader.await;
            }
        }
        fallback.job = None;
        drop(wait_process);
        drop(fallback);
        drop(process);
        drop(job);
        registry.complete(id);
    });
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
async fn wait_for_unix_group_drain(
    process_group: i32,
    deadline: Duration,
) -> Result<(), ProcessError> {
    let expires = tokio::time::Instant::now() + deadline;
    while !unix_group_is_empty(process_group)? {
        if tokio::time::Instant::now() >= expires {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Ok(())
}

#[cfg(unix)]
async fn cleanup_failed_unix_spawn(
    child: &mut tokio::process::Child,
    process_group: i32,
    registration: Registration,
) -> Result<(), ProcessError> {
    if terminate_unix_group(process_group).is_err() {
        registration.retain();
        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
    }
    match tokio::time::timeout(CLEANUP_DEADLINE, child.wait()).await {
        Ok(Ok(_)) => {}
        _ => {
            registration.retain();
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
    }
    if wait_for_unix_group_drain(process_group, CLEANUP_DEADLINE)
        .await
        .is_err()
    {
        registration.retain();
        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
    }
    registration.complete();
    Ok(())
}

#[cfg(unix)]
async fn abort_unix_readers(
    stdout: &mut tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
    stderr: &mut tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
) {
    stdout.abort();
    stderr.abort();
    let _ = stdout.await;
    let _ = stderr.await;
}

#[cfg(unix)]
async fn await_unix_reader(
    reader: &mut tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>,
) -> Result<Vec<u8>, ProcessError> {
    match tokio::time::timeout(CLEANUP_DEADLINE, &mut *reader).await {
        Ok(result) => result.map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?,
        Err(_) => {
            reader.abort();
            let _ = reader.await;
            Err(ProcessError::new(ProcessErrorCode::WaitFailed))
        }
    }
}

#[cfg(unix)]
async fn read_async_pipe<R>(
    mut pipe: R,
    limit: Option<usize>,
    keep: bool,
    limit_code: ProcessErrorCode,
    limit_tx: tokio::sync::mpsc::UnboundedSender<ProcessErrorCode>,
) -> Result<Vec<u8>, ProcessError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut output = Vec::with_capacity(limit.unwrap_or(0).min(8_192));
    let mut buffer = [0_u8; 8_192];
    let mut total = 0_usize;
    let mut exceeded = false;
    loop {
        let count = pipe
            .read(&mut buffer)
            .await
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
