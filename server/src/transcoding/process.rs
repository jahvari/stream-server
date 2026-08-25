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

use tokio::sync::{Notify, Semaphore};
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
    permits: Semaphore,
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

struct RegisteredEntry {
    target: RegisteredTarget,
    retained: bool,
    #[cfg(windows)]
    cleanup_tasks: Vec<tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>>>,
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
                    #[cfg(windows)]
                    cleanup_tasks: Vec::new(),
                },
            );
        Registration {
            registry: self.clone(),
            id,
        }
    }

    fn force_terminate_all(&self) -> Result<(), ProcessError> {
        let targets = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(|entry| entry.target.clone())
            .collect::<Vec<_>>();
        let mut failed = false;
        for target in targets {
            let result = match target {
                #[cfg(windows)]
                RegisteredTarget::WindowsProcessTree { job, .. } => windows::terminate(&job),
                #[cfg(unix)]
                RegisteredTarget::UnixProcessGroup(process_group) => {
                    terminate_unix_group(process_group)
                }
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
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let became_idle = entries.remove(&self.id).is_some() && entries.is_empty();
        drop(entries);
        if became_idle {
            self.registry.idle.notify_waiters();
        }
    }
}

impl Registration {
    #[cfg(any(unix, test))]
    fn retain(self) {
        if let Some(entry) = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(&self.id)
        {
            entry.retained = true;
        }
        std::mem::forget(self);
    }

    #[cfg(windows)]
    fn retain_with_windows_readers(
        self,
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
            entry.retained = true;
            entry.cleanup_tasks.extend([stdout, stderr]);
        }
        std::mem::forget(self);
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
                permits: Semaphore::new(maximum.max(1)),
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
            permit = self.inner.permits.acquire() => permit.map_err(|_| ProcessError::new(ProcessErrorCode::Cancelled))?,
        };
        if self.inner.cancellation.is_cancelled() || !self.inner.accepting.load(Ordering::Acquire) {
            self.cancel();
            return Err(ProcessError::new(ProcessErrorCode::Cancelled));
        }

        #[cfg(windows)]
        let result = self.run_windows(spec).await;
        #[cfg(unix)]
        let result = self.run_unix(spec).await;
        #[cfg(not(any(windows, unix)))]
        let result = Err(ProcessError::new(ProcessErrorCode::SpawnFailed));

        drop(permit);
        result
    }

    #[cfg(all(test, windows))]
    fn with_failure_point(cancellation: CancellationToken, point: FailurePoint) -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                cancellation,
                permits: Semaphore::new(DEFAULT_MAX_CONCURRENT_PROCESSES),
                accepting: AtomicBool::new(true),
                admission_gate: Mutex::new(()),
                registry: Arc::new(ProcessRegistry::new()),
                failure_point: Some(point),
            }),
        }
    }

    #[cfg(windows)]
    async fn run_windows(&self, spec: ProcessSpec) -> Result<BoundedOutput, ProcessError> {
        use std::os::windows::process::ExitStatusExt;

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
        let spawned = {
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
            windows::spawn(&spec, self.inner.registry.clone(), failure_point)?
        };
        let windows::SpawnedProcess {
            process,
            job,
            stdout,
            stderr,
            registration,
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

        #[cfg(test)]
        if failure_point == Some(FailurePoint::WaitAfterReaders) {
            registration.retain_with_windows_readers(stdout_reader, stderr_reader);
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }

        let mut wait_process = Box::pin(wait_windows_process(process.clone()));
        let deadline = tokio::time::sleep(spec.wall_deadline);
        tokio::pin!(deadline);

        enum Completion {
            Exited(Result<u32, ProcessError>),
            Stop(ProcessErrorCode),
        }
        let completion = tokio::select! {
            wait = &mut wait_process => Completion::Exited(wait),
            _ = self.inner.cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
            _ = &mut deadline => Completion::Stop(ProcessErrorCode::DeadlineExceeded),
            limit = limit_rx.recv() => match limit {
                Some(code) => Completion::Stop(code),
                None => Completion::Exited((&mut wait_process).await),
            },
        };

        let (exit_code, terminal_error) = match completion {
            Completion::Exited(result) => match result {
                Ok(exit_code) => (exit_code, None),
                Err(_) => {
                    registration.retain_with_windows_readers(stdout_reader, stderr_reader);
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
            },
            Completion::Stop(ProcessErrorCode::Cancelled) => {
                match tokio::time::timeout(CANCELLATION_GRACE, &mut wait_process).await {
                    Ok(Ok(waited)) => {
                        (waited, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                    Ok(Err(_)) => {
                        registration.retain_with_windows_readers(stdout_reader, stderr_reader);
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                    Err(_) => {
                        if windows::terminate(&job).is_err() {
                            registration.retain_with_windows_readers(stdout_reader, stderr_reader);
                            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                        }
                        let waited =
                            match tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_process).await {
                                Ok(Ok(waited)) => waited,
                                Ok(Err(_)) => {
                                    registration
                                        .retain_with_windows_readers(stdout_reader, stderr_reader);
                                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                                }
                                Err(_) => {
                                    registration
                                        .retain_with_windows_readers(stdout_reader, stderr_reader);
                                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                                }
                            };
                        (waited, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                }
            }
            Completion::Stop(code) => {
                if windows::terminate(&job).is_err() {
                    registration.retain_with_windows_readers(stdout_reader, stderr_reader);
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
                let waited = match tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_process).await {
                    Ok(Ok(waited)) => waited,
                    Ok(Err(_)) => {
                        registration.retain_with_windows_readers(stdout_reader, stderr_reader);
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                    Err(_) => {
                        registration.retain_with_windows_readers(stdout_reader, stderr_reader);
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
                registration.retain_with_windows_readers(stdout_reader, stderr_reader);
                return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
            }
        };
        if cleanup_result.is_err() {
            registration.retain_with_windows_readers(stdout_reader, stderr_reader);
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }

        drop(job);
        drop(process);

        let stdout_result = stdout_reader
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed));
        let stderr_result = stderr_reader
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed));

        drop(registration);
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
    async fn run_unix(&self, spec: ProcessSpec) -> Result<BoundedOutput, ProcessError> {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;

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
        let mut child = {
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
            command
                .spawn()
                .map_err(|_| ProcessError::new(ProcessErrorCode::SpawnFailed))?
        };
        let pid = child
            .id()
            .ok_or_else(|| ProcessError::new(ProcessErrorCode::SpawnFailed))?
            as i32;
        let registration = self.inner.registry.register_unix(pid);
        let Some(stdout_pipe) = child.stdout.take() else {
            cleanup_failed_unix_spawn(&mut child, pid, registration).await?;
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        };
        let Some(stderr_pipe) = child.stderr.take() else {
            cleanup_failed_unix_spawn(&mut child, pid, registration).await?;
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        };
        let (limit_tx, mut limit_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut stdout_reader = tokio::spawn({
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
        let mut stderr_reader = tokio::spawn(async move {
            read_async_pipe(
                stderr_pipe,
                Some(spec.stderr_byte_limit),
                true,
                ProcessErrorCode::StderrLimitExceeded,
                limit_tx,
            )
            .await
        });
        let mut wait_child = Box::pin(child.wait());
        let deadline = tokio::time::sleep(spec.wall_deadline);
        tokio::pin!(deadline);
        enum Completion {
            Exited(Result<std::process::ExitStatus, std::io::Error>),
            Stop(ProcessErrorCode),
        }
        let completion = tokio::select! {
            result = &mut wait_child => Completion::Exited(result),
            _ = self.inner.cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
            _ = &mut deadline => Completion::Stop(ProcessErrorCode::DeadlineExceeded),
            limit = limit_rx.recv() => match limit {
                Some(code) => Completion::Stop(code),
                None => Completion::Exited((&mut wait_child).await),
            },
        };
        let (status, terminal_error) = match completion {
            Completion::Exited(result) => match result {
                Ok(status) => (status, None),
                Err(_) => {
                    abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                    registration.retain();
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
            },
            Completion::Stop(ProcessErrorCode::Cancelled) => {
                match tokio::time::timeout(CANCELLATION_GRACE, &mut wait_child).await {
                    Ok(Ok(status)) => {
                        (status, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                    Ok(Err(_)) => {
                        abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                        registration.retain();
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                    Err(_) => {
                        if terminate_unix_group(pid).is_err() {
                            abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                            registration.retain();
                            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                        }
                        let status = match tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_child)
                            .await
                        {
                            Ok(Ok(status)) => status,
                            Ok(Err(_)) => {
                                abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                                registration.retain();
                                return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                            }
                            Err(_) => {
                                abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                                registration.retain();
                                return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                            }
                        };
                        (status, Some(ProcessError::new(ProcessErrorCode::Cancelled)))
                    }
                }
            }
            Completion::Stop(code) => {
                if terminate_unix_group(pid).is_err() {
                    abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                    registration.retain();
                    return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                }
                let status = match tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_child).await {
                    Ok(Ok(status)) => status,
                    Ok(Err(_)) => {
                        abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                        registration.retain();
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                    Err(_) => {
                        abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
                        registration.retain();
                        return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
                    }
                };
                (status, Some(ProcessError::new(code)))
            }
        };

        if terminate_unix_group(pid).is_err()
            || wait_for_unix_group_drain(pid, CLEANUP_DEADLINE)
                .await
                .is_err()
        {
            abort_unix_readers(&mut stdout_reader, &mut stderr_reader).await;
            registration.retain();
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }

        let stdout = match await_unix_reader(&mut stdout_reader).await {
            Ok(stdout) => stdout,
            Err(error) => {
                stderr_reader.abort();
                let _ = stderr_reader.await;
                drop(registration);
                return Err(error);
            }
        };
        let stderr = await_unix_reader(&mut stderr_reader).await?;
        drop(registration);
        if let Some(error) = terminal_error {
            return Err(error);
        }
        Ok(BoundedOutput {
            status,
            stdout,
            stderr,
        })
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

#[cfg(unix)]
fn terminate_unix_group(process_group: i32) -> Result<(), ProcessError> {
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
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
    drop(registration);
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
    WaitAfterReaders,
}

#[cfg(windows)]
type NativeFailurePoint = Option<FailurePoint>;

#[cfg(test)]
mod tests;
