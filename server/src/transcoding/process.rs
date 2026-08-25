use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    path::PathBuf,
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
mod windows;

const DEFAULT_MAX_CONCURRENT_PROCESSES: usize = 8;
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WALL_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);
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
    active: Arc<AtomicUsize>,
    #[cfg(all(test, windows))]
    failure_point: Option<FailurePoint>,
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
                active: Arc::new(AtomicUsize::new(0)),
                #[cfg(all(test, windows))]
                failure_point: None,
            }),
        }
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    pub fn active_processes(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }

    pub async fn run_bounded(&self, spec: ProcessSpec) -> Result<BoundedOutput, ProcessError> {
        validate_common_spec(&spec)?;
        let permit = tokio::select! {
            permit = self.inner.permits.acquire() => permit.map_err(|_| ProcessError::new(ProcessErrorCode::Cancelled))?,
            _ = self.inner.cancellation.cancelled() => return Err(ProcessError::new(ProcessErrorCode::Cancelled)),
        };

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
                active: Arc::new(AtomicUsize::new(0)),
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
        let spawned = windows::spawn(&spec, self.inner.active.clone(), failure_point)?;
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

        let wait_process = process.clone();
        let mut wait_task =
            tokio::task::spawn_blocking(move || (windows::wait(&wait_process), registration));
        let deadline = tokio::time::sleep(spec.wall_deadline);
        tokio::pin!(deadline);

        enum Completion {
            Exited(Result<u32, ProcessError>, windows::Registration),
            Stop(ProcessErrorCode),
        }
        let completion = tokio::select! {
            wait = &mut wait_task => {
                let (result, registration) = wait
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                Completion::Exited(result, registration)
            },
            _ = self.inner.cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
            _ = &mut deadline => Completion::Stop(ProcessErrorCode::DeadlineExceeded),
            limit = limit_rx.recv() => match limit {
                Some(code) => Completion::Stop(code),
                None => {
                    let (result, registration) = (&mut wait_task)
                        .await
                        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                    Completion::Exited(result, registration)
                },
            },
        };

        let (exit_code, registration, terminal_error) = match completion {
            Completion::Exited(result, registration) => (result?, registration, None),
            Completion::Stop(code) => {
                windows::terminate(&job);
                let (waited, registration) = tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_task)
                    .await
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                (waited?, registration, Some(ProcessError::new(code)))
            }
        };

        let cleanup_job = job.clone();
        let (cleanup_result, registration) = tokio::time::timeout(
            CLEANUP_DEADLINE,
            tokio::task::spawn_blocking(move || {
                (
                    windows::terminate_and_wait(&cleanup_job, CLEANUP_DEADLINE),
                    registration,
                )
            }),
        )
        .await
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        cleanup_result?;

        drop(job);
        drop(process);

        let stdout = tokio::time::timeout(CLEANUP_DEADLINE, stdout_reader)
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))??;
        let stderr = tokio::time::timeout(CLEANUP_DEADLINE, stderr_reader)
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))??;

        drop(registration);
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
        let mut command = std::process::Command::new(&spec.executable);
        command
            .args(&spec.args)
            .current_dir(&spec.current_dir)
            .env_clear()
            .envs(&spec.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command
            .spawn()
            .map_err(|_| ProcessError::new(ProcessErrorCode::SpawnFailed))?;
        let pid = child.id();
        let group = UnixProcessGroup(pid);
        let Some(stdout_pipe) = child.stdout.take() else {
            group.terminate();
            let _ = child.wait();
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        };
        let Some(stderr_pipe) = child.stderr.take() else {
            group.terminate();
            let _ = child.wait();
            return Err(ProcessError::new(ProcessErrorCode::SpawnFailed));
        };
        let registration = ActiveRegistration::new(self.inner.active.clone());
        let (limit_tx, mut limit_rx) = tokio::sync::mpsc::unbounded_channel();
        let stdout_reader = tokio::task::spawn_blocking({
            let limit_tx = limit_tx.clone();
            move || {
                read_sync_pipe(
                    stdout_pipe,
                    stdout_limit,
                    keep_stdout,
                    ProcessErrorCode::StdoutLimitExceeded,
                    limit_tx,
                )
            }
        });
        let stderr_reader = tokio::task::spawn_blocking(move || {
            read_sync_pipe(
                stderr_pipe,
                Some(spec.stderr_byte_limit),
                true,
                ProcessErrorCode::StderrLimitExceeded,
                limit_tx,
            )
        });
        let mut wait_task = tokio::task::spawn_blocking(move || (child.wait(), registration));
        let deadline = tokio::time::sleep(spec.wall_deadline);
        tokio::pin!(deadline);
        enum Completion {
            Exited(
                Result<std::process::ExitStatus, std::io::Error>,
                ActiveRegistration,
            ),
            Stop(ProcessErrorCode),
        }
        let completion = tokio::select! {
            result = &mut wait_task => {
                let (result, registration) = result
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                Completion::Exited(result, registration)
            },
            _ = self.inner.cancellation.cancelled() => Completion::Stop(ProcessErrorCode::Cancelled),
            _ = &mut deadline => Completion::Stop(ProcessErrorCode::DeadlineExceeded),
            limit = limit_rx.recv() => match limit {
                Some(code) => Completion::Stop(code),
                None => {
                    let (result, registration) = (&mut wait_task)
                        .await
                        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                    Completion::Exited(result, registration)
                },
            },
        };
        let (status, registration, terminal_error) = match completion {
            Completion::Exited(result, registration) => {
                group.terminate();
                (
                    result.map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?,
                    registration,
                    None,
                )
            }
            Completion::Stop(code) => {
                group.terminate();
                let (status, registration) = tokio::time::timeout(CLEANUP_DEADLINE, &mut wait_task)
                    .await
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
                    .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
                (
                    status.map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?,
                    registration,
                    Some(ProcessError::new(code)),
                )
            }
        };
        let stdout = tokio::time::timeout(CLEANUP_DEADLINE, stdout_reader)
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))??;
        let stderr = tokio::time::timeout(CLEANUP_DEADLINE, stderr_reader)
            .await
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))??;
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

#[cfg(unix)]
struct UnixProcessGroup(u32);

#[cfg(unix)]
impl UnixProcessGroup {
    fn terminate(&self) {
        unsafe {
            let _ = libc::kill(-(self.0 as i32), libc::SIGKILL);
        }
    }
}

#[cfg(unix)]
impl Drop for UnixProcessGroup {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(unix)]
struct ActiveRegistration {
    active: Arc<AtomicUsize>,
}

#[cfg(unix)]
impl ActiveRegistration {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::AcqRel);
        Self { active }
    }
}

#[cfg(unix)]
impl Drop for ActiveRegistration {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(unix)]
fn read_sync_pipe<R>(
    mut pipe: R,
    limit: Option<usize>,
    keep: bool,
    limit_code: ProcessErrorCode,
    limit_tx: tokio::sync::mpsc::UnboundedSender<ProcessErrorCode>,
) -> Result<Vec<u8>, ProcessError>
where
    R: std::io::Read,
{
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

fn validate_common_spec(spec: &ProcessSpec) -> Result<(), ProcessError> {
    let valid_stdout = match spec.stdout {
        StdoutPolicy::Null => true,
        StdoutPolicy::Capture { byte_limit } => (1..=MAX_CAPTURE_BYTES).contains(&byte_limit),
        StdoutPolicy::Stream { queue_bytes } => (1..=MAX_CAPTURE_BYTES).contains(&queue_bytes),
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
    AttributeListSetup,
    SuspendedCreate,
    JobAssignment,
    RegistryInsertion,
    Resume,
}

#[cfg(windows)]
type NativeFailurePoint = Option<FailurePoint>;

#[cfg(test)]
mod tests;
