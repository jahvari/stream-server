use super::{
    NativeFailurePoint, ProcessError, ProcessErrorCode, ProcessRegistry, ProcessSpec, Registration,
};
use std::{
    cmp::Ordering,
    ffi::{OsStr, OsString},
    fs::File,
    io::Read,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{FromRawHandle, RawHandle},
    },
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
    },
};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation,
            WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Globalization::{CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal},
        Security::SECURITY_ATTRIBUTES,
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            },
            Pipes::CreatePipe,
            Threading::{
                CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
                DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
                InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread,
                STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
                WaitForSingleObject,
            },
        },
    },
    core::{BOOL, PCWSTR, PWSTR},
};

#[cfg(test)]
use windows::Win32::System::Threading::GetProcessId;

const WINDOWS_STRING_LIMIT: usize = 32_767;
const FORCED_EXIT_CODE: u32 = 0xC000_013A;
const FAILURE_AFTER_PIPE_SETUP: u8 = 0;
const FAILURE_DURING_ATTRIBUTE_LIST_UPDATE: u8 = 1;
const FAILURE_AFTER_ATTRIBUTE_LIST_SETUP: u8 = 2;
const FAILURE_AFTER_SUSPENDED_CREATE: u8 = 3;
const FAILURE_AFTER_JOB_ASSIGNMENT: u8 = 4;
const FAILURE_AFTER_REGISTRY_INSERTION: u8 = 5;
const FAILURE_AFTER_RESUME: u8 = 6;

static TRACKED_HANDLES: AtomicUsize = AtomicUsize::new(0);
static TRACKED_ATTRIBUTE_LISTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static LAST_CREATED_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ResourceSnapshot {
    handles: usize,
    attribute_lists: usize,
}

#[cfg(test)]
pub(super) fn resource_snapshot() -> ResourceSnapshot {
    ResourceSnapshot {
        handles: TRACKED_HANDLES.load(AtomicOrdering::Acquire),
        attribute_lists: TRACKED_ATTRIBUTE_LISTS.load(AtomicOrdering::Acquire),
    }
}

#[cfg(test)]
pub(super) fn process_handle_count() -> u32 {
    let mut count = 0;
    unsafe {
        windows::Win32::System::Threading::GetProcessHandleCount(
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut count,
        )
        .expect("query process handle count");
    }
    count
}

#[cfg(test)]
pub(super) fn last_created_pid() -> u32 {
    LAST_CREATED_PID.load(AtomicOrdering::Acquire)
}

#[cfg(test)]
pub(super) fn process_is_alive(pid: u32) -> bool {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    unsafe {
        let Ok(handle) = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        ) else {
            return false;
        };
        let result = WaitForSingleObject(handle, 0) == windows::Win32::Foundation::WAIT_TIMEOUT;
        let _ = CloseHandle(handle);
        result
    }
}

pub(super) struct SpawnedProcess {
    pub(super) process: Arc<TrackedHandle>,
    pub(super) job: Arc<TrackedHandle>,
    pub(super) stdout: TrackedHandle,
    pub(super) stderr: TrackedHandle,
    pub(super) registration: Registration,
}

pub(super) struct TrackedHandle {
    raw: HANDLE,
}

unsafe impl Send for TrackedHandle {}
unsafe impl Sync for TrackedHandle {}

impl TrackedHandle {
    fn new(raw: HANDLE) -> Result<Self, ProcessError> {
        if raw.is_invalid() {
            return Err(spawn_error());
        }
        TRACKED_HANDLES.fetch_add(1, AtomicOrdering::AcqRel);
        Ok(Self { raw })
    }

    fn raw(&self) -> HANDLE {
        self.raw
    }

    fn into_file(mut self) -> File {
        let raw = self.raw;
        self.raw = HANDLE::default();
        TRACKED_HANDLES.fetch_sub(1, AtomicOrdering::AcqRel);
        unsafe { File::from_raw_handle(raw.0 as RawHandle) }
    }
}

impl Drop for TrackedHandle {
    fn drop(&mut self) {
        if !self.raw.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.raw);
            }
            TRACKED_HANDLES.fetch_sub(1, AtomicOrdering::AcqRel);
            self.raw = HANDLE::default();
        }
    }
}

struct AttributeList {
    storage: Vec<usize>,
    pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new(handles: &[HANDLE], failure_point: NativeFailurePoint) -> Result<Self, ProcessError> {
        let mut bytes = 0_usize;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut bytes);
        }
        if bytes == 0 {
            return Err(spawn_error());
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe {
            InitializeProcThreadAttributeList(Some(pointer), 1, None, &mut bytes)
                .map_err(|_| spawn_error())?;
        }
        TRACKED_ATTRIBUTE_LISTS.fetch_add(1, AtomicOrdering::AcqRel);
        let list = Self { storage, pointer };
        inject(failure_point, FAILURE_DURING_ATTRIBUTE_LIST_UPDATE)?;
        unsafe {
            UpdateProcThreadAttribute(
                list.pointer,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
            .map_err(|_| spawn_error())?;
        }
        Ok(list)
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer);
        }
        TRACKED_ATTRIBUTE_LISTS.fetch_sub(1, AtomicOrdering::AcqRel);
        self.storage.clear();
    }
}

struct PipeSet {
    stdin_child: TrackedHandle,
    stdin_parent: TrackedHandle,
    stdout_parent: TrackedHandle,
    stdout_child: TrackedHandle,
    stderr_parent: TrackedHandle,
    stderr_child: TrackedHandle,
}

impl PipeSet {
    fn new() -> Result<Self, ProcessError> {
        let (stdin_child, stdin_parent) = create_pipe()?;
        let (stdout_parent, stdout_child) = create_pipe()?;
        let (stderr_parent, stderr_child) = create_pipe()?;
        set_non_inheritable(&stdin_parent)?;
        set_non_inheritable(&stdout_parent)?;
        set_non_inheritable(&stderr_parent)?;
        Ok(Self {
            stdin_child,
            stdin_parent,
            stdout_parent,
            stdout_child,
            stderr_parent,
            stderr_child,
        })
    }
}

struct FailedSpawnCleanup {
    armed: bool,
    process: Option<Arc<TrackedHandle>>,
    thread: Option<TrackedHandle>,
    job: Option<Arc<TrackedHandle>>,
}

impl FailedSpawnCleanup {
    fn new(process: TrackedHandle, thread: TrackedHandle) -> Self {
        Self {
            armed: true,
            process: Some(Arc::new(process)),
            thread: Some(thread),
            job: None,
        }
    }

    fn terminate_and_wait(&mut self) -> Result<(), ProcessError> {
        if !self.armed {
            return Ok(());
        }
        let process = self.process.as_ref().ok_or_else(wait_error)?;
        let before = unsafe { WaitForSingleObject(process.raw(), 0) };
        if before == WAIT_OBJECT_0 {
            self.armed = false;
            return Ok(());
        }
        if before != WAIT_TIMEOUT {
            return Err(wait_error());
        }
        let terminated = unsafe {
            if let Some(job) = &self.job {
                TerminateJobObject(job.raw(), FORCED_EXIT_CODE)
            } else {
                TerminateProcess(process.raw(), FORCED_EXIT_CODE)
            }
        };
        if terminated.is_err() && unsafe { WaitForSingleObject(process.raw(), 0) } != WAIT_OBJECT_0
        {
            return Err(wait_error());
        }
        if unsafe { WaitForSingleObject(process.raw(), 5_000) } != WAIT_OBJECT_0 {
            return Err(wait_error());
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for FailedSpawnCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.terminate_and_wait();
    }
}

pub(super) fn spawn(
    spec: &ProcessSpec,
    registry: Arc<ProcessRegistry>,
    failure_point: NativeFailurePoint,
) -> Result<SpawnedProcess, ProcessError> {
    #[cfg(test)]
    LAST_CREATED_PID.store(0, AtomicOrdering::Release);
    let executable = nul_terminated(spec.executable.as_os_str())?;
    let current_dir = nul_terminated(spec.current_dir.as_os_str())?;
    let mut command_line = build_command_line(spec.executable.as_os_str(), &spec.args)?;
    let environment = build_environment_block(&spec.environment)?;
    let mut pipes = PipeSet::new()?;
    inject(failure_point, FAILURE_AFTER_PIPE_SETUP)?;

    let inheritable = [
        pipes.stdin_child.raw(),
        pipes.stdout_child.raw(),
        pipes.stderr_child.raw(),
    ];
    let attributes = AttributeList::new(&inheritable, failure_point)?;
    inject(failure_point, FAILURE_AFTER_ATTRIBUTE_LIST_SETUP)?;

    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = pipes.stdin_child.raw();
    startup.StartupInfo.hStdOutput = pipes.stdout_child.raw();
    startup.StartupInfo.hStdError = pipes.stderr_child.raw();
    startup.lpAttributeList = attributes.pointer;
    let mut process_info = PROCESS_INFORMATION::default();
    let flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW;
    unsafe {
        CreateProcessW(
            PCWSTR(executable.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            flags,
            Some(environment.as_ptr().cast()),
            PCWSTR(current_dir.as_ptr()),
            &startup.StartupInfo,
            &mut process_info,
        )
        .map_err(|_| spawn_error())?;
    }
    #[cfg(test)]
    LAST_CREATED_PID.store(process_info.dwProcessId, AtomicOrdering::Release);
    let process = TrackedHandle::new(process_info.hProcess)?;
    let thread = TrackedHandle::new(process_info.hThread)?;
    let mut cleanup = FailedSpawnCleanup::new(process, thread);
    if inject(failure_point, FAILURE_AFTER_SUSPENDED_CREATE).is_err() {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }

    let raw_job = match unsafe { CreateJobObjectW(None, PCWSTR::null()) } {
        Ok(job) => job,
        Err(_) => {
            cleanup.terminate_and_wait()?;
            return Err(spawn_error());
        }
    };
    let job = match TrackedHandle::new(raw_job) {
        Ok(job) => job,
        Err(error) => {
            cleanup.terminate_and_wait()?;
            return Err(error);
        }
    };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .is_err()
    {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }
    if unsafe {
        AssignProcessToJobObject(
            job.raw(),
            cleanup.process.as_ref().expect("process handle").raw(),
        )
    }
    .is_err()
    {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }
    cleanup.job = Some(Arc::new(job));
    if inject(failure_point, FAILURE_AFTER_JOB_ASSIGNMENT).is_err() {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }

    let job = cleanup.job.as_ref().expect("job handle").clone();
    let registration = registry.register_windows(
        job.clone(),
        cleanup.process.as_ref().expect("process handle").clone(),
    );
    if inject(failure_point, FAILURE_AFTER_REGISTRY_INSERTION).is_err() {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }
    let resume_result =
        unsafe { ResumeThread(cleanup.thread.as_ref().expect("thread handle").raw()) };
    if resume_result == u32::MAX {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }
    if inject(failure_point, FAILURE_AFTER_RESUME).is_err() {
        cleanup.terminate_and_wait()?;
        return Err(spawn_error());
    }

    drop(attributes);
    drop(pipes.stdin_child);
    drop(pipes.stdin_parent);
    drop(pipes.stdout_child);
    drop(pipes.stderr_child);
    drop(cleanup.thread.take());
    cleanup.armed = false;
    let process = cleanup.process.take().expect("process handle");
    let job = cleanup.job.take().expect("job handle");
    let stdout = std::mem::replace(
        &mut pipes.stdout_parent,
        TrackedHandle {
            raw: HANDLE::default(),
        },
    );
    let stderr = std::mem::replace(
        &mut pipes.stderr_parent,
        TrackedHandle {
            raw: HANDLE::default(),
        },
    );
    Ok(SpawnedProcess {
        process,
        job,
        stdout,
        stderr,
        registration,
    })
}

pub(super) fn read_pipe(
    pipe: TrackedHandle,
    limit: Option<usize>,
    keep: bool,
    limit_code: ProcessErrorCode,
    limit_tx: tokio::sync::mpsc::UnboundedSender<ProcessErrorCode>,
) -> tokio::task::JoinHandle<Result<Vec<u8>, ProcessError>> {
    tokio::task::spawn_blocking(move || {
        let mut file = pipe.into_file();
        let mut output = Vec::with_capacity(limit.unwrap_or(0).min(8_192));
        let mut buffer = [0_u8; 8_192];
        let mut total = 0_usize;
        let mut exceeded = false;
        loop {
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => 0,
                Err(_) => return Err(ProcessError::new(ProcessErrorCode::WaitFailed)),
            };
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
    })
}

pub(super) fn poll_exit(process: &TrackedHandle) -> Result<Option<u32>, ProcessError> {
    unsafe {
        match WaitForSingleObject(process.raw(), 0) {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(None),
            _ => return Err(ProcessError::new(ProcessErrorCode::WaitFailed)),
        }
        let mut exit_code = 0_u32;
        GetExitCodeProcess(process.raw(), &mut exit_code)
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        Ok(Some(exit_code))
    }
}

pub(super) fn terminate(job: &TrackedHandle) -> Result<(), ProcessError> {
    unsafe { TerminateJobObject(job.raw(), FORCED_EXIT_CODE).map_err(|_| spawn_error()) }
}

pub(super) fn terminate_and_wait(
    job: &TrackedHandle,
    deadline: std::time::Duration,
) -> Result<(), ProcessError> {
    let expires = std::time::Instant::now() + deadline;
    let mut terminated = false;
    loop {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        unsafe {
            QueryInformationJobObject(
                Some(job.raw()),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                None,
            )
            .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
        }
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        if !terminated {
            terminate(job)?;
            terminated = true;
        }
        if std::time::Instant::now() >= expires {
            return Err(ProcessError::new(ProcessErrorCode::WaitFailed));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

pub(super) fn is_process_tree_drained(
    job: &TrackedHandle,
    process: &TrackedHandle,
) -> Result<bool, ProcessError> {
    if poll_exit(process)?.is_none() {
        return Ok(false);
    }
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    unsafe {
        QueryInformationJobObject(
            Some(job.raw()),
            JobObjectBasicAccountingInformation,
            (&raw mut accounting).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            None,
        )
        .map_err(|_| ProcessError::new(ProcessErrorCode::WaitFailed))?;
    }
    Ok(accounting.ActiveProcesses == 0)
}

#[cfg(test)]
pub(super) fn process_id(process: &TrackedHandle) -> u32 {
    unsafe { GetProcessId(process.raw()) }
}

fn create_pipe() -> Result<(TrackedHandle, TrackedHandle), ProcessError> {
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: BOOL(1),
    };
    unsafe {
        CreatePipe(&mut read, &mut write, Some(&raw const attributes), 0)
            .map_err(|_| spawn_error())?;
    }
    let read = TrackedHandle::new(read)?;
    let write = TrackedHandle::new(write)?;
    Ok((read, write))
}

fn set_non_inheritable(handle: &TrackedHandle) -> Result<(), ProcessError> {
    unsafe {
        SetHandleInformation(handle.raw(), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
            .map_err(|_| spawn_error())
    }
}

fn nul_terminated(value: &OsStr) -> Result<Vec<u16>, ProcessError> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(invalid_spec());
    }
    wide.push(0);
    Ok(wide)
}

fn build_command_line(executable: &OsStr, args: &[OsString]) -> Result<Vec<u16>, ProcessError> {
    let mut rendered = Vec::new();
    for (index, argument) in std::iter::once(executable)
        .chain(args.iter().map(OsString::as_os_str))
        .enumerate()
    {
        let wide = argument.encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(invalid_spec());
        }
        if index != 0 {
            rendered.push(b' ' as u16);
        }
        quote_windows_argument(&wide, &mut rendered);
    }
    rendered.push(0);
    if rendered.len() > WINDOWS_STRING_LIMIT {
        return Err(invalid_spec());
    }
    Ok(rendered)
}

fn quote_windows_argument(argument: &[u16], output: &mut Vec<u16>) {
    let needs_quotes = argument.is_empty()
        || argument
            .iter()
            .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16 || *unit == b'"' as u16);
    if !needs_quotes {
        output.extend_from_slice(argument);
        return;
    }
    output.push(b'"' as u16);
    let mut backslashes = 0_usize;
    for &unit in argument {
        if unit == b'\\' as u16 {
            backslashes += 1;
        } else if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(unit);
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(unit);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
}

fn build_environment_block(
    environment: &std::collections::BTreeMap<OsString, OsString>,
) -> Result<Vec<u16>, ProcessError> {
    let mut entries = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let name = name.encode_wide().collect::<Vec<_>>();
        let value = value.encode_wide().collect::<Vec<_>>();
        if name.is_empty()
            || name.contains(&(b'=' as u16))
            || name.contains(&0)
            || value.contains(&0)
        {
            return Err(invalid_spec());
        }
        entries.push((name, value));
    }
    entries.sort_by(|left, right| compare_ordinal_ignore_case(&left.0, &right.0));
    if entries
        .windows(2)
        .any(|pair| compare_ordinal_ignore_case(&pair[0].0, &pair[1].0) == Ordering::Equal)
    {
        return Err(invalid_spec());
    }
    let mut block = Vec::new();
    for (name, value) in entries {
        block.extend_from_slice(&name);
        block.push(b'=' as u16);
        block.extend_from_slice(&value);
        block.push(0);
    }
    block.push(0);
    if environment.is_empty() {
        block.push(0);
    }
    if block.len() > WINDOWS_STRING_LIMIT {
        return Err(invalid_spec());
    }
    Ok(block)
}

fn compare_ordinal_ignore_case(left: &[u16], right: &[u16]) -> Ordering {
    match unsafe { CompareStringOrdinal(left, right, true) } {
        result if result == CSTR_LESS_THAN => Ordering::Less,
        result if result == CSTR_EQUAL => Ordering::Equal,
        result if result == CSTR_GREATER_THAN => Ordering::Greater,
        _ => left.cmp(right),
    }
}

fn inject(failure_point: NativeFailurePoint, expected: u8) -> Result<(), ProcessError> {
    #[cfg(test)]
    if failure_point.map(|point| point as u8) == Some(expected) {
        return Err(spawn_error());
    }
    #[cfg(not(test))]
    let _ = (failure_point, expected);
    Ok(())
}

fn invalid_spec() -> ProcessError {
    ProcessError::new(ProcessErrorCode::InvalidSpec)
}

fn spawn_error() -> ProcessError {
    ProcessError::new(ProcessErrorCode::SpawnFailed)
}

fn wait_error() -> ProcessError {
    ProcessError::new(ProcessErrorCode::WaitFailed)
}
