use super::{
    process::{
        BoundedOutput, ProcessError, ProcessErrorCode, ProcessSpec, ProcessSupervisor, StdinPolicy,
        StdoutPolicy,
    },
    runtime_manifest::{RuntimeError, RuntimeHost, RuntimeManifest},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File},
    io::{Read, Seek},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::Semaphore;

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

const IDENTITY_COMMAND_DEADLINE: Duration = Duration::from_secs(10);
const IDENTITY_STDOUT_LIMIT: usize = 128 * 1024;
const IDENTITY_STDERR_LIMIT: usize = 32 * 1024;
const SUPPORTED_FFMPEG_VERSION: &str = "7.1.4";
const SUPPORTED_JELLYFIN_MATCHER: &str = "7.1.4-Jellyfin";
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const HASH_DEADLINE: Duration = Duration::from_secs(10);
const MAX_PATH_CANDIDATES: usize = 64;
const RESOLUTION_DEADLINE: Duration = Duration::from_secs(30);

#[cfg(test)]
static HASH_ACTIVE: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HASH_MAX_ACTIVE: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HASH_TOTAL: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static HASH_PAUSED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    explicit_root: Option<PathBuf>,
    managed_current_root: Option<PathBuf>,
    system_roots: Vec<PathBuf>,
    search_path: Option<OsString>,
}

impl RuntimeConfig {
    pub fn isolated() -> Self {
        Self {
            explicit_root: None,
            managed_current_root: None,
            system_roots: Vec::new(),
            search_path: None,
        }
    }

    pub fn for_server(config_dir: &Path) -> Self {
        Self {
            explicit_root: None,
            managed_current_root: Some(config_dir.join("runtimes").join("current")),
            system_roots: known_system_roots(),
            search_path: std::env::var_os("PATH"),
        }
    }

    pub fn with_explicit_root(mut self, root: PathBuf) -> Self {
        self.explicit_root = Some(root);
        self
    }

    pub fn with_managed_current_root(mut self, root: PathBuf) -> Self {
        self.managed_current_root = Some(root);
        self
    }

    pub fn with_system_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.system_roots = roots;
        self
    }

    pub fn with_search_path(mut self, search_path: Option<OsString>) -> Self {
        self.search_path = search_path;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeId {
    pub install_digest: String,
    pub ffmpeg_version: String,
    pub jellyfin_revision: Option<String>,
    pub build_configuration_digest: String,
    pub pair_root_identity: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeKind {
    Jellyfin,
    SoftwareCompatible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStatus {
    Unavailable,
    Jellyfin,
    SoftwareCompatible,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeExecutable {
    Ffmpeg,
    Ffprobe,
}

/// Runtime commands are closed, crate-owned recipes.
///
/// ```compile_fail
/// use std::{ffi::OsString, time::Duration};
/// use stream_server::transcoding::{process::StdoutPolicy, runtime::RuntimeCommand};
/// let _bypass = RuntimeCommand {
///     args: vec![OsString::from("arbitrary-raw-flag")],
///     stdout: StdoutPolicy::Null,
///     stderr_byte_limit: 1,
///     wall_deadline: Duration::from_secs(1),
/// };
/// ```
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct RuntimeCommand {
    args: Vec<OsString>,
    stdout: StdoutPolicy,
    stderr_byte_limit: usize,
    wall_deadline: Duration,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeCommandError {
    Runtime(RuntimeError),
    Process(ProcessError),
}

impl fmt::Display for RuntimeCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(formatter),
            Self::Process(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RuntimeCommandError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    id: RuntimeId,
    kind: RuntimeKind,
}

impl RuntimeSnapshot {
    pub fn id(&self) -> &RuntimeId {
        &self.id
    }

    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }
}

/// An identity-bearing, leased runtime session. Executable paths stay opaque.
///
/// ```compile_fail
/// use stream_server::transcoding::runtime::{RuntimeExecutable, VerifiedRuntimeSession};
/// fn leak_path(session: &VerifiedRuntimeSession) {
///     let _ = session.executable_path(RuntimeExecutable::Ffmpeg);
/// }
/// ```
pub struct VerifiedRuntimeSession {
    runtime: Arc<FfmpegRuntime>,
    supervisor: Arc<ProcessSupervisor>,
}

impl VerifiedRuntimeSession {
    pub fn id(&self) -> &RuntimeId {
        &self.runtime.id
    }

    pub fn kind(&self) -> RuntimeKind {
        self.runtime.kind
    }

    #[allow(dead_code)]
    pub(crate) async fn run_bounded(
        &self,
        executable: RuntimeExecutable,
        command: RuntimeCommand,
    ) -> Result<BoundedOutput, RuntimeCommandError> {
        let execution_lease = open_pair_lease(
            self.runtime.lease.root.clone(),
            OpenMode::MetadataOnly {
                ffmpeg_digest: self.runtime.lease.ffmpeg.seal.digest,
                ffprobe_digest: self.runtime.lease.ffprobe.seal.digest,
            },
        )
        .await
        .map_err(|_| RuntimeCommandError::Runtime(RuntimeError::RuntimeChanged))?;
        if execution_lease.root != self.runtime.lease.root
            || execution_lease.ffmpeg != self.runtime.ffmpeg
            || execution_lease.ffprobe != self.runtime.ffprobe
            || execution_lease.lease.root_identity != self.runtime.lease.root_identity
            || execution_lease.lease.ffmpeg.seal != self.runtime.lease.ffmpeg.seal
            || execution_lease.lease.ffprobe.seal != self.runtime.lease.ffprobe.seal
        {
            return Err(RuntimeCommandError::Runtime(RuntimeError::RuntimeChanged));
        }
        let executable_path = match executable {
            RuntimeExecutable::Ffmpeg => {
                bound_execution_path(&execution_lease.lease.ffmpeg.file, &execution_lease.ffmpeg)
            }
            RuntimeExecutable::Ffprobe => bound_execution_path(
                &execution_lease.lease.ffprobe.file,
                &execution_lease.ffprobe,
            ),
        }
        .map_err(|_| RuntimeCommandError::Runtime(RuntimeError::RuntimeChanged))?;
        let current_dir =
            bound_execution_path(&execution_lease.lease._root_file, &execution_lease.root)
                .map_err(|_| RuntimeCommandError::Runtime(RuntimeError::RuntimeChanged))?;
        self.supervisor
            .run_bounded(ProcessSpec {
                executable: executable_path,
                args: command.args,
                current_dir,
                environment: BTreeMap::new(),
                stdin: StdinPolicy::Null,
                stdout: command.stdout,
                stderr_byte_limit: command.stderr_byte_limit,
                wall_deadline: command.wall_deadline,
            })
            .await
            .map_err(RuntimeCommandError::Process)
    }
}

impl RuntimeKind {
    pub fn hardware_allowed(self) -> bool {
        matches!(self, Self::Jellyfin)
    }
}

/// The service does not expose its raw process supervisor.
///
/// ```compile_fail
/// use stream_server::transcoding::runtime::TranscodingService;
/// fn bypass(service: &TranscodingService) {
///     let _ = service.supervisor();
/// }
/// ```
pub struct TranscodingService {
    supervisor: Arc<ProcessSupervisor>,
    state: tokio::sync::RwLock<ServiceState>,
}

enum ServiceState {
    Unavailable,
    Resolved {
        config: RuntimeConfig,
        runtime: Arc<FfmpegRuntime>,
    },
}

impl TranscodingService {
    pub fn unavailable(supervisor: Arc<ProcessSupervisor>) -> Self {
        Self {
            supervisor,
            state: tokio::sync::RwLock::new(ServiceState::Unavailable),
        }
    }

    pub fn resolved(
        config: RuntimeConfig,
        supervisor: Arc<ProcessSupervisor>,
        runtime: Arc<FfmpegRuntime>,
    ) -> Self {
        Self {
            supervisor,
            state: tokio::sync::RwLock::new(ServiceState::Resolved { config, runtime }),
        }
    }

    pub async fn current(&self) -> Option<RuntimeSnapshot> {
        match &*self.state.read().await {
            ServiceState::Unavailable => None,
            ServiceState::Resolved { runtime, .. } => Some(RuntimeSnapshot {
                id: runtime.id.clone(),
                kind: runtime.kind,
            }),
        }
    }

    pub async fn status(&self) -> RuntimeStatus {
        match &*self.state.read().await {
            ServiceState::Unavailable => RuntimeStatus::Unavailable,
            ServiceState::Resolved { runtime, .. } => match runtime.kind {
                RuntimeKind::Jellyfin => RuntimeStatus::Jellyfin,
                RuntimeKind::SoftwareCompatible => RuntimeStatus::SoftwareCompatible,
            },
        }
    }

    pub async fn runtime_for_session(&self) -> Result<VerifiedRuntimeSession, RuntimeError> {
        let mut state = self.state.write().await;
        let ServiceState::Resolved { config, runtime } = &mut *state else {
            return Err(RuntimeError::Unavailable);
        };
        let verification = if runtime.first_session_verified.load(Ordering::Acquire) {
            verify_metadata_unchanged(runtime).await
        } else {
            verify_unchanged(runtime).await
        };
        if verification.is_ok() {
            runtime
                .first_session_verified
                .store(true, Ordering::Release);
            return Ok(VerifiedRuntimeSession {
                runtime: runtime.clone(),
                supervisor: self.supervisor.clone(),
            });
        }
        let replacement = resolve_runtime(config, &self.supervisor).await?;
        verify_unchanged(&replacement).await?;
        replacement
            .first_session_verified
            .store(true, Ordering::Release);
        *runtime = replacement.clone();
        Ok(VerifiedRuntimeSession {
            runtime: replacement,
            supervisor: self.supervisor.clone(),
        })
    }
}

#[derive(Debug)]
pub struct FfmpegRuntime {
    id: RuntimeId,
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
    kind: RuntimeKind,
    lease: Arc<RuntimeLease>,
    first_session_verified: AtomicBool,
}

impl FfmpegRuntime {
    pub fn id(&self) -> &RuntimeId {
        &self.id
    }

    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }
}

#[derive(Debug)]
struct RuntimeLease {
    root: PathBuf,
    _root_file: Arc<File>,
    root_identity: FileIdentity,
    ffmpeg: FileLease,
    ffprobe: FileLease,
}

#[derive(Debug)]
struct FileLease {
    file: Arc<File>,
    seal: FileSeal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileSeal {
    length: u64,
    modified: Option<SystemTime>,
    digest: [u8; 32],
    identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume: u64,
    file: u64,
}

struct ProbedPair {
    root: PathBuf,
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
    lease: RuntimeLease,
    version: String,
    jellyfin: bool,
    build_configuration_digest: String,
}

#[derive(Debug)]
struct OpenedPair {
    root: PathBuf,
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
    lease: RuntimeLease,
}

#[derive(Clone, Copy, Debug)]
enum OpenMode {
    Full,
    MetadataOnly {
        ffmpeg_digest: [u8; 32],
        ffprobe_digest: [u8; 32],
    },
}

#[derive(Debug)]
enum CandidateFailure {
    Missing,
    Unsafe,
    Probe,
    Deadline,
    Incompatible,
}

#[derive(Clone, Copy)]
enum CandidateSource {
    ManagedCurrent,
    SystemPackage,
    SearchPath,
}

#[derive(Clone)]
enum RuntimeProvenance {
    Unproven,
    #[allow(dead_code)]
    AuthenticatedManaged {
        jellyfin_revision: String,
    },
}

pub async fn resolve_runtime(
    config: &RuntimeConfig,
    supervisor: &ProcessSupervisor,
) -> Result<Arc<FfmpegRuntime>, RuntimeError> {
    tokio::time::timeout(
        RESOLUTION_DEADLINE,
        resolve_runtime_inner(config, supervisor),
    )
    .await
    .map_err(|_| RuntimeError::ProbeDeadline)?
}

async fn resolve_runtime_inner(
    config: &RuntimeConfig,
    supervisor: &ProcessSupervisor,
) -> Result<Arc<FfmpegRuntime>, RuntimeError> {
    let manifest = RuntimeManifest::embedded()?;
    let host_artifact = current_runtime_host().and_then(|host| manifest.artifact_for_host(host));
    let required_version = host_artifact
        .map(|artifact| artifact.ffmpeg_version())
        .unwrap_or(SUPPORTED_FFMPEG_VERSION);
    let ffmpeg_jellyfin_matcher = host_artifact
        .map(|artifact| artifact.version_matchers().ffmpeg())
        .unwrap_or(SUPPORTED_JELLYFIN_MATCHER);
    let ffprobe_jellyfin_matcher = host_artifact
        .map(|artifact| artifact.version_matchers().ffprobe())
        .unwrap_or(SUPPORTED_JELLYFIN_MATCHER);
    let mut candidates = Vec::new();
    if let Some(root) = &config.explicit_root
        && (is_remote_or_device_path(root) || !root.is_absolute())
    {
        return Err(RuntimeError::UnsafePath);
    }
    if let Some(root) = &config.managed_current_root {
        candidates.push((
            root.clone(),
            CandidateSource::ManagedCurrent,
            RuntimeProvenance::Unproven,
        ));
    }
    candidates.extend(config.system_roots.iter().cloned().map(|root| {
        (
            root,
            CandidateSource::SystemPackage,
            RuntimeProvenance::Unproven,
        )
    }));
    if let Some(search_path) = &config.search_path {
        let mut path_candidates = Vec::new();
        for root in std::env::split_paths(search_path) {
            if !root.is_absolute()
                || is_remote_or_device_path(&root)
                || path_candidates
                    .iter()
                    .any(|seen: &PathBuf| paths_equal(seen, &root))
            {
                continue;
            }
            path_candidates.push(root);
            if path_candidates.len() == MAX_PATH_CANDIDATES {
                break;
            }
        }
        candidates.extend(path_candidates.into_iter().map(|root| {
            (
                root,
                CandidateSource::SearchPath,
                RuntimeProvenance::Unproven,
            )
        }));
    }

    let mut seen = Vec::<PathBuf>::new();
    let mut degraded = None;
    if let Some(root) = &config.explicit_root {
        let canonical_key = canonical_local_root(root).map_err(candidate_failure_error)?;
        seen.push(canonical_key);
        let pair = probe_pair(
            root,
            required_version,
            ffmpeg_jellyfin_matcher,
            ffprobe_jellyfin_matcher,
            supervisor,
        )
        .await
        .map_err(candidate_failure_error)?;
        return Ok(Arc::new(
            pair.into_runtime(RuntimeKind::SoftwareCompatible, None),
        ));
    }
    let mut saw_deadline = false;
    let mut saw_probe_failure = false;
    let mut saw_incompatible = false;
    for (root, _source, provenance) in candidates {
        let canonical_key = match canonical_local_root(&root) {
            Ok(root) => root,
            Err(CandidateFailure::Missing) => continue,
            Err(CandidateFailure::Unsafe) if config.explicit_root.as_ref() == Some(&root) => {
                return Err(RuntimeError::UnsafePath);
            }
            Err(_) => continue,
        };
        if seen.iter().any(|seen| paths_equal(seen, &canonical_key)) {
            continue;
        }
        seen.push(canonical_key);
        match probe_pair(
            &root,
            required_version,
            ffmpeg_jellyfin_matcher,
            ffprobe_jellyfin_matcher,
            supervisor,
        )
        .await
        {
            Ok(pair) if pair.jellyfin => match provenance {
                RuntimeProvenance::AuthenticatedManaged { jellyfin_revision } => {
                    return Ok(Arc::new(
                        pair.into_runtime(RuntimeKind::Jellyfin, Some(&jellyfin_revision)),
                    ));
                }
                RuntimeProvenance::Unproven => retain_best_software_candidate(&mut degraded, pair),
            },
            Ok(pair) => retain_best_software_candidate(&mut degraded, pair),
            Err(CandidateFailure::Deadline) => saw_deadline = true,
            Err(CandidateFailure::Probe) => saw_probe_failure = true,
            Err(CandidateFailure::Incompatible) => saw_incompatible = true,
            Err(CandidateFailure::Unsafe) if config.explicit_root.as_ref() == Some(&root) => {
                return Err(RuntimeError::UnsafePath);
            }
            Err(_) => {}
        }
    }
    if let Some(pair) = degraded {
        return Ok(Arc::new(
            pair.into_runtime(RuntimeKind::SoftwareCompatible, None),
        ));
    }
    if saw_deadline {
        Err(RuntimeError::ProbeDeadline)
    } else if saw_incompatible {
        Err(RuntimeError::IncompatiblePair)
    } else if saw_probe_failure {
        Err(RuntimeError::ProbeFailed)
    } else {
        Err(RuntimeError::Unavailable)
    }
}

fn retain_best_software_candidate(slot: &mut Option<ProbedPair>, candidate: ProbedPair) {
    if slot
        .as_ref()
        .is_none_or(|selected| candidate.jellyfin && !selected.jellyfin)
    {
        *slot = Some(candidate);
    }
}

fn current_runtime_host() -> Option<RuntimeHost> {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        Some(RuntimeHost::WindowsX64)
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some(RuntimeHost::LinuxX64)
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some(RuntimeHost::MacOsArm64)
    }
    #[cfg(not(any(
        all(windows, target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        None
    }
}

fn candidate_failure_error(failure: CandidateFailure) -> RuntimeError {
    match failure {
        CandidateFailure::Missing => RuntimeError::Unavailable,
        CandidateFailure::Unsafe => RuntimeError::UnsafePath,
        CandidateFailure::Probe => RuntimeError::ProbeFailed,
        CandidateFailure::Deadline => RuntimeError::ProbeDeadline,
        CandidateFailure::Incompatible => RuntimeError::IncompatiblePair,
    }
}

pub async fn verify_unchanged(runtime: &FfmpegRuntime) -> Result<(), RuntimeError> {
    verify_opened(runtime, OpenMode::Full).await
}

async fn verify_metadata_unchanged(runtime: &FfmpegRuntime) -> Result<(), RuntimeError> {
    verify_opened(
        runtime,
        OpenMode::MetadataOnly {
            ffmpeg_digest: runtime.lease.ffmpeg.seal.digest,
            ffprobe_digest: runtime.lease.ffprobe.seal.digest,
        },
    )
    .await
}

async fn verify_opened(runtime: &FfmpegRuntime, mode: OpenMode) -> Result<(), RuntimeError> {
    let opened = open_pair_lease(runtime.lease.root.clone(), mode)
        .await
        .map_err(|_| RuntimeError::RuntimeChanged)?;
    if opened.root != runtime.lease.root
        || opened.ffmpeg != runtime.ffmpeg
        || opened.ffprobe != runtime.ffprobe
        || opened.lease.root_identity != runtime.lease.root_identity
        || opened.lease.ffmpeg.seal != runtime.lease.ffmpeg.seal
        || opened.lease.ffprobe.seal != runtime.lease.ffprobe.seal
    {
        return Err(RuntimeError::RuntimeChanged);
    }
    Ok(())
}

impl ProbedPair {
    fn into_runtime(self, kind: RuntimeKind, jellyfin_revision: Option<&str>) -> FfmpegRuntime {
        let install_digest = pair_install_digest(&self.lease.ffmpeg.seal, &self.lease.ffprobe.seal);
        let pair_root_identity = pair_root_identity(&self.root, self.lease.root_identity);
        let id = RuntimeId {
            install_digest,
            ffmpeg_version: self.version,
            jellyfin_revision: jellyfin_revision.map(str::to_owned),
            build_configuration_digest: self.build_configuration_digest,
            pair_root_identity,
        };
        let lease = Arc::new(self.lease);
        FfmpegRuntime {
            id,
            ffmpeg: self.ffmpeg,
            ffprobe: self.ffprobe,
            kind,
            lease,
            first_session_verified: AtomicBool::new(false),
        }
    }
}

async fn probe_pair(
    root: &Path,
    required_version: &str,
    ffmpeg_jellyfin_matcher: &str,
    ffprobe_jellyfin_matcher: &str,
    supervisor: &ProcessSupervisor,
) -> Result<ProbedPair, CandidateFailure> {
    let opened = open_pair_lease(root.to_path_buf(), OpenMode::Full).await?;
    let OpenedPair {
        root,
        ffmpeg,
        ffprobe,
        lease,
    } = opened;
    let ffmpeg_before = lease.ffmpeg.seal.clone();
    let ffprobe_before = lease.ffprobe.seal.clone();
    let ffmpeg_version = probe_identity_command(
        &lease.ffmpeg.file,
        &ffmpeg,
        &lease._root_file,
        &root,
        "-version",
        supervisor,
    )
    .await?;
    let ffprobe_version = probe_identity_command(
        &lease.ffprobe.file,
        &ffprobe,
        &lease._root_file,
        &root,
        "-version",
        supervisor,
    )
    .await?;
    let ffmpeg_token = parse_version(&ffmpeg_version, "ffmpeg")?;
    let ffprobe_token = parse_version(&ffprobe_version, "ffprobe")?;
    if ffmpeg_token != ffprobe_token {
        return Err(CandidateFailure::Incompatible);
    }
    let jellyfin =
        ffmpeg_token == ffmpeg_jellyfin_matcher && ffprobe_token == ffprobe_jellyfin_matcher;
    if !jellyfin && ffmpeg_token != required_version {
        return Err(CandidateFailure::Incompatible);
    }

    let ffmpeg_build = probe_identity_command(
        &lease.ffmpeg.file,
        &ffmpeg,
        &lease._root_file,
        &root,
        "-buildconf",
        supervisor,
    )
    .await?;
    let ffprobe_build = probe_identity_command(
        &lease.ffprobe.file,
        &ffprobe,
        &lease._root_file,
        &root,
        "-buildconf",
        supervisor,
    )
    .await?;
    let ffmpeg_configuration = build_configuration(&ffmpeg_build)?;
    let ffprobe_configuration = build_configuration(&ffprobe_build)?;
    if ffmpeg_configuration != ffprobe_configuration {
        return Err(CandidateFailure::Incompatible);
    }
    let ffmpeg_after = metadata_seal_open_file(&lease.ffmpeg.file, ffmpeg_before.digest)?;
    let ffprobe_after = metadata_seal_open_file(&lease.ffprobe.file, ffprobe_before.digest)?;
    if ffmpeg_before != ffmpeg_after || ffprobe_before != ffprobe_after {
        return Err(CandidateFailure::Unsafe);
    }
    Ok(ProbedPair {
        root,
        ffmpeg,
        ffprobe,
        lease,
        version: required_version.to_owned(),
        jellyfin,
        build_configuration_digest: digest_bytes(&ffmpeg_configuration),
    })
}

async fn probe_identity_command(
    executable_file: &File,
    executable: &Path,
    root_file: &File,
    root: &Path,
    argument: &str,
    supervisor: &ProcessSupervisor,
) -> Result<Vec<u8>, CandidateFailure> {
    let executable = bound_execution_path(executable_file, executable)?;
    let root = bound_execution_path(root_file, root)?;
    let output = supervisor
        .run_bounded(ProcessSpec {
            executable,
            args: vec![OsString::from(argument)],
            current_dir: root,
            environment: BTreeMap::new(),
            stdin: StdinPolicy::Null,
            stdout: StdoutPolicy::Capture {
                byte_limit: IDENTITY_STDOUT_LIMIT,
            },
            stderr_byte_limit: IDENTITY_STDERR_LIMIT,
            wall_deadline: IDENTITY_COMMAND_DEADLINE,
        })
        .await
        .map_err(|error| match error.code() {
            ProcessErrorCode::DeadlineExceeded => CandidateFailure::Deadline,
            _ => CandidateFailure::Probe,
        })?;
    if !output.status.success() {
        return Err(CandidateFailure::Probe);
    }
    Ok(output.stdout)
}

fn parse_version<'a>(output: &'a [u8], role: &str) -> Result<&'a str, CandidateFailure> {
    let output = std::str::from_utf8(output).map_err(|_| CandidateFailure::Incompatible)?;
    let first_line = output
        .lines()
        .next()
        .ok_or(CandidateFailure::Incompatible)?;
    let prefix = format!("{role} version ");
    let token = first_line
        .strip_prefix(&prefix)
        .and_then(|rest| rest.split_ascii_whitespace().next())
        .ok_or(CandidateFailure::Incompatible)?;
    if token.is_empty() {
        return Err(CandidateFailure::Incompatible);
    }
    Ok(token)
}

fn build_configuration(output: &[u8]) -> Result<Vec<u8>, CandidateFailure> {
    let output = std::str::from_utf8(output).map_err(|_| CandidateFailure::Incompatible)?;
    let mut lines = output.lines();
    let header_remainder = loop {
        let line = lines.next().ok_or(CandidateFailure::Incompatible)?;
        if let Some(remainder) = line.trim_start().strip_prefix("configuration:") {
            break remainder.trim();
        }
    };
    let mut options = Vec::new();
    if !header_remainder.is_empty() {
        options.push(header_remainder);
    }
    for line in lines {
        let line = line.trim();
        if line.starts_with("--") {
            options.push(line);
        } else if !line.is_empty() {
            break;
        }
    }
    if options.is_empty() {
        return Err(CandidateFailure::Incompatible);
    }
    Ok(options.join("\n").into_bytes())
}

fn canonical_local_root(root: &Path) -> Result<PathBuf, CandidateFailure> {
    if !root.is_absolute() || is_remote_or_device_path(root) {
        return Err(CandidateFailure::Unsafe);
    }
    let metadata = fs::symlink_metadata(root).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => CandidateFailure::Missing,
        _ => CandidateFailure::Unsafe,
    })?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(CandidateFailure::Unsafe);
    }
    let canonical = fs::canonicalize(root).map_err(|_| CandidateFailure::Unsafe)?;
    let canonical = normalize_canonical_path(canonical);
    if is_remote_or_device_path(&canonical) {
        return Err(CandidateFailure::Unsafe);
    }
    Ok(canonical)
}

fn executable_name(role: &str) -> &str {
    match (role, std::env::consts::EXE_SUFFIX) {
        ("ffmpeg", ".exe") => "ffmpeg.exe",
        ("ffprobe", ".exe") => "ffprobe.exe",
        ("ffmpeg", _) => "ffmpeg",
        ("ffprobe", _) => "ffprobe",
        _ => unreachable!(),
    }
}

fn is_remote_or_device_path(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let value = path.as_os_str().to_string_lossy().replace('/', "\\");
        value.starts_with("\\\\")
            || value.starts_with("\\??\\")
            || value.starts_with("\\.\\")
            || value.starts_with("\\?\\")
            || windows_drive_is_remote(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

#[cfg(windows)]
fn windows_drive_is_remote(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::{Win32::Storage::FileSystem::GetDriveTypeW, core::PCWSTR};

    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.len() < 2 || units[1] != b':' as u16 {
        return false;
    }
    let root = [units[0], b':' as u16, b'\\' as u16, 0];
    drive_type_is_remote(unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) })
}

#[cfg(windows)]
fn drive_type_is_remote(drive_type: u32) -> bool {
    const DRIVE_REMOTE: u32 = 4;
    drive_type == DRIVE_REMOTE
}

fn normalize_canonical_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let value = path.as_os_str().to_string_lossy();
        if let Some(local) = value.strip_prefix(r"\\?\")
            && !local.starts_with("UNC\\")
        {
            return PathBuf::from(local);
        }
    }
    path
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy)]
enum FdNamespace {
    ProcSelf,
    Unsupported,
}

#[cfg_attr(not(test), allow(dead_code))]
fn render_fd_path(namespace: FdNamespace, descriptor: i32) -> Option<PathBuf> {
    if descriptor < 0 {
        return None;
    }
    match namespace {
        FdNamespace::ProcSelf => Some(PathBuf::from(format!("/proc/self/fd/{descriptor}"))),
        FdNamespace::Unsupported => None,
    }
}

fn bound_execution_path(file: &File, canonical_path: &Path) -> Result<PathBuf, CandidateFailure> {
    #[cfg(windows)]
    {
        let _ = file;
        Ok(canonical_path.to_path_buf())
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = canonical_path;
        render_fd_path(FdNamespace::ProcSelf, file.as_raw_fd()).ok_or(CandidateFailure::Probe)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let _ = (file, canonical_path);
        render_fd_path(FdNamespace::Unsupported, -1).ok_or(CandidateFailure::Probe)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (file, canonical_path);
        Err(CandidateFailure::Probe)
    }
}

async fn open_pair_lease(root: PathBuf, mode: OpenMode) -> Result<OpenedPair, CandidateFailure> {
    static HASH_ADMISSION: OnceLock<Arc<Semaphore>> = OnceLock::new();
    let _hash_permit = match mode {
        OpenMode::Full => Some(
            HASH_ADMISSION
                .get_or_init(|| Arc::new(Semaphore::new(1)))
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CandidateFailure::Unsafe)?,
        ),
        OpenMode::MetadataOnly { .. } => None,
    };
    tokio::task::spawn_blocking(move || {
        let _hash_permit = _hash_permit;
        open_pair_lease_blocking(&root, mode)
    })
    .await
    .map_err(|_| CandidateFailure::Unsafe)?
}

fn open_pair_lease_blocking(root: &Path, mode: OpenMode) -> Result<OpenedPair, CandidateFailure> {
    open_pair_lease_blocking_with_hook(root, mode, || {})
}

fn open_pair_lease_blocking_with_hook(
    root: &Path,
    mode: OpenMode,
    after_root_opened: impl FnOnce(),
) -> Result<OpenedPair, CandidateFailure> {
    #[cfg(target_os = "linux")]
    let root_file = open_local_root(root)?;
    #[cfg(target_os = "linux")]
    let root = final_linux_handle_path(&root_file)?;
    #[cfg(not(target_os = "linux"))]
    let root = canonical_local_root(root)?;
    #[cfg(not(target_os = "linux"))]
    let root_file = open_local_root(&root)?;
    let root_metadata = root_file.metadata().map_err(|_| CandidateFailure::Unsafe)?;
    if !root_metadata.is_dir() || opened_handle_is_reparse(&root_file)? {
        return Err(CandidateFailure::Unsafe);
    }
    #[cfg(windows)]
    {
        let final_root = final_windows_handle_path(&root_file)?;
        if !paths_equal(&final_root, &root) || windows_drive_is_remote(&final_root) {
            return Err(CandidateFailure::Unsafe);
        }
    }
    #[cfg(target_os = "linux")]
    if !linux_file_is_local(&root_file)? {
        return Err(CandidateFailure::Unsafe);
    }
    after_root_opened();
    let root_identity = file_identity(&root_file, &root_metadata)?;
    let ffmpeg = root.join(executable_name("ffmpeg"));
    let ffprobe = root.join(executable_name("ffprobe"));
    let ffmpeg_file = Arc::new(open_local_file_at(
        &root_file,
        &root,
        executable_name("ffmpeg"),
    )?);
    let ffprobe_file = Arc::new(open_local_file_at(
        &root_file,
        &root,
        executable_name("ffprobe"),
    )?);
    validate_opened_child(&ffmpeg_file, &ffmpeg, &root)?;
    validate_opened_child(&ffprobe_file, &ffprobe, &root)?;
    let (ffmpeg_seal, ffprobe_seal) = match mode {
        OpenMode::Full => (
            seal_open_file(&ffmpeg_file)?,
            seal_open_file(&ffprobe_file)?,
        ),
        OpenMode::MetadataOnly {
            ffmpeg_digest,
            ffprobe_digest,
        } => (
            metadata_seal_open_file(&ffmpeg_file, ffmpeg_digest)?,
            metadata_seal_open_file(&ffprobe_file, ffprobe_digest)?,
        ),
    };
    Ok(OpenedPair {
        root: root.clone(),
        ffmpeg,
        ffprobe,
        lease: RuntimeLease {
            root,
            _root_file: Arc::new(root_file),
            root_identity,
            ffmpeg: FileLease {
                file: ffmpeg_file,
                seal: ffmpeg_seal,
            },
            ffprobe: FileLease {
                file: ffprobe_file,
                seal: ffprobe_seal,
            },
        },
    })
}

fn open_local_file_at(root_file: &File, root: &Path, name: &str) -> Result<File, CandidateFailure> {
    #[cfg(windows)]
    {
        use std::os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle},
        };
        use windows::{
            Wdk::{
                Foundation::OBJECT_ATTRIBUTES,
                Storage::FileSystem::{
                    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
                    FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
                },
            },
            Win32::{
                Foundation::{
                    HANDLE, OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_NOT_FOUND,
                    STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
                },
                Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ},
                System::IO::IO_STATUS_BLOCK,
            },
            core::PWSTR,
        };

        let _ = root;
        if name.is_empty()
            || Path::new(name).components().count() != 1
            || Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name)
        {
            return Err(CandidateFailure::Unsafe);
        }
        let mut wide_name = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
        let byte_length = wide_name
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|length| u16::try_from(length).ok())
            .ok_or(CandidateFailure::Unsafe)?;
        let object_name = UNICODE_STRING {
            Length: byte_length,
            MaximumLength: byte_length,
            Buffer: PWSTR(wide_name.as_mut_ptr()),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
                .map_err(|_| CandidateFailure::Unsafe)?,
            RootDirectory: HANDLE(root_file.as_raw_handle()),
            ObjectName: &raw const object_name,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle = HANDLE::default();
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = unsafe {
            NtCreateFile(
                &raw mut handle,
                FILE_GENERIC_READ,
                &raw const object_attributes,
                &raw mut io_status,
                None,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                None,
                0,
            )
        };
        if status.0 < 0 {
            return Err(
                if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND
                {
                    CandidateFailure::Missing
                } else {
                    CandidateFailure::Unsafe
                },
            );
        }
        Ok(unsafe { File::from_raw_handle(handle.0) })
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = root;
        return linux_openat2(
            root_file.as_raw_fd(),
            std::ffi::OsStr::new(name),
            libc::O_RDONLY | libc::O_CLOEXEC,
            LINUX_RESOLVE_BENEATH | LINUX_RESOLVE_NO_MAGICLINKS | LINUX_RESOLVE_NO_SYMLINKS,
        );
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    let path = root.join(name);
    #[cfg(not(any(windows, target_os = "linux")))]
    let mut options = fs::OpenOptions::new();
    #[cfg(not(any(windows, target_os = "linux")))]
    options.read(true);
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let _ = (root_file, path);
        return Err(CandidateFailure::Unsafe);
    }
    #[cfg(not(any(windows, unix)))]
    let _ = root_file;
    #[cfg(not(any(windows, target_os = "linux")))]
    options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CandidateFailure::Missing
        } else {
            CandidateFailure::Unsafe
        }
    })
}

fn open_local_root(path: &Path) -> Result<File, CandidateFailure> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        if !path.is_absolute() {
            return Err(CandidateFailure::Unsafe);
        }
        let relative = path
            .strip_prefix(Path::new("/"))
            .map_err(|_| CandidateFailure::Unsafe)?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(CandidateFailure::Unsafe);
        }
        let filesystem_root = File::open("/").map_err(|_| CandidateFailure::Unsafe)?;
        return linux_openat2(
            filesystem_root.as_raw_fd(),
            relative.as_os_str(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            LINUX_RESOLVE_BENEATH | LINUX_RESOLVE_NO_MAGICLINKS | LINUX_RESOLVE_NO_SYMLINKS,
        );
    }
    #[cfg(not(target_os = "linux"))]
    let mut options = fs::OpenOptions::new();
    #[cfg(not(target_os = "linux"))]
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0);
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(not(target_os = "linux"))]
    options.open(path).map_err(|_| CandidateFailure::Unsafe)
}

#[cfg(target_os = "linux")]
const LINUX_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(target_os = "linux")]
const LINUX_RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const LINUX_RESOLVE_BENEATH: u64 = 0x08;

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn linux_openat2(
    directory: std::os::fd::RawFd,
    path: &std::ffi::OsStr,
    flags: i32,
    resolve: u64,
) -> Result<File, CandidateFailure> {
    use std::{
        ffi::CString,
        os::{fd::FromRawFd, unix::ffi::OsStrExt},
    };

    let path = CString::new(path.as_bytes()).map_err(|_| CandidateFailure::Unsafe)?;
    let how = LinuxOpenHow {
        flags: flags as u64,
        mode: 0,
        resolve,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<LinuxOpenHow>(),
        ) as i32
    };
    if descriptor < 0 {
        return Err(
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                CandidateFailure::Missing
            } else {
                CandidateFailure::Unsafe
            },
        );
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn final_linux_handle_path(file: &File) -> Result<PathBuf, CandidateFailure> {
    use std::os::fd::AsRawFd;

    let path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| CandidateFailure::Unsafe)?;
    if !path.is_absolute() || path.as_os_str().to_string_lossy().ends_with(" (deleted)") {
        return Err(CandidateFailure::Unsafe);
    }
    Ok(path)
}

fn opened_handle_is_reparse(file: &File) -> Result<bool, CandidateFailure> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        unsafe {
            GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
                .map_err(|_| CandidateFailure::Unsafe)?;
        }
        Ok(information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(false)
    }
}

fn validate_opened_child(
    file: &File,
    expected: &Path,
    root: &Path,
) -> Result<(), CandidateFailure> {
    if !file
        .metadata()
        .map_err(|_| CandidateFailure::Unsafe)?
        .is_file()
        || opened_handle_is_reparse(file)?
    {
        return Err(CandidateFailure::Unsafe);
    }
    #[cfg(windows)]
    {
        let final_path = final_windows_handle_path(file)?;
        if !paths_equal(&final_path, expected) || final_path.parent() != Some(root) {
            return Err(CandidateFailure::Unsafe);
        }
    }
    #[cfg(not(windows))]
    let _ = (expected, root);
    Ok(())
}

#[cfg(windows)]
fn final_windows_handle_path(file: &File) -> Result<PathBuf, CandidateFailure> {
    use std::{
        ffi::OsString,
        os::windows::{ffi::OsStringExt, io::AsRawHandle},
    };
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW},
    };

    let mut buffer = vec![0_u16; 512];
    loop {
        let count = unsafe {
            GetFinalPathNameByHandleW(
                HANDLE(file.as_raw_handle()),
                &mut buffer,
                FILE_NAME_NORMALIZED,
            )
        } as usize;
        if count == 0 {
            return Err(CandidateFailure::Unsafe);
        }
        if count < buffer.len() {
            buffer.truncate(count);
            return Ok(normalize_canonical_path(PathBuf::from(
                OsString::from_wide(&buffer),
            )));
        }
        buffer.resize(count + 1, 0);
    }
}

#[cfg(target_os = "linux")]
fn linux_file_is_local(file: &File) -> Result<bool, CandidateFailure> {
    use std::os::fd::AsRawFd;
    let mut statistics = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(CandidateFailure::Unsafe);
    }
    let statistics = unsafe { statistics.assume_init() };
    Ok(linux_filesystem_type_is_allowed_local(
        statistics.f_type as i64,
    ))
}

#[cfg(any(test, target_os = "linux"))]
fn linux_filesystem_type_is_allowed_local(filesystem_type: i64) -> bool {
    matches!(
        filesystem_type as u64,
        0x0000_ef53 // ext2/ext3/ext4
            | 0x5846_5342 // XFS
            | 0x9123_683e // Btrfs
            | 0x0102_1994 // tmpfs
            | 0x8584_58f6 // ramfs
            | 0x794c_7630 // overlayfs
            | 0x2fc1_2fc1 // ZFS
            | 0xf2f5_2010 // F2FS
            | 0x3153_464a // JFS
            | 0x5265_4973 // ReiserFS
            | 0x0000_3434 // NILFS
            | 0x1501_3346 // UDF
            | 0x0000_4d44 // FAT
            | 0x2011_bab0 // exFAT
            | 0x5346_544e // NTFS/NTFS3
            | 0x6175_6673 // aufs
    )
}

fn seal_open_file(file: &File) -> Result<FileSeal, CandidateFailure> {
    let metadata_before = file.metadata().map_err(|_| CandidateFailure::Unsafe)?;
    if !metadata_before.is_file() || metadata_before.len() > MAX_EXECUTABLE_BYTES {
        return Err(CandidateFailure::Unsafe);
    }
    #[cfg(test)]
    let _observation = HashObservation::start();
    #[cfg(test)]
    while HASH_PAUSED.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(1));
    }
    let expires = Instant::now() + HASH_DEADLINE;
    let identity = file_identity(file, &metadata_before)?;
    let mut reader = file.try_clone().map_err(|_| CandidateFailure::Unsafe)?;
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|_| CandidateFailure::Unsafe)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        if Instant::now() >= expires {
            return Err(CandidateFailure::Deadline);
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|_| CandidateFailure::Unsafe)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let metadata_after = file.metadata().map_err(|_| CandidateFailure::Unsafe)?;
    if metadata_before.len() != metadata_after.len()
        || metadata_before.modified().ok() != metadata_after.modified().ok()
        || identity != file_identity(file, &metadata_after)?
    {
        return Err(CandidateFailure::Unsafe);
    }
    Ok(FileSeal {
        length: metadata_after.len(),
        modified: metadata_after.modified().ok(),
        digest: hasher.finalize().into(),
        identity,
    })
}

#[cfg(test)]
struct HashObservation;

#[cfg(test)]
impl HashObservation {
    fn start() -> Self {
        HASH_TOTAL.fetch_add(1, Ordering::AcqRel);
        let active = HASH_ACTIVE.fetch_add(1, Ordering::AcqRel) + 1;
        HASH_MAX_ACTIVE.fetch_max(active, Ordering::AcqRel);
        Self
    }
}

#[cfg(test)]
impl Drop for HashObservation {
    fn drop(&mut self) {
        HASH_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
fn reset_hash_observation() {
    HASH_ACTIVE.store(0, Ordering::Release);
    HASH_MAX_ACTIVE.store(0, Ordering::Release);
    HASH_TOTAL.store(0, Ordering::Release);
}

#[cfg(test)]
fn set_hash_pause(paused: bool) {
    HASH_PAUSED.store(paused, Ordering::Release);
}

#[cfg(test)]
fn snapshot_hash_observation() -> (usize, usize) {
    (
        HASH_TOTAL.load(Ordering::Acquire),
        HASH_MAX_ACTIVE.load(Ordering::Acquire),
    )
}

fn metadata_seal_open_file(file: &File, digest: [u8; 32]) -> Result<FileSeal, CandidateFailure> {
    let metadata = file.metadata().map_err(|_| CandidateFailure::Unsafe)?;
    if !metadata.is_file() || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(CandidateFailure::Unsafe);
    }
    Ok(FileSeal {
        length: metadata.len(),
        modified: metadata.modified().ok(),
        digest,
        identity: file_identity(file, &metadata)?,
    })
}

fn file_identity(file: &File, metadata: &fs::Metadata) -> Result<FileIdentity, CandidateFailure> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        let _ = metadata;
        unsafe {
            GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
                .map_err(|_| CandidateFailure::Unsafe)?;
        }
        Ok(FileIdentity {
            volume: information.dwVolumeSerialNumber as u64,
            file: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = file;
        Ok(FileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (file, metadata);
        Err(CandidateFailure::Unsafe)
    }
}

fn pair_install_digest(ffmpeg: &FileSeal, ffprobe: &FileSeal) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ffmpeg\0");
    hasher.update(ffmpeg.digest);
    hasher.update(b"ffprobe\0");
    hasher.update(ffprobe.digest);
    hex::encode(hasher.finalize())
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_os_str(value: &OsStr) -> String {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut bytes = Vec::new();
        for unit in value.encode_wide() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        digest_bytes(&bytes)
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        digest_bytes(value.as_bytes())
    }
    #[cfg(not(any(windows, unix)))]
    {
        digest_bytes(value.to_string_lossy().as_bytes())
    }
}

fn pair_root_identity(root: &Path, identity: FileIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update(digest_os_str(root.as_os_str()).as_bytes());
    hasher.update(identity.volume.to_le_bytes());
    hasher.update(identity.file.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn known_system_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        vec![
            PathBuf::from(r"C:\Program Files\Jellyfin\Server"),
            PathBuf::from(r"C:\Program Files\Jellyfin\Server\ffmpeg"),
            PathBuf::from(r"C:\Program Files\Jellyfin\Server\bin"),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/lib/jellyfin-ffmpeg"),
            PathBuf::from("/usr/local/lib/jellyfin-ffmpeg"),
            PathBuf::from("/opt/jellyfin-ffmpeg"),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from(
            "/Applications/Jellyfin Server.app/Contents/MacOS",
        )]
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateFailure, FdNamespace, MAX_EXECUTABLE_BYTES, OpenMode, open_pair_lease,
        render_fd_path, reset_hash_observation, set_hash_pause, snapshot_hash_observation,
    };
    use std::{fs, path::PathBuf, time::Duration};

    #[cfg(windows)]
    #[test]
    fn mapped_remote_drive_type_is_rejected_by_local_path_policy() {
        assert!(super::drive_type_is_remote(4));
        assert!(!super::drive_type_is_remote(3));
    }

    #[test]
    fn linux_local_filesystem_policy_rejects_fuse_distributed_and_unknown_types() {
        for filesystem_type in [0xef53, 0x5846_5342, 0x9123_683e, 0x0102_1994] {
            assert!(super::linux_filesystem_type_is_allowed_local(
                filesystem_type
            ));
        }
        for filesystem_type in [
            0x6573_5546, // FUSE, including sshfs and GlusterFS clients
            0x0bd0_0bd0, // Lustre
            0x4750_4653, // GPFS
            0x6969,      // NFS
            0x1357_9bdf, // unknown
        ] {
            assert!(!super::linux_filesystem_type_is_allowed_local(
                filesystem_type
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_root_open_rejects_a_symlinked_ancestor_component() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("linux ancestor root");
        let real_namespace = directory.path().join("real-namespace");
        let real_root = real_namespace.join("approved");
        let linked_namespace = directory.path().join("linked-namespace");
        fs::create_dir_all(&real_root).expect("create real root");
        symlink(&real_namespace, &linked_namespace).expect("link ancestor namespace");
        for role in ["ffmpeg", "ffprobe"] {
            fs::copy(
                std::env::current_exe().expect("test executable"),
                real_root.join(role),
            )
            .expect("copy executable");
        }

        let error =
            super::open_pair_lease_blocking(&linked_namespace.join("approved"), OpenMode::Full)
                .expect_err("openat2 must reject symlinked ancestor traversal");

        assert!(matches!(error, CandidateFailure::Unsafe));
    }

    #[cfg(windows)]
    #[test]
    fn child_swapped_to_out_of_root_link_after_root_open_fails_closed() {
        let directory = tempfile::tempdir().expect("open-race root");
        let root = directory.path().join("approved");
        let outside = directory.path().join("outside.exe");
        fs::create_dir(&root).expect("create approved root");
        fs::copy(std::env::current_exe().expect("test executable"), &outside)
            .expect("copy outside executable");
        for role in ["ffmpeg", "ffprobe"] {
            fs::copy(
                &outside,
                root.join(format!("{role}{}", std::env::consts::EXE_SUFFIX)),
            )
            .expect("copy approved executable");
        }
        let ffmpeg = root.join("ffmpeg.exe");

        let error = super::open_pair_lease_blocking_with_hook(&root, OpenMode::Full, || {
            fs::remove_file(&ffmpeg).expect("remove validated child");
            std::os::windows::fs::symlink_file(&outside, &ffmpeg)
                .expect("swap child to outside link");
        })
        .expect_err("root-relative no-follow open must reject swapped link");

        assert!(matches!(error, CandidateFailure::Unsafe));
    }

    #[cfg(windows)]
    #[test]
    fn ancestor_namespace_swap_cannot_redirect_children_away_from_the_opened_root() {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let directory = tempfile::tempdir().expect("ancestor-swap root");
        let namespace = directory.path().join("namespace");
        let root = namespace.join("approved");
        let moved_root = namespace.join("moved-approved");
        fs::create_dir_all(&root).expect("create approved root");
        fs::write(root.join("ffmpeg.exe"), b"original-root")
            .expect("write original executable marker");

        let held_root = fs::OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(&root)
            .expect("open rename-permissive root handle");
        fs::rename(&root, &moved_root).expect("move the approved root");
        fs::create_dir(&root).expect("replace the approved root");
        fs::write(root.join("ffmpeg.exe"), b"replacement-root")
            .expect("write replacement executable marker");

        let mut opened = super::open_local_file_at(&held_root, &root, "ffmpeg.exe")
            .expect("open child through the held root handle");
        let mut contents = String::new();
        opened
            .read_to_string(&mut contents)
            .expect("read opened child marker");

        assert_eq!(contents, "original-root");
    }

    #[tokio::test]
    async fn verification_hashing_is_single_flight_and_metadata_reopens_do_not_rehash() {
        let directory = tempfile::tempdir().expect("hash test root");
        for role in ["ffmpeg", "ffprobe"] {
            fs::copy(
                std::env::current_exe().expect("test executable"),
                directory
                    .path()
                    .join(format!("{role}{}", std::env::consts::EXE_SUFFIX)),
            )
            .expect("copy hash input");
        }
        reset_hash_observation();
        let (first, second) = tokio::join!(
            open_pair_lease(directory.path().to_path_buf(), OpenMode::Full),
            open_pair_lease(directory.path().to_path_buf(), OpenMode::Full),
        );
        let first = first.expect("first full verification");
        second.expect("second full verification");
        assert_eq!(snapshot_hash_observation(), (4, 1));

        open_pair_lease(
            directory.path().to_path_buf(),
            OpenMode::MetadataOnly {
                ffmpeg_digest: first.lease.ffmpeg.seal.digest,
                ffprobe_digest: first.lease.ffprobe.seal.digest,
            },
        )
        .await
        .expect("metadata-only command-boundary reopen");
        assert_eq!(
            snapshot_hash_observation(),
            (4, 1),
            "metadata-only command validation unexpectedly started hash work"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_hash_future_keeps_admission_until_blocking_hash_finishes() {
        let directory = tempfile::tempdir().expect("cancelled hash root");
        for role in ["ffmpeg", "ffprobe"] {
            fs::copy(
                std::env::current_exe().expect("test executable"),
                directory
                    .path()
                    .join(format!("{role}{}", std::env::consts::EXE_SUFFIX)),
            )
            .expect("copy hash input");
        }
        reset_hash_observation();
        set_hash_pause(true);
        let first = tokio::spawn(open_pair_lease(
            directory.path().to_path_buf(),
            OpenMode::Full,
        ));
        while snapshot_hash_observation().0 == 0 {
            tokio::task::yield_now().await;
        }
        first.abort();
        assert!(
            first
                .await
                .expect_err("first hash future aborted")
                .is_cancelled()
        );
        let second = tokio::spawn(open_pair_lease(
            directory.path().to_path_buf(),
            OpenMode::Full,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            snapshot_hash_observation().0,
            1,
            "aborted future released admission while blocking hash was still alive"
        );

        set_hash_pause(false);
        second
            .await
            .expect("join second hash")
            .expect("second hash after retained admission");
        assert_eq!(snapshot_hash_observation(), (4, 1));
    }

    #[tokio::test]
    async fn many_sessions_hash_only_the_required_first_session() {
        use super::{FfmpegRuntime, RuntimeConfig, RuntimeId, RuntimeKind, TranscodingService};
        use crate::transcoding::process::ProcessSupervisor;
        use std::sync::{Arc, atomic::AtomicBool};
        use tokio_util::sync::CancellationToken;

        let directory = tempfile::tempdir().expect("session hash root");
        for role in ["ffmpeg", "ffprobe"] {
            fs::copy(
                std::env::current_exe().expect("test executable"),
                directory
                    .path()
                    .join(format!("{role}{}", std::env::consts::EXE_SUFFIX)),
            )
            .expect("copy hash input");
        }
        let opened = open_pair_lease(directory.path().to_path_buf(), OpenMode::Full)
            .await
            .expect("initial resolution seal");
        let runtime = Arc::new(FfmpegRuntime {
            id: RuntimeId {
                install_digest: "test-install".into(),
                ffmpeg_version: "7.1.4".into(),
                jellyfin_revision: None,
                build_configuration_digest: "test-build".into(),
                pair_root_identity: "test-root".into(),
            },
            ffmpeg: opened.ffmpeg,
            ffprobe: opened.ffprobe,
            kind: RuntimeKind::SoftwareCompatible,
            lease: Arc::new(opened.lease),
            first_session_verified: AtomicBool::new(false),
        });
        let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
        let service = TranscodingService::resolved(RuntimeConfig::isolated(), supervisor, runtime);
        reset_hash_observation();

        for _ in 0..16 {
            service
                .runtime_for_session()
                .await
                .expect("verified session");
        }

        assert_eq!(
            snapshot_hash_observation(),
            (2, 1),
            "sessions after the first integrity check must use metadata identity seals"
        );
    }

    #[tokio::test]
    async fn oversized_executable_is_rejected_before_hash_work_starts() {
        let directory = tempfile::tempdir().expect("oversized test root");
        for role in ["ffmpeg", "ffprobe"] {
            let file = fs::File::create(
                directory
                    .path()
                    .join(format!("{role}{}", std::env::consts::EXE_SUFFIX)),
            )
            .expect("create sparse executable");
            file.set_len(MAX_EXECUTABLE_BYTES + 1)
                .expect("size sparse executable");
        }
        reset_hash_observation();

        let error = open_pair_lease(directory.path().to_path_buf(), OpenMode::Full)
            .await
            .expect_err("oversized executable must fail closed");

        assert!(matches!(error, CandidateFailure::Unsafe));
        assert_eq!(snapshot_hash_observation(), (0, 0));
    }

    #[test]
    fn fd_bound_command_paths_are_absolute_and_platform_namespaced() {
        assert_eq!(
            render_fd_path(FdNamespace::ProcSelf, 42),
            Some(PathBuf::from("/proc/self/fd/42"))
        );
        assert_eq!(render_fd_path(FdNamespace::Unsupported, 42), None);
        assert_eq!(render_fd_path(FdNamespace::ProcSelf, -1), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "spawned by linux_fd_bound_execution_uses_the_opened_inode"]
    fn fd_bound_execution_helper() {}

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_fd_bound_execution_uses_the_opened_inode() {
        use super::{bound_execution_path, open_local_root};
        use crate::transcoding::process::{
            ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy,
        };
        use std::{collections::BTreeMap, ffi::OsString, fs, time::Duration};
        use tokio_util::sync::CancellationToken;

        let directory = tempfile::tempdir().expect("fd execution directory");
        let executable = directory.path().join("runtime");
        fs::copy(
            std::env::current_exe().expect("test executable"),
            &executable,
        )
        .expect("copy executable");
        let opened = fs::File::open(&executable).expect("open executable inode");
        let opened_root = open_local_root(directory.path()).expect("open execution root");
        fs::rename(&executable, directory.path().join("original")).expect("rename open inode");
        fs::write(&executable, b"replacement is not executable").expect("replace pathname");

        let output = ProcessSupervisor::new(CancellationToken::new())
            .run_bounded(ProcessSpec {
                executable: bound_execution_path(&opened, &executable).expect("fd executable"),
                args: vec![
                    OsString::from("--ignored"),
                    OsString::from("--exact"),
                    OsString::from("transcoding::runtime::tests::fd_bound_execution_helper"),
                ],
                current_dir: bound_execution_path(&opened_root, directory.path()).expect("fd root"),
                environment: BTreeMap::new(),
                stdin: StdinPolicy::Null,
                stdout: StdoutPolicy::Null,
                stderr_byte_limit: 8_192,
                wall_deadline: Duration::from_secs(2),
            })
            .await
            .expect("execute opened inode rather than replacement path");

        assert!(output.status.success());
    }
}

#[cfg(test)]
#[path = "integration_tests.rs"]
mod integration_tests;
