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
    sync::Arc,
    time::{Duration, SystemTime},
};

const IDENTITY_COMMAND_DEADLINE: Duration = Duration::from_secs(10);
const IDENTITY_STDOUT_LIMIT: usize = 128 * 1024;
const IDENTITY_STDERR_LIMIT: usize = 32 * 1024;
const SUPPORTED_FFMPEG_VERSION: &str = "7.1.4";
const SUPPORTED_JELLYFIN_MATCHER: &str = "7.1.4-Jellyfin";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeExecutable {
    Ffmpeg,
    Ffprobe,
}

#[derive(Clone, Debug)]
pub struct RuntimeCommand {
    pub args: Vec<OsString>,
    pub stdout: StdoutPolicy,
    pub stderr_byte_limit: usize,
    pub wall_deadline: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeCommandError {
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

    pub fn executable_path(&self, executable: RuntimeExecutable) -> &Path {
        match executable {
            RuntimeExecutable::Ffmpeg => &self.runtime.ffmpeg,
            RuntimeExecutable::Ffprobe => &self.runtime.ffprobe,
        }
    }

    pub async fn run_bounded(
        &self,
        executable: RuntimeExecutable,
        command: RuntimeCommand,
    ) -> Result<BoundedOutput, RuntimeCommandError> {
        let execution_lease = open_pair_lease(self.runtime.lease.root.clone())
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

    pub fn supervisor(&self) -> &Arc<ProcessSupervisor> {
        &self.supervisor
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
        if verify_unchanged(runtime).await.is_ok() {
            return Ok(VerifiedRuntimeSession {
                runtime: runtime.clone(),
                supervisor: self.supervisor.clone(),
            });
        }
        let replacement = resolve_runtime(config, &self.supervisor).await?;
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
}

impl FfmpegRuntime {
    pub fn id(&self) -> &RuntimeId {
        &self.id
    }

    pub fn kind(&self) -> RuntimeKind {
        self.kind
    }

    pub fn pair_root(&self) -> &Path {
        &self.lease.root
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

struct OpenedPair {
    root: PathBuf,
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
    lease: RuntimeLease,
}

enum CandidateFailure {
    Missing,
    Unsafe,
    Probe,
    Deadline,
    Incompatible,
}

#[derive(Clone, Copy)]
enum CandidateSource {
    ManagedManifest,
    SystemPackage,
    SearchPath,
}

pub async fn resolve_runtime(
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
        candidates.push((root.clone(), CandidateSource::ManagedManifest));
    }
    candidates.extend(
        config
            .system_roots
            .iter()
            .cloned()
            .map(|root| (root, CandidateSource::SystemPackage)),
    );
    if let Some(search_path) = &config.search_path {
        candidates.extend(
            std::env::split_paths(search_path)
                .filter(|root| root.is_absolute() && !is_remote_or_device_path(root))
                .map(|root| (root, CandidateSource::SearchPath)),
        );
    }

    let mut seen = Vec::<PathBuf>::new();
    let mut degraded = None;
    if let Some(root) = &config.explicit_root {
        let canonical_key = canonical_local_root(root).map_err(candidate_failure_error)?;
        seen.push(canonical_key);
        match probe_pair(
            root,
            required_version,
            ffmpeg_jellyfin_matcher,
            ffprobe_jellyfin_matcher,
            supervisor,
        )
        .await
        .map_err(candidate_failure_error)?
        {
            pair if pair.jellyfin => {
                return Ok(Arc::new(
                    pair.into_runtime(RuntimeKind::SoftwareCompatible, None),
                ));
            }
            pair => retain_best_software_candidate(&mut degraded, pair),
        }
    }
    let mut saw_deadline = false;
    let mut saw_probe_failure = false;
    let mut saw_incompatible = false;
    for (root, source) in candidates {
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
            Ok(pair)
                if pair.jellyfin
                    && matches!(source, CandidateSource::ManagedManifest)
                    && host_artifact.is_some() =>
            {
                return Ok(Arc::new(pair.into_runtime(
                    RuntimeKind::Jellyfin,
                    host_artifact.map(|artifact| artifact.jellyfin_revision()),
                )));
            }
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
    let opened = open_pair_lease(runtime.lease.root.clone())
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
    let opened = open_pair_lease(root.to_path_buf()).await?;
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
    let ffmpeg_after = seal_open_file(&lease.ffmpeg.file)?;
    let ffprobe_after = seal_open_file(&lease.ffprobe.file)?;
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

fn validate_pair_paths(root: &Path) -> Result<(PathBuf, PathBuf, PathBuf), CandidateFailure> {
    let root = canonical_local_root(root)?;
    let ffmpeg = validate_executable(&root, executable_name("ffmpeg"))?;
    let ffprobe = validate_executable(&root, executable_name("ffprobe"))?;
    if ffmpeg.parent() != Some(root.as_path()) || ffprobe.parent() != Some(root.as_path()) {
        return Err(CandidateFailure::Unsafe);
    }
    Ok((root, ffmpeg, ffprobe))
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

fn validate_executable(root: &Path, name: &str) -> Result<PathBuf, CandidateFailure> {
    let path = root.join(name);
    let metadata = fs::symlink_metadata(&path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => CandidateFailure::Missing,
        _ => CandidateFailure::Unsafe,
    })?;
    if !metadata.is_file() || is_link_or_reparse(&metadata) {
        return Err(CandidateFailure::Unsafe);
    }
    let canonical =
        normalize_canonical_path(fs::canonicalize(&path).map_err(|_| CandidateFailure::Unsafe)?);
    if canonical.parent() != Some(root) {
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
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
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

async fn open_pair_lease(root: PathBuf) -> Result<OpenedPair, CandidateFailure> {
    tokio::task::spawn_blocking(move || open_pair_lease_blocking(&root))
        .await
        .map_err(|_| CandidateFailure::Unsafe)?
}

fn open_pair_lease_blocking(root: &Path) -> Result<OpenedPair, CandidateFailure> {
    let (root, ffmpeg, ffprobe) = validate_pair_paths(root)?;
    let root_file = open_local_root(&root)?;
    let root_metadata = root_file.metadata().map_err(|_| CandidateFailure::Unsafe)?;
    if !root_metadata.is_dir() {
        return Err(CandidateFailure::Unsafe);
    }
    let root_identity = file_identity(&root_file, &root_metadata)?;
    let ffmpeg_file = Arc::new(open_local_file(&ffmpeg)?);
    let ffprobe_file = Arc::new(open_local_file(&ffprobe)?);
    let ffmpeg_seal = seal_open_file(&ffmpeg_file)?;
    let ffprobe_seal = seal_open_file(&ffprobe_file)?;
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

fn open_local_file(path: &Path) -> Result<File, CandidateFailure> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
        options.share_mode(FILE_SHARE_READ.0);
    }
    options.open(path).map_err(|_| CandidateFailure::Unsafe)
}

fn open_local_root(path: &Path) -> Result<File, CandidateFailure> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ};
        options
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0);
    }
    options.open(path).map_err(|_| CandidateFailure::Unsafe)
}

fn seal_open_file(file: &File) -> Result<FileSeal, CandidateFailure> {
    let metadata_before = file.metadata().map_err(|_| CandidateFailure::Unsafe)?;
    if !metadata_before.is_file() {
        return Err(CandidateFailure::Unsafe);
    }
    let identity = file_identity(file, &metadata_before)?;
    let mut reader = file.try_clone().map_err(|_| CandidateFailure::Unsafe)?;
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|_| CandidateFailure::Unsafe)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
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
    use super::{FdNamespace, render_fd_path};
    use std::path::PathBuf;

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
