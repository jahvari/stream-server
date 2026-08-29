use axum::{
    body::Body,
    extract::{ConnectInfo, Extension, RawQuery, State},
    http::{HeaderMap, HeaderValue, Method, Response, StatusCode, header},
};
use bytes::Bytes;
use enginefs::backend::{TorrentHandle, priorities::PlaybackIntent};
use futures_util::{Stream, StreamExt, stream};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::OsString,
    fmt,
    hash::{Hash, Hasher},
    ops::Range,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
};
use tokio_util::sync::CancellationToken;

const CAPABILITY_BYTES: usize = 32;
const CAPABILITY_HEX_BYTES: usize = CAPABILITY_BYTES * 2;
const MAX_LIVE_CAPABILITIES: usize = 256;
const MAX_CONCURRENT_REQUESTS_PER_CAPABILITY: usize = 8;
const MAX_CAPABILITY_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// Monotonic, source-owned evidence used to distinguish a stalled probe from
/// a torrent request that is demonstrably waiting for unavailable pieces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceActivitySnapshot {
    pub sequence: u64,
    pub delivered_bytes_total: u64,
    pub active_requests: u32,
    pub waiting_for_pieces: Vec<Range<u64>>,
    pub all_active_requests_piece_blocked: bool,
}

/// Closed protocol policy derived from the trusted source variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SourceProtocolPolicy {
    CompletedFile,
    EngineLoopback,
    ApprovedRemote,
    SyntheticFixture,
}

impl SourceProtocolPolicy {
    pub const fn ffmpeg_allowlist(self) -> &'static str {
        match self {
            Self::CompletedFile | Self::SyntheticFixture => "file,pipe",
            Self::EngineLoopback | Self::ApprovedRemote => "http,tcp",
        }
    }
}

/// A media source issued by the server-owned source broker. The variants are
/// public for exhaustive planning, but all fields and production constructors
/// remain sealed.
///
/// Route text cannot be deserialized into a trusted source:
///
/// ```compile_fail
/// use stream_server::transcoding::ValidatedMediaSource;
/// let _: ValidatedMediaSource = serde_json::from_str(
///     r#"{"approvedRemote":{"id":"route-text"}}"#,
/// ).unwrap();
/// ```
///
/// Variant fields are private, so callers cannot manufacture capabilities:
///
/// ```compile_fail
/// use stream_server::transcoding::{EngineSource, ValidatedMediaSource};
/// let source = EngineSource { id: "route-text".into() };
/// let _ = ValidatedMediaSource::EngineLoopback(source);
/// ```
#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidatedMediaSource {
    CompletedFile(CompletedFileSource),
    EngineLoopback(EngineSource),
    ApprovedRemote(RemoteSourceHandle),
    SyntheticFixture(FixtureSource),
}

impl ValidatedMediaSource {
    pub fn id(&self) -> &str {
        match self {
            Self::CompletedFile(source) => source.id(),
            Self::EngineLoopback(source) => source.id(),
            Self::ApprovedRemote(source) => source.id(),
            Self::SyntheticFixture(source) => source.id(),
        }
    }

    pub fn version(&self) -> &str {
        match self {
            Self::CompletedFile(source) => source.version(),
            Self::EngineLoopback(source) => source.version(),
            Self::ApprovedRemote(source) => source.version(),
            Self::SyntheticFixture(source) => source.version(),
        }
    }

    pub const fn protocol_policy(&self) -> SourceProtocolPolicy {
        match self {
            Self::CompletedFile(_) => SourceProtocolPolicy::CompletedFile,
            Self::EngineLoopback(_) => SourceProtocolPolicy::EngineLoopback,
            Self::ApprovedRemote(_) => SourceProtocolPolicy::ApprovedRemote,
            Self::SyntheticFixture(_) => SourceProtocolPolicy::SyntheticFixture,
        }
    }

    pub fn ffmpeg_protocol_allowlist(&self) -> &'static str {
        self.protocol_policy().ffmpeg_allowlist()
    }

    pub(crate) fn input_argument(&self) -> Result<OsString, SourceError> {
        match self {
            Self::CompletedFile(source) => source.input_argument(),
            Self::EngineLoopback(source) => source.input_argument(),
            Self::ApprovedRemote(source) => source.input_argument(),
            Self::SyntheticFixture(source) => source.input_argument(),
        }
    }

    pub fn subscribe_activity(&self) -> watch::Receiver<SourceActivitySnapshot> {
        match self {
            Self::EngineLoopback(source) => source.subscribe_activity(),
            Self::ApprovedRemote(source) => source.subscribe_activity(),
            Self::CompletedFile(_) | Self::SyntheticFixture(_) => {
                let (_, receiver) = watch::channel(SourceActivitySnapshot::default());
                receiver
            }
        }
    }

    #[cfg(test)]
    pub(super) fn completed_file(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self::CompletedFile(CompletedFileSource::stub(id)?))
    }

    #[cfg(test)]
    pub(super) fn engine_loopback(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self::EngineLoopback(EngineSource::stub(id)?))
    }

    #[cfg(test)]
    pub(super) fn approved_remote(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self::ApprovedRemote(RemoteSourceHandle::stub(id)?))
    }

    #[cfg(test)]
    pub(super) fn synthetic_fixture(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self::SyntheticFixture(FixtureSource::stub(id)?))
    }

    #[cfg(test)]
    pub(super) fn synthetic_fixture_path(
        id: impl Into<String>,
        version: impl Into<String>,
        path: PathBuf,
    ) -> Result<Self, SourceError> {
        Ok(Self::SyntheticFixture(FixtureSource {
            id: SourceId::new(id)?,
            version: version.into(),
            path: Some(path),
        }))
    }
}

impl fmt::Debug for ValidatedMediaSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompletedFile(source) => formatter
                .debug_tuple("CompletedFile")
                .field(source)
                .finish(),
            Self::EngineLoopback(source) => formatter
                .debug_tuple("EngineLoopback")
                .field(source)
                .finish(),
            Self::ApprovedRemote(source) => formatter
                .debug_tuple("ApprovedRemote")
                .field(source)
                .finish(),
            Self::SyntheticFixture(source) => formatter
                .debug_tuple("SyntheticFixture")
                .field(source)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletedFileSource {
    id: SourceId,
    #[serde(skip)]
    version: String,
    #[serde(skip)]
    canonical_path: Option<PathBuf>,
    #[serde(skip)]
    identity: Option<CompletedFileIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct CompletedFileIdentity {
    length: u64,
    modified_nanos: Option<u128>,
    #[cfg(windows)]
    volume: u64,
    #[cfg(windows)]
    file: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl CompletedFileSource {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    fn input_argument(&self) -> Result<OsString, SourceError> {
        let path = self
            .canonical_path
            .as_ref()
            .ok_or(SourceError::InvalidSource)?;
        let expected = self.identity.as_ref().ok_or(SourceError::InvalidSource)?;
        let actual = CompletedFileIdentity::from_path(path)?;
        if &actual != expected {
            return Err(SourceError::InvalidSource);
        }
        Ok(path.as_os_str().to_owned())
    }

    #[cfg(test)]
    fn stub(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self {
            id: SourceId::new(id)?,
            version: "test-version".to_owned(),
            canonical_path: None,
            identity: None,
        })
    }
}

impl fmt::Debug for CompletedFileSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletedFileSource")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl CompletedFileIdentity {
    fn from_path(path: &std::path::Path) -> Result<Self, SourceError> {
        let file = std::fs::File::open(path).map_err(|_| SourceError::NotFound)?;
        let metadata = file.metadata().map_err(|_| SourceError::Io)?;
        if !metadata.is_file() {
            return Err(SourceError::InvalidSource);
        }
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos());
        #[cfg(windows)]
        let (volume, file_identity) = windows_file_identity(&file)?;

        Ok(Self {
            length: metadata.len(),
            modified_nanos,
            #[cfg(windows)]
            volume,
            #[cfg(windows)]
            file: file_identity,
            #[cfg(unix)]
            device: std::os::unix::fs::MetadataExt::dev(&metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(&metadata),
        })
    }
}

#[cfg(windows)]
fn windows_file_identity(file: &std::fs::File) -> Result<(u64, u64), SourceError> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
            .map_err(|_| SourceError::Io)?;
    }
    Ok((
        information.dwVolumeSerialNumber as u64,
        ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    ))
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineSource {
    id: SourceId,
    #[serde(skip)]
    version: String,
    #[serde(skip)]
    lease: Option<Arc<CapabilityLease>>,
    #[serde(skip)]
    activity: Arc<ActivityTracker>,
}

impl EngineSource {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn subscribe_activity(&self) -> watch::Receiver<SourceActivitySnapshot> {
        self.activity.subscribe()
    }

    pub fn revoke(&self) {
        if let Some(lease) = &self.lease {
            lease.revoke();
        }
    }

    fn input_argument(&self) -> Result<OsString, SourceError> {
        self.lease
            .as_ref()
            .map(|lease| OsString::from(lease.input_url.as_str()))
            .ok_or(SourceError::InvalidSource)
    }

    #[cfg(test)]
    fn stub(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self {
            id: SourceId::new(id)?,
            version: "test-version".to_owned(),
            lease: None,
            activity: Arc::new(ActivityTracker::default()),
        })
    }
}

impl fmt::Debug for EngineSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineSource")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl PartialEq for EngineSource {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.version == other.version
    }
}

impl Eq for EngineSource {}

impl Hash for EngineSource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.version.hash(state);
    }
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteSourceHandle {
    id: SourceId,
    #[serde(skip)]
    version: String,
    #[serde(skip)]
    lease: Option<Arc<CapabilityLease>>,
    #[serde(skip)]
    activity: Arc<ActivityTracker>,
}

impl RemoteSourceHandle {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn subscribe_activity(&self) -> watch::Receiver<SourceActivitySnapshot> {
        self.activity.subscribe()
    }

    pub fn revoke(&self) {
        if let Some(lease) = &self.lease {
            lease.revoke();
        }
    }

    fn input_argument(&self) -> Result<OsString, SourceError> {
        self.lease
            .as_ref()
            .map(|lease| OsString::from(lease.input_url.as_str()))
            .ok_or(SourceError::InvalidSource)
    }

    #[cfg(test)]
    fn stub(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self {
            id: SourceId::new(id)?,
            version: "test-version".to_owned(),
            lease: None,
            activity: Arc::new(ActivityTracker::default()),
        })
    }
}

impl fmt::Debug for RemoteSourceHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteSourceHandle")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RemoteSourceHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.version == other.version
    }
}

impl Eq for RemoteSourceHandle {}

impl Hash for RemoteSourceHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.version.hash(state);
    }
}

#[derive(Clone, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureSource {
    id: SourceId,
    #[serde(skip)]
    version: String,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl FixtureSource {
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    fn input_argument(&self) -> Result<OsString, SourceError> {
        self.path
            .as_ref()
            .map(|path| path.as_os_str().to_owned())
            .ok_or(SourceError::InvalidSource)
    }

    #[cfg(test)]
    fn stub(id: impl Into<String>) -> Result<Self, SourceError> {
        Ok(Self {
            id: SourceId::new(id)?,
            version: "test-version".to_owned(),
            path: None,
        })
    }
}

impl fmt::Debug for FixtureSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureSource")
            .field("id", &self.id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(transparent)]
struct SourceId(String);

impl SourceId {
    #[cfg(test)]
    fn new(value: impl Into<String>) -> Result<Self, SourceError> {
        let value = value.into();
        if !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            Ok(Self(value))
        } else {
            Err(SourceError::InvalidSource)
        }
    }

    fn random() -> Result<Self, SourceError> {
        let mut bytes = [0_u8; CAPABILITY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| SourceError::Io)?;
        Ok(Self(hex::encode(bytes)))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SourceError {
    #[error("invalid source")]
    InvalidSource,
    #[error("source not found")]
    NotFound,
    #[error("invalid source capability")]
    InvalidCapability,
    #[error("source capability expired")]
    Expired,
    #[error("source capability revoked")]
    Revoked,
    #[error("source request capacity exceeded")]
    RateLimited,
    #[error("invalid byte range")]
    InvalidRange,
    #[error("source broker capacity exceeded")]
    Capacity,
    #[error("source I/O failed")]
    Io,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityScope {
    source_id: String,
    source_version: String,
}

impl CapabilityScope {
    #[cfg(test)]
    fn fixture(source_id: &str, source_version: &str) -> Self {
        Self {
            source_id: source_id.to_owned(),
            source_version: source_version.to_owned(),
        }
    }
}

struct SecretCredential {
    bytes: [u8; CAPABILITY_BYTES],
    encoded: String,
}

impl SecretCredential {
    fn generate() -> Result<Self, SourceError> {
        let mut bytes = [0_u8; CAPABILITY_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| SourceError::Io)?;
        let encoded = hex::encode(bytes);
        Ok(Self { bytes, encoded })
    }

    fn encoded(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Debug for SecretCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCredential([REDACTED])")
    }
}

struct CapabilityEntry {
    credential: SecretCredential,
    scope: CapabilityScope,
    expires_at: tokio::time::Instant,
    revoked: AtomicBool,
    revocation: CancellationToken,
    requests: Arc<Semaphore>,
    payload: CapabilityPayload,
}

impl CapabilityEntry {
    fn try_acquire(self: &Arc<Self>) -> Result<OwnedSemaphorePermit, SourceError> {
        self.requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| SourceError::RateLimited)
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        self.revocation.cancel();
    }
}

impl fmt::Debug for CapabilityEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityEntry")
            .field("source_id", &self.scope.source_id)
            .field("source_version", &self.scope.source_version)
            .field("revoked", &self.revoked.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

struct IssuedCapability {
    credential: SecretCredential,
    entry: Arc<CapabilityEntry>,
}

impl IssuedCapability {
    #[cfg(test)]
    fn revoke(&self) {
        self.entry.revoke();
    }

    fn into_lease(
        self,
        listener: std::net::SocketAddr,
    ) -> Result<Arc<CapabilityLease>, SourceError> {
        let host = if listener.is_ipv6() {
            "[::1]".to_owned()
        } else {
            "127.0.0.1".to_owned()
        };
        let input_url = url::Url::parse(&format!(
            "http://{host}:{}/_transcoding/source?cap={}",
            listener.port(),
            self.credential.encoded()
        ))
        .map_err(|_| SourceError::Io)?;
        Ok(Arc::new(CapabilityLease {
            input_url,
            entry: self.entry,
        }))
    }
}

struct CapabilityLease {
    input_url: url::Url,
    entry: Arc<CapabilityEntry>,
}

impl CapabilityLease {
    fn revoke(&self) {
        self.entry.revoke();
    }
}

impl fmt::Debug for CapabilityLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityLease([REDACTED])")
    }
}

impl Drop for CapabilityLease {
    fn drop(&mut self) {
        self.revoke();
    }
}

#[derive(Default)]
struct CapabilityRegistry {
    entries: Mutex<HashMap<[u8; CAPABILITY_BYTES], Arc<CapabilityEntry>>>,
}

impl CapabilityRegistry {
    #[cfg(test)]
    fn issue(
        &self,
        scope: CapabilityScope,
        lifetime: Duration,
    ) -> Result<IssuedCapability, SourceError> {
        self.issue_with_payload(scope, lifetime, CapabilityPayload::Fixture)
    }

    fn issue_with_payload(
        &self,
        scope: CapabilityScope,
        lifetime: Duration,
        payload: CapabilityPayload,
    ) -> Result<IssuedCapability, SourceError> {
        if lifetime.is_zero() || lifetime > MAX_CAPABILITY_LIFETIME {
            return Err(SourceError::InvalidSource);
        }
        let credential = SecretCredential::generate()?;
        let lookup_key = Sha256::digest(credential.bytes).into();
        let entry = Arc::new(CapabilityEntry {
            credential: SecretCredential {
                bytes: credential.bytes,
                encoded: credential.encoded.clone(),
            },
            scope,
            expires_at: tokio::time::Instant::now() + lifetime,
            revoked: AtomicBool::new(false),
            revocation: CancellationToken::new(),
            requests: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS_PER_CAPABILITY)),
            payload,
        });
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, existing| {
            !existing.revoked.load(Ordering::Acquire)
                && tokio::time::Instant::now() < existing.expires_at
        });
        if entries.len() >= MAX_LIVE_CAPABILITIES {
            return Err(SourceError::Capacity);
        }
        if entries.contains_key(&lookup_key) {
            return Err(SourceError::Io);
        }
        entries.insert(lookup_key, entry.clone());
        Ok(IssuedCapability { credential, entry })
    }

    fn lookup(&self, encoded: &str) -> Result<Arc<CapabilityEntry>, SourceError> {
        if encoded.len() != CAPABILITY_HEX_BYTES {
            return Err(SourceError::InvalidCapability);
        }
        let mut candidate = [0_u8; CAPABILITY_BYTES];
        hex::decode_to_slice(encoded, &mut candidate)
            .map_err(|_| SourceError::InvalidCapability)?;
        let lookup_key: [u8; CAPABILITY_BYTES] = Sha256::digest(candidate).into();
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&lookup_key)
            .cloned()
            .ok_or(SourceError::InvalidCapability)?;
        if !bool::from(candidate.ct_eq(&entry.credential.bytes)) {
            return Err(SourceError::InvalidCapability);
        }
        if entry.revoked.load(Ordering::Acquire) {
            return Err(SourceError::Revoked);
        }
        if tokio::time::Instant::now() >= entry.expires_at {
            return Err(SourceError::Expired);
        }
        Ok(entry)
    }
}

#[derive(Clone)]
enum CapabilityPayload {
    Engine(Arc<EngineCapability>),
    Remote(Arc<RemoteCapability>),
    #[cfg(test)]
    Fixture,
}

struct EngineCapability {
    info_hash: String,
    file_index: usize,
    intent: PlaybackIntent,
    metadata: EngineFileMetadata,
    provider: Arc<dyn EngineSourceProvider>,
    activity: Arc<ActivityTracker>,
}

struct RemoteCapability {
    target: url::Url,
    runtime: Arc<crate::network_security::ProxyRuntime>,
    activity: Arc<ActivityTracker>,
}

impl fmt::Debug for RemoteCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteCapability([REDACTED])")
    }
}

impl fmt::Debug for EngineCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineCapability")
            .field("file_index", &self.file_index)
            .field("intent", &self.intent)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct EngineFileMetadata {
    length: u64,
    version: String,
    content_type: &'static str,
}

struct CompletedFileCandidate {
    path: PathBuf,
    allowed_roots: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PieceAvailability {
    Available,
    Unavailable,
    Unknown,
}

struct OpenedEngineSource {
    reader: std::pin::Pin<Box<dyn AsyncRead + Send>>,
    _lifecycle: Box<dyn Send>,
}

#[async_trait::async_trait]
trait EngineSourceProvider: Send + Sync {
    async fn describe(
        &self,
        info_hash: &str,
        file_index: usize,
    ) -> Result<EngineFileMetadata, SourceError>;

    async fn open(
        &self,
        info_hash: &str,
        file_index: usize,
        range: ByteRange,
        intent: PlaybackIntent,
    ) -> Result<OpenedEngineSource, SourceError>;

    async fn piece_availability(
        &self,
        info_hash: &str,
        file_index: usize,
        offset: u64,
        intent: PlaybackIntent,
    ) -> Result<PieceAvailability, SourceError>;

    async fn refresh(&self, info_hash: &str, file_index: usize) -> Result<(), SourceError>;

    async fn completed_file(
        &self,
        _info_hash: &str,
        _file_index: usize,
    ) -> Result<Option<CompletedFileCandidate>, SourceError> {
        Ok(None)
    }
}

pub struct SourceBroker {
    registry: CapabilityRegistry,
    provider: Arc<dyn EngineSourceProvider>,
    remote_runtime: Option<Arc<crate::network_security::ProxyRuntime>>,
    listener: Mutex<std::net::SocketAddr>,
}

impl fmt::Debug for SourceBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceBroker")
            .field(
                "listener",
                &*self
                    .listener
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
            .finish_non_exhaustive()
    }
}

impl SourceBroker {
    pub(crate) fn new(
        engine: Arc<enginefs::EngineFS>,
        listener: std::net::SocketAddr,
        remote_runtime: Arc<crate::network_security::ProxyRuntime>,
    ) -> Self {
        Self {
            registry: CapabilityRegistry::default(),
            provider: Arc::new(EngineFsSourceProvider { engine }),
            remote_runtime: Some(remote_runtime),
            listener: Mutex::new(listener),
        }
    }

    #[cfg(test)]
    fn with_provider(
        provider: Arc<dyn EngineSourceProvider>,
        listener: std::net::SocketAddr,
    ) -> Self {
        Self {
            registry: CapabilityRegistry::default(),
            provider,
            remote_runtime: None,
            listener: Mutex::new(listener),
        }
    }

    pub async fn issue_engine_source(
        &self,
        info_hash: &str,
        file_index: usize,
        intent: PlaybackIntent,
        lifetime: Duration,
    ) -> Result<ValidatedMediaSource, SourceError> {
        let info_hash = normalize_info_hash(info_hash)?;
        let metadata = self.provider.describe(&info_hash, file_index).await?;
        let id = SourceId::random()?;
        let activity = Arc::new(ActivityTracker::default());
        let scope = CapabilityScope {
            source_id: id.as_str().to_owned(),
            source_version: metadata.version.clone(),
        };
        let payload = CapabilityPayload::Engine(Arc::new(EngineCapability {
            info_hash,
            file_index,
            intent,
            metadata: metadata.clone(),
            provider: self.provider.clone(),
            activity: activity.clone(),
        }));
        let issued = self.registry.issue_with_payload(scope, lifetime, payload)?;
        let listener = *self
            .listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let lease = Some(issued.into_lease(listener)?);
        Ok(ValidatedMediaSource::EngineLoopback(EngineSource {
            id,
            version: metadata.version,
            lease,
            activity,
        }))
    }

    pub async fn issue_completed_file(
        &self,
        info_hash: &str,
        file_index: usize,
    ) -> Result<ValidatedMediaSource, SourceError> {
        let info_hash = normalize_info_hash(info_hash)?;
        let described = self.provider.describe(&info_hash, file_index).await?;
        let candidate = self
            .provider
            .completed_file(&info_hash, file_index)
            .await?
            .ok_or(SourceError::NotFound)?;
        let canonical_path = tokio::fs::canonicalize(&candidate.path)
            .await
            .map_err(|_| SourceError::NotFound)?;
        let mut allowed = false;
        for root in candidate.allowed_roots {
            let Ok(root) = tokio::fs::canonicalize(root).await else {
                continue;
            };
            if canonical_path.starts_with(&root) && canonical_path != root {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(SourceError::InvalidSource);
        }
        let identity_path = canonical_path.clone();
        let identity =
            tokio::task::spawn_blocking(move || CompletedFileIdentity::from_path(&identity_path))
                .await
                .map_err(|_| SourceError::Io)??;
        if identity.length != described.length {
            return Err(SourceError::InvalidSource);
        }
        let version = hex::encode(Sha256::digest(
            format!(
                "completed-source-v1\0{}\0{}\0{:?}",
                described.version, identity.length, identity.modified_nanos
            )
            .as_bytes(),
        ));
        Ok(ValidatedMediaSource::CompletedFile(CompletedFileSource {
            id: SourceId::random()?,
            version,
            canonical_path: Some(canonical_path),
            identity: Some(identity),
        }))
    }

    #[allow(
        dead_code,
        reason = "casting remains on its legacy remote path until the shared casting adapter gate"
    )]
    pub(crate) async fn issue_remote_source(
        &self,
        mut target: url::Url,
        lifetime: Duration,
    ) -> Result<ValidatedMediaSource, SourceError> {
        let runtime = self
            .remote_runtime
            .as_ref()
            .cloned()
            .ok_or(SourceError::InvalidSource)?;
        target.set_fragment(None);
        let context = runtime
            .try_request_for_peer(None)
            .map_err(|_| SourceError::RateLimited)?;
        runtime
            .validate(&context, &target)
            .await
            .map_err(|_| SourceError::InvalidSource)?;
        drop(context);

        let id = SourceId::random()?;
        let version = hex::encode(Sha256::digest(
            format!("approved-remote-v1\0{}", target.as_str()).as_bytes(),
        ));
        let activity = Arc::new(ActivityTracker::default());
        let scope = CapabilityScope {
            source_id: id.as_str().to_owned(),
            source_version: version.clone(),
        };
        let payload = CapabilityPayload::Remote(Arc::new(RemoteCapability {
            target,
            runtime,
            activity: activity.clone(),
        }));
        let issued = self.registry.issue_with_payload(scope, lifetime, payload)?;
        let listener = *self
            .listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(ValidatedMediaSource::ApprovedRemote(RemoteSourceHandle {
            id,
            version,
            lease: Some(issued.into_lease(listener)?),
            activity,
        }))
    }

    async fn serve(
        &self,
        capability: &str,
        method: Method,
        range_header: Option<&str>,
        peer: Option<std::net::IpAddr>,
    ) -> Response<Body> {
        if !peer.is_some_and(|peer| peer.is_loopback()) {
            return empty_response(StatusCode::FORBIDDEN);
        }
        if !matches!(method, Method::GET | Method::HEAD) {
            return empty_response(StatusCode::METHOD_NOT_ALLOWED);
        }
        let entry = match self.registry.lookup(capability) {
            Ok(entry) => entry,
            Err(error) => return empty_response(source_error_status(error)),
        };
        let _permit = match entry.try_acquire() {
            Ok(permit) => permit,
            Err(error) => return empty_response(source_error_status(error)),
        };
        let source = match entry.payload.clone() {
            CapabilityPayload::Engine(source) => source,
            CapabilityPayload::Remote(source) => {
                return serve_remote_source(entry, _permit, source, method, range_header).await;
            }
            #[cfg(test)]
            CapabilityPayload::Fixture => return empty_response(StatusCode::NOT_FOUND),
        };
        let range = match parse_single_range(range_header, source.metadata.length) {
            Ok(range) => range,
            Err(error) => return empty_response(source_error_status(error)),
        };
        let status = if range.partial {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };

        if method == Method::HEAD {
            return build_source_response(status, &source, range, Body::empty());
        }

        let opened = match source
            .provider
            .open(&source.info_hash, source.file_index, range, source.intent)
            .await
        {
            Ok(opened) => opened,
            Err(error) => return empty_response(source_error_status(error)),
        };
        if source
            .provider
            .refresh(&source.info_hash, source.file_index)
            .await
            .is_err()
        {
            return empty_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let request_id = source.activity.start_request(range.half_open());
        let body_state = EngineBodyState {
            opened,
            source: source.clone(),
            entry,
            _permit,
            remaining: range.len(),
            offset: range.start,
            activity_lease: ActivityRequestLease {
                activity: source.activity.clone(),
                request_id,
            },
        };
        let body = Body::from_stream(stream::unfold(Some(body_state), |state| async move {
            let mut state = state?;
            if state.remaining == 0 {
                return None;
            }
            let availability = state
                .source
                .provider
                .piece_availability(
                    &state.source.info_hash,
                    state.source.file_index,
                    state.offset,
                    state.source.intent,
                )
                .await
                .unwrap_or(PieceAvailability::Unknown);
            state.activity_lease.activity.mark_piece_blocked(
                state.activity_lease.request_id,
                matches!(availability, PieceAvailability::Unavailable),
            );
            if state
                .source
                .provider
                .refresh(&state.source.info_hash, state.source.file_index)
                .await
                .is_err()
            {
                return Some((Err(std::io::Error::other("source refresh failed")), None));
            }
            let buffer_len = usize::try_from(state.remaining.min(64 * 1024)).unwrap_or(64 * 1024);
            let mut buffer = vec![0_u8; buffer_len];
            let expiry = tokio::time::sleep_until(state.entry.expires_at);
            tokio::pin!(expiry);
            let read = tokio::select! {
                biased;
                _ = state.entry.revocation.cancelled() => {
                    return Some((Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "source revoked")), None));
                }
                _ = &mut expiry => {
                    return Some((Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "source expired")), None));
                }
                read = state.opened.reader.read(&mut buffer) => read,
            };
            match read {
                Ok(0) => Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "source ended before the requested range",
                    )),
                    None,
                )),
                Ok(read) => {
                    buffer.truncate(read);
                    let delivered = read as u64;
                    state.remaining = state.remaining.saturating_sub(delivered);
                    state.offset = state.offset.saturating_add(delivered);
                    state
                        .activity_lease
                        .activity
                        .record_delivery(state.activity_lease.request_id, delivered);
                    Some((Ok(Bytes::from(buffer)), Some(state)))
                }
                Err(error) => Some((Err(error), None)),
            }
        }));
        build_source_response(status, &source, range, body)
    }
}

struct EngineFsSourceProvider {
    engine: Arc<enginefs::EngineFS>,
}

struct EngineFsRequestLease {
    engine: Arc<enginefs::EngineFS>,
    info_hash: String,
    file_index: usize,
}

impl Drop for EngineFsRequestLease {
    fn drop(&mut self) {
        let engine = self.engine.clone();
        let info_hash = self.info_hash.clone();
        let file_index = self.file_index;
        tokio::spawn(async move {
            engine.on_stream_end(&info_hash, file_index).await;
        });
    }
}

#[async_trait::async_trait]
impl EngineSourceProvider for EngineFsSourceProvider {
    async fn describe(
        &self,
        info_hash: &str,
        file_index: usize,
    ) -> Result<EngineFileMetadata, SourceError> {
        let engine = self
            .engine
            .get_engine(info_hash)
            .await
            .ok_or(SourceError::NotFound)?;
        let files = engine.handle.get_files().await;
        let file = files.get(file_index).ok_or(SourceError::NotFound)?;
        let version = hex::encode(Sha256::digest(
            format!(
                "engine-source-v1\0{info_hash}\0{file_index}\0{}",
                file.length
            )
            .as_bytes(),
        ));
        Ok(EngineFileMetadata {
            length: file.length,
            version,
            content_type: media_content_type(&file.name),
        })
    }

    async fn open(
        &self,
        info_hash: &str,
        file_index: usize,
        range: ByteRange,
        intent: PlaybackIntent,
    ) -> Result<OpenedEngineSource, SourceError> {
        use enginefs::backend::{HotFilePriorityPlan, TorrentHandle};

        let engine = self
            .engine
            .get_engine(info_hash)
            .await
            .ok_or(SourceError::NotFound)?;
        let priority = match intent {
            PlaybackIntent::InternalProbe => 255,
            PlaybackIntent::Background => 0,
            _ => 1,
        };
        self.engine.on_stream_start(info_hash, file_index).await;
        let lifecycle = Box::new(EngineFsRequestLease {
            engine: self.engine.clone(),
            info_hash: info_hash.to_owned(),
            file_index,
        });
        self.engine
            .refresh_hls_playback(info_hash, file_index, "transcoding-source")
            .await;
        if !engine.handle.manages_playback_lifecycle() {
            self.engine
                .activate_multifile_file_for_playback(
                    info_hash,
                    file_index,
                    Some(HotFilePriorityPlan {
                        file_idx: file_index,
                        start_offset: range.start,
                        priority,
                        intent,
                        bitrate_bytes_per_sec: None,
                    }),
                    "transcoding-source",
                )
                .await;
        }
        let mut file = engine
            .get_file_with_intent(file_index, range.start, priority, intent)
            .await
            .ok_or(SourceError::Io)?;
        file.seek(std::io::SeekFrom::Start(range.start))
            .await
            .map_err(|_| SourceError::Io)?;
        Ok(OpenedEngineSource {
            reader: Box::pin(file),
            _lifecycle: lifecycle,
        })
    }

    async fn piece_availability(
        &self,
        info_hash: &str,
        file_index: usize,
        offset: u64,
        intent: PlaybackIntent,
    ) -> Result<PieceAvailability, SourceError> {
        use enginefs::backend::TorrentHandle;

        let engine = self
            .engine
            .get_engine(info_hash)
            .await
            .ok_or(SourceError::NotFound)?;
        let readiness = engine
            .handle
            .wait_for_piece_ready(file_index, offset, Duration::from_millis(1), intent)
            .await
            .map_err(|_| SourceError::Io)?;
        if readiness.reason == "librqbit-reader" {
            return Ok(PieceAvailability::Unknown);
        }
        Ok(if readiness.ready {
            PieceAvailability::Available
        } else {
            PieceAvailability::Unavailable
        })
    }

    async fn refresh(&self, info_hash: &str, file_index: usize) -> Result<(), SourceError> {
        self.engine
            .refresh_hls_playback(info_hash, file_index, "transcoding-source")
            .await;
        Ok(())
    }

    async fn completed_file(
        &self,
        info_hash: &str,
        file_index: usize,
    ) -> Result<Option<CompletedFileCandidate>, SourceError> {
        let engine = self
            .engine
            .get_engine(info_hash)
            .await
            .ok_or(SourceError::NotFound)?;
        if !engine.handle.is_file_complete(file_index).await {
            return Ok(None);
        }
        let Some(path) = engine.handle.get_file_path(file_index).await else {
            return Ok(None);
        };
        Ok(Some(CompletedFileCandidate {
            path: PathBuf::from(path),
            allowed_roots: vec![
                self.engine.download_dir.clone(),
                self.engine.cache_dir.clone(),
            ],
        }))
    }
}

fn media_content_type(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".mp4") || lower.ends_with(".m4v") {
        "video/mp4"
    } else if lower.ends_with(".mkv") {
        "video/x-matroska"
    } else if lower.ends_with(".webm") {
        "video/webm"
    } else if lower.ends_with(".ts") || lower.ends_with(".m2ts") {
        "video/mp2t"
    } else if lower.ends_with(".avi") {
        "video/x-msvideo"
    } else if lower.ends_with(".mov") {
        "video/quicktime"
    } else if lower.ends_with(".mp3") {
        "audio/mpeg"
    } else if lower.ends_with(".flac") {
        "audio/flac"
    } else {
        "application/octet-stream"
    }
}

pub(crate) async fn route_source(
    State(state): State<crate::state::AppState>,
    peer: Option<Extension<ConnectInfo<std::net::SocketAddr>>>,
    method: Method,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response<Body> {
    let Some(capability) = raw_query.as_deref().and_then(parse_capability_query) else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let peer = peer.map(|Extension(ConnectInfo(address))| address.ip());
    state
        .source_broker
        .serve(capability, method, range, peer)
        .await
}

fn parse_capability_query(query: &str) -> Option<&str> {
    let capability = query.strip_prefix("cap=")?;
    (capability.len() == CAPABILITY_HEX_BYTES
        && capability.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(capability)
}

pub async fn issue_engine_source(
    broker: &SourceBroker,
    info_hash: &str,
    file_index: usize,
    intent: PlaybackIntent,
    lifetime: Duration,
) -> Result<ValidatedMediaSource, SourceError> {
    broker
        .issue_engine_source(info_hash, file_index, intent, lifetime)
        .await
}

struct EngineBodyState {
    opened: OpenedEngineSource,
    source: Arc<EngineCapability>,
    entry: Arc<CapabilityEntry>,
    _permit: OwnedSemaphorePermit,
    remaining: u64,
    offset: u64,
    activity_lease: ActivityRequestLease,
}

struct RemoteBodyState {
    upstream: std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>,
    entry: Arc<CapabilityEntry>,
    _source_lease: crate::network_security::ProxyProducerLease,
    _permit: OwnedSemaphorePermit,
    activity_lease: ActivityRequestLease,
}

async fn serve_remote_source(
    entry: Arc<CapabilityEntry>,
    permit: OwnedSemaphorePermit,
    source: Arc<RemoteCapability>,
    method: Method,
    range_header: Option<&str>,
) -> Response<Body> {
    let range_value = match range_header {
        Some(value) if remote_range_is_valid(value) => match HeaderValue::from_str(value) {
            Ok(value) => Some(value),
            Err(_) => return empty_response(StatusCode::RANGE_NOT_SATISFIABLE),
        },
        Some(_) => return empty_response(StatusCode::RANGE_NOT_SATISFIABLE),
        None => None,
    };
    let fetched = match crate::routes::proxy::fetch_media_source(
        &source.runtime,
        source.target.clone(),
        method.clone(),
        range_value.as_ref(),
    )
    .await
    {
        Ok(fetched) => fetched,
        Err(_) => return empty_response(StatusCode::BAD_GATEWAY),
    };
    let crate::routes::proxy::FetchedMediaSource {
        response: upstream,
        _lease: source_lease,
    } = fetched;
    let status = upstream.status();
    if !status.is_success() {
        return empty_response(status);
    }
    let upstream_headers = upstream.headers().clone();
    let mut builder = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store");
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        header::CONTENT_RANGE,
        header::ACCEPT_RANGES,
    ] {
        if let Some(value) = upstream_headers.get(&name) {
            builder = builder.header(name, value);
        }
    }
    if method == Method::HEAD {
        return builder
            .body(Body::empty())
            .expect("validated remote source response is valid");
    }

    let activity_range = remote_activity_range(&upstream_headers);
    let request_id = source.activity.start_request(activity_range);
    let body_state = RemoteBodyState {
        upstream: Box::pin(upstream.bytes_stream()),
        entry,
        _source_lease: source_lease,
        _permit: permit,
        activity_lease: ActivityRequestLease {
            activity: source.activity.clone(),
            request_id,
        },
    };
    let body = Body::from_stream(stream::unfold(Some(body_state), |state| async move {
        let mut state = state?;
        let expiry = tokio::time::sleep_until(state.entry.expires_at);
        tokio::pin!(expiry);
        let item = tokio::select! {
            biased;
            _ = state.entry.revocation.cancelled() => {
                return Some((Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "source revoked")), None));
            }
            _ = &mut expiry => {
                return Some((Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "source expired")), None));
            }
            item = state.upstream.next() => item,
        };
        match item {
            Some(Ok(bytes)) => {
                state
                    .activity_lease
                    .activity
                    .record_delivery(state.activity_lease.request_id, bytes.len() as u64);
                Some((Ok(bytes), Some(state)))
            }
            Some(Err(_)) => Some((Err(std::io::Error::other("remote source failed")), None)),
            None => None,
        }
    }));
    builder
        .body(body)
        .expect("validated remote source response is valid")
}

fn remote_range_is_valid(value: &str) -> bool {
    let Some(spec) = value.strip_prefix("bytes=") else {
        return false;
    };
    if spec.is_empty() || spec.contains(',') {
        return false;
    }
    let Some((left, right)) = spec.split_once('-') else {
        return false;
    };
    match (left.is_empty(), right.is_empty()) {
        (true, false) => right.parse::<u64>().is_ok_and(|suffix| suffix > 0),
        (false, true) => left.parse::<u64>().is_ok(),
        (false, false) => match (left.parse::<u64>(), right.parse::<u64>()) {
            (Ok(start), Ok(end)) => start <= end,
            _ => false,
        },
        (true, true) => false,
    }
}

fn remote_activity_range(headers: &HeaderMap) -> Range<u64> {
    if let Some(value) = headers
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("bytes "))
        .and_then(|value| value.split_once('/').map(|(range, _)| range))
        .and_then(|range| range.split_once('-'))
        && let (Ok(start), Ok(end)) = (value.0.parse::<u64>(), value.1.parse::<u64>())
        && start <= end
    {
        return start..end.saturating_add(1);
    }
    let length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    0..length
}

struct ActivityRequestLease {
    activity: Arc<ActivityTracker>,
    request_id: u64,
}

impl Drop for ActivityRequestLease {
    fn drop(&mut self) {
        self.activity.finish_request(self.request_id);
    }
}

fn normalize_info_hash(info_hash: &str) -> Result<String, SourceError> {
    if matches!(info_hash.len(), 40 | 64) && info_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(info_hash.to_ascii_lowercase())
    } else {
        Err(SourceError::InvalidSource)
    }
}

fn source_error_status(error: SourceError) -> StatusCode {
    match error {
        SourceError::InvalidCapability => StatusCode::UNAUTHORIZED,
        SourceError::Expired | SourceError::Revoked => StatusCode::GONE,
        SourceError::RateLimited | SourceError::Capacity => StatusCode::TOO_MANY_REQUESTS,
        SourceError::InvalidRange => StatusCode::RANGE_NOT_SATISFIABLE,
        SourceError::NotFound => StatusCode::NOT_FOUND,
        SourceError::InvalidSource | SourceError::Io => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("static source response is valid")
}

fn build_source_response(
    status: StatusCode,
    source: &EngineCapability,
    range: ByteRange,
    body: Body,
) -> Response<Body> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, source.metadata.content_type)
        .header(header::CONTENT_LENGTH, range.len())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "no-store");
    if range.partial {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                range.start, range.end_inclusive, range.full_size
            ),
        );
    }
    builder
        .body(body)
        .expect("validated source response headers are valid")
}

#[derive(Clone, Debug)]
struct RequestActivity {
    range: Range<u64>,
    piece_blocked: bool,
}

struct ActivityState {
    next_request_id: u64,
    snapshot: SourceActivitySnapshot,
    requests: HashMap<u64, RequestActivity>,
}

struct ActivityTracker {
    state: Mutex<ActivityState>,
    sender: watch::Sender<SourceActivitySnapshot>,
}

impl Default for ActivityTracker {
    fn default() -> Self {
        let snapshot = SourceActivitySnapshot::default();
        let (sender, _) = watch::channel(snapshot.clone());
        Self {
            state: Mutex::new(ActivityState {
                next_request_id: 1,
                snapshot,
                requests: HashMap::new(),
            }),
            sender,
        }
    }
}

impl ActivityTracker {
    fn subscribe(&self) -> watch::Receiver<SourceActivitySnapshot> {
        self.sender.subscribe()
    }

    fn start_request(&self, range: Range<u64>) -> u64 {
        let mut state = self.lock();
        let request_id = state.next_request_id;
        state.next_request_id = state.next_request_id.saturating_add(1);
        state.requests.insert(
            request_id,
            RequestActivity {
                range,
                piece_blocked: false,
            },
        );
        self.publish(&mut state);
        request_id
    }

    fn mark_piece_blocked(&self, request_id: u64, blocked: bool) {
        let mut state = self.lock();
        if let Some(request) = state.requests.get_mut(&request_id)
            && request.piece_blocked != blocked
        {
            request.piece_blocked = blocked;
            self.publish(&mut state);
        }
    }

    fn record_delivery(&self, request_id: u64, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let mut state = self.lock();
        let Some(request) = state.requests.get_mut(&request_id) else {
            return;
        };
        request.piece_blocked = false;
        request.range.start = request
            .range
            .start
            .saturating_add(bytes)
            .min(request.range.end);
        state.snapshot.delivered_bytes_total =
            state.snapshot.delivered_bytes_total.saturating_add(bytes);
        self.publish(&mut state);
    }

    fn finish_request(&self, request_id: u64) {
        let mut state = self.lock();
        if state.requests.remove(&request_id).is_some() {
            self.publish(&mut state);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ActivityState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn publish(&self, state: &mut ActivityState) {
        state.snapshot.sequence = state.snapshot.sequence.saturating_add(1);
        state.snapshot.active_requests = u32::try_from(state.requests.len()).unwrap_or(u32::MAX);
        let mut waiting = state
            .requests
            .values()
            .filter(|request| request.piece_blocked)
            .map(|request| request.range.clone())
            .collect::<Vec<_>>();
        waiting.sort_by_key(|range| (range.start, range.end));
        waiting.truncate(MAX_CONCURRENT_REQUESTS_PER_CAPABILITY);
        state.snapshot.waiting_for_pieces = waiting;
        state.snapshot.all_active_requests_piece_blocked = !state.requests.is_empty()
            && state.requests.values().all(|request| request.piece_blocked);
        self.sender.send_replace(state.snapshot.clone());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteRange {
    start: u64,
    end_inclusive: u64,
    full_size: u64,
    partial: bool,
}

impl ByteRange {
    fn full(full_size: u64) -> Self {
        Self {
            start: 0,
            end_inclusive: full_size.saturating_sub(1),
            full_size,
            partial: false,
        }
    }

    fn partial(start: u64, end_inclusive: u64, full_size: u64) -> Self {
        Self {
            start,
            end_inclusive,
            full_size,
            partial: true,
        }
    }

    fn len(self) -> u64 {
        if self.full_size == 0 {
            0
        } else {
            self.end_inclusive.saturating_sub(self.start) + 1
        }
    }

    fn half_open(self) -> Range<u64> {
        self.start..self.start.saturating_add(self.len())
    }
}

fn parse_single_range(value: Option<&str>, size: u64) -> Result<ByteRange, SourceError> {
    let Some(value) = value else {
        return Ok(ByteRange::full(size));
    };
    let spec = value
        .strip_prefix("bytes=")
        .ok_or(SourceError::InvalidRange)?;
    if spec.is_empty() || spec.contains(',') || size == 0 {
        return Err(SourceError::InvalidRange);
    }
    let (left, right) = spec.split_once('-').ok_or(SourceError::InvalidRange)?;
    let (start, end) = match (left.is_empty(), right.is_empty()) {
        (true, false) => {
            let suffix = right
                .parse::<u64>()
                .map_err(|_| SourceError::InvalidRange)?;
            if suffix == 0 {
                return Err(SourceError::InvalidRange);
            }
            let length = suffix.min(size);
            (size - length, size - 1)
        }
        (false, true) => {
            let start = left.parse::<u64>().map_err(|_| SourceError::InvalidRange)?;
            if start >= size {
                return Err(SourceError::InvalidRange);
            }
            (start, size - 1)
        }
        (false, false) => {
            let start = left.parse::<u64>().map_err(|_| SourceError::InvalidRange)?;
            let end = right
                .parse::<u64>()
                .map_err(|_| SourceError::InvalidRange)?;
            if start > end || start >= size {
                return Err(SourceError::InvalidRange);
            }
            (start, end.min(size - 1))
        }
        (true, true) => return Err(SourceError::InvalidRange),
    };
    Ok(ByteRange::partial(start, end, size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, http::Method};
    use enginefs::backend::priorities::PlaybackIntent;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, ReadBuf};

    #[derive(Default)]
    struct MockProvider {
        data: Vec<u8>,
        completed_path: Option<PathBuf>,
        opens: AtomicUsize,
        reads: Arc<AtomicUsize>,
        refreshes: AtomicUsize,
        finishes: Arc<AtomicUsize>,
        intent: Mutex<Option<PlaybackIntent>>,
    }

    impl MockProvider {
        fn with_data(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                ..Self::default()
            }
        }
    }

    struct CountingReader {
        inner: std::io::Cursor<Vec<u8>>,
        reads: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    struct FinishCounter(Arc<AtomicUsize>);

    impl Drop for FinishCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl EngineSourceProvider for MockProvider {
        async fn describe(
            &self,
            _info_hash: &str,
            file_index: usize,
        ) -> Result<EngineFileMetadata, SourceError> {
            if file_index != 0 {
                return Err(SourceError::NotFound);
            }
            Ok(EngineFileMetadata {
                length: self.data.len() as u64,
                version: "immutable-v1".to_owned(),
                content_type: "video/x-matroska",
            })
        }

        async fn open(
            &self,
            _info_hash: &str,
            _file_index: usize,
            range: ByteRange,
            intent: PlaybackIntent,
        ) -> Result<OpenedEngineSource, SourceError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            *self
                .intent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(intent);
            let start = usize::try_from(range.start).map_err(|_| SourceError::InvalidRange)?;
            let mut reader = CountingReader {
                inner: std::io::Cursor::new(self.data.clone()),
                reads: self.reads.clone(),
            };
            reader.inner.set_position(start as u64);
            Ok(OpenedEngineSource {
                reader: Box::pin(reader),
                _lifecycle: Box::new(FinishCounter(self.finishes.clone())),
            })
        }

        async fn piece_availability(
            &self,
            _info_hash: &str,
            _file_index: usize,
            _offset: u64,
            _intent: PlaybackIntent,
        ) -> Result<PieceAvailability, SourceError> {
            Ok(PieceAvailability::Available)
        }

        async fn refresh(&self, _info_hash: &str, _file_index: usize) -> Result<(), SourceError> {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn completed_file(
            &self,
            _info_hash: &str,
            file_index: usize,
        ) -> Result<Option<CompletedFileCandidate>, SourceError> {
            if file_index != 0 {
                return Err(SourceError::NotFound);
            }
            Ok(self
                .completed_path
                .as_ref()
                .map(|path| CompletedFileCandidate {
                    path: path.clone(),
                    allowed_roots: vec![path.parent().unwrap().to_path_buf()],
                }))
        }
    }

    fn broker_fixture(data: &[u8]) -> (Arc<MockProvider>, SourceBroker) {
        let provider = Arc::new(MockProvider::with_data(data));
        let broker =
            SourceBroker::with_provider(provider.clone(), SocketAddr::from(([0, 0, 0, 0], 43123)));
        (provider, broker)
    }

    fn capability_from(source: &ValidatedMediaSource) -> String {
        let input = source.input_argument().unwrap();
        let input = input.to_str().unwrap();
        url::Url::parse(input)
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == "cap").then(|| value.into_owned()))
            .unwrap()
    }

    #[tokio::test]
    async fn issued_engine_source_is_opaque_numeric_loopback_and_exact_intent_scoped() {
        let (provider, broker) = broker_fixture(b"0123456789");
        let info_hash = "0123456789abcdef0123456789abcdef01234567";
        let source = broker
            .issue_engine_source(
                info_hash,
                0,
                PlaybackIntent::InternalProbe,
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let input = source.input_argument().unwrap();
        let input = input.to_str().unwrap();
        let parsed = url::Url::parse(input).unwrap();

        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        assert_eq!(parsed.port(), Some(43123));
        assert_eq!(source.ffmpeg_protocol_allowlist(), "http,tcp");
        assert!(!source.id().contains(info_hash));
        assert!(!format!("{source:?}").contains(&capability_from(&source)));
        assert!(
            !serde_json::to_string(&source)
                .unwrap()
                .contains(&capability_from(&source))
        );

        let capability = capability_from(&source);
        let response = broker
            .serve(
                &capability,
                Method::GET,
                Some("bytes=2-5"),
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            )
            .await;
        assert_eq!(response.status(), axum::http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            to_bytes(response.into_body(), 16).await.unwrap().as_ref(),
            b"2345"
        );
        assert_eq!(
            *provider
                .intent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(PlaybackIntent::InternalProbe)
        );
        assert!(provider.refreshes.load(Ordering::SeqCst) > 0);
        assert_eq!(provider.finishes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn head_does_not_open_and_get_is_lazy_backpressured_and_cancel_safe() {
        let (provider, broker) = broker_fixture(b"0123456789");
        let source = broker
            .issue_engine_source(
                "0123456789abcdef0123456789abcdef01234567",
                0,
                PlaybackIntent::HlsInitial,
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let capability = capability_from(&source);

        let head = broker
            .serve(
                &capability,
                Method::HEAD,
                Some("bytes=1-3"),
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            )
            .await;
        assert_eq!(head.status(), axum::http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(provider.opens.load(Ordering::SeqCst), 0);

        let get = broker
            .serve(
                &capability,
                Method::GET,
                None,
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            )
            .await;
        assert_eq!(provider.opens.load(Ordering::SeqCst), 1);
        assert_eq!(provider.reads.load(Ordering::SeqCst), 0);
        drop(get);
        tokio::task::yield_now().await;
        assert_eq!(provider.finishes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn source_route_rejects_non_loopback_multiple_ranges_and_revocation() {
        let (_provider, broker) = broker_fixture(b"0123456789");
        let source = broker
            .issue_engine_source(
                "0123456789abcdef0123456789abcdef01234567",
                0,
                PlaybackIntent::HlsSeek,
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let capability = capability_from(&source);

        let remote = broker
            .serve(
                &capability,
                Method::GET,
                None,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            )
            .await;
        assert_eq!(remote.status(), axum::http::StatusCode::FORBIDDEN);

        let multiple = broker
            .serve(
                &capability,
                Method::GET,
                Some("bytes=0-1,3-4"),
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            )
            .await;
        assert_eq!(
            multiple.status(),
            axum::http::StatusCode::RANGE_NOT_SATISFIABLE
        );

        if let ValidatedMediaSource::EngineLoopback(engine) = &source {
            engine.revoke();
        }
        let revoked = broker
            .serve(
                &capability,
                Method::GET,
                None,
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            )
            .await;
        assert_eq!(revoked.status(), axum::http::StatusCode::GONE);
    }

    #[tokio::test]
    async fn completed_file_is_canonical_allowlisted_and_change_detected() {
        let temp = tempfile::tempdir().unwrap();
        let media = temp.path().join("movie.mkv");
        tokio::fs::write(&media, b"immutable-media").await.unwrap();
        let provider = Arc::new(MockProvider {
            data: b"immutable-media".to_vec(),
            completed_path: Some(media.clone()),
            ..MockProvider::default()
        });
        let broker =
            SourceBroker::with_provider(provider, SocketAddr::from(([127, 0, 0, 1], 43123)));
        let source = broker
            .issue_completed_file("0123456789abcdef0123456789abcdef01234567", 0)
            .await
            .unwrap();

        assert!(matches!(source, ValidatedMediaSource::CompletedFile(_)));
        let rendered = format!("{source:?}");
        let canonical = media.canonicalize().unwrap();
        assert!(!rendered.contains(&canonical.to_string_lossy().to_string()));
        assert!(!rendered.contains("movie.mkv"));
        assert!(!rendered.contains("immutable-media"));
        assert_eq!(source.ffmpeg_protocol_allowlist(), "file,pipe");
        assert_eq!(source.input_argument().unwrap(), canonical);

        let replacement = temp.path().join("replacement.mkv");
        tokio::fs::write(&replacement, vec![b'x'; b"immutable-media".len()])
            .await
            .unwrap();
        tokio::fs::remove_file(&media).await.unwrap();
        tokio::fs::rename(&replacement, &media).await.unwrap();
        assert_eq!(source.input_argument(), Err(SourceError::InvalidSource));
    }

    #[tokio::test]
    async fn approved_remote_uses_shared_ssrf_policy_and_keeps_target_credentials_opaque() {
        let provider = Arc::new(MockProvider::with_data(b"remote-placeholder"));
        let validator = Arc::new(crate::network_security::DestinationValidator::new(
            Arc::new(crate::network_security::SystemDnsResolver),
            Arc::new(crate::network_security::SystemLocalNetworkProvider),
            Arc::new(crate::network_security::SystemClock),
            vec![crate::network_security::ListenerBinding {
                socket: SocketAddr::from(([0, 0, 0, 0], 43123)),
            }],
        ));
        let runtime = Arc::new(crate::network_security::ProxyRuntime::new(
            crate::network_security::ProxyPolicySettings::default(),
            validator,
        ));
        let mut broker =
            SourceBroker::with_provider(provider, SocketAddr::from(([0, 0, 0, 0], 43123)));
        broker.remote_runtime = Some(runtime);

        let blocked = broker
            .issue_remote_source(
                url::Url::parse("http://169.254.169.254/latest/meta-data").unwrap(),
                Duration::from_secs(60),
            )
            .await;
        assert!(matches!(blocked, Err(SourceError::InvalidSource)));

        let target = "http://user:secret@93.184.216.34/media.mkv?token=private";
        let source = broker
            .issue_remote_source(url::Url::parse(target).unwrap(), Duration::from_secs(60))
            .await
            .unwrap();
        let capability = capability_from(&source);
        let debug = format!("{source:?}");
        let serialized = serde_json::to_string(&source).unwrap();

        assert!(matches!(source, ValidatedMediaSource::ApprovedRemote(_)));
        assert_eq!(source.ffmpeg_protocol_allowlist(), "http,tcp");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("93.184.216.34"));
        assert!(!debug.contains(&capability));
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("93.184.216.34"));
        assert!(!serialized.contains(&capability));
    }

    #[test]
    fn capabilities_are_256_bit_random_redacted_and_constant_time_verified() {
        let registry = CapabilityRegistry::default();
        let first = registry
            .issue(
                CapabilityScope::fixture("source-a", "version-a"),
                Duration::from_secs(60),
            )
            .unwrap();
        let second = registry
            .issue(
                CapabilityScope::fixture("source-b", "version-b"),
                Duration::from_secs(60),
            )
            .unwrap();

        assert_eq!(first.credential.encoded().len(), 64);
        assert_eq!(second.credential.encoded().len(), 64);
        assert_ne!(first.credential.encoded(), second.credential.encoded());
        assert!(!format!("{:?}", first.credential).contains(first.credential.encoded()));

        let resolved = registry
            .lookup(first.credential.encoded())
            .expect("issued capability resolves");
        assert_eq!(resolved.scope.source_id, "source-a");

        let mut altered = first.credential.encoded().as_bytes().to_vec();
        altered[0] = if altered[0] == b'a' { b'b' } else { b'a' };
        let altered = std::str::from_utf8(&altered).unwrap();
        assert!(matches!(
            registry.lookup(altered),
            Err(SourceError::InvalidCapability)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn capabilities_expire_revoke_and_enforce_per_source_request_capacity() {
        let registry = CapabilityRegistry::default();
        let issued = registry
            .issue(
                CapabilityScope::fixture("source-a", "version-a"),
                Duration::from_secs(5),
            )
            .unwrap();
        let entry = registry.lookup(issued.credential.encoded()).unwrap();

        let permits = (0..MAX_CONCURRENT_REQUESTS_PER_CAPABILITY)
            .map(|_| entry.try_acquire().unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(entry.try_acquire(), Err(SourceError::RateLimited)));
        drop(permits);
        assert!(entry.try_acquire().is_ok());

        issued.revoke();
        assert!(matches!(
            registry.lookup(issued.credential.encoded()),
            Err(SourceError::Revoked)
        ));

        let expiring = registry
            .issue(
                CapabilityScope::fixture("source-b", "version-b"),
                Duration::from_secs(5),
            )
            .unwrap();
        tokio::time::advance(Duration::from_secs(6)).await;
        assert!(matches!(
            registry.lookup(expiring.credential.encoded()),
            Err(SourceError::Expired)
        ));
    }

    #[test]
    fn activity_is_monotonic_bounded_and_requires_every_active_request_to_be_blocked() {
        let activity = ActivityTracker::default();
        let mut observer = activity.subscribe();
        let first = activity.start_request(0..64);
        let second = activity.start_request(128..192);

        activity.mark_piece_blocked(first, true);
        let partial = observer.borrow_and_update().clone();
        assert_eq!(partial.active_requests, 2);
        assert_eq!(partial.waiting_for_pieces, vec![0..64]);
        assert!(!partial.all_active_requests_piece_blocked);

        activity.mark_piece_blocked(second, true);
        let all_blocked = observer.borrow_and_update().clone();
        assert!(all_blocked.sequence > partial.sequence);
        assert_eq!(all_blocked.waiting_for_pieces, vec![0..64, 128..192]);
        assert!(all_blocked.all_active_requests_piece_blocked);

        activity.record_delivery(first, 16);
        let progressed = observer.borrow_and_update().clone();
        assert!(progressed.sequence > all_blocked.sequence);
        assert_eq!(progressed.delivered_bytes_total, 16);
        assert_eq!(progressed.waiting_for_pieces, vec![128..192]);
        assert!(!progressed.all_active_requests_piece_blocked);

        activity.mark_piece_blocked(first, true);
        let resumed_wait = observer.borrow_and_update().clone();
        assert_eq!(resumed_wait.waiting_for_pieces, vec![16..64, 128..192]);
        assert!(resumed_wait.all_active_requests_piece_blocked);

        activity.finish_request(first);
        activity.finish_request(second);
        let finished = observer.borrow_and_update().clone();
        assert_eq!(finished.active_requests, 0);
        assert!(!finished.all_active_requests_piece_blocked);
    }

    #[test]
    fn range_parser_accepts_one_bounded_range_and_rejects_multiple_or_invalid_ranges() {
        assert_eq!(parse_single_range(None, 100).unwrap(), ByteRange::full(100));
        assert_eq!(
            parse_single_range(Some("bytes=10-19"), 100).unwrap(),
            ByteRange::partial(10, 19, 100)
        );
        assert_eq!(
            parse_single_range(Some("bytes=90-"), 100).unwrap(),
            ByteRange::partial(90, 99, 100)
        );
        assert_eq!(
            parse_single_range(Some("bytes=-10"), 100).unwrap(),
            ByteRange::partial(90, 99, 100)
        );

        for invalid in [
            "bytes=0-1,4-5",
            "items=0-1",
            "bytes=100-100",
            "bytes=20-10",
            "bytes=-0",
            "bytes=",
        ] {
            assert_eq!(
                parse_single_range(Some(invalid), 100),
                Err(SourceError::InvalidRange),
                "{invalid}"
            );
        }
    }
}
