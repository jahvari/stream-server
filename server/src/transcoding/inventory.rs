use std::{collections::BTreeSet, ffi::OsString, fmt, time::Duration};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    device::TranscodingDevice,
    model::{BackendKind, DeviceClass, DeviceId},
    process::{ProcessErrorCode, StdoutPolicy},
    runtime::{
        RuntimeCommand, RuntimeCommandError, RuntimeExecutable, RuntimeId, RuntimeKind,
        VerifiedRuntimeSession,
    },
};

const MAX_LINES: usize = 32_768;
const MAX_LINE_BYTES: usize = 4 * 1024;
const MAX_RUNTIME_ID_FIELD_BYTES: usize = 2 * 1024;
const RUNTIME_EVIDENCE_DOMAIN: &[u8] = b"stream-server/runtime-evidence-id/v1\0";
const COMMAND_DEADLINE: Duration = Duration::from_secs(10);
const PHASE_DEADLINE: Duration = Duration::from_secs(60);
const STDOUT_LIMIT: usize = 1024 * 1024;
const STDERR_LIMIT: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum HardwareAccelerator {
    Cuda,
    D3d11va,
    Qsv,
    Vaapi,
    VideoToolbox,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DecoderComponent {
    BaseH264,
    BaseHevc,
    BaseAv1,
    BaseVp9,
    BaseMpeg2,
    BaseVc1,
    QsvH264,
    QsvHevc,
    QsvAv1,
    QsvVp9,
    QsvMpeg2,
    QsvVc1,
    CuvidH264,
    CuvidHevc,
    CuvidAv1,
    CuvidVp9,
    CuvidMpeg2,
    CuvidVc1,
    V4l2m2mH264,
    V4l2m2mHevc,
    V4l2m2mAv1,
    V4l2m2mVp9,
    V4l2m2mMpeg2,
    V4l2m2mVc1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum EncoderComponent {
    QsvH264,
    QsvHevc,
    QsvAv1,
    NvencH264,
    NvencHevc,
    NvencAv1,
    VaapiH264,
    VaapiHevc,
    VaapiAv1,
    AmfH264,
    AmfHevc,
    AmfAv1,
    VideoToolboxH264,
    VideoToolboxHevc,
    VideoToolboxAv1,
    V4l2m2mH264,
    V4l2m2mHevc,
    V4l2m2mAv1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum FilterComponent {
    Format,
    HardwareDownload,
    HardwareMap,
    HardwareUpload,
    ScaleSoftware,
    ScaleCuda,
    ScaleQsv,
    ScaleVaapi,
    DeinterlaceSoftware,
    DeinterlaceQsv,
    DeinterlaceVaapi,
    ToneMapSoftware,
    ToneMapOpenCl,
    ToneMapVaapi,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InventoryUnknownCounts {
    pub(crate) accelerators: u32,
    pub(crate) decoders: u32,
    pub(crate) encoders: u32,
    pub(crate) filters: u32,
    pub(crate) flags: u32,
    pub(crate) names: u32,
    pub(crate) historical: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SafeRuntimeVersion {
    pub(crate) ffmpeg: Option<String>,
    pub(crate) jellyfin_revision: Option<String>,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuntimeEvidenceId([u8; 32]);

impl fmt::Debug for RuntimeEvidenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeEvidenceId([redacted])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeInventory {
    pub(crate) runtime_id: RuntimeEvidenceId,
    pub(crate) safe_version: SafeRuntimeVersion,
    pub(crate) accelerators: BTreeSet<HardwareAccelerator>,
    pub(crate) decoders: BTreeSet<DecoderComponent>,
    pub(crate) encoders: BTreeSet<EncoderComponent>,
    pub(crate) filters: BTreeSet<FilterComponent>,
    pub(crate) unknown_counts: InventoryUnknownCounts,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ListedCodec {
    H264,
    Hevc,
    Av1,
    Vp9,
    Mpeg2,
    Vc1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ListedDirection {
    Decode,
    Encode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoarseCandidate {
    pub(crate) device: DeviceId,
    pub(crate) backend: BackendKind,
    pub(crate) codec: ListedCodec,
    pub(crate) direction: ListedDirection,
}

impl Ord for CoarseCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.device
            .as_str()
            .cmp(other.device.as_str())
            .then_with(|| self.backend.cmp(&other.backend))
            .then_with(|| self.codec.cmp(&other.codec))
            .then_with(|| self.direction.cmp(&other.direction))
    }
}

impl PartialOrd for CoarseCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryError {
    Bounds,
    Cancelled,
    IdentityMismatch,
    Malformed,
    ProcessFailed,
    RuntimeChanged,
    Timeout,
}

impl InventoryError {
    pub(crate) const fn safe_code(self) -> &'static str {
        match self {
            Self::Bounds => "inventory_overflow",
            Self::Cancelled => "refresh_cancelled",
            Self::IdentityMismatch | Self::Malformed => "inventory_malformed",
            Self::ProcessFailed => "inventory_process_failed",
            Self::RuntimeChanged => "runtime_unavailable",
            Self::Timeout => "inventory_timeout",
        }
    }
}

impl fmt::Display for InventoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl std::error::Error for InventoryError {}

#[async_trait]
#[allow(dead_code)]
pub(crate) trait StaticInventorySource: Send + Sync {
    async fn collect(
        &self,
        session: &VerifiedRuntimeSession,
        cancellation: CancellationToken,
    ) -> Result<RuntimeInventory, InventoryError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PairedRuntimeInventorySource;

#[async_trait]
impl StaticInventorySource for PairedRuntimeInventorySource {
    async fn collect(
        &self,
        session: &VerifiedRuntimeSession,
        cancellation: CancellationToken,
    ) -> Result<RuntimeInventory, InventoryError> {
        collect_with_deadline(session, cancellation, PHASE_DEADLINE).await
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryQuery {
    Version,
    BuildConfiguration,
    HardwareAccelerators,
    Encoders,
    Decoders,
    Filters,
}

impl InventoryQuery {
    const ALL: [Self; 6] = [
        Self::Version,
        Self::BuildConfiguration,
        Self::HardwareAccelerators,
        Self::Encoders,
        Self::Decoders,
        Self::Filters,
    ];

    const fn argument(self) -> &'static str {
        match self {
            Self::Version => "-version",
            Self::BuildConfiguration => "-buildconf",
            Self::HardwareAccelerators => "-hwaccels",
            Self::Encoders => "-encoders",
            Self::Decoders => "-decoders",
            Self::Filters => "-filters",
        }
    }
}

struct InventoryCommandOutput {
    stdout: Vec<u8>,
}

#[async_trait]
trait InventorySession: Send + Sync {
    fn id(&self) -> &RuntimeId;
    fn kind(&self) -> RuntimeKind;

    async fn execute(
        &self,
        query: InventoryQuery,
        command: RuntimeCommand,
        cancellation: &CancellationToken,
    ) -> Result<InventoryCommandOutput, InventoryError>;
}

#[async_trait]
impl InventorySession for VerifiedRuntimeSession {
    fn id(&self) -> &RuntimeId {
        VerifiedRuntimeSession::id(self)
    }

    fn kind(&self) -> RuntimeKind {
        VerifiedRuntimeSession::kind(self)
    }

    async fn execute(
        &self,
        _query: InventoryQuery,
        command: RuntimeCommand,
        cancellation: &CancellationToken,
    ) -> Result<InventoryCommandOutput, InventoryError> {
        let output = self
            .run_bounded_with_cancellation(RuntimeExecutable::Ffmpeg, command, cancellation)
            .await
            .map_err(map_command_error)?;
        if !output.status.success() {
            return Err(InventoryError::ProcessFailed);
        }
        Ok(InventoryCommandOutput {
            stdout: output.stdout,
        })
    }
}

fn map_command_error(error: RuntimeCommandError) -> InventoryError {
    match error {
        RuntimeCommandError::Runtime(_) => InventoryError::RuntimeChanged,
        RuntimeCommandError::Process(error) => match error.code() {
            ProcessErrorCode::Cancelled => InventoryError::Cancelled,
            ProcessErrorCode::DeadlineExceeded => InventoryError::Timeout,
            ProcessErrorCode::StdoutLimitExceeded | ProcessErrorCode::StderrLimitExceeded => {
                InventoryError::Bounds
            }
            ProcessErrorCode::InvalidSpec
            | ProcessErrorCode::UnsupportedPolicy
            | ProcessErrorCode::SpawnFailed
            | ProcessErrorCode::WaitFailed => InventoryError::ProcessFailed,
        },
    }
}

fn inventory_command(query: InventoryQuery) -> RuntimeCommand {
    RuntimeCommand::new(
        vec![
            OsString::from("-nostdin"),
            OsString::from("-hide_banner"),
            OsString::from(query.argument()),
        ],
        StdoutPolicy::Capture {
            byte_limit: STDOUT_LIMIT,
        },
        STDERR_LIMIT,
        COMMAND_DEADLINE,
    )
}

async fn collect_with_deadline<S: InventorySession + ?Sized>(
    session: &S,
    cancellation: CancellationToken,
    deadline: Duration,
) -> Result<RuntimeInventory, InventoryError> {
    if cancellation.is_cancelled() {
        return Err(InventoryError::Cancelled);
    }
    let phase_cancellation = cancellation.child_token();
    let phase = collect_inner(session, &phase_cancellation);
    tokio::pin!(phase);
    let timer = tokio::time::sleep(deadline);
    tokio::pin!(timer);

    tokio::select! {
        result = &mut phase => result,
        () = cancellation.cancelled() => {
            phase_cancellation.cancel();
            let _ = phase.await;
            Err(InventoryError::Cancelled)
        }
        () = &mut timer => {
            phase_cancellation.cancel();
            let _ = phase.await;
            Err(InventoryError::Timeout)
        }
    }
}

async fn collect_inner<S: InventorySession + ?Sized>(
    session: &S,
    cancellation: &CancellationToken,
) -> Result<RuntimeInventory, InventoryError> {
    let runtime = session.id().clone();
    let runtime_kind = session.kind();
    let mut outputs = Vec::with_capacity(InventoryQuery::ALL.len());
    for query in InventoryQuery::ALL {
        if cancellation.is_cancelled() {
            return Err(InventoryError::Cancelled);
        }
        let output = session
            .execute(query, inventory_command(query), cancellation)
            .await?;
        outputs.push(output.stdout);
    }
    if session.id() != &runtime {
        return Err(InventoryError::RuntimeChanged);
    }
    let [version, buildconf, hwaccels, encoders, decoders, filters] =
        outputs.try_into().map_err(|_| InventoryError::Malformed)?;
    parse_inventory_outputs(
        runtime_kind,
        &runtime,
        StaticInventoryOutputs::new(
            &version, &buildconf, &hwaccels, &encoders, &decoders, &filters,
        ),
    )
}

impl RuntimeEvidenceId {
    pub(crate) fn derive(runtime: &RuntimeId) -> Result<Self, InventoryError> {
        let mut digest = Sha256::new();
        digest.update(RUNTIME_EVIDENCE_DOMAIN);
        update_required(&mut digest, 1, runtime.install_digest.as_bytes())?;
        update_required(&mut digest, 2, runtime.ffmpeg_version.as_bytes())?;
        digest.update([3]);
        match &runtime.jellyfin_revision {
            Some(revision) => {
                digest.update([1]);
                update_length_and_value(&mut digest, revision.as_bytes())?;
            }
            None => digest.update([0]),
        }
        update_required(
            &mut digest,
            4,
            runtime.build_configuration_digest.as_bytes(),
        )?;
        update_required(&mut digest, 5, runtime.pair_root_identity.as_bytes())?;
        Ok(Self(digest.finalize().into()))
    }
}

fn update_required(digest: &mut Sha256, tag: u8, value: &[u8]) -> Result<(), InventoryError> {
    digest.update([tag]);
    update_length_and_value(digest, value)
}

fn update_length_and_value(digest: &mut Sha256, value: &[u8]) -> Result<(), InventoryError> {
    if value.len() > MAX_RUNTIME_ID_FIELD_BYTES {
        return Err(InventoryError::Bounds);
    }
    let length = u32::try_from(value.len()).map_err(|_| InventoryError::Bounds)?;
    digest.update(length.to_be_bytes());
    digest.update(value);
    Ok(())
}

fn safe_token(value: &str, maximum: usize) -> Option<String> {
    let bytes = value.as_bytes();
    (bytes.len() <= maximum
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(byte)))
    .then(|| value.to_owned())
}

fn version_token_matches(runtime_kind: RuntimeKind, runtime: &RuntimeId, observed: &str) -> bool {
    match runtime_kind {
        RuntimeKind::Jellyfin => observed == format!("{}-Jellyfin", runtime.ffmpeg_version),
        RuntimeKind::SoftwareCompatible => {
            observed == runtime.ffmpeg_version
                || observed == format!("{}-Jellyfin", runtime.ffmpeg_version)
        }
    }
}

fn bounded_text(output: &[u8]) -> Result<&str, InventoryError> {
    if output.len() > STDOUT_LIMIT {
        return Err(InventoryError::Bounds);
    }
    if output.contains(&0) {
        return Err(InventoryError::Malformed);
    }
    for (index, byte) in output.iter().enumerate() {
        if *byte == b'\r' && output.get(index + 1) != Some(&b'\n') {
            return Err(InventoryError::Malformed);
        }
    }
    let text = std::str::from_utf8(output).map_err(|_| InventoryError::Malformed)?;
    let mut count = 0usize;
    for line in text.lines() {
        count = count.checked_add(1).ok_or(InventoryError::Bounds)?;
        if count > MAX_LINES || line.len() > MAX_LINE_BYTES {
            return Err(InventoryError::Bounds);
        }
    }
    Ok(text)
}

fn parse_version(output: &[u8]) -> Result<&str, InventoryError> {
    let text = bounded_text(output)?;
    let line = text.lines().next().ok_or(InventoryError::Malformed)?;
    let token = line
        .strip_prefix("ffmpeg version ")
        .and_then(|remainder| remainder.split_ascii_whitespace().next())
        .filter(|token| !token.is_empty())
        .ok_or(InventoryError::Malformed)?;
    if !token.is_ascii() {
        return Err(InventoryError::Malformed);
    }
    Ok(token)
}

fn parse_hwaccels(
    output: &[u8],
    unknown: &mut InventoryUnknownCounts,
) -> Result<BTreeSet<HardwareAccelerator>, InventoryError> {
    let text = bounded_text(output)?;
    let mut lines = text.lines();
    if lines.next() != Some("Hardware acceleration methods:") {
        return Err(InventoryError::Malformed);
    }
    let mut components = BTreeSet::new();
    for line in lines.filter(|line| !line.is_empty()) {
        if !valid_name(line) {
            return Err(InventoryError::Malformed);
        }
        let component = match line {
            "cuda" => Some(HardwareAccelerator::Cuda),
            "d3d11va" => Some(HardwareAccelerator::D3d11va),
            "qsv" => Some(HardwareAccelerator::Qsv),
            "vaapi" => Some(HardwareAccelerator::Vaapi),
            "videotoolbox" => Some(HardwareAccelerator::VideoToolbox),
            "vdpau" => {
                increment(&mut unknown.historical)?;
                None
            }
            _ => {
                increment(&mut unknown.accelerators)?;
                increment(&mut unknown.names)?;
                None
            }
        };
        if let Some(component) = component {
            components.insert(component);
        }
    }
    Ok(components)
}

#[derive(Clone, Copy)]
enum ListKind {
    Decoder,
    Encoder,
    Filter,
}

fn parse_list<'a>(
    output: &'a [u8],
    header: &str,
    kind: ListKind,
) -> Result<Vec<&'a str>, InventoryError> {
    let text = bounded_text(output)?;
    let mut lines = text.lines();
    if lines.next() != Some(header) {
        return Err(InventoryError::Malformed);
    }
    let mut names = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        if line == " ------" || documented_filter_legend(line, kind) {
            continue;
        }
        let flag_width = match kind {
            ListKind::Decoder | ListKind::Encoder => 6,
            ListKind::Filter => 3,
        };
        let name_offset = flag_width + 2;
        let bytes = line.as_bytes();
        if bytes.first() != Some(&b' ') || bytes.get(flag_width + 1) != Some(&b' ') {
            return Err(InventoryError::Malformed);
        }
        let flags = &bytes[1..=flag_width];
        let remainder = line.get(name_offset..).ok_or(InventoryError::Malformed)?;
        if remainder.starts_with("= ") {
            continue;
        }
        let name = remainder
            .split_ascii_whitespace()
            .next()
            .ok_or(InventoryError::Malformed)?;
        if !valid_name(name) {
            return Err(InventoryError::Malformed);
        }
        let documented_flags = match kind {
            ListKind::Decoder | ListKind::Encoder => valid_codec_flags(flags),
            ListKind::Filter => valid_filter_flags(flags),
        };
        if !documented_flags
            || (matches!(kind, ListKind::Decoder | ListKind::Encoder) && flags[0] != b'V')
        {
            names.push("");
        } else {
            names.push(name);
        }
    }
    Ok(names)
}

fn documented_filter_legend(line: &str, kind: ListKind) -> bool {
    if !matches!(kind, ListKind::Filter) {
        return false;
    }
    let Some((marker, _description)) = line
        .strip_prefix("  ")
        .and_then(|line| line.split_once(" = "))
    else {
        return false;
    };
    matches!(marker, "T.." | ".S." | "..C" | "A" | "V" | "N" | "|")
}

fn valid_codec_flags(flags: &[u8]) -> bool {
    flags.len() == 6
        && matches!(flags[0], b'V' | b'A' | b'S')
        && matches!(flags[1], b'F' | b'.')
        && matches!(flags[2], b'S' | b'.')
        && matches!(flags[3], b'X' | b'.')
        && matches!(flags[4], b'B' | b'.')
        && matches!(flags[5], b'D' | b'.')
}

fn valid_filter_flags(flags: &[u8]) -> bool {
    flags.len() == 3
        && matches!(flags[0], b'T' | b'.')
        && matches!(flags[1], b'S' | b'.')
        && matches!(flags[2], b'C' | b'.')
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn increment(value: &mut u32) -> Result<(), InventoryError> {
    *value = value.checked_add(1).ok_or(InventoryError::Bounds)?;
    Ok(())
}

const CANDIDATE_LIMIT: usize = 1024;
const DECODE_CODECS: [ListedCodec; 6] = [
    ListedCodec::H264,
    ListedCodec::Hevc,
    ListedCodec::Av1,
    ListedCodec::Vp9,
    ListedCodec::Mpeg2,
    ListedCodec::Vc1,
];
const ENCODE_CODECS: [ListedCodec; 3] = [ListedCodec::H264, ListedCodec::Hevc, ListedCodec::Av1];

pub(crate) fn coarse_candidates(
    session: &VerifiedRuntimeSession,
    inventory: &RuntimeInventory,
    devices: &[TranscodingDevice],
) -> Result<Vec<CoarseCandidate>, InventoryError> {
    if RuntimeEvidenceId::derive(session.id())? != inventory.runtime_id {
        return Err(InventoryError::RuntimeChanged);
    }
    coarse_candidates_from(
        session.kind(),
        inventory,
        devices
            .iter()
            .map(|device| (&device.id, device.class, &device.backends)),
    )
}

fn coarse_candidates_from<'a>(
    runtime_kind: RuntimeKind,
    inventory: &RuntimeInventory,
    devices: impl IntoIterator<Item = (&'a DeviceId, DeviceClass, &'a BTreeSet<BackendKind>)>,
) -> Result<Vec<CoarseCandidate>, InventoryError> {
    if !runtime_kind.hardware_allowed() {
        return Ok(Vec::new());
    }
    let mut candidates = BTreeSet::new();
    for (device, class, backends) in devices {
        if matches!(class, DeviceClass::Virtual | DeviceClass::Software) {
            continue;
        }
        for backend in backends {
            if *backend == BackendKind::V4l2m2m {
                continue;
            }
            for codec in DECODE_CODECS {
                if decoder_listed(*backend, codec, inventory) {
                    insert_candidate(
                        &mut candidates,
                        CoarseCandidate {
                            device: device.clone(),
                            backend: *backend,
                            codec,
                            direction: ListedDirection::Decode,
                        },
                    )?;
                }
            }
            for codec in ENCODE_CODECS {
                if encoder_listed(*backend, codec, inventory) {
                    insert_candidate(
                        &mut candidates,
                        CoarseCandidate {
                            device: device.clone(),
                            backend: *backend,
                            codec,
                            direction: ListedDirection::Encode,
                        },
                    )?;
                }
            }
        }
    }
    Ok(candidates.into_iter().collect())
}

fn insert_candidate(
    candidates: &mut BTreeSet<CoarseCandidate>,
    candidate: CoarseCandidate,
) -> Result<(), InventoryError> {
    if !candidates.contains(&candidate) && candidates.len() >= CANDIDATE_LIMIT {
        return Err(InventoryError::Bounds);
    }
    candidates.insert(candidate);
    Ok(())
}

fn decoder_listed(backend: BackendKind, codec: ListedCodec, inventory: &RuntimeInventory) -> bool {
    match backend {
        BackendKind::Qsv => inventory.decoders.contains(&qsv_decoder(codec)),
        BackendKind::Cuda => inventory.decoders.contains(&cuvid_decoder(codec)),
        BackendKind::D3d11va => {
            inventory
                .accelerators
                .contains(&HardwareAccelerator::D3d11va)
                && inventory.decoders.contains(&base_decoder(codec))
        }
        BackendKind::Vaapi => {
            inventory.accelerators.contains(&HardwareAccelerator::Vaapi)
                && inventory.decoders.contains(&base_decoder(codec))
        }
        BackendKind::VideoToolbox => {
            inventory
                .accelerators
                .contains(&HardwareAccelerator::VideoToolbox)
                && inventory.decoders.contains(&base_decoder(codec))
        }
        BackendKind::Amf | BackendKind::Nvenc | BackendKind::V4l2m2m => false,
    }
}

fn encoder_listed(backend: BackendKind, codec: ListedCodec, inventory: &RuntimeInventory) -> bool {
    let component = match (backend, codec) {
        (BackendKind::Qsv, ListedCodec::H264) => Some(EncoderComponent::QsvH264),
        (BackendKind::Qsv, ListedCodec::Hevc) => Some(EncoderComponent::QsvHevc),
        (BackendKind::Qsv, ListedCodec::Av1) => Some(EncoderComponent::QsvAv1),
        (BackendKind::Nvenc, ListedCodec::H264) => Some(EncoderComponent::NvencH264),
        (BackendKind::Nvenc, ListedCodec::Hevc) => Some(EncoderComponent::NvencHevc),
        (BackendKind::Nvenc, ListedCodec::Av1) => Some(EncoderComponent::NvencAv1),
        (BackendKind::Vaapi, ListedCodec::H264) => Some(EncoderComponent::VaapiH264),
        (BackendKind::Vaapi, ListedCodec::Hevc) => Some(EncoderComponent::VaapiHevc),
        (BackendKind::Vaapi, ListedCodec::Av1) => Some(EncoderComponent::VaapiAv1),
        (BackendKind::Amf, ListedCodec::H264) => Some(EncoderComponent::AmfH264),
        (BackendKind::Amf, ListedCodec::Hevc) => Some(EncoderComponent::AmfHevc),
        (BackendKind::Amf, ListedCodec::Av1) => Some(EncoderComponent::AmfAv1),
        (BackendKind::VideoToolbox, ListedCodec::H264) => Some(EncoderComponent::VideoToolboxH264),
        (BackendKind::VideoToolbox, ListedCodec::Hevc) => Some(EncoderComponent::VideoToolboxHevc),
        (BackendKind::VideoToolbox, ListedCodec::Av1) => Some(EncoderComponent::VideoToolboxAv1),
        _ => None,
    };
    component.is_some_and(|component| inventory.encoders.contains(&component))
}

const fn base_decoder(codec: ListedCodec) -> DecoderComponent {
    match codec {
        ListedCodec::H264 => DecoderComponent::BaseH264,
        ListedCodec::Hevc => DecoderComponent::BaseHevc,
        ListedCodec::Av1 => DecoderComponent::BaseAv1,
        ListedCodec::Vp9 => DecoderComponent::BaseVp9,
        ListedCodec::Mpeg2 => DecoderComponent::BaseMpeg2,
        ListedCodec::Vc1 => DecoderComponent::BaseVc1,
    }
}

const fn qsv_decoder(codec: ListedCodec) -> DecoderComponent {
    match codec {
        ListedCodec::H264 => DecoderComponent::QsvH264,
        ListedCodec::Hevc => DecoderComponent::QsvHevc,
        ListedCodec::Av1 => DecoderComponent::QsvAv1,
        ListedCodec::Vp9 => DecoderComponent::QsvVp9,
        ListedCodec::Mpeg2 => DecoderComponent::QsvMpeg2,
        ListedCodec::Vc1 => DecoderComponent::QsvVc1,
    }
}

const fn cuvid_decoder(codec: ListedCodec) -> DecoderComponent {
    match codec {
        ListedCodec::H264 => DecoderComponent::CuvidH264,
        ListedCodec::Hevc => DecoderComponent::CuvidHevc,
        ListedCodec::Av1 => DecoderComponent::CuvidAv1,
        ListedCodec::Vp9 => DecoderComponent::CuvidVp9,
        ListedCodec::Mpeg2 => DecoderComponent::CuvidMpeg2,
        ListedCodec::Vc1 => DecoderComponent::CuvidVc1,
    }
}

fn historical_decoder(name: &str) -> bool {
    ["_rkmpp", "_mediacodec", "_vdpau", "_omx"]
        .iter()
        .any(|suffix| name.strip_suffix(suffix).is_some_and(is_known_codec_stem))
}

fn historical_encoder(name: &str) -> bool {
    ["_mediacodec", "_omx"]
        .iter()
        .any(|suffix| name.strip_suffix(suffix).is_some_and(is_known_codec_stem))
}

fn is_known_codec_stem(value: &str) -> bool {
    matches!(
        value,
        "h264" | "hevc" | "av1" | "vp9" | "mpeg2video" | "vc1"
    )
}

fn parse_decoders(
    output: &[u8],
    unknown: &mut InventoryUnknownCounts,
) -> Result<BTreeSet<DecoderComponent>, InventoryError> {
    let mut components = BTreeSet::new();
    for name in parse_list(output, "Decoders:", ListKind::Decoder)? {
        if name.is_empty() {
            increment(&mut unknown.flags)?;
            increment(&mut unknown.decoders)?;
            continue;
        }
        let component = match name {
            "h264" => Some(DecoderComponent::BaseH264),
            "hevc" => Some(DecoderComponent::BaseHevc),
            "av1" => Some(DecoderComponent::BaseAv1),
            "vp9" => Some(DecoderComponent::BaseVp9),
            "mpeg2video" => Some(DecoderComponent::BaseMpeg2),
            "vc1" => Some(DecoderComponent::BaseVc1),
            "h264_qsv" => Some(DecoderComponent::QsvH264),
            "hevc_qsv" => Some(DecoderComponent::QsvHevc),
            "av1_qsv" => Some(DecoderComponent::QsvAv1),
            "vp9_qsv" => Some(DecoderComponent::QsvVp9),
            "mpeg2_qsv" => Some(DecoderComponent::QsvMpeg2),
            "vc1_qsv" => Some(DecoderComponent::QsvVc1),
            "h264_cuvid" => Some(DecoderComponent::CuvidH264),
            "hevc_cuvid" => Some(DecoderComponent::CuvidHevc),
            "av1_cuvid" => Some(DecoderComponent::CuvidAv1),
            "vp9_cuvid" => Some(DecoderComponent::CuvidVp9),
            "mpeg2_cuvid" => Some(DecoderComponent::CuvidMpeg2),
            "vc1_cuvid" => Some(DecoderComponent::CuvidVc1),
            "h264_v4l2m2m" => Some(DecoderComponent::V4l2m2mH264),
            "hevc_v4l2m2m" => Some(DecoderComponent::V4l2m2mHevc),
            "av1_v4l2m2m" => Some(DecoderComponent::V4l2m2mAv1),
            "vp9_v4l2m2m" => Some(DecoderComponent::V4l2m2mVp9),
            "mpeg2_v4l2m2m" => Some(DecoderComponent::V4l2m2mMpeg2),
            "vc1_v4l2m2m" => Some(DecoderComponent::V4l2m2mVc1),
            _ if historical_decoder(name) => {
                increment(&mut unknown.historical)?;
                None
            }
            _ => {
                increment(&mut unknown.decoders)?;
                increment(&mut unknown.names)?;
                None
            }
        };
        if let Some(component) = component {
            components.insert(component);
        }
    }
    Ok(components)
}

fn parse_encoders(
    output: &[u8],
    unknown: &mut InventoryUnknownCounts,
) -> Result<BTreeSet<EncoderComponent>, InventoryError> {
    let mut components = BTreeSet::new();
    for name in parse_list(output, "Encoders:", ListKind::Encoder)? {
        if name.is_empty() {
            increment(&mut unknown.flags)?;
            increment(&mut unknown.encoders)?;
            continue;
        }
        let component = match name {
            "h264_qsv" => Some(EncoderComponent::QsvH264),
            "hevc_qsv" => Some(EncoderComponent::QsvHevc),
            "av1_qsv" => Some(EncoderComponent::QsvAv1),
            "h264_nvenc" => Some(EncoderComponent::NvencH264),
            "hevc_nvenc" => Some(EncoderComponent::NvencHevc),
            "av1_nvenc" => Some(EncoderComponent::NvencAv1),
            "h264_vaapi" => Some(EncoderComponent::VaapiH264),
            "hevc_vaapi" => Some(EncoderComponent::VaapiHevc),
            "av1_vaapi" => Some(EncoderComponent::VaapiAv1),
            "h264_amf" => Some(EncoderComponent::AmfH264),
            "hevc_amf" => Some(EncoderComponent::AmfHevc),
            "av1_amf" => Some(EncoderComponent::AmfAv1),
            "h264_videotoolbox" => Some(EncoderComponent::VideoToolboxH264),
            "hevc_videotoolbox" => Some(EncoderComponent::VideoToolboxHevc),
            "av1_videotoolbox" => Some(EncoderComponent::VideoToolboxAv1),
            "h264_v4l2m2m" => Some(EncoderComponent::V4l2m2mH264),
            "hevc_v4l2m2m" => Some(EncoderComponent::V4l2m2mHevc),
            "av1_v4l2m2m" => Some(EncoderComponent::V4l2m2mAv1),
            _ if historical_encoder(name) => {
                increment(&mut unknown.historical)?;
                None
            }
            _ => {
                increment(&mut unknown.encoders)?;
                increment(&mut unknown.names)?;
                None
            }
        };
        if let Some(component) = component {
            components.insert(component);
        }
    }
    Ok(components)
}

fn parse_filters(
    output: &[u8],
    unknown: &mut InventoryUnknownCounts,
) -> Result<BTreeSet<FilterComponent>, InventoryError> {
    let mut components = BTreeSet::new();
    for name in parse_list(output, "Filters:", ListKind::Filter)? {
        if name.is_empty() {
            increment(&mut unknown.flags)?;
            increment(&mut unknown.filters)?;
            continue;
        }
        let component = match name {
            "format" => Some(FilterComponent::Format),
            "hwdownload" => Some(FilterComponent::HardwareDownload),
            "hwmap" => Some(FilterComponent::HardwareMap),
            "hwupload" => Some(FilterComponent::HardwareUpload),
            "scale" => Some(FilterComponent::ScaleSoftware),
            "scale_cuda" => Some(FilterComponent::ScaleCuda),
            "scale_qsv" => Some(FilterComponent::ScaleQsv),
            "scale_vaapi" => Some(FilterComponent::ScaleVaapi),
            "yadif" => Some(FilterComponent::DeinterlaceSoftware),
            "deinterlace_qsv" => Some(FilterComponent::DeinterlaceQsv),
            "deinterlace_vaapi" => Some(FilterComponent::DeinterlaceVaapi),
            "tonemap" => Some(FilterComponent::ToneMapSoftware),
            "tonemap_opencl" => Some(FilterComponent::ToneMapOpenCl),
            "tonemap_vaapi" => Some(FilterComponent::ToneMapVaapi),
            _ => {
                increment(&mut unknown.filters)?;
                increment(&mut unknown.names)?;
                None
            }
        };
        if let Some(component) = component {
            components.insert(component);
        }
    }
    Ok(components)
}

#[derive(Clone, Copy)]
struct StaticInventoryOutputs<'a> {
    version: &'a [u8],
    buildconf: &'a [u8],
    hwaccels: &'a [u8],
    encoders: &'a [u8],
    decoders: &'a [u8],
    filters: &'a [u8],
}

impl<'a> StaticInventoryOutputs<'a> {
    const fn new(
        version: &'a [u8],
        buildconf: &'a [u8],
        hwaccels: &'a [u8],
        encoders: &'a [u8],
        decoders: &'a [u8],
        filters: &'a [u8],
    ) -> Self {
        Self {
            version,
            buildconf,
            hwaccels,
            encoders,
            decoders,
            filters,
        }
    }
}

fn parse_inventory_outputs(
    runtime_kind: RuntimeKind,
    runtime: &RuntimeId,
    outputs: StaticInventoryOutputs<'_>,
) -> Result<RuntimeInventory, InventoryError> {
    let runtime_evidence_id = RuntimeEvidenceId::derive(runtime)?;
    if !version_token_matches(runtime_kind, runtime, parse_version(outputs.version)?) {
        return Err(InventoryError::IdentityMismatch);
    }
    bounded_text(outputs.buildconf)?;
    let normalized = super::runtime::build_configuration(outputs.buildconf)
        .map_err(|_| InventoryError::Malformed)?;
    let build_digest = hex::encode(Sha256::digest(&normalized));
    if build_digest != runtime.build_configuration_digest {
        return Err(InventoryError::IdentityMismatch);
    }

    let mut unknown_counts = InventoryUnknownCounts::default();
    let accelerators = parse_hwaccels(outputs.hwaccels, &mut unknown_counts)?;
    let encoders = parse_encoders(outputs.encoders, &mut unknown_counts)?;
    let decoders = parse_decoders(outputs.decoders, &mut unknown_counts)?;
    let filters = parse_filters(outputs.filters, &mut unknown_counts)?;
    Ok(RuntimeInventory {
        runtime_id: runtime_evidence_id,
        safe_version: SafeRuntimeVersion {
            ffmpeg: safe_token(&runtime.ffmpeg_version, 96),
            jellyfin_revision: runtime
                .jellyfin_revision
                .as_deref()
                .and_then(|value| safe_token(value, 64)),
        },
        accelerators,
        decoders,
        encoders,
        filters,
        unknown_counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    const VERSION: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transcoding_inventory/version-jellyfin.txt"
    ));
    const BUILDCONF: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transcoding_inventory/buildconf-jellyfin.txt"
    ));
    const HWACCELS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transcoding_inventory/hwaccels.txt"
    ));
    const ENCODERS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transcoding_inventory/encoders.txt"
    ));
    const DECODERS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transcoding_inventory/decoders.txt"
    ));
    const FILTERS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/transcoding_inventory/filters.txt"
    ));

    fn fixture_runtime(buildconf: &[u8]) -> RuntimeId {
        let normalized = super::super::runtime::build_configuration(buildconf)
            .expect("fixture build configuration");
        RuntimeId {
            install_digest: "11".repeat(32),
            ffmpeg_version: "7.1.4".to_owned(),
            jellyfin_revision: Some("3".to_owned()),
            build_configuration_digest: hex::encode(Sha256::digest(normalized)),
            pair_root_identity: "22".repeat(32),
        }
    }

    fn parse_fixture_inventory(
        version: &[u8],
        buildconf: &[u8],
        hwaccels: &[u8],
        encoders: &[u8],
        decoders: &[u8],
        filters: &[u8],
    ) -> Result<RuntimeInventory, InventoryError> {
        let runtime = fixture_runtime(buildconf);
        parse_inventory_outputs(
            RuntimeKind::Jellyfin,
            &runtime,
            StaticInventoryOutputs::new(version, buildconf, hwaccels, encoders, decoders, filters),
        )
    }

    #[test]
    fn parses_closed_inventory_components() {
        let parsed =
            parse_fixture_inventory(VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS)
                .expect("fixture inventory");

        assert!(parsed.accelerators.contains(&HardwareAccelerator::D3d11va));
        assert!(parsed.accelerators.contains(&HardwareAccelerator::Cuda));
        assert!(parsed.accelerators.contains(&HardwareAccelerator::Qsv));
        assert!(parsed.accelerators.contains(&HardwareAccelerator::Vaapi));
        assert!(
            parsed
                .accelerators
                .contains(&HardwareAccelerator::VideoToolbox)
        );
        assert!(parsed.decoders.contains(&DecoderComponent::BaseAv1));
        assert!(parsed.decoders.contains(&DecoderComponent::QsvAv1));
        assert!(parsed.decoders.contains(&DecoderComponent::CuvidAv1));
        assert!(parsed.encoders.contains(&EncoderComponent::QsvAv1));
        assert!(parsed.encoders.contains(&EncoderComponent::NvencAv1));
        assert!(parsed.encoders.contains(&EncoderComponent::VaapiAv1));
        assert!(parsed.encoders.contains(&EncoderComponent::AmfAv1));
        assert!(parsed.encoders.contains(&EncoderComponent::VideoToolboxAv1));
        assert!(parsed.filters.contains(&FilterComponent::HardwareUpload));
        assert!(parsed.filters.contains(&FilterComponent::ScaleCuda));
        assert_eq!(parsed.safe_version.ffmpeg.as_deref(), Some("7.1.4"));
        assert_eq!(parsed.safe_version.jellyfin_revision.as_deref(), Some("3"));
        assert!(parsed.unknown_counts.historical >= 4);
        assert!(parsed.unknown_counts.names >= 4);
    }

    #[test]
    fn exact_names_do_not_alias_directions_backends_or_codecs() {
        let parsed =
            parse_fixture_inventory(VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS)
                .expect("fixture inventory");

        assert_eq!(
            parsed.accelerators.len(),
            5,
            "duplicate accelerator is deduplicated"
        );
        assert_eq!(parsed.decoders.len(), 24);
        assert_eq!(parsed.encoders.len(), 18);
        assert_eq!(parsed.filters.len(), 14);
        assert!(parsed.decoders.contains(&DecoderComponent::BaseH264));
        assert!(parsed.decoders.contains(&DecoderComponent::BaseHevc));
        assert!(parsed.decoders.contains(&DecoderComponent::BaseAv1));
        assert!(parsed.encoders.contains(&EncoderComponent::AmfH264));
        assert!(parsed.decoders.contains(&DecoderComponent::V4l2m2mH264));
        assert!(parsed.encoders.contains(&EncoderComponent::V4l2m2mH264));
        assert_eq!(parsed.unknown_counts.historical, 5);
        assert_eq!(parsed.unknown_counts.names, 6);
    }

    #[test]
    fn rejects_non_utf8_bare_carriage_return_and_mutated_name_grammar() {
        let mut unknown = InventoryUnknownCounts::default();
        assert_eq!(
            parse_hwaccels(b"Hardware acceleration methods:\nqsv\n\xff\n", &mut unknown),
            Err(InventoryError::Malformed)
        );
        assert_eq!(
            parse_hwaccels(b"Hardware acceleration methods:\rqsv\n", &mut unknown),
            Err(InventoryError::Malformed)
        );
        assert_eq!(
            parse_decoders(b"Decoders:\n V..... h264-qsv bad\n", &mut unknown),
            Err(InventoryError::Malformed)
        );
    }

    #[test]
    fn line_count_and_line_length_bounds_are_exact() {
        let mut at_line_limit = String::from("Hardware acceleration methods:\n");
        at_line_limit.push_str(&"cuda\n".repeat(MAX_LINES - 1));
        assert!(
            parse_hwaccels(
                at_line_limit.as_bytes(),
                &mut InventoryUnknownCounts::default()
            )
            .is_ok()
        );
        at_line_limit.push_str("cuda\n");
        assert_eq!(
            parse_hwaccels(
                at_line_limit.as_bytes(),
                &mut InventoryUnknownCounts::default()
            ),
            Err(InventoryError::Bounds)
        );

        let exact_name = "x".repeat(MAX_LINE_BYTES);
        let exact_line = format!("Hardware acceleration methods:\n{exact_name}\n");
        assert!(
            parse_hwaccels(
                exact_line.as_bytes(),
                &mut InventoryUnknownCounts::default()
            )
            .is_ok()
        );
        let overlong_name = "x".repeat(MAX_LINE_BYTES + 1);
        let overlong_line = format!("Hardware acceleration methods:\n{overlong_name}\n");
        assert_eq!(
            parse_hwaccels(
                overlong_line.as_bytes(),
                &mut InventoryUnknownCounts::default()
            ),
            Err(InventoryError::Bounds)
        );

        let aggregate_overflow = format!(
            "Hardware acceleration methods:\n{}",
            "unknown_accelerator_name_1234567890\n".repeat(MAX_LINES - 1)
        );
        assert!(aggregate_overflow.len() > STDOUT_LIMIT);
        assert_eq!(
            parse_hwaccels(
                aggregate_overflow.as_bytes(),
                &mut InventoryUnknownCounts::default()
            ),
            Err(InventoryError::Bounds)
        );
    }

    #[test]
    fn unknown_flags_and_names_are_counted_but_inert() {
        let mut unknown = InventoryUnknownCounts::default();
        let decoders = parse_decoders(
            b"Decoders:\n Z..... h264_qsv unknown flag\n V..... h264_qsv_extra unknown name\n",
            &mut unknown,
        )
        .expect("unknown rows remain inert");

        assert!(decoders.is_empty());
        assert_eq!(unknown.flags, 1);
        assert_eq!(unknown.decoders, 2);
        assert_eq!(unknown.names, 1);
    }

    #[test]
    fn version_and_build_identity_must_match_private_session() {
        let runtime = fixture_runtime(BUILDCONF);
        let wrong_version = b"ffmpeg version 7.1.5-Jellyfin\n";
        assert_eq!(
            parse_inventory_outputs(
                RuntimeKind::Jellyfin,
                &runtime,
                StaticInventoryOutputs::new(
                    wrong_version,
                    BUILDCONF,
                    HWACCELS,
                    ENCODERS,
                    DECODERS,
                    FILTERS,
                ),
            ),
            Err(InventoryError::IdentityMismatch)
        );

        let mut wrong_build = runtime;
        wrong_build.build_configuration_digest = "00".repeat(32);
        assert_eq!(
            parse_inventory_outputs(
                RuntimeKind::Jellyfin,
                &wrong_build,
                StaticInventoryOutputs::new(
                    VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS,
                ),
            ),
            Err(InventoryError::IdentityMismatch)
        );
    }

    #[test]
    fn unsafe_public_tokens_become_null_without_weakening_identity() {
        let mut runtime = fixture_runtime(BUILDCONF);
        runtime.ffmpeg_version = "7/unsafe".to_owned();
        runtime.jellyfin_revision = Some("bad/revision".to_owned());
        let parsed = parse_inventory_outputs(
            RuntimeKind::Jellyfin,
            &runtime,
            StaticInventoryOutputs::new(
                b"ffmpeg version 7/unsafe-Jellyfin\n",
                BUILDCONF,
                HWACCELS,
                ENCODERS,
                DECODERS,
                FILTERS,
            ),
        )
        .expect("private identity still matches");

        assert_eq!(parsed.safe_version.ffmpeg, None);
        assert_eq!(parsed.safe_version.jellyfin_revision, None);
    }

    #[test]
    fn safe_public_token_bounds_are_exact() {
        let ffmpeg_at_limit = format!("7{}", "a".repeat(95));
        let revision_at_limit = format!("3{}", "b".repeat(63));
        assert_eq!(safe_token(&ffmpeg_at_limit, 96), Some(ffmpeg_at_limit));
        assert_eq!(safe_token(&revision_at_limit, 64), Some(revision_at_limit));
        assert_eq!(safe_token(&format!("7{}", "a".repeat(96)), 96), None);
        assert_eq!(safe_token(&format!("3{}", "b".repeat(64)), 64), None);
        assert_eq!(safe_token("-7.1.4", 96), None);
        assert_eq!(safe_token("7/1/4", 96), None);
    }

    #[test]
    fn raw_descriptions_and_private_runtime_fields_do_not_survive() {
        let runtime = fixture_runtime(BUILDCONF);
        let private_marker = "C:\\private\\inventory-secret";
        let decoders = format!("Decoders:\n V..... h264 {private_marker}\n");
        let inventory = parse_inventory_outputs(
            RuntimeKind::Jellyfin,
            &runtime,
            StaticInventoryOutputs::new(
                VERSION,
                BUILDCONF,
                HWACCELS,
                ENCODERS,
                decoders.as_bytes(),
                FILTERS,
            ),
        )
        .expect("description is not identity data");
        let debug = format!("{inventory:?}");
        assert!(!debug.contains(private_marker));
        assert!(!debug.contains(&runtime.pair_root_identity));
        assert!(!debug.contains("--enable-amf"));
    }

    #[test]
    fn runtime_kind_not_optional_revision_controls_version_matcher() {
        let mut explicit_jellyfin = fixture_runtime(BUILDCONF);
        explicit_jellyfin.jellyfin_revision = None;
        assert!(
            parse_inventory_outputs(
                RuntimeKind::Jellyfin,
                &explicit_jellyfin,
                StaticInventoryOutputs::new(
                    VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS,
                ),
            )
            .is_ok()
        );

        let software_version = b"ffmpeg version 7.1.4\n";
        assert!(
            parse_inventory_outputs(
                RuntimeKind::SoftwareCompatible,
                &explicit_jellyfin,
                StaticInventoryOutputs::new(
                    software_version,
                    BUILDCONF,
                    HWACCELS,
                    ENCODERS,
                    DECODERS,
                    FILTERS,
                ),
            )
            .is_ok()
        );
        assert!(
            parse_inventory_outputs(
                RuntimeKind::SoftwareCompatible,
                &explicit_jellyfin,
                StaticInventoryOutputs::new(
                    VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS,
                ),
            )
            .is_ok()
        );
        assert_eq!(
            parse_inventory_outputs(
                RuntimeKind::SoftwareCompatible,
                &explicit_jellyfin,
                StaticInventoryOutputs::new(
                    b"ffmpeg version 7.1.4-Other\n",
                    BUILDCONF,
                    HWACCELS,
                    ENCODERS,
                    DECODERS,
                    FILTERS,
                ),
            ),
            Err(InventoryError::IdentityMismatch)
        );
    }

    #[test]
    fn every_runtime_identity_field_changes_evidence() {
        let baseline = fixture_runtime(BUILDCONF);
        let expected = RuntimeEvidenceId::derive(&baseline).expect("baseline evidence ID");
        assert_eq!(
            hex::encode(expected.0),
            "0d98a7712c6bf8c649e75b09d073fa0772f00ed8722388ed6e048fe9b698003d"
        );
        for mutate in [
            |runtime: &mut RuntimeId| runtime.install_digest.push('a'),
            |runtime: &mut RuntimeId| runtime.ffmpeg_version.push('a'),
            |runtime: &mut RuntimeId| runtime.jellyfin_revision = Some("4".to_owned()),
            |runtime: &mut RuntimeId| runtime.build_configuration_digest.push('a'),
            |runtime: &mut RuntimeId| runtime.pair_root_identity.push('a'),
        ] {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(RuntimeEvidenceId::derive(&changed).unwrap(), expected);
        }

        let mut absent_revision = baseline.clone();
        absent_revision.jellyfin_revision = None;
        assert_ne!(
            RuntimeEvidenceId::derive(&absent_revision).unwrap(),
            expected
        );
        assert_eq!(format!("{expected:?}"), "RuntimeEvidenceId([redacted])");
    }

    #[test]
    fn runtime_identity_fields_are_bounded_before_hashing() {
        let mut runtime = fixture_runtime(BUILDCONF);
        runtime.pair_root_identity = "x".repeat(MAX_RUNTIME_ID_FIELD_BYTES + 1);
        assert_eq!(
            RuntimeEvidenceId::derive(&runtime),
            Err(InventoryError::Bounds)
        );
    }

    struct FakeInventorySession {
        original: RuntimeId,
        changed: RuntimeId,
        invocations: Mutex<Vec<(InventoryQuery, Vec<OsString>)>>,
        failure: Option<(InventoryQuery, InventoryError)>,
        stall: Option<InventoryQuery>,
        change_after_complete: bool,
        change_identity: AtomicBool,
    }

    impl FakeInventorySession {
        fn success() -> Self {
            let original = fixture_runtime(BUILDCONF);
            let mut changed = original.clone();
            changed.install_digest.push('x');
            Self {
                original,
                changed,
                invocations: Mutex::new(Vec::new()),
                failure: None,
                stall: None,
                change_after_complete: false,
                change_identity: AtomicBool::new(false),
            }
        }

        fn output(query: InventoryQuery) -> Vec<u8> {
            match query {
                InventoryQuery::Version => VERSION.to_vec(),
                InventoryQuery::BuildConfiguration => BUILDCONF.to_vec(),
                InventoryQuery::HardwareAccelerators => HWACCELS.to_vec(),
                InventoryQuery::Encoders => ENCODERS.to_vec(),
                InventoryQuery::Decoders => DECODERS.to_vec(),
                InventoryQuery::Filters => FILTERS.to_vec(),
            }
        }
    }

    #[async_trait]
    impl InventorySession for FakeInventorySession {
        fn id(&self) -> &RuntimeId {
            if self.change_identity.load(Ordering::Acquire) {
                &self.changed
            } else {
                &self.original
            }
        }

        fn kind(&self) -> RuntimeKind {
            RuntimeKind::Jellyfin
        }

        async fn execute(
            &self,
            query: InventoryQuery,
            command: RuntimeCommand,
            cancellation: &CancellationToken,
        ) -> Result<InventoryCommandOutput, InventoryError> {
            self.invocations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((query, command.args().to_vec()));
            if self.stall == Some(query) {
                cancellation.cancelled().await;
                return Err(InventoryError::Cancelled);
            }
            if let Some((failed_query, error)) = self.failure
                && failed_query == query
            {
                return Err(error);
            }
            if query == InventoryQuery::Filters && self.change_after_complete {
                self.change_identity.store(true, Ordering::Release);
            }
            Ok(InventoryCommandOutput {
                stdout: Self::output(query),
            })
        }
    }

    #[tokio::test]
    async fn one_session_executes_exactly_six_closed_commands() {
        let session = FakeInventorySession::success();
        let inventory =
            collect_with_deadline(&session, CancellationToken::new(), Duration::from_secs(1))
                .await
                .expect("inventory succeeds");

        assert_eq!(
            inventory.runtime_id,
            RuntimeEvidenceId::derive(&session.original).unwrap()
        );
        let invocations = session
            .invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(invocations.len(), 6);
        for ((query, arguments), expected) in invocations.iter().zip(InventoryQuery::ALL) {
            assert_eq!(*query, expected);
            assert_eq!(
                arguments,
                &[
                    OsString::from("-nostdin"),
                    OsString::from("-hide_banner"),
                    OsString::from(expected.argument()),
                ]
            );
        }
    }

    #[tokio::test]
    async fn failure_stops_collection_without_partial_publication() {
        for error in [
            InventoryError::ProcessFailed,
            InventoryError::Bounds,
            InventoryError::Timeout,
            InventoryError::RuntimeChanged,
        ] {
            let mut session = FakeInventorySession::success();
            session.failure = Some((InventoryQuery::Encoders, error));
            assert_eq!(
                collect_with_deadline(&session, CancellationToken::new(), Duration::from_secs(1),)
                    .await,
                Err(error)
            );
            assert_eq!(
                session
                    .invocations
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len(),
                4
            );
        }
    }

    #[tokio::test]
    async fn cancellation_and_phase_timeout_cancel_the_active_command() {
        let mut cancelled = FakeInventorySession::success();
        cancelled.stall = Some(InventoryQuery::Version);
        let token = CancellationToken::new();
        token.cancel();
        assert_eq!(
            collect_with_deadline(&cancelled, token, Duration::from_secs(1)).await,
            Err(InventoryError::Cancelled)
        );

        let mut timed_out = FakeInventorySession::success();
        timed_out.stall = Some(InventoryQuery::Version);
        assert_eq!(
            collect_with_deadline(
                &timed_out,
                CancellationToken::new(),
                Duration::from_millis(10),
            )
            .await,
            Err(InventoryError::Timeout)
        );
        assert_eq!(
            timed_out
                .invocations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn session_identity_change_invalidates_the_complete_phase() {
        let mut session = FakeInventorySession::success();
        session.change_after_complete = true;
        assert_eq!(
            collect_with_deadline(&session, CancellationToken::new(), Duration::from_secs(1),)
                .await,
            Err(InventoryError::RuntimeChanged)
        );
    }

    #[test]
    fn production_source_remains_behind_the_static_inventory_trait() {
        fn accepts_source<T: StaticInventorySource>(_source: T) {}
        accepts_source(PairedRuntimeInventorySource);
        let _mapper = coarse_candidates;
        assert_eq!(PHASE_DEADLINE, Duration::from_secs(60));
    }

    fn device_id(index: u16) -> DeviceId {
        let mut bytes = [0u8; 20];
        bytes[..2].copy_from_slice(&index.to_be_bytes());
        DeviceId::from_hmac_prefix(bytes)
    }

    fn backends(values: &[BackendKind]) -> BTreeSet<BackendKind> {
        values.iter().copied().collect()
    }

    #[test]
    fn coarse_candidates_are_backend_codec_and_direction_specific() {
        let inventory =
            parse_fixture_inventory(VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS)
                .expect("fixture inventory");
        let devices = [
            (
                device_id(1),
                DeviceClass::Integrated,
                backends(&[BackendKind::Qsv, BackendKind::D3d11va]),
            ),
            (
                device_id(2),
                DeviceClass::Discrete,
                backends(&[BackendKind::Cuda, BackendKind::Nvenc]),
            ),
            (
                device_id(3),
                DeviceClass::Discrete,
                backends(&[BackendKind::D3d11va, BackendKind::Amf]),
            ),
            (
                device_id(4),
                DeviceClass::Unknown,
                backends(&[BackendKind::Vaapi]),
            ),
            (
                device_id(5),
                DeviceClass::Unknown,
                backends(&[BackendKind::VideoToolbox]),
            ),
            (
                device_id(6),
                DeviceClass::Unknown,
                backends(&[BackendKind::V4l2m2m]),
            ),
            (
                device_id(7),
                DeviceClass::Virtual,
                backends(&[BackendKind::Qsv]),
            ),
            (
                device_id(8),
                DeviceClass::Software,
                backends(&[BackendKind::Qsv]),
            ),
        ];
        let candidates = coarse_candidates_from(
            RuntimeKind::Jellyfin,
            &inventory,
            devices
                .iter()
                .map(|(id, class, backends)| (id, *class, backends)),
        )
        .expect("bounded candidates");

        assert_eq!(candidates.len(), 51);
        assert!(candidates.contains(&CoarseCandidate {
            device: device_id(1),
            backend: BackendKind::Qsv,
            codec: ListedCodec::Av1,
            direction: ListedDirection::Decode,
        }));
        assert!(candidates.contains(&CoarseCandidate {
            device: device_id(1),
            backend: BackendKind::Qsv,
            codec: ListedCodec::Av1,
            direction: ListedDirection::Encode,
        }));
        assert!(candidates.contains(&CoarseCandidate {
            device: device_id(2),
            backend: BackendKind::Cuda,
            codec: ListedCodec::Vc1,
            direction: ListedDirection::Decode,
        }));
        assert!(candidates.contains(&CoarseCandidate {
            device: device_id(2),
            backend: BackendKind::Nvenc,
            codec: ListedCodec::Av1,
            direction: ListedDirection::Encode,
        }));
        assert!(candidates.contains(&CoarseCandidate {
            device: device_id(3),
            backend: BackendKind::Amf,
            codec: ListedCodec::Hevc,
            direction: ListedDirection::Encode,
        }));
        assert!(!candidates.iter().any(|candidate| {
            candidate.device == device_id(3)
                && candidate.backend == BackendKind::Amf
                && candidate.direction == ListedDirection::Decode
        }));
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.device == device_id(6))
        );
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.device == device_id(7))
        );
        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.device == device_id(8))
        );
    }

    #[test]
    fn software_compatible_inventory_never_creates_hardware_candidates() {
        let inventory =
            parse_fixture_inventory(VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS)
                .expect("fixture inventory");
        let id = device_id(1);
        let aliases = backends(&[BackendKind::Qsv, BackendKind::D3d11va]);
        let candidates = coarse_candidates_from(
            RuntimeKind::SoftwareCompatible,
            &inventory,
            [(&id, DeviceClass::Integrated, &aliases)],
        )
        .expect("software inventory remains reportable");
        assert!(candidates.is_empty());
    }

    #[test]
    fn missing_exact_direction_component_does_not_cross_authorize() {
        let mut inventory =
            parse_fixture_inventory(VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS)
                .expect("fixture inventory");
        inventory.decoders.remove(&DecoderComponent::QsvAv1);
        let id = device_id(1);
        let aliases = backends(&[BackendKind::Qsv]);
        let candidates = coarse_candidates_from(
            RuntimeKind::Jellyfin,
            &inventory,
            [(&id, DeviceClass::Integrated, &aliases)],
        )
        .expect("bounded candidates");
        assert!(!candidates.contains(&CoarseCandidate {
            device: id.clone(),
            backend: BackendKind::Qsv,
            codec: ListedCodec::Av1,
            direction: ListedDirection::Decode,
        }));
        assert!(candidates.contains(&CoarseCandidate {
            device: id,
            backend: BackendKind::Qsv,
            codec: ListedCodec::Av1,
            direction: ListedDirection::Encode,
        }));
    }

    #[test]
    fn candidate_limit_fails_on_the_1025th_distinct_row() {
        let inventory =
            parse_fixture_inventory(VERSION, BUILDCONF, HWACCELS, ENCODERS, DECODERS, FILTERS)
                .expect("fixture inventory");
        let devices = (0..114u16)
            .map(|index| {
                (
                    device_id(index),
                    DeviceClass::Integrated,
                    backends(&[BackendKind::Qsv]),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            coarse_candidates_from(
                RuntimeKind::Jellyfin,
                &inventory,
                devices
                    .iter()
                    .map(|(id, class, backends)| (id, *class, backends)),
            ),
            Err(InventoryError::Bounds)
        );
    }
}
