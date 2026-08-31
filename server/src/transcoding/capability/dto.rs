use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use crate::transcoding::{
    BackendKind, CapabilityState, ChromaSubsampling, ColorMatrix, ColorPrimaries, ColorRange,
    ColorTransfer, DeviceClass, DeviceId, FieldOrder, FrameRateClass, InputVideoCodec,
    KeyframeStrategy, OutputVideoCodec, PixelFormat, RationalRate, VideoProfile,
    device::{DeviceAvailability, TranscodingDevice, Vendor},
    inventory::{
        CoarseCandidate, DecoderComponent, EncoderComponent, FilterComponent, HardwareAccelerator,
        ListedCodec, ListedDirection, RuntimeInventory,
    },
    runtime::RuntimeKind,
};

use super::{
    key::{
        BitDepth, CapabilityDirection, CodecLevel, CodedDimensionBucket, FrameRateBucket, HdrMode,
        InputVideoSignature, OutputContainerContract, OutputVideoSignature, PipelineRequirements,
        RequiredFilter, RequiredTransfer, RequiredTransform, SafeCapabilityKeyView,
        SegmentationContract,
    },
    registry::{
        RefreshCause, RefreshMetadata, RefreshOutcomeReason, RefreshState, RegistryPublication,
        SnapshotFreshness,
    },
    state::{
        EvidenceObservation, EvidenceOutcome, EvidenceReason, EvidenceRecord, EvidenceTarget,
        StateNow, TerminalObservation,
    },
    storage::StorageStatus,
};

const SCHEMA_VERSION: u8 = 1;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_SERIALIZED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DtoError {
    Bounds,
    ResponseTooLarge,
    UnsupportedSnapshot,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CapabilitiesDto {
    schema_version: u8,
    freshness: FreshnessDto,
    identity_epoch: u64,
    publication_revision: u64,
    runtime: RuntimeDto,
    software_baseline: SoftwareBaselineDto,
    devices: Vec<DeviceDto>,
    runtime_components: RuntimeComponentsDto,
    listed_candidates: Vec<ListedCandidateDto>,
    evidence_rows: Vec<EvidenceRowDto>,
    storage: StorageDto,
    refresh: RefreshDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RefreshAcceptedDto {
    schema_version: u8,
    refresh: RefreshDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuntimeDto {
    status: RuntimeStatusDto,
    version: Option<String>,
    jellyfin_revision: Option<String>,
    platform: RuntimePlatformDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SoftwareBaselineDto {
    state: SoftwareBaselineStateDto,
    reason: SoftwareBaselineReasonDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuntimeComponentsDto {
    hardware_accelerators: Vec<HardwareAccelerator>,
    decoders: Vec<DecoderComponent>,
    encoders: Vec<EncoderComponent>,
    filters: Vec<FilterComponent>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeviceDto {
    id: DeviceId,
    name: String,
    vendor: Vendor,
    class: DeviceClass,
    availability: DeviceAvailability,
    driver_status: DriverStatusDto,
    backends: Vec<BackendKind>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ListedCandidateDto {
    device_id: DeviceId,
    backend: BackendKind,
    codec: ListedCodec,
    direction: ListedDirection,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceRowDto {
    signature: SafeSignatureDto,
    state: CapabilityState,
    reason: Option<EvidenceReason>,
    observations: Vec<ObservationDto>,
    terminal: Option<TerminalDto>,
    circuit: Option<CircuitDto>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SafeSignatureDto {
    device_id: DeviceId,
    backend: BackendKind,
    direction: CapabilityDirection,
    input: Option<VideoSignatureDto>,
    output: Option<VideoSignatureDto>,
    transforms: Vec<RequiredTransform>,
    transfers: Vec<RequiredTransfer>,
    filters: Vec<RequiredFilter>,
    container: Option<OutputContainerContract>,
    output_time_base: Option<RationalDto>,
    segmented: Option<SegmentedSignatureDto>,
    copy_remux: Option<CopyRemuxDto>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VideoSignatureDto {
    codec: VideoCodecDto,
    profile: VideoProfile,
    level: CodecLevel,
    pixel_format: PixelFormat,
    bit_depth: BitDepth,
    chroma: ChromaSubsampling,
    color_range: ColorRange,
    color_primaries: ColorPrimaries,
    color_transfer: ColorTransfer,
    color_matrix: ColorMatrix,
    hdr_mode: HdrMode,
    field_order: Option<FieldOrder>,
    coded_width_bucket: CodedDimensionBucket,
    coded_height_bucket: CodedDimensionBucket,
    frame_rate_bucket: FrameRateBucket,
    frame_rate_class: FrameRateClass,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum VideoCodecDto {
    H264,
    Hevc,
    Av1,
    Vp9,
    Mpeg2,
    Vc1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RationalDto {
    numerator: u32,
    denominator: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SegmentedSignatureDto {
    frame_rate: RationalDto,
    frame_rate_class: FrameRateClass,
    segment_duration_ms: u32,
    output_time_base: RationalDto,
    keyframe_strategy: KeyframeStrategy,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CopyRemuxDto {
    source_specific: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ObservationDto {
    target: EvidenceTarget,
    observed_at: String,
    duration_ms: u64,
    expires_at: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TerminalDto {
    target: EvidenceTarget,
    kind: TerminalKindDto,
    observed_at: String,
    duration_ms: u64,
    expires_at: String,
    reason: EvidenceReason,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum TerminalKindDto {
    Unsupported,
    PermanentFailure,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CircuitDto {
    failure_streak: u64,
    cooldown_until: String,
    reason: EvidenceReason,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StorageDto {
    status: StorageStatusDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RefreshDto {
    id: Option<u64>,
    cause: Option<RefreshCauseDto>,
    state: RefreshStateDto,
    started_at: Option<String>,
    completed_at: Option<String>,
    outcome_reason: Option<RefreshOutcomeReasonDto>,
    persistence_status: StorageStatusDto,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum FreshnessDto {
    Uninitialized,
    Refreshing,
    Fresh,
    Stale,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum RuntimeStatusDto {
    Unavailable,
    Jellyfin,
    SoftwareCompatible,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum SoftwareBaselineStateDto {
    NotPresent,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum SoftwareBaselineReasonDto {
    VerificationNotImplemented,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum RuntimePlatformDto {
    Windows,
    Linux,
    Macos,
    Unsupported,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum RefreshCauseDto {
    Startup,
    Manual,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum RefreshStateDto {
    Idle,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum RefreshOutcomeReasonDto {
    PlatformUnsupported,
    DeviceIdentityUnavailable,
    DeviceMappingAmbiguous,
    DeviceEnumerationFailed,
    RuntimeUnavailable,
    InventoryTimeout,
    InventoryOverflow,
    InventoryMalformed,
    InventoryProcessFailed,
    RefreshCancelled,
    RefreshFailed,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum StorageStatusDto {
    Uninitialized,
    Writable,
    ReadOnlyLocked,
    Unavailable,
    Invalid,
    Untrusted,
    PersistFailed,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum DriverStatusDto {
    Complete,
    Incomplete,
}

impl CapabilitiesDto {
    pub(super) fn project(
        publication: RegistryPublication,
        _now: StateNow,
    ) -> Result<Self, DtoError> {
        let snapshot = publication.snapshot;
        if snapshot.identity_epoch > MAX_SAFE_INTEGER
            || snapshot.publication_revision > MAX_SAFE_INTEGER
        {
            return Err(DtoError::Bounds);
        }
        let (runtime, runtime_components) = match snapshot.runtime.as_ref() {
            Some(runtime) => (
                RuntimeDto::project(runtime),
                RuntimeComponentsDto::project(runtime),
            ),
            None => (RuntimeDto::unavailable(), RuntimeComponentsDto::empty()),
        };
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            freshness: snapshot.freshness.into(),
            identity_epoch: snapshot.identity_epoch,
            publication_revision: snapshot.publication_revision,
            runtime,
            software_baseline: SoftwareBaselineDto {
                state: SoftwareBaselineStateDto::NotPresent,
                reason: SoftwareBaselineReasonDto::VerificationNotImplemented,
            },
            devices: snapshot.devices.iter().map(DeviceDto::project).collect(),
            runtime_components,
            listed_candidates: snapshot
                .candidates
                .iter()
                .map(ListedCandidateDto::project)
                .collect(),
            evidence_rows: snapshot
                .evidence
                .values()
                .map(|record| EvidenceRowDto::project(record, _now))
                .filter_map(Result::transpose)
                .collect::<Result<Vec<_>, _>>()?,
            storage: StorageDto {
                status: publication.refresh.persistence_status.into(),
            },
            refresh: RefreshDto::project(publication.refresh)?,
        })
    }

    pub(crate) fn serialize_bounded(&self) -> Result<Vec<u8>, DtoError> {
        let mut writer = BoundedWriter::new(MAX_SERIALIZED_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|_| DtoError::ResponseTooLarge)?;
        Ok(writer.into_inner())
    }
}

impl RefreshAcceptedDto {
    pub(super) fn project_running(
        mut refresh: RefreshMetadata,
        expected_id: u64,
    ) -> Result<Self, DtoError> {
        if refresh.id != Some(expected_id) || refresh.started_at.is_none() {
            return Err(DtoError::UnsupportedSnapshot);
        }
        refresh.state = RefreshState::Running;
        refresh.completed_at = None;
        refresh.outcome_reason = None;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            refresh: RefreshDto::project(refresh)?,
        })
    }

    pub(crate) fn serialize_bounded(&self) -> Result<Vec<u8>, DtoError> {
        let mut writer = BoundedWriter::new(MAX_SERIALIZED_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|_| DtoError::ResponseTooLarge)?;
        Ok(writer.into_inner())
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let new_length = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .filter(|length| *length <= self.limit)
            .ok_or_else(|| io::Error::other("bounded response exceeded"))?;
        self.bytes
            .try_reserve_exact(new_length.saturating_sub(self.bytes.len()))
            .map_err(|_| io::Error::other("bounded response allocation failed"))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl RuntimeDto {
    fn unavailable() -> Self {
        Self {
            status: RuntimeStatusDto::Unavailable,
            version: None,
            jellyfin_revision: None,
            platform: current_platform(),
        }
    }

    fn project(runtime: &RuntimeInventory) -> Self {
        Self {
            status: match runtime.runtime_kind {
                RuntimeKind::Jellyfin => RuntimeStatusDto::Jellyfin,
                RuntimeKind::SoftwareCompatible => RuntimeStatusDto::SoftwareCompatible,
            },
            version: runtime.safe_version.ffmpeg.clone(),
            jellyfin_revision: runtime.safe_version.jellyfin_revision.clone(),
            platform: current_platform(),
        }
    }
}

impl RuntimeComponentsDto {
    fn empty() -> Self {
        Self {
            hardware_accelerators: Vec::new(),
            decoders: Vec::new(),
            encoders: Vec::new(),
            filters: Vec::new(),
        }
    }

    fn project(runtime: &RuntimeInventory) -> Self {
        Self {
            hardware_accelerators: runtime.accelerators.iter().copied().collect(),
            decoders: runtime.decoders.iter().copied().collect(),
            encoders: runtime.encoders.iter().copied().collect(),
            filters: runtime.filters.iter().copied().collect(),
        }
    }
}

impl DeviceDto {
    fn project(device: &TranscodingDevice) -> Self {
        Self {
            id: device.id.clone(),
            name: device.display_name.as_str().to_owned(),
            vendor: device.vendor,
            class: device.class,
            availability: device.availability,
            driver_status: if device.driver_identity.is_persistable() {
                DriverStatusDto::Complete
            } else {
                DriverStatusDto::Incomplete
            },
            backends: device.backends.iter().copied().collect(),
        }
    }
}

impl ListedCandidateDto {
    fn project(candidate: &CoarseCandidate) -> Self {
        Self {
            device_id: candidate.device.clone(),
            backend: candidate.backend,
            codec: candidate.codec,
            direction: candidate.direction,
        }
    }
}

impl EvidenceRowDto {
    fn project(record: &EvidenceRecord, now: StateNow) -> Result<Option<Self>, DtoError> {
        let mut projected = record.clone();
        let Some(state) =
            projected.project(now, super::state::ProjectionContext::new(false, false))
        else {
            return Ok(None);
        };
        let terminal = projected
            .terminal
            .as_ref()
            .map(TerminalDto::project)
            .transpose()?;
        let circuit = if state == CapabilityState::CircuitOpen {
            projected
                .failure_history
                .as_ref()
                .and_then(|history| history.cooldown_until.map(|until| (history, until)))
                .map(|(history, until)| {
                    Ok(CircuitDto {
                        failure_streak: u64::from(history.streak),
                        cooldown_until: format_timestamp(until)?,
                        reason: history.reason,
                    })
                })
                .transpose()?
        } else {
            None
        };
        let reason = terminal
            .as_ref()
            .map(|terminal| terminal.reason)
            .or_else(|| circuit.as_ref().map(|circuit| circuit.reason));
        let observations = [
            projected.correctness.as_ref(),
            projected.realtime.as_ref(),
            projected.segmented.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(ObservationDto::project)
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Self {
            signature: SafeSignatureDto::project(projected.key.safe_view())?,
            state,
            reason,
            observations,
            terminal,
            circuit,
        }))
    }
}

impl SafeSignatureDto {
    fn project(view: SafeCapabilityKeyView<'_>) -> Result<Self, DtoError> {
        let (transforms, transfers, filters, container, output_time_base) = view
            .requirements
            .map(PipelineRequirementsDtoView::from)
            .unwrap_or_default()
            .into_parts();
        Ok(Self {
            device_id: view.device.clone(),
            backend: view.backend,
            direction: view.direction,
            input: view.input.map(VideoSignatureDto::from_input).transpose()?,
            output: view.output.map(VideoSignatureDto::from_output),
            transforms,
            transfers,
            filters,
            container: container.or(view.copy_container),
            output_time_base,
            segmented: view.segmentation.map(SegmentedSignatureDto::project),
            copy_remux: (view.direction == CapabilityDirection::CopyRemux).then_some(
                CopyRemuxDto {
                    source_specific: true,
                },
            ),
        })
    }
}

#[derive(Default)]
struct PipelineRequirementsDtoView {
    transforms: Vec<RequiredTransform>,
    transfers: Vec<RequiredTransfer>,
    filters: Vec<RequiredFilter>,
    container: Option<OutputContainerContract>,
    output_time_base: Option<RationalDto>,
}

impl From<&PipelineRequirements> for PipelineRequirementsDtoView {
    fn from(value: &PipelineRequirements) -> Self {
        Self {
            transforms: value.transforms.clone(),
            transfers: value.transfers.clone(),
            filters: value.filters.clone(),
            container: value.container,
            output_time_base: value.output_time_base.map(RationalDto::project),
        }
    }
}

impl PipelineRequirementsDtoView {
    #[allow(clippy::type_complexity)]
    fn into_parts(
        self,
    ) -> (
        Vec<RequiredTransform>,
        Vec<RequiredTransfer>,
        Vec<RequiredFilter>,
        Option<OutputContainerContract>,
        Option<RationalDto>,
    ) {
        (
            self.transforms,
            self.transfers,
            self.filters,
            self.container,
            self.output_time_base,
        )
    }
}

impl VideoSignatureDto {
    fn from_input(value: &InputVideoSignature) -> Result<Self, DtoError> {
        Ok(Self {
            codec: VideoCodecDto::try_from(value.codec)?,
            profile: value.profile,
            level: value.level,
            pixel_format: value.pixel_format,
            bit_depth: value.bit_depth,
            chroma: value.chroma,
            color_range: value.color.range,
            color_primaries: value.color.primaries,
            color_transfer: value.color.transfer,
            color_matrix: value.color.matrix,
            hdr_mode: value.color.hdr,
            field_order: Some(value.field_order),
            coded_width_bucket: value.resolution.width,
            coded_height_bucket: value.resolution.height,
            frame_rate_bucket: value.frame_rate,
            frame_rate_class: value.frame_rate_class,
        })
    }

    fn from_output(value: &OutputVideoSignature) -> Self {
        Self {
            codec: value.codec.into(),
            profile: value.profile,
            level: value.level,
            pixel_format: value.pixel_format,
            bit_depth: value.bit_depth,
            chroma: value.chroma,
            color_range: value.color.range,
            color_primaries: value.color.primaries,
            color_transfer: value.color.transfer,
            color_matrix: value.color.matrix,
            hdr_mode: value.color.hdr,
            field_order: None,
            coded_width_bucket: value.resolution.width,
            coded_height_bucket: value.resolution.height,
            frame_rate_bucket: value.frame_rate,
            frame_rate_class: value.frame_rate_class,
        }
    }
}

impl TryFrom<InputVideoCodec> for VideoCodecDto {
    type Error = DtoError;

    fn try_from(value: InputVideoCodec) -> Result<Self, Self::Error> {
        Ok(match value {
            InputVideoCodec::H264 => Self::H264,
            InputVideoCodec::Hevc => Self::Hevc,
            InputVideoCodec::Av1 => Self::Av1,
            InputVideoCodec::Vp9 => Self::Vp9,
            InputVideoCodec::Mpeg2 => Self::Mpeg2,
            InputVideoCodec::Vc1 => Self::Vc1,
            InputVideoCodec::OtherProbed => return Err(DtoError::UnsupportedSnapshot),
        })
    }
}

impl From<OutputVideoCodec> for VideoCodecDto {
    fn from(value: OutputVideoCodec) -> Self {
        match value {
            OutputVideoCodec::H264 => Self::H264,
            OutputVideoCodec::Hevc => Self::Hevc,
            OutputVideoCodec::Av1 => Self::Av1,
        }
    }
}

impl RationalDto {
    fn project(value: RationalRate) -> Self {
        Self {
            numerator: value.numerator(),
            denominator: value.denominator().get(),
        }
    }
}

impl SegmentedSignatureDto {
    fn project(value: &SegmentationContract) -> Self {
        Self {
            frame_rate: RationalDto::project(value.exact_frame_rate),
            frame_rate_class: value.frame_rate_class,
            segment_duration_ms: value.segment_duration_ms.get(),
            output_time_base: RationalDto::project(value.output_time_base),
            keyframe_strategy: value.keyframe_strategy,
        }
    }
}

impl ObservationDto {
    fn project(value: &EvidenceObservation) -> Result<Self, DtoError> {
        if value.duration_ms > MAX_SAFE_INTEGER {
            return Err(DtoError::Bounds);
        }
        Ok(Self {
            target: value.target,
            observed_at: format_timestamp(value.observed_at)?,
            duration_ms: value.duration_ms,
            expires_at: format_timestamp(value.expires_at)?,
        })
    }
}

impl TerminalDto {
    fn project(value: &TerminalObservation) -> Result<Self, DtoError> {
        if value.duration_ms > MAX_SAFE_INTEGER {
            return Err(DtoError::Bounds);
        }
        let kind = match value.outcome {
            EvidenceOutcome::Unsupported => TerminalKindDto::Unsupported,
            EvidenceOutcome::PermanentFailure => TerminalKindDto::PermanentFailure,
            _ => return Err(DtoError::UnsupportedSnapshot),
        };
        Ok(Self {
            target: value.target,
            kind,
            observed_at: format_timestamp(value.observed_at)?,
            duration_ms: value.duration_ms,
            expires_at: format_timestamp(value.expires_at)?,
            reason: value.reason,
        })
    }
}

impl RefreshDto {
    fn project(value: RefreshMetadata) -> Result<Self, DtoError> {
        if value.id.is_some_and(|id| id > MAX_SAFE_INTEGER) {
            return Err(DtoError::Bounds);
        }
        Ok(Self {
            id: value.id,
            cause: value.cause.map(Into::into),
            state: value.state.into(),
            started_at: value.started_at.map(format_timestamp).transpose()?,
            completed_at: value.completed_at.map(format_timestamp).transpose()?,
            outcome_reason: value.outcome_reason.map(Into::into),
            persistence_status: value.persistence_status.into(),
        })
    }
}

fn format_timestamp(value: super::state::EvidenceTimestamp) -> Result<String, DtoError> {
    let milliseconds = i64::try_from(value.milliseconds()).map_err(|_| DtoError::Bounds)?;
    DateTime::<Utc>::from_timestamp_millis(milliseconds)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok_or(DtoError::Bounds)
}

impl From<SnapshotFreshness> for FreshnessDto {
    fn from(value: SnapshotFreshness) -> Self {
        match value {
            SnapshotFreshness::Uninitialized => Self::Uninitialized,
            SnapshotFreshness::Refreshing => Self::Refreshing,
            SnapshotFreshness::Fresh => Self::Fresh,
            SnapshotFreshness::Stale => Self::Stale,
        }
    }
}

impl From<RefreshCause> for RefreshCauseDto {
    fn from(value: RefreshCause) -> Self {
        match value {
            RefreshCause::Startup => Self::Startup,
            RefreshCause::Manual => Self::Manual,
        }
    }
}

impl From<RefreshState> for RefreshStateDto {
    fn from(value: RefreshState) -> Self {
        match value {
            RefreshState::Idle => Self::Idle,
            RefreshState::Running => Self::Running,
            RefreshState::Succeeded => Self::Succeeded,
            RefreshState::Failed => Self::Failed,
            RefreshState::Cancelled => Self::Cancelled,
        }
    }
}

impl From<RefreshOutcomeReason> for RefreshOutcomeReasonDto {
    fn from(value: RefreshOutcomeReason) -> Self {
        match value {
            RefreshOutcomeReason::PlatformUnsupported => Self::PlatformUnsupported,
            RefreshOutcomeReason::DeviceIdentityUnavailable => Self::DeviceIdentityUnavailable,
            RefreshOutcomeReason::DeviceMappingAmbiguous => Self::DeviceMappingAmbiguous,
            RefreshOutcomeReason::DeviceEnumerationFailed => Self::DeviceEnumerationFailed,
            RefreshOutcomeReason::RuntimeUnavailable => Self::RuntimeUnavailable,
            RefreshOutcomeReason::InventoryTimeout => Self::InventoryTimeout,
            RefreshOutcomeReason::InventoryOverflow => Self::InventoryOverflow,
            RefreshOutcomeReason::InventoryMalformed => Self::InventoryMalformed,
            RefreshOutcomeReason::InventoryProcessFailed => Self::InventoryProcessFailed,
            RefreshOutcomeReason::RefreshCancelled => Self::RefreshCancelled,
            RefreshOutcomeReason::RefreshFailed => Self::RefreshFailed,
        }
    }
}

impl From<StorageStatus> for StorageStatusDto {
    fn from(value: StorageStatus) -> Self {
        match value {
            StorageStatus::Uninitialized => Self::Uninitialized,
            StorageStatus::Writable => Self::Writable,
            StorageStatus::ReadOnlyLocked => Self::ReadOnlyLocked,
            StorageStatus::Unavailable => Self::Unavailable,
            StorageStatus::Invalid => Self::Invalid,
            StorageStatus::Untrusted => Self::Untrusted,
            StorageStatus::PersistFailed => Self::PersistFailed,
        }
    }
}

const fn current_platform() -> RuntimePlatformDto {
    #[cfg(windows)]
    {
        RuntimePlatformDto::Windows
    }
    #[cfg(target_os = "linux")]
    {
        RuntimePlatformDto::Linux
    }
    #[cfg(target_os = "macos")]
    {
        RuntimePlatformDto::Macos
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        RuntimePlatformDto::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedWriter, CapabilitiesDto, DtoError};
    use crate::transcoding::capability::{
        key::CapabilityKey,
        registry::{
            CapabilityRegistry, RefreshCause, RefreshMetadata, RefreshOutcomeReason, RefreshState,
            test_snapshot_for_keys,
        },
        state::{
            EvidenceOutcome, EvidenceReason, EvidenceRecord, EvidenceTarget, EvidenceTimestamp,
            StateNow, VerificationMode, VerificationResult,
        },
    };
    use serde_json::json;
    use std::io::Write as _;
    use std::sync::Arc;

    use crate::transcoding::capability::storage::StorageStatus;

    #[tokio::test]
    async fn uninitialized_publication_has_the_exact_schema_one_shape() {
        let publication = CapabilityRegistry::ephemeral_for_test().publication().await;
        let now = StateNow::new(
            EvidenceTimestamp::new(1_700_000_000_000).expect("bounded timestamp"),
            0,
        )
        .expect("bounded clock");

        let dto = CapabilitiesDto::project(publication, now).expect("safe projection");
        let bytes = serde_json::to_vec(&dto).expect("serialize DTO");

        assert_eq!(
            bytes,
            br#"{"schemaVersion":1,"freshness":"uninitialized","identityEpoch":0,"publicationRevision":0,"runtime":{"status":"unavailable","version":null,"jellyfinRevision":null,"platform":"windows"},"softwareBaseline":{"state":"notPresent","reason":"verificationNotImplemented"},"devices":[],"runtimeComponents":{"hardwareAccelerators":[],"decoders":[],"encoders":[],"filters":[]},"listedCandidates":[],"evidenceRows":[],"storage":{"status":"unavailable"},"refresh":{"id":null,"cause":null,"state":"idle","startedAt":null,"completedAt":null,"outcomeReason":null,"persistenceStatus":"unavailable"}}"#
        );
    }

    #[tokio::test]
    async fn populated_publication_projects_only_safe_runtime_device_and_candidate_fields() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let key = CapabilityKey::complete_test_keys().remove(0);
        publication.snapshot = Arc::new(test_snapshot_for_keys(&[key]));
        let now = StateNow::from_test_minutes(0);

        let value = serde_json::to_value(
            CapabilitiesDto::project(publication, now).expect("safe projection"),
        )
        .expect("serialize DTO");

        assert_eq!(value["runtime"]["status"], "jellyfin");
        assert_eq!(value["runtime"]["version"], "7.1.4");
        assert_eq!(value["runtime"]["jellyfinRevision"], "3");
        assert_eq!(
            value["devices"],
            json!([{
                "id": "gpu1_REREREREREREREREREREREREREQ",
                "name": "Test GPU",
                "vendor": "other",
                "class": "unknown",
                "availability": "available",
                "driverStatus": "complete",
                "backends": ["qsv"]
            }])
        );
        assert_eq!(
            value["listedCandidates"],
            json!([{
                "deviceId": "gpu1_REREREREREREREREREREREREREQ",
                "backend": "qsv",
                "codec": "h264",
                "direction": "decode"
            }])
        );
        assert_eq!(
            value["runtimeComponents"]["filters"],
            json!(["hardwareMap", "scaleSoftware"])
        );
        let encoded = serde_json::to_string(&value).expect("serialize public value");
        for private_marker in [
            "runtimeId",
            "driverId",
            "locator",
            "installDigest",
            "pairRoot",
        ] {
            assert!(!encoded.contains(private_marker));
        }
    }

    #[tokio::test]
    async fn one_record_with_three_positive_targets_remains_one_evidence_row() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let key = CapabilityKey::complete_test_keys().remove(3);
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(key.clone());
        for (target, outcome) in [
            (
                EvidenceTarget::Correctness,
                EvidenceOutcome::CorrectnessPassed,
            ),
            (EvidenceTarget::Realtime, EvidenceOutcome::RealtimePassed),
            (
                EvidenceTarget::Segmented,
                EvidenceOutcome::CorrectnessPassed,
            ),
        ] {
            record
                .apply(
                    VerificationResult::for_test(
                        target,
                        outcome,
                        EvidenceReason::VerificationFailed,
                        0,
                    ),
                    VerificationMode::Active,
                    now,
                )
                .expect("valid positive evidence");
        }
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
        snapshot.evidence.insert(key, record);
        publication.snapshot = Arc::new(snapshot);

        let value = serde_json::to_value(
            CapabilitiesDto::project(publication, now).expect("safe projection"),
        )
        .expect("serialize DTO");

        assert_eq!(value["evidenceRows"].as_array().unwrap().len(), 1);
        let row = &value["evidenceRows"][0];
        assert_eq!(row["state"], "realtimeQualified");
        assert!(row["reason"].is_null());
        assert!(row["terminal"].is_null());
        assert!(row["circuit"].is_null());
        assert_eq!(
            row["observations"],
            json!([
                {
                    "target": "correctness",
                    "observedAt": "1970-01-01T00:00:00.000Z",
                    "durationMs": 100,
                    "expiresAt": "1970-01-02T00:00:00.000Z"
                },
                {
                    "target": "realtime",
                    "observedAt": "1970-01-01T00:00:00.000Z",
                    "durationMs": 100,
                    "expiresAt": "1970-01-02T00:00:00.000Z"
                },
                {
                    "target": "segmented",
                    "observedAt": "1970-01-01T00:00:00.000Z",
                    "durationMs": 100,
                    "expiresAt": "1970-01-02T00:00:00.000Z"
                }
            ])
        );
        assert_eq!(row["signature"]["direction"], "segmentedPipeline");
        assert_eq!(row["signature"]["input"]["codec"], "h264");
        assert_eq!(row["signature"]["output"]["codec"], "hevc");
        assert_eq!(row["signature"]["segmented"]["segmentDurationMs"], 6_000);
        assert!(row["signature"]["copyRemux"].is_null());
    }

    #[tokio::test]
    async fn copy_remux_projection_exposes_only_the_source_specific_marker() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let key = CapabilityKey::complete_test_keys().remove(4);
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(key.clone());
        record
            .apply(
                VerificationResult::for_test(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::CorrectnessPassed,
                    EvidenceReason::VerificationFailed,
                    0,
                ),
                VerificationMode::Active,
                now,
            )
            .expect("valid copy evidence");
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
        snapshot.evidence.insert(key, record);
        publication.snapshot = Arc::new(snapshot);

        let value = serde_json::to_value(
            CapabilitiesDto::project(publication, now).expect("safe projection"),
        )
        .expect("serialize DTO");
        let signature = &value["evidenceRows"][0]["signature"];

        assert_eq!(signature["direction"], "copyRemux");
        assert!(signature["input"].is_null());
        assert!(signature["output"].is_null());
        assert_eq!(signature["transforms"], json!([]));
        assert_eq!(signature["transfers"], json!([]));
        assert_eq!(signature["filters"], json!([]));
        assert_eq!(signature["container"], "mpegTsStream");
        assert!(signature["outputTimeBase"].is_null());
        assert!(signature["segmented"].is_null());
        assert_eq!(signature["copyRemux"], json!({"sourceSpecific": true}));

        let encoded = serde_json::to_string(&value).expect("serialize public value");
        for private_marker in [
            "sourceVersion",
            "selectedStreams",
            "sourceSignature",
            "sourceCodec",
            "sampleEntry",
            "boundaryAlgorithm",
        ] {
            assert!(!encoded.contains(private_marker));
        }
    }

    #[tokio::test]
    async fn circuit_projection_preserves_the_closed_failure_reason() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let key = CapabilityKey::complete_test_keys().remove(0);
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(key.clone());
        record
            .apply(
                VerificationResult::for_test(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::TemporaryFailure,
                    EvidenceReason::VerificationTimeout,
                    0,
                ),
                VerificationMode::Active,
                now,
            )
            .expect("valid temporary failure");
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
        snapshot.evidence.insert(key, record);
        publication.snapshot = Arc::new(snapshot);

        let value = serde_json::to_value(
            CapabilitiesDto::project(publication, now).expect("safe projection"),
        )
        .expect("serialize DTO");
        let row = &value["evidenceRows"][0];

        assert_eq!(row["state"], "circuitOpen");
        assert_eq!(row["reason"], "verificationTimeout");
        assert_eq!(
            row["circuit"],
            json!({
                "failureStreak": 1,
                "cooldownUntil": "1970-01-01T00:10:00.000Z",
                "reason": "verificationTimeout"
            })
        );
        assert_eq!(row["observations"], json!([]));
        assert!(row["terminal"].is_null());
    }

    #[tokio::test]
    async fn cleared_failure_history_without_public_evidence_is_omitted() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let key = CapabilityKey::complete_test_keys().remove(0);
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(key.clone());
        record
            .apply(
                VerificationResult::for_test(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::TemporaryFailure,
                    EvidenceReason::VerificationFailed,
                    0,
                ),
                VerificationMode::Active,
                now,
            )
            .expect("valid temporary failure");
        record.clear_cooldown_after_refresh(now);
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
        snapshot.evidence.insert(key, record);
        publication.snapshot = Arc::new(snapshot);

        let value = serde_json::to_value(
            CapabilitiesDto::project(publication, now).expect("safe projection"),
        )
        .expect("serialize DTO");

        assert_eq!(value["evidenceRows"], json!([]));
    }

    #[tokio::test]
    async fn terminal_evidence_uses_the_closed_terminal_shape() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let key = CapabilityKey::complete_test_keys().remove(0);
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(key.clone());
        record
            .apply(
                VerificationResult::for_test(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::Unsupported,
                    EvidenceReason::Unsupported,
                    0,
                ),
                VerificationMode::Active,
                now,
            )
            .expect("valid terminal evidence");
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&key));
        snapshot.evidence.insert(key, record);
        publication.snapshot = Arc::new(snapshot);

        let value = serde_json::to_value(
            CapabilitiesDto::project(publication, now).expect("safe projection"),
        )
        .expect("serialize DTO");
        let row = &value["evidenceRows"][0];

        assert_eq!(row["state"], "failed");
        assert_eq!(row["reason"], "unsupported");
        assert_eq!(
            row["terminal"],
            json!({
                "target": "correctness",
                "kind": "unsupported",
                "observedAt": "1970-01-01T00:00:00.000Z",
                "durationMs": 100,
                "expiresAt": "1970-01-02T00:00:00.000Z",
                "reason": "unsupported"
            })
        );
        assert!(row["circuit"].is_null());
    }

    #[tokio::test]
    async fn refresh_and_storage_views_use_exact_closed_tokens_and_timestamps() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let now = StateNow::from_test_minutes(0);
        for (status, expected) in [
            (StorageStatus::Uninitialized, "uninitialized"),
            (StorageStatus::Writable, "writable"),
            (StorageStatus::ReadOnlyLocked, "readOnlyLocked"),
            (StorageStatus::Unavailable, "unavailable"),
            (StorageStatus::Invalid, "invalid"),
            (StorageStatus::Untrusted, "untrusted"),
            (StorageStatus::PersistFailed, "persistFailed"),
        ] {
            let mut publication = registry.publication().await;
            publication.refresh = RefreshMetadata {
                state: RefreshState::Failed,
                id: Some(7),
                cause: Some(RefreshCause::Manual),
                started_at: Some(EvidenceTimestamp::new(1_700_000_000_123).unwrap()),
                completed_at: Some(EvidenceTimestamp::new(1_700_000_001_456).unwrap()),
                outcome_reason: Some(RefreshOutcomeReason::InventoryTimeout),
                persistence_status: status,
            };

            let value = serde_json::to_value(
                CapabilitiesDto::project(publication, now).expect("safe projection"),
            )
            .expect("serialize DTO");

            assert_eq!(value["storage"]["status"], expected);
            assert_eq!(value["refresh"]["persistenceStatus"], expected);
            assert_eq!(value["refresh"]["id"], 7);
            assert_eq!(value["refresh"]["cause"], "manual");
            assert_eq!(value["refresh"]["state"], "failed");
            assert_eq!(value["refresh"]["startedAt"], "2023-11-14T22:13:20.123Z");
            assert_eq!(value["refresh"]["completedAt"], "2023-11-14T22:13:21.456Z");
            assert_eq!(value["refresh"]["outcomeReason"], "inventoryTimeout");
        }
    }

    #[tokio::test]
    async fn golden_dto_round_trip_rejects_unknown_fields() {
        let dto = CapabilitiesDto::project(
            CapabilityRegistry::ephemeral_for_test().publication().await,
            StateNow::from_test_minutes(0),
        )
        .expect("safe projection");
        let bytes = serde_json::to_vec(&dto).expect("serialize DTO");
        let round_trip: CapabilitiesDto = serde_json::from_slice(&bytes).expect("exact schema");
        assert_eq!(serde_json::to_vec(&round_trip).unwrap(), bytes);

        let mut value = serde_json::to_value(dto).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("privateRuntimeId".to_owned(), json!("forbidden"));
        assert!(serde_json::from_value::<CapabilitiesDto>(value).is_err());
    }

    #[test]
    fn bounded_writer_never_grows_capacity_past_its_limit() {
        let mut writer = BoundedWriter::new(7);
        for _ in 0..7 {
            writer.write_all(b"x").expect("within bound");
            assert!(writer.bytes.capacity() <= 7);
        }
        assert!(writer.write_all(b"x").is_err());
        assert_eq!(writer.bytes, b"xxxxxxx");
    }

    #[tokio::test]
    async fn malformed_internal_signature_fails_closed_without_panicking() {
        let registry = CapabilityRegistry::ephemeral_for_test();
        let mut publication = registry.publication().await;
        let valid = CapabilityKey::complete_test_keys().remove(0);
        let invalid = valid.with_test_open_input_codec();
        let now = StateNow::from_test_minutes(0);
        let mut record = EvidenceRecord::new(invalid.clone());
        record
            .apply(
                VerificationResult::for_test(
                    EvidenceTarget::Correctness,
                    EvidenceOutcome::CorrectnessPassed,
                    EvidenceReason::VerificationFailed,
                    0,
                ),
                VerificationMode::Active,
                now,
            )
            .expect("state shape is independent of key validation");
        let mut snapshot = test_snapshot_for_keys(std::slice::from_ref(&valid));
        snapshot.evidence.insert(invalid, record);
        publication.snapshot = Arc::new(snapshot);

        assert_eq!(
            CapabilitiesDto::project(publication, now).err(),
            Some(DtoError::UnsupportedSnapshot)
        );
    }
}
