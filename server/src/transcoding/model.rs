use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, num::NonZeroU32};

const DEVICE_ID_PREFIX: &str = "gpu1_";
const DEVICE_ID_DIGEST_BYTES: usize = 20;
const DEVICE_ID_SUFFIX_BYTES: usize = 27;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
/// A validated version-one opaque public device identifier.
///
/// Arbitrary text cannot bypass public parsing:
///
/// ```compile_fail
/// use stream_server::transcoding::DeviceId;
///
/// let _ = DeviceId::new("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA");
/// ```
pub struct DeviceId(String);

impl DeviceId {
    pub fn parse_public(value: &str) -> Result<Self, ModelValidationError> {
        let Some(suffix) = value.strip_prefix(DEVICE_ID_PREFIX) else {
            return Err(ModelValidationError::new("invalid device id"));
        };
        if suffix.len() != DEVICE_ID_SUFFIX_BYTES {
            return Err(ModelValidationError::new("invalid device id"));
        }

        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(suffix)
            .map_err(|_| ModelValidationError::new("invalid device id"))?;
        let decoded: [u8; DEVICE_ID_DIGEST_BYTES] = decoded
            .try_into()
            .map_err(|_| ModelValidationError::new("invalid device id"))?;
        let canonical = Self::from_hmac_prefix(decoded);
        if canonical.as_str() != value {
            return Err(ModelValidationError::new("invalid device id"));
        }

        Ok(canonical)
    }

    pub(crate) fn from_hmac_prefix(value: [u8; DEVICE_ID_DIGEST_BYTES]) -> Self {
        Self(format!(
            "{DEVICE_ID_PREFIX}{}",
            BASE64_URL_SAFE_NO_PAD.encode(value)
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_public(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceClass {
    Integrated,
    Discrete,
    Virtual,
    Software,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendKind {
    Amf,
    Cuda,
    D3d11va,
    Nvenc,
    Qsv,
    Vaapi,
    VideoToolbox,
    V4l2m2m,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityState {
    Listed,
    CorrectnessVerified,
    RealtimeQualified,
    Failed,
    CircuitOpen,
    AdministrativelyDisabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AccelerationMode {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "software")]
    Software,
    #[serde(rename = "prefer-iGPU")]
    PreferIgpu,
    #[serde(rename = "prefer-dGPU")]
    PreferDgpu,
    #[serde(rename = "device")]
    Device,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccelerationClass {
    Software,
    Partial,
    HardwareResident,
}

impl AccelerationClass {
    pub fn derive(stages: &[VideoStage]) -> Result<Self, ModelValidationError> {
        validate_complete_stage_graph(stages)?;

        let hardware = stages.iter().any(VideoStage::is_hardware);
        let software_or_transfer = stages.iter().any(VideoStage::requires_cpu_frames);
        let mut hardware_context = None;
        let compatible_hardware_context = stages.iter().all(|stage| match &stage.mode {
            StageMode::Software => true,
            StageMode::Hardware { backend, device } => match &hardware_context {
                Some((expected_backend, expected_device)) => {
                    expected_backend == backend && expected_device == device
                }
                None => {
                    hardware_context = Some((*backend, device.clone()));
                    true
                }
            },
        });

        Ok(
            match (hardware, software_or_transfer, compatible_hardware_context) {
                (false, _, _) => Self::Software,
                (true, false, true) => Self::HardwareResident,
                (true, _, _) => Self::Partial,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StageKind {
    Decode,
    Deinterlace,
    Rotate,
    Scale,
    PixelFormat,
    Color,
    Subtitle,
    Download,
    Upload,
    Encode,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StageMode {
    Software,
    Hardware {
        backend: BackendKind,
        device: DeviceId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoStage {
    kind: StageKind,
    mode: StageMode,
}

impl VideoStage {
    pub fn software(kind: StageKind) -> Self {
        Self {
            kind,
            mode: StageMode::Software,
        }
    }

    pub fn hardware(kind: StageKind, backend: BackendKind, device: DeviceId) -> Self {
        Self {
            kind,
            mode: StageMode::Hardware { backend, device },
        }
    }

    pub fn is_hardware(&self) -> bool {
        matches!(self.mode, StageMode::Hardware { .. })
    }

    pub fn requires_cpu_frames(&self) -> bool {
        matches!(self.mode, StageMode::Software)
            || matches!(self.kind, StageKind::Download | StageKind::Upload)
    }

    pub fn kind(&self) -> StageKind {
        self.kind
    }

    pub fn mode(&self) -> &StageMode {
        &self.mode
    }
}

/// A positive reduced rational frame rate.
///
/// Callers cannot bypass reduction with a struct literal:
///
/// ```compile_fail
/// use std::num::NonZeroU32;
/// use stream_server::transcoding::RationalRate;
///
/// let _ = RationalRate {
///     numerator: 60_000,
///     denominator: NonZeroU32::new(2_000).unwrap(),
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RationalRate {
    numerator: u32,
    denominator: NonZeroU32,
}

impl<'de> Deserialize<'de> for RationalRate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            numerator: u32,
            denominator: NonZeroU32,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.numerator, raw.denominator).map_err(serde::de::Error::custom)
    }
}

impl RationalRate {
    pub fn new(numerator: u32, denominator: NonZeroU32) -> Result<Self, ModelValidationError> {
        if numerator == 0 {
            return Err(ModelValidationError::new("rate numerator must be nonzero"));
        }

        let divisor = gcd(numerator, denominator.get());
        Ok(Self {
            numerator: numerator / divisor,
            denominator: NonZeroU32::new(denominator.get() / divisor)
                .expect("dividing a nonzero denominator by a common divisor keeps it nonzero"),
        })
    }

    pub fn numerator(&self) -> u32 {
        self.numerator
    }

    pub fn denominator(&self) -> NonZeroU32 {
        self.denominator
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FrameRateClass {
    Constant,
    Variable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RateControlIntent {
    Constant,
    ConstrainedVariable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PresetIntent {
    Speed,
    Balanced,
    Quality,
}

/// A validated, coherent rate-control envelope.
///
/// Fields are read-only after validation:
///
/// ```compile_fail
/// use stream_server::transcoding::{PresetIntent, RateControlEnvelope, RateControlIntent};
///
/// let _ = RateControlEnvelope {
///     intent: RateControlIntent::Constant,
///     target_video_bps: 0,
///     max_video_bps: 0,
///     buffer_bits: 0,
///     preset: PresetIntent::Balanced,
///     output_frame_rate: None,
///     width: 0,
///     height: 0,
///     audio_bps: 0,
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateControlEnvelope {
    intent: RateControlIntent,
    target_video_bps: u64,
    max_video_bps: u64,
    buffer_bits: u64,
    preset: PresetIntent,
    output_frame_rate: Option<RationalRate>,
    width: u32,
    height: u32,
    audio_bps: u64,
}

impl<'de> Deserialize<'de> for RateControlEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            intent: RateControlIntent,
            target_video_bps: u64,
            max_video_bps: u64,
            buffer_bits: u64,
            preset: PresetIntent,
            output_frame_rate: Option<RationalRate>,
            width: u32,
            height: u32,
            audio_bps: u64,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(
            raw.intent,
            raw.target_video_bps,
            raw.max_video_bps,
            raw.buffer_bits,
            raw.preset,
            raw.output_frame_rate,
            NonZeroU32::new(raw.width)
                .ok_or_else(|| serde::de::Error::custom("width must be nonzero"))?,
            NonZeroU32::new(raw.height)
                .ok_or_else(|| serde::de::Error::custom("height must be nonzero"))?,
            raw.audio_bps,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl RateControlEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: RateControlIntent,
        target_video_bps: u64,
        max_video_bps: u64,
        buffer_bits: u64,
        preset: PresetIntent,
        output_frame_rate: Option<RationalRate>,
        width: NonZeroU32,
        height: NonZeroU32,
        audio_bps: u64,
    ) -> Result<Self, ModelValidationError> {
        if target_video_bps == 0 {
            return Err(ModelValidationError::new(
                "target video bitrate must be nonzero",
            ));
        }
        if max_video_bps == 0 {
            return Err(ModelValidationError::new(
                "max video bitrate must be nonzero",
            ));
        }
        if max_video_bps < target_video_bps {
            return Err(ModelValidationError::new(
                "max video bitrate must be greater than or equal to target video bitrate",
            ));
        }
        if buffer_bits == 0 {
            return Err(ModelValidationError::new("buffer size must be nonzero"));
        }
        if audio_bps == 0 {
            return Err(ModelValidationError::new("audio bitrate must be nonzero"));
        }

        Ok(Self {
            intent,
            target_video_bps,
            max_video_bps,
            buffer_bits,
            preset,
            output_frame_rate,
            width: width.get(),
            height: height.get(),
            audio_bps,
        })
    }

    pub fn intent(&self) -> RateControlIntent {
        self.intent
    }

    pub fn target_video_bps(&self) -> u64 {
        self.target_video_bps
    }

    pub fn max_video_bps(&self) -> u64 {
        self.max_video_bps
    }

    pub fn buffer_bits(&self) -> u64 {
        self.buffer_bits
    }

    pub fn preset(&self) -> PresetIntent {
        self.preset
    }

    pub fn output_frame_rate(&self) -> Option<RationalRate> {
        self.output_frame_rate
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn audio_bps(&self) -> u64 {
        self.audio_bps
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyframeStrategy {
    FixedGop { frames: NonZeroU32 },
    TimeForced { segment_duration_ms: NonZeroU32 },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaDescriptor {
    source: super::source::ValidatedMediaSource,
    probe: super::probe::ProbeDocument,
}

impl MediaDescriptor {
    pub(crate) fn from_probe(
        source: super::source::ValidatedMediaSource,
        probe: super::probe::ProbeDocument,
    ) -> Self {
        Self { source, probe }
    }

    pub fn source(&self) -> &super::source::ValidatedMediaSource {
        &self.source
    }

    pub fn probe(&self) -> &super::probe::ProbeDocument {
        &self.probe
    }

    pub fn frame_rate_class(&self) -> FrameRateClass {
        self.probe
            .selected_video()
            .map(super::probe::VideoStreamDescriptor::frame_rate_class)
            .unwrap_or(FrameRateClass::Unknown)
    }

    pub fn media_signature(&self) -> String {
        self.probe.media_signature()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputContract {
    rate_control: RateControlEnvelope,
    keyframes: KeyframeStrategy,
}

impl OutputContract {
    pub fn new(rate_control: RateControlEnvelope, keyframes: KeyframeStrategy) -> Self {
        Self {
            rate_control,
            keyframes,
        }
    }

    pub fn rate_control(&self) -> &RateControlEnvelope {
        &self.rate_control
    }

    pub fn keyframes(&self) -> KeyframeStrategy {
        self.keyframes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodeRequest {
    source: super::source::ValidatedMediaSource,
    output: OutputContract,
    acceleration_mode: AccelerationMode,
}

impl TranscodeRequest {
    pub fn new(
        source: super::source::ValidatedMediaSource,
        output: OutputContract,
        acceleration_mode: AccelerationMode,
    ) -> Self {
        Self {
            source,
            output,
            acceleration_mode,
        }
    }

    pub fn source(&self) -> &super::source::ValidatedMediaSource {
        &self.source
    }

    pub fn output(&self) -> &OutputContract {
        &self.output
    }

    pub fn acceleration_mode(&self) -> AccelerationMode {
        self.acceleration_mode
    }
}

/// A plan whose stage graph and derived acceleration class are immutable.
///
/// Callers cannot replace its validated stage graph:
///
/// ```compile_fail
/// use stream_server::transcoding::{TranscodePlan, VideoStage};
///
/// fn replace_stages(plan: &mut TranscodePlan, stages: Vec<VideoStage>) {
///     plan.stages = stages;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodePlan {
    request: TranscodeRequest,
    stages: Vec<VideoStage>,
    acceleration_class: AccelerationClass,
}

impl TranscodePlan {
    pub fn new(
        request: TranscodeRequest,
        stages: Vec<VideoStage>,
    ) -> Result<Self, ModelValidationError> {
        let acceleration_class = AccelerationClass::derive(&stages)?;

        Ok(Self {
            request,
            stages,
            acceleration_class,
        })
    }

    pub fn acceleration_class(&self) -> AccelerationClass {
        self.acceleration_class
    }

    pub fn request(&self) -> &TranscodeRequest {
        &self.request
    }

    pub fn stages(&self) -> &[VideoStage] {
        &self.stages
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelValidationError {
    message: &'static str,
}

impl ModelValidationError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ModelValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for ModelValidationError {}

fn validate_complete_stage_graph(stages: &[VideoStage]) -> Result<(), ModelValidationError> {
    let decode_count = stages
        .iter()
        .filter(|stage| stage.kind == StageKind::Decode)
        .count();
    let encode_count = stages
        .iter()
        .filter(|stage| stage.kind == StageKind::Encode)
        .count();

    if stages.len() < 2
        || decode_count != 1
        || encode_count != 1
        || stages.first().map(VideoStage::kind) != Some(StageKind::Decode)
        || stages.last().map(VideoStage::kind) != Some(StageKind::Encode)
    {
        return Err(ModelValidationError::new(
            "video stage graph must start with one decode and end with one encode",
        ));
    }

    Ok(())
}

fn gcd(mut left: u32, mut right: u32) -> u32 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcoding::ValidatedMediaSource;
    use serde::{Serialize, de::DeserializeOwned};
    use std::num::NonZeroU32;

    fn round_trip<T>(value: T, json: &str)
    where
        T: Clone + Eq + std::fmt::Debug + Serialize + DeserializeOwned,
    {
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        assert_eq!(serde_json::from_str::<T>(json).unwrap(), value);
    }

    fn device(value: &str) -> DeviceId {
        DeviceId::parse_public(value).unwrap()
    }

    fn qsv_stages_with(kind: StageKind) -> Vec<VideoStage> {
        vec![
            VideoStage::hardware(
                StageKind::Decode,
                BackendKind::Qsv,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            VideoStage::hardware(
                kind,
                BackendKind::Qsv,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            VideoStage::hardware(
                StageKind::Encode,
                BackendKind::Qsv,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ]
    }

    #[test]
    fn closed_enums_use_stable_serde_names() {
        round_trip(AccelerationMode::Auto, "\"auto\"");
        round_trip(AccelerationMode::Software, "\"software\"");
        round_trip(AccelerationMode::PreferIgpu, "\"prefer-iGPU\"");
        round_trip(AccelerationMode::PreferDgpu, "\"prefer-dGPU\"");
        round_trip(AccelerationMode::Device, "\"device\"");
        round_trip(AccelerationClass::HardwareResident, "\"hardwareResident\"");
        round_trip(StageKind::PixelFormat, "\"pixelFormat\"");
        round_trip(
            StageMode::Hardware {
                backend: BackendKind::Vaapi,
                device: device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            },
            "{\"hardware\":{\"backend\":\"vaapi\",\"device\":\"gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}",
        );
        round_trip(DeviceClass::Integrated, "\"integrated\"");
        round_trip(DeviceClass::Discrete, "\"discrete\"");
        round_trip(DeviceClass::Virtual, "\"virtual\"");
        round_trip(DeviceClass::Software, "\"software\"");
        round_trip(DeviceClass::Unknown, "\"unknown\"");
        round_trip(BackendKind::D3d11va, "\"d3d11va\"");
        round_trip(BackendKind::Cuda, "\"cuda\"");
        round_trip(BackendKind::VideoToolbox, "\"videoToolbox\"");
        round_trip(CapabilityState::Listed, "\"listed\"");
        round_trip(
            CapabilityState::CorrectnessVerified,
            "\"correctnessVerified\"",
        );
        round_trip(CapabilityState::RealtimeQualified, "\"realtimeQualified\"");
        round_trip(CapabilityState::Failed, "\"failed\"");
        round_trip(CapabilityState::CircuitOpen, "\"circuitOpen\"");
        round_trip(
            CapabilityState::AdministrativelyDisabled,
            "\"administrativelyDisabled\"",
        );
        round_trip(FrameRateClass::Unknown, "\"unknown\"");
        round_trip(
            RateControlIntent::ConstrainedVariable,
            "\"constrainedVariable\"",
        );
        round_trip(PresetIntent::Quality, "\"quality\"");
    }

    #[test]
    fn rational_rate_reduces_and_rejects_zero_numerator() {
        let rate = RationalRate::new(60_000, NonZeroU32::new(2_000).unwrap()).unwrap();

        assert_eq!(rate.numerator(), 30);
        assert_eq!(rate.denominator().get(), 1);
        assert!(RationalRate::new(0, NonZeroU32::new(1).unwrap()).is_err());
    }

    #[test]
    fn device_ids_accept_only_the_version_one_wire_shape() {
        let valid = "gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(DeviceId::parse_public(valid).unwrap().as_str(), valid);
        assert_eq!(
            serde_json::to_string(&device(valid)).unwrap(),
            format!("\"{valid}\"")
        );
        assert_eq!(
            serde_json::from_str::<DeviceId>(&format!("\"{valid}\"")).unwrap(),
            device(valid)
        );

        for raw in [
            "",
            "gpu0_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gpu1_",
            "gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAA+",
            "gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "C:\\Users\\ExampleUser\\device",
            "/dev/dri/renderD128",
            "https://user:secret@example.test/gpu?token=abc",
            "gpu 0",
            "gpu; rm -rf /",
        ] {
            assert!(DeviceId::parse_public(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn hmac_prefix_constructor_produces_a_canonical_device_id() {
        let id = DeviceId::from_hmac_prefix([0; DEVICE_ID_DIGEST_BYTES]);
        assert_eq!(id.as_str(), "gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn transitional_capability_states_never_deserialize() {
        for raw in [
            "unknown",
            "verifying",
            "verified",
            "unsupported",
            "temporarilyFailed",
        ] {
            let json = format!("\"{raw}\"");
            assert!(
                serde_json::from_str::<CapabilityState>(&json).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn media_sources_are_closed_variants_not_raw_route_text() {
        let sources = [
            (
                ValidatedMediaSource::completed_file("file-a").unwrap(),
                "{\"completedFile\":{\"id\":\"file-a\"}}",
            ),
            (
                ValidatedMediaSource::engine_loopback("loopback-a").unwrap(),
                "{\"engineLoopback\":{\"id\":\"loopback-a\"}}",
            ),
            (
                ValidatedMediaSource::approved_remote("remote-a").unwrap(),
                "{\"approvedRemote\":{\"id\":\"remote-a\"}}",
            ),
            (
                ValidatedMediaSource::synthetic_fixture("fixture-a").unwrap(),
                "{\"syntheticFixture\":{\"id\":\"fixture-a\"}}",
            ),
        ];

        for (source, expected) in sources {
            assert_eq!(serde_json::to_string(&source).unwrap(), expected);
        }
    }

    #[test]
    fn serde_deserialization_enforces_public_numeric_value_invariants() {
        assert!(serde_json::from_str::<DeviceId>("\"/dev/dri/renderD128\"").is_err());
        assert!(
            serde_json::from_str::<RationalRate>("{\"numerator\":0,\"denominator\":1}").is_err()
        );
        assert_eq!(
            serde_json::from_str::<RationalRate>("{\"numerator\":60000,\"denominator\":2000}")
                .unwrap(),
            RationalRate::new(60_000, NonZeroU32::new(2_000).unwrap()).unwrap()
        );
        assert!(
            serde_json::from_str::<RateControlEnvelope>(
                "{\"intent\":\"constant\",\"targetVideoBps\":7000000,\"maxVideoBps\":6000000,\
                 \"bufferBits\":12000000,\"preset\":\"speed\",\"outputFrameRate\":null,\
                 \"width\":1920,\"height\":1080,\"audioBps\":128000}"
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<RateControlEnvelope>(
                "{\"intent\":\"constant\",\"targetVideoBps\":6000000,\"maxVideoBps\":6000000,\
                 \"bufferBits\":12000000,\"preset\":\"speed\",\"outputFrameRate\":null,\
                 \"width\":1920,\"height\":1080,\"audioBps\":0}"
            )
            .is_err()
        );
    }

    #[test]
    fn incomplete_stage_graphs_are_rejected() {
        for stages in [
            vec![],
            vec![VideoStage::hardware(
                StageKind::Encode,
                BackendKind::Qsv,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            )],
            vec![
                VideoStage::hardware(
                    StageKind::Encode,
                    BackendKind::Qsv,
                    device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                ),
                VideoStage::hardware(
                    StageKind::Decode,
                    BackendKind::Qsv,
                    device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                ),
            ],
        ] {
            assert!(AccelerationClass::derive(&stages).is_err());
        }
    }

    #[test]
    fn hardware_encode_with_software_decode_is_partial() {
        let stages = vec![
            VideoStage::software(StageKind::Decode),
            VideoStage::hardware(
                StageKind::Encode,
                BackendKind::Amf,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ];
        assert_eq!(
            AccelerationClass::derive(&stages).unwrap(),
            AccelerationClass::Partial
        );
    }

    #[test]
    fn hardware_resident_rejects_cpu_transfer() {
        let stages = qsv_stages_with(StageKind::Download);
        assert_eq!(
            AccelerationClass::derive(&stages).unwrap(),
            AccelerationClass::Partial
        );
    }

    #[test]
    fn all_hardware_stages_without_transfer_are_hardware_resident() {
        let stages = qsv_stages_with(StageKind::Scale);
        assert_eq!(
            AccelerationClass::derive(&stages).unwrap(),
            AccelerationClass::HardwareResident
        );
    }

    #[test]
    fn mixed_hardware_device_or_backend_is_not_hardware_resident() {
        let mixed_device = vec![
            VideoStage::hardware(
                StageKind::Decode,
                BackendKind::Qsv,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            VideoStage::hardware(
                StageKind::Encode,
                BackendKind::Qsv,
                device("gpu1_AQAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ];
        let mixed_backend = vec![
            VideoStage::hardware(
                StageKind::Decode,
                BackendKind::Qsv,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
            VideoStage::hardware(
                StageKind::Encode,
                BackendKind::Vaapi,
                device("gpu1_AAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ),
        ];

        assert_eq!(
            AccelerationClass::derive(&mixed_device).unwrap(),
            AccelerationClass::Partial
        );
        assert_eq!(
            AccelerationClass::derive(&mixed_backend).unwrap(),
            AccelerationClass::Partial
        );
    }

    #[test]
    fn rate_control_envelope_rejects_incoherent_bounds_and_zero_dimensions() {
        assert!(
            RateControlEnvelope::new(
                RateControlIntent::Constant,
                7_000_000,
                6_000_000,
                12_000_000,
                PresetIntent::Speed,
                None,
                NonZeroU32::new(1920).unwrap(),
                NonZeroU32::new(1080).unwrap(),
                128_000,
            )
            .is_err()
        );
        assert!(
            RateControlEnvelope::new(
                RateControlIntent::Constant,
                6_000_000,
                6_000_000,
                12_000_000,
                PresetIntent::Speed,
                None,
                NonZeroU32::new(1920).unwrap(),
                NonZeroU32::new(1080).unwrap(),
                0,
            )
            .is_err()
        );
    }
}
