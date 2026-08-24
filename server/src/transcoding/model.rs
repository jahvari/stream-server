use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, num::NonZeroU32};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelValidationError> {
        let value = value.into();
        if is_safe_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(ModelValidationError::new("invalid device id"))
        }
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
        Self::new(value).map_err(serde::de::Error::custom)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BackendKind {
    Amf,
    Nvenc,
    Qsv,
    Vaapi,
    VideoToolbox,
    V4l2m2m,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityState {
    Unknown,
    Listed,
    Verifying,
    Verified,
    Unsupported,
    TemporarilyFailed,
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
    pub fn derive(stages: &[VideoStage]) -> Self {
        let hardware = stages.iter().any(VideoStage::is_hardware);
        let software_or_transfer = stages.iter().any(VideoStage::requires_cpu_frames);
        match (hardware, software_or_transfer) {
            (false, _) => Self::Software,
            (true, true) => Self::Partial,
            (true, false) => Self::HardwareResident,
        }
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
    pub kind: StageKind,
    pub mode: StageMode,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RationalRate {
    pub numerator: u32,
    pub denominator: NonZeroU32,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RateControlEnvelope {
    pub intent: RateControlIntent,
    pub target_video_bps: u64,
    pub max_video_bps: u64,
    pub buffer_bits: u64,
    pub preset: PresetIntent,
    pub output_frame_rate: Option<RationalRate>,
    pub width: u32,
    pub height: u32,
    pub audio_bps: u64,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyframeStrategy {
    FixedGop { frames: NonZeroU32 },
    TimeForced { segment_duration_ms: NonZeroU32 },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidatedMediaSource {
    CompletedFile(CompletedFileSource),
    EngineLoopback(EngineLoopbackSource),
    ApprovedRemote(ApprovedRemoteSource),
    SyntheticFixture(SyntheticFixtureSource),
}

impl ValidatedMediaSource {
    pub fn completed_file(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self::CompletedFile(CompletedFileSource::new(id)?))
    }

    pub fn engine_loopback(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self::EngineLoopback(EngineLoopbackSource::new(id)?))
    }

    pub fn approved_remote(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self::ApprovedRemote(ApprovedRemoteSource::new(id)?))
    }

    pub fn synthetic_fixture(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self::SyntheticFixture(SyntheticFixtureSource::new(id)?))
    }

    pub fn id(&self) -> &str {
        match self {
            Self::CompletedFile(source) => source.id(),
            Self::EngineLoopback(source) => source.id(),
            Self::ApprovedRemote(source) => source.id(),
            Self::SyntheticFixture(source) => source.id(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompletedFileSource {
    id: SourceId,
}

impl CompletedFileSource {
    pub fn new(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self {
            id: SourceId::new(id)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineLoopbackSource {
    id: SourceId,
}

impl EngineLoopbackSource {
    pub fn new(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self {
            id: SourceId::new(id)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedRemoteSource {
    id: SourceId,
}

impl ApprovedRemoteSource {
    pub fn new(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self {
            id: SourceId::new(id)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyntheticFixtureSource {
    id: SourceId,
}

impl SyntheticFixtureSource {
    pub fn new(id: impl Into<String>) -> Result<Self, ModelValidationError> {
        Ok(Self {
            id: SourceId::new(id)?,
        })
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(transparent)]
struct SourceId(String);

impl SourceId {
    fn new(value: impl Into<String>) -> Result<Self, ModelValidationError> {
        let value = value.into();
        if is_safe_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(ModelValidationError::new("invalid media source id"))
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SourceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaDescriptor {
    pub source: ValidatedMediaSource,
    pub frame_rate_class: FrameRateClass,
}

impl MediaDescriptor {
    pub fn new(source: ValidatedMediaSource, frame_rate_class: FrameRateClass) -> Self {
        Self {
            source,
            frame_rate_class,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputContract {
    pub rate_control: RateControlEnvelope,
    pub keyframes: KeyframeStrategy,
}

impl OutputContract {
    pub fn new(rate_control: RateControlEnvelope, keyframes: KeyframeStrategy) -> Self {
        Self {
            rate_control,
            keyframes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodeRequest {
    pub source: ValidatedMediaSource,
    pub output: OutputContract,
    pub acceleration_mode: AccelerationMode,
}

impl TranscodeRequest {
    pub fn new(
        source: ValidatedMediaSource,
        output: OutputContract,
        acceleration_mode: AccelerationMode,
    ) -> Self {
        Self {
            source,
            output,
            acceleration_mode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodePlan {
    pub request: TranscodeRequest,
    pub stages: Vec<VideoStage>,
    pub acceleration_class: AccelerationClass,
}

impl<'de> Deserialize<'de> for TranscodePlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            request: TranscodeRequest,
            stages: Vec<VideoStage>,
            acceleration_class: AccelerationClass,
        }

        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.request, raw.stages, raw.acceleration_class).map_err(serde::de::Error::custom)
    }
}

impl TranscodePlan {
    pub fn new(
        request: TranscodeRequest,
        stages: Vec<VideoStage>,
        acceleration_class: AccelerationClass,
    ) -> Result<Self, ModelValidationError> {
        let derived = AccelerationClass::derive(&stages);
        if acceleration_class != derived {
            return Err(ModelValidationError::new(
                "acceleration class does not match stages",
            ));
        }

        Ok(Self {
            request,
            stages,
            acceleration_class,
        })
    }

    pub fn acceleration_class(&self) -> AccelerationClass {
        self.acceleration_class
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

fn is_safe_identifier(value: &str) -> bool {
    let len = value.len();
    (1..=128).contains(&len)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
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
        DeviceId::new(value).unwrap()
    }

    fn qsv_stages_with(kind: StageKind) -> Vec<VideoStage> {
        vec![
            VideoStage::hardware(StageKind::Decode, BackendKind::Qsv, device("gpu-a")),
            VideoStage::hardware(kind, BackendKind::Qsv, device("gpu-a")),
            VideoStage::hardware(StageKind::Encode, BackendKind::Qsv, device("gpu-a")),
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
                device: device("renderD128"),
            },
            "{\"hardware\":{\"backend\":\"vaapi\",\"device\":\"renderD128\"}}",
        );
        round_trip(DeviceClass::Integrated, "\"integrated\"");
        round_trip(DeviceClass::Discrete, "\"discrete\"");
        round_trip(DeviceClass::Virtual, "\"virtual\"");
        round_trip(DeviceClass::Software, "\"software\"");
        round_trip(DeviceClass::Unknown, "\"unknown\"");
        round_trip(BackendKind::VideoToolbox, "\"videoToolbox\"");
        round_trip(CapabilityState::Unknown, "\"unknown\"");
        round_trip(CapabilityState::Listed, "\"listed\"");
        round_trip(CapabilityState::Verifying, "\"verifying\"");
        round_trip(CapabilityState::Verified, "\"verified\"");
        round_trip(CapabilityState::Unsupported, "\"unsupported\"");
        round_trip(CapabilityState::TemporarilyFailed, "\"temporarilyFailed\"");
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

        assert_eq!(rate.numerator, 30);
        assert_eq!(rate.denominator.get(), 1);
        assert!(RationalRate::new(0, NonZeroU32::new(1).unwrap()).is_err());
    }

    #[test]
    fn device_id_rejects_raw_paths_urls_credentials_and_commands() {
        for raw in [
            "",
            "C:\\Users\\Hunter\\device",
            "/dev/dri/renderD128",
            "https://user:secret@example.test/gpu?token=abc",
            "gpu 0",
            "gpu; rm -rf /",
        ] {
            assert!(DeviceId::new(raw).is_err(), "{raw}");
        }
        assert_eq!(device("gpu-a").as_str(), "gpu-a");
    }

    #[test]
    fn media_sources_are_closed_variants_not_raw_route_text() {
        round_trip(
            ValidatedMediaSource::completed_file("file-a").unwrap(),
            "{\"completedFile\":{\"id\":\"file-a\"}}",
        );
        round_trip(
            ValidatedMediaSource::engine_loopback("loopback-a").unwrap(),
            "{\"engineLoopback\":{\"id\":\"loopback-a\"}}",
        );
        round_trip(
            ValidatedMediaSource::approved_remote("remote-a").unwrap(),
            "{\"approvedRemote\":{\"id\":\"remote-a\"}}",
        );
        round_trip(
            ValidatedMediaSource::synthetic_fixture("fixture-a").unwrap(),
            "{\"syntheticFixture\":{\"id\":\"fixture-a\"}}",
        );

        assert!(serde_json::from_str::<ValidatedMediaSource>("\"media-source\"").is_err());
        assert!(
            serde_json::from_str::<ValidatedMediaSource>(
                "\"https://user:secret@example.test/video?token=abc\""
            )
            .is_err()
        );
    }

    #[test]
    fn serde_deserialization_enforces_value_invariants() {
        assert!(serde_json::from_str::<DeviceId>("\"/dev/dri/renderD128\"").is_err());
        assert!(
            serde_json::from_str::<ValidatedMediaSource>(
                "{\"completedFile\":{\"id\":\"C:\\\\Users\\\\Hunter\\\\private.mp4\"}}"
            )
            .is_err()
        );
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
    fn transcode_plan_deserialization_enforces_acceleration_invariant() {
        let json = concat!(
            "{\"request\":{\"source\":\"media-source\",\"output\":{\"rateControl\":{",
            "\"intent\":\"constant\",\"targetVideoBps\":4000000,\"maxVideoBps\":4000000,",
            "\"bufferBits\":8000000,\"preset\":\"balanced\",\"outputFrameRate\":null,",
            "\"width\":1920,\"height\":1080,\"audioBps\":128000},",
            "\"keyframes\":{\"fixedGop\":{\"frames\":120}}},\"accelerationMode\":\"auto\"},",
            "\"stages\":[{\"kind\":\"decode\",\"mode\":\"software\"}],",
            "\"accelerationClass\":\"hardwareResident\"}"
        );

        assert!(serde_json::from_str::<TranscodePlan>(json).is_err());
    }

    #[test]
    fn hardware_encode_with_software_decode_is_partial() {
        let stages = vec![
            VideoStage::software(StageKind::Decode),
            VideoStage::hardware(StageKind::Encode, BackendKind::Amf, device("gpu-a")),
        ];
        assert_eq!(
            AccelerationClass::derive(&stages),
            AccelerationClass::Partial
        );
    }

    #[test]
    fn hardware_resident_rejects_cpu_transfer() {
        let stages = qsv_stages_with(StageKind::Download);
        assert_eq!(
            AccelerationClass::derive(&stages),
            AccelerationClass::Partial
        );
    }

    #[test]
    fn all_hardware_stages_without_transfer_are_hardware_resident() {
        let stages = qsv_stages_with(StageKind::Scale);
        assert_eq!(
            AccelerationClass::derive(&stages),
            AccelerationClass::HardwareResident
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
