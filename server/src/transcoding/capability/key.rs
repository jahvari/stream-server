use std::{collections::BTreeSet, fmt, num::NonZeroU32};

use crate::transcoding::{
    codec::{
        ChromaSubsampling, ColorMatrix, ColorPrimaries, ColorRange, ColorTransfer, FieldOrder,
        InputVideoCodec, OutputVideoCodec, PixelFormat, SampleEntry, VideoProfile,
    },
    device::identity::DriverIdentity,
    inventory::ListedCodec,
    inventory::RuntimeEvidenceId,
    model::{BackendKind, DeviceId, FrameRateClass, KeyframeStrategy, RationalRate},
};

const CURRENT_SCHEMA_VERSION: u16 = 1;
const CURRENT_EVIDENCE_VERSION: u16 = 1;
const MAX_REQUIREMENT_ITEMS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct KeyVersions {
    schema: u16,
    evidence: u16,
    recipe: u16,
}

impl KeyVersions {
    const fn for_direction(direction: CapabilityDirection) -> Self {
        Self {
            schema: CURRENT_SCHEMA_VERSION,
            evidence: CURRENT_EVIDENCE_VERSION,
            recipe: match direction {
                CapabilityDirection::Decode => 1,
                CapabilityDirection::Encode => 2,
                CapabilityDirection::FullPipeline => 3,
                CapabilityDirection::SegmentedPipeline => 4,
                CapabilityDirection::CopyRemux => 5,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum CapabilityDirection {
    Decode,
    Encode,
    FullPipeline,
    SegmentedPipeline,
    CopyRemux,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StaticPrerequisites<'a> {
    pub(super) decode: Option<ListedCodec>,
    pub(super) encode: Option<ListedCodec>,
    pub(super) requirements: Option<&'a PipelineRequirements>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum BitDepth {
    Eight,
    Ten,
    Twelve,
}

impl BitDepth {
    const fn value(self) -> u8 {
        match self {
            Self::Eight => 8,
            Self::Ten => 10,
            Self::Twelve => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum CodecLevel {
    L20,
    L21,
    L30,
    L31,
    L40,
    L41,
    L42,
    L50,
    L51,
    L52,
    L60,
    L61,
    L62,
    Mpeg2Low,
    Mpeg2Main,
    Mpeg2High1440,
    Mpeg2High,
    Vc1Low,
    Vc1Medium,
    Vc1High,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum HdrMode {
    Sdr,
    Hdr10,
    Hlg,
    DolbyVision,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum CodedDimensionBucket {
    UpTo480,
    UpTo576,
    UpTo640,
    UpTo720,
    UpTo1080,
    UpTo1280,
    UpTo1440,
    UpTo1920,
    UpTo2160,
    UpTo2560,
    UpTo3840,
    UpTo4096,
    UpTo4320,
    UpTo7680,
    UpTo8192,
}

impl CodedDimensionBucket {
    fn from_dimension(value: NonZeroU32) -> Result<Self, KeyValidationError> {
        match value.get() {
            1..=480 => Ok(Self::UpTo480),
            481..=576 => Ok(Self::UpTo576),
            577..=640 => Ok(Self::UpTo640),
            641..=720 => Ok(Self::UpTo720),
            721..=1080 => Ok(Self::UpTo1080),
            1081..=1280 => Ok(Self::UpTo1280),
            1281..=1440 => Ok(Self::UpTo1440),
            1441..=1920 => Ok(Self::UpTo1920),
            1921..=2160 => Ok(Self::UpTo2160),
            2161..=2560 => Ok(Self::UpTo2560),
            2561..=3840 => Ok(Self::UpTo3840),
            3841..=4096 => Ok(Self::UpTo4096),
            4097..=4320 => Ok(Self::UpTo4320),
            4321..=7680 => Ok(Self::UpTo7680),
            7681..=8192 => Ok(Self::UpTo8192),
            _ => Err(KeyValidationError::UnsupportedDimension),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ResolutionBucket {
    pub(super) width: CodedDimensionBucket,
    pub(super) height: CodedDimensionBucket,
}

impl ResolutionBucket {
    pub(super) fn from_coded_dimensions(
        width: NonZeroU32,
        height: NonZeroU32,
    ) -> Result<Self, KeyValidationError> {
        Ok(Self {
            width: CodedDimensionBucket::from_dimension(width)?,
            height: CodedDimensionBucket::from_dimension(height)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum FrameRateBucket {
    UpTo24,
    UpTo25,
    UpTo30,
    UpTo50,
    UpTo60,
    UpTo120,
    UpTo144,
    UpTo240,
}

impl FrameRateBucket {
    pub(super) fn from_rate(rate: RationalRate) -> Result<Self, KeyValidationError> {
        for (limit, bucket) in [
            (24_u32, Self::UpTo24),
            (25, Self::UpTo25),
            (30, Self::UpTo30),
            (50, Self::UpTo50),
            (60, Self::UpTo60),
            (120, Self::UpTo120),
            (144, Self::UpTo144),
            (240, Self::UpTo240),
        ] {
            let left = u64::from(rate.numerator());
            let right = u64::from(limit) * u64::from(rate.denominator().get());
            if left <= right {
                return Ok(bucket);
            }
        }
        Err(KeyValidationError::UnsupportedFrameRate)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum RequiredTransform {
    Scale,
    Deinterlace,
    Rotate90,
    Rotate180,
    Rotate270,
    ToneMap,
    SubtitleBurnIn,
    PixelFormat,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum RequiredTransfer {
    Upload,
    Download,
    HardwareMap,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum RequiredFilter {
    Format,
    Scale,
    Deinterlace,
    ToneMap,
    Subtitles,
    HardwareUpload,
    HardwareDownload,
    HardwareMap,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum OutputContainerContract {
    MpegTsHls,
    Fmp4Hls,
    MpegTsStream,
    Matroska,
    MovMp4,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ColorSignature {
    pub(super) range: ColorRange,
    pub(super) primaries: ColorPrimaries,
    pub(super) transfer: ColorTransfer,
    pub(super) matrix: ColorMatrix,
    pub(super) hdr: HdrMode,
}

impl ColorSignature {
    pub(super) fn new(
        range: ColorRange,
        primaries: ColorPrimaries,
        transfer: ColorTransfer,
        matrix: ColorMatrix,
        hdr: HdrMode,
    ) -> Result<Self, KeyValidationError> {
        if matches!(range, ColorRange::OtherProbed)
            || matches!(primaries, ColorPrimaries::OtherProbed)
            || matches!(transfer, ColorTransfer::OtherProbed)
            || matches!(matrix, ColorMatrix::OtherProbed)
        {
            return Err(KeyValidationError::NonFiniteSignature);
        }
        Ok(Self {
            range,
            primaries,
            transfer,
            matrix,
            hdr,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct InputVideoSignature {
    pub(super) codec: InputVideoCodec,
    pub(super) profile: VideoProfile,
    pub(super) level: CodecLevel,
    pub(super) pixel_format: PixelFormat,
    pub(super) bit_depth: BitDepth,
    pub(super) chroma: ChromaSubsampling,
    pub(super) color: ColorSignature,
    pub(super) field_order: FieldOrder,
    pub(super) resolution: ResolutionBucket,
    pub(super) frame_rate: FrameRateBucket,
    pub(super) frame_rate_class: FrameRateClass,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct OutputVideoSignature {
    pub(super) codec: OutputVideoCodec,
    pub(super) profile: VideoProfile,
    pub(super) level: CodecLevel,
    pub(super) pixel_format: PixelFormat,
    pub(super) bit_depth: BitDepth,
    pub(super) chroma: ChromaSubsampling,
    pub(super) color: ColorSignature,
    pub(super) resolution: ResolutionBucket,
    pub(super) frame_rate: FrameRateBucket,
    pub(super) frame_rate_class: FrameRateClass,
}

impl InputVideoSignature {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        codec: InputVideoCodec,
        profile: VideoProfile,
        level: CodecLevel,
        pixel_format: PixelFormat,
        bit_depth: BitDepth,
        chroma: ChromaSubsampling,
        color: ColorSignature,
        field_order: FieldOrder,
        resolution: ResolutionBucket,
        frame_rate: FrameRateBucket,
        frame_rate_class: FrameRateClass,
    ) -> Result<Self, KeyValidationError> {
        validate_input_video(codec, profile, level, pixel_format, bit_depth, chroma)?;
        Ok(Self {
            codec,
            profile,
            level,
            pixel_format,
            bit_depth,
            chroma,
            color,
            field_order,
            resolution,
            frame_rate,
            frame_rate_class,
        })
    }
}

impl OutputVideoSignature {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        codec: OutputVideoCodec,
        profile: VideoProfile,
        level: CodecLevel,
        pixel_format: PixelFormat,
        bit_depth: BitDepth,
        chroma: ChromaSubsampling,
        color: ColorSignature,
        resolution: ResolutionBucket,
        frame_rate: FrameRateBucket,
        frame_rate_class: FrameRateClass,
    ) -> Result<Self, KeyValidationError> {
        validate_output_video(codec, profile, level, pixel_format, bit_depth, chroma)?;
        Ok(Self {
            codec,
            profile,
            level,
            pixel_format,
            bit_depth,
            chroma,
            color,
            resolution,
            frame_rate,
            frame_rate_class,
        })
    }
}

fn validate_input_video(
    codec: InputVideoCodec,
    profile: VideoProfile,
    level: CodecLevel,
    pixel_format: PixelFormat,
    bit_depth: BitDepth,
    chroma: ChromaSubsampling,
) -> Result<(), KeyValidationError> {
    if matches!(codec, InputVideoCodec::OtherProbed)
        || !input_profile_matches(codec, profile)
        || !input_level_matches(codec, level)
        || !profile_depth_matches(profile, bit_depth)
        || !pixel_matches(pixel_format, bit_depth, chroma)
    {
        return Err(KeyValidationError::NonFiniteSignature);
    }
    Ok(())
}

fn validate_output_video(
    codec: OutputVideoCodec,
    profile: VideoProfile,
    level: CodecLevel,
    pixel_format: PixelFormat,
    bit_depth: BitDepth,
    chroma: ChromaSubsampling,
) -> Result<(), KeyValidationError> {
    if !output_profile_matches(codec, profile)
        || !output_level_matches(codec, level)
        || !profile_depth_matches(profile, bit_depth)
        || !pixel_matches(pixel_format, bit_depth, chroma)
    {
        return Err(KeyValidationError::NonFiniteSignature);
    }
    Ok(())
}

fn input_level_matches(codec: InputVideoCodec, level: CodecLevel) -> bool {
    match codec {
        InputVideoCodec::H264
        | InputVideoCodec::Hevc
        | InputVideoCodec::Av1
        | InputVideoCodec::Vp9 => numeric_level(level),
        InputVideoCodec::Mpeg2 => matches!(
            level,
            CodecLevel::Mpeg2Low
                | CodecLevel::Mpeg2Main
                | CodecLevel::Mpeg2High1440
                | CodecLevel::Mpeg2High
        ),
        InputVideoCodec::Vc1 => matches!(
            level,
            CodecLevel::Vc1Low | CodecLevel::Vc1Medium | CodecLevel::Vc1High
        ),
        InputVideoCodec::OtherProbed => false,
    }
}

fn output_level_matches(codec: OutputVideoCodec, level: CodecLevel) -> bool {
    matches!(
        codec,
        OutputVideoCodec::H264 | OutputVideoCodec::Hevc | OutputVideoCodec::Av1
    ) && numeric_level(level)
}

fn numeric_level(level: CodecLevel) -> bool {
    matches!(
        level,
        CodecLevel::L20
            | CodecLevel::L21
            | CodecLevel::L30
            | CodecLevel::L31
            | CodecLevel::L40
            | CodecLevel::L41
            | CodecLevel::L42
            | CodecLevel::L50
            | CodecLevel::L51
            | CodecLevel::L52
            | CodecLevel::L60
            | CodecLevel::L61
            | CodecLevel::L62
    )
}

fn profile_depth_matches(profile: VideoProfile, bit_depth: BitDepth) -> bool {
    match profile {
        VideoProfile::H264Baseline
        | VideoProfile::H264Main
        | VideoProfile::H264High
        | VideoProfile::HevcMain
        | VideoProfile::Vp9Profile0
        | VideoProfile::Mpeg2Main
        | VideoProfile::Vc1Advanced => bit_depth == BitDepth::Eight,
        VideoProfile::H264High10 | VideoProfile::HevcMain10 => bit_depth == BitDepth::Ten,
        VideoProfile::Av1Main => matches!(
            bit_depth,
            BitDepth::Eight | BitDepth::Ten | BitDepth::Twelve
        ),
        VideoProfile::Vp9Profile2 => matches!(bit_depth, BitDepth::Ten | BitDepth::Twelve),
        VideoProfile::OtherProbed | VideoProfile::Unknown => false,
    }
}

fn input_profile_matches(codec: InputVideoCodec, profile: VideoProfile) -> bool {
    matches!(
        (codec, profile),
        (
            InputVideoCodec::H264,
            VideoProfile::H264Baseline
                | VideoProfile::H264Main
                | VideoProfile::H264High
                | VideoProfile::H264High10
        ) | (
            InputVideoCodec::Hevc,
            VideoProfile::HevcMain | VideoProfile::HevcMain10
        ) | (InputVideoCodec::Av1, VideoProfile::Av1Main)
            | (
                InputVideoCodec::Vp9,
                VideoProfile::Vp9Profile0 | VideoProfile::Vp9Profile2
            )
            | (InputVideoCodec::Mpeg2, VideoProfile::Mpeg2Main)
            | (InputVideoCodec::Vc1, VideoProfile::Vc1Advanced)
    )
}

fn output_profile_matches(codec: OutputVideoCodec, profile: VideoProfile) -> bool {
    matches!(
        (codec, profile),
        (
            OutputVideoCodec::H264,
            VideoProfile::H264Baseline
                | VideoProfile::H264Main
                | VideoProfile::H264High
                | VideoProfile::H264High10
        ) | (
            OutputVideoCodec::Hevc,
            VideoProfile::HevcMain | VideoProfile::HevcMain10
        ) | (OutputVideoCodec::Av1, VideoProfile::Av1Main)
    )
}

fn pixel_matches(
    pixel_format: PixelFormat,
    bit_depth: BitDepth,
    chroma: ChromaSubsampling,
) -> bool {
    pixel_format.inferred_bit_depth() == Some(bit_depth.value())
        && pixel_format.chroma() == chroma
        && !matches!(chroma, ChromaSubsampling::Unknown)
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct PipelineRequirements {
    pub(super) transforms: Vec<RequiredTransform>,
    pub(super) transfers: Vec<RequiredTransfer>,
    pub(super) filters: Vec<RequiredFilter>,
    pub(super) container: Option<OutputContainerContract>,
    pub(super) output_time_base: Option<RationalRate>,
}

impl PipelineRequirements {
    pub(super) fn new(
        transforms: impl IntoIterator<Item = RequiredTransform>,
        transfers: impl IntoIterator<Item = RequiredTransfer>,
        filters: impl IntoIterator<Item = RequiredFilter>,
        container: Option<OutputContainerContract>,
        output_time_base: Option<RationalRate>,
    ) -> Result<Self, KeyValidationError> {
        Ok(Self {
            transforms: canonical_requirements(transforms)?,
            transfers: canonical_requirements(transfers)?,
            filters: canonical_requirements(filters)?,
            container,
            output_time_base,
        })
    }
}

fn canonical_requirements<T: Copy + Ord>(
    values: impl IntoIterator<Item = T>,
) -> Result<Vec<T>, KeyValidationError> {
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.len() > MAX_REQUIREMENT_ITEMS {
        return Err(KeyValidationError::TooManyRequirements);
    }
    Ok(values.into_iter().collect())
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct SegmentationContract {
    pub(super) exact_frame_rate: RationalRate,
    pub(super) frame_rate_class: FrameRateClass,
    pub(super) segment_duration_ms: NonZeroU32,
    pub(super) output_time_base: RationalRate,
    pub(super) keyframe_strategy: KeyframeStrategy,
}

impl SegmentationContract {
    pub(super) fn new(
        exact_frame_rate: RationalRate,
        frame_rate_class: FrameRateClass,
        segment_duration_ms: NonZeroU32,
        output_time_base: RationalRate,
        keyframe_strategy: KeyframeStrategy,
    ) -> Result<Self, KeyValidationError> {
        if let KeyframeStrategy::TimeForced {
            segment_duration_ms: forced,
        } = keyframe_strategy
            && forced != segment_duration_ms
        {
            return Err(KeyValidationError::InconsistentSegmentation);
        }
        Ok(Self {
            exact_frame_rate,
            frame_rate_class,
            segment_duration_ms,
            output_time_base,
            keyframe_strategy,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) enum BoundaryAlgorithmVersion {
    V1,
    V2,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct PrivateSourceDigest([u8; 32]);

impl PrivateSourceDigest {
    pub(super) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for PrivateSourceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateSourceDigest([redacted])")
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct CopyRemuxSignature {
    pub(super) source_version: u64,
    pub(super) selected_streams: PrivateSourceDigest,
    pub(super) source_signature: PrivateSourceDigest,
    pub(super) source_codec: InputVideoCodec,
    pub(super) source_color: ColorSignature,
    pub(super) sample_entry: SampleEntry,
    pub(super) container: OutputContainerContract,
    pub(super) boundary_algorithm: BoundaryAlgorithmVersion,
}

impl CopyRemuxSignature {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        source_version: u64,
        selected_streams: PrivateSourceDigest,
        source_signature: PrivateSourceDigest,
        source_codec: InputVideoCodec,
        source_color: ColorSignature,
        sample_entry: SampleEntry,
        container: OutputContainerContract,
        boundary_algorithm: BoundaryAlgorithmVersion,
    ) -> Result<Self, KeyValidationError> {
        if source_version == 0
            || matches!(source_codec, InputVideoCodec::OtherProbed)
            || matches!(sample_entry, SampleEntry::OtherProbed)
        {
            return Err(KeyValidationError::NonFiniteSignature);
        }
        Ok(Self {
            source_version,
            selected_streams,
            source_signature,
            source_codec,
            source_color,
            sample_entry,
            container,
            boundary_algorithm,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum CapabilityOperation {
    Decode {
        input: InputVideoSignature,
        requirements: PipelineRequirements,
    },
    Encode {
        output: OutputVideoSignature,
        requirements: PipelineRequirements,
    },
    FullPipeline {
        input: InputVideoSignature,
        output: OutputVideoSignature,
        requirements: PipelineRequirements,
    },
    SegmentedPipeline {
        input: InputVideoSignature,
        output: OutputVideoSignature,
        requirements: PipelineRequirements,
        segmentation: SegmentationContract,
    },
    CopyRemux(CopyRemuxSignature),
}

impl CapabilityOperation {
    const fn direction(&self) -> CapabilityDirection {
        match self {
            Self::Decode { .. } => CapabilityDirection::Decode,
            Self::Encode { .. } => CapabilityDirection::Encode,
            Self::FullPipeline { .. } => CapabilityDirection::FullPipeline,
            Self::SegmentedPipeline { .. } => CapabilityDirection::SegmentedPipeline,
            Self::CopyRemux(_) => CapabilityDirection::CopyRemux,
        }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct CapabilityKey {
    versions: KeyVersions,
    runtime: RuntimeEvidenceId,
    device: DeviceId,
    driver: DriverIdentity,
    backend: BackendKind,
    operation: CapabilityOperation,
}

impl CapabilityKey {
    fn new(
        runtime: RuntimeEvidenceId,
        device: DeviceId,
        driver: DriverIdentity,
        backend: BackendKind,
        operation: CapabilityOperation,
    ) -> Result<Self, KeyValidationError> {
        let direction = operation.direction();
        validate_operation(direction, &operation)?;
        Ok(Self {
            versions: KeyVersions::for_direction(direction),
            runtime,
            device,
            driver,
            backend,
            operation,
        })
    }

    pub(super) fn decode(
        runtime: RuntimeEvidenceId,
        device: DeviceId,
        driver: DriverIdentity,
        backend: BackendKind,
        input: InputVideoSignature,
        requirements: PipelineRequirements,
    ) -> Result<Self, KeyValidationError> {
        Self::new(
            runtime,
            device,
            driver,
            backend,
            CapabilityOperation::Decode {
                input,
                requirements,
            },
        )
    }

    pub(super) fn encode(
        runtime: RuntimeEvidenceId,
        device: DeviceId,
        driver: DriverIdentity,
        backend: BackendKind,
        output: OutputVideoSignature,
        requirements: PipelineRequirements,
    ) -> Result<Self, KeyValidationError> {
        Self::new(
            runtime,
            device,
            driver,
            backend,
            CapabilityOperation::Encode {
                output,
                requirements,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn full_pipeline(
        runtime: RuntimeEvidenceId,
        device: DeviceId,
        driver: DriverIdentity,
        backend: BackendKind,
        input: InputVideoSignature,
        output: OutputVideoSignature,
        requirements: PipelineRequirements,
    ) -> Result<Self, KeyValidationError> {
        Self::new(
            runtime,
            device,
            driver,
            backend,
            CapabilityOperation::FullPipeline {
                input,
                output,
                requirements,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn segmented_pipeline(
        runtime: RuntimeEvidenceId,
        device: DeviceId,
        driver: DriverIdentity,
        backend: BackendKind,
        input: InputVideoSignature,
        output: OutputVideoSignature,
        requirements: PipelineRequirements,
        segmentation: SegmentationContract,
    ) -> Result<Self, KeyValidationError> {
        Self::new(
            runtime,
            device,
            driver,
            backend,
            CapabilityOperation::SegmentedPipeline {
                input,
                output,
                requirements,
                segmentation,
            },
        )
    }

    pub(super) fn copy_remux(
        runtime: RuntimeEvidenceId,
        device: DeviceId,
        driver: DriverIdentity,
        backend: BackendKind,
        signature: CopyRemuxSignature,
    ) -> Result<Self, KeyValidationError> {
        Self::new(
            runtime,
            device,
            driver,
            backend,
            CapabilityOperation::CopyRemux(signature),
        )
    }

    pub(super) const fn direction(&self) -> CapabilityDirection {
        self.operation.direction()
    }

    pub(super) const fn runtime(&self) -> &RuntimeEvidenceId {
        &self.runtime
    }

    pub(super) const fn device(&self) -> &DeviceId {
        &self.device
    }

    pub(super) const fn driver(&self) -> &DriverIdentity {
        &self.driver
    }

    pub(super) const fn backend(&self) -> BackendKind {
        self.backend
    }

    pub(super) fn static_prerequisites(&self) -> StaticPrerequisites<'_> {
        match &self.operation {
            CapabilityOperation::Decode {
                input,
                requirements,
            } => StaticPrerequisites {
                decode: Some(listed_input_codec(input.codec)),
                encode: None,
                requirements: Some(requirements),
            },
            CapabilityOperation::Encode {
                output,
                requirements,
            } => StaticPrerequisites {
                decode: None,
                encode: Some(listed_output_codec(output.codec)),
                requirements: Some(requirements),
            },
            CapabilityOperation::FullPipeline {
                input,
                output,
                requirements,
            }
            | CapabilityOperation::SegmentedPipeline {
                input,
                output,
                requirements,
                ..
            } => StaticPrerequisites {
                decode: Some(listed_input_codec(input.codec)),
                encode: Some(listed_output_codec(output.codec)),
                requirements: Some(requirements),
            },
            CapabilityOperation::CopyRemux(_) => StaticPrerequisites {
                decode: None,
                encode: None,
                requirements: None,
            },
        }
    }

    pub(super) fn is_valid(&self) -> bool {
        self.versions == KeyVersions::for_direction(self.direction())
            && validate_operation(self.direction(), &self.operation).is_ok()
    }
}

fn listed_input_codec(codec: InputVideoCodec) -> ListedCodec {
    match codec {
        InputVideoCodec::H264 => ListedCodec::H264,
        InputVideoCodec::Hevc => ListedCodec::Hevc,
        InputVideoCodec::Av1 => ListedCodec::Av1,
        InputVideoCodec::Vp9 => ListedCodec::Vp9,
        InputVideoCodec::Mpeg2 => ListedCodec::Mpeg2,
        InputVideoCodec::Vc1 => ListedCodec::Vc1,
        InputVideoCodec::OtherProbed => unreachable!("validated keys reject open codec values"),
    }
}

fn listed_output_codec(codec: OutputVideoCodec) -> ListedCodec {
    match codec {
        OutputVideoCodec::H264 => ListedCodec::H264,
        OutputVideoCodec::Hevc => ListedCodec::Hevc,
        OutputVideoCodec::Av1 => ListedCodec::Av1,
    }
}

fn validate_operation(
    direction: CapabilityDirection,
    operation: &CapabilityOperation,
) -> Result<(), KeyValidationError> {
    match operation {
        CapabilityOperation::Decode { input, .. } => {
            validate_input_video(
                input.codec,
                input.profile,
                input.level,
                input.pixel_format,
                input.bit_depth,
                input.chroma,
            )?;
            validate_color(input.color)?;
        }
        CapabilityOperation::Encode { output, .. } => {
            validate_output_video(
                output.codec,
                output.profile,
                output.level,
                output.pixel_format,
                output.bit_depth,
                output.chroma,
            )?;
            validate_color(output.color)?;
        }
        CapabilityOperation::FullPipeline { input, output, .. }
        | CapabilityOperation::SegmentedPipeline { input, output, .. } => {
            validate_input_video(
                input.codec,
                input.profile,
                input.level,
                input.pixel_format,
                input.bit_depth,
                input.chroma,
            )?;
            validate_output_video(
                output.codec,
                output.profile,
                output.level,
                output.pixel_format,
                output.bit_depth,
                output.chroma,
            )?;
            validate_color(input.color)?;
            validate_color(output.color)?;
        }
        CapabilityOperation::CopyRemux(signature) => {
            if signature.source_version == 0
                || matches!(signature.source_codec, InputVideoCodec::OtherProbed)
                || matches!(signature.sample_entry, SampleEntry::OtherProbed)
            {
                return Err(KeyValidationError::NonFiniteSignature);
            }
            validate_color(signature.source_color)?;
        }
    }
    match operation {
        CapabilityOperation::Decode { requirements, .. } => {
            validate_requirements(requirements)?;
            if requirements.container.is_some() || requirements.output_time_base.is_some() {
                return Err(KeyValidationError::InvalidDirectionFields);
            }
            Ok(())
        }
        CapabilityOperation::Encode { requirements, .. }
        | CapabilityOperation::FullPipeline { requirements, .. } => {
            validate_requirements(requirements)?;
            if requirements.container.is_none() || requirements.output_time_base.is_none() {
                return Err(KeyValidationError::InvalidDirectionFields);
            }
            if direction == CapabilityDirection::CopyRemux {
                return Err(KeyValidationError::InvalidDirectionFields);
            }
            Ok(())
        }
        CapabilityOperation::SegmentedPipeline {
            requirements,
            segmentation,
            ..
        } => {
            validate_requirements(requirements)?;
            if requirements.output_time_base.is_some() || requirements.container.is_none() {
                return Err(KeyValidationError::InvalidDirectionFields);
            }
            if let KeyframeStrategy::TimeForced {
                segment_duration_ms,
            } = segmentation.keyframe_strategy
                && segment_duration_ms != segmentation.segment_duration_ms
            {
                return Err(KeyValidationError::InconsistentSegmentation);
            }
            Ok(())
        }
        CapabilityOperation::CopyRemux(_) => Ok(()),
    }
}

fn validate_color(color: ColorSignature) -> Result<(), KeyValidationError> {
    if matches!(color.range, ColorRange::OtherProbed)
        || matches!(color.primaries, ColorPrimaries::OtherProbed)
        || matches!(color.transfer, ColorTransfer::OtherProbed)
        || matches!(color.matrix, ColorMatrix::OtherProbed)
    {
        return Err(KeyValidationError::NonFiniteSignature);
    }
    Ok(())
}

fn validate_requirements(requirements: &PipelineRequirements) -> Result<(), KeyValidationError> {
    if requirements.transforms.len() > MAX_REQUIREMENT_ITEMS
        || requirements.transfers.len() > MAX_REQUIREMENT_ITEMS
        || requirements.filters.len() > MAX_REQUIREMENT_ITEMS
        || requirements
            .transforms
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || requirements
            .transfers
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || requirements
            .filters
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(KeyValidationError::NonFiniteSignature);
    }
    for (transform, filter) in [
        (RequiredTransform::Scale, RequiredFilter::Scale),
        (RequiredTransform::Deinterlace, RequiredFilter::Deinterlace),
        (RequiredTransform::ToneMap, RequiredFilter::ToneMap),
        (RequiredTransform::SubtitleBurnIn, RequiredFilter::Subtitles),
        (RequiredTransform::PixelFormat, RequiredFilter::Format),
    ] {
        if requirements.transforms.contains(&transform) && !requirements.filters.contains(&filter) {
            return Err(KeyValidationError::InvalidDirectionFields);
        }
    }
    for (transfer, filter) in [
        (RequiredTransfer::Upload, RequiredFilter::HardwareUpload),
        (RequiredTransfer::Download, RequiredFilter::HardwareDownload),
        (RequiredTransfer::HardwareMap, RequiredFilter::HardwareMap),
    ] {
        if requirements.transfers.contains(&transfer) && !requirements.filters.contains(&filter) {
            return Err(KeyValidationError::InvalidDirectionFields);
        }
    }
    Ok(())
}

impl fmt::Debug for CapabilityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityKey")
            .field("versions", &self.versions)
            .field("runtime", &"[redacted]")
            .field("device", &self.device)
            .field("driver", &"[redacted]")
            .field("backend", &self.backend)
            .field("operation", &self.operation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KeyValidationError {
    InconsistentSegmentation,
    InvalidDirectionFields,
    NonFiniteSignature,
    TooManyRequirements,
    UnsupportedDimension,
    UnsupportedFrameRate,
}

impl fmt::Display for KeyValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid capability key")
    }
}

impl std::error::Error for KeyValidationError {}

#[cfg(test)]
impl CapabilityKey {
    pub(super) fn complete_test_keys() -> Vec<Self> {
        test_keys()
    }

    pub(super) fn all_identity_mutations_for_test(&self) -> Vec<Self> {
        test_mutations(self)
    }

    pub(super) fn with_test_physical_identity(&self, marker: u8) -> Self {
        let mut key = self.clone();
        key.device = DeviceId::from_hmac_prefix([marker; 20]);
        key.driver = DriverIdentity::from_test_digest([marker.wrapping_add(1); 32], true);
        key
    }

    pub(super) fn with_test_runtime(&self, marker: u8) -> Self {
        let mut key = self.clone();
        key.runtime = test_runtime(marker);
        key
    }

    pub(super) fn with_test_driver(&self, marker: u8) -> Self {
        let mut key = self.clone();
        key.driver = DriverIdentity::from_test_digest([marker; 32], true);
        key
    }

    pub(super) fn with_test_backend(&self, backend: BackendKind) -> Self {
        let mut key = self.clone();
        key.backend = backend;
        key
    }

    pub(super) fn invalid_for_test(&self) -> Self {
        let mut key = self.clone();
        key.versions.schema = 0;
        key
    }

    pub(super) fn distinct_copy_keys_for_test(count: usize) -> Vec<Self> {
        let base = test_keys().remove(4);
        (0..count)
            .map(|index| {
                let mut key = base.clone();
                let CapabilityOperation::CopyRemux(signature) = &mut key.operation else {
                    unreachable!("copy fixture has the copy operation")
                };
                signature.source_version = u64::try_from(index)
                    .expect("bounded test key count")
                    .checked_add(1)
                    .expect("bounded test source version");
                key
            })
            .collect()
    }
}

#[cfg(test)]
fn test_runtime(byte: u8) -> RuntimeEvidenceId {
    use crate::transcoding::runtime::RuntimeId;

    RuntimeEvidenceId::derive(&RuntimeId {
        install_digest: format!("{byte:02x}").repeat(32),
        ffmpeg_version: "7.1.4".to_owned(),
        jellyfin_revision: Some("3".to_owned()),
        build_configuration_digest: "22".repeat(32),
        pair_root_identity: "33".repeat(32),
    })
    .expect("bounded test runtime")
}

#[cfg(test)]
pub(super) fn test_color() -> ColorSignature {
    ColorSignature::new(
        ColorRange::Limited,
        ColorPrimaries::Bt709,
        ColorTransfer::Bt709,
        ColorMatrix::Bt709,
        HdrMode::Sdr,
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn test_input() -> InputVideoSignature {
    InputVideoSignature::new(
        InputVideoCodec::H264,
        VideoProfile::H264High,
        CodecLevel::L41,
        PixelFormat::Yuv420p,
        BitDepth::Eight,
        ChromaSubsampling::Cs420,
        test_color(),
        FieldOrder::Progressive,
        ResolutionBucket::from_coded_dimensions(
            NonZeroU32::new(1920).unwrap(),
            NonZeroU32::new(1080).unwrap(),
        )
        .unwrap(),
        FrameRateBucket::UpTo60,
        FrameRateClass::Constant,
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn test_output() -> OutputVideoSignature {
    OutputVideoSignature::new(
        OutputVideoCodec::Hevc,
        VideoProfile::HevcMain10,
        CodecLevel::L51,
        PixelFormat::Yuv420p10le,
        BitDepth::Ten,
        ChromaSubsampling::Cs420,
        test_color(),
        ResolutionBucket::from_coded_dimensions(
            NonZeroU32::new(3840).unwrap(),
            NonZeroU32::new(2160).unwrap(),
        )
        .unwrap(),
        FrameRateBucket::UpTo60,
        FrameRateClass::Constant,
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn test_requirements(output: bool) -> PipelineRequirements {
    PipelineRequirements::new(
        [RequiredTransform::Scale],
        [RequiredTransfer::HardwareMap],
        [RequiredFilter::Scale, RequiredFilter::HardwareMap],
        output.then_some(OutputContainerContract::MpegTsStream),
        output.then(|| RationalRate::new(1, NonZeroU32::new(90_000).unwrap()).unwrap()),
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn test_common() -> (RuntimeEvidenceId, DeviceId, DriverIdentity, BackendKind) {
    (
        test_runtime(0x11),
        DeviceId::from_hmac_prefix([0x44; 20]),
        DriverIdentity::from_test_digest([0x55; 32], true),
        BackendKind::Qsv,
    )
}

#[cfg(test)]
fn test_keys() -> Vec<CapabilityKey> {
    let (runtime, device, driver, backend) = test_common();
    let decode = CapabilityKey::decode(
        runtime.clone(),
        device.clone(),
        driver.clone(),
        backend,
        test_input(),
        test_requirements(false),
    )
    .unwrap();
    let encode = CapabilityKey::encode(
        runtime.clone(),
        device.clone(),
        driver.clone(),
        backend,
        test_output(),
        test_requirements(true),
    )
    .unwrap();
    let pipeline = CapabilityKey::full_pipeline(
        runtime.clone(),
        device.clone(),
        driver.clone(),
        backend,
        test_input(),
        test_output(),
        test_requirements(true),
    )
    .unwrap();
    let segmented = CapabilityKey::segmented_pipeline(
        runtime.clone(),
        device.clone(),
        driver.clone(),
        backend,
        test_input(),
        test_output(),
        PipelineRequirements::new(
            [RequiredTransform::Scale],
            [RequiredTransfer::HardwareMap],
            [RequiredFilter::Scale, RequiredFilter::HardwareMap],
            Some(OutputContainerContract::MpegTsHls),
            None,
        )
        .unwrap(),
        SegmentationContract::new(
            RationalRate::new(60_000, NonZeroU32::new(1001).unwrap()).unwrap(),
            FrameRateClass::Constant,
            NonZeroU32::new(6_000).unwrap(),
            RationalRate::new(1, NonZeroU32::new(90_000).unwrap()).unwrap(),
            KeyframeStrategy::FixedGop {
                frames: NonZeroU32::new(360).unwrap(),
            },
        )
        .unwrap(),
    )
    .unwrap();
    let remux = CapabilityKey::copy_remux(
        runtime,
        device,
        driver,
        backend,
        CopyRemuxSignature::new(
            1,
            PrivateSourceDigest::from_digest([0x66; 32]),
            PrivateSourceDigest::from_digest([0x77; 32]),
            InputVideoCodec::H264,
            test_color(),
            SampleEntry::Avc1,
            OutputContainerContract::MpegTsStream,
            BoundaryAlgorithmVersion::V1,
        )
        .unwrap(),
    )
    .unwrap();
    vec![decode, encode, pipeline, segmented, remux]
}

#[cfg(test)]
fn test_mutations(key: &CapabilityKey) -> Vec<CapabilityKey> {
    let mut mutations = Vec::new();
    let mut mutate = |edit: fn(&mut CapabilityKey)| {
        let mut changed = key.clone();
        edit(&mut changed);
        mutations.push(changed);
    };
    mutate(|key| key.versions.schema += 1);
    mutate(|key| key.versions.evidence += 1);
    mutate(|key| key.versions.recipe += 1);
    mutate(|key| key.runtime = test_runtime(0x12));
    mutate(|key| key.device = DeviceId::from_hmac_prefix([0x45; 20]));
    mutate(|key| key.driver = DriverIdentity::from_test_digest([0x56; 32], true));
    mutate(|key| key.driver = DriverIdentity::from_test_digest([0x55; 32], false));
    mutate(|key| key.backend = BackendKind::Vaapi);
    mutate(|key| {
        key.operation = test_keys()
            .into_iter()
            .find(|candidate| candidate.direction() != key.direction())
            .unwrap()
            .operation;
    });
    match &key.operation {
        CapabilityOperation::Decode {
            input,
            requirements,
        } => {
            push_input_mutations(key, input, &mut mutations);
            push_requirement_mutations(key, requirements, &mut mutations);
        }
        CapabilityOperation::Encode {
            output,
            requirements,
        } => {
            push_output_mutations(key, output, &mut mutations);
            push_requirement_mutations(key, requirements, &mut mutations);
        }
        CapabilityOperation::FullPipeline {
            input,
            output,
            requirements,
        } => {
            push_input_mutations(key, input, &mut mutations);
            push_output_mutations(key, output, &mut mutations);
            push_requirement_mutations(key, requirements, &mut mutations);
        }
        CapabilityOperation::SegmentedPipeline {
            input,
            output,
            requirements,
            ..
        } => {
            push_input_mutations(key, input, &mut mutations);
            push_output_mutations(key, output, &mut mutations);
            push_requirement_mutations(key, requirements, &mut mutations);
            let mut changed = key.clone();
            if let CapabilityOperation::SegmentedPipeline { segmentation, .. } =
                &mut changed.operation
            {
                segmentation.exact_frame_rate =
                    RationalRate::new(30_000, NonZeroU32::new(1001).unwrap()).unwrap();
            }
            mutations.push(changed);
            let mut changed = key.clone();
            if let CapabilityOperation::SegmentedPipeline { segmentation, .. } =
                &mut changed.operation
            {
                segmentation.frame_rate_class = FrameRateClass::Variable;
            }
            mutations.push(changed);
            let mut changed = key.clone();
            if let CapabilityOperation::SegmentedPipeline { segmentation, .. } =
                &mut changed.operation
            {
                segmentation.segment_duration_ms = NonZeroU32::new(4_000).unwrap();
            }
            mutations.push(changed);
            let mut changed = key.clone();
            if let CapabilityOperation::SegmentedPipeline { segmentation, .. } =
                &mut changed.operation
            {
                segmentation.output_time_base =
                    RationalRate::new(1, NonZeroU32::new(1_000).unwrap()).unwrap();
            }
            mutations.push(changed);
            let mut changed = key.clone();
            if let CapabilityOperation::SegmentedPipeline { segmentation, .. } =
                &mut changed.operation
            {
                segmentation.keyframe_strategy = KeyframeStrategy::TimeForced {
                    segment_duration_ms: NonZeroU32::new(6_000).unwrap(),
                };
            }
            mutations.push(changed);
        }
        CapabilityOperation::CopyRemux(_) => {
            let edits: [fn(&mut CopyRemuxSignature); 12] = [
                |source: &mut CopyRemuxSignature| source.source_version += 1,
                |source: &mut CopyRemuxSignature| {
                    source.selected_streams = PrivateSourceDigest::from_digest([0x68; 32]);
                },
                |source: &mut CopyRemuxSignature| {
                    source.source_signature = PrivateSourceDigest::from_digest([0x78; 32]);
                },
                |source: &mut CopyRemuxSignature| source.source_codec = InputVideoCodec::Hevc,
                |source: &mut CopyRemuxSignature| source.source_color.range = ColorRange::Full,
                |source: &mut CopyRemuxSignature| {
                    source.source_color.primaries = ColorPrimaries::Bt2020;
                },
                |source: &mut CopyRemuxSignature| {
                    source.source_color.transfer = ColorTransfer::Smpte2084;
                },
                |source: &mut CopyRemuxSignature| {
                    source.source_color.matrix = ColorMatrix::Bt2020Nc;
                },
                |source: &mut CopyRemuxSignature| source.source_color.hdr = HdrMode::Hdr10,
                |source: &mut CopyRemuxSignature| source.sample_entry = SampleEntry::Avc3,
                |source: &mut CopyRemuxSignature| {
                    source.container = OutputContainerContract::Matroska;
                },
                |source: &mut CopyRemuxSignature| {
                    source.boundary_algorithm = BoundaryAlgorithmVersion::V2;
                },
            ];
            for edit in edits {
                let mut changed = key.clone();
                if let CapabilityOperation::CopyRemux(source) = &mut changed.operation {
                    edit(source);
                }
                mutations.push(changed);
            }
        }
    }
    mutations
}

#[cfg(test)]
fn push_input_mutations(
    key: &CapabilityKey,
    _input: &InputVideoSignature,
    mutations: &mut Vec<CapabilityKey>,
) {
    let edits: [fn(&mut InputVideoSignature); 16] = [
        |input| input.codec = InputVideoCodec::Hevc,
        |input| input.profile = VideoProfile::H264Main,
        |input| input.level = CodecLevel::L42,
        |input| input.pixel_format = PixelFormat::Yuv422p,
        |input| input.bit_depth = BitDepth::Ten,
        |input| input.chroma = ChromaSubsampling::Cs422,
        |input| input.color.range = ColorRange::Full,
        |input| input.color.primaries = ColorPrimaries::Bt2020,
        |input| input.color.transfer = ColorTransfer::Smpte2084,
        |input| input.color.matrix = ColorMatrix::Bt2020Nc,
        |input| input.color.hdr = HdrMode::Hdr10,
        |input| input.field_order = FieldOrder::TopFirst,
        |input| input.resolution.width = CodedDimensionBucket::UpTo2560,
        |input| input.resolution.height = CodedDimensionBucket::UpTo1440,
        |input| input.frame_rate = FrameRateBucket::UpTo120,
        |input| input.frame_rate_class = FrameRateClass::Variable,
    ];
    for edit in edits {
        let mut changed = key.clone();
        match &mut changed.operation {
            CapabilityOperation::Decode { input, .. }
            | CapabilityOperation::FullPipeline { input, .. }
            | CapabilityOperation::SegmentedPipeline { input, .. } => edit(input),
            _ => unreachable!(),
        }
        mutations.push(changed);
    }
}

#[cfg(test)]
fn push_output_mutations(
    key: &CapabilityKey,
    _output: &OutputVideoSignature,
    mutations: &mut Vec<CapabilityKey>,
) {
    let edits: [fn(&mut OutputVideoSignature); 15] = [
        |output| output.codec = OutputVideoCodec::Av1,
        |output| output.profile = VideoProfile::HevcMain,
        |output| output.level = CodecLevel::L52,
        |output| output.pixel_format = PixelFormat::Yuv422p10le,
        |output| output.bit_depth = BitDepth::Twelve,
        |output| output.chroma = ChromaSubsampling::Cs422,
        |output| output.color.range = ColorRange::Full,
        |output| output.color.primaries = ColorPrimaries::Bt2020,
        |output| output.color.transfer = ColorTransfer::Smpte2084,
        |output| output.color.matrix = ColorMatrix::Bt2020Nc,
        |output| output.color.hdr = HdrMode::Hdr10,
        |output| output.resolution.width = CodedDimensionBucket::UpTo4096,
        |output| output.resolution.height = CodedDimensionBucket::UpTo2560,
        |output| output.frame_rate = FrameRateBucket::UpTo120,
        |output| output.frame_rate_class = FrameRateClass::Variable,
    ];
    for edit in edits {
        let mut changed = key.clone();
        match &mut changed.operation {
            CapabilityOperation::Encode { output, .. }
            | CapabilityOperation::FullPipeline { output, .. }
            | CapabilityOperation::SegmentedPipeline { output, .. } => edit(output),
            _ => unreachable!(),
        }
        mutations.push(changed);
    }
}

#[cfg(test)]
fn push_requirement_mutations(
    key: &CapabilityKey,
    _requirements: &PipelineRequirements,
    mutations: &mut Vec<CapabilityKey>,
) {
    let edits: [fn(&mut PipelineRequirements); 5] = [
        |requirements| requirements.transforms.push(RequiredTransform::ToneMap),
        |requirements| requirements.transfers.push(RequiredTransfer::Download),
        |requirements| requirements.filters.push(RequiredFilter::ToneMap),
        |requirements| requirements.container = Some(OutputContainerContract::MovMp4),
        |requirements| {
            requirements.output_time_base =
                Some(RationalRate::new(1, NonZeroU32::new(1_000).unwrap()).unwrap());
        },
    ];
    for edit in edits {
        let mut changed = key.clone();
        match &mut changed.operation {
            CapabilityOperation::Decode { requirements, .. }
            | CapabilityOperation::Encode { requirements, .. }
            | CapabilityOperation::FullPipeline { requirements, .. }
            | CapabilityOperation::SegmentedPipeline { requirements, .. } => edit(requirements),
            CapabilityOperation::CopyRemux(_) => unreachable!(),
        }
        mutations.push(changed);
    }
}
