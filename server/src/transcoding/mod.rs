#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod capability;
pub mod codec;
/// Device identity material is intentionally unavailable to external callers.
///
/// ```compile_fail
/// use stream_server::transcoding::device::identity::{
///     DeviceIdSeed, DriverIdentity, PrivateDeviceIdentity,
/// };
/// use stream_server::transcoding::device::DeviceLocator;
/// ```
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod device;
pub mod error;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod inventory;
pub mod model;
pub mod probe;
/// Raw process construction is internal to the transcoding runtime.
///
/// ```compile_fail
/// use stream_server::transcoding::process::{ProcessSpec, ProcessSupervisor};
/// fn bypass(supervisor: &ProcessSupervisor, spec: ProcessSpec) {
///     let _ = supervisor.run_bounded(spec);
/// }
/// ```
pub(crate) mod process;
pub mod runtime;
pub mod runtime_manifest;
#[cfg(any(unix, test))]
pub(crate) mod snapshot_helper;
pub mod source;

pub use codec::{
    ChromaSubsampling, ColorMatrix, ColorPrimaries, ColorRange, ColorTransfer, ContainerKind,
    FieldOrder, InputVideoCodec, OutputVideoCodec, PixelFormat, SampleEntry, VideoProfile,
};
pub use error::{FailureCode, TranscodeFailure};
pub use model::{
    AccelerationClass, AccelerationMode, BackendKind, CapabilityState, DeviceClass, DeviceId,
    FrameRateClass, KeyframeStrategy, MediaDescriptor, OutputContract, PresetIntent,
    RateControlEnvelope, RateControlIntent, RationalRate, StageKind, StageMode, TranscodePlan,
    TranscodeRequest, VideoStage,
};
pub use probe::{
    AudioStreamDescriptor, ChapterDescriptor, ColorDescriptor, ContentLightMetadata,
    DolbyVisionMetadata, HdrMetadata, MasteringDisplayMetadata, MediaStreamDescriptor,
    ProbeDocument, ProbeError, ProbeErrorCode, ProbeRational, SafeProbeText, StreamDisposition,
    SubtitleStreamDescriptor, VideoStreamDescriptor, parse_probe_document, probe_media,
};
pub use source::{
    CompletedFileSource, EngineSource, FixtureSource, RemoteSourceHandle, SourceActivitySnapshot,
    SourceBroker, SourceError, SourceProtocolPolicy, ValidatedMediaSource, issue_engine_source,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;

    #[test]
    fn public_exports_can_compose_a_minimal_request() {
        let source = ValidatedMediaSource::completed_file("media-source").unwrap();
        let envelope = RateControlEnvelope::new(
            RateControlIntent::ConstrainedVariable,
            4_000_000,
            6_000_000,
            12_000_000,
            PresetIntent::Balanced,
            Some(RationalRate::new(60_000, NonZeroU32::new(2_000).unwrap()).unwrap()),
            NonZeroU32::new(1920).unwrap(),
            NonZeroU32::new(1080).unwrap(),
            128_000,
        )
        .unwrap();
        let output = OutputContract::new(
            envelope,
            KeyframeStrategy::FixedGop {
                frames: NonZeroU32::new(120).unwrap(),
            },
        );
        let request = TranscodeRequest::new(source, output, AccelerationMode::Auto);
        let plan = TranscodePlan::new(
            request,
            vec![
                VideoStage::software(StageKind::Decode),
                VideoStage::software(StageKind::Encode),
            ],
        )
        .unwrap();

        assert_eq!(plan.acceleration_class(), AccelerationClass::Software);
        assert_eq!(plan.stages().len(), 2);
    }
}
