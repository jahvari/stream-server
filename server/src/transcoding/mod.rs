pub mod error;
pub mod model;
pub mod process;
pub mod runtime;
pub mod runtime_manifest;

pub use error::{FailureCode, TranscodeFailure};
pub use model::{
    AccelerationClass, AccelerationMode, BackendKind, CapabilityState, DeviceClass, DeviceId,
    FrameRateClass, KeyframeStrategy, MediaDescriptor, OutputContract, PresetIntent,
    RateControlEnvelope, RateControlIntent, RationalRate, StageKind, StageMode, TranscodePlan,
    TranscodeRequest, ValidatedMediaSource, VideoStage,
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
