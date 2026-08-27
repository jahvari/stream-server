use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    RuntimeMissing,
    RuntimeUntrusted,
    RuntimeIncompatible,
    DeviceMissing,
    DeviceBusy,
    DriverChanged,
    DecodeUnsupported,
    FilterUnsupported,
    EncodeUnsupported,
    ResolutionUnsupported,
    PixelFormatUnsupported,
    VerificationTimeout,
    VerificationFailed,
    StartupTimeout,
    ProgressStalled,
    InvalidOutput,
    ProcessExit,
    ProcessKilled,
    SoftwareBaselineFailed,
    HardwareFallback,
    ResourceLimit,
    SessionExpired,
    ClientDisconnected,
    ServerShutdown,
}

impl FailureCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeMissing => "runtime_missing",
            Self::RuntimeUntrusted => "runtime_untrusted",
            Self::RuntimeIncompatible => "runtime_incompatible",
            Self::DeviceMissing => "device_missing",
            Self::DeviceBusy => "device_busy",
            Self::DriverChanged => "driver_changed",
            Self::DecodeUnsupported => "decode_unsupported",
            Self::FilterUnsupported => "filter_unsupported",
            Self::EncodeUnsupported => "encode_unsupported",
            Self::ResolutionUnsupported => "resolution_unsupported",
            Self::PixelFormatUnsupported => "pixel_format_unsupported",
            Self::VerificationTimeout => "verification_timeout",
            Self::VerificationFailed => "verification_failed",
            Self::StartupTimeout => "startup_timeout",
            Self::ProgressStalled => "progress_stalled",
            Self::InvalidOutput => "invalid_output",
            Self::ProcessExit => "process_exit",
            Self::ProcessKilled => "process_killed",
            Self::SoftwareBaselineFailed => "software_baseline_failed",
            Self::HardwareFallback => "hardware_fallback",
            Self::ResourceLimit => "resource_limit",
            Self::SessionExpired => "session_expired",
            Self::ClientDisconnected => "client_disconnected",
            Self::ServerShutdown => "server_shutdown",
        }
    }
}

/// A stable public failure with arbitrary diagnostic detail kept internal.
///
/// Free-form public context is deliberately unavailable:
///
/// ```compile_fail
/// use stream_server::transcoding::{FailureCode, TranscodeFailure};
///
/// let _ = TranscodeFailure::new(FailureCode::ProcessExit)
///     .with_safe_context("username", "ExampleUser");
/// ```
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodeFailure {
    code: FailureCode,
    #[serde(skip)]
    internal_detail: Option<String>,
}

impl TranscodeFailure {
    pub fn new(code: FailureCode) -> Self {
        Self {
            code,
            internal_detail: None,
        }
    }

    pub fn code(&self) -> FailureCode {
        self.code
    }

    pub fn with_internal_detail(mut self, detail: impl Into<String>) -> Self {
        self.internal_detail = Some(detail.into());
        self
    }

    #[allow(dead_code)]
    pub(crate) fn internal_detail(&self) -> Option<&str> {
        self.internal_detail.as_deref()
    }
}

impl<'de> Deserialize<'de> for TranscodeFailure {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            code: FailureCode,
        }

        let raw = Raw::deserialize(deserializer)?;
        Ok(Self::new(raw.code))
    }
}

impl fmt::Debug for TranscodeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranscodeFailure")
            .field("code", &self.code.as_str())
            .finish()
    }
}

impl fmt::Display for TranscodeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())?;
        Ok(())
    }
}

impl std::error::Error for TranscodeFailure {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, de::DeserializeOwned};

    fn round_trip<T>(value: T, json: &str)
    where
        T: Clone + Eq + std::fmt::Debug + Serialize + DeserializeOwned,
    {
        assert_eq!(serde_json::to_string(&value).unwrap(), json);
        assert_eq!(serde_json::from_str::<T>(json).unwrap(), value);
    }

    #[test]
    fn failure_codes_use_stable_serde_names() {
        round_trip(FailureCode::RuntimeMissing, "\"runtime_missing\"");
        round_trip(FailureCode::RuntimeUntrusted, "\"runtime_untrusted\"");
        round_trip(FailureCode::RuntimeIncompatible, "\"runtime_incompatible\"");
        round_trip(FailureCode::DeviceMissing, "\"device_missing\"");
        round_trip(FailureCode::DeviceBusy, "\"device_busy\"");
        round_trip(FailureCode::DriverChanged, "\"driver_changed\"");
        round_trip(FailureCode::DecodeUnsupported, "\"decode_unsupported\"");
        round_trip(FailureCode::FilterUnsupported, "\"filter_unsupported\"");
        round_trip(FailureCode::EncodeUnsupported, "\"encode_unsupported\"");
        round_trip(
            FailureCode::ResolutionUnsupported,
            "\"resolution_unsupported\"",
        );
        round_trip(
            FailureCode::PixelFormatUnsupported,
            "\"pixel_format_unsupported\"",
        );
        round_trip(FailureCode::VerificationTimeout, "\"verification_timeout\"");
        round_trip(FailureCode::VerificationFailed, "\"verification_failed\"");
        round_trip(FailureCode::StartupTimeout, "\"startup_timeout\"");
        round_trip(FailureCode::ProgressStalled, "\"progress_stalled\"");
        round_trip(FailureCode::InvalidOutput, "\"invalid_output\"");
        round_trip(FailureCode::ProcessExit, "\"process_exit\"");
        round_trip(FailureCode::ProcessKilled, "\"process_killed\"");
        round_trip(
            FailureCode::SoftwareBaselineFailed,
            "\"software_baseline_failed\"",
        );
        round_trip(FailureCode::HardwareFallback, "\"hardware_fallback\"");
        round_trip(FailureCode::ResourceLimit, "\"resource_limit\"");
        round_trip(FailureCode::SessionExpired, "\"session_expired\"");
        round_trip(FailureCode::ClientDisconnected, "\"client_disconnected\"");
        round_trip(FailureCode::ServerShutdown, "\"server_shutdown\"");
    }

    #[test]
    fn failure_serialization_display_and_debug_are_safe() {
        let failure = TranscodeFailure::new(FailureCode::ProcessExit).with_internal_detail(
            "C:\\Users\\ExampleUser\\Videos\\private.mp4 /home/ExampleUser/private.mp4 \
                 https://user:secret@example.test/video?token=abc \
                 ffmpeg -i secret raw stderr username=ExampleUser /dev/dri/renderD128",
        );

        let serialized = serde_json::to_string(&failure).unwrap();
        let display = failure.to_string();
        let debug = format!("{failure:?}");

        for rendered in [serialized, display, debug] {
            assert!(rendered.contains("process_exit"));
            for secret in [
                "C:\\Users",
                "/home/ExampleUser",
                "secret",
                "token=abc",
                "ffmpeg -i",
                "raw stderr",
                "ExampleUser",
                "/dev/dri",
                "renderD128",
            ] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }

    #[test]
    fn public_failure_json_rejects_every_free_form_secret_class() {
        for (key, value) in [
            ("username", "ExampleUser"),
            ("password", "CorrectHorseBatteryStaple"),
            ("infoHash", "0123456789abcdef0123456789abcdef01234567"),
            ("capabilityToken", "opaqueCapabilityToken123"),
            ("deviceLocator", "PCI00000001"),
        ] {
            let json =
                format!("{{\"code\":\"process_exit\",\"context\":{{\"{key}\":\"{value}\"}}}}");
            assert!(
                serde_json::from_str::<TranscodeFailure>(&json).is_err(),
                "accepted {key}"
            );
        }
    }

    #[test]
    fn alphanumeric_internal_secrets_never_reach_public_surfaces() {
        let secrets = [
            "ExampleUser",
            "CorrectHorseBatteryStaple",
            "0123456789abcdef0123456789abcdef01234567",
            "opaqueCapabilityToken123",
            "PCI00000001",
        ];
        let failure =
            TranscodeFailure::new(FailureCode::ProcessExit).with_internal_detail(secrets.join(" "));

        let serialized = serde_json::to_string(&failure).unwrap();
        let display = failure.to_string();
        let debug = format!("{failure:?}");

        for rendered in [serialized, display, debug] {
            assert!(rendered.contains("process_exit"));
            for secret in secrets {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }
}
