use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::BTreeMap, fmt};

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

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscodeFailure {
    pub code: FailureCode,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    context: BTreeMap<String, String>,
    #[serde(skip)]
    internal_detail: Option<String>,
}

impl TranscodeFailure {
    pub fn new(code: FailureCode) -> Self {
        Self {
            code,
            context: BTreeMap::new(),
            internal_detail: None,
        }
    }

    pub fn with_safe_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = sanitize_context_token(key.into());
        let value = sanitize_context_token(value.into());
        if let (Some(key), Some(value)) = (key, value) {
            self.context.insert(key, value);
        }
        self
    }

    pub fn context(&self) -> &BTreeMap<String, String> {
        &self.context
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
        #[serde(rename_all = "camelCase")]
        struct Raw {
            code: FailureCode,
            #[serde(default)]
            context: BTreeMap<String, String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let mut failure = Self::new(raw.code);
        for (key, value) in raw.context {
            let sanitized_key = sanitize_context_token(key.clone())
                .ok_or_else(|| serde::de::Error::custom("unsafe failure context key"))?;
            if sanitized_key != key {
                return Err(serde::de::Error::custom("unsafe failure context key"));
            }
            let sanitized_value = sanitize_context_token(value.clone())
                .ok_or_else(|| serde::de::Error::custom("unsafe failure context value"))?;
            if sanitized_value != value {
                return Err(serde::de::Error::custom("unsafe failure context value"));
            }
            failure.context.insert(key, value);
        }

        Ok(failure)
    }
}

impl fmt::Debug for TranscodeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TranscodeFailure")
            .field("code", &self.code.as_str())
            .field("context", &self.context)
            .finish()
    }
}

impl fmt::Display for TranscodeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())?;
        for (key, value) in &self.context {
            write!(f, " {key}={value}")?;
        }
        Ok(())
    }
}

impl std::error::Error for TranscodeFailure {}

fn sanitize_context_token(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return None;
    }

    if trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

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
        let failure = TranscodeFailure::new(FailureCode::ProcessExit)
            .with_safe_context("stage", "encode")
            .with_internal_detail(
                "C:\\Users\\Hunter\\Videos\\private.mp4 /home/hunter/private.mp4 \
                 https://user:secret@example.test/video?token=abc \
                 ffmpeg -i secret raw stderr username=Hunter /dev/dri/renderD128",
            );

        let serialized = serde_json::to_string(&failure).unwrap();
        let display = failure.to_string();
        let debug = format!("{failure:?}");

        for rendered in [serialized, display, debug] {
            assert!(rendered.contains("process_exit"));
            assert!(rendered.contains("encode"));
            for secret in [
                "C:\\Users",
                "/home/hunter",
                "secret",
                "token=abc",
                "ffmpeg -i",
                "raw stderr",
                "Hunter",
                "/dev/dri",
                "renderD128",
            ] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }

    #[test]
    fn unsafe_context_is_rejected_from_json() {
        let json = concat!(
            "{\"code\":\"process_exit\",\"context\":{",
            "\"stage\":\"encode\",",
            "\"path\":\"C:\\\\Users\\\\Hunter\\\\Videos\\\\private.mp4\",",
            "\"url\":\"https://user:secret@example.test/video?token=abc\"",
            "}}"
        );

        assert!(serde_json::from_str::<TranscodeFailure>(json).is_err());
    }

    #[test]
    fn unsafe_context_is_not_representable_through_public_builder() {
        let failure = TranscodeFailure::new(FailureCode::ProcessExit)
            .with_safe_context("stage", "encode")
            .with_safe_context("path", "C:\\Users\\Hunter\\Videos\\private.mp4")
            .with_safe_context("url", "https://user:secret@example.test/video?token=abc")
            .with_safe_context("stderr", "raw stderr");

        let serialized = serde_json::to_string(&failure).unwrap();
        let display = failure.to_string();
        let debug = format!("{failure:?}");

        for rendered in [serialized, display, debug] {
            assert!(rendered.contains("process_exit"));
            assert!(rendered.contains("encode"));
            assert!(!rendered.contains("C:\\Users"), "{rendered}");
            assert!(!rendered.contains("secret"), "{rendered}");
            assert!(!rendered.contains("token=abc"), "{rendered}");
            assert!(!rendered.contains("raw stderr"), "{rendered}");
        }
    }
}
