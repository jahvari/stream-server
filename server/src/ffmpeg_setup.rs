use crate::transcoding::{
    process::ProcessSupervisor,
    runtime::{RuntimeConfig, TranscodingService, resolve_runtime},
};
use anyhow::Result;
use std::{error::Error, fmt, path::Path, sync::Arc};

#[derive(Debug)]
pub struct MissingFfmpegError {
    details: &'static str,
}

impl MissingFfmpegError {
    fn unavailable() -> Self {
        Self {
            details: "No compatible FFmpeg and FFprobe pair is available.",
        }
    }

    pub fn details(&self) -> &str {
        self.details
    }
}

impl fmt::Display for MissingFfmpegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.details)
    }
}

impl Error for MissingFfmpegError {}

/// Compatibility startup adapter. Acquisition is implemented by the managed
/// installer; this adapter only resolves an already-installed paired runtime.
pub async fn setup_ffmpeg(
    config_dir: &Path,
    supervisor: Arc<ProcessSupervisor>,
) -> Result<Arc<TranscodingService>> {
    let config = RuntimeConfig::for_server(config_dir);
    let runtime = resolve_runtime(&config, &supervisor)
        .await
        .map_err(|_| MissingFfmpegError::unavailable())?;
    Ok(Arc::new(TranscodingService::resolved(
        config, supervisor, runtime,
    )))
}

pub fn unavailable_service(supervisor: Arc<ProcessSupervisor>) -> Arc<TranscodingService> {
    Arc::new(TranscodingService::unavailable(supervisor))
}
