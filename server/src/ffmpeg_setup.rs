#[cfg(all(windows, target_arch = "x86_64"))]
use crate::transcoding::runtime_manifest::{RuntimeHost, RuntimeManifest};
use crate::transcoding::{
    process::ProcessSupervisor,
    runtime::{RuntimeConfig, TranscodingService, ensure_managed_runtime, resolve_runtime},
    runtime_manifest::RuntimeError,
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

    fn from_runtime(error: RuntimeError) -> Self {
        let details = match error {
            RuntimeError::AdministratorRuntimeRequired => {
                "Install the administrator-provided Jellyfin FFmpeg package, then start Stream Server again."
            }
            RuntimeError::ManagedRuntimeUnsupported => {
                "Managed FFmpeg is unavailable on this platform. Install a compatible FFmpeg and FFprobe pair, then start Stream Server again."
            }
            _ => "No compatible FFmpeg and FFprobe pair is available.",
        };
        Self { details }
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
    match resolve_runtime(&config, &supervisor).await {
        Ok(runtime) => Ok(Arc::new(TranscodingService::resolved(
            config, supervisor, runtime,
        ))),
        Err(resolution_error) => {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                let _ = resolution_error;
                let manifest = RuntimeManifest::embedded()
                    .map_err(|error| anyhow::anyhow!(MissingFfmpegError::from_runtime(error)))?;
                let artifact = manifest
                    .artifact_for_host(RuntimeHost::WindowsX64)
                    .ok_or_else(|| anyhow::anyhow!(MissingFfmpegError::unavailable()))?;
                let runtime =
                    ensure_managed_runtime(&config_dir.join("runtimes"), artifact, &supervisor)
                        .await
                        .map_err(|error| {
                            anyhow::anyhow!(MissingFfmpegError::from_runtime(error))
                        })?;
                Ok(Arc::new(TranscodingService::resolved(
                    config, supervisor, runtime,
                )))
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                Err(MissingFfmpegError::from_runtime(resolution_error).into())
            }
        }
    }
}

/// Compatibility adapter for callers that already own resolution policy.
/// It resolves one adjacent pair and does not alter process-global search state.
pub async fn setup_ffmpeg_with_config(
    config: RuntimeConfig,
    supervisor: Arc<ProcessSupervisor>,
) -> Result<Arc<TranscodingService>> {
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
