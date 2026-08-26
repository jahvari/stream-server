#[cfg(all(windows, target_arch = "x86_64"))]
use crate::transcoding::runtime::ensure_managed_runtime;
#[cfg(all(windows, target_arch = "x86_64"))]
use crate::transcoding::runtime_manifest::{RuntimeHost, RuntimeManifest};
use crate::transcoding::{
    process::ProcessSupervisor,
    runtime::{RuntimeConfig, TranscodingService, resolve_runtime},
    runtime_manifest::RuntimeError,
};
use anyhow::Result;
use std::{error::Error, fmt, path::Path, sync::Arc};

#[derive(Debug)]
pub struct MissingFfmpegError {
    details: &'static str,
}

impl MissingFfmpegError {
    #[allow(dead_code)]
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
            RuntimeError::UnsafePath => {
                "The configured FFmpeg location is not a trusted local directory. Correct the configuration, then start Stream Server again."
            }
            RuntimeError::ProbeDeadline => {
                "FFmpeg identity verification timed out. Check the configured runtime and system load, then start Stream Server again."
            }
            RuntimeError::ProbeFailed => {
                "FFmpeg identity verification failed. Check the configured FFmpeg and FFprobe pair, then start Stream Server again."
            }
            RuntimeError::IncompatiblePair | RuntimeError::RuntimeChanged => {
                "The configured FFmpeg and FFprobe pair is incompatible or changed during verification. Correct the runtime, then start Stream Server again."
            }
            RuntimeError::InvalidManifest(_) => {
                "The embedded managed-runtime manifest is invalid. Reinstall or update Stream Server."
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

fn eligible_for_managed_acquisition(error: &RuntimeError) -> bool {
    matches!(error, RuntimeError::Unavailable)
}

#[cfg(any(test, all(windows, target_arch = "x86_64")))]
async fn run_startup_acquisition_policy<T, F, Fut>(
    resolution_error: RuntimeError,
    acquisition: F,
) -> Result<T, RuntimeError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, RuntimeError>>,
{
    if !eligible_for_managed_acquisition(&resolution_error) {
        return Err(resolution_error);
    }
    acquisition().await
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn platform_absence_error(error: RuntimeError) -> RuntimeError {
    if !eligible_for_managed_acquisition(&error) {
        return error;
    }
    #[cfg(target_os = "linux")]
    {
        RuntimeError::AdministratorRuntimeRequired
    }
    #[cfg(target_os = "macos")]
    {
        RuntimeError::ManagedRuntimeUnsupported
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        RuntimeError::ManagedRuntimeUnsupported
    }
}

/// Compatibility startup adapter. Acquisition is implemented by the managed
/// installer; this adapter only resolves an already-installed paired runtime.
pub(crate) async fn setup_ffmpeg(
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
                let runtime = run_startup_acquisition_policy(resolution_error, || async {
                    let manifest = RuntimeManifest::embedded()?;
                    let artifact = manifest
                        .artifact_for_host(RuntimeHost::WindowsX64)
                        .ok_or(RuntimeError::Unavailable)?;
                    ensure_managed_runtime(&config_dir.join("runtimes"), artifact, &supervisor)
                        .await
                })
                .await
                .map_err(|error| anyhow::anyhow!(MissingFfmpegError::from_runtime(error)))?;
                Ok(Arc::new(TranscodingService::resolved(
                    config, supervisor, runtime,
                )))
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                Err(
                    MissingFfmpegError::from_runtime(platform_absence_error(resolution_error))
                        .into(),
                )
            }
        }
    }
}

/// Compatibility adapter for callers that already own resolution policy.
/// It resolves one adjacent pair and does not alter process-global search state.
#[allow(dead_code)]
pub(crate) async fn setup_ffmpeg_with_config(
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

pub(crate) fn unavailable_service(supervisor: Arc<ProcessSupervisor>) -> Arc<TranscodingService> {
    Arc::new(TranscodingService::unavailable(supervisor))
}

#[cfg(test)]
mod tests {
    use crate::transcoding::runtime_manifest::RuntimeError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn startup_acquires_only_for_semantically_classified_absence() {
        let acquisitions = std::sync::Arc::new(AtomicUsize::new(0));
        for error in [
            RuntimeError::Unavailable,
            RuntimeError::ProbeDeadline,
            RuntimeError::UnsafePath,
            RuntimeError::ProbeFailed,
            RuntimeError::IncompatiblePair,
            RuntimeError::RuntimeChanged,
            RuntimeError::AdministratorRuntimeRequired,
        ] {
            let observed = std::sync::Arc::clone(&acquisitions);
            let _ = super::run_startup_acquisition_policy(error, move || async move {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok::<_, RuntimeError>(())
            })
            .await;
        }
        assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_production_absence_requires_administrator_runtime_without_acquisition() {
        assert_eq!(
            super::platform_absence_error(RuntimeError::Unavailable),
            RuntimeError::AdministratorRuntimeRequired
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_production_absence_reports_managed_runtime_unsupported() {
        assert_eq!(
            super::platform_absence_error(RuntimeError::Unavailable),
            RuntimeError::ManagedRuntimeUnsupported
        );
    }
}
