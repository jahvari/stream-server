use super::identity::{DriverField, DriverRecord, PlatformTag, PrivateDeviceIdentity};
use super::{
    DeviceAvailability, DeviceDiscovery, DeviceError, DeviceLocator, PlatformDeviceRecord, Vendor,
};
use crate::transcoding::{BackendKind, DeviceClass};

const MACOS_LOGICAL_IDENTITY: &[u8] = b"macos-videotoolbox-default-v1";
const MAX_PRIVATE_INPUT_BYTES: usize = 2_048;
const MAX_OS_BUILD_BYTES: usize = 256;

pub(super) fn logical_macos_discovery(
    os_build: Option<Vec<u8>>,
) -> Result<DeviceDiscovery, DeviceError> {
    let persistent_identity = PrivateDeviceIdentity::new(MACOS_LOGICAL_IDENTITY.to_vec())
        .map_err(|_| DeviceError::Invalid)?;
    let driver = match os_build {
        Some(os_build) => {
            validate_os_build(&os_build)?;
            DriverRecord::Complete(vec![
                DriverField::new(1, MACOS_LOGICAL_IDENTITY.to_vec()),
                DriverField::new(2, os_build),
            ])
        }
        None => DriverRecord::Incomplete,
    };
    Ok(DeviceDiscovery::platform_unsupported(vec![
        PlatformDeviceRecord {
            platform: PlatformTag::Macos,
            display_name: b"Apple VideoToolbox".to_vec(),
            vendor: Vendor::Apple,
            class: DeviceClass::Unknown,
            availability: DeviceAvailability::AdministrativelyDisabled,
            persistent_identity,
            locator: DeviceLocator::MacosDefault,
            driver,
            backends: vec![BackendKind::VideoToolbox],
        },
    ]))
}

pub(super) fn unsupported_platform_discovery() -> DeviceDiscovery {
    DeviceDiscovery::platform_unsupported(Vec::new())
}

#[cfg(any(test, not(any(windows, target_os = "linux", target_os = "macos"))))]
pub(crate) struct UnsupportedDeviceEnumerator;

#[cfg(any(test, not(any(windows, target_os = "linux", target_os = "macos"))))]
#[async_trait::async_trait]
impl super::DeviceEnumerator for UnsupportedDeviceEnumerator {
    async fn enumerate(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<DeviceDiscovery, DeviceError> {
        if cancellation.is_cancelled() {
            Err(DeviceError::Cancelled)
        } else {
            Ok(unsupported_platform_discovery())
        }
    }
}

fn validate_os_build(os_build: &[u8]) -> Result<(), DeviceError> {
    if os_build.len() > MAX_PRIVATE_INPUT_BYTES || os_build.len() > MAX_OS_BUILD_BYTES {
        return Err(DeviceError::Overflow);
    }
    if os_build.is_empty()
        || !os_build[0].is_ascii_alphanumeric()
        || os_build.iter().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
        })
    {
        return Err(DeviceError::Invalid);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use crate::transcoding::device::DeviceEnumerator;
    use std::ffi::c_void;
    use tokio_util::sync::CancellationToken;

    const OS_BUILD_SYSCTL: &[u8] = b"kern.osversion\0";

    pub(crate) struct MacosDeviceEnumerator;

    #[async_trait::async_trait]
    impl DeviceEnumerator for MacosDeviceEnumerator {
        async fn enumerate(
            &self,
            cancellation: CancellationToken,
        ) -> Result<DeviceDiscovery, DeviceError> {
            check_cancelled(&cancellation)?;
            let first = read_os_build(&cancellation)?;
            check_cancelled(&cancellation)?;
            let second = read_os_build(&cancellation)?;
            let stable_build = if first == second { first } else { None };
            logical_macos_discovery(stable_build)
        }
    }

    fn read_os_build(cancellation: &CancellationToken) -> Result<Option<Vec<u8>>, DeviceError> {
        check_cancelled(cancellation)?;
        let mut size = 0_usize;
        // SAFETY: the name is a fixed NUL-terminated sysctl key and size is writable.
        let probe = unsafe {
            libc::sysctlbyname(
                OS_BUILD_SYSCTL.as_ptr().cast(),
                std::ptr::null_mut(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if probe != 0 || !(2..=MAX_OS_BUILD_BYTES + 1).contains(&size) {
            return Ok(None);
        }
        check_cancelled(cancellation)?;
        let mut bytes = vec![0_u8; size];
        let mut actual_size = size;
        // SAFETY: bytes is writable for actual_size and the fixed query has no new value.
        let result = unsafe {
            libc::sysctlbyname(
                OS_BUILD_SYSCTL.as_ptr().cast(),
                bytes.as_mut_ptr().cast::<c_void>(),
                &raw mut actual_size,
                std::ptr::null_mut(),
                0,
            )
        };
        check_cancelled(cancellation)?;
        if result != 0
            || actual_size != size
            || bytes.last() != Some(&0)
            || bytes[..bytes.len() - 1].contains(&0)
        {
            return Ok(None);
        }
        bytes.pop();
        if validate_os_build(&bytes).is_err() {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    fn check_cancelled(cancellation: &CancellationToken) -> Result<(), DeviceError> {
        if cancellation.is_cancelled() {
            Err(DeviceError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(target_os = "macos", test))]
pub(super) use native::MacosDeviceEnumerator;
