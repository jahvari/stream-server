use crate::transcoding::{BackendKind, DeviceClass, DeviceId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, collections::HashSet, fmt, sync::Arc};

pub(crate) mod identity;
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(
    test,
    target_os = "macos",
    not(any(windows, target_os = "linux", target_os = "macos"))
))]
mod macos;
#[cfg(any(windows, test))]
mod windows;
#[cfg(test)]
pub(crate) use identity::DriverField;
use identity::{
    DeviceIdSeed, DriverIdentity, PlatformTag, PrivateDeviceIdentity, derive_device_id,
    derive_driver_identity,
};
pub(crate) use identity::{DriverRecord, DriverRunEpoch};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Vendor {
    Intel,
    Nvidia,
    Amd,
    Apple,
    Microsoft,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum DeviceAvailability {
    Available,
    LocatorUnavailable,
    PermissionDenied,
    AdministrativelyDisabled,
    Stale,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) enum DeviceLocator {
    Windows {
        adapter_luid: i64,
        physical_index: Option<u32>,
    },
    Linux {
        render_node: Vec<u8>,
        device_number: u64,
    },
    MacosDefault,
    Unavailable,
}

impl fmt::Debug for DeviceLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceLocator([redacted])")
    }
}

impl fmt::Display for DeviceLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

impl DeviceLocator {
    fn input_size(&self) -> Result<usize, DeviceError> {
        match self {
            Self::Windows { physical_index, .. } => {
                Ok(8 + usize::from(physical_index.is_some()) * 4)
            }
            Self::Linux { render_node, .. } if render_node.len() <= MAX_PRIVATE_INPUT_BYTES => {
                render_node
                    .len()
                    .checked_add(8)
                    .ok_or(DeviceError::Overflow)
            }
            Self::Linux { .. } => Err(DeviceError::Overflow),
            Self::MacosDefault | Self::Unavailable => Ok(0),
        }
    }

    fn is_concrete(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

#[derive(Clone)]
pub(crate) struct PlatformDeviceRecord {
    pub(crate) platform: PlatformTag,
    pub(crate) display_name: Vec<u8>,
    pub(crate) vendor: Vendor,
    pub(crate) class: DeviceClass,
    pub(crate) availability: DeviceAvailability,
    pub(crate) persistent_identity: PrivateDeviceIdentity,
    pub(crate) locator: DeviceLocator,
    pub(crate) driver: DriverRecord,
    pub(crate) backends: Vec<BackendKind>,
}

impl fmt::Debug for PlatformDeviceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformDeviceRecord([redacted])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct SafeDeviceName(String);

impl SafeDeviceName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn from_candidate(
        candidate: &[u8],
        vendor: Vendor,
        class: DeviceClass,
    ) -> Result<Self, DeviceError> {
        if candidate.len() > MAX_PRIVATE_INPUT_BYTES {
            return Err(DeviceError::Overflow);
        }
        let candidate = String::from_utf8_lossy(candidate);
        let lowered = candidate.to_ascii_lowercase();
        let forbidden = candidate.chars().any(is_unsafe_display_character)
            || ['/', '\\', ':', '%', '@']
                .into_iter()
                .any(|marker| candidate.contains(marker))
            || candidate.contains("..")
            || ["pci\\", "ven_", "dev_", "subsys_", "gpu1_"]
                .into_iter()
                .any(|marker| lowered.contains(marker));
        if forbidden {
            return Ok(Self(fallback_name(vendor, class)));
        }
        let mut normalized = candidate.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized.is_empty() {
            return Ok(Self(fallback_name(vendor, class)));
        }
        if normalized.len() > MAX_SAFE_NAME_BYTES {
            let mut end = MAX_SAFE_NAME_BYTES;
            while !normalized.is_char_boundary(end) {
                end -= 1;
            }
            normalized.truncate(end);
        }
        if normalized.is_empty() {
            normalized = fallback_name(vendor, class);
        }
        Ok(Self(normalized))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceError {
    Invalid,
    Ambiguous,
    Overflow,
    Cancelled,
}

impl fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "device_enumeration_failed",
            Self::Ambiguous => "device_mapping_ambiguous",
            Self::Overflow => "inventory_overflow",
            Self::Cancelled => "refresh_cancelled",
        })
    }
}

impl std::error::Error for DeviceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceDiscoveryStatus {
    Supported,
    PlatformUnsupported,
}

impl DeviceDiscoveryStatus {
    pub(crate) fn safe_reason(self) -> Option<&'static str> {
        match self {
            Self::Supported => None,
            Self::PlatformUnsupported => Some("platform_unsupported"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DeviceDiscovery {
    pub(crate) records: Vec<PlatformDeviceRecord>,
    pub(crate) status: DeviceDiscoveryStatus,
}

impl DeviceDiscovery {
    pub(crate) fn supported(records: Vec<PlatformDeviceRecord>) -> Self {
        Self {
            records,
            status: DeviceDiscoveryStatus::Supported,
        }
    }

    pub(crate) fn platform_unsupported(records: Vec<PlatformDeviceRecord>) -> Self {
        Self {
            records,
            status: DeviceDiscoveryStatus::PlatformUnsupported,
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait DeviceEnumerator: Send + Sync {
    async fn enumerate(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<DeviceDiscovery, DeviceError>;
}

pub(crate) fn production_device_enumerator() -> Arc<dyn DeviceEnumerator> {
    #[cfg(windows)]
    {
        Arc::new(windows::WindowsDeviceEnumerator)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(linux::LinuxDeviceEnumerator)
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(macos::MacosDeviceEnumerator)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Arc::new(macos::UnsupportedDeviceEnumerator)
    }
}

#[derive(Clone)]
pub(crate) struct TranscodingDevice {
    pub(crate) id: DeviceId,
    pub(crate) display_name: SafeDeviceName,
    pub(crate) vendor: Vendor,
    pub(crate) class: DeviceClass,
    pub(crate) availability: DeviceAvailability,
    pub(crate) backends: BTreeSet<BackendKind>,
    private_identity: PrivateDeviceIdentity,
    locator: DeviceLocator,
    pub(crate) driver_identity: DriverIdentity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicDeviceProjection<'a> {
    id: &'a DeviceId,
    display_name: &'a str,
    vendor: Vendor,
    class: DeviceClass,
    availability: DeviceAvailability,
    backends: &'a BTreeSet<BackendKind>,
    driver_identity_complete: bool,
}

impl TranscodingDevice {
    pub(crate) fn public_projection(&self) -> PublicDeviceProjection<'_> {
        PublicDeviceProjection {
            id: &self.id,
            display_name: self.display_name.as_str(),
            vendor: self.vendor,
            class: self.class,
            availability: self.availability,
            backends: &self.backends,
            driver_identity_complete: self.driver_identity.is_persistable(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_identity(
        id: DeviceId,
        driver_identity: DriverIdentity,
        backend: BackendKind,
    ) -> Self {
        Self {
            id,
            display_name: SafeDeviceName("Test GPU".to_owned()),
            vendor: Vendor::Other,
            class: DeviceClass::Unknown,
            availability: DeviceAvailability::Available,
            backends: BTreeSet::from([backend]),
            private_identity: PrivateDeviceIdentity::new(vec![1]).expect("bounded fixture"),
            locator: DeviceLocator::Unavailable,
            driver_identity,
        }
    }
}

impl fmt::Debug for TranscodingDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranscodingDevice")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("vendor", &self.vendor)
            .field("class", &self.class)
            .field("availability", &self.availability)
            .field("backends", &self.backends)
            .field("private_identity", &"[redacted]")
            .field("locator", &"[redacted]")
            .field("driver_identity", &"[redacted]")
            .finish()
    }
}

pub(crate) fn normalize_platform_records(
    records: Vec<PlatformDeviceRecord>,
    seed: &DeviceIdSeed,
    run_epoch: &DriverRunEpoch,
) -> Result<Vec<TranscodingDevice>, DeviceError> {
    normalize_platform_records_using(records, seed, run_epoch, |seed, platform, identity| {
        derive_device_id(seed, platform, identity).map_err(|_| DeviceError::Invalid)
    })
}

#[cfg(test)]
pub(crate) fn normalize_platform_records_with_deriver(
    records: Vec<PlatformDeviceRecord>,
    seed: &DeviceIdSeed,
    run_epoch: &DriverRunEpoch,
    mut derive_id: impl FnMut(
        &DeviceIdSeed,
        PlatformTag,
        &PrivateDeviceIdentity,
    ) -> Result<DeviceId, DeviceError>,
) -> Result<Vec<TranscodingDevice>, DeviceError> {
    normalize_platform_records_using(records, seed, run_epoch, &mut derive_id)
}

fn normalize_platform_records_using(
    records: Vec<PlatformDeviceRecord>,
    seed: &DeviceIdSeed,
    run_epoch: &DriverRunEpoch,
    mut derive_id: impl FnMut(
        &DeviceIdSeed,
        PlatformTag,
        &PrivateDeviceIdentity,
    ) -> Result<DeviceId, DeviceError>,
) -> Result<Vec<TranscodingDevice>, DeviceError> {
    if records.len() > MAX_RAW_DEVICES {
        return Err(DeviceError::Overflow);
    }
    let aggregate_size = records.iter().try_fold(0_usize, |size, record| {
        size.checked_add(validate_record_size(record)?)
            .ok_or(DeviceError::Overflow)
    })?;
    if aggregate_size > MAX_AGGREGATE_INPUT_BYTES {
        return Err(DeviceError::Overflow);
    }
    let mut identities = HashSet::with_capacity(records.len());
    let mut locators = HashSet::with_capacity(records.len());
    let mut public_ids = HashSet::with_capacity(records.len());
    let mut devices = Vec::with_capacity(records.len());
    for record in records {
        if !identities.insert((record.platform, record.persistent_identity.clone())) {
            return Err(DeviceError::Ambiguous);
        }
        if record.locator.is_concrete() && !locators.insert(record.locator.clone()) {
            return Err(DeviceError::Ambiguous);
        }
        let id = derive_id(seed, record.platform, &record.persistent_identity)?;
        if !public_ids.insert(id.clone()) {
            return Err(DeviceError::Ambiguous);
        }
        let driver_identity = derive_driver_identity(record.platform, &record.driver, run_epoch)
            .map_err(|_| DeviceError::Invalid)?;
        let display_name =
            SafeDeviceName::from_candidate(&record.display_name, record.vendor, record.class)?;
        devices.push(TranscodingDevice {
            id,
            display_name,
            vendor: record.vendor,
            class: record.class,
            availability: record.availability,
            backends: record.backends.into_iter().collect(),
            private_identity: record.persistent_identity,
            locator: record.locator,
            driver_identity,
        });
    }
    devices.sort_unstable_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    Ok(devices)
}

const MAX_RAW_DEVICES: usize = 32;
const MAX_AGGREGATE_INPUT_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_INPUT_BYTES: usize = 2_048;
const MAX_SAFE_NAME_BYTES: usize = 128;
fn validate_record_size(record: &PlatformDeviceRecord) -> Result<usize, DeviceError> {
    if record.display_name.len() > MAX_PRIVATE_INPUT_BYTES
        || record.persistent_identity.len() > MAX_PRIVATE_INPUT_BYTES
    {
        return Err(DeviceError::Overflow);
    }
    if !record.driver.is_structurally_valid() {
        return Err(DeviceError::Invalid);
    }
    let driver_size = record
        .driver
        .framed_size()
        .map_err(|_| DeviceError::Overflow)?;
    [
        record.display_name.len(),
        record.persistent_identity.len(),
        record.locator.input_size()?,
        driver_size,
        record.backends.len(),
    ]
    .into_iter()
    .try_fold(0_usize, |size, part| {
        size.checked_add(part).ok_or(DeviceError::Overflow)
    })
}

fn fallback_name(vendor: Vendor, class: DeviceClass) -> String {
    let vendor = match vendor {
        Vendor::Intel => "Intel",
        Vendor::Nvidia => "NVIDIA",
        Vendor::Amd => "AMD",
        Vendor::Apple => "Apple",
        Vendor::Microsoft => "Microsoft",
        Vendor::Other => "Other",
        Vendor::Unknown => "Unknown",
    };
    let class = match class {
        DeviceClass::Integrated => "integrated",
        DeviceClass::Discrete => "discrete",
        DeviceClass::Virtual => "virtual",
        DeviceClass::Software => "software",
        DeviceClass::Unknown => "unknown",
    };
    format!("{vendor} {class} GPU")
}

fn is_unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character as u32,
            0x00ad
                | 0x061c
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x2064
                | 0x2066..=0x206f
                | 0xfeff
        )
}

#[cfg(test)]
mod tests;
