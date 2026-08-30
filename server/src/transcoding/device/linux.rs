use super::identity::{DriverField, DriverRecord, PlatformTag, PrivateDeviceIdentity};
use super::{DeviceAvailability, DeviceError, DeviceLocator, PlatformDeviceRecord, Vendor};
use crate::transcoding::{BackendKind, DeviceClass};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

const LINUX_DEVICE_DOMAIN: &[u8] = b"linux-device/v1\0";
const MAX_PRIVATE_INPUT_BYTES: usize = 2_048;
const MAX_LINUX_RENDER_DEVICES: usize = 32;
const MAX_MODULE_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum LinuxBusKind {
    Pci = 1,
    Platform = 2,
    Virtio = 3,
    Mediated = 4,
    Other = 5,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub(super) struct LinuxStableFields {
    pub(super) vendor: Option<u16>,
    pub(super) device: Option<u16>,
    pub(super) subsystem_vendor: Option<u16>,
    pub(super) subsystem_device: Option<u16>,
    pub(super) revision: Option<u8>,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct LinuxIdentityInput {
    pub(super) bus: LinuxBusKind,
    pub(super) target_relative: Vec<u8>,
    pub(super) fields: LinuxStableFields,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinuxClassEvidence {
    Integrated,
    Discrete,
    Virtual,
    Unknown,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) enum LinuxLocatorStatus {
    Available { device_number: u64 },
    Missing,
    PermissionDenied,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct LinuxDriverSnapshot {
    pub(super) module: Option<Vec<u8>>,
    pub(super) kernel_release: Option<Vec<u8>>,
    pub(super) version: Option<Vec<u8>>,
    pub(super) srcversion: Option<Vec<u8>>,
    pub(super) build_identity: Option<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct LinuxRenderSnapshot {
    pub(super) render_name: Vec<u8>,
    pub(super) identity: LinuxIdentityInput,
    pub(super) repeated_target_relative: Vec<u8>,
    pub(super) display_name: Vec<u8>,
    pub(super) locator: LinuxLocatorStatus,
    pub(super) driver: LinuxDriverSnapshot,
    pub(super) class: LinuxClassEvidence,
}

pub(super) fn map_linux_records(
    snapshots: Vec<LinuxRenderSnapshot>,
    cancellation: &CancellationToken,
) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
    if snapshots.len() > MAX_LINUX_RENDER_DEVICES {
        return Err(DeviceError::Overflow);
    }

    let mut render_numbers = BTreeMap::<u32, (Vec<u8>, LinuxLocatorStatus, Vec<u8>)>::new();
    let mut target_identities = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut mapped = BTreeMap::<Vec<u8>, MappedLinuxRecord>::new();
    for snapshot in snapshots {
        check_cancelled(cancellation)?;
        if snapshot.identity.target_relative != snapshot.repeated_target_relative {
            return Err(DeviceError::Invalid);
        }
        let render_number =
            parse_render_node_name(&snapshot.render_name)?.ok_or(DeviceError::Invalid)?;
        let target = canonical_target(snapshot.identity.bus, &snapshot.identity.target_relative)?;
        let persistent_identity = build_linux_identity(&snapshot.identity)?;
        let identity_bytes = persistent_identity.as_bytes().to_vec();
        match target_identities.entry(target) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(identity_bytes.clone());
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get() == &identity_bytes => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(DeviceError::Ambiguous);
            }
        }

        match render_numbers.entry(render_number) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((
                    snapshot.render_name.clone(),
                    snapshot.locator.clone(),
                    identity_bytes.clone(),
                ));
            }
            std::collections::btree_map::Entry::Occupied(entry)
                if entry.get()
                    == &(
                        snapshot.render_name.clone(),
                        snapshot.locator.clone(),
                        identity_bytes.clone(),
                    ) => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(DeviceError::Ambiguous);
            }
        }

        let driver = driver_record(&persistent_identity, &snapshot.driver)?;
        let candidate = MappedLinuxRecord {
            render_number,
            render_name: snapshot.render_name,
            persistent_identity,
            display_name: snapshot.display_name,
            vendor: vendor_from_id(snapshot.identity.fields.vendor),
            class: class_from_evidence(snapshot.identity.bus, snapshot.class),
            locator: snapshot.locator,
            driver,
        };
        match mapped.entry(identity_bytes) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.get_mut().merge_alias(candidate)?;
            }
        }
    }

    mapped
        .into_values()
        .map(MappedLinuxRecord::into_platform_record)
        .collect()
}

struct MappedLinuxRecord {
    render_number: u32,
    render_name: Vec<u8>,
    persistent_identity: PrivateDeviceIdentity,
    display_name: Vec<u8>,
    vendor: Vendor,
    class: DeviceClass,
    locator: LinuxLocatorStatus,
    driver: DriverRecord,
}

impl MappedLinuxRecord {
    fn merge_alias(&mut self, candidate: Self) -> Result<(), DeviceError> {
        if self.vendor != candidate.vendor || self.driver != candidate.driver {
            return Err(DeviceError::Ambiguous);
        }
        self.class = merge_class(self.class, candidate.class)?;
        if candidate.display_name < self.display_name {
            self.display_name = candidate.display_name;
        }
        if locator_order(
            candidate.render_number,
            &candidate.render_name,
            &candidate.locator,
        ) < locator_order(self.render_number, &self.render_name, &self.locator)
        {
            self.render_number = candidate.render_number;
            self.render_name = candidate.render_name;
            self.locator = candidate.locator;
        }
        Ok(())
    }

    fn into_platform_record(self) -> Result<PlatformDeviceRecord, DeviceError> {
        let (availability, locator) = match self.locator {
            LinuxLocatorStatus::Available { device_number } => (
                DeviceAvailability::Available,
                DeviceLocator::Linux {
                    render_node: self.render_name,
                    device_number,
                },
            ),
            LinuxLocatorStatus::Missing => (
                DeviceAvailability::LocatorUnavailable,
                DeviceLocator::Unavailable,
            ),
            LinuxLocatorStatus::PermissionDenied => (
                DeviceAvailability::PermissionDenied,
                DeviceLocator::Unavailable,
            ),
        };
        Ok(PlatformDeviceRecord {
            platform: PlatformTag::Linux,
            display_name: self.display_name,
            vendor: self.vendor,
            class: self.class,
            availability,
            persistent_identity: self.persistent_identity,
            locator,
            driver: self.driver,
            backends: backends_for_vendor(self.vendor),
        })
    }
}

pub(super) fn parse_render_node_name(name: &[u8]) -> Result<Option<u32>, DeviceError> {
    let Some(digits) = name.strip_prefix(b"renderD") else {
        return Ok(None);
    };
    if digits.is_empty() || digits.iter().any(|byte| !byte.is_ascii_digit()) {
        return Ok(None);
    }
    let mut value = 0_u32;
    for digit in digits {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
            .ok_or(DeviceError::Overflow)?;
    }
    Ok(Some(value))
}

pub(super) fn normalize_pci_bdf(value: &[u8]) -> Result<String, DeviceError> {
    if value.len() != 12 || value[4] != b':' || value[7] != b':' || value[10] != b'.' {
        return Err(DeviceError::Invalid);
    }
    let domain = parse_hex(&value[0..4])?;
    let bus = parse_hex(&value[5..7])?;
    let device = parse_hex(&value[8..10])?;
    let function = parse_hex(&value[11..12])?;
    if domain > u64::from(u16::MAX) || bus > u64::from(u8::MAX) || device > 0x1f || function > 7 {
        return Err(DeviceError::Invalid);
    }
    Ok(format!("{domain:04x}:{bus:02x}:{device:02x}.{function:x}"))
}

pub(super) fn build_linux_identity(
    input: &LinuxIdentityInput,
) -> Result<PrivateDeviceIdentity, DeviceError> {
    let target = canonical_target(input.bus, &input.target_relative)?;
    let target_length = u32::try_from(target.len()).map_err(|_| DeviceError::Overflow)?;
    let mut identity = Vec::with_capacity(
        LINUX_DEVICE_DOMAIN
            .len()
            .checked_add(1 + 4)
            .and_then(|size| size.checked_add(target.len()))
            .ok_or(DeviceError::Overflow)?,
    );
    identity.extend_from_slice(LINUX_DEVICE_DOMAIN);
    identity.push(input.bus as u8);
    identity.extend_from_slice(&target_length.to_be_bytes());
    identity.extend_from_slice(&target);
    append_optional_field(&mut identity, 1, input.fields.vendor.map(u16::to_be_bytes))?;
    append_optional_field(&mut identity, 2, input.fields.device.map(u16::to_be_bytes))?;
    append_optional_field(
        &mut identity,
        3,
        input.fields.subsystem_vendor.map(u16::to_be_bytes),
    )?;
    append_optional_field(
        &mut identity,
        4,
        input.fields.subsystem_device.map(u16::to_be_bytes),
    )?;
    append_optional_field(&mut identity, 5, input.fields.revision.map(|value| [value]))?;
    if identity.len() > MAX_PRIVATE_INPUT_BYTES {
        return Err(DeviceError::Overflow);
    }
    PrivateDeviceIdentity::new(identity).map_err(|_| DeviceError::Overflow)
}

fn canonical_target(bus: LinuxBusKind, target: &[u8]) -> Result<Vec<u8>, DeviceError> {
    if target.is_empty()
        || target.len() > MAX_PRIVATE_INPUT_BYTES
        || target.first() == Some(&b'/')
        || target.last() == Some(&b'/')
        || target
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || *byte == b'\\' || *byte == 0x7f)
    {
        return Err(DeviceError::Invalid);
    }
    let mut components = target.split(|byte| *byte == b'/').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, b"." | b".."))
    {
        return Err(DeviceError::Invalid);
    }
    if bus == LinuxBusKind::Pci {
        let final_component = components.last_mut().ok_or(DeviceError::Invalid)?;
        let normalized = normalize_pci_bdf(final_component)?;
        *final_component = normalized.as_bytes();
        let canonical = components.join(&b'/');
        return Ok(canonical);
    }
    Ok(target.to_vec())
}

fn append_optional_field<const LENGTH: usize>(
    identity: &mut Vec<u8>,
    tag: u8,
    value: Option<[u8; LENGTH]>,
) -> Result<(), DeviceError> {
    let value = value.as_ref().map_or(&[][..], |value| value.as_slice());
    let length = u32::try_from(value.len()).map_err(|_| DeviceError::Overflow)?;
    let next_length = identity
        .len()
        .checked_add(1 + 4)
        .and_then(|size| size.checked_add(value.len()))
        .ok_or(DeviceError::Overflow)?;
    if next_length > MAX_PRIVATE_INPUT_BYTES {
        return Err(DeviceError::Overflow);
    }
    identity.push(tag);
    identity.extend_from_slice(&length.to_be_bytes());
    identity.extend_from_slice(value);
    Ok(())
}

fn driver_record(
    identity: &PrivateDeviceIdentity,
    snapshot: &LinuxDriverSnapshot,
) -> Result<DriverRecord, DeviceError> {
    if let Some(module) = &snapshot.module
        && (module.is_empty()
            || module.len() > MAX_MODULE_NAME_BYTES
            || module
                .iter()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))))
    {
        return Err(DeviceError::Invalid);
    }
    for field in [
        snapshot.kernel_release.as_deref(),
        snapshot.version.as_deref(),
        snapshot.srcversion.as_deref(),
        snapshot.build_identity.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_driver_field(field)?;
    }

    let distinguishing_identity = snapshot.version.is_some()
        || snapshot.srcversion.is_some()
        || snapshot.build_identity.is_some();
    let (Some(module), Some(kernel_release)) = (
        snapshot.module.as_deref(),
        snapshot.kernel_release.as_deref(),
    ) else {
        return Ok(DriverRecord::Incomplete);
    };
    if !distinguishing_identity {
        return Ok(DriverRecord::Incomplete);
    }

    let mut fields = vec![
        DriverField::new(1, identity.as_bytes().to_vec()),
        DriverField::new(2, module.to_vec()),
        DriverField::new(3, kernel_release.to_vec()),
    ];
    for (tag, value) in [
        (4, snapshot.version.as_deref()),
        (5, snapshot.srcversion.as_deref()),
        (6, snapshot.build_identity.as_deref()),
    ] {
        if let Some(value) = value {
            fields.push(DriverField::new(tag, value.to_vec()));
        }
    }
    Ok(DriverRecord::Complete(fields))
}

fn validate_driver_field(field: &[u8]) -> Result<(), DeviceError> {
    if field.is_empty() {
        return Err(DeviceError::Invalid);
    }
    if field.len() > MAX_PRIVATE_INPUT_BYTES {
        return Err(DeviceError::Overflow);
    }
    if field
        .iter()
        .any(|byte| !byte.is_ascii() || !(b' '..=b'~').contains(byte))
    {
        return Err(DeviceError::Invalid);
    }
    Ok(())
}

fn merge_class(left: DeviceClass, right: DeviceClass) -> Result<DeviceClass, DeviceError> {
    match (left, right) {
        (left, right) if left == right => Ok(left),
        (DeviceClass::Unknown, right) => Ok(right),
        (left, DeviceClass::Unknown) => Ok(left),
        _ => Err(DeviceError::Ambiguous),
    }
}

fn class_from_evidence(bus: LinuxBusKind, evidence: LinuxClassEvidence) -> DeviceClass {
    if matches!(bus, LinuxBusKind::Virtio | LinuxBusKind::Mediated) {
        return DeviceClass::Virtual;
    }
    match evidence {
        LinuxClassEvidence::Integrated => DeviceClass::Integrated,
        LinuxClassEvidence::Discrete => DeviceClass::Discrete,
        LinuxClassEvidence::Virtual => DeviceClass::Virtual,
        LinuxClassEvidence::Unknown => DeviceClass::Unknown,
    }
}

fn vendor_from_id(vendor: Option<u16>) -> Vendor {
    match vendor {
        Some(0x8086) => Vendor::Intel,
        Some(0x10de) => Vendor::Nvidia,
        Some(0x1002) => Vendor::Amd,
        Some(0x106b) => Vendor::Apple,
        Some(0x1414) => Vendor::Microsoft,
        Some(_) => Vendor::Other,
        None => Vendor::Unknown,
    }
}

fn backends_for_vendor(vendor: Vendor) -> Vec<BackendKind> {
    match vendor {
        Vendor::Intel => vec![BackendKind::Qsv, BackendKind::Vaapi],
        Vendor::Nvidia => vec![BackendKind::Cuda, BackendKind::Nvenc, BackendKind::Vaapi],
        _ => vec![BackendKind::Vaapi],
    }
}

fn locator_order<'a>(
    render_number: u32,
    render_name: &'a [u8],
    locator: &LinuxLocatorStatus,
) -> (u8, u32, &'a [u8], u64) {
    match locator {
        LinuxLocatorStatus::Available { device_number } => {
            (0, render_number, render_name, *device_number)
        }
        LinuxLocatorStatus::PermissionDenied => (1, render_number, render_name, 0),
        LinuxLocatorStatus::Missing => (2, render_number, render_name, 0),
    }
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), DeviceError> {
    if cancellation.is_cancelled() {
        Err(DeviceError::Cancelled)
    } else {
        Ok(())
    }
}

fn parse_hex(value: &[u8]) -> Result<u64, DeviceError> {
    value.iter().try_fold(0_u64, |parsed, byte| {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return Err(DeviceError::Invalid),
        };
        parsed
            .checked_mul(16)
            .and_then(|parsed| parsed.checked_add(digit))
            .ok_or(DeviceError::Overflow)
    })
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use crate::transcoding::device::DeviceEnumerator;
    use std::{
        ffi::{CStr, CString},
        fs::{self, File},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Path, PathBuf},
    };

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const MAX_UEVENT_LINES: usize = 256;
    const MAX_DIRECTORY_ENTRIES: usize = 4_096;
    const MAX_DIRECTORY_NAME_BYTES: usize = 256 * 1_024;

    pub(crate) struct LinuxDeviceEnumerator;

    #[async_trait::async_trait]
    impl DeviceEnumerator for LinuxDeviceEnumerator {
        async fn enumerate(
            &self,
            cancellation: CancellationToken,
        ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
            let worker_cancellation = cancellation.clone();
            tokio::task::spawn_blocking(move || {
                enumerate_linux_roots(&LinuxRoots::production(), &worker_cancellation)
            })
            .await
            .map_err(|_| DeviceError::Invalid)?
        }
    }

    struct LinuxRoots {
        class_drm: PathBuf,
        devices: PathBuf,
        modules: PathBuf,
        dev_dri: PathBuf,
    }

    impl LinuxRoots {
        fn production() -> Self {
            Self {
                class_drm: PathBuf::from("/sys/class/drm"),
                devices: PathBuf::from("/sys/devices"),
                modules: PathBuf::from("/sys/module"),
                dev_dri: PathBuf::from("/dev/dri"),
            }
        }
    }

    fn enumerate_linux_roots(
        roots: &LinuxRoots,
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
        let mut no_hook = |_: &[u8]| {};
        enumerate_linux_roots_with_hook(roots, cancellation, &mut no_hook)
    }

    fn enumerate_linux_roots_with_hook(
        roots: &LinuxRoots,
        cancellation: &CancellationToken,
        hook: &mut dyn FnMut(&[u8]),
    ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
        check_cancelled(cancellation)?;
        let class_root = open_absolute_directory(&roots.class_drm)?;
        check_cancelled(cancellation)?;
        let devices_root = open_absolute_directory(&roots.devices)?;
        check_cancelled(cancellation)?;
        let module_root = open_optional_directory(&roots.modules)?;
        check_cancelled(cancellation)?;
        let dev_root = open_optional_directory(&roots.dev_dri)?;

        let mut names = Vec::new();
        let mut entry_count = 0_usize;
        let mut aggregate_name_bytes = 0_usize;
        let proc_path = PathBuf::from(format!("/proc/self/fd/{}", class_root.as_raw_fd()));
        for entry in fs::read_dir(proc_path).map_err(|_| DeviceError::Invalid)? {
            check_cancelled(cancellation)?;
            let entry = entry.map_err(|_| DeviceError::Invalid)?;
            let bytes = entry.file_name().as_bytes().to_vec();
            entry_count = entry_count.checked_add(1).ok_or(DeviceError::Overflow)?;
            aggregate_name_bytes = aggregate_name_bytes
                .checked_add(bytes.len())
                .ok_or(DeviceError::Overflow)?;
            if entry_count > MAX_DIRECTORY_ENTRIES
                || aggregate_name_bytes > MAX_DIRECTORY_NAME_BYTES
            {
                return Err(DeviceError::Overflow);
            }
            if let Some(number) = parse_render_node_name(&bytes)? {
                names.push((number, bytes));
                if names.len() > MAX_LINUX_RENDER_DEVICES {
                    return Err(DeviceError::Overflow);
                }
            }
        }
        names.sort_unstable();

        let kernel_release = kernel_release()?;
        let opened_roots = OpenedLinuxRoots {
            class: &class_root,
            devices: &devices_root,
            modules: &module_root,
            dev: &dev_root,
        };
        let mut snapshots = Vec::with_capacity(names.len());
        for (_, name) in names {
            check_cancelled(cancellation)?;
            snapshots.push(snapshot_render_device(
                &opened_roots,
                &name,
                &kernel_release,
                cancellation,
                hook,
            )?);
        }
        map_linux_records(snapshots, cancellation)
    }

    struct OpenedLinuxRoots<'a> {
        class: &'a File,
        devices: &'a File,
        modules: &'a OptionalDirectory,
        dev: &'a OptionalDirectory,
    }

    fn snapshot_render_device(
        roots: &OpenedLinuxRoots<'_>,
        render_name: &[u8],
        kernel_release: &[u8],
        cancellation: &CancellationToken,
        hook: &mut dyn FnMut(&[u8]),
    ) -> Result<LinuxRenderSnapshot, DeviceError> {
        let render = open_following_normal_symlinks(
            roots.class,
            render_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let (_, render_identity) = trusted_relative_identity(roots.devices, &render, cancellation)?;
        check_cancelled(cancellation)?;
        let expected_device = read_required_device_number(&render, cancellation)?;
        check_cancelled(cancellation)?;
        let hardware = open_following_normal_symlinks(
            &render,
            b"device",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let (target_relative, target_identity) =
            trusted_relative_identity(roots.devices, &hardware, cancellation)?;
        let bus = bus_from_target(&target_relative);
        check_cancelled(cancellation)?;

        let uevent = read_optional_property(&hardware, b"uevent", cancellation)?
            .ok_or(DeviceError::Invalid)?;
        validate_uevent(&uevent, bus, &target_relative)?;
        let fields = LinuxStableFields {
            vendor: read_optional_hex_u16(&hardware, b"vendor", cancellation)?,
            device: read_optional_hex_u16(&hardware, b"device", cancellation)?,
            subsystem_vendor: read_optional_hex_u16(&hardware, b"subsystem_vendor", cancellation)?,
            subsystem_device: read_optional_hex_u16(&hardware, b"subsystem_device", cancellation)?,
            revision: read_optional_hex_u8(&hardware, b"revision", cancellation)?,
        };
        let driver = read_driver_snapshot(&hardware, roots.modules, kernel_release, cancellation)?;
        let locator =
            validate_render_locator(roots.dev, render_name, expected_device, cancellation)?;
        check_cancelled(cancellation)?;
        hook(render_name);
        check_cancelled(cancellation)?;

        let repeated_render = open_following_normal_symlinks(
            roots.class,
            render_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let (_, repeated_render_identity) =
            trusted_relative_identity(roots.devices, &repeated_render, cancellation)?;
        let repeated_expected_device = read_required_device_number(&repeated_render, cancellation)?;
        let repeated_hardware = open_following_normal_symlinks(
            &repeated_render,
            b"device",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let (repeated_target_relative, repeated_target_identity) =
            trusted_relative_identity(roots.devices, &repeated_hardware, cancellation)?;
        let repeated_locator = validate_render_locator(
            roots.dev,
            render_name,
            repeated_expected_device,
            cancellation,
        )?;
        if render_identity != repeated_render_identity
            || target_identity != repeated_target_identity
            || target_relative != repeated_target_relative
            || expected_device != repeated_expected_device
            || locator != repeated_locator
        {
            return Err(DeviceError::Invalid);
        }
        check_cancelled(cancellation)?;

        Ok(LinuxRenderSnapshot {
            render_name: render_name.to_vec(),
            identity: LinuxIdentityInput {
                bus,
                target_relative,
                fields,
            },
            repeated_target_relative,
            display_name: Vec::new(),
            locator,
            driver,
            class: if matches!(bus, LinuxBusKind::Virtio | LinuxBusKind::Mediated) {
                LinuxClassEvidence::Virtual
            } else {
                LinuxClassEvidence::Unknown
            },
        })
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct HandleIdentity {
        device: u64,
        inode: u64,
    }

    fn trusted_relative_identity(
        trusted_root: &File,
        candidate: &File,
        cancellation: &CancellationToken,
    ) -> Result<(Vec<u8>, HandleIdentity), DeviceError> {
        check_cancelled(cancellation)?;
        let root_path = final_handle_path(trusted_root)?;
        check_cancelled(cancellation)?;
        let candidate_path = final_handle_path(candidate)?;
        check_cancelled(cancellation)?;
        let relative = candidate_path
            .strip_prefix(&root_path)
            .map_err(|_| DeviceError::Invalid)?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(DeviceError::Invalid);
        }
        let relative_bytes = relative.as_os_str().as_bytes();
        if relative_bytes.len() > MAX_PRIVATE_INPUT_BYTES {
            return Err(DeviceError::Overflow);
        }
        let anchored = openat2(
            trusted_root,
            relative_bytes,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RESOLVE_NO_XDEV | RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )?;
        check_cancelled(cancellation)?;
        let candidate_identity = handle_identity(candidate)?;
        check_cancelled(cancellation)?;
        if candidate_identity != handle_identity(&anchored)? {
            return Err(DeviceError::Invalid);
        }
        Ok((relative_bytes.to_vec(), candidate_identity))
    }

    fn handle_identity(file: &File) -> Result<HandleIdentity, DeviceError> {
        let metadata = file.metadata().map_err(|_| DeviceError::Invalid)?;
        if !metadata.is_dir() || metadata.nlink() == 0 {
            return Err(DeviceError::Invalid);
        }
        Ok(HandleIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn final_handle_path(file: &File) -> Result<PathBuf, DeviceError> {
        let path = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| DeviceError::Invalid)?;
        if !path.is_absolute() || path.as_os_str().as_bytes().ends_with(b" (deleted)") {
            return Err(DeviceError::Invalid);
        }
        Ok(path)
    }

    fn open_absolute_directory(path: &Path) -> Result<File, DeviceError> {
        open_absolute_directory_classified(path).map_err(|_| DeviceError::Invalid)
    }

    #[derive(Clone, Copy)]
    enum OpenRootFailure {
        Missing,
        PermissionDenied,
        Invalid,
    }

    fn open_absolute_directory_classified(path: &Path) -> Result<File, OpenRootFailure> {
        if !path.is_absolute() {
            return Err(OpenRootFailure::Invalid);
        }
        let relative = path
            .strip_prefix(Path::new("/"))
            .map_err(|_| OpenRootFailure::Invalid)?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(OpenRootFailure::Invalid);
        }
        let root = File::open("/").map_err(|error| classify_root_error(&error))?;
        openat2_classified(
            &root,
            relative.as_os_str().as_bytes(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        )
    }

    enum OptionalDirectory {
        Available(File),
        Missing,
        PermissionDenied,
    }

    fn open_optional_directory(path: &Path) -> Result<OptionalDirectory, DeviceError> {
        match open_absolute_directory_classified(path) {
            Ok(file) => Ok(OptionalDirectory::Available(file)),
            Err(OpenRootFailure::Missing) => Ok(OptionalDirectory::Missing),
            Err(OpenRootFailure::PermissionDenied) => Ok(OptionalDirectory::PermissionDenied),
            Err(OpenRootFailure::Invalid) => Err(DeviceError::Invalid),
        }
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn openat2(
        directory: &File,
        path: &[u8],
        flags: i32,
        resolve: u64,
    ) -> Result<File, DeviceError> {
        openat2_classified(directory, path, flags, resolve).map_err(|_| DeviceError::Invalid)
    }

    fn openat2_classified(
        directory: &File,
        path: &[u8],
        flags: i32,
        resolve: u64,
    ) -> Result<File, OpenRootFailure> {
        let path = CString::new(path).map_err(|_| OpenRootFailure::Invalid)?;
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve,
        };
        // SAFETY: directory is live, path is NUL-terminated, and how has the kernel ABI layout.
        let descriptor = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                directory.as_raw_fd(),
                path.as_ptr(),
                &raw const how,
                std::mem::size_of::<OpenHow>(),
            ) as i32
        };
        if descriptor < 0 {
            return Err(classify_root_error(&std::io::Error::last_os_error()));
        }
        // SAFETY: successful openat2 returns one owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }

    fn classify_root_error(error: &std::io::Error) -> OpenRootFailure {
        match error.raw_os_error() {
            Some(libc::ENOENT | libc::ENOTDIR) => OpenRootFailure::Missing,
            Some(libc::EACCES | libc::EPERM) => OpenRootFailure::PermissionDenied,
            _ => OpenRootFailure::Invalid,
        }
    }

    fn open_following_normal_symlinks(
        directory: &File,
        path: &[u8],
        flags: i32,
    ) -> Result<File, DeviceError> {
        openat2(directory, path, flags, RESOLVE_NO_MAGICLINKS)
    }

    fn read_optional_property(
        directory: &File,
        name: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        check_cancelled(cancellation)?;
        let name = CString::new(name).map_err(|_| DeviceError::Invalid)?;
        // SAFETY: directory is live and name is a bounded NUL-terminated constant.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return match std::io::Error::last_os_error().kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => Ok(None),
                _ => Err(DeviceError::Invalid),
            };
        }
        // SAFETY: successful openat returns one owned descriptor.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|_| DeviceError::Invalid)?;
        if !metadata.is_file() || metadata.nlink() == 0 {
            return Err(DeviceError::Invalid);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_PRIVATE_INPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| DeviceError::Invalid)?;
        check_cancelled(cancellation)?;
        if bytes.len() > MAX_PRIVATE_INPUT_BYTES {
            return Err(DeviceError::Overflow);
        }
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        Ok(Some(bytes))
    }

    fn read_optional_hex_u16(
        directory: &File,
        name: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Option<u16>, DeviceError> {
        read_optional_hex(directory, name, 4, cancellation)?
            .map(|value| u16::try_from(value).map_err(|_| DeviceError::Invalid))
            .transpose()
    }

    fn read_optional_hex_u8(
        directory: &File,
        name: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Option<u8>, DeviceError> {
        read_optional_hex(directory, name, 2, cancellation)?
            .map(|value| u8::try_from(value).map_err(|_| DeviceError::Invalid))
            .transpose()
    }

    fn read_optional_hex(
        directory: &File,
        name: &[u8],
        digits: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<u64>, DeviceError> {
        let Some(bytes) = read_optional_property(directory, name, cancellation)? else {
            return Ok(None);
        };
        if bytes.len() != digits + 2 || !bytes.starts_with(b"0x") {
            return Err(DeviceError::Invalid);
        }
        parse_hex(&bytes[2..]).map(Some)
    }

    fn read_required_device_number(
        render: &File,
        cancellation: &CancellationToken,
    ) -> Result<u64, DeviceError> {
        let bytes =
            read_optional_property(render, b"dev", cancellation)?.ok_or(DeviceError::Invalid)?;
        let (major, minor) = split_ascii_once(&bytes, b':').ok_or(DeviceError::Invalid)?;
        if major.is_empty()
            || minor.is_empty()
            || major.iter().any(|byte| !byte.is_ascii_digit())
            || minor.iter().any(|byte| !byte.is_ascii_digit())
        {
            return Err(DeviceError::Invalid);
        }
        let major = parse_decimal_u32(major)?;
        let minor = parse_decimal_u32(minor)?;
        Ok(libc::makedev(major, minor) as u64)
    }

    fn parse_decimal_u32(bytes: &[u8]) -> Result<u32, DeviceError> {
        bytes.iter().try_fold(0_u32, |value, byte| {
            value
                .checked_mul(10)
                .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                .ok_or(DeviceError::Overflow)
        })
    }

    fn validate_render_locator(
        dev_root: &OptionalDirectory,
        render_name: &[u8],
        expected_device: u64,
        cancellation: &CancellationToken,
    ) -> Result<LinuxLocatorStatus, DeviceError> {
        check_cancelled(cancellation)?;
        let dev_root = match dev_root {
            OptionalDirectory::Available(file) => file,
            OptionalDirectory::Missing => return Ok(LinuxLocatorStatus::Missing),
            OptionalDirectory::PermissionDenied => {
                return Ok(LinuxLocatorStatus::PermissionDenied);
            }
        };
        let name = CString::new(render_name).map_err(|_| DeviceError::Invalid)?;
        // SAFETY: root is live and name is an exact validated render entry.
        let descriptor = unsafe {
            libc::openat(
                dev_root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return match std::io::Error::last_os_error().kind() {
                std::io::ErrorKind::NotFound => Ok(LinuxLocatorStatus::Missing),
                std::io::ErrorKind::PermissionDenied => Ok(LinuxLocatorStatus::PermissionDenied),
                _ => Err(DeviceError::Invalid),
            };
        }
        check_cancelled(cancellation)?;
        // SAFETY: successful openat returns one owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        let metadata = file.metadata().map_err(|_| DeviceError::Invalid)?;
        check_cancelled(cancellation)?;
        if metadata.mode() & libc::S_IFMT != libc::S_IFCHR || metadata.nlink() == 0 {
            return Err(DeviceError::Invalid);
        }
        let device_number = metadata.rdev();
        if device_number != expected_device {
            return Err(DeviceError::Invalid);
        }
        Ok(LinuxLocatorStatus::Available { device_number })
    }

    fn bus_from_target(target: &[u8]) -> LinuxBusKind {
        let components = target.split(|byte| *byte == b'/');
        let mut bus = LinuxBusKind::Other;
        for component in components {
            if normalize_pci_bdf(component).is_ok() {
                bus = LinuxBusKind::Pci;
            } else if component == b"platform" {
                if bus == LinuxBusKind::Other {
                    bus = LinuxBusKind::Platform;
                }
            } else if component
                .strip_prefix(b"virtio")
                .is_some_and(|suffix| !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit))
            {
                bus = LinuxBusKind::Virtio;
            } else if matches!(component, b"mdev" | b"mdev_bus") {
                bus = LinuxBusKind::Mediated;
            }
        }
        bus
    }

    fn validate_uevent(bytes: &[u8], bus: LinuxBusKind, target: &[u8]) -> Result<(), DeviceError> {
        let mut slot = None;
        for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            if index >= MAX_UEVENT_LINES || line.len() > MAX_PRIVATE_INPUT_BYTES {
                return Err(DeviceError::Overflow);
            }
            if line.is_empty() {
                continue;
            }
            let (key, value) = split_ascii_once(line, b'=').ok_or(DeviceError::Invalid)?;
            if key.is_empty()
                || key
                    .iter()
                    .any(|byte| !(byte.is_ascii_uppercase() || *byte == b'_'))
                || value
                    .iter()
                    .any(|byte| !byte.is_ascii() || byte.is_ascii_control())
            {
                return Err(DeviceError::Invalid);
            }
            if key == b"PCI_SLOT_NAME" && slot.replace(value).is_some() {
                return Err(DeviceError::Invalid);
            }
        }
        if bus == LinuxBusKind::Pci
            && let Some(slot) = slot
        {
            let normalized = normalize_pci_bdf(slot)?;
            let final_component = target
                .rsplit(|byte| *byte == b'/')
                .next()
                .ok_or(DeviceError::Invalid)?;
            if normalized.as_bytes() != final_component {
                return Err(DeviceError::Invalid);
            }
        }
        Ok(())
    }

    fn read_driver_snapshot(
        hardware: &File,
        module_root: &OptionalDirectory,
        kernel_release: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<LinuxDriverSnapshot, DeviceError> {
        let module_root = match module_root {
            OptionalDirectory::Available(file) => file,
            OptionalDirectory::Missing | OptionalDirectory::PermissionDenied => {
                return Ok(incomplete_driver(kernel_release));
            }
        };
        check_cancelled(cancellation)?;
        let module = match open_following_normal_symlinks(
            hardware,
            b"driver/module",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        ) {
            Ok(module) => module,
            Err(_) => return Ok(incomplete_driver(kernel_release)),
        };
        let (relative, module_identity) =
            trusted_relative_identity(module_root, &module, cancellation)?;
        if relative.contains(&b'/')
            || relative.is_empty()
            || relative.len() > MAX_MODULE_NAME_BYTES
            || relative
                .iter()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
        {
            return Err(DeviceError::Invalid);
        }
        check_cancelled(cancellation)?;
        let version = read_optional_property(&module, b"version", cancellation)?;
        let srcversion = read_optional_property(&module, b"srcversion", cancellation)?;
        let repeated = open_following_normal_symlinks(
            hardware,
            b"driver/module",
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let (repeated_relative, repeated_identity) =
            trusted_relative_identity(module_root, &repeated, cancellation)?;
        if relative != repeated_relative || module_identity != repeated_identity {
            return Err(DeviceError::Invalid);
        }
        Ok(LinuxDriverSnapshot {
            module: Some(relative),
            kernel_release: Some(kernel_release.to_vec()),
            version,
            srcversion,
            build_identity: None,
        })
    }

    fn incomplete_driver(kernel_release: &[u8]) -> LinuxDriverSnapshot {
        LinuxDriverSnapshot {
            module: None,
            kernel_release: Some(kernel_release.to_vec()),
            version: None,
            srcversion: None,
            build_identity: None,
        }
    }

    fn kernel_release() -> Result<Vec<u8>, DeviceError> {
        let mut name = std::mem::MaybeUninit::<libc::utsname>::uninit();
        // SAFETY: uname initializes the complete utsname structure on success.
        if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
            return Err(DeviceError::Invalid);
        }
        // SAFETY: uname succeeded and release is a NUL-terminated C array.
        let name = unsafe { name.assume_init() };
        // SAFETY: release is documented as a NUL-terminated field in utsname.
        let release = unsafe { CStr::from_ptr(name.release.as_ptr()) }
            .to_bytes()
            .to_vec();
        validate_driver_field(&release)?;
        Ok(release)
    }

    fn split_ascii_once(bytes: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
        let position = bytes.iter().position(|byte| *byte == separator)?;
        Some((&bytes[..position], &bytes[position + 1..]))
    }

    #[cfg(test)]
    pub(crate) fn native_no_gpu_for_test(root: &Path) -> Result<usize, DeviceError> {
        let roots = LinuxRoots {
            class_drm: root.join("class-drm"),
            devices: root.join("devices"),
            modules: root.join("modules"),
            dev_dri: root.join("dev-dri"),
        };
        enumerate_linux_roots(&roots, &CancellationToken::new()).map(|records| records.len())
    }

    #[cfg(test)]
    pub(crate) fn native_fixture_for_test(
        root: &Path,
        cancellation: &CancellationToken,
    ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
        let roots = LinuxRoots {
            class_drm: root.join("class-drm"),
            devices: root.join("devices"),
            modules: root.join("modules"),
            dev_dri: root.join("dev-dri"),
        };
        enumerate_linux_roots(&roots, cancellation)
    }

    #[cfg(test)]
    pub(crate) fn native_fixture_with_hook_for_test(
        root: &Path,
        cancellation: &CancellationToken,
        hook: &mut dyn FnMut(&[u8]),
    ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
        let roots = LinuxRoots {
            class_drm: root.join("class-drm"),
            devices: root.join("devices"),
            modules: root.join("modules"),
            dev_dri: root.join("dev-dri"),
        };
        enumerate_linux_roots_with_hook(&roots, cancellation, hook)
    }
}

#[cfg(all(target_os = "linux", test))]
pub(super) use native::{
    LinuxDeviceEnumerator, native_fixture_for_test, native_fixture_with_hook_for_test,
    native_no_gpu_for_test,
};
