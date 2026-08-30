use super::identity::{
    DeviceIdSeed, DriverIdentity, PlatformTag, PrivateDeviceIdentity, derive_device_id,
};
use super::linux::{
    LinuxBusKind, LinuxClassEvidence, LinuxDriverSnapshot, LinuxIdentityInput, LinuxLocatorStatus,
    LinuxRenderSnapshot, LinuxStableFields, build_linux_identity, map_linux_records,
    normalize_pci_bdf, parse_render_node_name,
};
#[cfg(target_os = "linux")]
use super::linux::{
    LinuxDeviceEnumerator, native_fixture_for_test, native_fixture_with_hook_for_test,
    native_no_gpu_for_test,
};
#[cfg(target_os = "macos")]
use super::macos::MacosDeviceEnumerator;
use super::macos::{
    UnsupportedDeviceEnumerator, logical_macos_discovery, unsupported_platform_discovery,
};
use super::windows::{
    D3D12_GENERIC_MEDIA_ATTRIBUTE_U128, WindowsAdapterSnapshot, WindowsCandidateLists,
    WindowsDriverSnapshot, WindowsPhysicalSnapshot, map_windows_records,
};
#[cfg(windows)]
use super::windows::{
    WindowsDeviceEnumerator, exercise_native_handle_exit_for_test,
    native_open_handle_count_for_test,
};
use super::{
    DeviceAvailability, DeviceDiscovery, DeviceDiscoveryStatus, DeviceEnumerator, DeviceError,
    DeviceLocator, DriverField, DriverRecord, DriverRunEpoch, PlatformDeviceRecord, Vendor,
    normalize_platform_records, normalize_platform_records_with_deriver,
};
use crate::transcoding::{BackendKind, DeviceClass};

static_assertions::assert_not_impl_any!(DeviceIdSeed: serde::Serialize);
static_assertions::assert_not_impl_any!(PrivateDeviceIdentity: serde::Serialize);
static_assertions::assert_not_impl_any!(DeviceLocator: serde::Serialize);
static_assertions::assert_not_impl_any!(DriverIdentity: serde::Serialize);
static_assertions::assert_not_impl_any!(DriverField: serde::Serialize);
static_assertions::assert_not_impl_any!(DriverRecord: serde::Serialize);
static_assertions::assert_not_impl_any!(PlatformDeviceRecord: serde::Serialize);
static_assertions::assert_not_impl_any!(DeviceDiscovery: serde::Serialize);
static_assertions::assert_not_impl_any!(WindowsAdapterSnapshot: serde::Serialize);
static_assertions::assert_not_impl_any!(WindowsPhysicalSnapshot: serde::Serialize);
static_assertions::assert_not_impl_any!(WindowsDriverSnapshot: serde::Serialize);
static_assertions::assert_not_impl_any!(LinuxIdentityInput: serde::Serialize);
static_assertions::assert_not_impl_any!(LinuxStableFields: serde::Serialize);
static_assertions::assert_not_impl_any!(LinuxLocatorStatus: serde::Serialize);
static_assertions::assert_not_impl_any!(LinuxRenderSnapshot: serde::Serialize);
static_assertions::assert_not_impl_any!(LinuxDriverSnapshot: serde::Serialize);

#[test]
fn macos_logical_device_is_stable_disabled_and_per_install_seeded() {
    let discovery = logical_macos_discovery(Some(b"23G93".to_vec())).unwrap();
    assert_eq!(discovery.status, DeviceDiscoveryStatus::PlatformUnsupported);
    assert_eq!(discovery.status.safe_reason(), Some("platform_unsupported"));
    assert_eq!(discovery.records.len(), 1);
    let record = &discovery.records[0];
    assert_eq!(record.platform, PlatformTag::Macos);
    assert_eq!(
        record.persistent_identity.as_bytes(),
        b"macos-videotoolbox-default-v1"
    );
    assert_eq!(record.vendor, Vendor::Apple);
    assert_eq!(record.class, DeviceClass::Unknown);
    assert_eq!(
        record.availability,
        DeviceAvailability::AdministrativelyDisabled
    );
    assert_eq!(record.locator, DeviceLocator::MacosDefault);
    assert_eq!(record.backends, vec![BackendKind::VideoToolbox]);

    let epoch = DriverRunEpoch::from_test_bytes([0x3c; 32]);
    let first = normalize_platform_records(
        discovery.records.clone(),
        &DeviceIdSeed::from_test_bytes([0x11; 32]),
        &epoch,
    )
    .unwrap();
    let second = normalize_platform_records(
        discovery.records,
        &DeviceIdSeed::from_test_bytes([0x22; 32]),
        &epoch,
    )
    .unwrap();
    assert_ne!(first[0].id, second[0].id);
    assert!(first[0].driver_identity.is_persistable());
}

#[test]
fn macos_missing_build_is_run_scoped_and_unsafe_builds_are_bounded() {
    let discovery = logical_macos_discovery(None).unwrap();
    let device = normalize_platform_records(
        discovery.records,
        &DeviceIdSeed::from_test_bytes([0x11; 32]),
        &DriverRunEpoch::from_test_bytes([0x3c; 32]),
    )
    .unwrap()
    .remove(0);
    assert!(!device.driver_identity.is_persistable());

    assert_eq!(
        logical_macos_discovery(Some(vec![b'X'; 257])).unwrap_err(),
        DeviceError::Overflow
    );
    assert_eq!(
        logical_macos_discovery(Some(vec![b'X'; 2_049])).unwrap_err(),
        DeviceError::Overflow
    );
    assert_eq!(
        logical_macos_discovery(Some(b"unsafe/build".to_vec())).unwrap_err(),
        DeviceError::Invalid
    );
}

#[test]
fn unsupported_platform_is_a_successful_empty_hardware_discovery() {
    let discovery = unsupported_platform_discovery();
    assert!(discovery.records.is_empty());
    assert_eq!(discovery.status, DeviceDiscoveryStatus::PlatformUnsupported);
    assert_eq!(discovery.status.safe_reason(), Some("platform_unsupported"));
    assert_eq!(DeviceDiscoveryStatus::Supported.safe_reason(), None);
}

#[tokio::test]
async fn unsupported_platform_enumerator_honors_cancellation() {
    let discovery = UnsupportedDeviceEnumerator
        .enumerate(tokio_util::sync::CancellationToken::new())
        .await
        .unwrap();
    assert!(discovery.records.is_empty());
    assert_eq!(discovery.status, DeviceDiscoveryStatus::PlatformUnsupported);

    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        UnsupportedDeviceEnumerator
            .enumerate(cancellation)
            .await
            .unwrap_err(),
        DeviceError::Cancelled
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_native_logical_device_is_packaging_disabled() {
    let discovery = MacosDeviceEnumerator
        .enumerate(tokio_util::sync::CancellationToken::new())
        .await
        .expect("bounded native sysctl failure degrades to incomplete driver identity");
    assert_eq!(discovery.status, DeviceDiscoveryStatus::PlatformUnsupported);
    assert_eq!(discovery.records.len(), 1);
    assert_eq!(
        discovery.records[0].availability,
        DeviceAvailability::AdministrativelyDisabled
    );
    assert_eq!(
        discovery.records[0].backends,
        vec![BackendKind::VideoToolbox]
    );

    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        MacosDeviceEnumerator
            .enumerate(cancellation)
            .await
            .unwrap_err(),
        DeviceError::Cancelled
    );
}

#[test]
fn linux_pure_render_node_names_are_exact_checked_and_nondefault() {
    assert_eq!(parse_render_node_name(b"renderD0").unwrap(), Some(0));
    assert_eq!(parse_render_node_name(b"renderD129").unwrap(), Some(129));
    for ignored in [
        b"renderD".as_slice(),
        b"RenderD128",
        b"renderD12x",
        b"renderD+128",
        b"renderD128/alias",
        b"card0",
        b"renderD\xff",
    ] {
        assert_eq!(parse_render_node_name(ignored).unwrap(), None);
    }
    assert_eq!(
        parse_render_node_name(b"renderD184467440737095516160").unwrap_err(),
        DeviceError::Overflow
    );
}

#[test]
fn linux_pure_pci_bdf_is_lowercase_fixed_width_and_checked() {
    assert_eq!(normalize_pci_bdf(b"0000:0A:02.0").unwrap(), "0000:0a:02.0");
    for invalid in [
        b"0:0a:02.0".as_slice(),
        b"0000:100:02.0",
        b"0000:0a:20.0",
        b"0000:0a:02.8",
        b"0000:0a:02",
        b"0000-0a-02-0",
    ] {
        assert_eq!(
            normalize_pci_bdf(invalid).unwrap_err(),
            DeviceError::Invalid
        );
    }
}

fn linux_identity_input(target: &[u8]) -> LinuxIdentityInput {
    LinuxIdentityInput {
        bus: LinuxBusKind::Pci,
        target_relative: target.to_vec(),
        fields: LinuxStableFields {
            vendor: Some(0x8086),
            device: Some(0x56a0),
            subsystem_vendor: Some(0x1028),
            subsystem_device: Some(0x0bda),
            revision: Some(0x05),
        },
    }
}

#[test]
fn linux_pure_identity_has_exact_versioned_framing_and_changes_on_slot_move() {
    let identity = build_linux_identity(&linux_identity_input(b"pci0000:00/0000:00:02.0"))
        .expect("valid PCI identity");
    let mut expected = b"linux-device/v1\0".to_vec();
    expected.push(1);
    let target = b"pci0000:00/0000:00:02.0";
    expected.extend_from_slice(&(target.len() as u32).to_be_bytes());
    expected.extend_from_slice(target);
    for (tag, bytes) in [
        (1_u8, 0x8086_u16.to_be_bytes().to_vec()),
        (2, 0x56a0_u16.to_be_bytes().to_vec()),
        (3, 0x1028_u16.to_be_bytes().to_vec()),
        (4, 0x0bda_u16.to_be_bytes().to_vec()),
        (5, vec![0x05]),
    ] {
        expected.push(tag);
        expected.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(&bytes);
    }
    assert_eq!(identity.as_bytes(), expected);

    let moved = build_linux_identity(&linux_identity_input(b"pci0000:00/0000:03:00.0"))
        .expect("valid moved identity");
    assert_ne!(identity.as_bytes(), moved.as_bytes());
}

#[test]
fn linux_pure_identity_rejects_untrusted_paths_and_frames_missing_fields() {
    for target in [
        b"".as_slice(),
        b"/pci0000:00/0000:00:02.0",
        b"pci0000:00/../0000:00:02.0",
        b"pci0000:00//0000:00:02.0",
        b"pci0000:00\\0000:00:02.0",
        b"pci0000:00/0000:00:02.0\0suffix",
    ] {
        assert_eq!(
            build_linux_identity(&linux_identity_input(target)).unwrap_err(),
            DeviceError::Invalid
        );
    }

    let mut missing = linux_identity_input(b"pci0000:00/0000:00:02.0");
    missing.fields = LinuxStableFields::default();
    let identity = build_linux_identity(&missing).expect("stable path is sufficient");
    let suffix = [
        1_u8, 0, 0, 0, 0, 2, 0, 0, 0, 0, 3, 0, 0, 0, 0, 4, 0, 0, 0, 0, 5, 0, 0, 0, 0,
    ];
    assert!(identity.as_bytes().ends_with(&suffix));

    for bus in [
        LinuxBusKind::Platform,
        LinuxBusKind::Virtio,
        LinuxBusKind::Mediated,
        LinuxBusKind::Other,
    ] {
        let input = LinuxIdentityInput {
            bus,
            target_relative: b"platform/synthetic-gpu".to_vec(),
            fields: LinuxStableFields::default(),
        };
        assert!(build_linux_identity(&input).is_ok());
    }
}

fn linux_render(render_number: u32, target: &[u8], vendor: Option<u16>) -> LinuxRenderSnapshot {
    let identity = LinuxIdentityInput {
        bus: LinuxBusKind::Pci,
        target_relative: target.to_vec(),
        fields: LinuxStableFields {
            vendor,
            device: Some(0x56a0),
            subsystem_vendor: Some(0x1028),
            subsystem_device: Some(0x0bda),
            revision: Some(0x05),
        },
    };
    LinuxRenderSnapshot {
        render_name: format!("renderD{render_number}").into_bytes(),
        repeated_target_relative: target.to_vec(),
        identity,
        display_name: b"Synthetic Linux Adapter".to_vec(),
        locator: LinuxLocatorStatus::Available {
            device_number: u64::from(render_number) + 4_096,
        },
        driver: LinuxDriverSnapshot {
            module: Some(b"xe".to_vec()),
            kernel_release: Some(b"6.12.0-test".to_vec()),
            version: None,
            srcversion: Some(b"0123456789ABCDEF".to_vec()),
            build_identity: None,
        },
        class: LinuxClassEvidence::Unknown,
    }
}

fn map_linux(
    snapshots: Vec<LinuxRenderSnapshot>,
) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
    map_linux_records(snapshots, &tokio_util::sync::CancellationToken::new())
}

#[test]
fn linux_pure_aliases_deduplicate_and_node_changes_do_not_change_identity() {
    let first = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086));
    let mut alias = first.clone();
    alias.render_name = b"renderD27".to_vec();
    alias.locator = LinuxLocatorStatus::Available {
        device_number: 8_219,
    };

    let mapped =
        map_linux(vec![alias.clone(), first.clone()]).expect("aliases share physical capacity");
    assert_eq!(mapped.len(), 1);
    assert_eq!(
        mapped[0].backends,
        vec![BackendKind::Qsv, BackendKind::Vaapi]
    );
    assert!(matches!(
        &mapped[0].locator,
        DeviceLocator::Linux {
            render_node,
            device_number: 4_105,
        } if render_node == b"renderD9"
    ));

    let renumbered = map_linux(vec![alias]).expect("same target after node renumbering");
    assert_eq!(
        mapped[0].persistent_identity.as_bytes(),
        renumbered[0].persistent_identity.as_bytes()
    );
    assert_ne!(mapped[0].locator, renumbered[0].locator);
}

#[test]
fn linux_pure_identical_gpus_and_slot_moves_remain_distinct() {
    let first = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x1002));
    let second = linux_render(10, b"pci0000:00/0000:03:00.0", Some(0x1002));
    let mapped = map_linux(vec![first, second]).expect("attachment identity separates devices");
    assert_eq!(mapped.len(), 2);
    assert_ne!(
        mapped[0].persistent_identity.as_bytes(),
        mapped[1].persistent_identity.as_bytes()
    );
    assert!(mapped.iter().all(|record| {
        record.vendor == Vendor::Amd
            && record.class == DeviceClass::Unknown
            && record.backends == vec![BackendKind::Vaapi]
    }));
}

#[test]
fn linux_pure_locator_unavailable_and_permission_denied_are_non_authorizing() {
    let mut missing = linux_render(9, b"pci0000:00/0000:00:02.0", None);
    missing.locator = LinuxLocatorStatus::Missing;
    let record = map_linux(vec![missing]).unwrap().remove(0);
    assert_eq!(record.availability, DeviceAvailability::LocatorUnavailable);
    assert_eq!(record.locator, DeviceLocator::Unavailable);
    assert_eq!(record.vendor, Vendor::Unknown);
    assert_eq!(record.backends, vec![BackendKind::Vaapi]);

    let mut denied = linux_render(10, b"pci0000:00/0000:03:00.0", Some(0x10de));
    denied.locator = LinuxLocatorStatus::PermissionDenied;
    let record = map_linux(vec![denied]).unwrap().remove(0);
    assert_eq!(record.availability, DeviceAvailability::PermissionDenied);
    assert_eq!(record.locator, DeviceLocator::Unavailable);
    assert_eq!(record.vendor, Vendor::Nvidia);
    assert_eq!(
        record.backends,
        vec![BackendKind::Cuda, BackendKind::Nvenc, BackendKind::Vaapi]
    );
}

#[test]
fn linux_pure_platform_virtio_and_cancellation_are_closed_boundaries() {
    let mut platform = linux_render(9, b"platform/soc/graphics", None);
    platform.identity.bus = LinuxBusKind::Platform;
    platform.identity.fields = LinuxStableFields::default();
    let platform = map_linux(vec![platform]).expect("bounded platform attachment");
    assert_eq!(platform[0].class, DeviceClass::Unknown);
    assert_eq!(platform[0].vendor, Vendor::Unknown);

    let mut virtio = linux_render(10, b"pci0000:00/virtio4/graphics", Some(0x1af4));
    virtio.identity.bus = LinuxBusKind::Virtio;
    let virtio = map_linux(vec![virtio]).expect("bounded virtio attachment");
    assert_eq!(virtio[0].class, DeviceClass::Virtual);
    assert_eq!(virtio[0].vendor, Vendor::Other);

    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        map_linux_records(
            vec![linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086),)],
            &cancellation,
        )
        .unwrap_err(),
        DeviceError::Cancelled
    );
}

#[test]
fn linux_pure_driver_completeness_and_class_need_explicit_evidence() {
    let mut complete = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086));
    complete.class = LinuxClassEvidence::Integrated;
    let device = normalize_one(map_linux(vec![complete.clone()]).unwrap().remove(0));
    assert_eq!(device.class, DeviceClass::Integrated);
    assert!(device.driver_identity.is_persistable());

    complete.driver.srcversion = None;
    let device = normalize_one(map_linux(vec![complete]).unwrap().remove(0));
    assert!(!device.driver_identity.is_persistable());

    for (evidence, expected) in [
        (LinuxClassEvidence::Discrete, DeviceClass::Discrete),
        (LinuxClassEvidence::Virtual, DeviceClass::Virtual),
        (LinuxClassEvidence::Unknown, DeviceClass::Unknown),
    ] {
        let mut snapshot = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086));
        snapshot.class = evidence;
        assert_eq!(map_linux(vec![snapshot]).unwrap()[0].class, expected);
    }
}

#[test]
fn linux_pure_rejects_swaps_collisions_malformed_driver_and_overflow() {
    let mut swapped = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086));
    swapped.repeated_target_relative = b"pci0000:00/0000:03:00.0".to_vec();
    assert_eq!(map_linux(vec![swapped]).unwrap_err(), DeviceError::Invalid);

    let first = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086));
    let second = linux_render(9, b"pci0000:00/0000:03:00.0", Some(0x8086));
    assert_eq!(
        map_linux(vec![first, second]).unwrap_err(),
        DeviceError::Ambiguous
    );

    let mut conflicting = linux_render(9, b"pci0000:00/0000:00:02.0", Some(0x8086));
    let mut alias = conflicting.clone();
    alias.render_name = b"renderD10".to_vec();
    alias.driver.module = Some(b"different".to_vec());
    assert_eq!(
        map_linux(vec![conflicting.clone(), alias]).unwrap_err(),
        DeviceError::Ambiguous
    );

    conflicting.driver.module = Some(b"unsafe/module".to_vec());
    assert_eq!(
        map_linux(vec![conflicting]).unwrap_err(),
        DeviceError::Invalid
    );

    let too_many = (0..33)
        .map(|index| {
            linux_render(
                index,
                format!("pci0000:00/0000:{:02x}:00.0", index + 1).as_bytes(),
                Some(0x8086),
            )
        })
        .collect();
    assert_eq!(map_linux(too_many).unwrap_err(), DeviceError::Overflow);
}

#[cfg(target_os = "linux")]
fn create_linux_native_fixture(root: &std::path::Path, render_name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::symlink;

    let class = root.join("class-drm");
    let devices = root.join("devices");
    let modules = root.join("modules");
    let dev = root.join("dev-dri");
    let hardware = devices.join("pci0000:00/0000:00:02.0");
    let render = hardware.join("drm").join(render_name);
    std::fs::create_dir_all(&class).unwrap();
    std::fs::create_dir_all(&render).unwrap();
    std::fs::create_dir_all(modules.join("xe")).unwrap();
    std::fs::create_dir_all(&dev).unwrap();
    std::fs::create_dir_all(hardware.join("driver")).unwrap();
    std::fs::write(render.join("dev"), b"226:9\n").unwrap();
    std::fs::write(hardware.join("vendor"), b"0x8086\n").unwrap();
    std::fs::write(hardware.join("device"), b"0x56a0\n").unwrap();
    std::fs::write(hardware.join("subsystem_vendor"), b"0x1028\n").unwrap();
    std::fs::write(hardware.join("subsystem_device"), b"0x0bda\n").unwrap();
    std::fs::write(hardware.join("revision"), b"0x05\n").unwrap();
    std::fs::write(
        hardware.join("uevent"),
        b"PCI_SLOT_NAME=0000:00:02.0\nDRIVER=xe\n",
    )
    .unwrap();
    std::fs::write(modules.join("xe/srcversion"), b"0123456789ABCDEF\n").unwrap();
    symlink(&render, class.join(render_name)).unwrap();
    symlink(&hardware, render.join("device")).unwrap();
    symlink(modules.join("xe"), hardware.join("driver/module")).unwrap();
    hardware
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_virtual_root_missing_locator_and_aliases_are_safe() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let hardware = create_linux_native_fixture(temporary.path(), "renderD9");
    let second_render = hardware.join("drm/renderD27");
    std::fs::create_dir_all(&second_render).unwrap();
    std::fs::write(second_render.join("dev"), b"226:27\n").unwrap();
    symlink(&hardware, second_render.join("device")).unwrap();
    symlink(&second_render, temporary.path().join("class-drm/renderD27")).unwrap();

    let records = native_fixture_for_test(
        temporary.path(),
        &tokio_util::sync::CancellationToken::new(),
    )
    .expect("anchored aliases are safe");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].availability,
        DeviceAvailability::LocatorUnavailable
    );
    assert_eq!(records[0].vendor, Vendor::Intel);
    assert_eq!(records[0].class, DeviceClass::Unknown);
    assert_eq!(
        records[0].backends,
        vec![BackendKind::Qsv, BackendKind::Vaapi]
    );
    assert!(matches!(records[0].driver, DriverRecord::Complete(_)));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_permission_denied_is_reported_without_mutating_access() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    create_linux_native_fixture(temporary.path(), "renderD9");
    let dev_root = temporary.path().join("dev-dri");
    std::fs::set_permissions(&dev_root, std::fs::Permissions::from_mode(0)).unwrap();
    let result = native_fixture_for_test(
        temporary.path(),
        &tokio_util::sync::CancellationToken::new(),
    );
    std::fs::set_permissions(&dev_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let records = result.expect("stable sysfs identity survives inaccessible render directory");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].availability,
        DeviceAvailability::PermissionDenied
    );
    assert_eq!(records[0].locator, DeviceLocator::Unavailable);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_rejects_loop_escape_magic_link_and_noncharacter_locator() {
    use std::{os::fd::AsRawFd, os::unix::fs::symlink};

    for attack in ["loop", "escape", "magic"] {
        let temporary = tempfile::tempdir().unwrap();
        let hardware = create_linux_native_fixture(temporary.path(), "renderD9");
        let class_link = temporary.path().join("class-drm/renderD9");
        std::fs::remove_file(&class_link).unwrap();
        let held_render = if attack == "magic" {
            Some(std::fs::File::open(hardware.join("drm/renderD9")).unwrap())
        } else {
            None
        };
        match attack {
            "loop" => symlink(&class_link, &class_link).unwrap(),
            "escape" => {
                let outside = temporary.path().join("outside");
                std::fs::create_dir(&outside).unwrap();
                symlink(outside, &class_link).unwrap();
            }
            "magic" => {
                symlink(
                    format!(
                        "/proc/self/fd/{}",
                        held_render.as_ref().unwrap().as_raw_fd()
                    ),
                    &class_link,
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            native_fixture_for_test(
                temporary.path(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .unwrap_err(),
            DeviceError::Invalid
        );
    }

    let temporary = tempfile::tempdir().unwrap();
    create_linux_native_fixture(temporary.path(), "renderD9");
    std::fs::write(temporary.path().join("dev-dri/renderD9"), b"not a device").unwrap();
    assert_eq!(
        native_fixture_for_test(
            temporary.path(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Invalid
    );

    let temporary = tempfile::tempdir().unwrap();
    let hardware = create_linux_native_fixture(temporary.path(), "renderD9");
    let non_device = temporary.path().join("devices/not-a-device");
    std::fs::create_dir(&non_device).unwrap();
    let device_link = hardware.join("drm/renderD9/device");
    std::fs::remove_file(&device_link).unwrap();
    symlink(non_device, device_link).unwrap();
    assert_eq!(
        native_fixture_for_test(
            temporary.path(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Invalid
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_detects_target_swap_and_hot_unplug() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let hardware = create_linux_native_fixture(temporary.path(), "renderD9");
    let replacement = temporary.path().join("devices/pci0000:00/0000:03:00.0");
    std::fs::create_dir_all(&replacement).unwrap();
    let device_link = hardware.join("drm/renderD9/device");
    let mut swap = |_: &[u8]| {
        std::fs::remove_file(&device_link).unwrap();
        symlink(&replacement, &device_link).unwrap();
    };
    assert_eq!(
        native_fixture_with_hook_for_test(
            temporary.path(),
            &tokio_util::sync::CancellationToken::new(),
            &mut swap,
        )
        .unwrap_err(),
        DeviceError::Invalid
    );

    let temporary = tempfile::tempdir().unwrap();
    let hardware = create_linux_native_fixture(temporary.path(), "renderD9");
    let device_link = hardware.join("drm/renderD9/device");
    let mut unplug = |_: &[u8]| std::fs::remove_file(&device_link).unwrap();
    assert_eq!(
        native_fixture_with_hook_for_test(
            temporary.path(),
            &tokio_util::sync::CancellationToken::new(),
            &mut unplug,
        )
        .unwrap_err(),
        DeviceError::Invalid
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_rejects_oversized_too_many_and_cancelled_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    let hardware = create_linux_native_fixture(temporary.path(), "renderD9");
    std::fs::write(hardware.join("vendor"), vec![b'0'; 2_049]).unwrap();
    assert_eq!(
        native_fixture_for_test(
            temporary.path(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Overflow
    );

    let temporary = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temporary.path().join("class-drm")).unwrap();
    std::fs::create_dir_all(temporary.path().join("devices")).unwrap();
    std::fs::create_dir_all(temporary.path().join("modules")).unwrap();
    std::fs::create_dir_all(temporary.path().join("dev-dri")).unwrap();
    for number in 0..33 {
        std::os::unix::fs::symlink(
            temporary.path().join("devices"),
            temporary.path().join(format!("class-drm/renderD{number}")),
        )
        .unwrap();
    }
    assert_eq!(
        native_fixture_for_test(
            temporary.path(),
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Overflow
    );

    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        native_fixture_for_test(temporary.path(), &cancellation).unwrap_err(),
        DeviceError::Cancelled
    );
}

#[cfg(target_os = "linux")]
#[test]
fn native_linux_no_gpu_is_valid() {
    let temporary = tempfile::tempdir().unwrap();
    for directory in ["class-drm", "devices", "modules", "dev-dri"] {
        std::fs::create_dir(temporary.path().join(directory)).unwrap();
    }
    assert_eq!(native_no_gpu_for_test(temporary.path()).unwrap(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_native_production_inventory_is_no_gpu_safe() {
    let result = LinuxDeviceEnumerator
        .enumerate(tokio_util::sync::CancellationToken::new())
        .await;
    assert!(result.is_ok(), "native discovery failed: {result:?}");
}

fn private_identity(bytes: impl Into<Vec<u8>>) -> PrivateDeviceIdentity {
    PrivateDeviceIdentity::new(bytes.into()).expect("bounded private identity")
}

fn record_with_driver(version: &str) -> PlatformDeviceRecord {
    PlatformDeviceRecord {
        platform: PlatformTag::Windows,
        display_name: b"Synthetic Graphics Adapter".to_vec(),
        vendor: Vendor::Intel,
        class: DeviceClass::Integrated,
        availability: DeviceAvailability::Available,
        persistent_identity: private_identity(b"stable-device-identity".to_vec()),
        locator: DeviceLocator::Windows {
            adapter_luid: 41,
            physical_index: None,
        },
        driver: DriverRecord::Complete(vec![DriverField::new(1, version.as_bytes().to_vec())]),
        backends: vec![BackendKind::Qsv, BackendKind::D3d11va],
    }
}

fn normalize_one(record: PlatformDeviceRecord) -> super::TranscodingDevice {
    normalize_platform_records(
        vec![record],
        &DeviceIdSeed::from_test_bytes([0x5a; 32]),
        &DriverRunEpoch::from_test_bytes([0x6b; 32]),
    )
    .expect("valid normalized device")
    .remove(0)
}

fn record_with_identity(identity: impl Into<Vec<u8>>) -> PlatformDeviceRecord {
    let mut record = record_with_driver("31.0.101.5590");
    record.persistent_identity = private_identity(identity);
    record
}

fn windows_adapter(luid: i64, instance: &str) -> WindowsAdapterSnapshot {
    WindowsAdapterSnapshot {
        luid,
        display_name: b"Synthetic Windows Adapter".to_vec(),
        vendor_id: Some(0x8086),
        is_hardware: Some(true),
        is_integrated: Some(true),
        has_virtual_or_remote_evidence: false,
        physical_adapters: vec![WindowsPhysicalSnapshot {
            physical_index: Some(0),
            instance_id: instance.encode_utf16().collect(),
            repeated_instance_id: instance.encode_utf16().collect(),
            driver: WindowsDriverSnapshot::complete_for_test("31.0.test"),
        }],
    }
}

fn map_windows_adapter(
    adapter: WindowsAdapterSnapshot,
) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
    map_windows_records(
        WindowsCandidateLists::DxCore {
            d3d11_graphics: vec![adapter],
            generic_media: None,
        },
        &tokio_util::sync::CancellationToken::new(),
    )
}

#[test]
fn windows_dxcore_union_deduplicates_and_dxgi_is_fallback_only() {
    assert_eq!(
        D3D12_GENERIC_MEDIA_ATTRIBUTE_U128,
        0x8eb2c848_82f6_4b49_aa87_aecfcf0174c6
    );
    let first = windows_adapter(11, r"TEST\DISPLAY\ONE");
    let second = windows_adapter(22, r"TEST\DISPLAY\TWO");
    let fallback = windows_adapter(33, r"TEST\DISPLAY\FALLBACK");

    let union = map_windows_records(
        WindowsCandidateLists::DxCore {
            d3d11_graphics: vec![first.clone()],
            generic_media: Some(vec![first.clone(), second.clone()]),
        },
        &tokio_util::sync::CancellationToken::new(),
    )
    .expect("consistent duplicate LUID is deduplicated");
    assert_eq!(union.len(), 2);
    assert!(union.iter().any(|record| matches!(
        record.locator,
        DeviceLocator::Windows {
            adapter_luid: 11,
            physical_index: Some(0)
        }
    )));
    assert!(union.iter().any(|record| matches!(
        record.locator,
        DeviceLocator::Windows {
            adapter_luid: 22,
            physical_index: Some(0)
        }
    )));

    let older_os = map_windows_records(
        WindowsCandidateLists::DxCore {
            d3d11_graphics: vec![first],
            generic_media: None,
        },
        &tokio_util::sync::CancellationToken::new(),
    )
    .expect("unsupported Generic Media list does not weaken D3D11 discovery");
    assert_eq!(older_os.len(), 1);
    assert!(matches!(
        older_os[0].locator,
        DeviceLocator::Windows {
            adapter_luid: 11,
            physical_index: Some(0)
        }
    ));

    let dxgi = map_windows_records(
        WindowsCandidateLists::DxgiFallback(vec![fallback]),
        &tokio_util::sync::CancellationToken::new(),
    )
    .expect("DXGI fallback uses the same PnP mapper");
    assert_eq!(dxgi.len(), 1);
    assert!(matches!(
        dxgi[0].locator,
        DeviceLocator::Windows {
            adapter_luid: 33,
            physical_index: Some(0)
        }
    ));
}

#[test]
fn windows_union_accepts_member_reordering_but_rejects_conflicting_snapshots() {
    let mut first = windows_adapter(77, "unused");
    let mut second_member = first.physical_adapters[0].clone();
    second_member.physical_index = Some(1);
    second_member.instance_id = r"TEST\SECOND".encode_utf16().collect();
    second_member.repeated_instance_id = second_member.instance_id.clone();
    first.physical_adapters.push(second_member);
    let mut reordered = first.clone();
    reordered.physical_adapters.reverse();
    assert_eq!(
        map_windows_records(
            WindowsCandidateLists::DxCore {
                d3d11_graphics: vec![first.clone()],
                generic_media: Some(vec![reordered]),
            },
            &tokio_util::sync::CancellationToken::new(),
        )
        .expect("physical member ordering is not identity")
        .len(),
        2
    );

    let mut conflicting = first.clone();
    conflicting.physical_adapters[0].driver = WindowsDriverSnapshot::complete_for_test("different");
    assert_eq!(
        map_windows_records(
            WindowsCandidateLists::DxCore {
                d3d11_graphics: vec![first],
                generic_media: Some(vec![conflicting]),
            },
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Ambiguous
    );
}

#[test]
fn windows_pnp_identity_is_luid_independent_and_separates_identical_models() {
    let first =
        map_windows_adapter(windows_adapter(11, r"TEST\DISPLAY\STABLE")).expect("first identity");
    let rebooted = map_windows_adapter(windows_adapter(99, r"TEST\DISPLAY\STABLE"))
        .expect("same PnP identity after LUID change");
    assert_eq!(
        first[0].persistent_identity.as_bytes(),
        rebooted[0].persistent_identity.as_bytes()
    );
    assert_ne!(first[0].locator, rebooted[0].locator);

    let other = map_windows_adapter(windows_adapter(22, r"TEST\DISPLAY\OTHER"))
        .expect("identical model with distinct PnP identity");
    assert_ne!(
        first[0].persistent_identity.as_bytes(),
        other[0].persistent_identity.as_bytes()
    );
}

#[test]
fn windows_pnp_identity_is_exact_utf16le_and_rejects_unsafe_reads() {
    let mut adapter = windows_adapter(11, "A\u{00e9}");
    let exact = map_windows_adapter(adapter.clone()).expect("valid UTF-16 identity");
    assert_eq!(
        exact[0].persistent_identity.as_bytes(),
        &[0x41, 0x00, 0xe9, 0x00]
    );

    adapter.physical_adapters[0].repeated_instance_id = "changed".encode_utf16().collect();
    assert_eq!(
        map_windows_adapter(adapter).unwrap_err(),
        DeviceError::Invalid
    );

    for invalid in [Vec::new(), vec![b'A' as u16, 0, b'B' as u16], vec![1; 200]] {
        let mut adapter = windows_adapter(11, "placeholder");
        adapter.physical_adapters[0].instance_id = invalid.clone();
        adapter.physical_adapters[0].repeated_instance_id = invalid;
        assert_eq!(
            map_windows_adapter(adapter).unwrap_err(),
            DeviceError::Invalid
        );
    }
    let maximum = vec![1; 199];
    let mut adapter = windows_adapter(11, "placeholder");
    adapter.physical_adapters[0].instance_id = maximum.clone();
    adapter.physical_adapters[0].repeated_instance_id = maximum;
    assert_eq!(
        map_windows_adapter(adapter).expect("199 units pass").len(),
        1
    );
}

#[test]
fn windows_linked_adapters_split_only_with_one_to_one_locators() {
    let first = WindowsPhysicalSnapshot {
        physical_index: Some(0),
        instance_id: r"TEST\LINKED\ONE".encode_utf16().collect(),
        repeated_instance_id: r"TEST\LINKED\ONE".encode_utf16().collect(),
        driver: WindowsDriverSnapshot::complete_for_test("1"),
    };
    let mut second = first.clone();
    second.physical_index = Some(1);
    second.instance_id = r"TEST\LINKED\TWO".encode_utf16().collect();
    second.repeated_instance_id = second.instance_id.clone();
    let mut adapter = windows_adapter(44, "unused");
    adapter.physical_adapters = vec![first.clone(), second.clone()];

    let split = map_windows_adapter(adapter.clone()).expect("one-to-one physical locators");
    assert_eq!(split.len(), 2);
    assert!(
        split
            .iter()
            .all(|record| record.class == DeviceClass::Integrated)
    );

    adapter.physical_adapters[0].physical_index = None;
    adapter.physical_adapters[1].physical_index = None;
    let grouped = map_windows_adapter(adapter).expect("linked logical group");
    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped[0].class, DeviceClass::Unknown);
    assert!(matches!(
        grouped[0].locator,
        DeviceLocator::Windows {
            adapter_luid: 44,
            physical_index: None
        }
    ));

    let mut duplicate_locator = windows_adapter(44, "unused");
    duplicate_locator.physical_adapters = vec![first, second];
    duplicate_locator.physical_adapters[1].physical_index = Some(0);
    assert_eq!(
        map_windows_adapter(duplicate_locator).unwrap_err(),
        DeviceError::Ambiguous
    );
}

#[test]
fn windows_linked_group_framing_is_sorted_deduplicated_and_topology_sensitive() {
    let member = |identity: &str| WindowsPhysicalSnapshot {
        physical_index: None,
        instance_id: identity.encode_utf16().collect(),
        repeated_instance_id: identity.encode_utf16().collect(),
        driver: WindowsDriverSnapshot::complete_for_test("1"),
    };
    let mut adapter = windows_adapter(55, "unused");
    adapter.physical_adapters = vec![
        member(r"TEST\MEMBER\B"),
        member(r"TEST\MEMBER\A"),
        member(r"TEST\MEMBER\A"),
    ];
    let canonical = map_windows_adapter(adapter.clone()).expect("canonical group");

    let mut expected = b"windows-linked-group/v1\0".to_vec();
    expected.extend_from_slice(&2_u32.to_be_bytes());
    for identity in [r"TEST\MEMBER\A", r"TEST\MEMBER\B"] {
        let bytes = identity
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        expected.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(&bytes);
    }
    assert_eq!(canonical[0].persistent_identity.as_bytes(), expected);

    adapter.physical_adapters.reverse();
    let reordered = map_windows_adapter(adapter).expect("member order is irrelevant");
    assert_eq!(
        canonical[0].persistent_identity.as_bytes(),
        reordered[0].persistent_identity.as_bytes()
    );

    let mut changed = windows_adapter(55, "unused");
    changed.physical_adapters = vec![member(r"TEST\MEMBER\A"), member(r"TEST\MEMBER\C")];
    let changed = map_windows_adapter(changed).expect("changed topology");
    assert_ne!(
        canonical[0].persistent_identity.as_bytes(),
        changed[0].persistent_identity.as_bytes()
    );

    let large_identity = "X".repeat(198);
    let mut overflow = windows_adapter(55, "unused");
    overflow.physical_adapters = (0..6)
        .map(|index| member(&format!("{index}{large_identity}")))
        .collect();
    assert_eq!(
        map_windows_adapter(overflow).unwrap_err(),
        DeviceError::Overflow
    );
}

#[test]
fn windows_mapping_excludes_software_and_uses_only_explicit_class_evidence() {
    let mut software = windows_adapter(1, r"TEST\SOFTWARE");
    software.is_hardware = Some(false);
    software.physical_adapters.clear();
    assert!(
        map_windows_adapter(software)
            .expect("software adapter excluded before mapping")
            .is_empty()
    );

    let mut virtual_adapter = windows_adapter(2, r"TEST\VIRTUAL");
    virtual_adapter.has_virtual_or_remote_evidence = true;
    assert_eq!(
        map_windows_adapter(virtual_adapter).unwrap()[0].class,
        DeviceClass::Virtual
    );

    let mut unknown = windows_adapter(3, r"TEST\UNKNOWN");
    unknown.is_integrated = None;
    assert_eq!(
        map_windows_adapter(unknown).unwrap()[0].class,
        DeviceClass::Unknown
    );

    let mut discrete = windows_adapter(4, r"TEST\DISCRETE");
    discrete.is_integrated = Some(false);
    assert_eq!(
        map_windows_adapter(discrete).unwrap()[0].class,
        DeviceClass::Discrete
    );
}

#[test]
fn windows_missing_duplicate_and_stale_mappings_fail_closed() {
    let mut missing = windows_adapter(1, "unused");
    missing.physical_adapters.clear();
    assert_eq!(
        map_windows_adapter(missing).unwrap_err(),
        DeviceError::Invalid
    );

    let first = windows_adapter(2, r"TEST\DUPLICATE").physical_adapters[0].clone();
    let mut second = first.clone();
    second.physical_index = Some(1);
    let mut duplicate = windows_adapter(2, "unused");
    duplicate.physical_adapters = vec![first, second];
    assert_eq!(
        map_windows_adapter(duplicate).unwrap_err(),
        DeviceError::Ambiguous
    );

    let mut stale = windows_adapter(3, r"TEST\STALE");
    stale.physical_adapters[0].repeated_instance_id = r"TEST\REPLACED".encode_utf16().collect();
    assert_eq!(
        map_windows_adapter(stale).unwrap_err(),
        DeviceError::Invalid
    );

    let first = windows_adapter(4, r"TEST\ONE");
    let mut conflicting = first.clone();
    conflicting.display_name = b"Different snapshot".to_vec();
    assert_eq!(
        map_windows_records(
            WindowsCandidateLists::DxCore {
                d3d11_graphics: vec![first],
                generic_media: Some(vec![conflicting]),
            },
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Ambiguous
    );
}

#[test]
fn windows_driver_completeness_and_cancellation_are_closed_boundaries() {
    let complete =
        map_windows_adapter(windows_adapter(1, r"TEST\COMPLETE")).expect("complete driver");
    assert!(matches!(complete[0].driver, DriverRecord::Complete(_)));

    let mut incomplete = windows_adapter(2, r"TEST\INCOMPLETE");
    incomplete.physical_adapters[0].driver = WindowsDriverSnapshot::incomplete_for_test();
    let incomplete = map_windows_adapter(incomplete).expect("incomplete is not fabricated");
    assert_eq!(incomplete[0].driver, DriverRecord::Incomplete);

    let mut oversized = windows_adapter(3, r"TEST\OVERSIZED");
    oversized.physical_adapters[0].driver = WindowsDriverSnapshot::oversized_incomplete_for_test();
    assert_eq!(
        map_windows_adapter(oversized).unwrap_err(),
        DeviceError::Overflow
    );

    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        map_windows_records(
            WindowsCandidateLists::DxgiFallback(vec![windows_adapter(4, r"TEST\CANCELLED")]),
            &cancellation,
        )
        .unwrap_err(),
        DeviceError::Cancelled
    );
}

#[test]
fn windows_linked_group_driver_is_incomplete_when_any_member_is_incomplete() {
    let mut first = windows_adapter(71, r"TEST\GROUP\ONE")
        .physical_adapters
        .remove(0);
    first.physical_index = None;
    let mut second = windows_adapter(71, r"TEST\GROUP\TWO")
        .physical_adapters
        .remove(0);
    second.physical_index = None;
    second.driver = WindowsDriverSnapshot::incomplete_for_test();
    let mut adapter = windows_adapter(71, "unused");
    adapter.physical_adapters = vec![first, second];
    let grouped = map_windows_adapter(adapter).expect("valid linked group");
    assert_eq!(grouped.len(), 1);
    assert_eq!(grouped[0].driver, DriverRecord::Incomplete);
}

#[test]
fn windows_adapter_count_accepts_32_and_rejects_33_without_truncation() {
    let candidates = (0..32)
        .map(|index| windows_adapter(index, &format!(r"TEST\COUNT\{index}")))
        .collect::<Vec<_>>();
    assert_eq!(
        map_windows_records(
            WindowsCandidateLists::DxgiFallback(candidates.clone()),
            &tokio_util::sync::CancellationToken::new(),
        )
        .expect("exact device bound")
        .len(),
        32
    );
    let mut overflow = candidates;
    overflow.push(windows_adapter(32, r"TEST\COUNT\OVERFLOW"));
    assert_eq!(
        map_windows_records(
            WindowsCandidateLists::DxgiFallback(overflow),
            &tokio_util::sync::CancellationToken::new(),
        )
        .unwrap_err(),
        DeviceError::Overflow
    );
}

#[test]
fn windows_vendor_backend_aliases_are_static_candidates_not_codec_proof() {
    for (vendor_id, vendor, backends) in [
        (
            Some(0x8086),
            Vendor::Intel,
            vec![BackendKind::D3d11va, BackendKind::Qsv],
        ),
        (
            Some(0x10de),
            Vendor::Nvidia,
            vec![BackendKind::Cuda, BackendKind::D3d11va, BackendKind::Nvenc],
        ),
        (
            Some(0x1002),
            Vendor::Amd,
            vec![BackendKind::Amf, BackendKind::D3d11va],
        ),
        (None, Vendor::Unknown, vec![BackendKind::D3d11va]),
    ] {
        let mut adapter = windows_adapter(88, "TEST");
        adapter.vendor_id = vendor_id;
        let record = map_windows_adapter(adapter).unwrap().remove(0);
        assert_eq!(record.vendor, vendor);
        assert_eq!(record.backends, backends);
    }
}

#[cfg(windows)]
#[tokio::test]
async fn native_windows_no_gpu_is_valid() {
    let records = WindowsDeviceEnumerator
        .enumerate(tokio_util::sync::CancellationToken::new())
        .await
        .expect("native Windows discovery degrades to an empty inventory without a GPU");
    assert_eq!(records.status, DeviceDiscoveryStatus::Supported);
    assert!(records.records.len() <= 32);
    assert_eq!(native_open_handle_count_for_test(), 0);
    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        WindowsDeviceEnumerator
            .enumerate(cancellation)
            .await
            .unwrap_err(),
        DeviceError::Cancelled
    );
    assert_eq!(native_open_handle_count_for_test(), 0);
    for result in [
        Ok(()),
        Err(DeviceError::Invalid),
        Err(DeviceError::Cancelled),
        Err(DeviceError::Overflow),
        Err(DeviceError::Ambiguous),
    ] {
        let expected = result;
        assert_eq!(exercise_native_handle_exit_for_test(result), expected);
        assert_eq!(native_open_handle_count_for_test(), 0);
    }
}

#[test]
fn driver_change_invalidates_evidence_without_renaming_device() {
    let first = normalize_one(record_with_driver("31.0.101.5590"));
    let second = normalize_one(record_with_driver("32.0.101.7000"));
    assert_eq!(first.id, second.id);
    assert_ne!(first.driver_identity, second.driver_identity);
}

#[test]
fn safe_name_replaces_invalid_utf8_collapses_space_and_truncates_on_a_char_boundary() {
    let mut replaced = record_with_identity(b"replaced-name".to_vec());
    replaced.display_name = b"  Synthetic \xff   Adapter  ".to_vec();
    assert_eq!(
        normalize_one(replaced).display_name.as_str(),
        "Synthetic \u{fffd} Adapter"
    );

    let mut long = record_with_identity(b"long-name".to_vec());
    long.display_name = "\u{e9}".repeat(100).into_bytes();
    let normalized = normalize_one(long);
    assert_eq!(normalized.display_name.as_str(), "\u{e9}".repeat(64));
    assert_eq!(normalized.display_name.as_str().len(), 128);
    assert!(normalized.display_name.as_str().is_char_boundary(128));
}

#[test]
fn unsafe_name_candidates_are_rejected_as_a_whole() {
    let unsafe_names = [
        "/tmp/adapter",
        r"C:\adapter",
        "https:adapter",
        "adapter%20name",
        "user@host",
        "adapter..name",
        r"PCI\VEN_SYNTHETIC",
        "model-ven_test",
        "model-DEV_TEST",
        "model-subsys_TEST",
        "GPU1_AAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "control\u{0007}name",
        "adapter\u{202e}txt",
    ];
    for (index, unsafe_name) in unsafe_names.into_iter().enumerate() {
        let mut record = record_with_identity(format!("unsafe-name-{index}").into_bytes());
        record.display_name = unsafe_name.as_bytes().to_vec();
        assert_eq!(
            normalize_one(record).display_name.as_str(),
            "Intel integrated GPU",
            "candidate was not rejected: {unsafe_name:?}"
        );
    }
}

#[test]
fn empty_name_fallbacks_cover_every_closed_vendor_and_class() {
    let vendors = [
        (Vendor::Intel, "Intel"),
        (Vendor::Nvidia, "NVIDIA"),
        (Vendor::Amd, "AMD"),
        (Vendor::Apple, "Apple"),
        (Vendor::Microsoft, "Microsoft"),
        (Vendor::Other, "Other"),
        (Vendor::Unknown, "Unknown"),
    ];
    let classes = [
        (DeviceClass::Integrated, "integrated"),
        (DeviceClass::Discrete, "discrete"),
        (DeviceClass::Virtual, "virtual"),
        (DeviceClass::Software, "software"),
        (DeviceClass::Unknown, "unknown"),
    ];
    for (vendor_index, (vendor, vendor_label)) in vendors.into_iter().enumerate() {
        for (class_index, (class, class_token)) in classes.into_iter().enumerate() {
            let mut record =
                record_with_identity(format!("fallback-{vendor_index}-{class_index}").into_bytes());
            record.display_name.clear();
            record.vendor = vendor;
            record.class = class;
            assert_eq!(
                normalize_one(record).display_name.as_str(),
                format!("{vendor_label} {class_token} GPU")
            );
        }
    }
}

#[test]
fn vendor_class_and_availability_serialize_only_closed_tokens() {
    for (vendor, token) in [
        (Vendor::Intel, "intel"),
        (Vendor::Nvidia, "nvidia"),
        (Vendor::Amd, "amd"),
        (Vendor::Apple, "apple"),
        (Vendor::Microsoft, "microsoft"),
        (Vendor::Other, "other"),
        (Vendor::Unknown, "unknown"),
    ] {
        assert_eq!(
            serde_json::to_string(&vendor).unwrap(),
            format!("\"{token}\"")
        );
    }
    assert_eq!(
        serde_json::to_string(&DeviceClass::Integrated).unwrap(),
        "\"integrated\""
    );
    for (availability, token) in [
        (DeviceAvailability::Available, "available"),
        (DeviceAvailability::LocatorUnavailable, "locatorUnavailable"),
        (DeviceAvailability::PermissionDenied, "permissionDenied"),
        (
            DeviceAvailability::AdministrativelyDisabled,
            "administrativelyDisabled",
        ),
        (DeviceAvailability::Stale, "stale"),
    ] {
        assert_eq!(
            serde_json::to_string(&availability).unwrap(),
            format!("\"{token}\"")
        );
    }
}

#[test]
fn normalization_is_deterministic_and_backend_aliases_are_deduplicated() {
    let mut first = record_with_identity(b"deterministic-a".to_vec());
    first.backends = vec![BackendKind::Qsv, BackendKind::D3d11va, BackendKind::Qsv];
    let mut second = record_with_identity(b"deterministic-b".to_vec());
    second.locator = DeviceLocator::Windows {
        adapter_luid: 42,
        physical_index: None,
    };
    second.backends = vec![BackendKind::Nvenc, BackendKind::Cuda, BackendKind::Nvenc];
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);

    let forward =
        normalize_platform_records(vec![first.clone(), second.clone()], &seed, &epoch).unwrap();
    let reverse = normalize_platform_records(vec![second, first], &seed, &epoch).unwrap();
    assert_eq!(
        forward.iter().map(|device| &device.id).collect::<Vec<_>>(),
        reverse.iter().map(|device| &device.id).collect::<Vec<_>>()
    );
    assert!(forward.iter().all(|device| device.backends.len() == 2));
}

#[test]
fn duplicate_identity_and_locator_ambiguity_fail_closed() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let first = record_with_identity(b"duplicate-identity".to_vec());
    let mut duplicate = first.clone();
    duplicate.locator = DeviceLocator::Windows {
        adapter_luid: 99,
        physical_index: None,
    };
    assert_eq!(
        normalize_platform_records(vec![first, duplicate], &seed, &epoch).unwrap_err(),
        DeviceError::Ambiguous
    );

    let first = record_with_identity(b"locator-a".to_vec());
    let mut second = record_with_identity(b"locator-b".to_vec());
    second.locator = first.locator.clone();
    assert_eq!(
        normalize_platform_records(vec![first, second], &seed, &epoch).unwrap_err(),
        DeviceError::Ambiguous
    );
}

#[test]
fn injected_hmac_collision_fails_closed() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let collision = crate::transcoding::DeviceId::from_hmac_prefix([0x11; 20]);
    let result = normalize_platform_records_with_deriver(
        vec![
            record_with_identity(b"collision-a".to_vec()),
            record_with_identity(b"collision-b".to_vec()),
        ],
        &seed,
        &epoch,
        |_, _, _| Ok(collision.clone()),
    );
    assert_eq!(result.unwrap_err(), DeviceError::Ambiguous);
}

#[test]
fn raw_record_count_individual_and_aggregate_bounds_fail_without_truncation() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let records = (0..33)
        .map(|index| record_with_identity(format!("record-{index}").into_bytes()))
        .collect();
    assert_eq!(
        normalize_platform_records(records, &seed, &epoch).unwrap_err(),
        DeviceError::Overflow
    );

    let mut oversized_name = record_with_identity(b"oversized-name".to_vec());
    oversized_name.display_name = vec![b'a'; 2_049];
    assert_eq!(
        normalize_platform_records(vec![oversized_name], &seed, &epoch).unwrap_err(),
        DeviceError::Overflow
    );

    let mut oversized_locator = record_with_identity(b"oversized-locator".to_vec());
    oversized_locator.locator = DeviceLocator::Linux {
        render_node: vec![b'x'; 2_049],
        device_number: 1,
    };
    assert_eq!(
        normalize_platform_records(vec![oversized_locator], &seed, &epoch).unwrap_err(),
        DeviceError::Overflow
    );

    let mut oversized_driver = record_with_identity(b"oversized-driver".to_vec());
    oversized_driver.driver = DriverRecord::Complete(vec![DriverField::new(1, vec![b'x'; 2_049])]);
    assert_eq!(
        normalize_platform_records(vec![oversized_driver], &seed, &epoch).unwrap_err(),
        DeviceError::Overflow
    );

    let aggregate = (0..32)
        .map(|index| {
            let mut record = record_with_identity(format!("aggregate-{index}").into_bytes());
            record.driver = DriverRecord::Complete(
                (1..=5)
                    .map(|tag| DriverField::new(tag, vec![tag; 2_048]))
                    .collect(),
            );
            record
        })
        .collect();
    assert_eq!(
        normalize_platform_records(aggregate, &seed, &epoch).unwrap_err(),
        DeviceError::Overflow
    );
}

#[test]
fn aggregate_input_accepts_exactly_256_kib_and_rejects_the_next_byte() {
    const PER_RECORD_BYTES: usize = 8 * 1024;
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let records = (0..32)
        .map(|index| {
            let mut record = record_with_identity(format!("boundary-{index:02}").into_bytes());
            record.locator = DeviceLocator::Windows {
                adapter_luid: i64::from(index),
                physical_index: None,
            };
            record.driver = DriverRecord::Complete(
                (1..=4)
                    .map(|tag| DriverField::new(tag, vec![tag; 1_900]))
                    .collect(),
            );
            let current = super::validate_record_size(&record).unwrap();
            let final_field_bytes = PER_RECORD_BYTES
                .checked_sub(current + 5)
                .expect("fixture leaves room for the final framed field");
            assert!(final_field_bytes <= 2_048);
            let DriverRecord::Complete(fields) = &mut record.driver else {
                unreachable!()
            };
            fields.push(DriverField::new(5, vec![5; final_field_bytes]));
            assert_eq!(
                super::validate_record_size(&record).unwrap(),
                PER_RECORD_BYTES
            );
            record
        })
        .collect::<Vec<_>>();
    assert_eq!(
        normalize_platform_records(records.clone(), &seed, &epoch)
            .unwrap()
            .len(),
        32
    );

    let mut overflow = records;
    overflow[0].display_name.push(b'x');
    assert_eq!(
        normalize_platform_records(overflow, &seed, &epoch).unwrap_err(),
        DeviceError::Overflow
    );
}

#[test]
fn incomplete_driver_identity_is_run_scoped_and_never_persistable() {
    let mut record = record_with_identity(b"incomplete-driver".to_vec());
    record.driver = DriverRecord::Incomplete;
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let first_epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let second_epoch = DriverRunEpoch::from_test_bytes([0x6c; 32]);
    let first = normalize_platform_records(vec![record.clone()], &seed, &first_epoch)
        .unwrap()
        .remove(0);
    let same_run = normalize_platform_records(vec![record.clone()], &seed, &first_epoch)
        .unwrap()
        .remove(0);
    let next_run = normalize_platform_records(vec![record], &seed, &second_epoch)
        .unwrap()
        .remove(0);
    assert_eq!(first.driver_identity, same_run.driver_identity);
    assert_ne!(first.driver_identity, next_run.driver_identity);
    assert!(!first.driver_identity.is_persistable());
    assert!(
        normalize_one(record_with_driver("complete"))
            .driver_identity
            .is_persistable()
    );
}

#[test]
fn public_projection_and_debug_output_omit_every_private_sentinel() {
    let mut record =
        record_with_identity(b"private-identity-sentinel:account-name-sentinel".to_vec());
    record.locator = DeviceLocator::Linux {
        render_node: b"/dev/dri/private-locator-sentinel".to_vec(),
        device_number: 2,
    };
    record.driver = DriverRecord::Complete(vec![DriverField::new(
        7,
        b"private-driver-sentinel:/private/path/driver.inf".to_vec(),
    )]);
    let raw_debug = format!("{record:?}");
    let device = normalize_one(record);
    let public = serde_json::to_string(&device.public_projection()).unwrap();
    let debug = format!("{device:?}");
    for sentinel in [
        "private-identity-sentinel",
        "private-locator-sentinel",
        "private-driver-sentinel",
        "account-name-sentinel",
        "/private/path/driver.inf",
    ] {
        assert!(!public.contains(sentinel));
        assert!(!debug.contains(sentinel));
        assert!(!raw_debug.contains(sentinel));
    }
    assert!(public.contains("Synthetic Graphics Adapter"));
    assert!(!public.contains("adapter_luid"));
    assert!(!public.contains("render_node"));
}

#[test]
fn mutable_name_locator_and_driver_inputs_never_change_device_id() {
    let first = record_with_identity(b"stable-public-id".to_vec());
    let mut changed = record_with_identity(b"stable-public-id".to_vec());
    changed.display_name = b"Renamed Adapter".to_vec();
    changed.locator = DeviceLocator::MacosDefault;
    changed.driver = DriverRecord::Complete(vec![DriverField::new(1, b"changed".to_vec())]);
    assert_eq!(normalize_one(first).id, normalize_one(changed).id);
}

#[test]
fn driver_identity_matches_independent_framing_vector_and_field_order_matters() {
    let mut record = record_with_identity(b"driver-vector-device".to_vec());
    record.driver = DriverRecord::Complete(vec![
        DriverField::new(1, b"31.0.101.5590".to_vec()),
        DriverField::new(2, vec![0, 255]),
    ]);
    let expected =
        hex::decode("af288e3f4968bc13de8c7547688c6bb5c6629d00d32dde5636ef0f711297cbcf").unwrap();
    let first = normalize_one(record.clone());
    assert_eq!(first.driver_identity.as_test_digest().as_slice(), expected);

    let DriverRecord::Complete(fields) = &mut record.driver else {
        unreachable!()
    };
    fields.reverse();
    let reversed = normalize_one(record);
    assert_ne!(first.driver_identity, reversed.driver_identity);
}

#[test]
fn malformed_complete_driver_records_are_invalid_not_overflow() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    for driver in [
        DriverRecord::Complete(Vec::new()),
        DriverRecord::Complete(vec![DriverField::new(0, b"field".to_vec())]),
        DriverRecord::Complete(vec![DriverField::new(1, Vec::new())]),
    ] {
        let mut record = record_with_identity(b"malformed-driver".to_vec());
        record.driver = driver;
        assert_eq!(
            normalize_platform_records(vec![record], &seed, &epoch).unwrap_err(),
            DeviceError::Invalid
        );
    }
}

#[test]
fn exactly_32_records_pass_and_unavailable_locators_do_not_alias() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let records = (0..32)
        .map(|index| {
            let mut record = record_with_identity(format!("limit-{index}").into_bytes());
            record.locator = DeviceLocator::Windows {
                adapter_luid: i64::from(index),
                physical_index: None,
            };
            record
        })
        .collect();
    assert_eq!(
        normalize_platform_records(records, &seed, &epoch)
            .unwrap()
            .len(),
        32
    );

    let mut first = record_with_identity(b"unavailable-a".to_vec());
    first.locator = DeviceLocator::Unavailable;
    first.availability = DeviceAvailability::LocatorUnavailable;
    let mut second = record_with_identity(b"unavailable-b".to_vec());
    second.locator = DeviceLocator::Unavailable;
    second.availability = DeviceAvailability::PermissionDenied;
    assert_eq!(
        normalize_platform_records(vec![first, second], &seed, &epoch)
            .unwrap()
            .len(),
        2
    );
}

#[derive(Clone)]
struct InjectedEnumerator {
    records: Vec<PlatformDeviceRecord>,
}

#[async_trait::async_trait]
impl DeviceEnumerator for InjectedEnumerator {
    async fn enumerate(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<DeviceDiscovery, DeviceError> {
        if cancellation.is_cancelled() {
            Err(DeviceError::Cancelled)
        } else {
            Ok(DeviceDiscovery::supported(self.records.clone()))
        }
    }
}

#[tokio::test]
async fn injected_enumerator_has_a_closed_cancellation_boundary() {
    let enumerator = InjectedEnumerator {
        records: vec![record_with_identity(b"enumerated-device".to_vec())],
    };
    assert_eq!(
        enumerator
            .enumerate(tokio_util::sync::CancellationToken::new())
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    let cancelled = tokio_util::sync::CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        enumerator.enumerate(cancelled).await.unwrap_err(),
        DeviceError::Cancelled
    );
    assert_eq!(DeviceError::Cancelled.to_string(), "refresh_cancelled");
}

#[test]
fn generated_run_epoch_and_all_private_wrappers_are_redacted() {
    let epoch = DriverRunEpoch::generate().expect("OS randomness is available");
    let field = DriverField::new(1, b"private-driver-field".to_vec());
    let record = DriverRecord::Complete(vec![field.clone()]);
    let locator = DeviceLocator::Linux {
        render_node: b"private-render-node".to_vec(),
        device_number: 3,
    };
    let device = normalize_one(record_with_driver("private-driver-version"));
    for rendered in [
        format!("{epoch:?}"),
        format!("{epoch}"),
        format!("{field:?}"),
        format!("{field}"),
        format!("{record:?}"),
        format!("{record}"),
        format!("{locator:?}"),
        format!("{locator}"),
        format!("{:?}", device.driver_identity),
        format!("{}", device.driver_identity),
        format!("{:?}", device.private_identity),
        format!("{:?}", device.locator),
    ] {
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("private-"));
    }
}

#[test]
fn device_id_matches_independent_platform_vectors() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let windows = "TEST\\DEVICE_IDENTITY_01"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let linux = b"linux-device/v1\x00pci\x000000:00:02.0".to_vec();
    let macos = b"macos-videotoolbox-default-v1".to_vec();

    let cases = [
        (
            PlatformTag::Windows,
            windows,
            "gpu1_3REctjGQD22DgiDF-lACZviIwQ0",
        ),
        (
            PlatformTag::Linux,
            linux,
            "gpu1_xSGam_xkMj-S-ZuRGMukhuHUbK4",
        ),
        (
            PlatformTag::Macos,
            macos,
            "gpu1_7WQbyvdIAMInb-KzBJcu0nKuM_M",
        ),
    ];

    for (platform, identity, expected) in cases {
        let derived = derive_device_id(&seed, platform, &private_identity(identity)).unwrap();
        assert_eq!(derived.as_str(), expected);
    }
}

#[test]
fn device_id_is_domain_platform_length_and_seed_separated() {
    let first_seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let second_seed = DeviceIdSeed::from_test_bytes([0x5b; 32]);
    let identity = private_identity(b"same-bytes".to_vec());

    let windows = derive_device_id(&first_seed, PlatformTag::Windows, &identity).unwrap();
    let linux = derive_device_id(&first_seed, PlatformTag::Linux, &identity).unwrap();
    let fresh_namespace = derive_device_id(&second_seed, PlatformTag::Windows, &identity).unwrap();
    let framed_differently = derive_device_id(
        &first_seed,
        PlatformTag::Windows,
        &private_identity(b"same-bytes\0".to_vec()),
    )
    .unwrap();

    assert_ne!(windows, linux);
    assert_ne!(windows, fresh_namespace);
    assert_ne!(windows, framed_differently);
    assert!(windows.as_str().starts_with("gpu1_"));
    assert_eq!(windows.as_str().len(), 32);
}

#[test]
fn identical_private_bytes_on_distinct_platforms_are_domain_separated() {
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let epoch = DriverRunEpoch::from_test_bytes([0x6b; 32]);
    let windows = record_with_identity(b"cross-platform-identity".to_vec());
    let mut linux = record_with_identity(b"cross-platform-identity".to_vec());
    linux.platform = PlatformTag::Linux;
    linux.locator = DeviceLocator::Linux {
        render_node: b"synthetic-render-node".to_vec(),
        device_number: 4,
    };
    let devices = normalize_platform_records(vec![windows, linux], &seed, &epoch).unwrap();
    assert_eq!(devices.len(), 2);
    assert_ne!(devices[0].id, devices[1].id);
}

#[test]
fn private_identity_rejects_input_over_2048_bytes() {
    assert!(PrivateDeviceIdentity::new(vec![0; 2_048]).is_ok());
    assert!(PrivateDeviceIdentity::new(vec![0; 2_049]).is_err());
}

#[test]
fn secret_and_identity_debug_output_is_redacted() {
    let sentinel = b"private-device-identity-sentinel".to_vec();
    let seed = DeviceIdSeed::from_test_bytes([0x5a; 32]);
    let identity = private_identity(sentinel.clone());
    let public = derive_device_id(&seed, PlatformTag::Linux, &identity).unwrap();

    for rendered in [
        format!("{seed:?}"),
        format!("{seed}"),
        format!("{identity:?}"),
        format!("{identity}"),
    ] {
        assert!(!rendered.contains("5a"));
        assert!(!rendered.contains("private-device-identity-sentinel"));
        assert!(rendered.contains("redacted"));
    }
    assert!(
        !public
            .as_str()
            .as_bytes()
            .windows(sentinel.len())
            .any(|part| part == sentinel)
    );
}
