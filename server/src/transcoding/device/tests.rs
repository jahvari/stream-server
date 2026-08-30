use super::identity::{
    DeviceIdSeed, DriverIdentity, PlatformTag, PrivateDeviceIdentity, derive_device_id,
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
    DeviceAvailability, DeviceEnumerator, DeviceError, DeviceLocator, DriverField, DriverRecord,
    DriverRunEpoch, PlatformDeviceRecord, Vendor, normalize_platform_records,
    normalize_platform_records_with_deriver,
};
use crate::transcoding::{BackendKind, DeviceClass};

static_assertions::assert_not_impl_any!(DeviceIdSeed: serde::Serialize);
static_assertions::assert_not_impl_any!(PrivateDeviceIdentity: serde::Serialize);
static_assertions::assert_not_impl_any!(DeviceLocator: serde::Serialize);
static_assertions::assert_not_impl_any!(DriverIdentity: serde::Serialize);
static_assertions::assert_not_impl_any!(DriverField: serde::Serialize);
static_assertions::assert_not_impl_any!(DriverRecord: serde::Serialize);
static_assertions::assert_not_impl_any!(PlatformDeviceRecord: serde::Serialize);
static_assertions::assert_not_impl_any!(WindowsAdapterSnapshot: serde::Serialize);
static_assertions::assert_not_impl_any!(WindowsPhysicalSnapshot: serde::Serialize);
static_assertions::assert_not_impl_any!(WindowsDriverSnapshot: serde::Serialize);

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
    assert!(records.len() <= 32);
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
    ) -> Result<Vec<PlatformDeviceRecord>, DeviceError> {
        if cancellation.is_cancelled() {
            Err(DeviceError::Cancelled)
        } else {
            Ok(self.records.clone())
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
