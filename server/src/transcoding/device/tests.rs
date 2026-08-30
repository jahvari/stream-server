use super::identity::{DeviceIdSeed, PlatformTag, PrivateDeviceIdentity, derive_device_id};

fn private_identity(bytes: impl Into<Vec<u8>>) -> PrivateDeviceIdentity {
    PrivateDeviceIdentity::new(bytes.into()).expect("bounded private identity")
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
