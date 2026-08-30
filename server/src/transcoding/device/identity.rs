use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;

use crate::transcoding::DeviceId;

const DEVICE_ID_DOMAIN: &[u8] = b"stream-server/device-id/v1\0";
const DEVICE_ID_SEED_BYTES: usize = 32;
const MAX_PRIVATE_IDENTITY_BYTES: usize = 2_048;

#[derive(Clone)]
pub(crate) struct DeviceIdSeed([u8; DEVICE_ID_SEED_BYTES]);

impl DeviceIdSeed {
    pub(crate) fn from_storage_bytes(bytes: [u8; DEVICE_ID_SEED_BYTES]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(super) fn from_test_bytes(bytes: [u8; DEVICE_ID_SEED_BYTES]) -> Self {
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn as_test_bytes(&self) -> [u8; DEVICE_ID_SEED_BYTES] {
        self.0
    }
}

impl fmt::Debug for DeviceIdSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceIdSeed([redacted])")
    }
}

impl fmt::Display for DeviceIdSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum PlatformTag {
    Windows = 1,
    Linux = 2,
    Macos = 3,
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct PrivateDeviceIdentity(Vec<u8>);

impl PrivateDeviceIdentity {
    pub(super) fn new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_IDENTITY_BYTES {
            return Err(IdentityError);
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PrivateDeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateDeviceIdentity([redacted])")
    }
}

impl fmt::Display for PrivateDeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IdentityError;

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("device_identity_unavailable")
    }
}

impl std::error::Error for IdentityError {}

pub(super) fn derive_device_id(
    seed: &DeviceIdSeed,
    platform: PlatformTag,
    identity: &PrivateDeviceIdentity,
) -> Result<DeviceId, IdentityError> {
    let identity_length = u32::try_from(identity.as_bytes().len()).map_err(|_| IdentityError)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&seed.0).map_err(|_| IdentityError)?;
    mac.update(DEVICE_ID_DOMAIN);
    mac.update(&[platform as u8]);
    mac.update(&identity_length.to_be_bytes());
    mac.update(identity.as_bytes());

    let digest = mac.finalize().into_bytes();
    let prefix: [u8; 20] = digest[..20].try_into().map_err(|_| IdentityError)?;
    Ok(DeviceId::from_hmac_prefix(prefix))
}
