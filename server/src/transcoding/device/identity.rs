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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum PlatformTag {
    Windows = 1,
    Linux = 2,
    Macos = 3,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct PrivateDeviceIdentity(Vec<u8>);

impl PrivateDeviceIdentity {
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_IDENTITY_BYTES {
            return Err(IdentityError);
        }
        Ok(Self(bytes))
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
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
pub(crate) struct IdentityError;

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

const DRIVER_ID_DOMAIN: &[u8] = b"stream-server/driver-id/v1\0";

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DriverField {
    tag: u8,
    bytes: Vec<u8>,
}

impl DriverField {
    pub(crate) fn new(tag: u8, bytes: Vec<u8>) -> Self {
        Self { tag, bytes }
    }

    fn framed_size(&self) -> Result<usize, IdentityError> {
        if self.bytes.len() > MAX_PRIVATE_IDENTITY_BYTES {
            return Err(IdentityError);
        }
        1_usize
            .checked_add(4)
            .and_then(|size| size.checked_add(self.bytes.len()))
            .ok_or(IdentityError)
    }
}

impl fmt::Debug for DriverField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DriverField([redacted])")
    }
}

impl fmt::Display for DriverField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum DriverRecord {
    Complete(Vec<DriverField>),
    Incomplete,
}

impl fmt::Debug for DriverRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DriverRecord([redacted])")
    }
}

impl fmt::Display for DriverRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

impl DriverRecord {
    pub(super) fn is_structurally_valid(&self) -> bool {
        match self {
            Self::Complete(fields) => {
                !fields.is_empty()
                    && fields
                        .iter()
                        .all(|field| field.tag != 0 && !field.bytes.is_empty())
            }
            Self::Incomplete => true,
        }
    }

    pub(super) fn framed_size(&self) -> Result<usize, IdentityError> {
        match self {
            Self::Complete(fields) => fields.iter().try_fold(0_usize, |size, field| {
                size.checked_add(field.framed_size()?).ok_or(IdentityError)
            }),
            Self::Incomplete => Ok(0),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DriverRunEpoch([u8; 32]);

impl DriverRunEpoch {
    pub(crate) fn generate() -> Result<Self, IdentityError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| IdentityError)?;
        Ok(Self(bytes))
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for DriverRunEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DriverRunEpoch([redacted])")
    }
}

impl fmt::Display for DriverRunEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct DriverIdentity {
    digest: [u8; 32],
    persistable: bool,
}

impl DriverIdentity {
    pub(super) fn is_persistable(&self) -> bool {
        self.persistable
    }

    #[cfg(test)]
    pub(crate) fn as_test_digest(&self) -> [u8; 32] {
        self.digest
    }

    #[cfg(test)]
    pub(crate) fn from_test_digest(digest: [u8; 32], persistable: bool) -> Self {
        Self {
            digest,
            persistable,
        }
    }
}

impl fmt::Debug for DriverIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DriverIdentity([redacted])")
    }
}

impl fmt::Display for DriverIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

pub(super) fn derive_driver_identity(
    platform: PlatformTag,
    record: &DriverRecord,
    run_epoch: &DriverRunEpoch,
) -> Result<DriverIdentity, IdentityError> {
    match record {
        DriverRecord::Complete(fields) => {
            use sha2::Digest as _;
            if !record.is_structurally_valid() {
                return Err(IdentityError);
            }
            record.framed_size()?;
            let mut hasher = Sha256::new();
            hasher.update(DRIVER_ID_DOMAIN);
            hasher.update([platform as u8]);
            for field in fields {
                let length = u32::try_from(field.bytes.len()).map_err(|_| IdentityError)?;
                hasher.update([field.tag]);
                hasher.update(length.to_be_bytes());
                hasher.update(&field.bytes);
            }
            Ok(DriverIdentity {
                digest: hasher.finalize().into(),
                persistable: true,
            })
        }
        DriverRecord::Incomplete => Ok(DriverIdentity {
            digest: run_epoch.0,
            persistable: false,
        }),
    }
}
