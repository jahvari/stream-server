use std::{
    fmt,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    thread,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

use crate::transcoding::device::identity::DeviceIdSeed;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
pub(super) mod windows;
#[cfg(windows)]
use windows as platform;

const DEVICE_ID_SEED_BYTES: usize = 32;
const WINNER_REOPEN_ATTEMPTS: usize = 200;
const WINNER_REOPEN_DELAY: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SeedStorageError {
    Cancelled,
    Invalid,
    Untrusted,
    Unavailable,
}

impl fmt::Display for SeedStorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "refresh_cancelled",
            Self::Invalid | Self::Untrusted | Self::Unavailable => "device_identity_unavailable",
        })
    }
}

impl std::error::Error for SeedStorageError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SeedStorageEvent {
    RootReady,
    SeedCreatedBeforeWrite,
    SeedFileSynced,
    ParentDirectorySyncAttempted,
}

pub(super) fn load_or_create_device_seed(
    config_directory: &Path,
    cancellation: &CancellationToken,
) -> Result<DeviceIdSeed, SeedStorageError> {
    load_or_create_device_seed_with_observer(config_directory, cancellation, |_| {})
}

pub(super) fn load_or_create_device_seed_with_observer(
    config_directory: &Path,
    cancellation: &CancellationToken,
    mut observer: impl FnMut(SeedStorageEvent),
) -> Result<DeviceIdSeed, SeedStorageError> {
    if cancellation.is_cancelled() {
        return Err(SeedStorageError::Cancelled);
    }
    let directory = platform::prepare_storage_directory(config_directory)?;
    observer(SeedStorageEvent::RootReady);
    if cancellation.is_cancelled() {
        return Err(SeedStorageError::Cancelled);
    }

    for _ in 0..WINNER_REOPEN_ATTEMPTS {
        if cancellation.is_cancelled() {
            return Err(SeedStorageError::Cancelled);
        }
        match platform::open_seed(&directory)? {
            platform::SeedOpen::File(file) => return read_seed(file),
            platform::SeedOpen::Busy => {
                thread::sleep(WINNER_REOPEN_DELAY);
                continue;
            }
            platform::SeedOpen::Missing => {}
        }

        let mut bytes = [0_u8; DEVICE_ID_SEED_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| SeedStorageError::Unavailable)?;
        match platform::create_seed(&directory)? {
            platform::SeedCreate::Created(mut file) => {
                observer(SeedStorageEvent::SeedCreatedBeforeWrite);
                file.write_all(&bytes)
                    .map_err(|_| SeedStorageError::Unavailable)?;
                file.sync_all().map_err(|_| SeedStorageError::Unavailable)?;
                observer(SeedStorageEvent::SeedFileSynced);
                drop(file);
                observer(SeedStorageEvent::ParentDirectorySyncAttempted);
                platform::sync_directory(&directory)?;
                return Ok(DeviceIdSeed::from_storage_bytes(bytes));
            }
            platform::SeedCreate::Exists => continue,
        }
    }
    Err(SeedStorageError::Unavailable)
}

fn read_seed(mut file: File) -> Result<DeviceIdSeed, SeedStorageError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SeedStorageError::Unavailable)?;
    let mut bytes = [0_u8; DEVICE_ID_SEED_BYTES];
    file.read_exact(&mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            SeedStorageError::Invalid
        } else {
            SeedStorageError::Unavailable
        }
    })?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| SeedStorageError::Unavailable)?
        != 0
    {
        return Err(SeedStorageError::Invalid);
    }
    Ok(DeviceIdSeed::from_storage_bytes(bytes))
}

#[cfg(not(any(unix, windows)))]
compile_error!("protected device seed storage is unsupported on this target");
