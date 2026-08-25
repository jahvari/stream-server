//! Minimal, hidden executable snapshot worker.
//!
//! The parent supplies two inherited descriptors. The worker has no pathname
//! access to either file, applies a byte/deadline-independent hard process
//! boundary, and reports only a length and digest on stdout.

#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::io::Write;
#[cfg(unix)]
use std::io::{Read, Seek};

pub(crate) const SNAPSHOT_HELPER_ARGUMENT: &str = "--stream-server-internal-snapshot-v1";

pub(crate) fn maybe_run_from_environment() -> Option<i32> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let position = arguments
        .iter()
        .position(|argument| argument == SNAPSHOT_HELPER_ARGUMENT)?;
    let source = arguments
        .get(position + 1)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<i32>().ok());
    let destination = arguments
        .get(position + 2)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<i32>().ok());
    let maximum = arguments
        .get(position + 3)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u64>().ok());
    let Some((source, destination, maximum)) = source
        .zip(destination)
        .zip(maximum)
        .map(|((source, destination), maximum)| (source, destination, maximum))
    else {
        return Some(2);
    };
    match copy_and_hash(source, destination, maximum) {
        Ok((length, digest)) => {
            let mut output = std::io::stdout().lock();
            if writeln!(output, "{length}:{}", hex::encode(digest)).is_ok() {
                Some(0)
            } else {
                Some(3)
            }
        }
        Err(_) => Some(4),
    }
}

#[cfg(unix)]
fn copy_and_hash(
    source_descriptor: i32,
    destination_descriptor: i32,
    maximum: u64,
) -> std::io::Result<(u64, [u8; 32])> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // These are child-local duplicates installed by pre_exec. Taking
    // ownership cannot affect the parent's descriptors.
    let source = unsafe { OwnedFd::from_raw_fd(source_descriptor) };
    let destination = unsafe { OwnedFd::from_raw_fd(destination_descriptor) };
    let mut source = std::fs::File::from(source);
    let mut destination = std::fs::File::from(destination);
    source.seek(std::io::SeekFrom::Start(0))?;
    destination.seek(std::io::SeekFrom::Start(0))?;
    destination.set_len(0)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("snapshot length overflow"))?;
        if length > maximum {
            return Err(std::io::Error::other("snapshot exceeds byte limit"));
        }
        destination.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
    }
    destination.flush()?;
    destination.sync_all()?;
    Ok((length, hasher.finalize().into()))
}

#[cfg(not(unix))]
fn copy_and_hash(
    _source_descriptor: i32,
    _destination_descriptor: i32,
    _maximum: u64,
) -> std::io::Result<(u64, [u8; 32])> {
    Err(std::io::Error::other("unsupported snapshot helper host"))
}
