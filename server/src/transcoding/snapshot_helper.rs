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
#[cfg(unix)]
pub(crate) const SNAPSHOT_SOURCE_DESCRIPTOR: i32 = 198;
#[cfg(unix)]
pub(crate) const SNAPSHOT_DESTINATION_DESCRIPTOR: i32 = 199;
#[cfg(unix)]
pub(crate) const SNAPSHOT_MAXIMUM_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(unix)]
#[allow(
    dead_code,
    reason = "this source is included by both the library and executable; only the executable entry point calls this copy"
)]
pub(crate) fn maybe_run_from_environment() -> Option<i32> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let mut output = std::io::stdout().lock();
    maybe_run_from_arguments(&arguments, &mut output)
}

#[allow(
    dead_code,
    reason = "this source is included by both the library and executable, whose copies have different callers"
)]
fn maybe_run_from_arguments(
    arguments: &[std::ffi::OsString],
    output: &mut impl Write,
) -> Option<i32> {
    let marker_present = arguments
        .iter()
        .any(|argument| argument == SNAPSHOT_HELPER_ARGUMENT);
    if !marker_present {
        return None;
    }
    let exact = arguments.len() == 5
        && arguments[1] == SNAPSHOT_HELPER_ARGUMENT
        && arguments[2] == std::ffi::OsStr::new("198")
        && arguments[3] == std::ffi::OsStr::new("199")
        && arguments[4] == std::ffi::OsStr::new("536870912");
    if !exact {
        return Some(2);
    }
    match copy_and_hash() {
        Ok((length, digest)) => {
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
#[allow(
    dead_code,
    reason = "this source is included by both the library and executable, whose copies have different callers"
)]
fn copy_and_hash() -> std::io::Result<(u64, [u8; 32])> {
    use std::os::fd::{FromRawFd, OwnedFd};

    fn duplicate_checked(descriptor: i32, write: bool) -> std::io::Result<OwnedFd> {
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let status = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if status < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let access = status & libc::O_ACCMODE;
        if (write && access == libc::O_RDONLY) || (!write && access == libc::O_WRONLY) {
            return Err(std::io::Error::other("snapshot descriptor access mismatch"));
        }
        let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 256) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    // Validate the fixed inherited descriptors, then work only through new,
    // distinct CLOEXEC-owned duplicates. The untrusted argv never becomes an
    // fd ownership operation.
    let source = duplicate_checked(SNAPSHOT_SOURCE_DESCRIPTOR, false)?;
    let destination = duplicate_checked(SNAPSHOT_DESTINATION_DESCRIPTOR, true)?;
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
        if length > SNAPSHOT_MAXIMUM_BYTES {
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
fn copy_and_hash() -> std::io::Result<(u64, [u8; 32])> {
    Err(std::io::Error::other("unsupported snapshot helper host"))
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "this source is included by both the library and executable; only the library test copy invokes this helper"
)]
pub(crate) fn run_exact_test_request(malformed_case: Option<usize>) -> i32 {
    let payload: Vec<&str> = match malformed_case {
        None => vec![SNAPSHOT_HELPER_ARGUMENT, "198", "199", "536870912"],
        Some(0) => vec![SNAPSHOT_HELPER_ARGUMENT, "-198", "199", "536870912"],
        Some(1) => vec![SNAPSHOT_HELPER_ARGUMENT, "198", "198", "536870912"],
        Some(2) => vec![SNAPSHOT_HELPER_ARGUMENT, "198", "199", "536870911"],
        Some(3) => vec![SNAPSHOT_HELPER_ARGUMENT, "198", "199", "536870912", "extra"],
        Some(4) => vec![
            "prefix",
            SNAPSHOT_HELPER_ARGUMENT,
            "198",
            "199",
            "536870912",
        ],
        Some(_) => return 2,
    };
    let mut arguments = vec![std::ffi::OsString::from("snapshot-helper")];
    arguments.extend(payload.into_iter().map(std::ffi::OsString::from));
    // The libtest harness writes its own banner to stdout before invoking an
    // ignored test. Keep the helper protocol on stderr in test subprocesses so
    // the parent receives exactly one machine-readable record.
    let mut output = std::io::stderr().lock();
    maybe_run_from_arguments(&arguments, &mut output).unwrap_or(2)
}
