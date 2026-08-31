use super::SeedStorageError;
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};

const STORAGE_DIRECTORY_NAME: &[u8] = b"transcoding\0";
const SEED_FILE_NAME: &[u8] = b"device-id.key\0";
const CACHE_LOCK_FILE_NAME: &[u8] = b"capabilities.lock\0";
const CACHE_LOCK_FILE_NAME_STR: &str = "capabilities.lock";
const CACHE_FILE_NAME: &[u8] = b"capabilities-v1.json\0";
const CACHE_TEMPORARY_PREFIX: &[u8] = b"capabilities-v1.tmp-";
const MAX_RECOVERY_TEMPORARIES: usize = 16;

pub(super) struct ProtectedDirectory {
    file: File,
    device: u64,
}

pub(super) enum SeedOpen {
    File(File),
    Missing,
    Busy,
}

pub(super) enum SeedCreate {
    Created(File),
    Exists,
}

pub(super) enum LifetimeLockOpen {
    Acquired(LifetimeLock),
    Contended,
}

pub(super) struct LifetimeLock {
    file: File,
}

impl Drop for LifetimeLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

pub(super) fn prepare_storage_directory(
    config_directory: &Path,
) -> Result<ProtectedDirectory, SeedStorageError> {
    let config = open_absolute_directory(config_directory)?;
    ensure_local(&config)?;
    let descriptor = unsafe {
        libc::openat(
            config.as_raw_fd(),
            STORAGE_DIRECTORY_NAME.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    let root = if descriptor >= 0 {
        unsafe { File::from_raw_fd(descriptor) }
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(SeedStorageError::Untrusted);
        }
        let created = unsafe {
            libc::mkdirat(
                config.as_raw_fd(),
                STORAGE_DIRECTORY_NAME.as_ptr().cast(),
                0o700,
            )
        };
        if created != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(SeedStorageError::Unavailable);
        }
        let descriptor = unsafe {
            libc::openat(
                config.as_raw_fd(),
                STORAGE_DIRECTORY_NAME.as_ptr().cast(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(SeedStorageError::Untrusted);
        }
        unsafe { File::from_raw_fd(descriptor) }
    };
    let metadata = root.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() == 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(SeedStorageError::Untrusted);
    }
    ensure_local(&root)?;
    Ok(ProtectedDirectory {
        file: root,
        device: metadata.dev(),
    })
}

pub(super) fn open_seed(directory: &ProtectedDirectory) -> Result<SeedOpen, SeedStorageError> {
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            SEED_FILE_NAME.as_ptr().cast(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::NotFound => Ok(SeedOpen::Missing),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::PermissionDenied => {
                Ok(SeedOpen::Busy)
            }
            _ => Err(SeedStorageError::Untrusted),
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => Ok(SeedOpen::Busy),
            _ => Err(SeedStorageError::Untrusted),
        };
    }
    validate_seed(&file, directory)?;
    Ok(SeedOpen::File(file))
}

pub(super) fn create_seed(directory: &ProtectedDirectory) -> Result<SeedCreate, SeedStorageError> {
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            SEED_FILE_NAME.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if descriptor < 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::AlreadyExists => Ok(SeedCreate::Exists),
            _ => Err(SeedStorageError::Unavailable),
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(SeedStorageError::Unavailable);
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(SeedStorageError::Unavailable);
    }
    validate_seed(&file, directory)?;
    Ok(SeedCreate::Created(file))
}

pub(super) fn acquire_lifetime_lock(
    directory: &ProtectedDirectory,
) -> Result<LifetimeLockOpen, SeedStorageError> {
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            CACHE_LOCK_FILE_NAME.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(SeedStorageError::Untrusted);
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_regular(&file, directory)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::WouldBlock => Ok(LifetimeLockOpen::Contended),
            _ => Err(SeedStorageError::Unavailable),
        };
    }
    Ok(LifetimeLockOpen::Acquired(LifetimeLock { file }))
}

pub(super) fn validate_lifetime_lock(
    directory: &ProtectedDirectory,
    lock: &LifetimeLock,
) -> Result<(), SeedStorageError> {
    validate_regular(&lock.file, directory)?;
    let metadata = lock
        .file
        .metadata()
        .map_err(|_| SeedStorageError::Untrusted)?;
    validate_named_identity(directory, CACHE_LOCK_FILE_NAME_STR, &metadata)
}

pub(super) fn open_cache(directory: &ProtectedDirectory) -> Result<Option<File>, SeedStorageError> {
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            CACHE_FILE_NAME.as_ptr().cast(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(SeedStorageError::Untrusted),
        };
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_regular(&file, directory)?;
    Ok(Some(file))
}

pub(super) fn create_cache_temporary(
    directory: &ProtectedDirectory,
    name: &str,
) -> Result<File, SeedStorageError> {
    if !valid_temporary_name(name) {
        return Err(SeedStorageError::Untrusted);
    }
    let name = CString::new(name).map_err(|_| SeedStorageError::Untrusted)?;
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(SeedStorageError::Unavailable);
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_regular(&file, directory)?;
    Ok(file)
}

pub(super) fn open_cache_temporary(
    directory: &ProtectedDirectory,
    name: &str,
) -> Result<File, SeedStorageError> {
    if !valid_temporary_name(name) {
        return Err(SeedStorageError::Untrusted);
    }
    let name = CString::new(name).map_err(|_| SeedStorageError::Untrusted)?;
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(SeedStorageError::Untrusted);
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    validate_regular(&file, directory)?;
    Ok(file)
}

pub(super) fn list_cache_temporaries(
    directory: &ProtectedDirectory,
) -> Result<Vec<String>, SeedStorageError> {
    let descriptor = unsafe { libc::fcntl(directory.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(SeedStorageError::Unavailable);
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        unsafe { libc::close(descriptor) };
        return Err(SeedStorageError::Unavailable);
    }
    let mut names = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            if last_errno() != 0 {
                unsafe { libc::closedir(stream) };
                return Err(SeedStorageError::Unavailable);
            }
            break;
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if !bytes.starts_with(CACHE_TEMPORARY_PREFIX) {
            continue;
        }
        if names.len() == MAX_RECOVERY_TEMPORARIES {
            unsafe { libc::closedir(stream) };
            return Err(SeedStorageError::Untrusted);
        }
        let Ok(name) = std::str::from_utf8(bytes) else {
            unsafe { libc::closedir(stream) };
            return Err(SeedStorageError::Untrusted);
        };
        if !valid_temporary_name(name) {
            unsafe { libc::closedir(stream) };
            return Err(SeedStorageError::Untrusted);
        }
        names.push(name.to_owned());
    }
    if unsafe { libc::closedir(stream) } != 0 {
        return Err(SeedStorageError::Unavailable);
    }
    Ok(names)
}

pub(super) fn replace_cache_temporary(
    directory: &ProtectedDirectory,
    temporary: &File,
    temporary_name: &str,
) -> Result<(), SeedStorageError> {
    if !valid_temporary_name(temporary_name) {
        return Err(SeedStorageError::Untrusted);
    }
    validate_regular(temporary, directory)?;
    let temporary_metadata = temporary
        .metadata()
        .map_err(|_| SeedStorageError::Untrusted)?;
    validate_named_identity(directory, temporary_name, &temporary_metadata)?;
    if let Some(existing) = open_cache(directory)? {
        drop(existing);
    }
    validate_named_identity(directory, temporary_name, &temporary_metadata)?;
    let temporary_name = CString::new(temporary_name).map_err(|_| SeedStorageError::Untrusted)?;
    if unsafe {
        libc::renameat(
            directory.file.as_raw_fd(),
            temporary_name.as_ptr(),
            directory.file.as_raw_fd(),
            CACHE_FILE_NAME.as_ptr().cast(),
        )
    } != 0
    {
        return Err(SeedStorageError::Unavailable);
    }
    let installed = open_cache(directory)?.ok_or(SeedStorageError::Untrusted)?;
    let installed_metadata = installed
        .metadata()
        .map_err(|_| SeedStorageError::Untrusted)?;
    if temporary_metadata.dev() != installed_metadata.dev()
        || temporary_metadata.ino() != installed_metadata.ino()
    {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(())
}

pub(super) fn discard_temporary(
    directory: &ProtectedDirectory,
    file: &File,
    temporary_name: &str,
) -> Result<(), SeedStorageError> {
    if !valid_temporary_name(temporary_name) {
        return Err(SeedStorageError::Untrusted);
    }
    validate_regular(file, directory)?;
    let metadata = file.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    validate_named_identity(directory, temporary_name, &metadata)?;
    let name = CString::new(temporary_name).map_err(|_| SeedStorageError::Untrusted)?;
    if unsafe { libc::unlinkat(directory.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(SeedStorageError::Unavailable);
    }
    Ok(())
}

pub(super) fn sync_directory(directory: &ProtectedDirectory) -> Result<(), SeedStorageError> {
    match directory.file.sync_all() {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .raw_os_error()
                .is_some_and(|code| matches!(code, libc::EINVAL | libc::ENOTSUP | libc::EROFS)) =>
        {
            Ok(())
        }
        Err(_) => Err(SeedStorageError::Unavailable),
    }
}

fn open_absolute_directory(path: &Path) -> Result<File, SeedStorageError> {
    if !path.is_absolute() {
        return Err(SeedStorageError::Untrusted);
    }
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| SeedStorageError::Untrusted)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(SeedStorageError::Untrusted);
    }
    let mut directory = File::open("/").map_err(|_| SeedStorageError::Untrusted)?;
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(SeedStorageError::Untrusted);
        };
        directory = open_directory_at(&directory, component)?;
    }
    Ok(directory)
}

fn open_directory_at(directory: &File, name: &OsStr) -> Result<File, SeedStorageError> {
    let name = CString::new(name.as_bytes()).map_err(|_| SeedStorageError::Untrusted)?;
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_seed(file: &File, directory: &ProtectedDirectory) -> Result<(), SeedStorageError> {
    let metadata = file.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.dev() != directory.device
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(SeedStorageError::Untrusted);
    }
    ensure_local(file)
}

fn validate_regular(file: &File, directory: &ProtectedDirectory) -> Result<(), SeedStorageError> {
    let metadata = file.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.dev() != directory.device
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(SeedStorageError::Untrusted);
    }
    ensure_local(file)
}

fn valid_temporary_name(name: &str) -> bool {
    const PREFIX: &str = "capabilities-v1.tmp-";
    name.strip_prefix(PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

fn clear_errno() {
    unsafe { *errno_location() = 0 };
}

fn last_errno() -> libc::c_int {
    unsafe { *errno_location() }
}

fn validate_named_identity(
    directory: &ProtectedDirectory,
    name: &str,
    expected: &std::fs::Metadata,
) -> Result<(), SeedStorageError> {
    let name = CString::new(name).map_err(|_| SeedStorageError::Untrusted)?;
    let descriptor = unsafe {
        libc::openat(
            directory.file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(SeedStorageError::Untrusted);
    }
    let current = unsafe { File::from_raw_fd(descriptor) };
    validate_regular(&current, directory)?;
    let actual = current
        .metadata()
        .map_err(|_| SeedStorageError::Untrusted)?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_local(file: &File) -> Result<(), SeedStorageError> {
    let mut statistics = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(SeedStorageError::Untrusted);
    }
    let filesystem_type = i128::from(unsafe { statistics.assume_init() }.f_type);
    if matches!(
        filesystem_type,
        0x0000_ef53 // ext2/ext3/ext4
            | 0x5846_5342 // XFS
            | 0x9123_683e // Btrfs
            | 0x0102_1994 // tmpfs
            | 0x8584_58f6 // ramfs
            | 0x794c_7630 // overlayfs
            | 0x2fc1_2fc1 // ZFS
            | 0xf2f5_2010 // F2FS
            | 0x3153_464a // JFS
            | 0x5265_4973 // ReiserFS
            | 0x0000_3434 // NILFS
            | 0x1501_3346 // UDF
            | 0x0000_4d44 // FAT
            | 0x2011_bab0 // exFAT
            | 0x5346_544e // NTFS/NTFS3
            | 0x6175_6673 // aufs
    ) {
        Ok(())
    } else {
        Err(SeedStorageError::Untrusted)
    }
}

#[cfg(target_os = "macos")]
fn ensure_local(file: &File) -> Result<(), SeedStorageError> {
    let mut statistics = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), statistics.as_mut_ptr()) } != 0 {
        return Err(SeedStorageError::Untrusted);
    }
    const MNT_LOCAL: u32 = 0x0000_1000;
    if unsafe { statistics.assume_init() }.f_flags & MNT_LOCAL == 0 {
        Err(SeedStorageError::Untrusted)
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_local(_file: &File) -> Result<(), SeedStorageError> {
    Err(SeedStorageError::Untrusted)
}
