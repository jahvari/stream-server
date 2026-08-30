use super::SeedStorageError;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};

const STORAGE_DIRECTORY_NAME: &[u8] = b"transcoding\0";
const SEED_FILE_NAME: &[u8] = b"device-id.key\0";

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
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 || metadata.nlink() == 0 {
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

pub(super) fn sync_directory(directory: &ProtectedDirectory) -> Result<(), SeedStorageError> {
    directory
        .file
        .sync_all()
        .map_err(|_| SeedStorageError::Unavailable)
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
    {
        return Err(SeedStorageError::Untrusted);
    }
    ensure_local(file)
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
    if unsafe { statistics.assume_init() }.f_flags as u32 & MNT_LOCAL == 0 {
        Err(SeedStorageError::Untrusted)
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ensure_local(_file: &File) -> Result<(), SeedStorageError> {
    Err(SeedStorageError::Untrusted)
}
