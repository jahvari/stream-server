use super::SeedStorageError;
use std::{
    fs::{self, File},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
};
use windows::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
            FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS,
            FILE_RENAME_REPLACE_IF_EXISTS, FILE_SYNCHRONOUS_IO_NONALERT, FileRenameInformationEx,
            NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
            NtSetInformationFile,
        },
    },
    Win32::{
        Foundation::{
            CloseHandle, ERROR_LOCK_VIOLATION, ERROR_NO_MORE_FILES, HANDLE, HLOCAL, LocalFree,
            OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
            STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SHARING_VIOLATION, UNICODE_STRING,
        },
        Globalization::{CSTR_EQUAL, CompareStringOrdinal},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
            },
            DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
            SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_NORMAL,
            FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_ID_BOTH_DIR_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_MODE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA,
            FileDispositionInfoEx, FileIdBothDirectoryInfo, GetDriveTypeW,
            GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, READ_CONTROL,
            SetFileInformationByHandle, UnlockFileEx, WRITE_DAC,
        },
        System::{
            IO::{IO_STATUS_BLOCK, OVERLAPPED},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
    core::{PCWSTR, PWSTR},
};

const STORAGE_DIRECTORY_NAME: &str = "transcoding";
const SEED_FILE_NAME: &str = "device-id.key";
const CACHE_LOCK_FILE_NAME: &str = "capabilities.lock";
const CACHE_FILE_NAME: &str = "capabilities-v1.json";
const CACHE_TEMPORARY_PREFIX: &str = "capabilities-v1.tmp-";
const MAX_RECOVERY_TEMPORARIES: usize = 16;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const DIRECTORY_SDDL: &str = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)";
const FILE_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)";
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

pub(super) struct ProtectedDirectory {
    file: File,
    path: PathBuf,
    volume: u32,
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
        let mut overlapped = OVERLAPPED::default();
        let _ = unsafe {
            UnlockFileEx(
                HANDLE(self.file.as_raw_handle()),
                None,
                1,
                0,
                &raw mut overlapped,
            )
        };
    }
}

pub(super) fn prepare_storage_directory(
    config_directory: &Path,
) -> Result<ProtectedDirectory, SeedStorageError> {
    if !config_directory.is_absolute() || is_remote_or_device_path(config_directory) {
        return Err(SeedStorageError::Untrusted);
    }
    validate_no_reparse_components(config_directory)?;
    let config = open_directory_path(config_directory)?;
    validate_directory_handle(&config, config_directory, None)?;
    validate_no_reparse_components(config_directory)?;
    let canonical_config = final_handle_path(&config)?;
    let expected = canonical_config.join(STORAGE_DIRECTORY_NAME);

    let root = match open_relative(
        &config,
        STORAGE_DIRECTORY_NAME,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_TRAVERSE | READ_CONTROL | WRITE_DAC,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
    ) {
        RelativeOpen::File(file) => {
            if !dacl_is_protected(&file) || !owner_is_current_user(&file) {
                return Err(SeedStorageError::Untrusted);
            }
            apply_protected_dacl(&file, DIRECTORY_SDDL)?;
            file
        }
        RelativeOpen::Missing => {
            let descriptor = SecurityDescriptor::new(DIRECTORY_SDDL)?;
            match open_relative(
                &config,
                STORAGE_DIRECTORY_NAME,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_TRAVERSE | READ_CONTROL | WRITE_DAC,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                Some(descriptor.as_ptr()),
            ) {
                RelativeOpen::File(file) => file,
                RelativeOpen::Collision => match open_relative(
                    &config,
                    STORAGE_DIRECTORY_NAME,
                    FILE_GENERIC_READ
                        | FILE_GENERIC_WRITE
                        | FILE_TRAVERSE
                        | READ_CONTROL
                        | WRITE_DAC,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                    None,
                ) {
                    RelativeOpen::File(file)
                        if dacl_is_protected(&file) && owner_is_current_user(&file) =>
                    {
                        file
                    }
                    _ => return Err(SeedStorageError::Untrusted),
                },
                _ => return Err(SeedStorageError::Unavailable),
            }
        }
        _ => return Err(SeedStorageError::Untrusted),
    };
    let volume = validate_directory_handle(&root, &expected, Some(&canonical_config))?;
    if !dacl_is_protected(&root) || !owner_is_current_user(&root) {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(ProtectedDirectory {
        file: root,
        path: expected,
        volume,
    })
}

pub(super) fn open_seed(directory: &ProtectedDirectory) -> Result<SeedOpen, SeedStorageError> {
    match open_relative(
        &directory.file,
        SEED_FILE_NAME,
        FILE_GENERIC_READ | READ_CONTROL,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
    ) {
        RelativeOpen::File(file) => {
            validate_seed_handle(&file, directory)?;
            if !dacl_is_protected(&file) {
                return Err(SeedStorageError::Untrusted);
            }
            Ok(SeedOpen::File(file))
        }
        RelativeOpen::Missing => Ok(SeedOpen::Missing),
        RelativeOpen::Busy => Ok(SeedOpen::Busy),
        _ => Err(SeedStorageError::Untrusted),
    }
}

pub(super) fn create_seed(directory: &ProtectedDirectory) -> Result<SeedCreate, SeedStorageError> {
    let descriptor = SecurityDescriptor::new(FILE_SDDL)?;
    match open_relative(
        &directory.file,
        SEED_FILE_NAME,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        Some(descriptor.as_ptr()),
    ) {
        RelativeOpen::File(file) => {
            validate_seed_handle(&file, directory)?;
            apply_protected_dacl(&file, FILE_SDDL)?;
            Ok(SeedCreate::Created(file))
        }
        RelativeOpen::Collision | RelativeOpen::Busy => Ok(SeedCreate::Exists),
        _ => Err(SeedStorageError::Unavailable),
    }
}

pub(super) fn acquire_lifetime_lock(
    directory: &ProtectedDirectory,
) -> Result<LifetimeLockOpen, SeedStorageError> {
    let descriptor = SecurityDescriptor::new(FILE_SDDL)?;
    let file = match open_relative(
        &directory.file,
        CACHE_LOCK_FILE_NAME,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        Some(descriptor.as_ptr()),
    ) {
        RelativeOpen::File(file) => file,
        _ => return Err(SeedStorageError::Untrusted),
    };
    validate_regular_handle(&file, directory, CACHE_LOCK_FILE_NAME)?;
    if !dacl_is_protected(&file) {
        return Err(SeedStorageError::Untrusted);
    }
    apply_protected_dacl(&file, FILE_SDDL)?;
    let mut overlapped = OVERLAPPED::default();
    match unsafe {
        LockFileEx(
            HANDLE(file.as_raw_handle()),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            None,
            1,
            0,
            &raw mut overlapped,
        )
    } {
        Ok(()) => Ok(LifetimeLockOpen::Acquired(LifetimeLock { file })),
        Err(error)
            if error.code() == windows::core::HRESULT::from_win32(ERROR_LOCK_VIOLATION.0) =>
        {
            Ok(LifetimeLockOpen::Contended)
        }
        Err(_) => Err(SeedStorageError::Unavailable),
    }
}

pub(super) fn validate_lifetime_lock(
    directory: &ProtectedDirectory,
    lock: &LifetimeLock,
) -> Result<(), SeedStorageError> {
    validate_regular_handle(&lock.file, directory, CACHE_LOCK_FILE_NAME)?;
    if !dacl_is_protected(&lock.file) {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(())
}

pub(super) fn open_cache(directory: &ProtectedDirectory) -> Result<Option<File>, SeedStorageError> {
    match open_relative(
        &directory.file,
        CACHE_FILE_NAME,
        FILE_GENERIC_READ | READ_CONTROL,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
    ) {
        RelativeOpen::File(file) => {
            validate_regular_handle(&file, directory, CACHE_FILE_NAME)?;
            if !dacl_is_protected(&file) {
                return Err(SeedStorageError::Untrusted);
            }
            Ok(Some(file))
        }
        RelativeOpen::Missing => Ok(None),
        _ => Err(SeedStorageError::Untrusted),
    }
}

pub(super) fn create_cache_temporary(
    directory: &ProtectedDirectory,
    name: &str,
) -> Result<File, SeedStorageError> {
    if !valid_temporary_name(name) {
        return Err(SeedStorageError::Untrusted);
    }
    let descriptor = SecurityDescriptor::new(FILE_SDDL)?;
    match open_relative(
        &directory.file,
        name,
        FILE_GENERIC_READ
            | FILE_GENERIC_WRITE
            | FILE_WRITE_DATA
            | DELETE
            | READ_CONTROL
            | WRITE_DAC,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        Some(descriptor.as_ptr()),
    ) {
        RelativeOpen::File(file) => {
            validate_regular_handle(&file, directory, name)?;
            apply_protected_dacl(&file, FILE_SDDL)?;
            Ok(file)
        }
        _ => Err(SeedStorageError::Unavailable),
    }
}

pub(super) fn open_cache_temporary(
    directory: &ProtectedDirectory,
    name: &str,
) -> Result<File, SeedStorageError> {
    if !valid_temporary_name(name) {
        return Err(SeedStorageError::Untrusted);
    }
    match open_relative(
        &directory.file,
        name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | READ_CONTROL,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
    ) {
        RelativeOpen::File(file) => {
            validate_regular_handle(&file, directory, name)?;
            if !dacl_is_protected(&file) {
                return Err(SeedStorageError::Untrusted);
            }
            Ok(file)
        }
        _ => Err(SeedStorageError::Untrusted),
    }
}

pub(super) fn list_cache_temporaries(
    directory: &ProtectedDirectory,
) -> Result<Vec<String>, SeedStorageError> {
    let mut storage = vec![0_usize; 64 * 1024 / std::mem::size_of::<usize>()];
    let mut names = Vec::new();
    let mut visited = 0_usize;
    loop {
        let result = unsafe {
            GetFileInformationByHandleEx(
                HANDLE(directory.file.as_raw_handle()),
                FileIdBothDirectoryInfo,
                storage.as_mut_ptr().cast(),
                u32::try_from(storage.len() * std::mem::size_of::<usize>())
                    .map_err(|_| SeedStorageError::Unavailable)?,
            )
        };
        if let Err(error) = result {
            if error.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
                return Ok(names);
            }
            return Err(SeedStorageError::Unavailable);
        }

        let mut offset = 0_usize;
        loop {
            visited = visited
                .checked_add(1)
                .filter(|count| *count <= MAX_DIRECTORY_ENTRIES)
                .ok_or(SeedStorageError::Untrusted)?;
            let bytes = storage.len() * std::mem::size_of::<usize>();
            let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            if offset.checked_add(header).is_none_or(|end| end > bytes) {
                return Err(SeedStorageError::Untrusted);
            }
            let information = unsafe {
                &*storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FILE_ID_BOTH_DIR_INFO>()
            };
            let name_bytes = usize::try_from(information.FileNameLength)
                .map_err(|_| SeedStorageError::Untrusted)?;
            if name_bytes % std::mem::size_of::<u16>() != 0
                || offset
                    .checked_add(header)
                    .and_then(|start| start.checked_add(name_bytes))
                    .is_none_or(|end| end > bytes)
            {
                return Err(SeedStorageError::Untrusted);
            }
            let wide_name = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(information.FileName).cast::<u16>(),
                    name_bytes / std::mem::size_of::<u16>(),
                )
            };
            let prefix = CACHE_TEMPORARY_PREFIX.encode_utf16().collect::<Vec<_>>();
            if wide_name.starts_with(&prefix) {
                if names.len() == MAX_RECOVERY_TEMPORARIES {
                    return Err(SeedStorageError::Untrusted);
                }
                let name =
                    String::from_utf16(wide_name).map_err(|_| SeedStorageError::Untrusted)?;
                if !valid_temporary_name(&name) {
                    return Err(SeedStorageError::Untrusted);
                }
                names.push(name);
            }
            let next = usize::try_from(information.NextEntryOffset)
                .map_err(|_| SeedStorageError::Untrusted)?;
            if next == 0 {
                break;
            }
            if next < header || offset.checked_add(next).is_none_or(|next| next >= bytes) {
                return Err(SeedStorageError::Untrusted);
            }
            offset += next;
        }
    }
}

pub(super) fn replace_cache_temporary(
    directory: &ProtectedDirectory,
    temporary: &File,
    temporary_name: &str,
) -> Result<(), SeedStorageError> {
    if !valid_temporary_name(temporary_name) {
        return Err(SeedStorageError::Untrusted);
    }
    validate_regular_handle(temporary, directory, temporary_name)?;
    if !dacl_is_protected(temporary) {
        return Err(SeedStorageError::Untrusted);
    }
    let temporary_identity = handle_information(temporary)?;
    if let Some(existing) = open_cache(directory)? {
        drop(existing);
    }
    let destination = CACHE_FILE_NAME.encode_utf16().collect::<Vec<_>>();
    let byte_length = destination
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(SeedStorageError::Unavailable)?;
    let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
    let total = offset
        .checked_add(byte_length)
        .map(|length| length.max(std::mem::size_of::<FILE_RENAME_INFORMATION>()))
        .ok_or(SeedStorageError::Unavailable)?;
    let words = total
        .checked_add(std::mem::size_of::<usize>() - 1)
        .ok_or(SeedStorageError::Unavailable)?
        / std::mem::size_of::<usize>();
    let mut storage = vec![0_usize; words];
    let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    unsafe {
        (*information).Anonymous.Flags =
            FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
        (*information).RootDirectory = HANDLE(directory.file.as_raw_handle());
        (*information).FileNameLength =
            u32::try_from(byte_length).map_err(|_| SeedStorageError::Unavailable)?;
        std::ptr::copy_nonoverlapping(
            destination.as_ptr(),
            std::ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
            destination.len(),
        );
        // The Win32 wrapper rejects a non-null RootDirectory on supported
        // hosts. The native information class preserves the required
        // handle-relative rename instead of falling back to an absolute path.
        let mut status_block = IO_STATUS_BLOCK::default();
        let status = NtSetInformationFile(
            HANDLE(temporary.as_raw_handle()),
            &raw mut status_block,
            information.cast(),
            u32::try_from(total).map_err(|_| SeedStorageError::Unavailable)?,
            FileRenameInformationEx,
        );
        if status.0 < 0 {
            return Err(SeedStorageError::Unavailable);
        }
    }
    let installed = match open_cache(directory)? {
        Some(installed) => installed,
        None => return Err(SeedStorageError::Untrusted),
    };
    let installed_identity = handle_information(&installed)?;
    if file_identity(&temporary_identity) != file_identity(&installed_identity) {
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
    validate_regular_handle(file, directory, temporary_name)?;
    if !dacl_is_protected(file) {
        return Err(SeedStorageError::Untrusted);
    }
    let information = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0,
        ),
    };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfoEx,
            (&raw const information).cast(),
            u32::try_from(std::mem::size_of_val(&information))
                .map_err(|_| SeedStorageError::Unavailable)?,
        )
        .map_err(|_| SeedStorageError::Unavailable)
    }
}

pub(super) fn sync_directory(directory: &ProtectedDirectory) -> Result<(), SeedStorageError> {
    match directory.file.sync_all() {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(SeedStorageError::Unavailable),
    }
}

enum RelativeOpen {
    File(File),
    Missing,
    Busy,
    Collision,
    Failed,
}

fn open_relative(
    root: &File,
    name: &str,
    desired_access: FILE_ACCESS_RIGHTS,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: NTCREATEFILE_CREATE_OPTIONS,
    security_descriptor: Option<*const SECURITY_DESCRIPTOR>,
) -> RelativeOpen {
    let mut wide_name = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
    let Some(byte_length) = wide_name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
    else {
        return RelativeOpen::Failed;
    };
    let object_name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: PWSTR(wide_name.as_mut_ptr()),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: HANDLE(root.as_raw_handle()),
        ObjectName: &raw const object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security_descriptor.unwrap_or(std::ptr::null()),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = HANDLE::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    let share_access = if name == SEED_FILE_NAME && disposition == FILE_CREATE {
        FILE_SHARE_MODE(0)
    } else if name == CACHE_LOCK_FILE_NAME {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    };
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            desired_access,
            &raw const object_attributes,
            &raw mut status_block,
            None,
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            disposition,
            options,
            None,
            0,
        )
    };
    if status.0 >= 0 {
        return RelativeOpen::File(unsafe { File::from_raw_handle(handle.0) });
    }
    if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        RelativeOpen::Missing
    } else if status == STATUS_SHARING_VIOLATION {
        RelativeOpen::Busy
    } else if status == STATUS_OBJECT_NAME_COLLISION {
        RelativeOpen::Collision
    } else {
        RelativeOpen::Failed
    }
}

fn open_directory_path(path: &Path) -> Result<File, SeedStorageError> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .access_mode((FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL).0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0);
    options.open(path).map_err(|_| SeedStorageError::Untrusted)
}

fn validate_directory_handle(
    file: &File,
    expected: &Path,
    expected_parent: Option<&Path>,
) -> Result<u32, SeedStorageError> {
    let metadata = file.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    if !metadata.is_dir() {
        return Err(SeedStorageError::Untrusted);
    }
    let information = handle_information(file)?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SeedStorageError::Untrusted);
    }
    let final_path = final_handle_path(file)?;
    let canonical_expected = fs::canonicalize(expected)
        .map(normalize_canonical_path)
        .map_err(|_| SeedStorageError::Untrusted)?;
    if !paths_equal(&final_path, &canonical_expected)
        || expected_parent.is_some_and(|parent| {
            final_path
                .parent()
                .is_none_or(|actual| !paths_equal(actual, parent))
        })
        || windows_drive_is_remote(&final_path)
    {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(information.dwVolumeSerialNumber)
}

fn validate_seed_handle(
    file: &File,
    directory: &ProtectedDirectory,
) -> Result<(), SeedStorageError> {
    let metadata = file.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    let information = handle_information(file)?;
    let expected = directory.path.join(SEED_FILE_NAME);
    let final_path = final_handle_path(file)?;
    if !metadata.is_file()
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks != 1
        || information.dwVolumeSerialNumber != directory.volume
        || !paths_equal(&final_path, &expected)
        || final_path
            .parent()
            .is_none_or(|parent| !paths_equal(parent, &directory.path))
        || !owner_is_current_user(file)
    {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(())
}

fn validate_regular_handle(
    file: &File,
    directory: &ProtectedDirectory,
    name: &str,
) -> Result<(), SeedStorageError> {
    let metadata = file.metadata().map_err(|_| SeedStorageError::Untrusted)?;
    let information = handle_information(file)?;
    let expected = directory.path.join(name);
    let final_path = final_handle_path(file)?;
    if !metadata.is_file()
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.nNumberOfLinks != 1
        || information.dwVolumeSerialNumber != directory.volume
        || !paths_equal(&final_path, &expected)
        || final_path
            .parent()
            .is_none_or(|parent| !paths_equal(parent, &directory.path))
        || !owner_is_current_user(file)
    {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(())
}

fn file_identity(information: &BY_HANDLE_FILE_INFORMATION) -> (u32, u32, u32) {
    (
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    )
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

fn handle_information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, SeedStorageError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information)
            .map_err(|_| SeedStorageError::Untrusted)?;
    }
    Ok(information)
}

fn final_handle_path(file: &File) -> Result<PathBuf, SeedStorageError> {
    let mut buffer = vec![0_u16; 512];
    loop {
        let count = unsafe {
            GetFinalPathNameByHandleW(
                HANDLE(file.as_raw_handle()),
                &mut buffer,
                FILE_NAME_NORMALIZED,
            )
        } as usize;
        if count == 0 {
            return Err(SeedStorageError::Untrusted);
        }
        if count < buffer.len() {
            buffer.truncate(count);
            return Ok(normalize_canonical_path(PathBuf::from(
                std::ffi::OsString::from_wide(&buffer),
            )));
        }
        buffer.resize(count + 1, 0);
    }
}

fn normalize_canonical_path(path: PathBuf) -> PathBuf {
    const EXTENDED_PREFIX: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const UNC_PREFIX: [u16; 4] = [b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
    let value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.starts_with(&EXTENDED_PREFIX)
        && !value[EXTENDED_PREFIX.len()..].starts_with(&UNC_PREFIX)
    {
        PathBuf::from(std::ffi::OsString::from_wide(
            &value[EXTENDED_PREFIX.len()..],
        ))
    } else {
        path
    }
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    let left = left.as_os_str().encode_wide().collect::<Vec<_>>();
    let right = right.as_os_str().encode_wide().collect::<Vec<_>>();
    (unsafe { CompareStringOrdinal(&left, &right, true) }) == CSTR_EQUAL
}

fn is_remote_or_device_path(path: &Path) -> bool {
    let value = path
        .as_os_str()
        .encode_wide()
        .map(|unit| {
            if unit == b'/' as u16 {
                b'\\' as u16
            } else {
                unit
            }
        })
        .collect::<Vec<_>>();
    value.starts_with(&[b'\\' as u16, b'\\' as u16])
        || value.starts_with(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16])
        || value.starts_with(&[b'\\' as u16, b'.' as u16, b'\\' as u16])
        || value.starts_with(&[b'\\' as u16, b'?' as u16, b'\\' as u16])
        || windows_drive_is_remote(path)
}

fn validate_no_reparse_components(path: &Path) -> Result<(), SeedStorageError> {
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component).map_err(|_| SeedStorageError::Untrusted)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SeedStorageError::Untrusted);
        }
    }
    Ok(())
}

fn windows_drive_is_remote(path: &Path) -> bool {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.len() < 2 || units[1] != b':' as u16 {
        return true;
    }
    let root = [units[0], b':' as u16, b'\\' as u16, 0];
    const DRIVE_REMOTE: u32 = 4;
    (unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) }) == DRIVE_REMOTE
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn new(sddl: &str) -> Result<Self, SeedStorageError> {
        let sddl = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|_| SeedStorageError::Unavailable)?;
        Ok(Self(descriptor))
    }

    fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
        self.0.0.cast()
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn apply_protected_dacl(file: &File, sddl: &str) -> Result<(), SeedStorageError> {
    let descriptor = SecurityDescriptor::new(sddl)?;
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
        .map_err(|_| SeedStorageError::Unavailable)?;
    }
    if !present.as_bool() || dacl.is_null() {
        return Err(SeedStorageError::Unavailable);
    }
    let status = unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if status.0 != 0 {
        return Err(SeedStorageError::Unavailable);
    }
    Ok(())
}

fn dacl_is_protected(file: &File) -> bool {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if status.0 != 0 {
        return false;
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let result = unsafe {
        GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision).is_ok()
    } && control & SE_DACL_PROTECTED.0 != 0;
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    result
}

fn owner_is_current_user(file: &File) -> bool {
    const MAX_TOKEN_USER_BYTES: usize = 64 * 1024;

    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }

    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let token = TokenHandle(token);
    let mut required = 0_u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &raw mut required) };
    let Ok(required_bytes) = usize::try_from(required) else {
        return false;
    };
    if required_bytes < std::mem::size_of::<TOKEN_USER>() || required_bytes > MAX_TOKEN_USER_BYTES {
        return false;
    }
    let words = match required_bytes.checked_add(std::mem::size_of::<usize>() - 1) {
        Some(bytes) => bytes / std::mem::size_of::<usize>(),
        None => return false,
    };
    let mut token_storage = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(token_storage.as_mut_ptr().cast()),
            match u32::try_from(token_storage.len() * std::mem::size_of::<usize>()) {
                Ok(length) => length,
                Err(_) => return false,
            },
            &raw mut required,
        )
    }
    .is_err()
    {
        return false;
    }
    let current_user = unsafe { &*token_storage.as_ptr().cast::<TOKEN_USER>() };

    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if status.0 != 0 || owner.is_invalid() || descriptor.is_invalid() {
        if !descriptor.is_invalid() {
            let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        }
        return false;
    }
    let matches = unsafe { EqualSid(owner, current_user.User.Sid) }.is_ok();
    let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    matches
}

#[cfg(test)]
pub(crate) fn dacl_is_protected_for_test(path: &Path) -> bool {
    open_directory_path(path)
        .or_else(|_| {
            let mut options = fs::OpenOptions::new();
            options
                .read(true)
                .access_mode((FILE_GENERIC_READ | READ_CONTROL).0)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
            options.open(path).map_err(|_| SeedStorageError::Untrusted)
        })
        .is_ok_and(|file| dacl_is_protected(&file))
}
