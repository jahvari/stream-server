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
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NTCREATEFILE_CREATE_DISPOSITION,
            NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
        },
    },
    Win32::{
        Foundation::{
            HANDLE, HLOCAL, LocalFree, OBJ_CASE_INSENSITIVE, STATUS_OBJECT_NAME_COLLISION,
            STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_SHARING_VIOLATION,
            UNICODE_STRING,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
            SECURITY_DESCRIPTOR,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_NORMAL,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_MODE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, GetDriveTypeW,
            GetFileInformationByHandle, GetFinalPathNameByHandleW, READ_CONTROL, WRITE_DAC,
        },
        System::IO::IO_STATUS_BLOCK,
    },
    core::{PCWSTR, PWSTR},
};

const STORAGE_DIRECTORY_NAME: &str = "transcoding";
const SEED_FILE_NAME: &str = "device-id.key";
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
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        None,
    ) {
        RelativeOpen::File(file) => {
            if !dacl_is_protected(&file) {
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
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                Some(descriptor.as_ptr()),
            ) {
                RelativeOpen::File(file) => file,
                RelativeOpen::Collision => match open_relative(
                    &config,
                    STORAGE_DIRECTORY_NAME,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                    None,
                ) {
                    RelativeOpen::File(file) if dacl_is_protected(&file) => file,
                    _ => return Err(SeedStorageError::Untrusted),
                },
                _ => return Err(SeedStorageError::Unavailable),
            }
        }
        _ => return Err(SeedStorageError::Untrusted),
    };
    let volume = validate_directory_handle(&root, &expected, Some(&canonical_config))?;
    if !dacl_is_protected(&root) {
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
        || expected_parent.is_some_and(|parent| final_path.parent() != Some(parent))
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
        || final_path.parent() != Some(directory.path.as_path())
    {
        return Err(SeedStorageError::Untrusted);
    }
    Ok(())
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
    let value = path.as_os_str().to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .filter(|local| !local.starts_with("UNC\\"))
        .map(PathBuf::from)
        .unwrap_or(path)
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn is_remote_or_device_path(path: &Path) -> bool {
    let value = path.as_os_str().to_string_lossy().replace('/', "\\");
    value.starts_with("\\\\")
        || value.starts_with("\\??\\")
        || value.starts_with("\\.\\")
        || value.starts_with("\\?\\")
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
