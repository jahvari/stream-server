use anyhow::{Context, bail};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

pub(crate) fn read_regular_file_no_follow<F>(
    path: &Path,
    maximum_length: u64,
    required_unix_mode: Option<u32>,
    after_open: F,
) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(),
{
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    read_validated_handle(file, path, maximum_length, required_unix_mode, after_open)
}

fn read_validated_handle<F>(
    file: File,
    path: &Path,
    maximum_length: u64,
    required_unix_mode: Option<u32>,
    after_open: F,
) -> anyhow::Result<Vec<u8>>
where
    F: FnOnce(),
{
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("file must be a regular non-symlink file");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("file must be a regular non-reparse-point file");
        }
    }
    #[cfg(unix)]
    if let Some(required_mode) = required_unix_mode {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != required_mode {
            bail!("file permissions do not match the required mode");
        }
    }
    #[cfg(not(unix))]
    let _ = required_unix_mode;

    if metadata.len() > maximum_length {
        bail!("file is oversized");
    }
    after_open();

    let read_limit = maximum_length
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("file length limit is too large"))?;
    let mut bytes = Vec::with_capacity(read_limit.min(8192) as usize);
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_length {
        bail!("file is oversized");
    }
    Ok(bytes)
}
