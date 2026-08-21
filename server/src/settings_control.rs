use anyhow::{Context, bail};
use axum::http::HeaderMap;
use std::{
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub(crate) const SETTINGS_TOKEN_HEADER: &str = "x-stream-server-settings-token";
const TOKEN_FILE_NAME: &str = "settings-control.token";
const TOKEN_LENGTH: usize = 64;
const MAX_TOKEN_FILE_LENGTH: u64 = 66;

#[derive(Clone)]
pub(crate) struct SettingsControl {
    token: Arc<[u8; TOKEN_LENGTH]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SettingsMutationAuthority {
    TrustedLocal,
    HttpAuthorized,
    Untrusted,
}

impl SettingsControl {
    pub(crate) fn load_or_create(config_dir: &Path) -> anyhow::Result<Self> {
        Self::load_or_create_with(config_dir, create_token_file)
    }

    fn load_or_create_with<F>(config_dir: &Path, create: F) -> anyhow::Result<Self>
    where
        F: FnOnce(&Path) -> io::Result<[u8; TOKEN_LENGTH]>,
    {
        Self::load_or_create_with_hooks(config_dir, create, || {})
    }

    fn load_or_create_with_hooks<F, H>(
        config_dir: &Path,
        create: F,
        before_existing_load: H,
    ) -> anyhow::Result<Self>
    where
        F: FnOnce(&Path) -> io::Result<[u8; TOKEN_LENGTH]>,
        H: FnOnce(),
    {
        fs::create_dir_all(config_dir).with_context(|| {
            format!("failed to create config directory {}", config_dir.display())
        })?;
        let path = config_dir.join(TOKEN_FILE_NAME);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                before_existing_load();
                let token = load_token_file(&path)?;
                return Ok(Self {
                    token: Arc::new(token),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect settings control token {}",
                        path.display()
                    )
                });
            }
        }
        match create(&path) {
            Ok(token) => Ok(Self {
                token: Arc::new(token),
            }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let token = load_token_file(&path)?;
                Ok(Self {
                    token: Arc::new(token),
                })
            }
            Err(error) => Err(error).with_context(|| {
                format!("failed to create settings control token {}", path.display())
            }),
        }
    }

    pub(crate) fn authorize_http(
        &self,
        peer: SocketAddr,
        headers: &HeaderMap,
    ) -> SettingsMutationAuthority {
        if !is_loopback(peer.ip()) {
            return SettingsMutationAuthority::Untrusted;
        }
        let Some(candidate) = headers.get(SETTINGS_TOKEN_HEADER) else {
            return SettingsMutationAuthority::Untrusted;
        };
        let candidate = candidate.as_bytes();
        if candidate.len() != TOKEN_LENGTH {
            return SettingsMutationAuthority::Untrusted;
        }
        if bool::from(candidate.ct_eq(self.token.as_ref())) {
            SettingsMutationAuthority::HttpAuthorized
        } else {
            SettingsMutationAuthority::Untrusted
        }
    }

    pub(crate) fn ephemeral() -> Self {
        let raw = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let token = raw
            .as_bytes()
            .try_into()
            .expect("two simple UUIDs are exactly 64 bytes");
        Self {
            token: Arc::new(token),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(token: [u8; TOKEN_LENGTH]) -> Self {
        Self {
            token: Arc::new(token),
        }
    }
}

fn is_loopback(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_loopback(),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.is_loopback(), |mapped| mapped.is_loopback()),
    }
}

fn create_token_file(path: &Path) -> io::Result<[u8; TOKEN_LENGTH]> {
    let raw = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let token: [u8; TOKEN_LENGTH] = raw
        .as_bytes()
        .try_into()
        .expect("two simple UUIDs are exactly 64 bytes");

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("settings control token path has no parent"))?;
    let mut file = tempfile::Builder::new()
        .prefix(".settings-control-token-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&token)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map(|_| token)
        .map_err(|error| error.error)
}

fn load_token_file(path: &Path) -> anyhow::Result<[u8; TOKEN_LENGTH]> {
    load_token_file_with_after_open(path, || {})
}

fn load_token_file_with_after_open<F>(
    path: &Path,
    after_open: F,
) -> anyhow::Result<[u8; TOKEN_LENGTH]>
where
    F: FnOnce(),
{
    let bytes = crate::safe_file::read_regular_file_no_follow(
        path,
        MAX_TOKEN_FILE_LENGTH,
        Some(0o600),
        after_open,
    )?;
    parse_token_bytes(&bytes)
}

fn parse_token_bytes(bytes: &[u8]) -> anyhow::Result<[u8; TOKEN_LENGTH]> {
    let token = match bytes {
        [token @ .., b'\n'] if token.len() == TOKEN_LENGTH => token,
        [token @ .., b'\r', b'\n'] if token.len() == TOKEN_LENGTH => token,
        token if token.len() == TOKEN_LENGTH => token,
        _ => bail!("settings control token has invalid length or line ending"),
    };
    if !token
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        bail!("settings control token must be lowercase hexadecimal");
    }
    Ok(token.try_into().expect("token length was validated"))
}

#[cfg(test)]
mod tests {
    use super::{
        SETTINGS_TOKEN_HEADER, SettingsControl, SettingsMutationAuthority, parse_token_bytes,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use std::{fs, net::SocketAddr};

    fn headers_with(value: &[u8]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            SETTINGS_TOKEN_HEADER,
            HeaderValue::from_bytes(value).unwrap(),
        );
        headers
    }

    #[test]
    fn valid_token_requires_a_loopback_peer() {
        let control = SettingsControl::for_test([b'a'; 64]);
        let headers = headers_with(&[b'a'; 64]);
        assert_eq!(
            control.authorize_http(
                "192.168.1.50:40000".parse::<SocketAddr>().unwrap(),
                &headers,
            ),
            SettingsMutationAuthority::Untrusted
        );
        assert_eq!(
            control.authorize_http("127.0.0.1:40000".parse::<SocketAddr>().unwrap(), &headers,),
            SettingsMutationAuthority::HttpAuthorized
        );
        assert_eq!(
            control.authorize_http("[::1]:40000".parse::<SocketAddr>().unwrap(), &headers),
            SettingsMutationAuthority::HttpAuthorized
        );
        assert_eq!(
            control.authorize_http(
                "[::ffff:127.0.0.1]:40000".parse::<SocketAddr>().unwrap(),
                &headers,
            ),
            SettingsMutationAuthority::HttpAuthorized
        );
    }

    #[test]
    fn missing_wrong_or_wrong_length_token_is_untrusted() {
        let control = SettingsControl::for_test([b'a'; 64]);
        let peer = "127.0.0.1:40000".parse().unwrap();
        assert_eq!(
            control.authorize_http(peer, &HeaderMap::new()),
            SettingsMutationAuthority::Untrusted
        );
        for value in [&[b'b'; 64][..], &[b'a'; 63][..], &[b'a'; 65][..]] {
            assert_eq!(
                control.authorize_http(peer, &headers_with(value)),
                SettingsMutationAuthority::Untrusted
            );
        }
    }

    #[test]
    fn token_file_syntax_is_exact_and_allows_one_line_ending() {
        let token = [b'a'; 64];
        assert_eq!(parse_token_bytes(&token).unwrap(), token);
        assert_eq!(
            parse_token_bytes(&[&token[..], b"\n"].concat()).unwrap(),
            token
        );
        assert_eq!(
            parse_token_bytes(&[&token[..], b"\r\n"].concat()).unwrap(),
            token
        );

        for invalid in [
            Vec::new(),
            vec![b'a'; 63],
            vec![b'a'; 65],
            vec![b'A'; 64],
            [&token[..], b" \n"].concat(),
            [&token[..], b"\n\n"].concat(),
            [b" ".as_slice(), &token[..]].concat(),
        ] {
            assert!(parse_token_bytes(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn token_is_created_once_and_reloaded_stably() {
        let temp = tempfile::tempdir().unwrap();
        let first = SettingsControl::load_or_create(temp.path()).unwrap();
        let bytes = fs::read(temp.path().join("settings-control.token")).unwrap();
        assert_eq!(bytes.len(), 64);
        assert!(bytes.iter().all(u8::is_ascii_hexdigit));
        assert!(bytes.iter().all(|byte| !byte.is_ascii_uppercase()));

        let second = SettingsControl::load_or_create(temp.path()).unwrap();
        let headers = headers_with(&bytes);
        let peer = "127.0.0.1:40000".parse().unwrap();
        assert_eq!(
            first.authorize_http(peer, &headers),
            SettingsMutationAuthority::HttpAuthorized
        );
        assert_eq!(
            second.authorize_http(peer, &headers),
            SettingsMutationAuthority::HttpAuthorized
        );
    }

    #[test]
    fn an_existing_valid_token_is_loaded_without_attempting_creation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        fs::write(&path, [b'a'; 64]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let creation_attempted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = creation_attempted.clone();

        let control = SettingsControl::load_or_create_with(temp.path(), move |_| {
            observed.store(true, std::sync::atomic::Ordering::Release);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "creation must not be attempted",
            ))
        })
        .unwrap();

        assert!(!creation_attempted.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(
            control.authorize_http(
                "127.0.0.1:40000".parse().unwrap(),
                &headers_with(&[b'a'; 64]),
            ),
            SettingsMutationAuthority::HttpAuthorized
        );
    }

    #[test]
    fn token_bytes_are_read_from_the_validated_handle_after_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        let replacement = temp.path().join("replacement.token");
        let original_moved = temp.path().join("original.token");
        fs::write(&path, [b'a'; 64]).unwrap();
        fs::write(&replacement, [b'b'; 64]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let token = super::load_token_file_with_after_open(&path, || {
            fs::rename(&path, &original_moved).unwrap();
            fs::rename(&replacement, &path).unwrap();
        })
        .unwrap();

        assert_eq!(token, [b'a'; 64]);
        assert_eq!(fs::read(path).unwrap(), [b'b'; 64]);
    }

    #[test]
    fn concurrent_token_creation_observes_only_a_complete_winner() {
        let temp = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let path = temp.path().to_owned();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                SettingsControl::load_or_create(&path).unwrap()
            }));
        }
        let controls: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        let bytes = fs::read(temp.path().join("settings-control.token")).unwrap();
        assert_eq!(bytes.len(), 64);
        let headers = headers_with(&bytes);
        let peer = "127.0.0.1:40000".parse().unwrap();
        for control in controls {
            assert_eq!(
                control.authorize_http(peer, &headers),
                SettingsMutationAuthority::HttpAuthorized
            );
        }
    }

    #[test]
    fn existing_non_regular_or_invalid_token_is_never_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        fs::create_dir(&path).unwrap();
        assert!(SettingsControl::load_or_create(temp.path()).is_err());
        assert!(path.is_dir());

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        fs::write(&path, b"not-a-token").unwrap();
        assert!(SettingsControl::load_or_create(temp.path()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"not-a-token");
    }

    #[test]
    fn oversized_token_is_rejected_without_truncation_or_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        let oversized = vec![b'a'; super::MAX_TOKEN_FILE_LENGTH as usize + 1];
        fs::write(&path, &oversized).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(SettingsControl::load_or_create(temp.path()).is_err());
        assert_eq!(fs::read(path).unwrap(), oversized);
    }

    #[cfg(unix)]
    #[test]
    fn unix_token_symlinks_fifos_and_broad_permissions_are_rejected() {
        use std::os::{unix::ffi::OsStrExt, unix::fs::PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.token");
        fs::write(&target, [b'a'; 64]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let path = temp.path().join("settings-control.token");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(SettingsControl::load_or_create(temp.path()).is_err());
        assert_eq!(fs::read(&target).unwrap(), [b'a'; 64]);

        fs::remove_file(&path).unwrap();
        let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path_bytes.as_ptr(), 0o600) }, 0);
        assert!(SettingsControl::load_or_create(temp.path()).is_err());

        fs::remove_file(&path).unwrap();
        fs::write(&path, [b'a'; 64]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(SettingsControl::load_or_create(temp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unix_existing_token_preopen_swaps_cannot_follow_symlinks_or_block_on_fifos() {
        use std::os::{unix::ffi::OsStrExt, unix::fs::PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        let target = temp.path().join("target.token");
        fs::write(&path, [b'a'; 64]).unwrap();
        fs::write(&target, [b'b'; 64]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let path_for_swap = path.clone();
        let target_for_swap = target.clone();
        assert!(
            SettingsControl::load_or_create_with_hooks(
                temp.path(),
                |_| panic!("existing token must not create"),
                move || {
                    fs::remove_file(&path_for_swap).unwrap();
                    std::os::unix::fs::symlink(&target_for_swap, &path_for_swap).unwrap();
                },
            )
            .is_err()
        );
        assert_eq!(fs::read(&target).unwrap(), [b'b'; 64]);

        fs::remove_file(&path).unwrap();
        fs::write(&path, [b'a'; 64]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let path_for_swap = path.clone();
        assert!(
            SettingsControl::load_or_create_with_hooks(
                temp.path(),
                |_| panic!("existing token must not create"),
                move || {
                    fs::remove_file(&path_for_swap).unwrap();
                    let bytes =
                        std::ffi::CString::new(path_for_swap.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(bytes.as_ptr(), 0o600) }, 0);
                },
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_token_reloads_from_a_nonwritable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings-control.token");
        fs::write(&path, [b'a'; 64]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = SettingsControl::load_or_create(temp.path());
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_ok());
    }
}
