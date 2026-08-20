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
        fs::create_dir_all(config_dir).with_context(|| {
            format!("failed to create config directory {}", config_dir.display())
        })?;
        let path = config_dir.join(TOKEN_FILE_NAME);
        match create_token_file(&path) {
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
    validate_token_metadata(path)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_TOKEN_FILE_LENGTH {
        bail!("settings control token file is oversized");
    }
    let bytes = fs::read(path)?;
    parse_token_bytes(&bytes)
}

fn validate_token_metadata(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect settings control token {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("settings control token must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("settings control token permissions must be 0600");
        }
    }
    Ok(())
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
}
