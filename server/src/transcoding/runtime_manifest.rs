use serde::Deserialize;
use std::{collections::BTreeSet, fmt, path::Path};
use url::Url;

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const JELLYFIN_GITHUB_HOST: &str = "github.com";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeManifest {
    entries: Vec<RuntimeArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeArtifact {
    ffmpeg_version: String,
    jellyfin_revision: String,
    url: Url,
    sha256: String,
    max_bytes: u64,
    required_paths: Vec<RelativeArchivePath>,
    version_matchers: VersionOutputMatchers,
    license_url: Url,
    source_url: Url,
    source_tag: String,
    minimum_platform: MinimumPlatform,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionOutputMatchers {
    ffmpeg: String,
    ffprobe: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimumPlatform {
    windows: WindowsMinimumPlatform,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsMinimumPlatform {
    minimum_operating_system_version: PeVersion,
    minimum_subsystem_version: PeVersion,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeVersion {
    major: u16,
    minor: u16,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelativeArchivePath(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeHost {
    WindowsX64,
    LinuxX64,
    MacOsArm64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    InvalidManifest(&'static str),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(reason) => write!(f, "invalid runtime manifest: {reason}"),
        }
    }
}
impl std::error::Error for RuntimeError {}

impl RuntimeManifest {
    pub fn embedded() -> Result<Self, RuntimeError> {
        Self::from_json(include_str!(
            "../../resources/jellyfin-ffmpeg-manifest.json"
        ))
    }

    pub(crate) fn from_json(document: &str) -> Result<Self, RuntimeError> {
        let raw: RawManifest = serde_json::from_str(document)
            .map_err(|_| RuntimeError::InvalidManifest("malformed or unknown manifest field"))?;
        if raw.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(RuntimeError::InvalidManifest("unsupported schema version"));
        }
        let mut hosts = BTreeSet::new();
        let mut entries = Vec::with_capacity(raw.entries.len());
        for raw_entry in raw.entries {
            if !hosts.insert(format!("{}:{}", raw_entry.platform, raw_entry.arch)) {
                return Err(RuntimeError::InvalidManifest(
                    "duplicate platform and architecture",
                ));
            }
            entries.push(RuntimeArtifact::try_from(raw_entry)?);
        }
        if entries.is_empty() {
            return Err(RuntimeError::InvalidManifest("no artifacts"));
        }
        Ok(Self { entries })
    }

    pub fn artifact_for_host(&self, host: RuntimeHost) -> Option<&RuntimeArtifact> {
        self.entries.iter().find(|artifact| artifact.for_host(host))
    }
    pub fn artifacts(&self) -> &[RuntimeArtifact] {
        &self.entries
    }
}

impl RuntimeArtifact {
    pub fn for_host(&self, host: RuntimeHost) -> bool {
        matches!(host, RuntimeHost::WindowsX64)
    }
    pub fn ffmpeg_version(&self) -> &str {
        &self.ffmpeg_version
    }
    pub fn jellyfin_revision(&self) -> &str {
        &self.jellyfin_revision
    }
    pub fn url(&self) -> &Url {
        &self.url
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
    pub fn required_paths(&self) -> &[RelativeArchivePath] {
        &self.required_paths
    }
    pub fn version_matchers(&self) -> &VersionOutputMatchers {
        &self.version_matchers
    }
    pub fn license_url(&self) -> &Url {
        &self.license_url
    }
    pub fn source_url(&self) -> &Url {
        &self.source_url
    }
    pub fn source_tag(&self) -> &str {
        &self.source_tag
    }
    pub fn minimum_platform(&self) -> &MinimumPlatform {
        &self.minimum_platform
    }
}
impl VersionOutputMatchers {
    pub fn ffmpeg(&self) -> &str {
        &self.ffmpeg
    }
    pub fn ffprobe(&self) -> &str {
        &self.ffprobe
    }
}
impl MinimumPlatform {
    pub fn windows(&self) -> &WindowsMinimumPlatform {
        &self.windows
    }
}
impl WindowsMinimumPlatform {
    pub fn minimum_operating_system_version(&self) -> PeVersion {
        self.minimum_operating_system_version
    }
    pub fn minimum_subsystem_version(&self) -> PeVersion {
        self.minimum_subsystem_version
    }
}
impl PeVersion {
    pub fn major(&self) -> u16 {
        self.major
    }
    pub fn minor(&self) -> u16 {
        self.minor
    }
    fn is_set(self) -> bool {
        self.major != 0 || self.minor != 0
    }
}
impl RelativeArchivePath {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl TryFrom<RawArtifact> for RuntimeArtifact {
    type Error = RuntimeError;
    fn try_from(raw: RawArtifact) -> Result<Self, Self::Error> {
        if raw.platform != "windows" || raw.arch != "x86_64" {
            return Err(RuntimeError::InvalidManifest(
                "unsupported platform or architecture",
            ));
        }
        if !is_release_version(&raw.ffmpeg_version) || !is_decimal(&raw.jellyfin_revision) {
            return Err(RuntimeError::InvalidManifest(
                "invalid Jellyfin version or revision",
            ));
        }
        let expected_source_tag = format!("v{}-{}", raw.ffmpeg_version, raw.jellyfin_revision);
        if raw.source_tag != expected_source_tag {
            return Err(RuntimeError::InvalidManifest(
                "source tag does not match release identity",
            ));
        }
        let url = parse_github_url(&raw.url)?;
        let expected_release_path = format!(
            "/jellyfin/jellyfin-ffmpeg/releases/download/{}/jellyfin-ffmpeg_{}-{}_portable_win64-clang-gpl.zip",
            raw.source_tag, raw.ffmpeg_version, raw.jellyfin_revision
        );
        if url.path() != expected_release_path {
            return Err(RuntimeError::InvalidManifest(
                "unexpected Jellyfin release URL",
            ));
        }
        if !is_lowercase_sha256(&raw.sha256) {
            return Err(RuntimeError::InvalidManifest("invalid SHA-256"));
        }
        if raw.max_bytes == 0 || raw.max_bytes > MAX_ARCHIVE_BYTES {
            return Err(RuntimeError::InvalidManifest("invalid archive byte bound"));
        }
        let required_paths = validate_required_paths(raw.required_paths)?;
        for required in ["ffmpeg.exe", "ffprobe.exe"] {
            if !required_paths.iter().any(|path| path.as_str() == required) {
                return Err(RuntimeError::InvalidManifest("required executable missing"));
            }
        }
        let expected_version_matcher = format!("{}-Jellyfin", raw.ffmpeg_version);
        let version_matchers = VersionOutputMatchers {
            ffmpeg: validate_release_version_matcher(
                raw.version_matchers.ffmpeg,
                &expected_version_matcher,
            )?,
            ffprobe: validate_release_version_matcher(
                raw.version_matchers.ffprobe,
                &expected_version_matcher,
            )?,
        };
        let license_url = parse_github_url(&raw.license_url)?;
        if license_url.path()
            != format!("/jellyfin/jellyfin-ffmpeg/blob/{}/LICENSE", raw.source_tag)
        {
            return Err(RuntimeError::InvalidManifest("unexpected license URL"));
        }
        let source_url = parse_github_url(&raw.source_url)?;
        if source_url.path() != format!("/jellyfin/jellyfin-ffmpeg/tree/{}", raw.source_tag) {
            return Err(RuntimeError::InvalidManifest("unexpected source URL"));
        }
        let minimum_platform = MinimumPlatform {
            windows: WindowsMinimumPlatform {
                minimum_operating_system_version: PeVersion {
                    major: raw
                        .minimum_platform
                        .windows
                        .minimum_operating_system_version
                        .major,
                    minor: raw
                        .minimum_platform
                        .windows
                        .minimum_operating_system_version
                        .minor,
                },
                minimum_subsystem_version: PeVersion {
                    major: raw.minimum_platform.windows.minimum_subsystem_version.major,
                    minor: raw.minimum_platform.windows.minimum_subsystem_version.minor,
                },
            },
        };
        if !minimum_platform
            .windows
            .minimum_operating_system_version
            .is_set()
            || !minimum_platform.windows.minimum_subsystem_version.is_set()
        {
            return Err(RuntimeError::InvalidManifest(
                "invalid minimum platform version",
            ));
        }
        Ok(Self {
            ffmpeg_version: raw.ffmpeg_version,
            jellyfin_revision: raw.jellyfin_revision,
            url,
            sha256: raw.sha256,
            max_bytes: raw.max_bytes,
            required_paths,
            version_matchers,
            license_url,
            source_url,
            source_tag: raw.source_tag,
            minimum_platform,
        })
    }
}

fn parse_github_url(value: &str) -> Result<Url, RuntimeError> {
    let url = Url::parse(value).map_err(|_| RuntimeError::InvalidManifest("invalid HTTPS URL"))?;
    if url.scheme() != "https"
        || url.host_str() != Some(JELLYFIN_GITHUB_HOST)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RuntimeError::InvalidManifest("untrusted URL"));
    }
    Ok(url)
}
fn is_release_version(value: &str) -> bool {
    let components = value.split('.');
    components.clone().all(is_decimal) && components.count() == 3
}
fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte <= b'f'))
}
fn validate_release_version_matcher(value: String, expected: &str) -> Result<String, RuntimeError> {
    if value != expected {
        return Err(RuntimeError::InvalidManifest("invalid version matcher"));
    }
    Ok(value)
}
fn validate_required_paths(paths: Vec<String>) -> Result<Vec<RelativeArchivePath>, RuntimeError> {
    if paths.is_empty() {
        return Err(RuntimeError::InvalidManifest("no required archive paths"));
    }
    let mut normalized = BTreeSet::new();
    for path in &paths {
        if !normalized.insert(normalize_archive_path(path)?) {
            return Err(RuntimeError::InvalidManifest(
                "duplicate or colliding archive path",
            ));
        }
    }
    Ok(normalized.into_iter().collect())
}
fn normalize_archive_path(path: &str) -> Result<RelativeArchivePath, RuntimeError> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || !path.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(RuntimeError::InvalidManifest("unsafe archive path"));
    }
    let mut normalized = Vec::new();
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with('.')
            || component.ends_with(' ')
            || is_windows_device_name(component)
        {
            return Err(RuntimeError::InvalidManifest("unsafe archive path"));
        }
        normalized.push(component.to_ascii_lowercase());
    }
    let normalized = normalized.join("/");
    if normalized.ends_with(".lnk") {
        return Err(RuntimeError::InvalidManifest("link archive path"));
    }
    Ok(RelativeArchivePath(normalized))
}
fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawManifest {
    schema_version: u32,
    entries: Vec<RawArtifact>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawArtifact {
    platform: String,
    arch: String,
    ffmpeg_version: String,
    jellyfin_revision: String,
    url: String,
    sha256: String,
    max_bytes: u64,
    required_paths: Vec<String>,
    version_matchers: RawVersionOutputMatchers,
    license_url: String,
    source_url: String,
    source_tag: String,
    minimum_platform: RawMinimumPlatform,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawVersionOutputMatchers {
    ffmpeg: String,
    ffprobe: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawMinimumPlatform {
    windows: RawWindowsMinimumPlatform,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawWindowsMinimumPlatform {
    minimum_operating_system_version: RawPeVersion,
    minimum_subsystem_version: RawPeVersion,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawPeVersion {
    major: u16,
    minor: u16,
}

#[cfg(test)]
mod tests {
    use super::{RelativeArchivePath, RuntimeHost, RuntimeManifest};
    use serde_json::{Value, json};
    use std::path::Path;

    fn manifest() -> Value {
        json!({ "schemaVersion": 1, "entries": [{
            "platform": "windows", "arch": "x86_64", "ffmpegVersion": "7.1.4", "jellyfinRevision": "3",
            "url": "https://github.com/jellyfin/jellyfin-ffmpeg/releases/download/v7.1.4-3/jellyfin-ffmpeg_7.1.4-3_portable_win64-clang-gpl.zip",
            "sha256": "113adeb702683c38be40a65d859f8ef7ffb07bae9df16dfb6c3df5ac3d95ef3c", "maxBytes": 60257737,
            "requiredPaths": ["ffmpeg.exe", "ffprobe.exe"], "versionMatchers": { "ffmpeg": "7.1.4-Jellyfin", "ffprobe": "7.1.4-Jellyfin" },
            "licenseUrl": "https://github.com/jellyfin/jellyfin-ffmpeg/blob/v7.1.4-3/LICENSE", "sourceUrl": "https://github.com/jellyfin/jellyfin-ffmpeg/tree/v7.1.4-3", "sourceTag": "v7.1.4-3",
            "minimumPlatform": { "windows": { "minimumOperatingSystemVersion": { "major": 6, "minor": 0 }, "minimumSubsystemVersion": { "major": 6, "minor": 0 } } }
        }]})
    }
    fn parse(value: Value) -> Result<RuntimeManifest, super::RuntimeError> {
        RuntimeManifest::from_json(&serde_json::to_string(&value).unwrap())
    }

    #[test]
    fn rejects_an_unknown_schema_version() {
        let mut value = manifest();
        value["schemaVersion"] = json!(2);
        assert!(parse(value).is_err());
    }
    #[test]
    fn rejects_unknown_fields_at_each_schema_level() {
        for (path, value) in [
            (vec!["unexpected"], json!(true)),
            (vec!["entries", "0", "unexpected"], json!(true)),
            (
                vec!["entries", "0", "versionMatchers", "unexpected"],
                json!(true),
            ),
            (
                vec![
                    "entries",
                    "0",
                    "minimumPlatform",
                    "windows",
                    "minimumOperatingSystemVersion",
                    "unexpected",
                ],
                json!(true),
            ),
        ] {
            let mut document = manifest();
            let mut current = &mut document;
            for segment in &path[..path.len() - 1] {
                current = if let Ok(index) = segment.parse::<usize>() {
                    &mut current[index]
                } else {
                    &mut current[segment]
                };
            }
            current[path.last().unwrap()] = value;
            assert!(parse(document).is_err(), "accepted {path:?}");
        }
    }
    #[test]
    fn rejects_duplicate_platform_architecture_entries() {
        let mut value = manifest();
        value["entries"]
            .as_array_mut()
            .unwrap()
            .push(manifest()["entries"][0].clone());
        assert!(parse(value).is_err());
    }
    #[test]
    fn rejects_untrusted_or_non_https_artifact_urls() {
        for url in [
            "http://github.com/jellyfin/jellyfin-ffmpeg/releases/download/v7.1.4-3/runtime.zip",
            "https://github.com.evil.example/runtime.zip",
        ] {
            let mut value = manifest();
            value["entries"][0]["url"] = json!(url);
            assert!(parse(value).is_err(), "accepted {url}");
        }
    }
    #[test]
    fn rejects_digest_that_is_not_lowercase_sha256() {
        for digest in [
            "abc",
            "113ADEB702683C38BE40A65D859F8EF7FFB07BAE9DF16DFB6C3DF5AC3D95EF3C",
        ] {
            let mut value = manifest();
            value["entries"][0]["sha256"] = json!(digest);
            assert!(parse(value).is_err(), "accepted {digest}");
        }
    }
    #[test]
    fn rejects_version_matchers_that_do_not_pin_the_declared_release() {
        let mut value = manifest();
        value["entries"][0]["versionMatchers"]["ffmpeg"] = json!("7.1.3-Jellyfin");
        assert!(parse(value).is_err());
    }
    #[test]
    fn rejects_an_archive_bound_above_512_mib() {
        let mut value = manifest();
        value["entries"][0]["maxBytes"] = json!(536_870_913_u64);
        assert!(parse(value).is_err());
    }
    #[test]
    fn rejects_duplicate_or_case_colliding_required_paths() {
        for paths in [
            json!(["ffmpeg.exe", "ffprobe.exe", "ffmpeg.exe"]),
            json!(["ffmpeg.exe", "ffprobe.exe", "FFMPEG.EXE"]),
        ] {
            let mut value = manifest();
            value["entries"][0]["requiredPaths"] = paths;
            assert!(parse(value).is_err());
        }
    }
    #[test]
    fn rejects_required_path_hazards() {
        for path in [
            "bin/../ffmpeg.exe",
            "/ffmpeg.exe",
            "C:/ffmpeg.exe",
            "ffmpeg.exe:payload",
            "CON",
            "ffmpeg.lnk",
            "bin//ffmpeg.exe",
            "bin/",
        ] {
            let mut value = manifest();
            value["entries"][0]["requiredPaths"] = json!(["ffmpeg.exe", "ffprobe.exe", path]);
            assert!(parse(value).is_err(), "accepted {path}");
        }
    }
    #[test]
    fn rejects_missing_or_invalid_legal_urls() {
        for field in ["licenseUrl", "sourceUrl"] {
            let mut missing = manifest();
            missing["entries"][0].as_object_mut().unwrap().remove(field);
            assert!(parse(missing).is_err(), "accepted missing {field}");
            let mut invalid = manifest();
            invalid["entries"][0][field] = json!("http://github.com/jellyfin/jellyfin-ffmpeg");
            assert!(parse(invalid).is_err(), "accepted invalid {field}");
        }
    }
    #[test]
    fn rejects_missing_identity_matchers_or_platform_requirements() {
        for field in ["versionMatchers", "minimumPlatform"] {
            let mut value = manifest();
            value["entries"][0].as_object_mut().unwrap().remove(field);
            assert!(parse(value).is_err(), "accepted missing {field}");
        }
        let mut empty_matcher = manifest();
        empty_matcher["entries"][0]["versionMatchers"]["ffmpeg"] = json!("");
        assert!(parse(empty_matcher).is_err());
        let mut invalid_platform = manifest();
        invalid_platform["entries"][0]["minimumPlatform"]["windows"]["minimumOperatingSystemVersion"]
            ["major"] = json!(0);
        invalid_platform["entries"][0]["minimumPlatform"]["windows"]["minimumOperatingSystemVersion"]
            ["minor"] = json!(0);
        assert!(parse(invalid_platform).is_err());
    }
    #[test]
    fn embedded_manifest_selects_only_windows_x64_once() {
        let manifest = RuntimeManifest::embedded().unwrap();
        assert_eq!(
            manifest
                .artifacts()
                .iter()
                .filter(|artifact| artifact.for_host(RuntimeHost::WindowsX64))
                .count(),
            1
        );
        assert!(
            manifest
                .artifact_for_host(RuntimeHost::WindowsX64)
                .is_some()
        );
        assert!(manifest.artifact_for_host(RuntimeHost::LinuxX64).is_none());
        assert!(
            manifest
                .artifact_for_host(RuntimeHost::MacOsArm64)
                .is_none()
        );
    }
    #[test]
    fn runtime_artifact_exposes_validated_relative_paths() {
        let manifest = RuntimeManifest::embedded().unwrap();
        let artifact = manifest.artifact_for_host(RuntimeHost::WindowsX64).unwrap();
        let path: &RelativeArchivePath = &artifact.required_paths()[0];

        assert_eq!(path.as_str(), "ffmpeg.exe");
        assert_eq!(path.as_path(), Path::new("ffmpeg.exe"));
    }
}
