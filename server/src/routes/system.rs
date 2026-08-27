use crate::routes::compat;
use crate::state::AppState;
use crate::updater::version::UpdateChannel;
use crate::{network_security::ProxyPolicySettings, settings_control::SettingsMutationAuthority};
use axum::{
    Json,
    extract::{ConnectInfo, Query, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use enginefs::backend::{
    TorrentEncryptionMode, TorrentHandle, TorrentPrivacyConfig, TorrentProxyType,
};
use serde_json::{Value, json};
use std::collections::HashMap;

async fn combined_engine_stats(
    state: &AppState,
) -> HashMap<String, enginefs::backend::EngineStats> {
    let mut engines = state.engine.get_all_statistics().await;
    let download_engines = state.download_engine.get_all_statistics().await;

    // Direct playback/download requests use download_engine when disk-backed
    // mode is available. Prefer those stats for duplicate info hashes so UI
    // speed/peer counters reflect the active transfer.
    for (hash, stats) in download_engines {
        engines.insert(hash, stats);
    }

    engines
}

#[derive(serde::Deserialize)]
pub struct StatsParams {
    pub sys: Option<String>, // "1"
}

pub async fn get_stats(
    State(state): State<AppState>,
    Query(params): Query<StatsParams>,
) -> impl IntoResponse {
    let engines = combined_engine_stats(&state).await;

    // Convert engines HashMap to Value
    let mut root: serde_json::Map<String, Value> = serde_json::Map::new();

    for (hash, stats) in engines {
        root.insert(hash, serde_json::to_value(stats).unwrap_or(Value::Null));
    }

    if params.sys.as_deref() == Some("1") {
        let mut system = sysinfo::System::new_all();
        system.refresh_all();
        let loadavg = sysinfo::System::load_average();
        root.insert(
            "sys".to_string(),
            json!({
                "loadavg": [loadavg.one, loadavg.five, loadavg.fifteen],
                "cpus": system.cpus().iter().map(|cpu| {
                    json!({
                        "model": cpu.brand(),
                        "speed": cpu.frequency(),
                    })
                }).collect::<Vec<_>>()
            }),
        );
    }

    Json(Value::Object(root))
}

pub async fn heartbeat() -> impl IntoResponse {
    Json(json!({ "success": true }))
}

pub async fn network_info() -> impl IntoResponse {
    let mut interfaces = Vec::new();
    if let Ok(if_addrs) = if_addrs::get_if_addrs() {
        for iface in if_addrs {
            if !iface.is_loopback()
                && let if_addrs::IfAddr::V4(addr) = iface.addr
            {
                interfaces.push(addr.ip.to_string());
            }
        }
    }
    Json(json!({ "availableInterfaces": interfaces }))
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ServerSettings {
    #[serde(rename = "appPath")]
    pub app_path: String,
    #[serde(rename = "serverVersion")]
    pub server_version: String,
    #[serde(rename = "cacheRoot")]
    pub cache_root: String,
    #[serde(rename = "cacheSize")]
    pub cache_size: f64,
    #[serde(rename = "proxyStreamsEnabled")]
    pub proxy_streams_enabled: bool,
    #[serde(rename = "allowPrivateNetworkSources", default)]
    pub allow_private_network_sources: bool,
    #[serde(rename = "allowInvalidProxyTlsCertificates", default)]
    pub allow_invalid_proxy_tls_certificates: bool,
    #[serde(rename = "btMaxConnections")]
    pub bt_max_connections: u64,
    #[serde(rename = "btHandshakeTimeout")]
    pub bt_handshake_timeout: u64,
    #[serde(rename = "btRequestTimeout")]
    pub bt_request_timeout: u64,
    #[serde(rename = "btDownloadSpeedSoftLimit")]
    pub bt_download_speed_soft_limit: f64,
    #[serde(rename = "btDownloadSpeedHardLimit")]
    pub bt_download_speed_hard_limit: f64,
    #[serde(rename = "btMinPeersForStable")]
    pub bt_min_peers_for_stable: u64,
    #[serde(rename = "btEnableDht", default = "default_bt_enable_dht")]
    pub bt_enable_dht: bool,
    #[serde(rename = "btEnablePex", default = "default_bt_enable_pex")]
    pub bt_enable_pex: bool,
    #[serde(rename = "btEnableLsd", default = "default_bt_enable_lsd")]
    pub bt_enable_lsd: bool,
    #[serde(rename = "btEncryptionMode", default)]
    pub bt_encryption_mode: TorrentEncryptionMode,
    #[serde(rename = "btAnonymousMode", default = "default_bt_anonymous_mode")]
    pub bt_anonymous_mode: bool,
    #[serde(
        rename = "btAllowMultipleConnectionsPerIp",
        default = "default_bt_allow_multiple_connections_per_ip"
    )]
    pub bt_allow_multiple_connections_per_ip: bool,
    #[serde(
        rename = "btListenInterfaces",
        default = "default_bt_listen_interfaces"
    )]
    pub bt_listen_interfaces: String,
    #[serde(rename = "btOutgoingInterfaces", default)]
    pub bt_outgoing_interfaces: String,
    #[serde(rename = "btOutgoingPort", default)]
    pub bt_outgoing_port: u16,
    #[serde(rename = "btNumOutgoingPorts", default)]
    pub bt_num_outgoing_ports: u16,
    #[serde(rename = "btProxyType", default)]
    pub bt_proxy_type: TorrentProxyType,
    #[serde(rename = "btProxyHost", default)]
    pub bt_proxy_host: String,
    #[serde(rename = "btProxyPort", default)]
    pub bt_proxy_port: u16,
    #[serde(rename = "btProxyUsername", default)]
    pub bt_proxy_username: String,
    #[serde(rename = "btProxyPassword", default)]
    pub bt_proxy_password: String,
    #[serde(rename = "btProxyHostnames", default = "default_bt_proxy_hostnames")]
    pub bt_proxy_hostnames: bool,
    #[serde(
        rename = "btProxyPeerConnections",
        default = "default_bt_proxy_peer_connections"
    )]
    pub bt_proxy_peer_connections: bool,
    #[serde(
        rename = "btProxyTrackerConnections",
        default = "default_bt_proxy_tracker_connections"
    )]
    pub bt_proxy_tracker_connections: bool,
    #[serde(
        rename = "btProxySendHostInConnect",
        default = "default_bt_proxy_send_host_in_connect"
    )]
    pub bt_proxy_send_host_in_connect: bool,
    #[serde(
        rename = "btValidateHttpsTrackers",
        default = "default_bt_validate_https_trackers"
    )]
    pub bt_validate_https_trackers: bool,
    #[serde(rename = "btSsrfMitigation", default = "default_bt_ssrf_mitigation")]
    pub bt_ssrf_mitigation: bool,
    #[serde(rename = "remoteHttps")]
    pub remote_https: Option<String>,
    #[serde(rename = "transcodeProfile")]
    pub transcode_profile: Option<String>,
    #[serde(rename = "autoUpdateEnabled", default = "default_auto_update_enabled")]
    pub auto_update_enabled: bool,
    #[serde(rename = "updateChannel", default)]
    pub update_channel: UpdateChannel,
    #[serde(
        rename = "updateCheckIntervalHours",
        default = "default_update_check_interval_hours"
    )]
    pub update_check_interval_hours: u64,

    /// Cached list of fastest trackers (ranked by RTT)
    #[serde(rename = "cachedTrackers", default)]
    pub cached_trackers: Vec<String>,

    /// Unix timestamp (seconds) when trackers were last updated
    #[serde(rename = "trackersLastUpdated", default)]
    pub trackers_last_updated: i64,

    /// URL to fetch public tracker list (configurable)
    #[serde(rename = "trackersSourceUrl", default = "default_trackers_url")]
    pub trackers_source_url: String,

    /// When true (default), torrents continue seeding after download
    /// completes, improving swarm health and download speeds from reciprocal
    /// peers.  When false, torrents are paused once their download finishes.
    #[serde(rename = "seedingEnabled", default = "default_seeding_enabled")]
    pub seeding_enabled: bool,
}

pub fn default_trackers_url() -> String {
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt".to_string()
}

pub fn default_seeding_enabled() -> bool {
    true
}

pub fn default_auto_update_enabled() -> bool {
    true
}

pub fn default_update_check_interval_hours() -> u64 {
    6
}

pub fn default_bt_enable_dht() -> bool {
    true
}

pub fn default_bt_enable_pex() -> bool {
    true
}

pub fn default_bt_enable_lsd() -> bool {
    true
}

pub fn default_bt_anonymous_mode() -> bool {
    false
}

pub fn default_bt_allow_multiple_connections_per_ip() -> bool {
    false
}

pub fn default_bt_listen_interfaces() -> String {
    enginefs::backend::TorrentPrivacyConfig::default().bt_listen_interfaces
}

pub fn default_bt_proxy_hostnames() -> bool {
    true
}

pub fn default_bt_proxy_peer_connections() -> bool {
    false
}

pub fn default_bt_proxy_tracker_connections() -> bool {
    true
}

pub fn default_bt_proxy_send_host_in_connect() -> bool {
    false
}

pub fn default_bt_validate_https_trackers() -> bool {
    true
}

pub fn default_bt_ssrf_mitigation() -> bool {
    true
}

fn parse_environment_bool(value: &str) -> Option<bool> {
    if value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
    {
        Some(true)
    } else if value.eq_ignore_ascii_case("0")
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off")
    {
        Some(false)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProxyEnvironmentOverrides {
    pub(crate) allow_private_network_sources: Option<bool>,
    pub(crate) allow_invalid_proxy_tls_certificates: Option<bool>,
}

impl ProxyEnvironmentOverrides {
    pub(crate) fn apply_to(self, settings: &mut ServerSettings) {
        if let Some(value) = self.allow_private_network_sources {
            settings.allow_private_network_sources = value;
        }
        if let Some(value) = self.allow_invalid_proxy_tls_certificates {
            settings.allow_invalid_proxy_tls_certificates = value;
        }
    }

    fn from_environment() -> Self {
        Self::from_reader(
            |name| std::env::var(name),
            |name| {
                tracing::warn!(
                    variable = name,
                    "ignoring invalid boolean environment override"
                );
            },
        )
    }

    fn from_reader<R, W>(mut read: R, mut warn_invalid: W) -> Self
    where
        R: FnMut(&str) -> Result<String, std::env::VarError>,
        W: FnMut(&str),
    {
        let mut overrides = Self::default();
        for (name, target) in [
            (
                "STREMIO_ALLOW_PRIVATE_NETWORK_SOURCES",
                &mut overrides.allow_private_network_sources,
            ),
            (
                "STREMIO_ALLOW_INVALID_PROXY_TLS_CERTIFICATES",
                &mut overrides.allow_invalid_proxy_tls_certificates,
            ),
        ] {
            match read(name) {
                Ok(value) => match parse_environment_bool(&value) {
                    Some(value) => *target = Some(value),
                    None => warn_invalid(name),
                },
                Err(std::env::VarError::NotPresent) => {}
                Err(std::env::VarError::NotUnicode(_)) => warn_invalid(name),
            }
        }
        overrides
    }
}

pub(crate) fn apply_proxy_environment_overrides(settings: &mut ServerSettings) {
    ProxyEnvironmentOverrides::from_environment().apply_to(settings);
}

fn parse_torrent_encryption_mode(value: &Value) -> Option<TorrentEncryptionMode> {
    if let Some(code) = value.as_u64() {
        return match code {
            0 => Some(TorrentEncryptionMode::Allow),
            1 => Some(TorrentEncryptionMode::Require),
            2 => Some(TorrentEncryptionMode::Disable),
            _ => None,
        };
    }

    let raw = value.as_str()?.trim();
    if raw.eq_ignore_ascii_case("allow")
        || raw.eq_ignore_ascii_case("allowEncryption")
        || raw.eq_ignore_ascii_case("enabled")
    {
        Some(TorrentEncryptionMode::Allow)
    } else if raw.eq_ignore_ascii_case("require")
        || raw.eq_ignore_ascii_case("requireEncryption")
        || raw.eq_ignore_ascii_case("forced")
    {
        Some(TorrentEncryptionMode::Require)
    } else if raw.eq_ignore_ascii_case("disable")
        || raw.eq_ignore_ascii_case("disableEncryption")
        || raw.eq_ignore_ascii_case("disabled")
    {
        Some(TorrentEncryptionMode::Disable)
    } else {
        None
    }
}

fn parse_torrent_proxy_type(value: &Value) -> Option<TorrentProxyType> {
    if let Some(code) = value.as_u64() {
        return match code {
            0 => Some(TorrentProxyType::None),
            1 => Some(TorrentProxyType::Socks4),
            2 => Some(TorrentProxyType::Socks5),
            3 => Some(TorrentProxyType::Socks5Password),
            4 => Some(TorrentProxyType::Http),
            5 => Some(TorrentProxyType::HttpPassword),
            _ => None,
        };
    }

    let raw = value.as_str()?.trim();
    if raw.eq_ignore_ascii_case("none") || raw.eq_ignore_ascii_case("disabled") {
        Some(TorrentProxyType::None)
    } else if raw.eq_ignore_ascii_case("socks4") {
        Some(TorrentProxyType::Socks4)
    } else if raw.eq_ignore_ascii_case("socks5") {
        Some(TorrentProxyType::Socks5)
    } else if raw.eq_ignore_ascii_case("socks5Password")
        || raw.eq_ignore_ascii_case("socks5_password")
        || raw.eq_ignore_ascii_case("socks5_pw")
    {
        Some(TorrentProxyType::Socks5Password)
    } else if raw.eq_ignore_ascii_case("http") {
        Some(TorrentProxyType::Http)
    } else if raw.eq_ignore_ascii_case("httpPassword")
        || raw.eq_ignore_ascii_case("http_password")
        || raw.eq_ignore_ascii_case("http_pw")
    {
        Some(TorrentProxyType::HttpPassword)
    } else {
        None
    }
}

fn value_as_u16(value: &Value) -> Option<u16> {
    value.as_u64().and_then(|n| u16::try_from(n).ok())
}

fn update_bool_setting(obj: &serde_json::Map<String, Value>, key: &str, target: &mut bool) {
    if let Some(value) = obj.get(key).and_then(Value::as_bool) {
        *target = value;
    }
}

fn update_u16_setting(obj: &serde_json::Map<String, Value>, key: &str, target: &mut u16) {
    if let Some(value) = obj.get(key).and_then(value_as_u16) {
        *target = value;
    }
}

fn update_string_setting(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    target: &mut String,
    trim: bool,
    allow_empty: bool,
) {
    if let Some(value) = obj.get(key).and_then(Value::as_str) {
        let value = if trim { value.trim() } else { value };
        if allow_empty || !value.is_empty() {
            *target = value.to_string();
        }
    }
}

impl Default for ServerSettings {
    fn default() -> Self {
        let cache_root = std::env::var("STREMIO_CACHE_ROOT")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{}/.cache/stremio-server", h)))
            .unwrap_or_else(|_| {
                std::env::temp_dir()
                    .join("stremio-cache")
                    .to_string_lossy()
                    .to_string()
            });

        Self {
            app_path: std::env::current_exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "/usr/bin/stremio-server".to_string()),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            cache_root,
            cache_size: 10.0 * 1024.0 * 1024.0 * 1024.0, // 10GB
            proxy_streams_enabled: false,
            allow_private_network_sources: false,
            allow_invalid_proxy_tls_certificates: false,
            bt_max_connections: enginefs::backend::DEFAULT_BT_MAX_CONNECTIONS,
            bt_handshake_timeout: 20000,
            bt_request_timeout: 10000,
            bt_download_speed_soft_limit: 0.0,
            bt_download_speed_hard_limit: 0.0,
            bt_min_peers_for_stable: 5,
            bt_enable_dht: default_bt_enable_dht(),
            bt_enable_pex: default_bt_enable_pex(),
            bt_enable_lsd: default_bt_enable_lsd(),
            bt_encryption_mode: TorrentEncryptionMode::default(),
            bt_anonymous_mode: default_bt_anonymous_mode(),
            bt_allow_multiple_connections_per_ip: default_bt_allow_multiple_connections_per_ip(),
            bt_listen_interfaces: default_bt_listen_interfaces(),
            bt_outgoing_interfaces: String::new(),
            bt_outgoing_port: 0,
            bt_num_outgoing_ports: 0,
            bt_proxy_type: TorrentProxyType::default(),
            bt_proxy_host: String::new(),
            bt_proxy_port: 0,
            bt_proxy_username: String::new(),
            bt_proxy_password: String::new(),
            bt_proxy_hostnames: default_bt_proxy_hostnames(),
            bt_proxy_peer_connections: default_bt_proxy_peer_connections(),
            bt_proxy_tracker_connections: default_bt_proxy_tracker_connections(),
            bt_proxy_send_host_in_connect: default_bt_proxy_send_host_in_connect(),
            bt_validate_https_trackers: default_bt_validate_https_trackers(),
            bt_ssrf_mitigation: default_bt_ssrf_mitigation(),
            remote_https: None,
            transcode_profile: None,
            auto_update_enabled: default_auto_update_enabled(),
            update_channel: UpdateChannel::default(),
            update_check_interval_hours: default_update_check_interval_hours(),
            cached_trackers: Vec::new(),
            trackers_last_updated: 0,
            trackers_source_url: default_trackers_url(),
            seeding_enabled: default_seeding_enabled(),
        }
    }
}

pub(crate) struct PreparedSettingsUpdate {
    pub(crate) next: ServerSettings,
    allow_private_network_sources_changed: bool,
    allow_invalid_proxy_tls_certificates_changed: bool,
}

impl PreparedSettingsUpdate {
    fn disk_candidate(&self, live: &ServerSettings, raw: &ServerSettings) -> ServerSettings {
        let mut disk = live.clone();
        if !self.allow_private_network_sources_changed {
            disk.allow_private_network_sources = raw.allow_private_network_sources;
        }
        if !self.allow_invalid_proxy_tls_certificates_changed {
            disk.allow_invalid_proxy_tls_certificates = raw.allow_invalid_proxy_tls_certificates;
        }
        disk
    }
}

pub(crate) fn preserve_raw_protected_settings(
    live: &ServerSettings,
    raw: &ServerSettings,
) -> ServerSettings {
    let mut disk = live.clone();
    disk.allow_private_network_sources = raw.allow_private_network_sources;
    disk.allow_invalid_proxy_tls_certificates = raw.allow_invalid_proxy_tls_certificates;
    disk
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum SettingsUpdateError {
    #[error("protected setting requires local authorization")]
    Forbidden,
    #[error("invalid settings payload: {0}")]
    Invalid(&'static str),
    #[error("settings persistence failed")]
    Persistence(#[source] anyhow::Error),
}

fn prepare_settings_update(
    current: &ServerSettings,
    payload: &Value,
    authority: SettingsMutationAuthority,
) -> Result<PreparedSettingsUpdate, SettingsUpdateError> {
    let object = payload
        .as_object()
        .ok_or(SettingsUpdateError::Invalid("expected a JSON object"))?;
    let mut next = current.clone();
    let mut allow_private_network_sources_changed = false;
    let mut allow_invalid_proxy_tls_certificates_changed = false;
    for (key, current_value, target, changed) in [
        (
            "allowPrivateNetworkSources",
            current.allow_private_network_sources,
            &mut next.allow_private_network_sources,
            &mut allow_private_network_sources_changed,
        ),
        (
            "allowInvalidProxyTlsCertificates",
            current.allow_invalid_proxy_tls_certificates,
            &mut next.allow_invalid_proxy_tls_certificates,
            &mut allow_invalid_proxy_tls_certificates_changed,
        ),
    ] {
        if let Some(value) = object.get(key) {
            let value = value.as_bool().ok_or(SettingsUpdateError::Invalid(
                "protected values must be boolean",
            ))?;
            if value != current_value && authority == SettingsMutationAuthority::Untrusted {
                return Err(SettingsUpdateError::Forbidden);
            }
            *changed = value != current_value;
            *target = value;
        }
    }

    Ok(PreparedSettingsUpdate {
        next,
        allow_private_network_sources_changed,
        allow_invalid_proxy_tls_certificates_changed,
    })
}

/// Returns server settings in the SettingsResponse format expected by stremio-core
/// Response format: { "baseUrl": "http://...", "values": { ...settings } }
pub async fn get_settings(State(state): State<AppState>) -> impl IntoResponse {
    let settings = state.settings.read().await;
    Json(json!({
        "baseUrl": state.base_url.clone(),
        "options": [],
        "values": settings.clone()
    }))
}

#[cfg(not(test))]
pub(crate) async fn persist_settings_atomic(
    path: &std::path::Path,
    settings: &ServerSettings,
) -> anyhow::Result<SettingsPersistenceOutcome> {
    persist_settings_atomic_with_after_rename(path, settings, async {}).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SettingsPersistenceOutcome {
    Durable,
    CommittedWithDurabilityWarning,
}

#[cfg(not(test))]
pub(crate) async fn persist_settings_atomic_with_after_rename<F>(
    path: &std::path::Path,
    settings: &ServerSettings,
    after_rename: F,
) -> anyhow::Result<SettingsPersistenceOutcome>
where
    F: std::future::Future<Output = ()>,
{
    persist_settings_atomic_with_hooks(path, settings, after_rename, sync_settings_parent).await
}

#[cfg(not(test))]
async fn sync_settings_parent(parent: std::path::PathBuf) -> anyhow::Result<()> {
    #[cfg(unix)]
    tokio::task::spawn_blocking(move || std::fs::File::open(parent)?.sync_all()).await??;
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

pub(crate) async fn persist_settings_atomic_with_hooks<F, S, SF>(
    path: &std::path::Path,
    settings: &ServerSettings,
    after_rename: F,
    sync_parent: S,
) -> anyhow::Result<SettingsPersistenceOutcome>
where
    F: std::future::Future<Output = ()>,
    S: FnOnce(std::path::PathBuf) -> SF,
    SF: std::future::Future<Output = anyhow::Result<()>>,
{
    let bytes = serde_json::to_vec_pretty(settings)?;
    let path = path.to_owned();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("settings path has no parent"))?
        .to_owned();
    tokio::fs::create_dir_all(&parent).await?;
    let parent_to_sync = parent.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        use std::io::Write;
        let mut temporary = tempfile::NamedTempFile::new_in(&parent)?;
        temporary.write_all(&bytes)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(&path).map_err(|error| error.error)?;
        Ok(())
    })
    .await??;
    after_rename.await;
    match sync_parent(parent_to_sync).await {
        Ok(()) => Ok(SettingsPersistenceOutcome::Durable),
        Err(_) => {
            tracing::warn!("settings persistence durability warning");
            Ok(SettingsPersistenceOutcome::CommittedWithDurabilityWarning)
        }
    }
}

pub async fn update_settings(
    state: &AppState,
    payload: &Value,
    authority: SettingsMutationAuthority,
) -> Result<(), SettingsUpdateError> {
    let mut raw = state.settings_persistence.lock_owned().await;
    let current = state.settings.read().await.clone();
    let protected = prepare_settings_update(&current, payload, authority)?;
    let mut settings = current;
    settings.allow_private_network_sources = protected.next.allow_private_network_sources;
    settings.allow_invalid_proxy_tls_certificates =
        protected.next.allow_invalid_proxy_tls_certificates;

    if let Some(obj) = payload.as_object() {
        // Update fields that are present in the payload
        if let Some(v) = obj.get("transcodeProfile") {
            if v.is_null() {
                settings.transcode_profile = None;
            } else if let Some(s) = v.as_str() {
                settings.transcode_profile = Some(s.to_string());
            }
        }
        if let Some(v) = obj.get("cacheSize") {
            if v.is_null() {
                settings.cache_size = 0.0;
            } else if let Some(n) = v.as_f64() {
                settings.cache_size = n;
            }
        }
        if let Some(v) = obj.get("cacheRoot")
            && let Some(s) = v.as_str()
        {
            settings.cache_root = s.to_string();
        }
        if let Some(v) = obj.get("proxyStreamsEnabled")
            && let Some(b) = v.as_bool()
        {
            settings.proxy_streams_enabled = b;
        }
        if let Some(v) = obj.get("btMaxConnections")
            && let Some(n) = v.as_u64()
        {
            settings.bt_max_connections =
                if n == 0 || n >= enginefs::backend::LEGACY_UNLIMITED_BT_MAX_CONNECTIONS {
                    enginefs::backend::DEFAULT_BT_MAX_CONNECTIONS
                } else {
                    n
                };
        }
        if let Some(v) = obj.get("btHandshakeTimeout")
            && let Some(n) = v.as_u64()
        {
            settings.bt_handshake_timeout = n;
        }
        if let Some(v) = obj.get("btRequestTimeout")
            && let Some(n) = v.as_u64()
        {
            settings.bt_request_timeout = n;
        }
        if let Some(v) = obj.get("btDownloadSpeedSoftLimit")
            && let Some(n) = v.as_f64()
        {
            settings.bt_download_speed_soft_limit = n;
        }
        if let Some(v) = obj.get("btDownloadSpeedHardLimit")
            && let Some(n) = v.as_f64()
        {
            settings.bt_download_speed_hard_limit = n;
        }
        if let Some(v) = obj.get("btMinPeersForStable")
            && let Some(n) = v.as_u64()
        {
            settings.bt_min_peers_for_stable = n;
        }
        update_bool_setting(obj, "btEnableDht", &mut settings.bt_enable_dht);
        update_bool_setting(obj, "btEnablePex", &mut settings.bt_enable_pex);
        update_bool_setting(obj, "btEnableLsd", &mut settings.bt_enable_lsd);
        if let Some(mode) = obj
            .get("btEncryptionMode")
            .and_then(parse_torrent_encryption_mode)
        {
            settings.bt_encryption_mode = mode;
        }
        update_bool_setting(obj, "btAnonymousMode", &mut settings.bt_anonymous_mode);
        update_bool_setting(
            obj,
            "btAllowMultipleConnectionsPerIp",
            &mut settings.bt_allow_multiple_connections_per_ip,
        );
        update_string_setting(
            obj,
            "btListenInterfaces",
            &mut settings.bt_listen_interfaces,
            true,
            false,
        );
        update_string_setting(
            obj,
            "btOutgoingInterfaces",
            &mut settings.bt_outgoing_interfaces,
            true,
            true,
        );
        update_u16_setting(obj, "btOutgoingPort", &mut settings.bt_outgoing_port);
        update_u16_setting(
            obj,
            "btNumOutgoingPorts",
            &mut settings.bt_num_outgoing_ports,
        );
        if let Some(proxy_type) = obj.get("btProxyType").and_then(parse_torrent_proxy_type) {
            settings.bt_proxy_type = proxy_type;
        }
        update_string_setting(obj, "btProxyHost", &mut settings.bt_proxy_host, true, true);
        update_u16_setting(obj, "btProxyPort", &mut settings.bt_proxy_port);
        update_string_setting(
            obj,
            "btProxyUsername",
            &mut settings.bt_proxy_username,
            false,
            true,
        );
        update_string_setting(
            obj,
            "btProxyPassword",
            &mut settings.bt_proxy_password,
            false,
            true,
        );
        update_bool_setting(obj, "btProxyHostnames", &mut settings.bt_proxy_hostnames);
        update_bool_setting(
            obj,
            "btProxyPeerConnections",
            &mut settings.bt_proxy_peer_connections,
        );
        update_bool_setting(
            obj,
            "btProxyTrackerConnections",
            &mut settings.bt_proxy_tracker_connections,
        );
        update_bool_setting(
            obj,
            "btProxySendHostInConnect",
            &mut settings.bt_proxy_send_host_in_connect,
        );
        update_bool_setting(
            obj,
            "btValidateHttpsTrackers",
            &mut settings.bt_validate_https_trackers,
        );
        update_bool_setting(obj, "btSsrfMitigation", &mut settings.bt_ssrf_mitigation);
        if let Some(v) = obj.get("remoteHttps") {
            if v.is_null() {
                settings.remote_https = None;
            } else if let Some(s) = v.as_str() {
                settings.remote_https = Some(s.to_string());
            }
        }
        if let Some(v) = obj.get("autoUpdateEnabled")
            && let Some(enabled) = v.as_bool()
        {
            settings.auto_update_enabled = enabled;
        }
        if let Some(v) = obj.get("updateChannel").and_then(|v| v.as_str()) {
            settings.update_channel = if v.eq_ignore_ascii_case("prerelease") {
                UpdateChannel::Prerelease
            } else {
                UpdateChannel::Stable
            };
        }
        if let Some(v) = obj.get("updateCheckIntervalHours")
            && let Some(hours) = v.as_u64()
        {
            settings.update_check_interval_hours = hours.max(1);
        }
        if let Some(v) = obj.get("seedingEnabled")
            && let Some(enabled) = v.as_bool()
        {
            settings.seeding_enabled = enabled;
        }
    }

    let seeding_enabled = settings.seeding_enabled;

    // Build new speed profile from updated settings
    let new_profile = enginefs::backend::TorrentSpeedProfile {
        bt_download_speed_hard_limit: settings.bt_download_speed_hard_limit,
        bt_download_speed_soft_limit: settings.bt_download_speed_soft_limit,
        bt_handshake_timeout: settings.bt_handshake_timeout,
        bt_max_connections: settings.bt_max_connections,
        bt_min_peers_for_stable: settings.bt_min_peers_for_stable,
        bt_request_timeout: settings.bt_request_timeout,
    };
    let new_privacy = TorrentPrivacyConfig {
        bt_enable_dht: settings.bt_enable_dht,
        bt_enable_pex: settings.bt_enable_pex,
        bt_enable_lsd: settings.bt_enable_lsd,
        bt_encryption_mode: settings.bt_encryption_mode,
        bt_anonymous_mode: settings.bt_anonymous_mode,
        bt_allow_multiple_connections_per_ip: settings.bt_allow_multiple_connections_per_ip,
        bt_listen_interfaces: settings.bt_listen_interfaces.clone(),
        bt_outgoing_interfaces: settings.bt_outgoing_interfaces.clone(),
        bt_outgoing_port: settings.bt_outgoing_port,
        bt_num_outgoing_ports: settings.bt_num_outgoing_ports,
        bt_proxy_type: settings.bt_proxy_type,
        bt_proxy_host: settings.bt_proxy_host.clone(),
        bt_proxy_port: settings.bt_proxy_port,
        bt_proxy_username: settings.bt_proxy_username.clone(),
        bt_proxy_password: settings.bt_proxy_password.clone(),
        bt_proxy_hostnames: settings.bt_proxy_hostnames,
        bt_proxy_peer_connections: settings.bt_proxy_peer_connections,
        bt_proxy_tracker_connections: settings.bt_proxy_tracker_connections,
        bt_proxy_send_host_in_connect: settings.bt_proxy_send_host_in_connect,
        bt_validate_https_trackers: settings.bt_validate_https_trackers,
        bt_ssrf_mitigation: settings.bt_ssrf_mitigation,
    };

    let proxy_policy = ProxyPolicySettings {
        allow_private_network_sources: settings.allow_private_network_sources,
        allow_invalid_proxy_tls_certificates: settings.allow_invalid_proxy_tls_certificates,
    };
    let disk = protected.disk_candidate(&settings, &raw);
    let transaction_state = state.clone();
    let persistence = state.settings_persistence.clone();
    #[cfg(test)]
    let before_final_side_effect = state
        .settings_persistence
        .take_before_final_side_effect_gate();
    let completion = state
        .settings_persistence
        .register_transaction(async move {
            persistence
                .persist_settings(&transaction_state.settings_path, &disk)
                .await?;
            *raw = disk;
            let mut published = transaction_state.settings.write().await;
            transaction_state
                .proxy_runtime
                .begin_reconfigure(proxy_policy);
            *published = settings;
            transaction_state
                .proxy_runtime
                .finish_reconfigure(proxy_policy);
            drop(published);

            #[cfg(test)]
            transaction_state
                .settings_persistence
                .record_post_persist_side_effects();
            transaction_state
                .engine
                .update_torrent_settings(&new_profile, &new_privacy)
                .await;
            transaction_state
                .download_engine
                .update_torrent_settings(&new_profile, &new_privacy)
                .await;

            transaction_state
                .engine
                .set_seeding_enabled(seeding_enabled);
            #[cfg(test)]
            if let Some(gate) = before_final_side_effect {
                gate.reach_and_wait().await;
            }
            transaction_state
                .download_engine
                .set_seeding_enabled(seeding_enabled);
            Ok(())
        })
        .map_err(|error| SettingsUpdateError::Persistence(error.into()))?;

    match completion.await {
        Ok(result) => result.map_err(SettingsUpdateError::Persistence),
        Err(error) => {
            tracing::error!("settings transaction failed");
            Err(SettingsUpdateError::Persistence(error.into()))
        }
    }
}

pub async fn set_settings(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let authority = state.settings_control.authorize_http(peer, &headers);
    match update_settings(&state, &payload, authority).await {
        Ok(()) => (StatusCode::OK, Json(json!({"success": true}))).into_response(),
        Err(SettingsUpdateError::Forbidden) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "success": false,
                "error": "protected setting requires local authorization"
            })),
        )
            .into_response(),
        Err(SettingsUpdateError::Invalid(_)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "invalid settings payload"})),
        )
            .into_response(),
        Err(SettingsUpdateError::Persistence(_)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "error": "settings could not be saved"
            })),
        )
            .into_response(),
    }
}

pub(crate) fn compat_device_info(profiles: Vec<String>) -> serde_json::Value {
    json!({ "availableHardwareAccelerations": profiles })
}

pub(crate) fn compat_profiler(profiles: Vec<String>) -> serde_json::Value {
    json!({ "success": true, "profiles": profiles })
}

pub async fn get_device_info() -> impl IntoResponse {
    let profiles = probe_hwaccel().await;
    Json(compat_device_info(profiles))
}

pub async fn hwaccel_profiler() -> impl IntoResponse {
    let profiles = probe_hwaccel().await;
    Json(compat_profiler(profiles))
}

static HWACCEL_PROFILES: tokio::sync::OnceCell<Vec<String>> = tokio::sync::OnceCell::const_new();

pub async fn probe_hwaccel() -> Vec<String> {
    HWACCEL_PROFILES
        .get_or_init(probe_hwaccel_uncached)
        .await
        .clone()
}

async fn probe_hwaccel_uncached() -> Vec<String> {
    let mut profiles = Vec::new();
    let output = match tokio::process::Command::new("ffmpeg")
        .args(["-hide_banner", "-encoders"])
        .output()
        .await
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return profiles,
    };

    if output.contains("h264_nvenc") {
        profiles.push("nvenc".to_string());
        if verify_h264_encoder("h264_nvenc").await {
            profiles.push("nvenc:verified".to_string());
        }
    }
    if output.contains("h264_vaapi") {
        profiles.push("vaapi".to_string());
        if verify_h264_encoder("h264_vaapi").await {
            profiles.push("vaapi:verified".to_string());
        }
    }
    if output.contains("h264_vdpau") {
        profiles.push("vdpau".to_string());
    }
    if output.contains("h264_qsv") {
        profiles.push("qsv".to_string());
        if verify_h264_encoder("h264_qsv").await {
            profiles.push("qsv:verified".to_string());
        }
    }
    if output.contains("h264_omx") {
        profiles.push("omx".to_string());
    }
    if output.contains("h264_v4l2m2m") {
        profiles.push("v4l2m2m".to_string());
        if verify_h264_encoder("h264_v4l2m2m").await {
            profiles.push("v4l2m2m:verified".to_string());
        }
    }
    if output.contains("h264_videotoolbox") {
        profiles.push("videotoolbox".to_string());
        if verify_h264_encoder("h264_videotoolbox").await {
            profiles.push("videotoolbox:verified".to_string());
        }
    }
    if output.contains("h264_mediacodec") {
        profiles.push("mediacodec".to_string());
    }

    profiles
}

async fn verify_h264_encoder(encoder: &str) -> bool {
    let mut cmd = tokio::process::Command::new("ffmpeg");
    cmd.args([
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=64x64:rate=1:duration=1",
        "-frames:v",
        "1",
        "-an",
        "-pix_fmt",
        "yuv420p",
        "-c:v",
        encoder,
        "-f",
        "null",
        "-",
    ]);

    let output = match tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            tracing::debug!(encoder, error = %err, "hardware encoder verification failed to spawn");
            return false;
        }
        Err(_) => {
            tracing::debug!(encoder, "hardware encoder verification timed out");
            return false;
        }
    };

    if output.status.success() {
        tracing::info!(encoder, "hardware encoder verified");
        true
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::debug!(
            encoder,
            status = ?output.status.code(),
            stderr = %stderr.trim(),
            "hardware encoder listed by FFmpeg but failed verification"
        );
        false
    }
}

pub async fn get_https(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let ip_address = match params.get("ipAddress") {
        Some(ip) => ip,
        None => return (StatusCode::BAD_REQUEST, "Missing ipAddress").into_response(),
    };
    let auth_key = match params.get("authKey") {
        Some(key) => key,
        None => return (StatusCode::BAD_REQUEST, "Missing authKey").into_response(),
    };

    let client = reqwest::Client::new();
    let api_url = "https://api.strem.io/api/certificateGet";

    let payload = json!({
        "authKey": auth_key,
        "ipAddress": ip_address
    });

    let resp = match client.post(api_url).json(&payload).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("API error: {}", e),
            )
                .into_response();
        }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("JSON error: {}", e),
            )
                .into_response();
        }
    };

    // Parity with http_client_804.js: parse certificate response
    let result = &json["result"];
    if result.is_null() {
        return (StatusCode::NOT_FOUND, "No certificate found in response").into_response();
    }

    let cert_data_str = match result["certificate"].as_str() {
        Some(s) => s,
        None => return (StatusCode::NOT_FOUND, "Certificate field missing").into_response(),
    };

    let cert_data: serde_json::Value = match serde_json::from_str(cert_data_str) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to parse inner certificate JSON",
            )
                .into_response();
        }
    };

    // Save to disk for main.rs HTTPS listener
    if let (Some(cert), Some(key)) = (
        cert_data["certificate"].as_str(),
        cert_data["privateKey"].as_str(),
    ) {
        let cert_path = state.config_dir.join("https-cert.pem");
        let key_path = state.config_dir.join("https-key.pem");

        if let Err(e) = tokio::fs::write(&cert_path, cert).await {
            tracing::error!("Failed to write https-cert.pem: {}", e);
        }
        if let Err(e) = tokio::fs::write(&key_path, key).await {
            tracing::error!("Failed to write https-key.pem: {}", e);
        }
        tracing::info!("Saved HTTPS certificates to {:?}", state.config_dir);
    }

    let domain = format!(
        "{}-{}",
        ip_address.replace(".", "-"),
        cert_data["commonName"]
            .as_str()
            .unwrap_or("")
            .replace("*", "")
    );

    // We should save this to disk, but for the API response:
    Json(json!({
        "ipAddress": ip_address,
        "domain": domain,
        "port": state.http_addr.port()
    }))
    .into_response()
}

pub async fn get_samples(
    axum::extract::Path(filename): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Parity with /samples/:filename
    (
        StatusCode::NOT_FOUND,
        format!("Sample {} not found", filename),
    )
        .into_response()
}

pub async fn get_engine_stats(
    State(state): State<AppState>,
    axum::extract::Path(info_hash): axum::extract::Path<String>,
) -> Response {
    let info_hash = info_hash.to_lowercase();

    // Try to get existing engine, or auto-create from info hash
    let engine = if let Some(e) = state.download_engine.get_engine(&info_hash).await {
        e
    } else if let Some(e) = state.engine.get_engine(&info_hash).await {
        e
    } else {
        tracing::info!("Auto-creating engine for stats request: {}", info_hash);
        let magnet = format!("magnet:?xt=urn:btih:{}", info_hash);
        let source = enginefs::backend::TorrentSource::Url(magnet);
        match state.download_engine.add_torrent(source, None).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("Failed to create engine: {}", e);
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to create engine: {}", e),
                )
                    .into_response();
            }
        }
    };

    let stats = engine.get_statistics().await;
    Json(serde_json::to_value(stats).unwrap()).into_response()
}

pub async fn get_file_stats(
    State(state): State<AppState>,
    axum::extract::Path((info_hash, requested_idx)): axum::extract::Path<(String, String)>,
    RawQuery(query_str): RawQuery,
) -> Response {
    let info_hash = info_hash.to_lowercase();

    // Try to get existing engine, or auto-create from info hash
    let engine = if let Some(e) = state.download_engine.get_engine(&info_hash).await {
        e
    } else if let Some(e) = state.engine.get_engine(&info_hash).await {
        e
    } else {
        tracing::info!("Auto-creating engine for file stats request: {}", info_hash);
        let magnet = format!("magnet:?xt=urn:btih:{}", info_hash);
        let source = enginefs::backend::TorrentSource::Url(magnet);
        match state.download_engine.add_torrent(source, None).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("Failed to create engine: {}", e);
                return (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to create engine: {}", e),
                )
                    .into_response();
            }
        }
    };

    let files = engine.handle.get_files().await;
    let candidates = files
        .iter()
        .enumerate()
        .map(|(index, file)| compat::FileCandidate {
            index,
            name: file.name.clone(),
            length: file.length,
        })
        .collect::<Vec<_>>();
    let filters = compat::query_values(query_str.as_deref(), "f");
    let idx = match compat::resolve_file_idx(&requested_idx, &candidates, &filters) {
        Ok(idx) => idx,
        Err(err) => {
            return (axum::http::StatusCode::NOT_FOUND, err).into_response();
        }
    };
    state
        .stream_engine()
        .refresh_existing_hls_playback(&info_hash, idx, "stats-json")
        .await;

    let mut stats = engine.get_statistics().await;
    if idx >= stats.files.len() {
        return (
            axum::http::StatusCode::NOT_FOUND,
            "File index out of bounds",
        )
            .into_response();
    }
    // Report progress for the exact file the client asked about. The guess
    // inside get_statistics can resolve to a different file in a multi-file
    // torrent, and downloaded/length stays stable during cold start (unlike the
    // torrent's total_wanted set, which briefly collapses to the metadata
    // window and spikes the percentage just before playback).
    let file = &stats.files[idx];
    stats.stream_name = file.name.clone();
    stats.stream_len = file.length;
    stats.stream_progress = if file.length > 0 {
        (file.downloaded as f64 / file.length as f64).min(1.0)
    } else {
        0.0
    };
    Json(serde_json::to_value(stats).unwrap()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings_control::{
        SETTINGS_TOKEN_HEADER, SettingsControl, SettingsMutationAuthority,
    };
    use enginefs::EngineFS;
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn real_settings_handler_uses_connect_info_token_and_ignores_forwarded_headers() {
        async fn call(
            state: &AppState,
            peer: &str,
            token: Option<&[u8]>,
            forwarded_for: Option<&str>,
            value: bool,
        ) -> StatusCode {
            let mut headers = HeaderMap::new();
            if let Some(token) = token {
                headers.insert(
                    SETTINGS_TOKEN_HEADER,
                    axum::http::HeaderValue::from_bytes(token).unwrap(),
                );
            }
            if let Some(forwarded_for) = forwarded_for {
                headers.insert(
                    "x-forwarded-for",
                    axum::http::HeaderValue::from_str(forwarded_for).unwrap(),
                );
                headers.insert(
                    "forwarded",
                    axum::http::HeaderValue::from_str(&format!("for={forwarded_for}")).unwrap(),
                );
            }
            set_settings(
                ConnectInfo(peer.parse().unwrap()),
                State(state.clone()),
                headers,
                Json(json!({"allowPrivateNetworkSources": value})),
            )
            .await
            .status()
        }

        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let mut state = AppState::new(
            engine,
            ServerSettings::default(),
            temp.path().join("config"),
            crate::state::unavailable_transcoding_for_test(),
        );
        let token = [b'a'; 64];
        state.settings_control = SettingsControl::for_test(token);

        for (peer, next) in [
            ("127.0.0.1:40000", true),
            ("[::1]:40000", false),
            ("[::ffff:127.0.0.1]:40000", true),
        ] {
            assert_eq!(
                call(&state, peer, Some(&token), None, next).await,
                StatusCode::OK
            );
        }
        assert_eq!(
            call(
                &state,
                "127.0.0.1:40000",
                Some(&token),
                Some("192.168.1.50"),
                false,
            )
            .await,
            StatusCode::OK,
            "forwarded remote address must not override loopback ConnectInfo"
        );

        for (peer, token_value, forwarded) in [
            ("192.168.1.50:40000", Some(&token[..]), Some("127.0.0.1")),
            ("[::ffff:192.168.1.50]:40000", Some(&token[..]), None),
            ("127.0.0.1:40000", None, None),
            ("127.0.0.1:40000", Some(&[b'b'; 64][..]), None),
        ] {
            assert_eq!(
                call(&state, peer, token_value, forwarded, true).await,
                StatusCode::FORBIDDEN,
                "peer={peer}"
            );
        }
        assert_eq!(
            call(&state, "192.168.1.50:40000", None, Some("127.0.0.1"), false,).await,
            StatusCode::OK,
            "unchanged protected values remain compatible for untrusted callers"
        );
        assert!(!state.settings.read().await.allow_private_network_sources);
    }

    #[tokio::test]
    async fn persistence_failure_rolls_back_handler_policy_engine_and_tracker_state() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let mut state = AppState::new(
            engine,
            ServerSettings::default(),
            temp.path().join("config"),
            crate::state::unavailable_transcoding_for_test(),
        );
        let token = [b'a'; 64];
        state.settings_control = SettingsControl::for_test(token);
        std::fs::create_dir_all(&state.settings_path).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            SETTINGS_TOKEN_HEADER,
            axum::http::HeaderValue::from_bytes(&token).unwrap(),
        );
        let response = set_settings(
            ConnectInfo("127.0.0.1:40000".parse().unwrap()),
            State(state.clone()),
            headers,
            Json(json!({
                "allowPrivateNetworkSources": true,
                "btMaxConnections": 321,
                "btProxyPassword": "unique-secret-marker",
                "cacheSize": 123.0,
                "seedingEnabled": false,
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let outward = String::from_utf8(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            outward,
            r#"{"error":"settings could not be saved","success":false}"#
        );
        assert!(!outward.contains("unique-secret-marker"));
        assert!(!outward.contains(state.settings_path.to_string_lossy().as_ref()));

        let live = state.settings.read().await.clone();
        assert!(!live.allow_private_network_sources);
        assert_eq!(
            live.bt_max_connections,
            ServerSettings::default().bt_max_connections
        );
        assert_eq!(live.cache_size, ServerSettings::default().cache_size);
        assert!(live.bt_proxy_password.is_empty());
        assert!(live.cached_trackers.is_empty());
        assert!(live.seeding_enabled);
        let raw = state.settings_persistence.raw_snapshot().await;
        assert!(!raw.allow_private_network_sources);
        assert_eq!(
            raw.bt_max_connections,
            ServerSettings::default().bt_max_connections
        );
        assert_eq!(raw.cache_size, ServerSettings::default().cache_size);
        assert!(raw.bt_proxy_password.is_empty());
        assert!(raw.cached_trackers.is_empty());
        assert!(raw.seeding_enabled);
        let request = state.proxy_runtime.try_request().unwrap();
        assert!(!request.settings.allow_private_network_sources);
        assert!(state.engine.seeding_enabled());
        assert!(state.download_engine.seeding_enabled());
        assert_eq!(
            state.settings_persistence.post_persist_side_effect_count(),
            0
        );

        let bridge = crate::state::TrackerStorageBridge::new_with_persistence(
            state.settings.clone(),
            state.settings_path.clone(),
            state.settings_persistence.clone(),
        );
        assert!(
            bridge
                .save_trackers_with_completion(
                    vec!["udp://unique-tracker-secret".to_string()],
                    123,
                )
                .await
                .unwrap()
                .is_err()
        );
        assert!(state.settings.read().await.cached_trackers.is_empty());
        assert!(
            state
                .settings_persistence
                .raw_snapshot()
                .await
                .cached_trackers
                .is_empty()
        );
        assert_eq!(
            state.settings_persistence.post_persist_side_effect_count(),
            0
        );
        assert!(state.settings_path.is_dir());
    }
    #[test]
    fn server_version_default_uses_crate_version() {
        let settings = ServerSettings::default();
        assert_eq!(settings.server_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn proxy_security_settings_default_false_when_missing_from_json() {
        let mut value = serde_json::to_value(ServerSettings::default()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("allowPrivateNetworkSources");
        object.remove("allowInvalidProxyTlsCertificates");
        let settings: ServerSettings = serde_json::from_value(value).unwrap();
        assert!(!settings.allow_private_network_sources);
        assert!(!settings.allow_invalid_proxy_tls_certificates);
    }

    #[test]
    fn untrusted_round_trip_may_repeat_but_not_change_protected_values() {
        let current = ServerSettings::default();
        let unchanged = json!({
            "allowPrivateNetworkSources": false,
            "allowInvalidProxyTlsCertificates": false,
        });
        assert!(
            prepare_settings_update(&current, &unchanged, SettingsMutationAuthority::Untrusted,)
                .is_ok()
        );

        let changed = json!({"allowPrivateNetworkSources": true});
        assert!(matches!(
            prepare_settings_update(&current, &changed, SettingsMutationAuthority::Untrusted,),
            Err(SettingsUpdateError::Forbidden)
        ));
    }

    #[test]
    fn authorized_callers_may_change_protected_values() {
        let current = ServerSettings::default();
        for authority in [
            SettingsMutationAuthority::TrustedLocal,
            SettingsMutationAuthority::HttpAuthorized,
        ] {
            let prepared = prepare_settings_update(
                &current,
                &json!({
                    "allowPrivateNetworkSources": true,
                    "allowInvalidProxyTlsCertificates": true,
                }),
                authority,
            )
            .unwrap();
            assert!(prepared.next.allow_private_network_sources);
            assert!(prepared.next.allow_invalid_proxy_tls_certificates);
        }
    }

    #[test]
    fn same_effective_protected_values_do_not_overwrite_raw_settings() {
        for (raw_value, effective_value) in [(false, true), (true, false)] {
            for authority in [
                SettingsMutationAuthority::Untrusted,
                SettingsMutationAuthority::TrustedLocal,
                SettingsMutationAuthority::HttpAuthorized,
            ] {
                for field in [
                    "allowPrivateNetworkSources",
                    "allowInvalidProxyTlsCertificates",
                ] {
                    let raw = ServerSettings {
                        allow_private_network_sources: raw_value,
                        allow_invalid_proxy_tls_certificates: raw_value,
                        ..ServerSettings::default()
                    };
                    let mut effective = raw.clone();
                    effective.allow_private_network_sources = effective_value;
                    effective.allow_invalid_proxy_tls_certificates = effective_value;
                    let payload = json!({field: effective_value});
                    let prepared =
                        prepare_settings_update(&effective, &payload, authority).unwrap();
                    let mut live = prepared.next.clone();
                    live.cache_size = 321.0;

                    let disk = prepared.disk_candidate(&live, &raw);

                    assert_eq!(disk.allow_private_network_sources, raw_value, "{field}");
                    assert_eq!(
                        disk.allow_invalid_proxy_tls_certificates, raw_value,
                        "{field}"
                    );
                    assert_eq!(disk.cache_size, 321.0, "{field}");
                    assert_eq!(
                        prepared.next.allow_private_network_sources, effective_value,
                        "{field}"
                    );
                    assert_eq!(
                        prepared.next.allow_invalid_proxy_tls_certificates, effective_value,
                        "{field}"
                    );
                }
            }
        }
    }

    #[test]
    fn non_boolean_protected_values_are_invalid_even_when_falsey() {
        let current = ServerSettings::default();
        for payload in [
            json!({"allowPrivateNetworkSources": null}),
            json!({"allowPrivateNetworkSources": 0}),
            json!({"allowInvalidProxyTlsCertificates": "false"}),
        ] {
            assert!(matches!(
                prepare_settings_update(
                    &current,
                    &payload,
                    SettingsMutationAuthority::TrustedLocal,
                ),
                Err(SettingsUpdateError::Invalid(_))
            ));
        }
    }

    #[test]
    fn environment_boolean_parser_is_strict_and_case_insensitive() {
        for value in ["1", "true", "TRUE", "yes", "On"] {
            assert_eq!(parse_environment_bool(value), Some(true), "{value}");
        }
        for value in ["0", "false", "FALSE", "no", "Off"] {
            assert_eq!(parse_environment_bool(value), Some(false), "{value}");
        }
        for value in ["", " true ", "enabled", "2"] {
            assert_eq!(parse_environment_bool(value), None, "{value}");
        }
    }

    #[test]
    fn pure_environment_overrides_apply_in_both_directions_and_win_on_restart() {
        for (raw_value, override_value) in [(false, true), (true, false)] {
            let raw = ServerSettings {
                allow_private_network_sources: raw_value,
                allow_invalid_proxy_tls_certificates: raw_value,
                ..ServerSettings::default()
            };
            let overrides = ProxyEnvironmentOverrides {
                allow_private_network_sources: Some(override_value),
                allow_invalid_proxy_tls_certificates: Some(override_value),
            };

            let mut effective = raw.clone();
            overrides.apply_to(&mut effective);

            assert_eq!(effective.allow_private_network_sources, override_value);
            assert_eq!(
                effective.allow_invalid_proxy_tls_certificates,
                override_value
            );
            assert_eq!(raw.allow_private_network_sources, raw_value);
            assert_eq!(raw.allow_invalid_proxy_tls_certificates, raw_value);

            let mut restarted = raw;
            overrides.apply_to(&mut restarted);
            assert_eq!(restarted.allow_private_network_sources, override_value);
            assert_eq!(
                restarted.allow_invalid_proxy_tls_certificates,
                override_value
            );
        }
    }

    #[test]
    fn environment_reader_reports_invalid_unicode_by_name_without_value() {
        let mut warnings = Vec::new();
        let overrides = ProxyEnvironmentOverrides::from_reader(
            |_| {
                Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                    "secret-environment-bytes",
                )))
            },
            |name| warnings.push(name.to_string()),
        );

        assert_eq!(overrides, ProxyEnvironmentOverrides::default());
        assert_eq!(
            warnings,
            [
                "STREMIO_ALLOW_PRIVATE_NETWORK_SOURCES",
                "STREMIO_ALLOW_INVALID_PROXY_TLS_CERTIFICATES",
            ]
        );
        assert!(
            warnings
                .iter()
                .all(|warning| !warning.contains("secret-environment-bytes"))
        );
    }

    #[tokio::test]
    async fn rename_commit_survives_a_parent_directory_sync_failure() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");
        let candidate = ServerSettings {
            cache_size: 654.0,
            ..ServerSettings::default()
        };

        let outcome = persist_settings_atomic_with_hooks(&path, &candidate, async {}, |_| async {
            Err(anyhow::anyhow!("injected parent sync failure"))
        })
        .await
        .unwrap();

        assert_eq!(
            outcome,
            SettingsPersistenceOutcome::CommittedWithDurabilityWarning
        );
        let disk: ServerSettings = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(disk.cache_size, 654.0);
    }

    #[test]
    fn device_info_shape_is_stable() {
        let value = compat_device_info(vec!["nvenc".into(), "nvenc:verified".into()]);
        assert_eq!(
            value,
            json!({
                "availableHardwareAccelerations": ["nvenc", "nvenc:verified"]
            })
        );
    }

    #[test]
    fn profiler_shape_is_stable() {
        assert_eq!(
            compat_profiler(vec!["qsv".into()]),
            json!({
                "success": true,
                "profiles": ["qsv"]
            })
        );
    }
}
