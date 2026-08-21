use crate::routes::system::ServerSettings;
use crate::{
    network_security::{
        DestinationValidator, ListenerBinding, ProxyPolicySettings, ProxyRuntime, SystemClock,
        SystemDnsResolver, SystemLocalNetworkProvider,
    },
    settings_control::SettingsControl,
};
use enginefs::EngineFS;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::local_addon::LocalIndex;

pub(crate) struct SettingsPersistenceCoordinator {
    raw: Arc<tokio::sync::Mutex<ServerSettings>>,
    supervisor: std::sync::Mutex<SettingsSupervisorState>,
    tasks: tokio_util::task::TaskTracker,
    active_transactions: Arc<std::sync::atomic::AtomicUsize>,
    idle_notify: Arc<tokio::sync::Notify>,
    next_tracker_sequence: std::sync::atomic::AtomicU64,
    #[cfg(test)]
    after_rename_gate: std::sync::Mutex<Option<Arc<SettingsPersistenceTestGate>>>,
    #[cfg(test)]
    tracker_before_lock_gate: std::sync::Mutex<Option<Arc<SettingsPersistenceTestGate>>>,
    #[cfg(test)]
    fail_parent_sync: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    before_final_side_effect_gate: std::sync::Mutex<Option<Arc<SettingsPersistenceTestGate>>>,
}

struct SettingsSupervisorState {
    closed: bool,
    latest_admitted_tracker_sequence: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("settings persistence coordinator is closed")]
pub(crate) struct SettingsCoordinatorClosed;

struct ActiveSettingsTransaction {
    active_transactions: Arc<std::sync::atomic::AtomicUsize>,
    idle_notify: Arc<tokio::sync::Notify>,
}

impl Drop for ActiveSettingsTransaction {
    fn drop(&mut self) {
        if self
            .active_transactions
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.idle_notify.notify_waiters();
        }
    }
}

#[cfg(test)]
pub(crate) struct SettingsPersistenceTestGate {
    reached: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
    reached_notify: tokio::sync::Notify,
    release_notify: tokio::sync::Notify,
}

#[cfg(test)]
impl SettingsPersistenceTestGate {
    fn new() -> Self {
        Self {
            reached: std::sync::atomic::AtomicBool::new(false),
            released: std::sync::atomic::AtomicBool::new(false),
            reached_notify: tokio::sync::Notify::new(),
            release_notify: tokio::sync::Notify::new(),
        }
    }

    pub(crate) async fn reach_and_wait(&self) {
        self.reached
            .store(true, std::sync::atomic::Ordering::Release);
        self.reached_notify.notify_waiters();
        while !self.released.load(std::sync::atomic::Ordering::Acquire) {
            let notified = self.release_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.released.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    pub(crate) async fn wait_reached(&self) {
        while !self.reached.load(std::sync::atomic::Ordering::Acquire) {
            let notified = self.reached_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.reached.load(std::sync::atomic::Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::Release);
        self.release_notify.notify_waiters();
    }
}

impl SettingsPersistenceCoordinator {
    pub(crate) fn new(raw: ServerSettings) -> Self {
        Self {
            raw: Arc::new(tokio::sync::Mutex::new(raw)),
            supervisor: std::sync::Mutex::new(SettingsSupervisorState {
                closed: false,
                latest_admitted_tracker_sequence: 0,
            }),
            tasks: tokio_util::task::TaskTracker::new(),
            active_transactions: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            idle_notify: Arc::new(tokio::sync::Notify::new()),
            next_tracker_sequence: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            after_rename_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            tracker_before_lock_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            fail_parent_sync: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            before_final_side_effect_gate: std::sync::Mutex::new(None),
        }
    }

    pub(crate) async fn lock(&self) -> tokio::sync::MutexGuard<'_, ServerSettings> {
        self.raw.lock().await
    }

    pub(crate) async fn lock_owned(
        self: &Arc<Self>,
    ) -> tokio::sync::OwnedMutexGuard<ServerSettings> {
        self.raw.clone().lock_owned().await
    }

    pub(crate) fn register_transaction<F>(
        &self,
        transaction: F,
    ) -> Result<tokio::sync::oneshot::Receiver<anyhow::Result<()>>, SettingsCoordinatorClosed>
    where
        F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.register_transaction_inner(None, transaction)
    }

    fn next_tracker_sequence(&self) -> u64 {
        self.next_tracker_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1
    }

    fn register_tracker_transaction<F>(
        &self,
        sequence: u64,
        transaction: F,
    ) -> Result<tokio::sync::oneshot::Receiver<anyhow::Result<()>>, SettingsCoordinatorClosed>
    where
        F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        self.register_transaction_inner(Some(sequence), transaction)
    }

    fn register_transaction_inner<F>(
        &self,
        tracker_sequence: Option<u64>,
        transaction: F,
    ) -> Result<tokio::sync::oneshot::Receiver<anyhow::Result<()>>, SettingsCoordinatorClosed>
    where
        F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let mut supervisor = self
            .supervisor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if supervisor.closed {
            tracing::error!("settings transaction failed");
            return Err(SettingsCoordinatorClosed);
        }
        if let Some(sequence) = tracker_sequence {
            supervisor.latest_admitted_tracker_sequence =
                supervisor.latest_admitted_tracker_sequence.max(sequence);
        }
        self.active_transactions
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let active = ActiveSettingsTransaction {
            active_transactions: self.active_transactions.clone(),
            idle_notify: self.idle_notify.clone(),
        };
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let task = self.tasks.spawn(async move {
            let _active = active;
            let result = transaction.await;
            if result.is_err() {
                tracing::error!("settings transaction failed");
            }
            let _ = completion_tx.send(result);
        });
        drop(task);
        Ok(completion_rx)
    }

    fn latest_admitted_tracker_sequence(&self) -> u64 {
        self.supervisor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .latest_admitted_tracker_sequence
    }

    pub(crate) fn close(&self) {
        let mut supervisor = self
            .supervisor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !supervisor.closed {
            supervisor.closed = true;
            self.tasks.close();
        }
    }

    pub(crate) async fn drain(&self) {
        self.tasks.wait().await;
    }

    #[cfg(test)]
    pub(crate) async fn wait_until_idle(&self) {
        loop {
            let notified = self.idle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .active_transactions
                .load(std::sync::atomic::Ordering::Acquire)
                == 0
            {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn persist_settings(
        &self,
        path: &std::path::Path,
        settings: &ServerSettings,
    ) -> anyhow::Result<crate::routes::system::SettingsPersistenceOutcome> {
        #[cfg(test)]
        {
            let gate = self
                .after_rename_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let fail_parent_sync = self
                .fail_parent_sync
                .swap(false, std::sync::atomic::Ordering::AcqRel);
            return crate::routes::system::persist_settings_atomic_with_hooks(
                path,
                settings,
                async move {
                    if let Some(gate) = gate {
                        gate.reach_and_wait().await;
                    }
                },
                move |_| async move {
                    if fail_parent_sync {
                        Err(anyhow::anyhow!("injected parent sync failure"))
                    } else {
                        Ok(())
                    }
                },
            )
            .await;
        }
        #[cfg(not(test))]
        crate::routes::system::persist_settings_atomic(path, settings).await
    }

    #[cfg(test)]
    pub(crate) fn gate_next_after_rename(&self) -> Arc<SettingsPersistenceTestGate> {
        let gate = Arc::new(SettingsPersistenceTestGate::new());
        let mut next = self
            .after_rename_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(next.replace(gate.clone()).is_none(), "gate already armed");
        gate
    }

    #[cfg(test)]
    pub(crate) fn gate_next_tracker_before_lock(&self) -> Arc<SettingsPersistenceTestGate> {
        let gate = Arc::new(SettingsPersistenceTestGate::new());
        let mut next = self
            .tracker_before_lock_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(next.replace(gate.clone()).is_none(), "gate already armed");
        gate
    }

    #[cfg(test)]
    pub(crate) fn fail_next_parent_sync(&self) {
        assert!(
            !self
                .fail_parent_sync
                .swap(true, std::sync::atomic::Ordering::AcqRel),
            "parent sync failure already armed"
        );
    }

    #[cfg(test)]
    pub(crate) fn gate_next_before_final_side_effect(&self) -> Arc<SettingsPersistenceTestGate> {
        let gate = Arc::new(SettingsPersistenceTestGate::new());
        let mut next = self
            .before_final_side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(next.replace(gate.clone()).is_none(), "gate already armed");
        gate
    }

    #[cfg(test)]
    pub(crate) fn take_before_final_side_effect_gate(
        &self,
    ) -> Option<Arc<SettingsPersistenceTestGate>> {
        self.before_final_side_effect_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    #[cfg(test)]
    fn take_tracker_before_lock_gate(&self) -> Option<Arc<SettingsPersistenceTestGate>> {
        self.tracker_before_lock_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    #[cfg(test)]
    pub(crate) async fn raw_snapshot(&self) -> ServerSettings {
        self.raw.lock().await.clone()
    }

    #[cfg(test)]
    pub(crate) fn active_transaction_count(&self) -> usize {
        self.active_transactions
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<EngineFS>,
    pub download_engine: Arc<EngineFS>,
    pub download_engine_disk_backed: bool,
    pub settings: Arc<RwLock<ServerSettings>>,
    pub settings_path: PathBuf,
    pub config_dir: PathBuf,
    pub log_dir: PathBuf,
    pub base_url: String,
    pub http_addr: SocketAddr,
    pub update_install_exit_enabled: bool,
    pub updater: Arc<crate::updater::UpdateManager>,
    pub local_index: LocalIndex,
    pub archive_cache: Arc<dashmap::DashMap<String, crate::archives::ArchiveSession>>,
    pub nzb_sessions: Arc<dashmap::DashMap<String, crate::archives::nzb::session::NzbSession>>,
    pub devices: Arc<RwLock<Vec<crate::ssdp::Device>>>,
    pub(crate) settings_control: SettingsControl,
    pub(crate) proxy_runtime: Arc<ProxyRuntime>,
    pub(crate) settings_persistence: Arc<SettingsPersistenceCoordinator>,
}

impl AppState {
    /// EngineFS that owns stream/HLS torrents: the disk-backed download engine when
    /// available, otherwise the memory-only engine. Mirrors the selection in
    /// `routes::stream` so HLS playback and the `/stream` loopback share one torrent
    /// instead of spinning up a redundant memory-only copy that never evicts pieces.
    pub fn stream_engine(&self) -> Arc<EngineFS> {
        if self.download_engine_disk_backed {
            self.download_engine.clone()
        } else {
            self.engine.clone()
        }
    }

    #[allow(unused)]
    pub fn new(engine: Arc<EngineFS>, settings: ServerSettings, config_dir: PathBuf) -> Self {
        let log_dir = config_dir.join("logs");
        Self::new_with_shared_settings_and_log_dir(
            engine,
            Arc::new(RwLock::new(settings)),
            config_dir,
            log_dir,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_raw_and_effective_settings(
        engine: Arc<EngineFS>,
        raw: ServerSettings,
        effective: ServerSettings,
        config_dir: PathBuf,
    ) -> Self {
        let mut state = Self::new(engine, effective, config_dir);
        state.settings_persistence = Arc::new(SettingsPersistenceCoordinator::new(raw));
        state
    }

    #[allow(unused)]
    pub fn new_with_shared_settings(
        engine: Arc<EngineFS>,
        settings: Arc<RwLock<ServerSettings>>,
        config_dir: PathBuf,
    ) -> Self {
        let log_dir = config_dir.join("logs");
        Self::new_with_shared_settings_and_log_dir(engine, settings, config_dir, log_dir)
    }

    pub fn new_with_shared_settings_and_log_dir(
        engine: Arc<EngineFS>,
        settings: Arc<RwLock<ServerSettings>>,
        config_dir: PathBuf,
        log_dir: PathBuf,
    ) -> Self {
        Self::new_with_shared_settings_log_dir_and_download_engine(
            engine.clone(),
            engine,
            false,
            settings,
            config_dir,
            log_dir,
        )
    }

    pub fn new_with_shared_settings_log_dir_and_download_engine(
        engine: Arc<EngineFS>,
        download_engine: Arc<EngineFS>,
        download_engine_disk_backed: bool,
        settings: Arc<RwLock<ServerSettings>>,
        config_dir: PathBuf,
        log_dir: PathBuf,
    ) -> Self {
        let settings_path = config_dir.join("settings.json");
        let updater = Arc::new(crate::updater::UpdateManager::new(config_dir.clone()));
        let initial_settings = settings
            .try_read()
            .expect("shared settings must be uncontended during AppState construction")
            .clone();
        let proxy_policy = ProxyPolicySettings {
            allow_private_network_sources: initial_settings.allow_private_network_sources,
            allow_invalid_proxy_tls_certificates: initial_settings
                .allow_invalid_proxy_tls_certificates,
        };
        let default_http_addr = SocketAddr::from(([127, 0, 0, 1], 11470));
        let validator = Arc::new(DestinationValidator::new(
            Arc::new(SystemDnsResolver),
            Arc::new(SystemLocalNetworkProvider),
            Arc::new(SystemClock),
            vec![ListenerBinding {
                socket: default_http_addr,
            }],
        ));

        Self {
            engine,
            download_engine,
            download_engine_disk_backed,
            settings,
            settings_path,
            config_dir,
            log_dir,
            base_url: "http://127.0.0.1:11470".to_string(),
            http_addr: default_http_addr,
            update_install_exit_enabled: true,
            updater,
            local_index: LocalIndex::new(),
            archive_cache: Arc::new(dashmap::DashMap::new()),
            nzb_sessions: Arc::new(dashmap::DashMap::new()),
            devices: Arc::new(RwLock::new(Vec::new())),
            settings_control: SettingsControl::ephemeral(),
            proxy_runtime: Arc::new(ProxyRuntime::new(proxy_policy, validator)),
            settings_persistence: Arc::new(SettingsPersistenceCoordinator::new(initial_settings)),
        }
    }

    pub async fn save_settings(&self) -> anyhow::Result<()> {
        let mut raw = self.settings_persistence.lock_owned().await;
        let live = self.settings.read().await.clone();
        let disk = crate::routes::system::preserve_raw_protected_settings(&live, &raw);
        let settings_path = self.settings_path.clone();
        let settings_persistence = self.settings_persistence.clone();
        let completion = self.settings_persistence.register_transaction(async move {
            settings_persistence
                .persist_settings(&settings_path, &disk)
                .await?;
            *raw = disk;
            tracing::info!("Settings saved to {:?}", settings_path);
            Ok(())
        })?;

        match completion.await {
            Ok(result) => result,
            Err(_) => {
                tracing::error!("settings transaction failed");
                Err(anyhow::anyhow!("settings transaction failed"))
            }
        }
    }

    pub(crate) fn load_raw_settings(
        config_dir: &std::path::Path,
        defaults: &ServerSettings,
    ) -> ServerSettings {
        let settings_path = config_dir.join("settings.json");

        if settings_path.exists()
            && let Ok(content) = std::fs::read_to_string(&settings_path)
            && let Ok(mut settings) = serde_json::from_str::<ServerSettings>(&content)
        {
            tracing::info!("Loaded settings from {:?}", settings_path);
            if settings.cache_root.is_empty() {
                settings.cache_root = defaults.cache_root.clone();
            }
            if settings.bt_max_connections == 0
                || settings.bt_max_connections
                    >= enginefs::backend::LEGACY_UNLIMITED_BT_MAX_CONNECTIONS
            {
                tracing::info!(
                    previous_bt_max_connections = settings.bt_max_connections,
                    normalized_bt_max_connections = enginefs::backend::DEFAULT_BT_MAX_CONNECTIONS,
                    "Normalizing legacy torrent connection setting for multi-client stability"
                );
                settings.bt_max_connections = enginefs::backend::DEFAULT_BT_MAX_CONNECTIONS;
            }
            return settings;
        }

        tracing::info!("Using default settings");
        defaults.clone()
    }

    pub fn load_settings(
        config_dir: &std::path::Path,
        defaults: &ServerSettings,
    ) -> ServerSettings {
        let mut settings = Self::load_raw_settings(config_dir, defaults);
        crate::routes::system::apply_proxy_environment_overrides(&mut settings);
        settings
    }
}

/// Wrapper for TrackerStorage that bridges sync trait with async AppState
/// This is created before EngineFS and passed to it for tracker persistence
pub struct TrackerStorageBridge {
    settings: Arc<RwLock<ServerSettings>>,
    settings_path: PathBuf,
    settings_persistence: Arc<SettingsPersistenceCoordinator>,
}

impl TrackerStorageBridge {
    #[allow(dead_code)] // Retained for embedders that construct the bridge directly.
    pub fn new(settings: Arc<RwLock<ServerSettings>>, settings_path: PathBuf) -> Self {
        Self::new_with_persistence(
            settings.clone(),
            settings_path,
            Arc::new(SettingsPersistenceCoordinator::new(
                settings
                    .try_read()
                    .expect(
                        "shared settings must be uncontended during tracker bridge construction",
                    )
                    .clone(),
            )),
        )
    }

    pub fn new_with_persistence(
        settings: Arc<RwLock<ServerSettings>>,
        settings_path: PathBuf,
        settings_persistence: Arc<SettingsPersistenceCoordinator>,
    ) -> Self {
        Self {
            settings,
            settings_path,
            settings_persistence,
        }
    }

    pub(crate) fn save_trackers_with_completion(
        &self,
        trackers: Vec<String>,
        timestamp: i64,
    ) -> tokio::sync::oneshot::Receiver<anyhow::Result<()>> {
        let settings = self.settings.clone();
        let settings_path = self.settings_path.clone();
        let settings_persistence = self.settings_persistence.clone();
        let sequence = settings_persistence.next_tracker_sequence();
        #[cfg(test)]
        let before_lock_gate = settings_persistence.take_tracker_before_lock_gate();
        let transaction_persistence = settings_persistence.clone();
        let transaction = async move {
            #[cfg(test)]
            if let Some(gate) = before_lock_gate {
                gate.reach_and_wait().await;
            }
            let mut raw = transaction_persistence.lock().await;
            if sequence < transaction_persistence.latest_admitted_tracker_sequence() {
                return Ok(());
            }
            let mut next = settings.read().await.clone();
            next.cached_trackers = trackers;
            next.trackers_last_updated = timestamp;
            let disk = crate::routes::system::preserve_raw_protected_settings(&next, &raw);
            transaction_persistence
                .persist_settings(&settings_path, &disk)
                .await?;
            *raw = disk;
            *settings.write().await = next;
            tracing::debug!("Saved cached trackers to settings");
            Ok(())
        };

        match settings_persistence.register_tracker_transaction(sequence, transaction) {
            Ok(completion) => completion,
            Err(error) => {
                let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
                let _ = completion_tx.send(Err(error.into()));
                completion_rx
            }
        }
    }
}

impl enginefs::TrackerStorage for TrackerStorageBridge {
    fn get_cached_trackers(&self) -> Vec<String> {
        // Use blocking_read for sync access from async context
        // This is safe because we're only reading small data
        let handle = tokio::runtime::Handle::try_current();
        match handle {
            Ok(h) => {
                // We're in an async context, use block_in_place
                tokio::task::block_in_place(|| {
                    h.block_on(async {
                        let settings = self.settings.read().await;
                        settings.cached_trackers.clone()
                    })
                })
            }
            Err(_) => {
                // Not in async context, shouldn't happen but return empty
                Vec::new()
            }
        }
    }

    fn get_last_updated(&self) -> i64 {
        let handle = tokio::runtime::Handle::try_current();
        match handle {
            Ok(h) => tokio::task::block_in_place(|| {
                h.block_on(async {
                    let settings = self.settings.read().await;
                    settings.trackers_last_updated
                })
            }),
            Err(_) => 0,
        }
    }

    fn get_source_url(&self) -> String {
        let handle = tokio::runtime::Handle::try_current();
        match handle {
            Ok(h) => tokio::task::block_in_place(|| {
                h.block_on(async {
                    let settings = self.settings.read().await;
                    settings.trackers_source_url.clone()
                })
            }),
            Err(_) => crate::routes::system::default_trackers_url(),
        }
    }

    fn save_trackers(&self, trackers: Vec<String>, timestamp: i64) {
        drop(self.save_trackers_with_completion(trackers, timestamp));
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, ServerSettings};
    use crate::{routes::system::update_settings, settings_control::SettingsMutationAuthority};
    use enginefs::EngineFS;
    use serde_json::json;
    use std::sync::Arc;

    #[derive(Clone)]
    struct TestLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for TestLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn explicit_save_preserves_raw_protected_values_under_effective_overrides() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let raw = ServerSettings {
            allow_private_network_sources: false,
            allow_invalid_proxy_tls_certificates: false,
            ..ServerSettings::default()
        };
        let mut effective = raw.clone();
        effective.allow_private_network_sources = true;
        effective.allow_invalid_proxy_tls_certificates = true;
        effective.cache_size = 321.0;
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            raw,
            effective,
            temp.path().join("config"),
        );

        state.save_settings().await.unwrap();

        let disk: ServerSettings = serde_json::from_slice(
            &std::fs::read(temp.path().join("config/settings.json")).unwrap(),
        )
        .unwrap();
        assert!(!disk.allow_private_network_sources);
        assert!(!disk.allow_invalid_proxy_tls_certificates);
        assert_eq!(disk.cache_size, 321.0);
        let committed_raw = state.settings_persistence.raw_snapshot().await;
        assert!(!committed_raw.allow_private_network_sources);
        assert!(!committed_raw.allow_invalid_proxy_tls_certificates);
        assert_eq!(committed_raw.cache_size, 321.0);
        let live = state.settings.read().await;
        assert!(live.allow_private_network_sources);
        assert!(live.allow_invalid_proxy_tls_certificates);
    }

    #[tokio::test]
    async fn http_updates_preserve_raw_values_for_same_effective_protected_fields() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let mut case_index = 0usize;
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
                    let config_dir = temp.path().join(format!("case-{case_index}"));
                    case_index += 1;
                    let state = AppState::new_with_raw_and_effective_settings(
                        engine.clone(),
                        raw,
                        effective,
                        config_dir,
                    );
                    let mut payload = json!({"cacheSize": 321.0});
                    payload
                        .as_object_mut()
                        .unwrap()
                        .insert(field.to_string(), json!(effective_value));

                    update_settings(&state, &payload, authority).await.unwrap();

                    let disk: ServerSettings =
                        serde_json::from_slice(&std::fs::read(&state.settings_path).unwrap())
                            .unwrap();
                    assert_eq!(disk.allow_private_network_sources, raw_value, "{field}");
                    assert_eq!(
                        disk.allow_invalid_proxy_tls_certificates, raw_value,
                        "{field}"
                    );
                    assert_eq!(disk.cache_size, 321.0, "{field}");
                    let committed_raw = state.settings_persistence.raw_snapshot().await;
                    assert_eq!(
                        committed_raw.allow_private_network_sources, raw_value,
                        "{field}"
                    );
                    assert_eq!(
                        committed_raw.allow_invalid_proxy_tls_certificates, raw_value,
                        "{field}"
                    );
                    let live = state.settings.read().await.clone();
                    assert_eq!(
                        live.allow_private_network_sources, effective_value,
                        "{field}"
                    );
                    assert_eq!(
                        live.allow_invalid_proxy_tls_certificates, effective_value,
                        "{field}"
                    );
                    assert_eq!(live.cache_size, 321.0, "{field}");
                    let request = state.proxy_runtime.try_request().unwrap();
                    assert_eq!(
                        request.settings.allow_private_network_sources, effective_value,
                        "{field}"
                    );
                    assert_eq!(
                        request.settings.allow_invalid_proxy_tls_certificates, effective_value,
                        "{field}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn tracker_saves_preserve_raw_protected_values_under_effective_overrides() {
        for (raw_value, effective_value) in [(false, true), (true, false)] {
            let temp = tempfile::tempdir().unwrap();
            let raw = ServerSettings {
                allow_private_network_sources: raw_value,
                allow_invalid_proxy_tls_certificates: raw_value,
                ..ServerSettings::default()
            };
            let mut effective = raw.clone();
            effective.allow_private_network_sources = effective_value;
            effective.allow_invalid_proxy_tls_certificates = effective_value;
            let settings = Arc::new(tokio::sync::RwLock::new(effective));
            let persistence = Arc::new(super::SettingsPersistenceCoordinator::new(raw));
            let settings_path = temp.path().join("settings.json");
            let bridge = super::TrackerStorageBridge::new_with_persistence(
                settings.clone(),
                settings_path.clone(),
                persistence.clone(),
            );

            bridge
                .save_trackers_with_completion(vec!["udp://tracker.example".to_string()], 123)
                .await
                .unwrap()
                .unwrap();

            let disk: ServerSettings =
                serde_json::from_slice(&std::fs::read(settings_path).unwrap()).unwrap();
            assert_eq!(disk.allow_private_network_sources, raw_value);
            assert_eq!(disk.allow_invalid_proxy_tls_certificates, raw_value);
            assert_eq!(disk.cached_trackers, ["udp://tracker.example"]);
            assert_eq!(disk.trackers_last_updated, 123);
            let committed_raw = persistence.raw_snapshot().await;
            assert_eq!(committed_raw.allow_private_network_sources, raw_value);
            assert_eq!(
                committed_raw.allow_invalid_proxy_tls_certificates,
                raw_value
            );
            let live = settings.read().await;
            assert_eq!(live.allow_private_network_sources, effective_value);
            assert_eq!(live.allow_invalid_proxy_tls_certificates, effective_value);
            assert_eq!(live.cached_trackers, ["udp://tracker.example"]);
            assert_eq!(live.trackers_last_updated, 123);
        }
    }

    #[tokio::test]
    async fn older_tracker_save_cannot_overwrite_a_newer_admitted_save() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Arc::new(tokio::sync::RwLock::new(ServerSettings::default()));
        let persistence = Arc::new(super::SettingsPersistenceCoordinator::new(
            ServerSettings::default(),
        ));
        let bridge = super::TrackerStorageBridge::new_with_persistence(
            settings.clone(),
            temp.path().join("settings.json"),
            persistence.clone(),
        );
        let older_gate = persistence.gate_next_tracker_before_lock();
        let older = bridge.save_trackers_with_completion(vec!["udp://older".to_string()], 1);
        older_gate.wait_reached().await;

        let newer = bridge.save_trackers_with_completion(vec!["udp://newer".to_string()], 2);
        newer.await.unwrap().unwrap();
        older_gate.release();
        older.await.unwrap().unwrap();

        let disk: ServerSettings =
            serde_json::from_slice(&std::fs::read(temp.path().join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(disk.cached_trackers, ["udp://newer"]);
        assert_eq!(disk.trackers_last_updated, 2);
        let raw = persistence.raw_snapshot().await;
        assert_eq!(raw.cached_trackers, ["udp://newer"]);
        assert_eq!(raw.trackers_last_updated, 2);
        let live = settings.read().await;
        assert_eq!(live.cached_trackers, ["udp://newer"]);
        assert_eq!(live.trackers_last_updated, 2);
    }

    #[tokio::test]
    async fn rejected_newer_tracker_save_does_not_stale_an_admitted_save() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Arc::new(tokio::sync::RwLock::new(ServerSettings::default()));
        let persistence = Arc::new(super::SettingsPersistenceCoordinator::new(
            ServerSettings::default(),
        ));
        let bridge = super::TrackerStorageBridge::new_with_persistence(
            settings.clone(),
            temp.path().join("settings.json"),
            persistence.clone(),
        );
        let admitted_gate = persistence.gate_next_tracker_before_lock();
        let admitted = bridge.save_trackers_with_completion(vec!["udp://admitted".to_string()], 1);
        admitted_gate.wait_reached().await;

        persistence.close();
        let rejected = bridge.save_trackers_with_completion(vec!["udp://rejected".to_string()], 2);
        assert!(rejected.await.unwrap().is_err());
        admitted_gate.release();
        admitted.await.unwrap().unwrap();
        persistence.drain().await;

        let disk: ServerSettings =
            serde_json::from_slice(&std::fs::read(temp.path().join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(disk.cached_trackers, ["udp://admitted"]);
        assert_eq!(disk.trackers_last_updated, 1);
        assert_eq!(settings.read().await.cached_trackers, ["udp://admitted"]);
    }

    #[tokio::test]
    async fn failed_newer_tracker_save_does_not_resurrect_an_older_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let settings_path = temp.path().join("settings.json");
        std::fs::create_dir(&settings_path).unwrap();
        let settings = Arc::new(tokio::sync::RwLock::new(ServerSettings::default()));
        let persistence = Arc::new(super::SettingsPersistenceCoordinator::new(
            ServerSettings::default(),
        ));
        let bridge = super::TrackerStorageBridge::new_with_persistence(
            settings.clone(),
            settings_path.clone(),
            persistence.clone(),
        );
        let older_gate = persistence.gate_next_tracker_before_lock();
        let older = bridge.save_trackers_with_completion(vec!["udp://older".to_string()], 1);
        older_gate.wait_reached().await;

        let failed_newer = bridge.save_trackers_with_completion(vec!["udp://newer".to_string()], 2);
        assert!(failed_newer.await.unwrap().is_err());
        older_gate.release();
        older.await.unwrap().unwrap();

        assert!(settings_path.is_dir());
        assert!(settings.read().await.cached_trackers.is_empty());
        assert!(persistence.raw_snapshot().await.cached_trackers.is_empty());
    }

    #[tokio::test]
    async fn coordinator_close_rejects_new_work_and_drain_waits_for_admitted_work() {
        let coordinator = Arc::new(super::SettingsPersistenceCoordinator::new(
            ServerSettings::default(),
        ));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let admitted = coordinator
            .register_transaction(async move {
                let _ = release_rx.await;
                Ok(())
            })
            .unwrap();

        coordinator.close();
        assert!(coordinator.register_transaction(async { Ok(()) }).is_err());
        let drain = coordinator.drain();
        tokio::pin!(drain);
        assert!(futures_util::poll!(&mut drain).is_pending());

        release_tx.send(()).unwrap();
        drain.await;
        admitted.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn caller_abort_after_rename_cannot_split_disk_raw_live_and_proxy_policy() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            ServerSettings::default(),
            ServerSettings::default(),
            temp.path().join("config"),
        );
        let gate = state.settings_persistence.gate_next_after_rename();
        let worker_state = state.clone();
        let caller = tokio::spawn(async move {
            update_settings(
                &worker_state,
                &json!({
                    "allowPrivateNetworkSources": true,
                    "cacheSize": 777.0,
                }),
                SettingsMutationAuthority::TrustedLocal,
            )
            .await
        });
        gate.wait_reached().await;

        caller.abort();
        gate.release();
        assert!(caller.await.unwrap_err().is_cancelled());
        state.settings_persistence.wait_until_idle().await;

        let disk: ServerSettings =
            serde_json::from_slice(&std::fs::read(&state.settings_path).unwrap()).unwrap();
        assert!(disk.allow_private_network_sources);
        assert_eq!(disk.cache_size, 777.0);
        let raw = state.settings_persistence.raw_snapshot().await;
        assert!(raw.allow_private_network_sources);
        assert_eq!(raw.cache_size, 777.0);
        let live = state.settings.read().await;
        assert!(live.allow_private_network_sources);
        assert_eq!(live.cache_size, 777.0);
        let request = state.proxy_runtime.try_request().unwrap();
        assert!(request.settings.allow_private_network_sources);
    }

    #[tokio::test]
    async fn explicit_save_caller_abort_after_rename_still_commits_raw_state() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            ServerSettings::default(),
            ServerSettings::default(),
            temp.path().join("config"),
        );
        state.settings.write().await.cache_size = 888.0;
        let gate = state.settings_persistence.gate_next_after_rename();
        let worker_state = state.clone();
        let caller = tokio::spawn(async move { worker_state.save_settings().await });
        gate.wait_reached().await;

        caller.abort();
        gate.release();
        assert!(caller.await.unwrap_err().is_cancelled());
        state.settings_persistence.wait_until_idle().await;

        let disk: ServerSettings =
            serde_json::from_slice(&std::fs::read(&state.settings_path).unwrap()).unwrap();
        assert_eq!(disk.cache_size, 888.0);
        assert_eq!(
            state.settings_persistence.raw_snapshot().await.cache_size,
            888.0
        );
        assert_eq!(state.settings.read().await.cache_size, 888.0);
    }

    #[tokio::test]
    async fn post_rename_durability_warning_is_committed_by_all_settings_writers() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            ServerSettings::default(),
            ServerSettings::default(),
            temp.path().join("config"),
        );

        state.settings.write().await.cache_size = 101.0;
        state.settings_persistence.fail_next_parent_sync();
        state.save_settings().await.unwrap();
        assert_eq!(
            state.settings_persistence.raw_snapshot().await.cache_size,
            101.0
        );

        state.settings_persistence.fail_next_parent_sync();
        update_settings(
            &state,
            &json!({
                "cacheSize": 202.0,
                "allowPrivateNetworkSources": true,
            }),
            SettingsMutationAuthority::TrustedLocal,
        )
        .await
        .unwrap();
        assert!(
            state
                .proxy_runtime
                .try_request()
                .unwrap()
                .settings
                .allow_private_network_sources
        );

        let bridge = super::TrackerStorageBridge::new_with_persistence(
            state.settings.clone(),
            state.settings_path.clone(),
            state.settings_persistence.clone(),
        );
        state.settings_persistence.fail_next_parent_sync();
        bridge
            .save_trackers_with_completion(vec!["udp://committed".to_string()], 303)
            .await
            .unwrap()
            .unwrap();

        let disk: ServerSettings =
            serde_json::from_slice(&std::fs::read(&state.settings_path).unwrap()).unwrap();
        assert_eq!(disk.cache_size, 202.0);
        assert!(disk.allow_private_network_sources);
        assert_eq!(disk.cached_trackers, ["udp://committed"]);
        assert_eq!(disk.trackers_last_updated, 303);
        let raw = state.settings_persistence.raw_snapshot().await;
        assert_eq!(raw.cache_size, 202.0);
        assert!(raw.allow_private_network_sources);
        assert_eq!(raw.cached_trackers, ["udp://committed"]);
        let live = state.settings.read().await;
        assert_eq!(live.cache_size, 202.0);
        assert_eq!(live.cached_trackers, ["udp://committed"]);
    }

    #[tokio::test]
    async fn caller_cancelled_while_waiting_for_settings_guard_is_never_admitted() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            ServerSettings::default(),
            ServerSettings::default(),
            temp.path().join("config"),
        );
        let guard = state.settings_persistence.lock().await;
        let worker_state = state.clone();
        let caller = tokio::spawn(async move {
            update_settings(
                &worker_state,
                &json!({"cacheSize": 444.0}),
                SettingsMutationAuthority::TrustedLocal,
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(state.settings_persistence.active_transaction_count(), 0);

        caller.abort();
        drop(guard);
        assert!(caller.await.unwrap_err().is_cancelled());
        state.settings_persistence.wait_until_idle().await;
        assert!(!state.settings_path.exists());
        assert_eq!(state.settings.read().await.cache_size, 10_737_418_240.0);
        assert_eq!(
            state.settings_persistence.raw_snapshot().await.cache_size,
            10_737_418_240.0
        );
    }

    #[tokio::test]
    async fn transaction_guard_is_held_through_the_final_seeding_side_effect() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            ServerSettings::default(),
            ServerSettings::default(),
            temp.path().join("config"),
        );
        let final_side_effect = state
            .settings_persistence
            .gate_next_before_final_side_effect();
        let first_state = state.clone();
        let first = tokio::spawn(async move {
            update_settings(
                &first_state,
                &json!({"cacheSize": 111.0, "seedingEnabled": false}),
                SettingsMutationAuthority::TrustedLocal,
            )
            .await
        });
        final_side_effect.wait_reached().await;
        assert_eq!(state.settings_persistence.active_transaction_count(), 1);
        assert_eq!(state.settings.read().await.cache_size, 111.0);
        assert!(!state.engine.seeding_enabled());

        let second_state = state.clone();
        let second = tokio::spawn(async move {
            update_settings(
                &second_state,
                &json!({"cacheSize": 222.0, "seedingEnabled": true}),
                SettingsMutationAuthority::TrustedLocal,
            )
            .await
        });
        tokio::task::yield_now().await;
        assert_eq!(state.settings_persistence.active_transaction_count(), 1);
        assert!(!second.is_finished());

        final_side_effect.release();
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        assert_eq!(state.settings_persistence.active_transaction_count(), 0);
        assert_eq!(state.settings.read().await.cache_size, 222.0);
        assert!(state.engine.seeding_enabled());
        assert_eq!(
            state.settings_persistence.raw_snapshot().await.cache_size,
            222.0
        );
        let disk: ServerSettings =
            serde_json::from_slice(&std::fs::read(&state.settings_path).unwrap()).unwrap();
        assert_eq!(disk.cache_size, 222.0);
        assert!(disk.seeding_enabled);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_transactions_log_one_fixed_category_even_without_a_waiter() {
        let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = TestLogWriter(logs.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_writer(move || writer.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let coordinator = Arc::new(super::SettingsPersistenceCoordinator::new(
            ServerSettings::default(),
        ));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let completion = coordinator
            .register_transaction(async move {
                let _ = release_rx.await;
                Err(anyhow::anyhow!(
                    "secret-source-error token-marker payload-marker"
                ))
            })
            .unwrap();
        drop(completion);
        release_tx.send(()).unwrap();
        coordinator.close();
        coordinator.drain().await;

        let completed_before_drop = Arc::new(super::SettingsPersistenceCoordinator::new(
            ServerSettings::default(),
        ));
        let completion = completed_before_drop
            .register_transaction(async {
                Err(anyhow::anyhow!(
                    "second-secret-source token-marker payload-marker"
                ))
            })
            .unwrap();
        completed_before_drop.wait_until_idle().await;
        drop(completion);
        completed_before_drop.close();
        completed_before_drop.drain().await;

        let output = String::from_utf8(
            logs.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .unwrap();
        assert_eq!(output.matches("settings transaction failed").count(), 2);
        for secret in [
            "secret-source-error",
            "second-secret-source",
            "token-marker",
            "payload-marker",
        ] {
            assert!(!output.contains(secret));
        }
    }

    #[tokio::test]
    async fn http_and_tracker_updates_serialize_without_losing_unrelated_changes() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        for iteration in 0..25 {
            let raw = ServerSettings {
                allow_private_network_sources: false,
                ..ServerSettings::default()
            };
            let mut effective = raw.clone();
            effective.allow_private_network_sources = true;
            let state = AppState::new_with_raw_and_effective_settings(
                engine.clone(),
                raw,
                effective,
                temp.path().join(format!("race-{iteration}")),
            );
            let bridge = super::TrackerStorageBridge::new_with_persistence(
                state.settings.clone(),
                state.settings_path.clone(),
                state.settings_persistence.clone(),
            );
            let first_gate = state.settings_persistence.gate_next_after_rename();
            let cache_size = 500.0 + iteration as f64;
            let tracker = format!("udp://tracker-{iteration}");

            if iteration % 2 == 0 {
                let worker_state = state.clone();
                let http = tokio::spawn(async move {
                    update_settings(
                        &worker_state,
                        &json!({"cacheSize": cache_size}),
                        SettingsMutationAuthority::TrustedLocal,
                    )
                    .await
                });
                first_gate.wait_reached().await;
                let trackers =
                    bridge.save_trackers_with_completion(vec![tracker.clone()], iteration as i64);
                tokio::task::yield_now().await;
                first_gate.release();
                http.await.unwrap().unwrap();
                trackers.await.unwrap().unwrap();
            } else {
                let trackers =
                    bridge.save_trackers_with_completion(vec![tracker.clone()], iteration as i64);
                first_gate.wait_reached().await;
                let worker_state = state.clone();
                let http = tokio::spawn(async move {
                    update_settings(
                        &worker_state,
                        &json!({"cacheSize": cache_size}),
                        SettingsMutationAuthority::TrustedLocal,
                    )
                    .await
                });
                tokio::task::yield_now().await;
                first_gate.release();
                trackers.await.unwrap().unwrap();
                http.await.unwrap().unwrap();
            }

            let disk: ServerSettings =
                serde_json::from_slice(&std::fs::read(&state.settings_path).unwrap()).unwrap();
            assert_eq!(disk.cache_size, cache_size, "iteration {iteration}");
            assert_eq!(
                disk.cached_trackers.as_slice(),
                std::slice::from_ref(&tracker),
                "iteration {iteration}"
            );
            assert!(!disk.allow_private_network_sources, "iteration {iteration}");
            let raw = state.settings_persistence.raw_snapshot().await;
            assert_eq!(raw.cache_size, cache_size, "iteration {iteration}");
            assert_eq!(
                raw.cached_trackers.as_slice(),
                std::slice::from_ref(&tracker),
                "iteration {iteration}"
            );
            assert!(!raw.allow_private_network_sources, "iteration {iteration}");
            let live = state.settings.read().await;
            assert_eq!(live.cache_size, cache_size, "iteration {iteration}");
            assert_eq!(live.cached_trackers, [tracker], "iteration {iteration}");
            assert!(live.allow_private_network_sources, "iteration {iteration}");
        }
    }

    #[tokio::test]
    async fn shutdown_rejects_http_direct_and_tracker_settings_writers() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_raw_and_effective_settings(
            engine,
            ServerSettings::default(),
            ServerSettings::default(),
            temp.path().join("config"),
        );
        let bridge = super::TrackerStorageBridge::new_with_persistence(
            state.settings.clone(),
            state.settings_path.clone(),
            state.settings_persistence.clone(),
        );
        state.settings_persistence.close();

        assert!(state.save_settings().await.is_err());
        assert!(matches!(
            update_settings(
                &state,
                &json!({"cacheSize": 909.0}),
                SettingsMutationAuthority::TrustedLocal,
            )
            .await,
            Err(crate::routes::system::SettingsUpdateError::Persistence(_))
        ));
        assert!(
            bridge
                .save_trackers_with_completion(vec!["udp://rejected".to_string()], 1)
                .await
                .unwrap()
                .is_err()
        );
        state.settings_persistence.drain().await;

        assert!(!state.settings_path.exists());
        assert_eq!(state.settings.read().await.cache_size, 10_737_418_240.0);
        assert!(state.settings.read().await.cached_trackers.is_empty());
        assert_eq!(state.settings_persistence.active_transaction_count(), 0);
    }
}
