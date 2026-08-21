pub mod logging;

use std::{
    collections::{HashSet, VecDeque},
    io::{BufRead, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Instant,
};

use axum::{
    Json,
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::json;
use sysinfo::{Pid, System};

use crate::state::AppState;

const MAX_DIAGNOSTICS_LOG_FILE_LENGTH: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct LocalOnly;

impl IntoResponse for LocalOnly {
    fn into_response(self) -> Response {
        (StatusCode::FORBIDDEN, "Diagnostics are local-only").into_response()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessMemorySnapshot {
    pub pid: u32,
    pub rss_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub thread_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemorySnapshot {
    pub process: ProcessMemorySnapshot,
    pub engine: enginefs::EngineDiagnosticsSnapshot,
    pub download_engine: enginefs::EngineDiagnosticsSnapshot,
    pub download_disk_cache_bytes: u64,
    pub download_disk_cache_files: u64,
    pub active_disk_downloads: u64,
    pub disk_download_root: String,
    pub download_storage_mode: &'static str,
    pub download_disk_backed_available: bool,
    pub archive_session_count: usize,
    pub nzb_session_count: usize,
    pub active_direct_streams: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrashDumpInfo {
    pub path: String,
    pub bytes: u64,
    pub modified_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogFileInfo {
    pub path: String,
    pub name: String,
    pub bytes: u64,
    pub modified_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogsSnapshot {
    pub log_dir: String,
    pub current_human_log: Option<String>,
    pub current_json_log: Option<String>,
    pub recent_logs: Vec<LogFileInfo>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CurrentLogQuery {
    pub format: Option<String>,
    pub lines: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CurrentLogTail {
    pub path: Option<String>,
    pub lines: Vec<String>,
    pub content: String,
}

pub fn process_memory_snapshot() -> ProcessMemorySnapshot {
    let pid_u32 = std::process::id();
    let mut system = System::new_all();
    system.refresh_all();

    let process = system.process(Pid::from_u32(pid_u32));
    ProcessMemorySnapshot {
        pid: pid_u32,
        rss_bytes: process.map(|process| process.memory()).unwrap_or(0),
        virtual_memory_bytes: process.map(|process| process.virtual_memory()).unwrap_or(0),
        thread_count: current_thread_count(),
    }
}

fn current_thread_count() -> u64 {
    current_thread_count_impl()
}

#[cfg(windows)]
fn current_thread_count_impl() -> u64 {
    use windows::Win32::{
        Foundation::CloseHandle,
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
    };

    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) else {
            return 0;
        };

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let pid = std::process::id();
        let mut count = 0u64;

        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    count += 1;
                }

                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        count
    }
}

#[cfg(not(windows))]
fn current_thread_count_impl() -> u64 {
    0
}

async fn memory_snapshot_for_state(state: &AppState) -> MemorySnapshot {
    let stream_engine = state.stream_engine();
    let stream_engine_snapshot = stream_engine.diagnostics_snapshot().await;
    let download_engine = state.download_engine.diagnostics_snapshot().await;
    let (download_disk_cache_bytes, download_disk_cache_files) =
        disk_tree_stats(&state.download_engine.download_dir);
    let mut active_disk_files = HashSet::new();
    for stream in &download_engine.streams.active_file_streams {
        if stream.count > 0 {
            active_disk_files.insert((stream.info_hash.clone(), stream.file_idx));
        }
    }
    for lease in &download_engine.streams.active_playback_leases {
        active_disk_files.insert((lease.info_hash.clone(), lease.file_idx));
    }
    for selection in &download_engine.streams.active_multifile_selections {
        active_disk_files.insert((selection.info_hash.clone(), selection.file_idx));
    }
    let active_disk_downloads = active_disk_files.len() as u64;

    MemorySnapshot {
        process: process_memory_snapshot(),
        engine: stream_engine_snapshot,
        download_engine,
        download_disk_cache_bytes,
        download_disk_cache_files,
        active_disk_downloads,
        disk_download_root: state.download_engine.download_dir.display().to_string(),
        download_storage_mode: "dynamic",
        download_disk_backed_available: state.download_engine_disk_backed,
        archive_session_count: state.archive_cache.len(),
        nzb_session_count: state.nzb_sessions.len(),
        active_direct_streams: logging::active_direct_streams(),
    }
}

fn disk_tree_stats(root: &std::path::Path) -> (u64, u64) {
    if !root.exists() {
        return (0, 0);
    }

    let mut bytes = 0u64;
    let mut files = 0u64;
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry
            .path()
            .components()
            .any(|component| component.as_os_str() == ".metadata")
        {
            continue;
        }
        if let Ok(metadata) = entry.metadata() {
            bytes = bytes.saturating_add(metadata.len());
            files = files.saturating_add(1);
        }
    }
    (bytes, files)
}

pub fn start_memory_sampler(state: AppState) -> tokio::task::JoinHandle<()> {
    logging::spawn_logged("memory-sampler", async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        let mut last_snapshot_log = Instant::now()
            .checked_sub(logging::MEMORY_SNAPSHOT_INTERVAL)
            .unwrap_or_else(Instant::now);
        let mut last_rss = 0u64;

        loop {
            interval.tick().await;
            let snapshot = memory_snapshot_for_state(&state).await;
            let rss = snapshot.process.rss_bytes;
            let growth = rss.saturating_sub(last_rss);
            let should_log_periodic =
                last_snapshot_log.elapsed() >= logging::MEMORY_SNAPSHOT_INTERVAL;
            let should_log_growth = growth >= logging::MEMORY_GROWTH_ALERT_BYTES;

            if should_log_periodic || should_log_growth {
                tracing::info!(
                    rss_bytes = snapshot.process.rss_bytes,
                    virtual_memory_bytes = snapshot.process.virtual_memory_bytes,
                    thread_count = snapshot.process.thread_count,
                    engine_count = snapshot.engine.streams.engine_count,
                    engine_active_streams = snapshot.engine.streams.engine_active_streams,
                    active_file_priority_generation =
                        snapshot.engine.streams.active_file_priority_generation,
                    active_stream_hashes = snapshot.engine.streams.active_streams.len(),
                    active_file_streams = snapshot.engine.streams.active_file_streams.len(),
                    active_multifile_selections =
                        snapshot.engine.streams.active_multifile_selections.len(),
                    idle_paused_torrents = snapshot.engine.streams.idle_paused_torrents.len(),
                    download_active_multifile_selections =
                        snapshot.download_engine.streams.active_multifile_selections.len(),
                    download_idle_paused_torrents =
                        snapshot.download_engine.streams.idle_paused_torrents.len(),
                    rust_piece_cache_entries = snapshot.engine.memory.rust_piece_cache_entries,
                    rust_piece_cache_bytes = snapshot.engine.memory.rust_piece_cache_bytes,
                    native_storage_bytes = snapshot.engine.memory.native_storage_bytes,
                    native_storage_pieces = snapshot.engine.memory.native_storage_pieces,
                    download_disk_cache_bytes = snapshot.download_disk_cache_bytes,
                    download_disk_cache_files = snapshot.download_disk_cache_files,
                    active_disk_downloads = snapshot.active_disk_downloads,
                    disk_download_root = %snapshot.disk_download_root,
                    download_storage_mode = snapshot.download_storage_mode,
                    download_disk_backed_available = snapshot.download_disk_backed_available,
                    waiter_keys = snapshot.engine.memory.waiter_keys,
                    waiter_wakers = snapshot.engine.memory.waiter_wakers,
                    archive_session_count = snapshot.archive_session_count,
                    nzb_session_count = snapshot.nzb_session_count,
                    active_direct_streams = snapshot.active_direct_streams,
                    growth_bytes = growth,
                    growth_alert = should_log_growth,
                    "memory diagnostics snapshot"
                );
                last_snapshot_log = Instant::now();
                last_rss = rss;
            }
        }
    })
}

pub async fn memory(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(response) = ensure_local(addr) {
        return response.into_response();
    }

    Json(memory_snapshot_for_state(&state).await).into_response()
}

pub async fn streams(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(response) = ensure_local(addr) {
        return response.into_response();
    }

    Json(state.stream_engine().stream_activity_snapshot().await).into_response()
}

pub async fn crashes(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(response) = ensure_local(addr) {
        return response.into_response();
    }

    Json(list_crashes(&state)).into_response()
}

pub async fn logs(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(response) = ensure_local(addr) {
        return response.into_response();
    }

    Json(logs_snapshot(&state)).into_response()
}

pub async fn current_log(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(query): Query<CurrentLogQuery>,
) -> Response {
    if let Err(response) = ensure_local(addr) {
        return response.into_response();
    }

    let lines = query.lines.unwrap_or(500).clamp(1, 5000);
    let path = match query.format.as_deref() {
        Some("json") | Some("jsonl") => latest_log_with_extension(&state.log_dir, "jsonl"),
        _ => {
            let current = state.log_dir.join("server_current.log");
            if current.exists() {
                Some(current)
            } else {
                latest_log_with_extension(&state.log_dir, "log")
            }
        }
    };

    let Some(path) = path else {
        return Json(CurrentLogTail {
            path: None,
            lines: Vec::new(),
            content: String::new(),
        })
        .into_response();
    };

    match tail_lines(&path, lines) {
        Ok(lines) => {
            let content = lines.join("\n");
            Json(CurrentLogTail {
                path: Some(path.display().to_string()),
                lines,
                content,
            })
            .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to read log: {err}"),
        )
            .into_response(),
    }
}

pub async fn export(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Err(response) = ensure_local(addr) {
        return response.into_response();
    }

    match build_diagnostics_zip(&state) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/zip"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"stream-server-diagnostics.zip\"",
                ),
            ],
            Body::from(bytes),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to export diagnostics: {err}"),
        )
            .into_response(),
    }
}

fn ensure_local(addr: SocketAddr) -> Result<(), LocalOnly> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(LocalOnly)
    }
}

pub(crate) fn logs_snapshot(state: &AppState) -> LogsSnapshot {
    let current_human = state.log_dir.join("server_current.log");
    let current_human_log = current_human
        .exists()
        .then(|| current_human.display().to_string());
    let current_json_log =
        latest_log_with_extension(&state.log_dir, "jsonl").map(|path| path.display().to_string());

    LogsSnapshot {
        log_dir: state.log_dir.display().to_string(),
        current_human_log,
        current_json_log,
        recent_logs: recent_log_files(&state.log_dir, 30),
    }
}

fn recent_log_files(log_dir: &Path, limit: usize) -> Vec<LogFileInfo> {
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return Vec::new();
    };

    let mut logs = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let extension = path.extension().and_then(|ext| ext.to_str())?;
            if !matches!(extension, "log" | "jsonl" | "dmp") {
                return None;
            }

            let metadata = entry.metadata().ok()?;
            let modified_unix_secs = modified_unix_secs(&metadata);
            Some(LogFileInfo {
                name: path.file_name()?.to_string_lossy().to_string(),
                path: path.display().to_string(),
                bytes: metadata.len(),
                modified_unix_secs,
            })
        })
        .collect::<Vec<_>>();

    logs.sort_by_key(|log| std::cmp::Reverse(log.modified_unix_secs));
    logs.truncate(limit);
    logs
}

pub(crate) fn latest_log_with_extension(log_dir: &Path, extension: &str) -> Option<PathBuf> {
    recent_log_files(log_dir, usize::MAX)
        .into_iter()
        .find(|info| {
            Path::new(&info.path)
                .extension()
                .and_then(|ext| ext.to_str())
                == Some(extension)
        })
        .map(|info| PathBuf::from(info.path))
}

pub(crate) fn tail_lines(path: &Path, max_lines: usize) -> std::io::Result<Vec<String>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut lines = VecDeque::with_capacity(max_lines.min(1024));

    for line in reader.lines() {
        if lines.len() == max_lines {
            lines.pop_front();
        }
        lines.push_back(line?);
    }

    Ok(lines.into_iter().collect())
}

pub(crate) fn build_diagnostics_zip(state: &AppState) -> anyhow::Result<Vec<u8>> {
    build_diagnostics_zip_with_log_hook(state, |_| {})
}

fn build_diagnostics_zip_with_log_hook<F>(
    state: &AppState,
    mut after_log_open: F,
) -> anyhow::Result<Vec<u8>>
where
    F: FnMut(&Path),
{
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut exported_logs = 0usize;
    for info in recent_log_files(&state.log_dir, usize::MAX)
        .into_iter()
        .filter(|info| {
            matches!(
                Path::new(&info.path)
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("log" | "jsonl")
            )
        })
    {
        if exported_logs == 20 {
            break;
        }
        let path = PathBuf::from(&info.path);
        let Ok(bytes) = crate::safe_file::read_regular_file_no_follow(
            &path,
            MAX_DIAGNOSTICS_LOG_FILE_LENGTH,
            None,
            || after_log_open(&path),
        ) else {
            continue;
        };
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "log".to_string());
        zip.start_file(format!("logs/{name}"), options)?;
        zip.write_all(&bytes)?;
        exported_logs += 1;
    }

    if let Ok(settings) = std::fs::read_to_string(&state.settings_path) {
        zip.start_file("settings.redacted.json", options)?;
        zip.write_all(redact_settings_json(&settings).as_bytes())?;
    }

    let manifest = json!({
        "serverVersion": env!("CARGO_PKG_VERSION"),
        "gitSha": option_env!("GIT_SHA").unwrap_or("unknown"),
        "processId": std::process::id(),
        "logDir": state.log_dir.display().to_string(),
        "settingsPath": state.settings_path.display().to_string(),
    });
    zip.start_file("manifest.json", options)?;
    zip.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;

    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

fn redact_settings_json(raw: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return "{}".to_string();
    };

    if let Some(obj) = value.as_object_mut() {
        for key in [
            "btProxyPassword",
            "btProxyUsername",
            "remoteHttps",
            "cachedTrackers",
        ] {
            if obj.contains_key(key) {
                obj.insert(
                    key.to_string(),
                    serde_json::Value::String("<redacted>".to_string()),
                );
            }
        }
    }

    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

fn list_crashes(state: &AppState) -> Vec<CrashDumpInfo> {
    let crash_dir = state.log_dir.join("crashes");
    let Ok(entries) = std::fs::read_dir(crash_dir) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("dmp") {
                return None;
            }

            let metadata = entry.metadata().ok()?;
            Some(CrashDumpInfo {
                path: path.display().to_string(),
                bytes: metadata.len(),
                modified_unix_secs: modified_unix_secs(&metadata),
            })
        })
        .collect()
}

fn modified_unix_secs(metadata: &std::fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use enginefs::EngineFS;
    use std::{io::Read, sync::Arc};

    #[tokio::test]
    async fn diagnostics_export_excludes_opaque_dump_files_and_scans_decompressed_bytes() {
        let _engine_test_guard = crate::TEST_ENGINE_MUTEX.lock().await;
        let temp = tempfile::tempdir().unwrap();
        let log_dir = temp.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        let token = "a".repeat(64);
        std::fs::write(log_dir.join("proof.dmp"), token.as_bytes()).unwrap();
        let server_log_path = log_dir.join("server.log");
        std::fs::write(&server_log_path, b"safe-log-sentinel").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&server_log_path)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)),
            )
            .unwrap();
        for index in 0..21 {
            let path = log_dir.join(format!("newer-{index}.dmp"));
            std::fs::write(&path, b"opaque").unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(
                    std::fs::FileTimes::new()
                        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(2)),
                )
                .unwrap();
        }
        for index in 0..21 {
            std::fs::create_dir(log_dir.join(format!("invalid-{index}.log"))).unwrap();
        }
        let engine = Arc::new(
            EngineFS::new(temp.path().join("engine"), Default::default())
                .await
                .unwrap(),
        );
        let state = AppState::new_with_shared_settings_and_log_dir(
            engine,
            Arc::new(tokio::sync::RwLock::new(
                crate::routes::system::ServerSettings::default(),
            )),
            temp.path().join("config"),
            log_dir,
        );

        let bytes = build_diagnostics_zip(&state).unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut entries = Vec::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            let name = entry.name().to_string();
            let mut body = Vec::new();
            entry.read_to_end(&mut body).unwrap();
            entries.push((name, body));
        }

        assert!(entries.iter().any(|(name, body)| {
            name == "logs/server.log" && body.windows(17).any(|part| part == b"safe-log-sentinel")
        }));
        assert!(entries.iter().all(|(name, body)| {
            name != "logs/proof.dmp"
                && !body
                    .windows(token.len())
                    .any(|part| part == token.as_bytes())
        }));

        let server_log = state.log_dir.join("server.log");
        let moved_log = state.log_dir.join("server-opened.log");
        let replacement = state.log_dir.join("replacement.log");
        std::fs::write(&server_log, b"opened-handle-sentinel").unwrap();
        std::fs::write(&replacement, b"replacement-path-sentinel").unwrap();
        let bytes = build_diagnostics_zip_with_log_hook(&state, |opened| {
            if opened == server_log {
                std::fs::rename(&server_log, &moved_log).unwrap();
                std::fs::rename(&replacement, &server_log).unwrap();
            }
        })
        .unwrap();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let mut archived_server_log = Vec::new();
        archive
            .by_name("logs/server.log")
            .unwrap()
            .read_to_end(&mut archived_server_log)
            .unwrap();
        assert_eq!(archived_server_log, b"opened-handle-sentinel");
    }
}
