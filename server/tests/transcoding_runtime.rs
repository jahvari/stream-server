use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use stream_server::transcoding::process::{
    ProcessErrorCode, ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy,
};
use stream_server::transcoding::runtime::{
    RuntimeConfig, RuntimeKind, RuntimeStatus, TranscodingService, resolve_runtime,
    verify_unchanged,
};
use stream_server::transcoding::runtime_manifest::RuntimeError;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

static PROCESS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct FakeProcess {
    _directory: TempDir,
    executable: PathBuf,
}

fn fake_process() -> &'static FakeProcess {
    static FAKE: OnceLock<FakeProcess> = OnceLock::new();
    FAKE.get_or_init(|| {
        let directory = tempfile::tempdir().expect("fake process directory");
        let source = directory.path().join("fake_process.rs");
        let executable = directory
            .path()
            .join(format!("fake-process{}", std::env::consts::EXE_SUFFIX));
        fs::write(&source, FAKE_PROCESS_SOURCE).expect("write fake process source");
        let status = Command::new("rustc")
            .args(["--edition=2024", "-O"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("compile fake process");
        assert!(status.success(), "fake process compilation failed");
        FakeProcess {
            _directory: directory,
            executable,
        }
    })
}

fn spec(args: impl IntoIterator<Item = impl Into<OsString>>) -> ProcessSpec {
    ProcessSpec {
        executable: fake_process().executable.clone(),
        args: args.into_iter().map(Into::into).collect(),
        current_dir: fake_process()._directory.path().to_path_buf(),
        environment: BTreeMap::new(),
        stdin: StdinPolicy::Null,
        stdout: StdoutPolicy::Capture { byte_limit: 8_192 },
        stderr_byte_limit: 8_192,
        wall_deadline: Duration::from_secs(2),
    }
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(path.is_file(), "marker was not created: {}", path.display());
}

fn read_pid(path: &Path) -> u32 {
    fs::read_to_string(path)
        .expect("read pid marker")
        .trim()
        .parse()
        .expect("parse pid marker")
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    unsafe {
        let Ok(handle) = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        ) else {
            return false;
        };
        let wait = WaitForSingleObject(handle, 0);
        let _ = CloseHandle(handle);
        wait == windows::Win32::Foundation::WAIT_TIMEOUT
    }
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn decode_arguments(bytes: &[u8]) -> Vec<String> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let length = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("argument length bytes"),
        ) as usize;
        offset += 4;
        let end = offset + length;
        decoded.push(String::from_utf8(bytes[offset..end].to_vec()).expect("utf8 argument"));
        offset = end;
    }
    decoded
}

fn runtime_root(
    base: &Path,
    name: &str,
    ffmpeg_version: &str,
    ffprobe_version: &str,
    build_configuration: &str,
) -> PathBuf {
    let root = base.join(name);
    fs::create_dir_all(&root).expect("create fake runtime root");
    for role in ["ffmpeg", "ffprobe"] {
        fs::copy(
            &fake_process().executable,
            root.join(format!("{role}{}", std::env::consts::EXE_SUFFIX)),
        )
        .expect("copy fake runtime executable");
    }
    fs::write(root.join("ffmpeg.version"), ffmpeg_version).expect("write ffmpeg version");
    fs::write(root.join("ffprobe.version"), ffprobe_version).expect("write ffprobe version");
    fs::write(root.join("ffmpeg.buildconf"), build_configuration).expect("write ffmpeg buildconf");
    fs::write(root.join("ffprobe.buildconf"), build_configuration)
        .expect("write ffprobe buildconf");
    root
}

fn jellyfin_root(base: &Path, name: &str) -> PathBuf {
    runtime_root(
        base,
        name,
        "7.1.4-Jellyfin",
        "7.1.4-Jellyfin",
        "--enable-gpl\n--enable-libx264",
    )
}

fn isolated_config() -> RuntimeConfig {
    RuntimeConfig::isolated()
}

#[test]
fn startup_publishes_one_shared_managed_pair_and_cancels_its_supervisor_on_shutdown()
-> anyhow::Result<()> {
    let _guard = PROCESS_TEST_LOCK.blocking_lock();
    let config_parent = tempfile::tempdir()?;
    let cache_parent = tempfile::tempdir()?;
    let config_dir = config_parent.path().join("config");
    let managed_root = jellyfin_root(&config_dir.join("runtimes"), "current");
    let expected_root = fs::canonicalize(managed_root)?;

    let handle = stream_server::start(stream_server::ServerConfig {
        http_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        config_dir: Some(config_dir),
        cache_dir: Some(cache_parent.path().join("cache")),
        setup_ffmpeg: true,
        enable_cache_cleaner: false,
        ..stream_server::ServerConfig::embedded()
    })?;

    let service = {
        let state = stream_server::GLOBAL_STATE
            .read()
            .map_err(|_| anyhow::anyhow!("global state lock was poisoned"))?;
        state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server did not publish AppState"))?
            .transcoding
            .clone()
    };
    let same_service = {
        let state = stream_server::GLOBAL_STATE
            .read()
            .map_err(|_| anyhow::anyhow!("global state lock was poisoned"))?;
        state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server did not publish AppState"))?
            .transcoding
            .clone()
    };
    assert!(Arc::ptr_eq(&service, &same_service));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(service.runtime_for_session())?;
    assert_eq!(
        fs::canonicalize(runtime.ffmpeg.parent().expect("ffmpeg parent"))?,
        expected_root
    );
    assert_eq!(
        fs::canonicalize(runtime.ffprobe.parent().expect("ffprobe parent"))?,
        expected_root
    );
    assert_eq!(service.supervisor().active_processes(), 0);

    handle.shutdown()?;
    assert_eq!(
        handle.join()?,
        Some(stream_server::ShutdownSource::External)
    );
    assert!(service.supervisor().cancellation_token().is_cancelled());
    assert_eq!(service.supervisor().active_processes(), 0);

    Ok(())
}

#[tokio::test]
async fn deadline_kills_the_registered_parent_and_descendant_then_reaps_both() {
    let _guard = PROCESS_TEST_LOCK.lock().await;
    let markers = tempfile::tempdir().expect("marker directory");
    let token = CancellationToken::new();
    let supervisor = ProcessSupervisor::new(token);
    let mut request = spec([
        OsString::from("--spawn-descendant"),
        markers.path().as_os_str().to_os_string(),
    ]);
    request.wall_deadline = Duration::from_millis(350);

    let error = supervisor
        .run_bounded(request)
        .await
        .expect_err("descendant scenario must time out");

    assert_eq!(error.code(), ProcessErrorCode::DeadlineExceeded);
    let parent_marker = markers.path().join("parent.pid");
    let child_marker = markers.path().join("child.pid");
    wait_for_file(&parent_marker, Duration::from_secs(1));
    wait_for_file(&child_marker, Duration::from_secs(1));
    assert!(
        !process_is_alive(read_pid(&parent_marker)),
        "parent survived deadline cleanup"
    );
    assert!(
        !process_is_alive(read_pid(&child_marker)),
        "descendant survived deadline cleanup"
    );
    assert_eq!(
        supervisor.active_processes(),
        0,
        "timed-out child remained registered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_cancellation_kills_a_running_process_tree_and_reaps_registry_ownership() {
    let _guard = PROCESS_TEST_LOCK.lock().await;
    let markers = tempfile::tempdir().expect("marker directory");
    let token = CancellationToken::new();
    let supervisor = Arc::new(ProcessSupervisor::new(token.clone()));
    let request = spec([
        OsString::from("--spawn-descendant"),
        markers.path().as_os_str().to_os_string(),
    ]);
    let running = {
        let supervisor = supervisor.clone();
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    let parent_marker = markers.path().join("parent.pid");
    let child_marker = markers.path().join("child.pid");
    wait_for_file(&parent_marker, Duration::from_secs(2));
    wait_for_file(&child_marker, Duration::from_secs(2));

    token.cancel();
    let error = running
        .await
        .expect("join bounded process")
        .expect_err("cancelled process must fail");

    assert_eq!(error.code(), ProcessErrorCode::Cancelled);
    assert!(
        !process_is_alive(read_pid(&parent_marker)),
        "parent survived cancellation"
    );
    assert!(
        !process_is_alive(read_pid(&child_marker)),
        "descendant survived cancellation"
    );
    assert_eq!(
        supervisor.active_processes(),
        0,
        "cancelled child remained registered"
    );
}

#[tokio::test]
async fn stdout_ceiling_stops_the_process_before_unbounded_capture() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let mut request = spec(["--emit", "4097", "0"]);
    request.stdout = StdoutPolicy::Capture { byte_limit: 4_096 };

    let error = supervisor
        .run_bounded(request)
        .await
        .expect_err("stdout cap must fail closed");

    assert_eq!(error.code(), ProcessErrorCode::StdoutLimitExceeded);
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test]
async fn stderr_ceiling_stops_the_process_before_unbounded_capture() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let mut request = spec(["--emit", "0", "4097"]);
    request.stderr_byte_limit = 4_096;

    let error = supervisor
        .run_bounded(request)
        .await
        .expect_err("stderr cap must fail closed");

    assert_eq!(error.code(), ProcessErrorCode::StderrLimitExceeded);
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test]
async fn completed_process_returns_bounded_output_and_is_reaped_before_return() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let output = supervisor
        .run_bounded(spec(["--emit", "7", "5"]))
        .await
        .expect("successful bounded process");

    assert!(output.status.success());
    assert_eq!(output.stdout, vec![b'o'; 7]);
    assert_eq!(output.stderr, vec![b'e'; 5]);
    assert_eq!(
        supervisor.active_processes(),
        0,
        "completed child returned before reap"
    );
}

#[tokio::test]
async fn parent_exit_still_kills_a_descendant_that_keeps_the_capture_pipes_open() {
    let _guard = PROCESS_TEST_LOCK.lock().await;
    let markers = tempfile::tempdir().expect("marker directory");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let request = spec([
        OsString::from("--spawn-inheriting-descendant-then-exit"),
        markers.path().as_os_str().to_os_string(),
    ]);
    let started = Instant::now();

    let output = supervisor
        .run_bounded(request)
        .await
        .expect("parent success must still contain and reap its descendant");

    assert!(output.status.success());
    let child_marker = markers.path().join("child.pid");
    wait_for_file(&child_marker, Duration::from_secs(1));
    assert!(!process_is_alive(read_pid(&child_marker)));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(supervisor.active_processes(), 0);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_command_line_round_trips_empty_unicode_quotes_backslashes_and_option_values() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let expected = vec!["", "Zażółć 世界", "a\"b", r"a\b", "trailing\\", "-version"];
    let mut args = vec![OsString::from("--echo")];
    args.extend(expected.iter().map(OsString::from));

    let output = supervisor
        .run_bounded(spec(args))
        .await
        .expect("round-trip fake process");

    assert_eq!(decode_arguments(&output.stdout), expected);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_rejects_nul_invalid_or_duplicate_environment_and_oversized_blocks() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let mut cases = Vec::new();

    let mut empty_name = BTreeMap::new();
    empty_name.insert(OsString::new(), OsString::from("value"));
    cases.push(("empty name", empty_name));

    let mut equals_name = BTreeMap::new();
    equals_name.insert(OsString::from("=hidden"), OsString::from("value"));
    cases.push(("equals name", equals_name));

    let mut duplicate_path = BTreeMap::new();
    duplicate_path.insert(OsString::from("Path"), OsString::from("one"));
    duplicate_path.insert(OsString::from("PATH"), OsString::from("two"));
    cases.push(("case-insensitive duplicate", duplicate_path));

    let mut nul_value = BTreeMap::new();
    nul_value.insert(OsString::from("SAFE"), OsString::from("bad\0value"));
    cases.push(("NUL value", nul_value));

    let mut oversized = BTreeMap::new();
    oversized.insert(OsString::from("SAFE"), OsString::from("x".repeat(32_768)));
    cases.push(("oversized environment", oversized));

    for (name, environment) in cases {
        let mut request = spec(["--emit", "0", "0"]);
        request.environment = environment;
        let error = match supervisor.run_bounded(request).await {
            Ok(_) => panic!("accepted {name}"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ProcessErrorCode::InvalidSpec, "{name}");
    }

    let mut nul_argument = spec([OsString::from("bad\0argument")]);
    nul_argument.stdout = StdoutPolicy::Null;
    assert_eq!(
        supervisor
            .run_bounded(nul_argument)
            .await
            .unwrap_err()
            .code(),
        ProcessErrorCode::InvalidSpec
    );

    let mut oversized_command = spec([OsString::from("x".repeat(32_768))]);
    oversized_command.stdout = StdoutPolicy::Null;
    assert_eq!(
        supervisor
            .run_bounded(oversized_command)
            .await
            .unwrap_err()
            .code(),
        ProcessErrorCode::InvalidSpec
    );
}

#[tokio::test]
async fn resolution_prefers_explicit_then_managed_then_system_then_path_without_mutating_path() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let explicit = jellyfin_root(directory.path(), "explicit");
    let managed = jellyfin_root(directory.path(), "managed");
    let system = jellyfin_root(directory.path(), "system");
    let path = jellyfin_root(directory.path(), "path");
    let search_path = std::env::join_paths([path.clone()]).expect("fake search path");
    let original_path = std::env::var_os("PATH");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());

    let cases = [
        (
            isolated_config()
                .with_explicit_root(explicit.clone())
                .with_managed_current_root(managed.clone())
                .with_system_roots(vec![system.clone()])
                .with_search_path(Some(search_path.clone())),
            "explicit",
        ),
        (
            isolated_config()
                .with_managed_current_root(managed.clone())
                .with_system_roots(vec![system.clone()])
                .with_search_path(Some(search_path.clone())),
            "managed",
        ),
        (
            isolated_config()
                .with_system_roots(vec![system])
                .with_search_path(Some(search_path.clone())),
            "system",
        ),
        (
            isolated_config().with_search_path(Some(search_path)),
            "path",
        ),
    ];

    for (config, expected_root) in cases {
        let runtime = resolve_runtime(&config, &supervisor)
            .await
            .expect("resolve ordered runtime");
        assert!(runtime.ffmpeg.is_absolute());
        assert!(runtime.ffprobe.is_absolute());
        assert_eq!(runtime.ffmpeg.parent(), runtime.ffprobe.parent());
        assert!(
            runtime
                .ffmpeg
                .parent()
                .expect("runtime root")
                .ends_with(expected_root),
            "wrong resolution root: {}",
            runtime.ffmpeg.display()
        );
    }
    assert_eq!(
        std::env::var_os("PATH"),
        original_path,
        "resolver mutated process PATH"
    );
}

#[tokio::test]
async fn resolver_never_pairs_ffmpeg_with_ffprobe_from_another_root() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let incomplete = jellyfin_root(directory.path(), "incomplete");
    fs::remove_file(incomplete.join(format!("ffprobe{}", std::env::consts::EXE_SUFFIX)))
        .expect("remove adjacent ffprobe");
    let complete = jellyfin_root(directory.path(), "complete");
    let search_path = std::env::join_paths([complete]).expect("fake search path");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let config = isolated_config()
        .with_explicit_root(incomplete)
        .with_search_path(Some(search_path));

    let runtime = resolve_runtime(&config, &supervisor)
        .await
        .expect("resolve complete adjacent pair");

    assert_eq!(runtime.ffmpeg.parent(), runtime.ffprobe.parent());
    assert!(runtime.ffmpeg.parent().unwrap().ends_with("complete"));
}

#[tokio::test(start_paused = true)]
async fn version_probe_is_killed_at_the_ten_second_runtime_deadline() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let stalled = jellyfin_root(directory.path(), "stalled");
    fs::write(stalled.join("stall-version"), b"stall").expect("write stall control");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let config = isolated_config().with_explicit_root(stalled);
    let started = tokio::time::Instant::now();
    let resolving = {
        let supervisor = supervisor.clone();
        tokio::spawn(async move { resolve_runtime(&config, &supervisor).await })
    };
    while supervisor.active_processes() == 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(10)).await;

    let error = resolving
        .await
        .expect("join stalled resolver")
        .expect_err("stalled version probe must fail");

    assert!(matches!(error, RuntimeError::ProbeDeadline));
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test]
async fn upstream_runtime_is_degraded_only_when_no_jellyfin_pair_exists() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let upstream = runtime_root(
        directory.path(),
        "upstream",
        "7.1.4",
        "7.1.4",
        "--enable-gpl\n--enable-libx264",
    );
    let jellyfin = jellyfin_root(directory.path(), "jellyfin");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let preferred = isolated_config()
        .with_explicit_root(upstream.clone())
        .with_system_roots(vec![jellyfin]);

    let runtime = resolve_runtime(&preferred, &supervisor)
        .await
        .expect("resolve Jellyfin over upstream fallback");
    assert_eq!(runtime.kind, RuntimeKind::Jellyfin);
    assert!(runtime.ffmpeg.parent().unwrap().ends_with("jellyfin"));
    assert!(runtime.kind.hardware_allowed());

    let degraded = resolve_runtime(&isolated_config().with_explicit_root(upstream), &supervisor)
        .await
        .expect("resolve upstream degraded fallback");
    assert_eq!(degraded.kind, RuntimeKind::SoftwareCompatible);
    assert!(!degraded.kind.hardware_allowed());
}

#[tokio::test]
async fn mismatched_ffmpeg_and_ffprobe_versions_are_rejected() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = runtime_root(
        directory.path(),
        "mismatch",
        "7.1.4-Jellyfin",
        "7.1.4",
        "--enable-gpl",
    );
    let supervisor = ProcessSupervisor::new(CancellationToken::new());

    let error = resolve_runtime(&isolated_config().with_explicit_root(root), &supervisor)
        .await
        .expect_err("mismatched pair must fail");

    assert!(matches!(error, RuntimeError::IncompatiblePair));
}

#[tokio::test]
async fn real_buildconf_banner_and_library_footer_do_not_hide_the_configuration_identity() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = jellyfin_root(directory.path(), "real-buildconf");
    fs::write(root.join("real-buildconf-layout"), b"").expect("enable real buildconf layout");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());

    let runtime = resolve_runtime(&isolated_config().with_explicit_root(root), &supervisor)
        .await
        .expect("real Jellyfin -buildconf layout must resolve");

    assert_eq!(runtime.kind, RuntimeKind::Jellyfin);
    assert_eq!(runtime.id.build_configuration_digest.len(), 64);
}

#[tokio::test]
async fn runtime_identity_binds_files_versions_revision_build_configuration_and_pair_root() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let first = jellyfin_root(directory.path(), "first");
    let second = jellyfin_root(directory.path(), "second");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let first_runtime = resolve_runtime(&isolated_config().with_explicit_root(first), &supervisor)
        .await
        .expect("resolve first runtime");
    let second_runtime =
        resolve_runtime(&isolated_config().with_explicit_root(second), &supervisor)
            .await
            .expect("resolve second runtime");

    assert_eq!(first_runtime.id.ffmpeg_version, "7.1.4");
    assert_eq!(first_runtime.id.jellyfin_revision.as_deref(), Some("3"));
    assert_eq!(first_runtime.id.install_digest.len(), 64);
    assert_eq!(first_runtime.id.build_configuration_digest.len(), 64);
    assert_eq!(first_runtime.id.pair_root_identity.len(), 64);
    assert_eq!(
        first_runtime.id.install_digest, second_runtime.id.install_digest,
        "same executable pair bytes must have the same install digest"
    );
    assert_ne!(
        first_runtime.id.pair_root_identity, second_runtime.id.pair_root_identity,
        "distinct install roots must not alias one pair identity"
    );
}

#[tokio::test]
async fn changed_runtime_file_fails_closed_before_a_session_can_use_it() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = jellyfin_root(directory.path(), "mutable");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let runtime = resolve_runtime(&isolated_config().with_explicit_root(root), &supervisor)
        .await
        .expect("resolve runtime");
    let original_len = fs::metadata(&runtime.ffmpeg).unwrap().len();
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&runtime.ffmpeg)
        .expect("open runtime for mutation")
        .write_all(b"changed")
        .expect("mutate runtime");
    assert!(fs::metadata(&runtime.ffmpeg).unwrap().len() > original_len);

    let error = verify_unchanged(&runtime)
        .await
        .expect_err("changed runtime must fail closed");

    assert!(matches!(error, RuntimeError::RuntimeChanged));
}

#[tokio::test]
async fn first_session_re_resolves_changed_files_through_the_same_shared_supervisor() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = jellyfin_root(directory.path(), "service");
    let config = isolated_config().with_explicit_root(root);
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let initial = resolve_runtime(&config, &supervisor)
        .await
        .expect("resolve initial runtime");
    let initial_digest = initial.id.install_digest.clone();
    let service = TranscodingService::resolved(config, supervisor.clone(), initial);
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(service.current().await.unwrap().ffmpeg.clone())
        .expect("open runtime for mutation")
        .write_all(b"replacement")
        .expect("mutate runtime");

    let refreshed = service
        .runtime_for_session()
        .await
        .expect("re-resolve changed runtime before session");

    assert_ne!(refreshed.id.install_digest, initial_digest);
    assert!(Arc::ptr_eq(service.supervisor(), &supervisor));
    assert_eq!(service.status().await, RuntimeStatus::Jellyfin);
}

#[tokio::test]
async fn unavailable_service_is_side_effect_free_and_exposes_disabled_status() {
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let service = TranscodingService::unavailable(supervisor.clone());

    assert_eq!(service.status().await, RuntimeStatus::Unavailable);
    assert!(matches!(
        service.runtime_for_session().await,
        Err(RuntimeError::Unavailable)
    ));
    assert!(Arc::ptr_eq(service.supervisor(), &supervisor));
    assert_eq!(supervisor.active_processes(), 0);
}

#[cfg(windows)]
#[tokio::test]
async fn explicit_unc_and_device_paths_are_rejected_without_a_probe() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    for path in [r"\\server\share\ffmpeg", r"\\.\C:\ffmpeg", r"\\?\C:\ffmpeg"] {
        let error = resolve_runtime(
            &isolated_config().with_explicit_root(PathBuf::from(path)),
            &supervisor,
        )
        .await
        .expect_err("remote or device path must be rejected");
        assert!(matches!(error, RuntimeError::UnsafePath), "accepted {path}");
    }
    assert_eq!(supervisor.active_processes(), 0);
}

#[cfg(windows)]
#[tokio::test]
async fn explicit_runtime_rejects_a_symlinked_executable_escape() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let approved = jellyfin_root(directory.path(), "approved");
    let outside = jellyfin_root(directory.path(), "outside");
    let ffmpeg = approved.join("ffmpeg.exe");
    fs::remove_file(&ffmpeg).expect("remove approved ffmpeg");
    std::os::windows::fs::symlink_file(outside.join("ffmpeg.exe"), &ffmpeg)
        .expect("create executable symlink");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());

    let error = resolve_runtime(&isolated_config().with_explicit_root(approved), &supervisor)
        .await
        .expect_err("link escape must fail closed");

    assert!(matches!(error, RuntimeError::UnsafePath));
    assert_eq!(supervisor.active_processes(), 0);
}

const FAKE_PROCESS_SOURCE: &str = r#"
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if runtime_query(&args) {
        return;
    }
    match args.first().and_then(|arg| arg.to_str()) {
        Some("--emit") => {
            let stdout = parse_size(args.get(1));
            let stderr = parse_size(args.get(2));
            io::stdout().write_all(&vec![b'o'; stdout]).unwrap();
            io::stderr().write_all(&vec![b'e'; stderr]).unwrap();
        }
        Some("--echo") => {
            let mut output = io::stdout().lock();
            for argument in &args[1..] {
                let text = argument.to_string_lossy();
                output.write_all(&(text.len() as u32).to_le_bytes()).unwrap();
                output.write_all(text.as_bytes()).unwrap();
            }
        }
        Some("--spawn-descendant") => {
            let directory = PathBuf::from(args.get(1).expect("marker directory"));
            let child = Command::new(env::current_exe().unwrap())
                .arg("--descendant-child")
                .arg(&directory)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            fs::write(directory.join("parent.pid"), std::process::id().to_string()).unwrap();
            fs::write(directory.join("child.pid"), child.id().to_string()).unwrap();
            loop { thread::sleep(Duration::from_secs(1)); }
        }
        Some("--spawn-inheriting-descendant-then-exit") => {
            let directory = PathBuf::from(args.get(1).expect("marker directory"));
            let child = Command::new(env::current_exe().unwrap())
                .arg("--descendant-child")
                .arg(&directory)
                .spawn()
                .unwrap();
            fs::write(directory.join("child.pid"), child.id().to_string()).unwrap();
        }
        Some("--descendant-child") => loop { thread::sleep(Duration::from_secs(1)); },
        Some("--stall") => loop { thread::sleep(Duration::from_secs(1)); },
        _ => std::process::exit(2),
    }
}

fn runtime_query(args: &[OsString]) -> bool {
    let Some(query) = args.first().and_then(|arg| arg.to_str()) else {
        return false;
    };
    if args.len() != 1 || (query != "-version" && query != "-buildconf") {
        return false;
    }
    let root = env::current_dir().unwrap();
    if root.join("stall-version").is_file() && query == "-version" {
        loop { thread::sleep(Duration::from_secs(1)); }
    }
    let executable = env::current_exe().unwrap();
    let role = if executable
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_ascii_lowercase()
        .contains("ffprobe")
    {
        "ffprobe"
    } else {
        "ffmpeg"
    };
    let version = fs::read_to_string(root.join(format!("{role}.version"))).unwrap();
    println!("{role} version {}", version.trim());
    if query == "-buildconf" {
        let configuration = fs::read_to_string(root.join(format!("{role}.buildconf"))).unwrap();
        if root.join("real-buildconf-layout").is_file() {
            println!("  built with clang 19.1.7");
        }
        println!("configuration:");
        print!("{configuration}");
        if root.join("real-buildconf-layout").is_file() {
            println!();
            println!("libavutil      59. 39.100 / 59. 39.100");
        }
    }
    true
}

fn parse_size(value: Option<&OsString>) -> usize {
    value.and_then(|value| value.to_str()).unwrap().parse().unwrap()
}
"#;
