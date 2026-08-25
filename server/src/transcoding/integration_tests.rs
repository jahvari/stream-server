use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::transcoding::process::{
    PROCESS_TEST_LOCK, ProcessErrorCode, ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy,
};
#[cfg(unix)]
use crate::transcoding::runtime::verify_unchanged;
use crate::transcoding::runtime::{
    RuntimeConfig, RuntimeKind, RuntimeStatus, TranscodingService, resolve_runtime,
};
use crate::transcoding::runtime_manifest::RuntimeError;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

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

#[tokio::test]
async fn setup_ffmpeg_compatibility_adapter_returns_the_exact_explicit_pair_without_path_mutation()
{
    let directory = tempfile::tempdir().expect("runtime candidates");
    let explicit = jellyfin_root(directory.path(), "explicit-adapter");
    let decoy = jellyfin_root(directory.path(), "path-decoy");
    let original_path = std::env::var_os("PATH");
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let config = isolated_config()
        .with_explicit_root(explicit.clone())
        .with_search_path(Some(std::env::join_paths([decoy]).expect("decoy path")));

    let service = crate::setup_ffmpeg_with_config(config, supervisor)
        .await
        .expect("compatibility adapter resolves explicit pair");
    let expected = resolve_runtime(
        &isolated_config().with_explicit_root(explicit),
        &service.supervisor,
    )
    .await
    .expect("resolve expected explicit identity");
    let actual = service.current().await.expect("published adapter identity");

    assert_eq!(actual.id(), expected.id());
    assert_eq!(std::env::var_os("PATH"), original_path);
}

#[test]
fn startup_publishes_one_shared_managed_pair_and_cancels_its_supervisor_on_shutdown()
-> anyhow::Result<()> {
    let _guard = PROCESS_TEST_LOCK.blocking_lock();
    let config_parent = tempfile::tempdir()?;
    let cache_parent = tempfile::tempdir()?;
    let config_dir = config_parent.path().join("config");
    let managed_root = jellyfin_root(&config_dir.join("runtimes"), "current");
    let expected_managed_root = managed_root.clone();

    let handle = crate::start(crate::ServerConfig {
        http_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        config_dir: Some(config_dir),
        cache_dir: Some(cache_parent.path().join("cache")),
        setup_ffmpeg: true,
        enable_cache_cleaner: false,
        ..crate::ServerConfig::embedded()
    })?;

    let service = {
        let state = crate::GLOBAL_STATE
            .read()
            .map_err(|_| anyhow::anyhow!("global state lock was poisoned"))?;
        state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server did not publish AppState"))?
            .transcoding
            .clone()
    };
    let same_service = {
        let state = crate::GLOBAL_STATE
            .read()
            .map_err(|_| anyhow::anyhow!("global state lock was poisoned"))?;
        state
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server did not publish AppState"))?
            .transcoding
            .clone()
    };
    assert!(Arc::ptr_eq(&service, &same_service));

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let expected = resolve_runtime(
                &isolated_config().with_explicit_root(expected_managed_root),
                &service.supervisor,
            )
            .await?;
            let actual = service.current().await.ok_or(RuntimeError::Unavailable)?;
            anyhow::ensure!(
                actual.id() == expected.id(),
                "startup selected wrong runtime pair"
            );
            Ok::<_, anyhow::Error>(())
        })?;
    assert_eq!(service.supervisor.active_processes(), 0);

    handle.shutdown()?;
    assert_eq!(handle.join()?, Some(crate::ShutdownSource::External));
    assert!(service.supervisor.cancellation_token().is_cancelled());
    assert_eq!(service.supervisor.active_processes(), 0);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborting_run_future_keeps_tree_readers_and_permit_owned_until_confirmed_reap() {
    let _guard = PROCESS_TEST_LOCK.lock().await;
    let markers = tempfile::tempdir().expect("marker directory");
    let queued_marker = markers.path().join("queued");
    let supervisor = Arc::new(ProcessSupervisor::with_max_concurrency(
        CancellationToken::new(),
        1,
    ));
    let running = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--spawn-descendant"),
            markers.path().as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    let parent_marker = markers.path().join("parent.pid");
    let child_marker = markers.path().join("child.pid");
    wait_for_file(&parent_marker, Duration::from_secs(2));
    wait_for_file(&child_marker, Duration::from_secs(2));
    let parent_pid = read_pid(&parent_marker);
    let child_pid = read_pid(&child_marker);

    running.abort();
    assert!(
        running
            .await
            .expect_err("run future must be aborted")
            .is_cancelled()
    );
    let queued = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--touch"),
            queued_marker.as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        supervisor.active_processes(),
        1,
        "caller abort released registry ownership before confirmed reap"
    );
    assert!(
        !queued_marker.exists(),
        "caller abort released the owned capacity permit before confirmed reap"
    );

    supervisor.cancel();
    let _ = queued.await.expect("join queued process");
    supervisor
        .wait_for_idle(Duration::from_secs(8))
        .await
        .expect("supervisor-owned cleanup must drain");
    assert!(
        !process_is_alive(parent_pid),
        "aborted parent survived cleanup"
    );
    assert!(
        !process_is_alive(child_pid),
        "aborted descendant survived cleanup"
    );
    assert_eq!(supervisor.active_processes(), 0);
}

#[cfg(windows)]
#[test]
fn repeated_runtime_teardown_uses_kill_fallback_then_allows_confirmed_registry_drain() {
    let _guard = PROCESS_TEST_LOCK.blocking_lock();
    for iteration in 0..3 {
        let markers = tempfile::tempdir().expect("marker directory");
        let supervisor = Arc::new(ProcessSupervisor::with_max_concurrency(
            CancellationToken::new(),
            1,
        ));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.spawn({
            let supervisor = supervisor.clone();
            let request = spec([
                OsString::from("--spawn-descendant"),
                markers.path().as_os_str().to_os_string(),
            ]);
            async move { supervisor.run_bounded(request).await }
        });
        let parent_marker = markers.path().join("parent.pid");
        let child_marker = markers.path().join("child.pid");
        wait_for_file(&parent_marker, Duration::from_secs(2));
        wait_for_file(&child_marker, Duration::from_secs(2));
        let parent_pid = read_pid(&parent_marker);
        let child_pid = read_pid(&child_marker);

        runtime.shutdown_timeout(Duration::from_secs(3));
        let drain_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("drain runtime");
        drain_runtime
            .block_on(supervisor.wait_for_idle(Duration::from_secs(5)))
            .expect("registry drain after runtime teardown");

        assert!(
            !process_is_alive(parent_pid),
            "iteration {iteration} left the parent alive"
        );
        assert!(
            !process_is_alive(child_pid),
            "iteration {iteration} left the descendant alive"
        );
        assert_eq!(supervisor.active_processes(), 0);
    }
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
async fn stream_policy_is_rejected_as_unsupported_before_the_executable_can_start() {
    let marker_dir = tempfile::tempdir().expect("marker directory");
    let marker = marker_dir.path().join("spawned");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let mut request = spec([OsString::from("--touch"), marker.as_os_str().to_os_string()]);
    request.stdout = StdoutPolicy::Stream { queue_bytes: 1024 };

    let error = supervisor
        .run_bounded(request)
        .await
        .expect_err("Task 5 bounded commands must reject live streaming");

    assert_eq!(error.code(), ProcessErrorCode::UnsupportedPolicy);
    assert!(!marker.exists(), "unsupported policy still spawned a child");
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_closes_admission_before_a_queued_process_can_spawn() {
    let marker_dir = tempfile::tempdir().expect("marker directory");
    let running_marker = marker_dir.path().join("running");
    let queued_marker = marker_dir.path().join("queued");
    let supervisor = Arc::new(ProcessSupervisor::with_max_concurrency(
        CancellationToken::new(),
        1,
    ));
    let running = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--stall-with-marker"),
            running_marker.as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    wait_for_file(&running_marker, Duration::from_secs(2));
    let queued = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--touch"),
            queued_marker.as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    tokio::task::yield_now().await;

    supervisor.cancel();
    let running_error = running.await.expect("join running child").unwrap_err();
    let queued_error = queued.await.expect("join queued child").unwrap_err();

    assert_eq!(running_error.code(), ProcessErrorCode::Cancelled);
    assert_eq!(queued_error.code(), ProcessErrorCode::Cancelled);
    assert!(
        !queued_marker.exists(),
        "queued child crossed closed admission"
    );
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_registry_can_kill_and_reap_the_registered_process_tree() {
    let marker_dir = tempfile::tempdir().expect("marker directory");
    let pid_marker = marker_dir.path().join("registered.pid");
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let running = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--stall-with-marker"),
            pid_marker.as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    wait_for_file(&pid_marker, Duration::from_secs(2));
    let pid = read_pid(&pid_marker);
    assert_eq!(supervisor.active_processes(), 1);

    supervisor
        .force_terminate_registered()
        .expect("registry force termination");
    let output = tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("registered process reap deadline")
        .expect("join registered process")
        .expect("forced process is still a confirmed process result");

    assert!(!output.status.success());
    assert!(
        !process_is_alive(pid),
        "registry-owned process survived force"
    );
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_allows_a_process_two_seconds_to_exit_before_force() {
    let marker_dir = tempfile::tempdir().expect("marker directory");
    let pid_marker = marker_dir.path().join("graceful.pid");
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let running = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--sleep-ms-with-marker"),
            OsString::from("350"),
            pid_marker.as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    wait_for_file(&pid_marker, Duration::from_secs(2));
    let started = Instant::now();

    supervisor.cancel();
    let error = running
        .await
        .expect("join gracefully exiting child")
        .expect_err("cancellation remains the stable terminal surface");

    assert_eq!(error.code(), ProcessErrorCode::Cancelled);
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "cancellation forced the child without its grace period"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_forces_a_stalled_tree_after_two_seconds_then_confirms_reap() {
    let marker_dir = tempfile::tempdir().expect("marker directory");
    let pid_marker = marker_dir.path().join("forced.pid");
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let running = {
        let supervisor = supervisor.clone();
        let request = spec([
            OsString::from("--stall-with-marker"),
            pid_marker.as_os_str().to_os_string(),
        ]);
        tokio::spawn(async move { supervisor.run_bounded(request).await })
    };
    wait_for_file(&pid_marker, Duration::from_secs(2));
    let pid = read_pid(&pid_marker);
    let started = Instant::now();

    supervisor.cancel();
    let error = running
        .await
        .expect("join forcibly stopped child")
        .expect_err("cancelled stalled child must fail");

    assert_eq!(error.code(), ProcessErrorCode::Cancelled);
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!process_is_alive(pid), "forced child was not reaped");
    assert_eq!(supervisor.active_processes(), 0);
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
    let expected = vec![
        "",
        "Zażółć 世界",
        "a\"b",
        r"a\b",
        "trailing\\",
        "quoted trailing\\",
        "-version",
    ];
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

    let mut non_ascii_duplicate = BTreeMap::new();
    non_ascii_duplicate.insert(OsString::from("Ångström"), OsString::from("one"));
    non_ascii_duplicate.insert(OsString::from("ångström"), OsString::from("two"));
    cases.push(("ordinal non-ASCII duplicate", non_ascii_duplicate));

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
        let expected = resolve_runtime(
            &isolated_config().with_explicit_root(directory.path().join(expected_root)),
            &supervisor,
        )
        .await
        .expect("resolve expected candidate identity");
        assert_eq!(
            runtime.id().pair_root_identity,
            expected.id().pair_root_identity,
            "resolver selected the wrong candidate identity"
        );
    }
    assert_eq!(
        std::env::var_os("PATH"),
        original_path,
        "resolver mutated process PATH"
    );
}

#[tokio::test]
async fn path_candidates_are_deduplicated_then_capped_before_probing() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let valid = jellyfin_root(directory.path(), "valid-after-duplicates");
    let duplicate = directory.path().join("missing-duplicate");
    let mut duplicated = std::iter::repeat_n(duplicate, 100).collect::<Vec<_>>();
    duplicated.push(valid.clone());
    let supervisor = ProcessSupervisor::new(CancellationToken::new());

    let runtime = resolve_runtime(
        &isolated_config().with_search_path(Some(
            std::env::join_paths(duplicated).expect("duplicated hostile PATH"),
        )),
        &supervisor,
    )
    .await
    .expect("deduplication must leave room for the valid candidate");
    let expected = resolve_runtime(&isolated_config().with_explicit_root(valid), &supervisor)
        .await
        .expect("expected valid identity");
    assert_eq!(runtime.id(), expected.id());

    let mut unique = (0..64)
        .map(|index| directory.path().join(format!("missing-{index}")))
        .collect::<Vec<_>>();
    unique.push(jellyfin_root(directory.path(), "beyond-cap"));
    let error = resolve_runtime(
        &isolated_config().with_search_path(Some(
            std::env::join_paths(unique).expect("unique hostile PATH"),
        )),
        &supervisor,
    )
    .await
    .expect_err("candidate beyond the PATH cap must not be probed");
    assert!(matches!(error, RuntimeError::Unavailable));
}

#[tokio::test(start_paused = true)]
async fn repeated_hanging_candidates_hit_the_overall_resolution_deadline() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let mut stalled = Vec::new();
    for index in 0..4 {
        let root = jellyfin_root(directory.path(), &format!("stalled-{index}"));
        fs::write(root.join("stall-version"), b"stall").expect("write stall control");
        stalled.push(root);
    }
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let started = tokio::time::Instant::now();
    let resolving = {
        let supervisor = supervisor.clone();
        tokio::spawn(async move {
            resolve_runtime(&isolated_config().with_system_roots(stalled), &supervisor).await
        })
    };
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(30)).await;

    let error = resolving
        .await
        .expect("join bounded resolver")
        .expect_err("repeated hangs must reach the overall deadline");

    assert!(matches!(error, RuntimeError::ProbeDeadline));
    assert_eq!(started.elapsed(), Duration::from_secs(30));
    tokio::time::advance(Duration::from_secs(7)).await;
    supervisor
        .wait_for_idle(Duration::from_secs(1))
        .await
        .expect("deadline-abandoned probe must remain owned through reap");
}

#[tokio::test]
async fn incomplete_explicit_pair_fails_closed_without_using_a_valid_path_pair() {
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

    let error = resolve_runtime(&config, &supervisor)
        .await
        .expect_err("an incomplete explicit pair must stop fallback");

    assert!(matches!(error, RuntimeError::Unavailable));
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test]
async fn explicit_probe_error_fails_closed_without_using_a_valid_managed_pair() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let broken = jellyfin_root(directory.path(), "broken");
    fs::remove_file(broken.join("ffmpeg.version")).expect("remove probe response");
    let managed = jellyfin_root(directory.path(), "managed");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let config = isolated_config()
        .with_explicit_root(broken)
        .with_managed_current_root(managed);

    let error = resolve_runtime(&config, &supervisor)
        .await
        .expect_err("a failed explicit probe must stop fallback");

    assert!(matches!(error, RuntimeError::ProbeFailed));
}

#[tokio::test]
async fn incompatible_explicit_pair_fails_closed_without_using_a_valid_managed_pair() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let incompatible = runtime_root(
        directory.path(),
        "incompatible",
        "7.1.4-Jellyfin",
        "7.1.4",
        "--enable-gpl",
    );
    let managed = jellyfin_root(directory.path(), "managed");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let config = isolated_config()
        .with_explicit_root(incompatible)
        .with_managed_current_root(managed);

    let error = resolve_runtime(&config, &supervisor)
        .await
        .expect_err("an incompatible explicit pair must stop fallback");

    assert!(matches!(error, RuntimeError::IncompatiblePair));
}

#[tokio::test(start_paused = true)]
async fn version_probe_is_killed_at_the_ten_second_runtime_deadline() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let stalled = jellyfin_root(directory.path(), "stalled");
    let managed = jellyfin_root(directory.path(), "managed");
    fs::write(stalled.join("stall-version"), b"stall").expect("write stall control");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let config = isolated_config()
        .with_explicit_root(stalled)
        .with_managed_current_root(managed);
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
    assert!(started.elapsed() >= Duration::from_secs(10));
    assert!(
        started.elapsed() <= Duration::from_millis(17_100),
        "the ten-second probe deadline may be followed by the specified two-second grace and five-second bounded reap"
    );
    assert_eq!(supervisor.active_processes(), 0);
}

#[tokio::test]
async fn explicit_upstream_runtime_is_authoritative_and_software_degraded() {
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
        .with_managed_current_root(jellyfin);

    let runtime = resolve_runtime(&preferred, &supervisor)
        .await
        .expect("resolve authoritative explicit upstream pair");
    assert_eq!(runtime.kind(), RuntimeKind::SoftwareCompatible);
    let expected_explicit = resolve_runtime(
        &isolated_config().with_explicit_root(upstream.clone()),
        &supervisor,
    )
    .await
    .expect("resolve expected explicit identity");
    assert_eq!(
        runtime.id().pair_root_identity,
        expected_explicit.id().pair_root_identity
    );

    let degraded = resolve_runtime(&isolated_config().with_explicit_root(upstream), &supervisor)
        .await
        .expect("resolve upstream degraded fallback");
    assert_eq!(degraded.kind(), RuntimeKind::SoftwareCompatible);
    assert!(!degraded.kind().hardware_allowed());
}

#[tokio::test]
async fn valid_explicit_software_pair_is_authoritative_over_lower_jellyfin_candidates() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let explicit = runtime_root(
        directory.path(),
        "explicit-upstream",
        "7.1.4",
        "7.1.4",
        "--enable-gpl\n--enable-libx264",
    );
    let lower = jellyfin_root(directory.path(), "lower-jellyfin");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let expected = resolve_runtime(
        &isolated_config().with_explicit_root(explicit.clone()),
        &supervisor,
    )
    .await
    .expect("resolve explicit identity alone");

    let actual = resolve_runtime(
        &isolated_config()
            .with_explicit_root(explicit)
            .with_managed_current_root(lower),
        &supervisor,
    )
    .await
    .expect("valid explicit software runtime");

    assert_eq!(actual.id(), expected.id());
    assert_eq!(actual.kind(), RuntimeKind::SoftwareCompatible);
}

#[tokio::test]
async fn arbitrary_explicit_system_and_path_jellyfin_pairs_are_not_hardware_qualified() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let explicit = jellyfin_root(directory.path(), "explicit-unproven");
    let system = jellyfin_root(directory.path(), "system-unproven");
    let path = jellyfin_root(directory.path(), "path-unproven");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let configs = [
        isolated_config().with_explicit_root(explicit),
        isolated_config().with_system_roots(vec![system]),
        isolated_config().with_search_path(Some(std::env::join_paths([path]).expect("fake path"))),
    ];

    for config in configs {
        let runtime = resolve_runtime(&config, &supervisor)
            .await
            .expect("resolve unproven Jellyfin pair in software mode");
        assert_eq!(runtime.kind(), RuntimeKind::SoftwareCompatible);
        assert_eq!(runtime.id().jellyfin_revision, None);
        assert!(!runtime.kind().hardware_allowed());
    }
}

#[tokio::test]
async fn managed_candidate_without_authenticated_activation_proof_stays_software_only() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let managed = jellyfin_root(directory.path(), "managed-provenance");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());

    let runtime = resolve_runtime(
        &isolated_config().with_managed_current_root(managed),
        &supervisor,
    )
    .await
    .expect("resolve app-managed pair");

    assert_eq!(runtime.kind(), RuntimeKind::SoftwareCompatible);
    assert_eq!(runtime.id().jellyfin_revision, None);
    assert!(!runtime.kind().hardware_allowed());
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

    assert_eq!(runtime.kind(), RuntimeKind::SoftwareCompatible);
    assert_eq!(runtime.id().build_configuration_digest.len(), 64);
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

    assert_eq!(first_runtime.id().ffmpeg_version, "7.1.4");
    assert_eq!(first_runtime.id().jellyfin_revision, None);
    assert_eq!(first_runtime.id().install_digest.len(), 64);
    assert_eq!(first_runtime.id().build_configuration_digest.len(), 64);
    assert_eq!(first_runtime.id().pair_root_identity.len(), 64);
    assert_eq!(
        first_runtime.id().install_digest,
        second_runtime.id().install_digest,
        "same executable pair bytes must have the same install digest"
    );
    assert_ne!(
        first_runtime.id().pair_root_identity,
        second_runtime.id().pair_root_identity,
        "distinct install roots must not alias one pair identity"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn changed_runtime_file_fails_closed_before_a_session_can_use_it() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = jellyfin_root(directory.path(), "mutable");
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let runtime = resolve_runtime(
        &isolated_config().with_explicit_root(root.clone()),
        &supervisor,
    )
    .await
    .expect("resolve runtime");
    let ffmpeg = root.join(format!("ffmpeg{}", std::env::consts::EXE_SUFFIX));
    let original_len = fs::metadata(&ffmpeg).unwrap().len();
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(&ffmpeg)
        .expect("open runtime for mutation")
        .write_all(b"changed")
        .expect("mutate runtime");
    assert!(fs::metadata(&ffmpeg).unwrap().len() > original_len);

    let error = verify_unchanged(&runtime)
        .await
        .expect_err("changed runtime must fail closed");

    assert!(matches!(error, RuntimeError::RuntimeChanged));
}

#[tokio::test]
async fn verified_session_keeps_the_pair_leased_and_publishes_only_safe_identity() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = jellyfin_root(directory.path(), "service");
    let config = isolated_config().with_explicit_root(root.clone());
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let initial = resolve_runtime(&config, &supervisor)
        .await
        .expect("resolve initial runtime");
    let initial_digest = initial.id().install_digest.clone();
    let service = TranscodingService::resolved(config, supervisor.clone(), initial);
    let snapshot = service
        .current()
        .await
        .expect("published identity snapshot");
    assert_eq!(snapshot.id().install_digest, initial_digest);
    let session = service
        .runtime_for_session()
        .await
        .expect("verified runtime session");

    #[cfg(windows)]
    {
        let ffmpeg = root.join(format!("ffmpeg{}", std::env::consts::EXE_SUFFIX));
        let backup = ffmpeg.with_extension("replacement-race-backup");
        assert!(
            fs::rename(&ffmpeg, &backup).is_err(),
            "the validated executable was replaceable while its session lease was live"
        );
    }
    assert_eq!(session.id().install_digest, initial_digest);
    assert!(Arc::ptr_eq(&service.supervisor, &supervisor));
}

#[cfg(unix)]
#[tokio::test]
async fn session_revalidation_detects_a_path_replaced_after_validation() {
    let directory = tempfile::tempdir().expect("runtime candidates");
    let root = jellyfin_root(directory.path(), "replaceable");
    let config = isolated_config().with_explicit_root(root.clone());
    let supervisor = Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let initial = resolve_runtime(&config, &supervisor)
        .await
        .expect("resolve initial runtime");
    let service = TranscodingService::resolved(config, supervisor, initial);
    let original_session = service
        .runtime_for_session()
        .await
        .expect("verified runtime session");
    let ffmpeg = root.join(format!("ffmpeg{}", std::env::consts::EXE_SUFFIX));
    let original = ffmpeg.with_extension("original");
    fs::rename(&ffmpeg, &original).expect("replace executable path after validation");
    fs::copy(&fake_process().executable, &ffmpeg).expect("install byte-identical replacement");

    let replacement_session = service
        .runtime_for_session()
        .await
        .expect("service must resolve and verify the replacement before returning it");

    assert_eq!(
        replacement_session.id().install_digest,
        original_session.id().install_digest
    );
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
    assert!(Arc::ptr_eq(&service.supervisor, &supervisor));
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
        Some("--touch") => {
            fs::write(PathBuf::from(args.get(1).expect("marker path")), b"spawned").unwrap();
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
        Some("--stall-with-marker") => {
            fs::write(
                PathBuf::from(args.get(1).expect("marker path")),
                std::process::id().to_string(),
            )
            .unwrap();
            loop { thread::sleep(Duration::from_secs(1)); }
        }
        Some("--sleep-ms-with-marker") => {
            let milliseconds = parse_size(args.get(1));
            fs::write(
                PathBuf::from(args.get(2).expect("marker path")),
                std::process::id().to_string(),
            )
            .unwrap();
            thread::sleep(Duration::from_millis(milliseconds as u64));
        }
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
