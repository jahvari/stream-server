#![cfg(windows)]

use super::{
    FailurePoint, ProcessErrorCode, ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy,
};
use std::{collections::BTreeMap, ffi::OsString, fs, process::Command, time::Duration};
use tokio_util::sync::CancellationToken;

#[test]
#[ignore = "spawned only by retained_registry_entry_can_be_retried_until_confirmed_drained"]
fn retained_registry_sleep_helper() {
    std::thread::sleep(Duration::from_secs(60));
}

#[tokio::test]
#[ignore = "spawned only by isolated_native_handle_baseline_is_stable_after_repeated_runs"]
async fn isolated_native_handle_baseline_helper() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    supervisor
        .run_bounded(inert_spec())
        .await
        .expect("warm native process resources");
    let handles_before = super::windows::process_handle_count();

    for _ in 0..4 {
        supervisor
            .run_bounded(inert_spec())
            .await
            .expect("repeat bounded native process");
    }

    assert_eq!(supervisor.test_native_handle_count(), 0);
    assert_eq!(super::windows::process_handle_count(), handles_before);
}

#[test]
fn isolated_native_handle_baseline_is_stable_after_repeated_runs() {
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--ignored",
            "--exact",
            "transcoding::process::tests::isolated_native_handle_baseline_helper",
        ])
        .output()
        .expect("spawn isolated native handle test");

    assert!(
        output.status.success(),
        "isolated native handle test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_for_hook(reached: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !reached() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lifecycle hook reached");
}

fn remove_test_registry_entry(supervisor: &ProcessSupervisor, registration_id: u64) {
    supervisor
        .inner
        .registry
        .mark_cleanup_stopped(registration_id);
    supervisor.inner.registry.complete(registration_id);
}

#[test]
fn unix_group_identity_forbids_reap_before_final_signal_and_reuse_after_reap() {
    let mut identity = super::UnixGroupIdentity::new(4_321);
    assert_eq!(identity.final_signal_target(), Some(4_321));
    assert_eq!(
        identity
            .mark_leader_reaped()
            .expect_err("leader cannot be reaped before the final group signal")
            .code(),
        ProcessErrorCode::WaitFailed
    );

    identity.mark_final_signal_sent();
    identity
        .mark_leader_reaped()
        .expect("leader can be reaped after the final group signal");

    assert_eq!(
        identity.final_signal_target(),
        None,
        "a reaped leader must never expose its numeric PGID as a kill target"
    );
}

#[test]
fn failed_unix_final_signal_keeps_identity_retryable() {
    let mut identity = super::UnixGroupIdentity::new(4_322);
    let injected = Err(super::ProcessError::new(ProcessErrorCode::WaitFailed));

    assert_eq!(
        identity
            .record_final_signal_result(injected)
            .expect_err("injected signal failure must surface")
            .code(),
        ProcessErrorCode::WaitFailed
    );
    assert_eq!(
        identity.final_signal_target(),
        Some(4_322),
        "failed signal must preserve the pinned retry target"
    );
    assert!(identity.killable_for_retention());

    identity
        .record_final_signal_result(Ok(()))
        .expect("successful retry marks the final signal");
    assert_eq!(identity.final_signal_target(), None);
    assert!(!identity.killable_for_retention());
}

#[test]
fn unix_registry_release_requires_child_reap_and_both_reader_joins() {
    let mut ownership = super::UnixDurableOwnership::new();
    assert!(!ownership.can_release());
    ownership.mark_final_signal_sent();
    ownership.mark_child_reaped();
    assert!(!ownership.can_release(), "readers are still owned");
    ownership.mark_reader_joined();
    assert!(!ownership.can_release(), "one reader is still owned");
    ownership.mark_reader_joined();
    assert!(
        ownership.can_release(),
        "registry/permit release requires child reap and both reader joins"
    );
}

#[test]
fn panicked_unix_reader_is_terminally_joined_but_still_reports_wait_failure() {
    let mut ownership = super::UnixDurableOwnership::new();
    ownership.mark_final_signal_sent();
    ownership.mark_child_reaped();

    let result = ownership.record_reader_join_result::<Vec<u8>>(Err(super::ProcessError::new(
        ProcessErrorCode::WaitFailed,
    )));

    assert_eq!(
        result.expect_err("reader panic must remain visible").code(),
        ProcessErrorCode::WaitFailed
    );
    assert!(!ownership.can_release(), "the second reader remains owned");
    ownership.mark_reader_joined();
    assert!(ownership.can_release());
}

#[test]
fn unix_fd_execution_parser_limits_inheritance_to_the_selected_bound_descriptor() {
    assert_eq!(
        super::unix_bound_execution_descriptor(std::path::Path::new("/proc/self/fd/41")),
        Some(41)
    );
    assert_eq!(
        super::unix_bound_execution_descriptor(std::path::Path::new("/dev/fd/42")),
        Some(42)
    );
    for unbound in [
        "/usr/bin/ffmpeg",
        "/proc/self/fd/41/trailing",
        "/proc/other/fd/41",
        "/dev/fd/-1",
    ] {
        assert_eq!(
            super::unix_bound_execution_descriptor(std::path::Path::new(unbound)),
            None
        );
    }
}

#[test]
fn unix_bound_descriptor_inheritance_never_changes_parent_fd_flags() {
    let source = include_str!("../process.rs");
    let configuration = source
        .split("fn configure_unix_descriptor_inheritance")
        .nth(1)
        .and_then(|source| source.split("\n#[cfg(").next())
        .expect("Unix child-only descriptor inheritance configuration");

    assert!(configuration.contains(".pre_exec("));
    assert!(configuration.contains("libc::F_SETFD"));
    assert_eq!(
        source.matches("libc::F_SETFD").count(),
        configuration.matches("libc::F_SETFD").count(),
        "FD_CLOEXEC may only be changed by the forked child's pre_exec hook"
    );
    assert!(
        !source.contains("struct UnixDescriptorInheritance"),
        "a parent-side inheritance guard can race unrelated process spawns"
    );
}

#[test]
fn linux_group_parser_distinguishes_terminal_zombies_with_stable_start_identity() {
    let statistics =
        "321 (descendant with spaces) Z 300 300 300 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 987654 0";
    let identity = super::parse_linux_process_identity(statistics).expect("parse proc stat");

    assert_eq!(identity.process_group, 300);
    assert_eq!(identity.start_time, 987654);
    assert!(identity.terminal);
}

async fn abort_one_run_at_reader_handoff(
    supervisor: &std::sync::Arc<ProcessSupervisor>,
) -> Result<(), super::ProcessError> {
    let hooks = supervisor.test_hooks();
    hooks.set_reader_completion_pause(true);
    hooks.set_reader_handoff_pause(true);
    let running = {
        let supervisor = supervisor.clone();
        tokio::spawn(async move { supervisor.run_bounded(inert_spec()).await })
    };
    wait_for_hook(|| hooks.reader_completion_reached()).await;
    wait_for_hook(|| hooks.reader_handoff_reached()).await;
    running.abort();
    assert!(
        running
            .await
            .expect_err("run future must be aborted")
            .is_cancelled()
    );
    hooks.set_reader_handoff_pause(false);
    let premature_drain = supervisor.wait_for_idle(Duration::from_millis(100)).await;
    hooks.set_reader_completion_pause(false);
    supervisor
        .wait_for_idle(Duration::from_secs(5))
        .await
        .expect("reader owner must converge after the barrier opens");
    premature_drain
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_pauses_only_block_the_target_supervisor() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    let target = std::sync::Arc::new(ProcessSupervisor::new(CancellationToken::new()));
    let control = ProcessSupervisor::new(CancellationToken::new());
    let hooks = target.test_hooks();
    hooks.set_reader_completion_pause(true);
    hooks.set_owner_complete_pause(true);
    let target_run = {
        let target = target.clone();
        tokio::spawn(async move { target.run_bounded(inert_spec()).await })
    };

    wait_for_hook(|| hooks.reader_completion_reached()).await;
    tokio::time::timeout(Duration::from_secs(2), control.run_bounded(inert_spec()))
        .await
        .expect("unrelated supervisor must not inherit reader pause")
        .expect("unrelated supervisor completes normally");
    assert_eq!(target.active_processes(), 1);

    hooks.set_reader_completion_pause(false);
    wait_for_hook(|| hooks.owner_complete_reached()).await;
    assert!(
        !target_run.is_finished(),
        "target owner must remain at its own completion barrier"
    );
    hooks.set_owner_complete_pause(false);
    target_run
        .await
        .expect("join target run")
        .expect("target completes after releasing its own hooks");
    assert_eq!(target.active_processes(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_after_complete_send_keeps_owner_until_registry_and_permit_are_released() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    let supervisor = std::sync::Arc::new(ProcessSupervisor::with_max_concurrency(
        CancellationToken::new(),
        1,
    ));
    supervisor
        .run_bounded(inert_spec())
        .await
        .expect("warm owner resources");
    let resources_before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();
    let hooks = supervisor.test_hooks();
    hooks.set_owner_complete_pause(true);
    let running = {
        let supervisor = supervisor.clone();
        tokio::spawn(async move { supervisor.run_bounded(inert_spec()).await })
    };
    wait_for_hook(|| hooks.owner_complete_reached()).await;
    let registration_id = *supervisor
        .inner
        .registry
        .entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .keys()
        .next()
        .expect("registered process during owner completion");
    assert_eq!(supervisor.active_processes(), 1);
    assert_eq!(supervisor.inner.permits.available_permits(), 0);

    running.abort();
    assert!(
        running
            .await
            .expect_err("run future must be aborted")
            .is_cancelled()
    );
    hooks.set_owner_complete_pause(false);
    let first_drain = supervisor.wait_for_idle(Duration::from_millis(100)).await;
    if first_drain.is_err() {
        remove_test_registry_entry(&supervisor, registration_id);
    }

    assert!(
        first_drain.is_ok(),
        "owner acknowledgment was not preceded by durable registry completion"
    );
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.inner.permits.available_permits(), 1);
    assert_eq!(supervisor.test_resource_snapshot(), resources_before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_after_reader_handoff_keeps_readers_registry_and_permit_owned_until_joined() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    let supervisor = std::sync::Arc::new(ProcessSupervisor::with_max_concurrency(
        CancellationToken::new(),
        1,
    ));
    let _ = abort_one_run_at_reader_handoff(&supervisor).await;
    let resources_before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();
    let premature_drain = abort_one_run_at_reader_handoff(&supervisor).await;

    assert!(
        premature_drain.is_err(),
        "reader handles left durable ownership before their tasks finished"
    );
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.inner.permits.available_permits(), 1);
    assert_eq!(supervisor.test_resource_snapshot(), resources_before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}

#[test]
fn registration_drop_without_a_runtime_leaves_no_stuck_cleanup_state() {
    let _resource_guard = super::PROCESS_TEST_LOCK.blocking_lock();
    let supervisor = ProcessSupervisor::with_max_concurrency(CancellationToken::new(), 1);
    let permit = supervisor
        .inner
        .permits
        .clone()
        .try_acquire_owned()
        .expect("owned test permit");
    let mut request = inert_spec();
    request.args = vec![
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("transcoding::process::tests::retained_registry_sleep_helper"),
    ];
    let spawned = super::windows::spawn(&request, supervisor.inner.registry.clone(), None)
        .expect("spawn no-runtime cleanup helper");
    let super::windows::SpawnedProcess {
        process,
        job,
        stdout,
        stderr,
        registration,
    } = spawned;
    let pid = super::windows::process_id(&process);
    let registration_id = registration.id;
    registration.bind_permit(permit);
    drop((process, job, stdout, stderr, registration));

    let drain_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("drain runtime");
    let first_drain = drain_runtime.block_on(supervisor.wait_for_idle(Duration::from_millis(100)));
    if first_drain.is_err() {
        supervisor
            .force_terminate_registered()
            .expect("test cleanup termination");
        remove_test_registry_entry(&supervisor, registration_id);
    }

    assert!(
        first_drain.is_ok(),
        "cleanup_started remained set without a Tokio cleanup owner"
    );
    assert!(!super::windows::process_is_alive(pid));
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.inner.permits.available_permits(), 1);
}

#[test]
fn never_polled_owner_is_killed_and_made_reapable_during_runtime_teardown() {
    let _resource_guard = super::PROCESS_TEST_LOCK.blocking_lock();
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let mut request = inert_spec();
    request.args = vec![
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("transcoding::process::tests::retained_registry_sleep_helper"),
    ];
    let spawned = super::windows::spawn(&request, supervisor.inner.registry.clone(), None)
        .expect("spawn never-polled-owner helper");
    let super::windows::SpawnedProcess {
        process,
        job,
        stdout,
        stderr,
        mut registration,
    } = spawned;
    let pid = super::windows::process_id(&process);
    let registration_id = registration.id;
    let owner_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("owner runtime");
    registration.start_windows_owner_on(owner_runtime.handle());
    drop((process, job, stdout, stderr, registration));
    owner_runtime.shutdown_timeout(Duration::ZERO);

    let drain_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("drain runtime");
    let first_drain = drain_runtime.block_on(supervisor.wait_for_idle(Duration::from_millis(50)));
    if first_drain.is_err() {
        supervisor
            .force_terminate_registered()
            .expect("test cleanup termination");
        supervisor
            .inner
            .registry
            .mark_cleanup_stopped(registration_id);
        drain_runtime
            .block_on(supervisor.wait_for_idle(Duration::from_secs(5)))
            .expect("test cleanup registry drain");
    }

    assert!(
        first_drain.is_ok(),
        "a queued but never-polled owner left retained cleanup permanently active"
    );
    assert!(!super::windows::process_is_alive(pid));
}

#[test]
#[ignore = "spawned only by post_resume_failure_drains_descendant_job_before_return"]
fn post_resume_descendant_helper() {
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--ignored",
            "--exact",
            "transcoding::process::tests::retained_registry_sleep_helper",
        ])
        .spawn()
        .expect("spawn descendant helper");
    fs::write(
        std::env::var_os("STREAM_SERVER_TEST_DESCENDANT_MARKER")
            .expect("descendant marker environment"),
        child.id().to_string(),
    )
    .expect("write descendant pid");
    std::thread::sleep(Duration::from_secs(60));
    let _ = child.wait();
}

fn inert_spec() -> ProcessSpec {
    ProcessSpec {
        executable: std::env::current_exe().expect("test executable path"),
        args: vec![
            OsString::from("--exact"),
            OsString::from("transcoding::process::tests::never_matches"),
        ],
        current_dir: std::env::current_dir().expect("test current directory"),
        environment: BTreeMap::new(),
        stdin: StdinPolicy::Null,
        stdout: StdoutPolicy::Null,
        stderr_byte_limit: 1_024,
        wall_deadline: Duration::from_secs(2),
    }
}

#[tokio::test]
async fn every_injected_native_spawn_failure_releases_all_resources_and_registry_ownership() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    let points = [
        FailurePoint::PipeSetup,
        FailurePoint::AttributeListUpdate,
        FailurePoint::AttributeListSetup,
        FailurePoint::SuspendedCreate,
        FailurePoint::JobAssignment,
        FailurePoint::RegistryInsertion,
        FailurePoint::Resume,
    ];
    // Let Tokio and the Windows loader initialize runtime-owned handles for
    // every native boundary before measuring repeated-call growth.
    for point in points {
        let warmup = ProcessSupervisor::with_failure_point(CancellationToken::new(), point);
        let _ = warmup.run_bounded(inert_spec()).await;
    }

    for point in points {
        let supervisor = ProcessSupervisor::with_failure_point(CancellationToken::new(), point);
        let before = supervisor.test_resource_snapshot();
        let handles_before = supervisor.test_native_handle_count();

        let error = supervisor
            .run_bounded(inert_spec())
            .await
            .expect_err("injected failure must be returned");

        assert_eq!(error.code(), ProcessErrorCode::SpawnFailed, "{point:?}");
        assert_eq!(
            supervisor.active_processes(),
            0,
            "{point:?} leaked registry ownership"
        );
        assert_eq!(
            supervisor.test_resource_snapshot(),
            before,
            "{point:?} leaked native resources"
        );
        assert_eq!(
            supervisor.test_native_handle_count(),
            handles_before,
            "{point:?} changed the native process handle count"
        );
    }
}

#[tokio::test]
async fn update_attribute_failure_creates_no_child_and_releases_initialized_storage() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    ProcessSupervisor::new(CancellationToken::new())
        .run_bounded(inert_spec())
        .await
        .expect("warm owner and blocking spawn resources");
    let supervisor = ProcessSupervisor::with_failure_point(
        CancellationToken::new(),
        FailurePoint::AttributeListUpdate,
    );
    let before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();

    let error = supervisor
        .run_bounded(inert_spec())
        .await
        .expect_err("attribute update injection must fail");

    assert_eq!(error.code(), ProcessErrorCode::SpawnFailed);
    assert_eq!(supervisor.test_hooks().last_created_pid(), 0);
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.test_resource_snapshot(), before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}

#[tokio::test]
async fn every_post_create_injected_failure_waits_until_the_actual_pid_is_dead() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    for point in [
        FailurePoint::SuspendedCreate,
        FailurePoint::JobAssignment,
        FailurePoint::RegistryInsertion,
        FailurePoint::Resume,
    ] {
        let supervisor = ProcessSupervisor::with_failure_point(CancellationToken::new(), point);

        supervisor
            .run_bounded(inert_spec())
            .await
            .expect_err("post-create injection must fail");
        let pid = supervisor.test_hooks().last_created_pid();

        assert_ne!(pid, 0, "{point:?} did not reach CreateProcessW");
        assert!(
            !super::windows::process_is_alive(pid),
            "{point:?} released ownership before PID {pid} was dead"
        );
        assert_eq!(supervisor.active_processes(), 0);
    }
}

#[tokio::test]
async fn post_resume_failure_drains_descendant_job_before_return() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    ProcessSupervisor::new(CancellationToken::new())
        .run_bounded(inert_spec())
        .await
        .expect("warm owner and blocking cleanup resources");
    let marker_directory = tempfile::tempdir().expect("descendant marker directory");
    let marker = marker_directory.path().join("child.pid");
    let supervisor = ProcessSupervisor::with_failure_point(
        CancellationToken::new(),
        FailurePoint::ResumeAfterDescendant,
    );
    let resources_before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();
    let mut request = inert_spec();
    request.args = vec![
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("transcoding::process::tests::post_resume_descendant_helper"),
    ];
    request.environment.insert(
        OsString::from("STREAM_SERVER_TEST_DESCENDANT_MARKER"),
        marker.as_os_str().to_os_string(),
    );

    let error = supervisor
        .run_bounded(request)
        .await
        .expect_err("post-resume injection must fail");
    let parent_pid = supervisor.test_hooks().last_created_pid();
    let child_pid = fs::read_to_string(&marker)
        .expect("read descendant pid")
        .parse::<u32>()
        .expect("parse descendant pid");

    assert_eq!(error.code(), ProcessErrorCode::SpawnFailed);
    assert!(!super::windows::process_is_alive(parent_pid));
    assert!(!super::windows::process_is_alive(child_pid));
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.test_resource_snapshot(), resources_before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_during_native_return_handoff_keeps_tree_permit_and_handles_owned() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    ProcessSupervisor::new(CancellationToken::new())
        .run_bounded(inert_spec())
        .await
        .expect("warm owner and blocking cleanup resources");
    let marker_directory = tempfile::tempdir().expect("handoff marker directory");
    let marker = marker_directory.path().join("child.pid");
    let supervisor = std::sync::Arc::new(ProcessSupervisor::with_failure_point(
        CancellationToken::new(),
        FailurePoint::PauseAfterResume,
    ));
    let resources_before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();
    let mut request = inert_spec();
    request.args = vec![
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("transcoding::process::tests::post_resume_descendant_helper"),
    ];
    request.environment.insert(
        OsString::from("STREAM_SERVER_TEST_DESCENDANT_MARKER"),
        marker.as_os_str().to_os_string(),
    );
    let hooks = supervisor.test_hooks();
    hooks.set_after_resume_pause(true);
    let running = tokio::spawn({
        let supervisor = supervisor.clone();
        async move { supervisor.run_bounded(request).await }
    });
    while !hooks.after_resume_reached() {
        tokio::task::yield_now().await;
    }
    while !marker.is_file() {
        tokio::task::yield_now().await;
    }
    let parent_pid = hooks.last_created_pid();
    let child_pid = fs::read_to_string(&marker)
        .expect("read descendant pid")
        .parse::<u32>()
        .expect("parse descendant pid");

    running.abort();
    assert_eq!(supervisor.active_processes(), 1);
    assert_eq!(
        supervisor.inner.permits.available_permits(),
        super::DEFAULT_MAX_CONCURRENT_PROCESSES - 1
    );
    hooks.set_after_resume_pause(false);
    assert!(
        running
            .await
            .expect_err("outer run future must abort")
            .is_cancelled()
    );
    supervisor
        .wait_for_idle(Duration::from_secs(8))
        .await
        .expect("blocking-worker handoff cleanup must drain");

    assert!(!super::windows::process_is_alive(parent_pid));
    assert!(!super::windows::process_is_alive(child_pid));
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(
        supervisor.inner.permits.available_permits(),
        super::DEFAULT_MAX_CONCURRENT_PROCESSES
    );
    assert_eq!(supervisor.test_resource_snapshot(), resources_before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}

#[tokio::test]
async fn retained_registry_entry_can_be_retried_until_confirmed_drained() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    supervisor
        .run_bounded(inert_spec())
        .await
        .expect("warm owner and blocking cleanup resources");
    let resources_before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();
    let mut request = inert_spec();
    request.args = vec![
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("transcoding::process::tests::retained_registry_sleep_helper"),
    ];
    let spawned = super::windows::spawn(&request, supervisor.inner.registry.clone(), None)
        .expect("spawn retained-registry helper");
    let super::windows::SpawnedProcess {
        process,
        job,
        stdout,
        stderr,
        registration,
    } = spawned;
    let pid = super::windows::process_id(&process);
    registration.retain();
    drop((process, job, stdout, stderr));

    let error = supervisor
        .wait_for_idle(Duration::from_millis(20))
        .await
        .expect_err("a live retained job must not be reported idle");

    assert_eq!(error.code(), ProcessErrorCode::WaitFailed);
    assert_eq!(error.to_string(), "process wait failed");
    assert_eq!(supervisor.active_processes(), 1);

    supervisor
        .force_terminate_registered()
        .expect("retry termination");
    supervisor
        .wait_for_idle(Duration::from_secs(5))
        .await
        .expect("retry must confirm the retained job drained");

    assert_eq!(supervisor.active_processes(), 0);
    assert!(!super::windows::process_is_alive(pid));
    assert_eq!(supervisor.test_resource_snapshot(), resources_before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}

#[tokio::test]
async fn post_spawn_wait_failure_retains_blocking_readers_until_retry_drains_every_resource() {
    let _resource_guard = super::PROCESS_TEST_LOCK.lock().await;
    ProcessSupervisor::new(CancellationToken::new())
        .run_bounded(inert_spec())
        .await
        .expect("warm native spawn and blocking readers");
    let supervisor = ProcessSupervisor::with_failure_point(
        CancellationToken::new(),
        FailurePoint::WaitAfterReaders,
    );
    let resources_before = supervisor.test_resource_snapshot();
    let handles_before = supervisor.test_native_handle_count();
    let mut request = inert_spec();
    request.args = vec![
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("transcoding::process::tests::retained_registry_sleep_helper"),
    ];

    let error = supervisor
        .run_bounded(request)
        .await
        .expect_err("injected post-reader wait failure must surface");

    assert_eq!(error.code(), ProcessErrorCode::WaitFailed);
    assert_eq!(error.to_string(), "process wait failed");
    assert_eq!(supervisor.active_processes(), 1);

    supervisor
        .force_terminate_registered()
        .expect("retry termination");
    supervisor
        .wait_for_idle(Duration::from_secs(5))
        .await
        .expect("retry must drain process and retained blocking readers");

    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.test_resource_snapshot(), resources_before);
    assert_eq!(supervisor.test_native_handle_count(), handles_before);
}
