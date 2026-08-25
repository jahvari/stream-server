#![cfg(windows)]

use super::{
    FailurePoint, ProcessErrorCode, ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy,
};
use std::{collections::BTreeMap, ffi::OsString, time::Duration};
use tokio_util::sync::CancellationToken;

#[test]
#[ignore = "spawned only by retained_registry_entry_can_be_retried_until_confirmed_drained"]
fn retained_registry_sleep_helper() {
    std::thread::sleep(Duration::from_secs(60));
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
        let before = super::windows::resource_snapshot();
        let handles_before = super::windows::process_handle_count();

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
            super::windows::resource_snapshot(),
            before,
            "{point:?} leaked native resources"
        );
        assert_eq!(
            super::windows::process_handle_count(),
            handles_before,
            "{point:?} changed the native process handle count"
        );
    }
}

#[tokio::test]
async fn update_attribute_failure_creates_no_child_and_releases_initialized_storage() {
    let supervisor = ProcessSupervisor::with_failure_point(
        CancellationToken::new(),
        FailurePoint::AttributeListUpdate,
    );
    let before = super::windows::resource_snapshot();
    let handles_before = super::windows::process_handle_count();

    let error = supervisor
        .run_bounded(inert_spec())
        .await
        .expect_err("attribute update injection must fail");

    assert_eq!(error.code(), ProcessErrorCode::SpawnFailed);
    assert_eq!(super::windows::last_created_pid(), 0);
    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(super::windows::resource_snapshot(), before);
    assert_eq!(super::windows::process_handle_count(), handles_before);
}

#[tokio::test]
async fn every_post_create_injected_failure_waits_until_the_actual_pid_is_dead() {
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
        let pid = super::windows::last_created_pid();

        assert_ne!(pid, 0, "{point:?} did not reach CreateProcessW");
        assert!(
            !super::windows::process_is_alive(pid),
            "{point:?} released ownership before PID {pid} was dead"
        );
        assert_eq!(supervisor.active_processes(), 0);
    }
}

#[tokio::test]
async fn retained_registry_entry_can_be_retried_until_confirmed_drained() {
    let supervisor = ProcessSupervisor::new(CancellationToken::new());
    let resources_before = super::windows::resource_snapshot();
    let handles_before = super::windows::process_handle_count();
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
    assert!(super::windows::process_is_alive(pid));

    supervisor
        .force_terminate_registered()
        .expect("retry termination");
    supervisor
        .wait_for_idle(Duration::from_secs(5))
        .await
        .expect("retry must confirm the retained job drained");

    assert_eq!(supervisor.active_processes(), 0);
    assert!(!super::windows::process_is_alive(pid));
    assert_eq!(super::windows::resource_snapshot(), resources_before);
    assert_eq!(super::windows::process_handle_count(), handles_before);
}

#[tokio::test]
async fn post_spawn_wait_failure_retains_blocking_readers_until_retry_drains_every_resource() {
    ProcessSupervisor::new(CancellationToken::new())
        .run_bounded(inert_spec())
        .await
        .expect("warm native spawn and blocking readers");
    let supervisor = ProcessSupervisor::with_failure_point(
        CancellationToken::new(),
        FailurePoint::WaitAfterReaders,
    );
    let resources_before = super::windows::resource_snapshot();
    let handles_before = super::windows::process_handle_count();
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
    assert_eq!(super::windows::resource_snapshot(), resources_before);
    assert_eq!(super::windows::process_handle_count(), handles_before);
}
