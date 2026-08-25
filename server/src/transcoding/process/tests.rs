#![cfg(windows)]

use super::{
    FailurePoint, ProcessErrorCode, ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy,
};
use std::{collections::BTreeMap, ffi::OsString, time::Duration};
use tokio_util::sync::CancellationToken;

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
