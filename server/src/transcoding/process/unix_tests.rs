#[cfg(target_os = "linux")]
use super::{ProcessSpec, ProcessSupervisor, StdinPolicy, StdoutPolicy};
#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, sync::Arc, time::Duration};
#[cfg(target_os = "linux")]
use tokio_util::sync::CancellationToken;

#[test]
fn macos_process_status_only_treats_zombies_as_terminal_before_leader_reap() {
    assert!(super::macos_process_status_is_terminal(5));
    for running_status in [1, 2, 3, 4] {
        assert!(!super::macos_process_status_is_terminal(running_status));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn dropping_tokio_runtime_keeps_os_owner_until_child_descendant_and_readers_reap() {
    let directory = tempfile::tempdir().expect("Unix teardown markers");
    let descendant_marker = directory.path().join("descendant.pid");
    let started_marker = directory.path().join("started");
    let supervisor = Arc::new(ProcessSupervisor::with_max_concurrency(
        CancellationToken::new(),
        1,
    ));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime");
    runtime.block_on(async {
        let spec = ProcessSpec {
            executable: PathBuf::from("/bin/sh"),
            args: vec![
                OsString::from("-c"),
                OsString::from(format!(
                    "sleep 60 & child=$!; echo $child > '{}'; : > '{}'; wait",
                    descendant_marker.display(),
                    started_marker.display()
                )),
            ],
            current_dir: directory.path().to_path_buf(),
            environment: BTreeMap::new(),
            stdin: StdinPolicy::Null,
            stdout: StdoutPolicy::Capture { byte_limit: 1024 },
            stderr_byte_limit: 1024,
            wall_deadline: Duration::from_secs(60),
        };
        let running_supervisor = supervisor.clone();
        tokio::spawn(async move { running_supervisor.run_bounded(spec).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !started_marker.is_file() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("child and descendant reached explicit barrier");
        tokio::time::timeout(Duration::from_secs(2), async {
            while supervisor.active_processes() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("spawned process reached the supervisor registry");
        assert_eq!(supervisor.active_processes(), 1);
    });
    let descendant = std::fs::read_to_string(&descendant_marker)
        .expect("read descendant PID")
        .trim()
        .parse::<i32>()
        .expect("parse descendant PID");
    drop(runtime);

    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("drain runtime")
        .block_on(supervisor.wait_for_idle(Duration::from_secs(10)))
        .expect("OS owner drains after original runtime teardown");

    assert_eq!(supervisor.active_processes(), 0);
    assert_eq!(supervisor.inner.permits.available_permits(), 1);
    assert_eq!(unsafe { libc::kill(descendant, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "descendant remained after durable owner cleanup"
    );
}
