use std::time::Duration;

const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

fn protected_config_tempdir() -> anyhow::Result<tempfile::TempDir> {
    #[cfg(windows)]
    {
        // Windows hosted-runner temp roots can contain reparse aliases. The
        // production storage policy correctly rejects those paths, so keep
        // this writable-lock fixture under the checked-out workspace instead.
        Ok(tempfile::Builder::new()
            .prefix(".stream-server-protected-test-")
            .tempdir_in(std::env::current_dir()?)?)
    }
    #[cfg(not(windows))]
    {
        Ok(tempfile::tempdir()?)
    }
}

fn stop_and_join(
    handle: stream_server::ServerHandle,
) -> anyhow::Result<Option<stream_server::ShutdownSource>> {
    handle.shutdown()?;
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let joiner = std::thread::spawn(move || {
        let _ = result_tx.send(handle.join());
    });
    let shutdown_source = result_rx
        .recv_timeout(SERVER_JOIN_TIMEOUT)
        .map_err(|err| {
            anyhow::anyhow!("embedded server did not stop within {SERVER_JOIN_TIMEOUT:?}: {err}")
        })??;
    joiner
        .join()
        .map_err(|_| anyhow::anyhow!("server join helper thread panicked"))?;
    Ok(shutdown_source)
}

fn start_and_stop_embedded_server() -> anyhow::Result<()> {
    let config_dir = tempfile::tempdir()?;
    let cache_dir = tempfile::tempdir()?;

    let handle = stream_server::start(stream_server::ServerConfig {
        // Tests must not compete with a running desktop instance (or another
        // test process) for the production port.
        http_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        config_dir: Some(config_dir.path().join("config")),
        cache_dir: Some(cache_dir.path().join("cache")),
        ..stream_server::ServerConfig::default()
    })?;

    let response = reqwest::blocking::get(format!("http://{}/heartbeat", handle.http_addr()))?
        .error_for_status()?;
    let body: serde_json::Value = response.json()?;
    assert_eq!(body["success"], true);

    // ServerHandle::join is intentionally blocking. Run it on a separate
    // thread so a shutdown regression fails this test instead of hanging CI.
    let shutdown_source = stop_and_join(handle)?;

    assert_eq!(
        shutdown_source,
        Some(stream_server::ShutdownSource::External)
    );

    Ok(())
}

#[test]
fn capability_storage_lock_is_released_before_embedded_shutdown_returns() -> anyhow::Result<()> {
    let config_dir = protected_config_tempdir()?;
    let cache_dir = tempfile::tempdir()?;
    let server_config_dir = config_dir.path().join("config");

    for cycle in 1..=2 {
        let handle = stream_server::start(stream_server::ServerConfig {
            http_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            config_dir: Some(server_config_dir.clone()),
            cache_dir: Some(cache_dir.path().join("cache")),
            ..stream_server::ServerConfig::default()
        })?;
        let body: serde_json::Value = reqwest::blocking::get(format!(
            "http://{}/transcoding/capabilities",
            handle.http_addr()
        ))?
        .error_for_status()?
        .json()?;
        assert_eq!(
            body["storage"]["status"], "writable",
            "cycle {cycle} must own the protected capability lock"
        );
        assert_eq!(
            stop_and_join(handle)?,
            Some(stream_server::ShutdownSource::External)
        );
    }

    Ok(())
}

#[cfg(not(windows))]
#[test]
fn starts_and_stops_embedded_server() -> anyhow::Result<()> {
    start_and_stop_embedded_server()
}

#[cfg(windows)]
#[test]
fn repeated_windows_shutdown_completes_after_thread_local_cleanup() -> anyhow::Result<()> {
    // Rust 1.98 moved Windows thread-local destruction to Fiber Local Storage.
    // Repeated full runtime teardown exercises that path and catches hangs or
    // cleanup-order regressions that a single lifecycle may miss.
    const CYCLES: usize = 5;

    for cycle in 1..=CYCLES {
        start_and_stop_embedded_server()
            .map_err(|err| anyhow::anyhow!("shutdown cycle {cycle}/{CYCLES} failed: {err:#}"))?;
    }

    Ok(())
}
