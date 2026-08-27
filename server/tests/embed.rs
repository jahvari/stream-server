use std::time::Duration;

const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

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

    handle.shutdown()?;

    // ServerHandle::join is intentionally blocking. Run it on a separate
    // thread so a shutdown regression fails this test instead of hanging CI.
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

    assert_eq!(
        shutdown_source,
        Some(stream_server::ShutdownSource::External)
    );

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
