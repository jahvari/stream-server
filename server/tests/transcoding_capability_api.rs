use std::time::Duration;

const SERVER_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

#[test]
fn public_server_exposes_the_isolated_loopback_capability_api() -> anyhow::Result<()> {
    let config_dir = tempfile::tempdir()?;
    let cache_dir = tempfile::tempdir()?;
    let server_config_dir = config_dir.path().join("config");
    let handle = stream_server::start(stream_server::ServerConfig {
        http_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        config_dir: Some(server_config_dir.clone()),
        cache_dir: Some(cache_dir.path().join("cache")),
        ..stream_server::ServerConfig::default()
    })?;
    let address = handle.http_addr();
    let response = reqwest::blocking::Client::new()
        .get(format!("http://{address}/transcoding/capabilities"))
        .header("origin", format!("http://{address}"))
        .send()?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers()[reqwest::header::CONTENT_TYPE],
        "application/json"
    );
    assert_eq!(
        response.headers()[reqwest::header::CACHE_CONTROL],
        "no-store"
    );
    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'none'"
    );
    assert_eq!(
        response.headers()["cross-origin-resource-policy"],
        "same-origin"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    let body: serde_json::Value = response.json()?;
    assert_eq!(body["schemaVersion"], 1);
    assert_eq!(body["freshness"], "uninitialized");

    let forbidden = reqwest::blocking::Client::new()
        .get(format!("http://{address}/transcoding/capabilities"))
        .header("host", "example.com")
        .header("origin", "http://example.com")
        .send()?;
    assert_eq!(forbidden.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        forbidden
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    assert_eq!(
        forbidden.text()?,
        r#"{"schemaVersion":1,"error":"forbidden"}"#
    );

    let token = std::fs::read(server_config_dir.join("settings-control.token"))?;
    let accepted = reqwest::blocking::Client::new()
        .post(format!("http://{address}/transcoding/capabilities/refresh"))
        .header("x-stream-server-settings-token", token)
        .send()?;
    assert_eq!(accepted.status(), reqwest::StatusCode::ACCEPTED);
    assert!(
        accepted
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    let accepted_body: serde_json::Value = accepted.json()?;
    assert_eq!(accepted_body["schemaVersion"], 1);
    assert_eq!(accepted_body.as_object().unwrap().len(), 2);

    handle.shutdown()?;
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let joiner = std::thread::spawn(move || {
        let _ = result_tx.send(handle.join());
    });
    result_rx
        .recv_timeout(SERVER_JOIN_TIMEOUT)
        .map_err(|error| anyhow::anyhow!("server did not stop: {error}"))??;
    joiner
        .join()
        .map_err(|_| anyhow::anyhow!("join helper panicked"))?;
    Ok(())
}
