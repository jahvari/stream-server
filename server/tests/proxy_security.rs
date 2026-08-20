use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Response, StatusCode, header},
    routing::get,
};
use futures_util::{StreamExt, stream};
use serde_json::json;
use std::{convert::Infallible, time::Duration};

async fn range(headers: HeaderMap) -> Response<Body> {
    let bytes = b"0123456789";
    if headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        == Some("bytes=2-5")
    {
        return Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_RANGE, "bytes 2-5/10")
            .header(header::CONTENT_LENGTH, "4")
            .body(Body::from(&bytes[2..=5]))
            .unwrap();
    }
    Response::new(Body::from(bytes.as_slice()))
}

async fn stall() -> Response<Body> {
    let first = stream::once(async { Ok::<_, Infallible>(bytes::Bytes::from_static(b"first")) });
    let stalled = stream::pending::<Result<bytes::Bytes, Infallible>>();
    Response::new(Body::from_stream(first.chain(stalled)))
}

async fn start_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let router = Router::new()
        .route("/ok", get(|| async { "fixture-ok" }))
        .route("/range", get(range))
        .route(
            "/playlist",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "application/vnd.apple.mpegurl"),
                        (header::CONTENT_RANGE, "bytes 0-9/10"),
                    ],
                    "#EXTM3U\nsegment.ts\n",
                )
            }),
        )
        .route(
            "/playlist-partial",
            get(|| async {
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                    .header(header::CONTENT_RANGE, "bytes 0-10/100")
                    .header(header::CONTENT_LENGTH, "11")
                    .body(Body::from("segment.ts\n"))
                    .unwrap()
            }),
        )
        .route(
            "/redirect-metadata",
            get(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, "http://169.254.169.254/latest/meta-data/")],
                )
            }),
        )
        .route("/stall", get(stall));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (address, task)
}

async fn start_tls_fixture() -> anyhow::Result<(
    std::net::SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
)> {
    // This private key is intentionally public test data. Never reuse it outside tests.
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/localhost-cert.pem"
        ),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/localhost-key.pem"
        ),
    )
    .await?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let app = Router::new()
        .route("/ok", get(|| async { "secure-fixture-ok" }))
        .route(
            "/redirect-http",
            get(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, "http://example.com/")],
                )
            }),
        );
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)?
            .serve(app.into_make_service())
            .await?;
        Ok(())
    });
    Ok((address, task))
}

fn proxy_url(server: std::net::SocketAddr, target: &str) -> String {
    format!("http://{server}/proxy/?d={}", urlencoding::encode(target))
}

#[tokio::test]
async fn default_deny_protected_opt_in_and_cancellation_work_end_to_end() -> anyhow::Result<()> {
    let (fixture_addr, fixture_task) = start_fixture().await;
    let (tls_fixture_addr, tls_fixture_task) = start_tls_fixture().await?;
    let config = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let config_dir = config.path().join("config");
    let server_config = stream_server::ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        config_dir: Some(config_dir.clone()),
        cache_dir: Some(cache.path().join("cache")),
        ..stream_server::ServerConfig::embedded()
    };
    let server = tokio::task::spawn_blocking(move || stream_server::start(server_config)).await??;
    let base = format!("http://{}", server.http_addr());
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let ok_target = format!("http://{fixture_addr}/ok");

    let denied = client
        .get(proxy_url(server.http_addr(), &ok_target))
        .send()
        .await?;
    let denied_status = denied.status();
    let denied_body = denied.text().await?;
    assert_eq!(
        denied_status,
        StatusCode::FORBIDDEN,
        "unexpected proxy response body: {denied_body:?}"
    );
    assert_eq!(denied_body, "Proxy destination is blocked");

    let unauthorized = client
        .post(format!("{base}/settings"))
        .json(&json!({"allowPrivateNetworkSources": true}))
        .send()
        .await?;
    assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);

    let token = std::fs::read_to_string(config_dir.join("settings-control.token"))?;
    assert_eq!(token.len(), 64);
    let authorized = |payload: serde_json::Value| {
        client
            .post(format!("{base}/settings"))
            .header("x-stream-server-settings-token", token.clone())
            .json(&payload)
    };
    assert_eq!(
        authorized(json!({"allowPrivateNetworkSources": true}))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );

    let allowed = client
        .get(proxy_url(server.http_addr(), &ok_target))
        .send()
        .await?;
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(allowed.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(allowed.text().await?, "fixture-ok");

    let range_target = format!("http://{fixture_addr}/range");
    let range = client
        .get(proxy_url(server.http_addr(), &range_target))
        .header(header::RANGE, "bytes=2-5")
        .send()
        .await?;
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(range.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
    assert_eq!(range.headers()[header::CONTENT_LENGTH], "4");
    assert_eq!(range.bytes().await?, &b"2345"[..]);

    let playlist_target = format!("http://{fixture_addr}/playlist");
    let playlist = client
        .get(proxy_url(server.http_addr(), &playlist_target))
        .send()
        .await?;
    assert_eq!(playlist.status(), StatusCode::OK);
    assert!(playlist.headers().get(header::CONTENT_LENGTH).is_none());
    assert!(playlist.headers().get(header::CONTENT_RANGE).is_none());
    assert!(playlist.headers().get(header::CONTENT_ENCODING).is_none());
    assert!(playlist.text().await?.contains("/proxy/?d="));

    let partial_playlist_target = format!("http://{fixture_addr}/playlist-partial");
    let partial_playlist = client
        .get(proxy_url(server.http_addr(), &partial_playlist_target))
        .send()
        .await?;
    assert_eq!(partial_playlist.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        partial_playlist.headers()[header::CONTENT_RANGE],
        "bytes 0-10/100"
    );
    assert_eq!(partial_playlist.headers()[header::CONTENT_LENGTH], "11");
    assert_eq!(partial_playlist.text().await?, "segment.ts\n");

    for self_path in ["/heartbeat", "/settings", "/proxy"] {
        let self_target = format!("{base}{self_path}");
        assert_eq!(
            client
                .get(proxy_url(server.http_addr(), &self_target))
                .send()
                .await?
                .status(),
            StatusCode::FORBIDDEN,
            "self-listener path was not blocked: {self_path}"
        );
    }
    let redirect_target = format!("http://{fixture_addr}/redirect-metadata");
    assert_eq!(
        client
            .get(proxy_url(server.http_addr(), &redirect_target))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );

    let tls_target = format!("https://127.0.0.1:{}/ok", tls_fixture_addr.port());
    let default_tls = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .get(proxy_url(server.http_addr(), &tls_target))
            .send(),
    )
    .await??;
    assert_eq!(default_tls.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(default_tls.text().await?, "Proxy upstream request failed");
    assert_eq!(
        authorized(json!({"allowInvalidProxyTlsCertificates": true}))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let allowed_tls = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .get(proxy_url(server.http_addr(), &tls_target))
            .send(),
    )
    .await??;
    assert_eq!(allowed_tls.status(), StatusCode::OK);
    assert_eq!(allowed_tls.text().await?, "secure-fixture-ok");
    let downgrade_target = format!(
        "https://127.0.0.1:{}/redirect-http",
        tls_fixture_addr.port()
    );
    let downgrade = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .get(proxy_url(server.http_addr(), &downgrade_target))
            .send(),
    )
    .await??;
    assert_eq!(downgrade.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(downgrade.text().await?, "Proxy upstream request failed");

    let stall_target = format!("http://{fixture_addr}/stall");
    let stalled = client
        .get(proxy_url(server.http_addr(), &stall_target))
        .send()
        .await?;
    let mut body = stalled.bytes_stream();
    assert_eq!(body.next().await.unwrap()?, &b"first"[..]);
    assert_eq!(
        authorized(json!({"allowPrivateNetworkSources": false}))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let cancelled = tokio::time::timeout(Duration::from_secs(5), body.next()).await?;
    assert!(cancelled.unwrap().is_err());

    let settings: serde_json::Value = client
        .get(format!("{base}/settings"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(settings["values"]["allowPrivateNetworkSources"], false);
    assert!(!settings.to_string().contains(&token));

    let diagnostics = tokio::time::timeout(
        Duration::from_secs(5),
        client.get(format!("{base}/diagnostics/export")).send(),
    )
    .await??
    .error_for_status()?
    .bytes()
    .await?;
    assert!(
        !diagnostics
            .windows(token.len())
            .any(|bytes| bytes == token.as_bytes())
    );

    fixture_task.abort();
    let _ = fixture_task.await;
    tls_fixture_task.abort();
    let _ = tls_fixture_task.await;
    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    Ok(())
}
