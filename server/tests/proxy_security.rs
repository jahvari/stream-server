use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{HeaderMap, Response, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use futures_util::{StreamExt, stream};
use serde_json::json;
use std::{
    convert::Infallible,
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};

static EMBEDDED_SERVER_TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serialize_embedded_servers() -> tokio::sync::MutexGuard<'static, ()> {
    EMBEDDED_SERVER_TEST_MUTEX.lock().await
}

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

fn install_https_fixture(config_dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(config_dir)?;
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/localhost-cert.pem"
        ),
        config_dir.join("https-cert.pem"),
    )?;
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/localhost-key.pem"
        ),
        config_dir.join("https-key.pem"),
    )?;
    Ok(())
}

fn proxy_url(server: std::net::SocketAddr, target: &str) -> String {
    format!("http://{server}/proxy/?d={}", urlencoding::encode(target))
}

#[tokio::test]
async fn proxy_failure_bodies_never_expose_request_credentials() -> anyhow::Result<()> {
    let _server_test_guard = serialize_embedded_servers().await;
    const SECRETS: &[&str] = &[
        "parser-header-secret-9c30",
        "policy-user-secret-9c30",
        "policy-query-secret-9c30",
        "policy-header-secret-9c30",
        "redirect-user-secret-9c30",
        "redirect-query-secret-9c30",
        "redirect-header-secret-9c30",
        "upstream-user-secret-9c30",
        "upstream-query-secret-9c30",
        "upstream-header-secret-9c30",
    ];

    let redirect_router = Router::new().route(
        "/redirect",
        get(|| async {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(
                    header::LOCATION,
                    concat!(
                        "http://redirect-user:redirect-user-secret-9c30@169.254.169.254/",
                        "latest/meta-data/?token=redirect-query-secret-9c30"
                    ),
                )],
            )
        }),
    );
    let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let redirect_address = redirect_listener.local_addr()?;
    let redirect_task = tokio::spawn(async move {
        axum::serve(redirect_listener, redirect_router)
            .await
            .unwrap();
    });
    let closed_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let closed_address = closed_listener.local_addr()?;
    drop(closed_listener);

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
    let client = reqwest::Client::new();
    let token = std::fs::read_to_string(config_dir.join("settings-control.token"))?;
    client
        .post(format!("http://{}/settings", server.http_addr()))
        .header("x-stream-server-settings-token", token)
        .json(&json!({"allowPrivateNetworkSources": true}))
        .send()
        .await?
        .error_for_status()?;

    let requests = [
        (
            format!(
                "http://{}/proxy/?d=not-a-url&h={}",
                server.http_addr(),
                urlencoding::encode("X-Api-Key:parser-header-secret-9c30")
            ),
            StatusCode::BAD_REQUEST,
            "Invalid proxy request",
        ),
        (
            format!(
                "http://{}/proxy/?d={}&h={}",
                server.http_addr(),
                urlencoding::encode(concat!(
                    "http://policy-user:policy-user-secret-9c30@169.254.169.254/",
                    "latest/meta-data/?token=policy-query-secret-9c30"
                )),
                urlencoding::encode("X-Api-Key:policy-header-secret-9c30")
            ),
            StatusCode::FORBIDDEN,
            "Proxy destination is blocked",
        ),
        (
            format!(
                "http://{}/proxy/?d={}&h={}",
                server.http_addr(),
                urlencoding::encode(&format!(
                    "http://redirect-user:redirect-user-secret-9c30@{redirect_address}/redirect?token=redirect-query-secret-9c30"
                )),
                urlencoding::encode("X-Api-Key:redirect-header-secret-9c30")
            ),
            StatusCode::FORBIDDEN,
            "Proxy destination is blocked",
        ),
        (
            format!(
                "http://{}/proxy/?d={}&h={}",
                server.http_addr(),
                urlencoding::encode(&format!(
                    "http://upstream-user:upstream-user-secret-9c30@{closed_address}/asset?token=upstream-query-secret-9c30"
                )),
                urlencoding::encode("X-Api-Key:upstream-header-secret-9c30")
            ),
            StatusCode::BAD_GATEWAY,
            "Proxy upstream request failed",
        ),
    ];
    for (url, expected_status, expected_body) in requests {
        let response = client.get(url).send().await?;
        assert_eq!(response.status(), expected_status);
        let body = response.text().await?;
        assert_eq!(body, expected_body);
        for secret in SECRETS {
            assert!(!body.contains(secret));
        }
    }

    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    redirect_task.abort();
    Ok(())
}

#[tokio::test]
async fn marker_preserving_reverse_proxy_cannot_reenter_application_routes() -> anyhow::Result<()> {
    let _server_test_guard = serialize_embedded_servers().await;
    let server_address = Arc::new(Mutex::new(None::<std::net::SocketAddr>));
    let fixture_server_address = server_address.clone();
    let fixture_router = Router::new().route(
        "/{mode}",
        get(move |Path(mode): Path<String>, headers: HeaderMap| {
            let server_address = fixture_server_address.clone();
            async move {
                let server = server_address.lock().unwrap().unwrap();
                let client = reqwest::Client::new();
                let (method, path, preserve_marker) = match mode.as_str() {
                    "heartbeat" => (reqwest::Method::GET, "/heartbeat", true),
                    "proxyevil" => (reqwest::Method::GET, "/proxyevil", true),
                    "strip" => (reqwest::Method::GET, "/heartbeat", false),
                    "preflight" => (reqwest::Method::OPTIONS, "/heartbeat", true),
                    _ => return StatusCode::NOT_FOUND.into_response(),
                };
                let mut request = client.request(method, format!("http://{server}{path}"));
                if preserve_marker {
                    request = request.header(
                        "x-stream-server-proxy-hop",
                        headers["x-stream-server-proxy-hop"].clone(),
                    );
                }
                if mode == "preflight" {
                    request = request
                        .header(header::ORIGIN, "https://app.example")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET");
                }
                let response = request.send().await.unwrap();
                let status = response.status();
                let body = response.bytes().await.unwrap();
                (status, body).into_response()
            }
        }),
    );
    let fixture_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let fixture_address = fixture_listener.local_addr()?;
    let fixture_task = tokio::spawn(async move {
        axum::serve(fixture_listener, fixture_router).await.unwrap();
    });

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
    *server_address.lock().unwrap() = Some(server.http_addr());
    let client = reqwest::Client::new();
    let token = std::fs::read_to_string(config_dir.join("settings-control.token"))?;
    assert_eq!(
        client
            .post(format!("http://{}/settings", server.http_addr()))
            .header("x-stream-server-settings-token", token)
            .json(&json!({"allowPrivateNetworkSources": true}))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );

    for (mode, expected) in [
        ("heartbeat", StatusCode::FORBIDDEN),
        ("proxyevil", StatusCode::FORBIDDEN),
        ("strip", StatusCode::OK),
        ("preflight", StatusCode::OK),
    ] {
        let target = format!("http://{fixture_address}/{mode}");
        let response = client
            .get(proxy_url(server.http_addr(), &target))
            .send()
            .await?;
        assert_eq!(response.status(), expected, "mode={mode}");
    }

    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    fixture_task.abort();
    Ok(())
}

#[tokio::test]
async fn managed_https_port_zero_reports_serves_and_blocks_the_exact_socket() -> anyhow::Result<()>
{
    let _server_test_guard = serialize_embedded_servers().await;
    let config = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let config_dir = config.path().join("config");
    install_https_fixture(&config_dir)?;
    let server_config = stream_server::ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        https_addr: Some("127.0.0.1:0".parse().unwrap()),
        config_dir: Some(config_dir.clone()),
        cache_dir: Some(cache.path().join("cache")),
        ..stream_server::ServerConfig::embedded()
    };
    let server = tokio::task::spawn_blocking(move || stream_server::start(server_config)).await??;
    let https_address = server
        .bound_https_addr()
        .expect("prepared HTTPS listener must be exposed");
    assert_ne!(https_address.port(), 0);
    let tls_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    assert_eq!(
        tls_client
            .get(format!("https://{https_address}/heartbeat"))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );

    let client = reqwest::Client::new();
    let token = std::fs::read_to_string(config_dir.join("settings-control.token"))?;
    assert_eq!(
        client
            .post(format!("http://{}/settings", server.http_addr()))
            .header("x-stream-server-settings-token", token)
            .json(&json!({"allowPrivateNetworkSources": true}))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let target = format!("https://{https_address}/heartbeat");
    assert_eq!(
        client
            .get(proxy_url(server.http_addr(), &target))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );

    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    Ok(())
}

#[tokio::test]
async fn failed_https_preparation_is_not_registered_and_http_remains_usable() -> anyhow::Result<()>
{
    let _server_test_guard = serialize_embedded_servers().await;
    let occupied_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let occupied_address = occupied_listener.local_addr()?;
    let fixture = tokio::spawn(async move {
        axum::serve(
            occupied_listener,
            Router::new().route("/ok", get(|| async { "occupied-fixture" })),
        )
        .await
        .unwrap();
    });
    let config = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let config_dir = config.path().join("config");
    install_https_fixture(&config_dir)?;
    let server_config = stream_server::ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        https_addr: Some(occupied_address),
        config_dir: Some(config_dir.clone()),
        cache_dir: Some(cache.path().join("cache")),
        ..stream_server::ServerConfig::embedded()
    };
    let server = tokio::task::spawn_blocking(move || stream_server::start(server_config)).await??;
    assert_eq!(server.bound_https_addr(), None);
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("http://{}/heartbeat", server.http_addr()))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let token = std::fs::read_to_string(config_dir.join("settings-control.token"))?;
    client
        .post(format!("http://{}/settings", server.http_addr()))
        .header("x-stream-server-settings-token", token)
        .json(&json!({"allowPrivateNetworkSources": true}))
        .send()
        .await?
        .error_for_status()?;
    let target = format!("http://{occupied_address}/ok");
    let response = client
        .get(proxy_url(server.http_addr(), &target))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await?, "occupied-fixture");

    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    fixture.abort();
    Ok(())
}

#[tokio::test]
async fn malformed_https_pem_leaves_http_ready_without_a_stale_listener() -> anyhow::Result<()> {
    let _server_test_guard = serialize_embedded_servers().await;
    let config = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let config_dir = config.path().join("config");
    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(config_dir.join("https-cert.pem"), b"not a certificate")?;
    std::fs::write(config_dir.join("https-key.pem"), b"not a key")?;
    let server_config = stream_server::ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        https_addr: Some("127.0.0.1:0".parse().unwrap()),
        config_dir: Some(config_dir),
        cache_dir: Some(cache.path().join("cache")),
        ..stream_server::ServerConfig::embedded()
    };
    let server = tokio::task::spawn_blocking(move || stream_server::start(server_config)).await??;
    assert_eq!(server.bound_https_addr(), None);
    assert_eq!(
        reqwest::get(format!("http://{}/heartbeat", server.http_addr()))
            .await?
            .status(),
        StatusCode::OK
    );
    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    Ok(())
}

#[tokio::test]
async fn unreadable_https_pem_leaves_http_ready_without_a_stale_listener() -> anyhow::Result<()> {
    let _server_test_guard = serialize_embedded_servers().await;
    let config = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let config_dir = config.path().join("config");
    std::fs::create_dir_all(config_dir.join("https-cert.pem"))?;
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/localhost-key.pem"
        ),
        config_dir.join("https-key.pem"),
    )?;
    let server_config = stream_server::ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        https_addr: Some("127.0.0.1:0".parse().unwrap()),
        config_dir: Some(config_dir),
        cache_dir: Some(cache.path().join("cache")),
        ..stream_server::ServerConfig::embedded()
    };
    let server = tokio::task::spawn_blocking(move || stream_server::start(server_config)).await??;
    assert_eq!(server.bound_https_addr(), None);
    assert_eq!(
        reqwest::get(format!("http://{}/heartbeat", server.http_addr()))
            .await?
            .status(),
        StatusCode::OK
    );
    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    Ok(())
}

#[tokio::test]
async fn normal_encoded_core_path_form_reaches_destination_policy() -> anyhow::Result<()> {
    let _server_test_guard = serialize_embedded_servers().await;
    let config = tempfile::tempdir()?;
    let cache = tempfile::tempdir()?;
    let server_config = stream_server::ServerConfig {
        http_addr: "127.0.0.1:0".parse().unwrap(),
        config_dir: Some(config.path().join("config")),
        cache_dir: Some(cache.path().join("cache")),
        ..stream_server::ServerConfig::embedded()
    };
    let server = tokio::task::spawn_blocking(move || stream_server::start(server_config)).await??;
    let client = reqwest::Client::new();

    for path in [
        "/proxy?d=http%3A%2F%2F127.0.0.1%3A1%2Fmedia",
        "/proxy/?d=http%3A%2F%2F127.0.0.1%3A1%2Fmedia",
        "/proxy/d=http%3A%2F%2F127.0.0.1%3A1/media",
    ] {
        let response = client
            .get(format!("http://{}{path}", server.http_addr()))
            .send()
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "unexpected response for {path}: {:?}",
            response.text().await?
        );
    }

    let shutdown = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        server.shutdown()?;
        server.join()
    })
    .await??;
    assert_eq!(shutdown, Some(stream_server::ShutdownSource::External));
    Ok(())
}

#[tokio::test]
async fn default_deny_protected_opt_in_and_cancellation_work_end_to_end() -> anyhow::Result<()> {
    let _server_test_guard = serialize_embedded_servers().await;
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

    let log_dir = config_dir.join("logs");
    std::fs::write(log_dir.join("proof.dmp"), token.as_bytes())?;
    std::fs::write(log_dir.join("proof.log"), b"diagnostics-log-sentinel")?;
    let diagnostics = tokio::time::timeout(
        Duration::from_secs(5),
        client.get(format!("{base}/diagnostics/export")).send(),
    )
    .await??
    .error_for_status()?
    .bytes()
    .await?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(diagnostics))?;
    let mut saw_log_sentinel = false;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        assert_ne!(entry.name(), "logs/proof.dmp");
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        assert!(
            !bytes
                .windows(token.len())
                .any(|part| part == token.as_bytes())
        );
        saw_log_sentinel |= bytes
            .windows(b"diagnostics-log-sentinel".len())
            .any(|part| part == b"diagnostics-log-sentinel");
    }
    assert!(saw_log_sentinel);

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
