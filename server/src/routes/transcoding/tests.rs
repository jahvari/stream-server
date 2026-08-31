use super::{GET_BUILD_PERMITS, actual_peer_is_loopback, browser_request_allowed, router};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri, header},
};
use enginefs::EngineFS;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceExt;

use crate::settings_control::{SETTINGS_TOKEN_HEADER, SettingsControl};
use crate::transcoding::{
    capability::registry::CapabilityRegistry,
    device::{DeviceDiscovery, DeviceEnumerator, DeviceError},
    inventory::PairedRuntimeInventorySource,
    process::ProcessSupervisor,
    runtime::TranscodingService,
};
use crate::{AppState, routes::system::ServerSettings};
use tokio_util::sync::CancellationToken;

fn headers(values: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    headers
}

#[test]
fn actual_peer_accepts_only_loopback_and_loopback_mapped_addresses() {
    for peer in [
        "127.0.0.1:40000",
        "127.255.255.254:40000",
        "[::1]:40000",
        "[::ffff:127.0.0.2]:40000",
    ] {
        assert!(actual_peer_is_loopback(peer.parse::<SocketAddr>().unwrap()));
    }
    for peer in [
        "0.0.0.0:40000",
        "192.0.2.10:40000",
        "[::]:40000",
        "[2001:db8::1]:40000",
        "[::ffff:192.0.2.10]:40000",
    ] {
        assert!(!actual_peer_is_loopback(
            peer.parse::<SocketAddr>().unwrap()
        ));
    }
}

#[test]
fn desktop_requests_may_omit_browser_and_reference_headers() {
    assert!(browser_request_allowed(
        &HeaderMap::new(),
        &Uri::from_static("/transcoding/capabilities"),
    ));
}

#[test]
fn host_parser_accepts_only_canonical_loopback_authorities() {
    for host in [
        "localhost",
        "localhost:11470",
        "127.0.0.1",
        "127.255.255.254:65535",
        "[::1]",
        "[::1]:11470",
    ] {
        assert!(
            browser_request_allowed(
                &headers(&[("host", host)]),
                &Uri::from_static("/transcoding/capabilities"),
            ),
            "expected accepted host: {host}"
        );
    }

    for host in [
        "Localhost",
        "localhost.",
        "localhost@127.0.0.1",
        "local%68ost",
        "127.1",
        "0177.0.0.1",
        "2130706433",
        "127.0.0.1.",
        "127.0.0.1:0",
        "127.0.0.1:011470",
        "127.0.0.1:65536",
        "192.0.2.1",
        "::1",
        "[0:0:0:0:0:0:0:1]",
        "[::ffff:127.0.0.1]",
    ] {
        assert!(
            !browser_request_allowed(
                &headers(&[("host", host)]),
                &Uri::from_static("/transcoding/capabilities"),
            ),
            "expected rejected host: {host}"
        );
    }
}

#[test]
fn multiple_or_conflicting_reference_authorities_are_rejected() {
    let mut multiple = HeaderMap::new();
    multiple.append(header::HOST, HeaderValue::from_static("localhost:11470"));
    multiple.append(header::HOST, HeaderValue::from_static("127.0.0.1:11470"));
    assert!(!browser_request_allowed(
        &multiple,
        &Uri::from_static("/transcoding/capabilities"),
    ));

    let absolute: Uri = "http://localhost:11470/transcoding/capabilities"
        .parse()
        .unwrap();
    assert!(browser_request_allowed(
        &headers(&[("host", "localhost:11470")]),
        &absolute,
    ));
    assert!(!browser_request_allowed(
        &headers(&[("host", "127.0.0.1:11470")]),
        &absolute,
    ));

    let scheme_relative: Uri = "//localhost:11470/transcoding/capabilities"
        .parse()
        .unwrap();
    assert!(!browser_request_allowed(
        &HeaderMap::new(),
        &scheme_relative
    ));
}

#[test]
fn origin_and_fetch_metadata_must_match_the_local_reference() {
    for (host, origin) in [
        ("localhost", "http://localhost"),
        ("localhost", "https://localhost"),
        ("localhost:11470", "http://localhost:11470"),
        ("127.0.0.2:11470", "http://127.0.0.2:11470"),
        ("[::1]:11470", "http://[::1]:11470"),
    ] {
        assert!(browser_request_allowed(
            &headers(&[
                ("host", host),
                ("origin", origin),
                ("sec-fetch-site", "same-origin"),
            ]),
            &Uri::from_static("/transcoding/capabilities"),
        ));
    }

    for (host, origin) in [
        ("localhost:11470", "http://localhost"),
        ("localhost", "http://127.0.0.1"),
        ("localhost", "null"),
        ("localhost", "ftp://localhost"),
        ("localhost", "http://user@localhost"),
        ("localhost", "http://local%68ost"),
        ("localhost", "http://localhost/"),
        ("localhost", "http://localhost?query"),
        ("localhost", "http://localhost#fragment"),
        ("localhost", "http://localhost:0"),
        ("localhost", "http://localhost:080"),
        ("localhost", "http://localhost:65536"),
        ("localhost", "http://example.com"),
    ] {
        assert!(
            !browser_request_allowed(
                &headers(&[("host", host), ("origin", origin)]),
                &Uri::from_static("/transcoding/capabilities"),
            ),
            "expected rejected origin: {origin}"
        );
    }

    for fetch_site in ["cross-site", "same-site ", "unknown", ""] {
        assert!(!browser_request_allowed(
            &headers(&[("host", "localhost"), ("sec-fetch-site", fetch_site)]),
            &Uri::from_static("/transcoding/capabilities"),
        ));
    }
    for fetch_site in ["none", "same-origin", "same-site"] {
        assert!(browser_request_allowed(
            &headers(&[("host", "localhost"), ("sec-fetch-site", fetch_site)]),
            &Uri::from_static("/transcoding/capabilities"),
        ));
    }

    assert!(!browser_request_allowed(
        &headers(&[("origin", "http://localhost")]),
        &Uri::from_static("/transcoding/capabilities"),
    ));

    let mut duplicate_origin = headers(&[("host", "localhost")]);
    duplicate_origin.append(header::ORIGIN, HeaderValue::from_static("http://localhost"));
    duplicate_origin.append(header::ORIGIN, HeaderValue::from_static("http://localhost"));
    assert!(!browser_request_allowed(
        &duplicate_origin,
        &Uri::from_static("/transcoding/capabilities"),
    ));

    let mut duplicate_fetch_site = headers(&[("host", "localhost")]);
    duplicate_fetch_site.append(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    duplicate_fetch_site.append(
        HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("same-origin"),
    );
    assert!(!browser_request_allowed(
        &duplicate_fetch_site,
        &Uri::from_static("/transcoding/capabilities"),
    ));
}

async fn test_state() -> (tempfile::TempDir, AppState) {
    let temp = tempfile::tempdir().unwrap();
    let engine = Arc::new(
        EngineFS::new(temp.path().join("engine"), Default::default())
            .await
            .unwrap(),
    );
    let state = AppState::new(
        engine,
        ServerSettings::default(),
        temp.path().join("config"),
        crate::state::unavailable_transcoding_for_test(),
    );
    (temp, state)
}

async fn capability_response(
    state: AppState,
    peer: Option<&str>,
    request_headers: &[(&'static str, &'static str)],
) -> axum::response::Response {
    let mut request = Request::builder()
        .uri("/transcoding/capabilities")
        .body(Body::empty())
        .unwrap();
    for (name, value) in request_headers {
        request.headers_mut().append(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().expect("valid peer")));
    }
    router().with_state(state).oneshot(request).await.unwrap()
}

fn assert_isolated_json(response: &axum::response::Response) {
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get("content-security-policy").unwrap(),
        "default-src 'none'"
    );
    assert_eq!(
        response
            .headers()
            .get("cross-origin-resource-policy")
            .unwrap(),
        "same-origin"
    );
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
}

#[tokio::test]
async fn get_requires_actual_loopback_before_browser_headers_or_work() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, state) = test_state().await;

    let accepted = capability_response(
        state.clone(),
        Some("127.0.0.2:40000"),
        &[("host", "127.0.0.2:11470")],
    )
    .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_isolated_json(&accepted);
    let body = to_bytes(accepted.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["schemaVersion"],
        1
    );

    for (peer, request_headers) in [
        (None, vec![("host", "localhost")]),
        (
            Some("203.0.113.9:40000"),
            vec![("host", "localhost"), ("forwarded", "for=127.0.0.1")],
        ),
        (Some("127.0.0.1:40000"), vec![("host", "example.com")]),
    ] {
        let response = capability_response(state.clone(), peer, &request_headers).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_isolated_json(&response);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            br#"{"schemaVersion":1,"error":"forbidden"}"#.as_slice()
        );
    }
}

#[tokio::test]
async fn real_tcp_router_uses_socket_connect_info_and_never_emits_cors() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, state) = test_state().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router()
                .with_state(state)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let response = reqwest::Client::new()
        .get(format!("http://{address}/transcoding/capabilities"))
        .header("origin", format!("http://{address}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );

    server.abort();
    let _ = server.await;
}

async fn refresh_response(
    state: AppState,
    peer: Option<&str>,
    request_headers: HeaderMap,
    body: Body,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method("POST")
        .uri("/transcoding/capabilities/refresh")
        .body(body)
        .unwrap();
    *request.headers_mut() = request_headers;
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().expect("valid peer")));
    }
    router().with_state(state).oneshot(request).await.unwrap()
}

fn authorized_headers(token: &[u8; 64]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, HeaderValue::from_static("localhost:11470"));
    headers.insert(
        SETTINGS_TOKEN_HEADER,
        HeaderValue::from_bytes(token).unwrap(),
    );
    headers
}

#[tokio::test]
async fn post_authenticates_before_body_and_returns_only_the_running_refresh_view() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);

    let response = refresh_response(
        state.clone(),
        Some("127.0.0.1:40000"),
        authorized_headers(&token),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_isolated_json(&response);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(body.starts_with(br#"{"schemaVersion":1,"refresh":{"#));
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 2);
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["refresh"]["id"], 1);
    assert_eq!(value["refresh"]["cause"], "manual");
    assert_eq!(value["refresh"]["state"], "running");
    assert!(value["refresh"]["startedAt"].is_string());
    assert!(value["refresh"]["completedAt"].is_null());
    assert!(value["refresh"]["outcomeReason"].is_null());

    state
        .transcoding
        .capability_registry_for_test()
        .wait_for_refresh_for_test()
        .await;
}

#[tokio::test]
async fn post_trust_failures_are_indistinguishable_and_do_not_poll_the_body() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);

    let stalled = Body::from_stream(futures_util::stream::pending::<
        Result<bytes::Bytes, std::io::Error>,
    >());
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        refresh_response(
            state.clone(),
            Some("127.0.0.1:40000"),
            headers(&[("host", "localhost:11470")]),
            stalled,
        ),
    )
    .await
    .expect("unauthorized request must not poll body");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        br#"{"schemaVersion":1,"error":"forbidden"}"#.as_slice()
    );

    let mut duplicate = authorized_headers(&token);
    duplicate.append(
        SETTINGS_TOKEN_HEADER,
        HeaderValue::from_bytes(&token).unwrap(),
    );
    for (peer, request_headers) in [
        (None, authorized_headers(&token)),
        (Some("203.0.113.9:40000"), authorized_headers(&token)),
        (Some("127.0.0.1:40000"), duplicate),
        (Some("127.0.0.1:40000"), headers(&[("host", "example.com")])),
    ] {
        let response = refresh_response(state.clone(), peer, request_headers, Body::empty()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_isolated_json(&response);
    }
}

#[tokio::test]
async fn authenticated_post_rejects_every_advertised_or_observed_body() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);

    let mut advertised = authorized_headers(&token);
    advertised.insert(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
    let mut chunked = authorized_headers(&token);
    chunked.insert(
        header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    let mut duplicate_zero = authorized_headers(&token);
    duplicate_zero.append(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    duplicate_zero.append(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    let mut claimed_empty = authorized_headers(&token);
    claimed_empty.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));

    for (request_headers, body) in [
        (advertised, Body::from("x")),
        (chunked, Body::empty()),
        (duplicate_zero, Body::empty()),
        (claimed_empty, Body::from("unexpected")),
        (authorized_headers(&token), Body::from("unadvertised")),
    ] {
        let response = refresh_response(
            state.clone(),
            Some("127.0.0.1:40000"),
            request_headers,
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_isolated_json(&response);
        assert_eq!(
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
            br#"{"schemaVersion":1,"error":"request_body_not_allowed"}"#.as_slice()
        );
    }
}

#[tokio::test]
async fn authenticated_stalled_body_is_bounded_and_rejected() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);

    let stalled = Body::from_stream(futures_util::stream::pending::<
        Result<bytes::Bytes, std::io::Error>,
    >());
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(1_500),
        refresh_response(
            state,
            Some("127.0.0.1:40000"),
            authorized_headers(&token),
            stalled,
        ),
    )
    .await
    .expect("authenticated stalled body must be bounded");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_isolated_json(&response);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        br#"{"schemaVersion":1,"error":"request_body_not_allowed"}"#.as_slice()
    );
}

#[tokio::test]
async fn fifth_get_is_rejected_before_registry_snapshot_or_dto_work() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, state) = test_state().await;
    let registry = Arc::clone(state.transcoding.capability_registry_for_test());
    let before = registry.api_dto_invocations_for_test();
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(GET_BUILD_PERMITS.acquire().await.unwrap());
    }

    let response = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        capability_response(
            state,
            Some("127.0.0.1:40000"),
            &[("host", "localhost:11470")],
        ),
    )
    .await
    .expect("capacity refusal must be immediate");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_isolated_json(&response);
    assert_eq!(registry.api_dto_invocations_for_test(), before);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        br#"{"schemaVersion":1,"error":"capacity_exhausted"}"#.as_slice()
    );
    drop(held);
}

#[derive(Clone, Copy)]
struct PausedEnumerator;

#[async_trait::async_trait]
impl DeviceEnumerator for PausedEnumerator {
    async fn enumerate(
        &self,
        cancellation: CancellationToken,
    ) -> Result<DeviceDiscovery, DeviceError> {
        cancellation.cancelled().await;
        Err(DeviceError::Cancelled)
    }
}

fn paused_transcoding() -> Arc<TranscodingService> {
    let registry = CapabilityRegistry::with_refresh_dependencies_for_test(
        Arc::new(PausedEnumerator),
        Arc::new(PairedRuntimeInventorySource),
        None,
        None,
    );
    Arc::new(TranscodingService::unavailable(
        Arc::new(ProcessSupervisor::new(CancellationToken::new())),
        registry,
    ))
}

#[tokio::test]
async fn running_refresh_precedes_rate_limit_and_shutdown_closes_admission() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);
    state.transcoding = paused_transcoding();

    for _ in 0..2 {
        let response = refresh_response(
            state.clone(),
            Some("127.0.0.1:40000"),
            authorized_headers(&token),
            Body::empty(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["refresh"]["id"], 1);
        assert_eq!(value["refresh"]["state"], "running");
    }

    state.transcoding.shutdown_capabilities().await;
    let response = refresh_response(
        state,
        Some("127.0.0.1:40000"),
        authorized_headers(&token),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_isolated_json(&response);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        br#"{"schemaVersion":1,"error":"server_shutdown"}"#.as_slice()
    );
}

#[tokio::test]
async fn completed_manual_refresh_is_rate_limited_with_integer_retry_after() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);

    let first = refresh_response(
        state.clone(),
        Some("127.0.0.1:40000"),
        authorized_headers(&token),
        Body::empty(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    state
        .transcoding
        .capability_registry_for_test()
        .wait_for_refresh_for_test()
        .await;

    let second = refresh_response(
        state,
        Some("127.0.0.1:40000"),
        authorized_headers(&token),
        Body::empty(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_isolated_json(&second);
    let retry_after = second.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!((1..=60).contains(&retry_after));
    assert_eq!(
        to_bytes(second.into_body(), usize::MAX).await.unwrap(),
        br#"{"schemaVersion":1,"error":"refresh_rate_limited"}"#.as_slice()
    );
}

#[tokio::test]
async fn checked_refresh_counter_exhaustion_returns_capacity_exhausted() {
    let _engine_guard = crate::TEST_ENGINE_MUTEX.lock().await;
    let (_temp, mut state) = test_state().await;
    let token = [b'a'; 64];
    state.settings_control = SettingsControl::for_test(token);
    state
        .transcoding
        .capability_registry_for_test()
        .exhaust_refresh_counter_for_test();

    let response = refresh_response(
        state,
        Some("127.0.0.1:40000"),
        authorized_headers(&token),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_isolated_json(&response);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        br#"{"schemaVersion":1,"error":"capacity_exhausted"}"#.as_slice()
    );
}
