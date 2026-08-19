use crate::{
    network_security::{DestinationError, ProxyRequestContext, ProxyRuntime},
    state::AppState,
};
use axum::{
    Router,
    body::Body,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::{Client, Method};
use std::{pin::Pin, time::Duration};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;
use url::Url;

const MAX_PROXY_INPUT: usize = 64 * 1024;
const MAX_TARGET_URL: usize = 16 * 1024;
const MAX_CUSTOM_OPTIONS: usize = 64;
const MAX_HEADER_PAIR: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyError {
    InvalidRequest,
    Blocked,
    Capacity,
    Upstream,
    Cancelled,
}

impl From<DestinationError> for ProxyError {
    fn from(value: DestinationError) -> Self {
        match value {
            DestinationError::UnsupportedScheme | DestinationError::MissingHost => {
                Self::InvalidRequest
            }
            DestinationError::Blocked => Self::Blocked,
            DestinationError::ResolutionFailed | DestinationError::LocalNetworkUnavailable => {
                Self::Upstream
            }
        }
    }
}

struct ParsedProxyRequest {
    target: Url,
    request_headers: HeaderMap,
    response_headers: HeaderMap,
}

fn parse_proxy_request(
    rest: &str,
    raw_query: Option<&str>,
) -> Result<ParsedProxyRequest, ProxyError> {
    let input_length = rest
        .len()
        .checked_add(raw_query.map_or(0, str::len))
        .ok_or(ProxyError::InvalidRequest)?;
    if input_length > MAX_PROXY_INPUT {
        return Err(ProxyError::InvalidRequest);
    }

    let query_has_target = raw_query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "d")
    });
    let (encoded_options, path_tail, upstream_query) = if query_has_target {
        (raw_query.unwrap_or_default(), "", None)
    } else {
        let (options, tail) = rest.split_once('/').unwrap_or((rest, ""));
        (options, tail, raw_query)
    };

    let mut target = None;
    let mut request_headers = HeaderMap::new();
    let mut response_headers = HeaderMap::new();
    let mut option_count = 0usize;
    for (key, value) in url::form_urlencoded::parse(encoded_options.as_bytes()) {
        match key.as_ref() {
            "d" => target = Some(value.into_owned()),
            "h" | "r" => {
                option_count = option_count
                    .checked_add(1)
                    .ok_or(ProxyError::InvalidRequest)?;
                if option_count > MAX_CUSTOM_OPTIONS || value.len() > MAX_HEADER_PAIR {
                    return Err(ProxyError::InvalidRequest);
                }
                let (name, value) = parse_custom_header(&value)?;
                if key == "h" {
                    if request_header_forbidden(&name) {
                        return Err(ProxyError::InvalidRequest);
                    }
                    request_headers.insert(name, value);
                } else {
                    if response_header_forbidden(&name) {
                        return Err(ProxyError::InvalidRequest);
                    }
                    response_headers.insert(name, value);
                }
            }
            _ => {}
        }
    }

    let target = target.ok_or(ProxyError::InvalidRequest)?;
    if target.len() > MAX_TARGET_URL {
        return Err(ProxyError::InvalidRequest);
    }
    let mut target = Url::parse(&target).map_err(|_| ProxyError::InvalidRequest)?;
    if !matches!(target.scheme(), "http" | "https") || target.host().is_none() {
        return Err(ProxyError::InvalidRequest);
    }
    target.set_fragment(None);
    if !path_tail.is_empty() {
        target = target
            .join(path_tail)
            .map_err(|_| ProxyError::InvalidRequest)?;
    }
    if let Some(query) = upstream_query {
        target.set_query(Some(query));
    }
    if target.as_str().len() > MAX_TARGET_URL {
        return Err(ProxyError::InvalidRequest);
    }

    Ok(ParsedProxyRequest {
        target,
        request_headers,
        response_headers,
    })
}

fn parse_custom_header(value: &str) -> Result<(HeaderName, HeaderValue), ProxyError> {
    let (name, value) = value.split_once(':').ok_or(ProxyError::InvalidRequest)?;
    let name = name.trim();
    let value = value.trim();
    if name
        .len()
        .checked_add(value.len())
        .and_then(|length| length.checked_add(1))
        .is_none_or(|length| length > MAX_HEADER_PAIR)
    {
        return Err(ProxyError::InvalidRequest);
    }
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| ProxyError::InvalidRequest)?;
    let value = HeaderValue::from_str(value).map_err(|_| ProxyError::InvalidRequest)?;
    Ok((name, value))
}

fn request_header_forbidden(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "expect"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

fn response_header_forbidden(name: &HeaderName) -> bool {
    request_header_forbidden(name)
        || matches!(
            name.as_str(),
            "set-cookie"
                | "access-control-allow-origin"
                | "access-control-allow-methods"
                | "access-control-allow-headers"
        )
}

async fn fetch_with_redirects(
    runtime: &ProxyRuntime,
    context: &ProxyRequestContext,
    request: &ParsedProxyRequest,
    method: Method,
    incoming: &HeaderMap,
) -> Result<(reqwest::Response, Url), ProxyError> {
    const REDIRECT_STATUSES: &[StatusCode] = &[
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::SEE_OTHER,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ];
    const AUTOMATIC_REQUEST_HEADERS: &[HeaderName] = &[
        header::ACCEPT,
        header::ACCEPT_LANGUAGE,
        header::RANGE,
        header::IF_RANGE,
        header::USER_AGENT,
    ];

    let mut target = request.target.clone();
    let mut custom_headers = request.request_headers.clone();
    let mut redirects = 0usize;
    loop {
        let destination = runtime.validate(context, &target).await?;
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .http2_max_header_list_size(65_536)
            .danger_accept_invalid_certs(context.settings.allow_invalid_proxy_tls_certificates);
        if let Some(domain) = &destination.domain {
            builder = builder.resolve_to_addrs(domain, &destination.addrs);
        }
        let client = builder.build().map_err(|_| ProxyError::Upstream)?;
        let mut headers = HeaderMap::new();
        for name in AUTOMATIC_REQUEST_HEADERS {
            if let Some(value) = incoming.get(name) {
                headers.insert(name.clone(), value.clone());
            }
        }
        for (name, value) in &custom_headers {
            headers.insert(name.clone(), value.clone());
        }
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        let send = client
            .request(method.clone(), destination.url.clone())
            .headers(headers)
            .send();
        let response = tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => return Err(ProxyError::Cancelled),
            result = send => result.map_err(|_| ProxyError::Upstream)?,
        };

        if !REDIRECT_STATUSES.contains(&response.status()) {
            return Ok((response, destination.url));
        }
        if redirects >= 5 {
            return Err(ProxyError::Upstream);
        }
        redirects += 1;
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ProxyError::Upstream)?;
        let mut next = destination
            .url
            .join(location)
            .map_err(|_| ProxyError::Upstream)?;
        if destination.url.scheme() == "https" && next.scheme() == "http" {
            return Err(ProxyError::Upstream);
        }
        if !matches!(next.scheme(), "http" | "https") || next.host().is_none() {
            return Err(ProxyError::Upstream);
        }
        next.set_fragment(None);
        if !same_authority(&destination.url, &next) {
            let _ = next.set_username("");
            let _ = next.set_password(None);
            custom_headers.remove(header::AUTHORIZATION);
            custom_headers.remove(header::COOKIE);
            custom_headers.remove(header::PROXY_AUTHORIZATION);
        }
        target = next;
    }
}

fn same_authority(left: &Url, right: &Url) -> bool {
    left.host() == right.host() && left.port_or_known_default() == right.port_or_known_default()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/proxy", any(proxy_root_handler))
        .route("/proxy/", any(proxy_root_handler))
        .route("/proxy/{*rest}", any(proxy_path_handler))
}

async fn proxy_root_handler(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    method: Method,
) -> Response {
    handle_proxy(state, String::new(), raw_query, headers, method).await
}

async fn proxy_path_handler(
    State(state): State<AppState>,
    Path(rest): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    method: Method,
) -> Response {
    handle_proxy(state, rest, raw_query, headers, method).await
}

async fn handle_proxy(
    state: AppState,
    rest: String,
    raw_query: Option<String>,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let context = match state.proxy_runtime.try_request() {
        Ok(context) => context,
        Err(_) => return proxy_error_response(ProxyError::Capacity),
    };
    let request = match parse_proxy_request(&rest, raw_query.as_deref()) {
        Ok(request) => request,
        Err(error) => return proxy_error_response(error),
    };
    let (upstream, final_url) = match fetch_with_redirects(
        &state.proxy_runtime,
        &context,
        &request,
        method,
        &headers,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return proxy_error_response(error),
    };
    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let content_type = upstream_headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let playlist = final_url.path().ends_with(".m3u8")
        || final_url.path().ends_with(".m3u")
        || content_type.to_ascii_lowercase().contains("mpegurl");

    if playlist {
        if upstream_headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| {
                value
                    .to_str()
                    .map(|value| !value.eq_ignore_ascii_case("identity"))
                    .unwrap_or(true)
            })
        {
            return proxy_error_response(ProxyError::Upstream);
        }
        let body = match collect_playlist(upstream, &context).await {
            Ok(body) => body,
            Err(error) => return proxy_error_response(error),
        };
        let body = match String::from_utf8(body)
            .map_err(|_| ProxyError::Upstream)
            .and_then(|body| rewrite_playlist_bounded(&body, &final_url))
        {
            Ok(body) => body,
            Err(error) => return proxy_error_response(error),
        };
        return build_proxy_response(
            status,
            &upstream_headers,
            &request.response_headers,
            Body::from(body),
            true,
        );
    }

    let ProxyRequestContext {
        cancellation,
        capacity,
        ..
    } = context;
    let stream = ProxyBodyState {
        stream: Box::pin(upstream.bytes_stream()),
        cancellation,
        _capacity: capacity,
        terminal: false,
    };
    let stream = futures_util::stream::unfold(stream, |mut state| async move {
        if state.terminal {
            return None;
        }
        let next = tokio::select! {
            biased;
            _ = state.cancellation.cancelled() => {
                state.terminal = true;
                Some(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "proxy policy changed",
                )))
            }
            result = tokio::time::timeout(Duration::from_secs(30), state.stream.next()) => {
                match result {
                    Err(_) => {
                        state.terminal = true;
                        Some(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "proxy upstream body timed out",
                        )))
                    }
                    Ok(Some(Ok(bytes))) => Some(Ok(bytes)),
                    Ok(Some(Err(_))) => {
                        state.terminal = true;
                        Some(Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "proxy upstream body failed",
                        )))
                    }
                    Ok(None) => return None,
                }
            }
        };
        next.map(|item| (item, state))
    });
    build_proxy_response(
        status,
        &upstream_headers,
        &request.response_headers,
        Body::from_stream(stream),
        false,
    )
}

type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

struct ProxyBodyState {
    stream: UpstreamByteStream,
    cancellation: CancellationToken,
    _capacity: OwnedSemaphorePermit,
    terminal: bool,
}

const MAX_PLAYLIST_INPUT: usize = 8 * 1024 * 1024;

async fn collect_playlist(
    response: reqwest::Response,
    context: &ProxyRequestContext,
) -> Result<Vec<u8>, ProxyError> {
    if response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .is_some_and(|length| length > MAX_PLAYLIST_INPUT)
    {
        return Err(ProxyError::Upstream);
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(MAX_PLAYLIST_INPUT),
    );
    let mut stream = response.bytes_stream();
    loop {
        let next = tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => return Err(ProxyError::Cancelled),
            result = tokio::time::timeout(Duration::from_secs(30), stream.next()) => {
                result.map_err(|_| ProxyError::Upstream)?
            }
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk.map_err(|_| ProxyError::Upstream)?;
        let next_length = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(ProxyError::Upstream)?;
        if next_length > MAX_PLAYLIST_INPUT {
            return Err(ProxyError::Upstream);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn build_proxy_response(
    status: StatusCode,
    upstream: &HeaderMap,
    custom: &HeaderMap,
    body: Body,
    rewritten: bool,
) -> Response {
    const SAFE_RESPONSE_HEADERS: &[HeaderName] = &[
        header::ACCEPT_RANGES,
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        header::CONTENT_RANGE,
        header::LAST_MODIFIED,
        header::ETAG,
        header::SERVER,
        header::DATE,
        header::CONTENT_ENCODING,
    ];
    let mut response = Response::new(body);
    *response.status_mut() = status;
    for name in SAFE_RESPONSE_HEADERS {
        if rewritten
            && matches!(
                *name,
                header::CONTENT_LENGTH | header::CONTENT_RANGE | header::CONTENT_ENCODING
            )
        {
            continue;
        }
        if let Some(value) = upstream.get(name) {
            response.headers_mut().insert(name.clone(), value.clone());
        }
    }
    for (name, value) in custom {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    response.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    response
}

fn proxy_error_response(error: ProxyError) -> Response {
    let (status, message) = match error {
        ProxyError::InvalidRequest => (StatusCode::BAD_REQUEST, "Invalid proxy request"),
        ProxyError::Blocked => (StatusCode::FORBIDDEN, "Proxy destination is blocked"),
        ProxyError::Capacity => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy capacity is exhausted",
        ),
        ProxyError::Upstream | ProxyError::Cancelled => {
            (StatusCode::BAD_GATEWAY, "Proxy upstream request failed")
        }
    };
    let mut response = (status, message).into_response();
    if error == ProxyError::Capacity {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

const MAX_PLAYLIST_OUTPUT: usize = 16 * 1024 * 1024;

fn rewrite_playlist_bounded(body: &str, base_url: &Url) -> Result<String, ProxyError> {
    let mut output = String::with_capacity(body.len().min(MAX_PLAYLIST_OUTPUT));
    for line_with_ending in body.split_inclusive('\n') {
        let (line, ending) = if let Some(line) = line_with_ending.strip_suffix("\r\n") {
            (line, "\r\n")
        } else if let Some(line) = line_with_ending.strip_suffix('\n') {
            (line, "\n")
        } else {
            (line_with_ending, "")
        };

        if line.starts_with('#') {
            rewrite_playlist_tag(line, base_url, &mut output)?;
        } else if line.is_empty() {
            push_playlist(&mut output, "")?;
        } else if let Ok(absolute) = base_url.join(line) {
            push_proxy_uri(&mut output, &absolute)?;
        } else {
            push_playlist(&mut output, line)?;
        }
        push_playlist(&mut output, ending)?;
    }
    if body.is_empty() {
        return Ok(String::new());
    }
    Ok(output)
}

fn rewrite_playlist_tag(line: &str, base_url: &Url, output: &mut String) -> Result<(), ProxyError> {
    let mut remaining = line;
    while let Some(start) = remaining.find("URI=\"") {
        let value_start = start + 5;
        push_playlist(output, &remaining[..value_start])?;
        let after_start = &remaining[value_start..];
        let Some(end) = after_start.find('"') else {
            push_playlist(output, after_start)?;
            return Ok(());
        };
        let value = &after_start[..end];
        if let Ok(absolute) = base_url.join(value) {
            push_proxy_uri(output, &absolute)?;
        } else {
            push_playlist(output, value)?;
        }
        remaining = &after_start[end..];
    }
    push_playlist(output, remaining)
}

fn push_proxy_uri(output: &mut String, absolute: &Url) -> Result<(), ProxyError> {
    const PREFIX: &str = "/proxy/?d=";
    let maximum_encoded = absolute
        .as_str()
        .len()
        .checked_mul(3)
        .and_then(|length| length.checked_add(PREFIX.len()))
        .ok_or(ProxyError::Upstream)?;
    let remaining = MAX_PLAYLIST_OUTPUT.saturating_sub(output.len());
    if maximum_encoded > remaining {
        return Err(ProxyError::Upstream);
    }
    push_playlist(output, PREFIX)?;
    push_playlist(output, &urlencoding::encode(absolute.as_str()))
}

fn push_playlist(output: &mut String, value: &str) -> Result<(), ProxyError> {
    let next_length = output
        .len()
        .checked_add(value.len())
        .ok_or(ProxyError::Upstream)?;
    if next_length > MAX_PLAYLIST_OUTPUT {
        return Err(ProxyError::Upstream);
    }
    output.push_str(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProxyError, fetch_with_redirects, parse_proxy_request, rewrite_playlist_bounded};
    use crate::network_security::{
        Clock, DestinationValidator, DnsResolver, LocalNetworkProvider, ProxyPolicySettings,
        ProxyRuntime,
    };
    use async_trait::async_trait;
    use axum::{
        Router,
        http::{HeaderMap, StatusCode, header},
        routing::get,
    };
    use std::{
        io,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Instant,
    };

    #[test]
    fn parse_core_path_format_preserves_tail_query() {
        let parsed = parse_proxy_request(
            "d=https%3A%2F%2Fexample.com&h=Range%3Abytes%3D1-9&r=Content-Type%3Avideo%2Fmp4/media/file",
            Some("token=a%2Bb"),
        )
        .unwrap();
        assert_eq!(
            parsed.target.as_str(),
            "https://example.com/media/file?token=a%2Bb"
        );
        assert_eq!(parsed.request_headers[header::RANGE], "bytes=1-9");
        assert_eq!(parsed.response_headers[header::CONTENT_TYPE], "video/mp4");
    }

    #[test]
    fn parse_query_format_accepts_full_url_and_repeated_options_last_wins() {
        let parsed = parse_proxy_request(
            "",
            Some(
                "d=https%3A%2F%2Fexample.com%2Fvideo%3Fx%3D1&h=X-Test%3Afirst&h=X-Test%3Asecond&r=X-Reply%3Aok",
            ),
        )
        .unwrap();
        assert_eq!(parsed.target.as_str(), "https://example.com/video?x=1");
        assert_eq!(parsed.request_headers["x-test"], "second");
        assert_eq!(parsed.response_headers["x-reply"], "ok");
    }

    #[test]
    fn parse_rejects_missing_or_unsupported_targets() {
        for (rest, query) in [
            ("", None),
            ("", Some("h=X-Test%3Avalue")),
            ("", Some("d=file%3A%2F%2F%2Fetc%2Fpasswd")),
            ("", Some("d=not-a-url")),
        ] {
            assert!(matches!(
                parse_proxy_request(rest, query),
                Err(ProxyError::InvalidRequest)
            ));
        }
    }

    #[test]
    fn parse_rejects_header_smuggling_and_forbidden_fields() {
        for option in [
            "h=Host%3Aexample.com",
            "h=Content-Length%3A4",
            "h=Connection%3Akeep-alive",
            "h=Expect%3A100-continue",
            "h=X-Test%3Aok%0D%0AX-Evil%3Ayes",
            "r=Set-Cookie%3Astolen%3D1",
            "r=Transfer-Encoding%3Achunked",
            "r=Access-Control-Allow-Origin%3Ahttps%3A%2F%2Fevil.example",
        ] {
            let query = format!("d=https%3A%2F%2Fexample.com&{option}");
            assert!(
                matches!(
                    parse_proxy_request("", Some(&query)),
                    Err(ProxyError::InvalidRequest)
                ),
                "{option}"
            );
        }
    }

    #[test]
    fn parse_enforces_option_and_target_limits_before_network_access() {
        let options = (0..65)
            .map(|index| format!("h=X-{index}%3Avalue"))
            .collect::<Vec<_>>()
            .join("&");
        let query = format!("d=https%3A%2F%2Fexample.com&{options}");
        assert!(matches!(
            parse_proxy_request("", Some(&query)),
            Err(ProxyError::InvalidRequest)
        ));

        let oversized = format!("https://example.com/{}", "a".repeat(16 * 1024));
        let query = format!("d={}", urlencoding::encode(&oversized));
        assert!(matches!(
            parse_proxy_request("", Some(&query)),
            Err(ProxyError::InvalidRequest)
        ));
    }

    struct FixtureResolver {
        address: SocketAddr,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl DnsResolver for FixtureResolver {
        async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            assert_ne!(host, "ipv4only.arpa");
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![SocketAddr::new(self.address.ip(), port)])
        }
    }

    struct EmptyLocalNetworks;

    #[async_trait]
    impl LocalNetworkProvider for EmptyLocalNetworks {
        async fn current(&self) -> io::Result<crate::network_security::LocalNetworks> {
            Ok(crate::network_security::LocalNetworks::default())
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    fn test_runtime(
        address: SocketAddr,
        settings: ProxyPolicySettings,
    ) -> (ProxyRuntime, Arc<FixtureResolver>) {
        let resolver = Arc::new(FixtureResolver {
            address,
            calls: AtomicUsize::new(0),
        });
        let validator = Arc::new(DestinationValidator::new(
            resolver.clone(),
            Arc::new(EmptyLocalNetworks),
            Arc::new(FixedClock),
            Vec::new(),
        ));
        (ProxyRuntime::new(settings, validator), resolver)
    }

    async fn fixture(router: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (address, task)
    }

    #[tokio::test]
    async fn dns_pinning_resolves_each_hop_exactly_once() {
        let (address, fixture) = fixture(Router::new().route(
            "/resource",
            get(|| async { (StatusCode::OK, "fixture-body") }),
        ))
        .await;
        let (runtime, resolver) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let parsed = parse_proxy_request(
            "",
            Some(&format!(
                "d=http%3A%2F%2Frebind.test%3A{}%2Fresource",
                address.port()
            )),
        )
        .unwrap();
        let context = runtime.try_request().unwrap();
        let (response, _) = fetch_with_redirects(
            &runtime,
            &context,
            &parsed,
            reqwest::Method::GET,
            &HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap(), "fixture-body");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        fixture.abort();
    }

    #[tokio::test]
    async fn redirect_to_metadata_is_revalidated_with_private_opt_in() {
        let (address, fixture) = fixture(Router::new().route(
            "/redirect",
            get(|| async {
                (
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, "http://169.254.169.254/latest/meta-data/")],
                )
            }),
        ))
        .await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let parsed = parse_proxy_request(
            "",
            Some(&format!(
                "d=http%3A%2F%2Fredirect.test%3A{}%2Fredirect",
                address.port()
            )),
        )
        .unwrap();
        let context = runtime.try_request().unwrap();
        assert!(matches!(
            fetch_with_redirects(
                &runtime,
                &context,
                &parsed,
                reqwest::Method::GET,
                &HeaderMap::new(),
            )
            .await,
            Err(ProxyError::Blocked)
        ));
        fixture.abort();
    }

    #[test]
    fn playlist_rewriter_handles_plain_and_every_quoted_uri() {
        let base = url::Url::parse("https://media.example/path/master.m3u8").unwrap();
        let body = concat!(
            "#EXTM3U\r\n",
            "#EXT-X-MEDIA:TYPE=AUDIO,URI=\"audio.m3u8\",X=1,URI=\"backup.m3u8\"\r\n",
            "segment.ts?token=1\r\n"
        );
        let rewritten = rewrite_playlist_bounded(body, &base).unwrap();
        assert!(rewritten.starts_with("#EXTM3U\r\n"));
        assert_eq!(rewritten.matches("/proxy/?d=").count(), 3);
        assert!(rewritten.contains("https%3A%2F%2Fmedia.example%2Fpath%2Faudio.m3u8"));
        assert!(rewritten.contains("https%3A%2F%2Fmedia.example%2Fpath%2Fsegment.ts%3Ftoken%3D1"));
        assert!(rewritten.ends_with("\r\n"));
    }

    #[test]
    fn playlist_rewriter_fails_before_output_expansion_exceeds_limit() {
        let base = url::Url::parse(&format!(
            "https://media.example/{}/master.m3u8",
            "a".repeat(15_000)
        ))
        .unwrap();
        let body = "segment.ts\n".repeat(1_200);
        assert!(matches!(
            rewrite_playlist_bounded(&body, &base),
            Err(ProxyError::Upstream)
        ));
    }
}
