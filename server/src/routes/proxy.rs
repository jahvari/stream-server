#[cfg(test)]
use crate::network_security::ProxyProducerProbe;
use crate::{
    network_security::{DestinationError, ProxyProducerLease, ProxyRequestContext, ProxyRuntime},
    state::AppState,
};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Extension, OriginalUri, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::{Client, Method};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use url::{Position, Url};

const MAX_PROXY_INPUT: usize = 64 * 1024;
const MAX_TARGET_URL: usize = 16 * 1024;
const MAX_CUSTOM_OPTIONS: usize = 64;
const MAX_HEADER_PAIR: usize = 8 * 1024;
const RAW_CANONICAL_PATH_KEY: &str = "x-stream-path";
const RAW_CANONICAL_PATH_OPTION: &str = "&x-stream-path=raw";
const RESPONSE_HEADER_DEADLINE: Duration = Duration::from_secs(30);
const UPSTREAM_READ_IDLE_DEADLINE: Duration = Duration::from_secs(30);
const DOWNSTREAM_NO_PROGRESS_DEADLINE: Duration = Duration::from_secs(120);
const PROXY_BODY_CHUNK_SIZE: usize = 64 * 1024;

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

struct FetchedProxyResponse {
    response: reqwest::Response,
    final_url: Url,
    effective_custom_request_headers: HeaderMap,
    effective_response_headers: HeaderMap,
}

#[cfg(test)]
fn parse_proxy_request(
    rest: &str,
    raw_query: Option<&str>,
) -> Result<ParsedProxyRequest, ProxyError> {
    let mut suffix = if rest.is_empty() {
        String::new()
    } else {
        format!("/{rest}")
    };
    if let Some(query) = raw_query {
        suffix.push('?');
        suffix.push_str(query);
    }
    parse_proxy_suffix(&suffix)
}

fn parse_proxy_suffix(raw_suffix: &str) -> Result<ParsedProxyRequest, ProxyError> {
    if raw_suffix.len() > MAX_PROXY_INPUT {
        return Err(ProxyError::InvalidRequest);
    }

    let (encoded_options, path_tail, upstream_query) = if raw_suffix.is_empty() {
        ("", None, None)
    } else if let Some(query) = raw_suffix.strip_prefix('?') {
        (query, None, None)
    } else if raw_suffix == "/" {
        ("", None, None)
    } else if let Some(query) = raw_suffix.strip_prefix("/?") {
        (query, None, None)
    } else {
        let path_and_query = raw_suffix
            .strip_prefix('/')
            .ok_or(ProxyError::InvalidRequest)?;
        let (raw_path, upstream_query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (path_and_query, None),
        };
        let (options, tail) = match raw_path.split_once('/') {
            Some((options, tail)) => (options, tail),
            None => (raw_path, ""),
        };
        (options, Some(tail), upstream_query)
    };

    let mut target = None;
    let mut request_headers = HeaderMap::new();
    let mut response_headers = HeaderMap::new();
    let mut option_count = 0usize;
    let mut raw_canonical_path = false;
    for option in encoded_options.split('&') {
        let (key, value) = option.split_once('=').unwrap_or((option, ""));
        let key = strict_percent_decode(key, true)?;
        let value = strict_percent_decode(value, true)?;
        match key.as_str() {
            "d" => {
                if target.replace(value).is_some() {
                    return Err(ProxyError::InvalidRequest);
                }
            }
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
            RAW_CANONICAL_PATH_KEY => {
                if value != "raw" || raw_canonical_path {
                    return Err(ProxyError::InvalidRequest);
                }
                raw_canonical_path = true;
            }
            _ => {}
        }
    }

    if raw_canonical_path && path_tail.is_none_or(str::is_empty) {
        return Err(ProxyError::InvalidRequest);
    }

    let target = target.ok_or(ProxyError::InvalidRequest)?;
    let mut target = Url::parse(&target).map_err(|_| ProxyError::InvalidRequest)?;
    if let Some(path_tail) = path_tail {
        let decoded_path;
        let path_tail = if raw_canonical_path {
            validate_percent_encoding(path_tail)?;
            if let Some(upstream_query) = upstream_query {
                validate_percent_encoding(upstream_query)?;
            }
            path_tail
        } else {
            decoded_path = strict_percent_decode(path_tail, false)?;
            &decoded_path
        };
        target.set_path(if path_tail.is_empty() { "/" } else { path_tail });
        target.set_query(upstream_query);
    }
    let target = validate_proxy_target(target)?;

    Ok(ParsedProxyRequest {
        target,
        request_headers,
        response_headers,
    })
}

fn validate_percent_encoding(value: &str) -> Result<(), ProxyError> {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes
                .get(index + 1)
                .is_none_or(|byte| !byte.is_ascii_hexdigit())
                || bytes
                    .get(index + 2)
                    .is_none_or(|byte| !byte.is_ascii_hexdigit())
            {
                return Err(ProxyError::InvalidRequest);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn strict_percent_decode(value: &str, plus_as_space: bool) -> Result<String, ProxyError> {
    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = bytes
                    .get(index + 1)
                    .and_then(|byte| hex_value(*byte))
                    .ok_or(ProxyError::InvalidRequest)?;
                let low = bytes
                    .get(index + 2)
                    .and_then(|byte| hex_value(*byte))
                    .ok_or(ProxyError::InvalidRequest)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' if plus_as_space => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| ProxyError::InvalidRequest)
}

fn validate_proxy_target(mut target: Url) -> Result<Url, ProxyError> {
    if !matches!(target.scheme(), "http" | "https") || target.host().is_none() {
        return Err(ProxyError::InvalidRequest);
    }
    target.set_fragment(None);
    if target.as_str().len() > MAX_TARGET_URL {
        return Err(ProxyError::InvalidRequest);
    }
    Ok(target)
}

fn parse_custom_header(value: &str) -> Result<(HeaderName, HeaderValue), ProxyError> {
    let (name, value) = value.split_once(':').ok_or(ProxyError::InvalidRequest)?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ProxyError::InvalidRequest);
    }
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
    let name = name.as_str();
    matches!(
        name,
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
            | "forwarded"
            | "via"
            | "proxy-connection"
            | "http2-settings"
            | "x-real-ip"
            | "x-host"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("x-original-")
        || name.starts_with("x-rewrite-")
}

fn response_header_forbidden(name: &HeaderName) -> bool {
    name != header::CONTENT_TYPE
}

async fn await_response_headers<F, T, E>(
    cancellation: &CancellationToken,
    send: F,
) -> Result<T, ProxyError>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(ProxyError::Cancelled),
        result = tokio::time::timeout(RESPONSE_HEADER_DEADLINE, send) => {
            result.map_err(|_| ProxyError::Upstream)?
                .map_err(|_| ProxyError::Upstream)
        }
    }
}

async fn fetch_with_redirects(
    runtime: &ProxyRuntime,
    context: &ProxyRequestContext,
    request: &ParsedProxyRequest,
    method: Method,
    incoming: &HeaderMap,
) -> Result<FetchedProxyResponse, ProxyError> {
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
    let mut automatic_headers = HeaderMap::new();
    for name in AUTOMATIC_REQUEST_HEADERS {
        if let Some(value) = incoming.get(name) {
            automatic_headers.insert(name.clone(), value.clone());
        }
    }
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
        let mut headers = automatic_headers.clone();
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
        let response = await_response_headers(&context.cancellation, send).await?;

        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            return Err(ProxyError::Upstream);
        }

        if !REDIRECT_STATUSES.contains(&response.status()) {
            return Ok(FetchedProxyResponse {
                response,
                final_url: destination.url,
                effective_custom_request_headers: custom_headers,
                effective_response_headers: request.response_headers.clone(),
            });
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
        if next.as_str().len() > MAX_TARGET_URL {
            return Err(ProxyError::Upstream);
        }
        apply_redirect_origin_policy(
            &destination.url,
            &mut next,
            &mut automatic_headers,
            &mut custom_headers,
        );
        target = next;
    }
}

fn apply_redirect_origin_policy(
    current: &Url,
    next: &mut Url,
    automatic_headers: &mut HeaderMap,
    custom_headers: &mut HeaderMap,
) {
    if !same_origin(current, next) {
        let _ = next.set_username("");
        let _ = next.set_password(None);
        custom_headers.clear();
        automatic_headers.remove(header::IF_RANGE);
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub fn service(state: AppState) -> Router {
    runtime_service(state.proxy_runtime.clone())
}

fn runtime_service(runtime: Arc<ProxyRuntime>) -> Router {
    Router::new()
        .fallback(any(proxy_handler))
        .with_state(runtime)
}

async fn proxy_handler(
    State(runtime): State<Arc<ProxyRuntime>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let peer = peer.map(|Extension(ConnectInfo(address))| address.ip());
    handle_proxy_for_peer(&runtime, peer, original_uri, headers, method).await
}

#[cfg(test)]
async fn handle_proxy(
    runtime: &ProxyRuntime,
    original_uri: Uri,
    headers: HeaderMap,
    method: Method,
) -> Response {
    handle_proxy_for_peer(runtime, None, original_uri, headers, method).await
}

async fn handle_proxy_for_peer(
    runtime: &ProxyRuntime,
    peer: Option<IpAddr>,
    original_uri: Uri,
    headers: HeaderMap,
    method: Method,
) -> Response {
    let raw_target = original_uri
        .path_and_query()
        .map_or_else(|| original_uri.path(), |value| value.as_str());
    let raw_suffix = match raw_target.strip_prefix("/proxy") {
        Some(suffix) if suffix.is_empty() || suffix.starts_with('/') || suffix.starts_with('?') => {
            suffix
        }
        _ => return proxy_error_response(ProxyError::InvalidRequest),
    };
    handle_proxy_suffix_for_peer(runtime, peer, raw_suffix, headers, method).await
}

#[cfg(test)]
async fn handle_proxy_suffix(
    runtime: &ProxyRuntime,
    raw_suffix: &str,
    headers: HeaderMap,
    method: Method,
) -> Response {
    handle_proxy_suffix_for_peer(runtime, None, raw_suffix, headers, method).await
}

async fn handle_proxy_suffix_for_peer(
    runtime: &ProxyRuntime,
    peer: Option<IpAddr>,
    raw_suffix: &str,
    headers: HeaderMap,
    method: Method,
) -> Response {
    if raw_suffix.len() > MAX_PROXY_INPUT {
        return proxy_error_response(ProxyError::InvalidRequest);
    }
    if method == Method::CONNECT {
        return proxy_error_response(ProxyError::InvalidRequest);
    }
    let context = match runtime.try_request_for_peer(peer) {
        Ok(context) => context,
        Err(_) => return proxy_error_response(ProxyError::Capacity),
    };
    let request = match parse_proxy_suffix(raw_suffix) {
        Ok(request) => request,
        Err(error) => return proxy_error_response(error),
    };
    let credential_bearing = !request.target.username().is_empty()
        || request.target.password().is_some()
        || !request.request_headers.is_empty();
    let request_method = method.clone();
    let fetched = match fetch_with_redirects(runtime, &context, &request, method, &headers).await {
        Ok(response) => response,
        Err(error) => return proxy_error_response(error),
    };
    let FetchedProxyResponse {
        response: upstream,
        final_url,
        effective_custom_request_headers,
        effective_response_headers,
    } = fetched;
    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let content_type_playlist = effective_response_headers
        .get(header::CONTENT_TYPE)
        .or_else(|| upstream_headers.get(header::CONTENT_TYPE))
        .is_some_and(content_type_is_playlist);
    let playlist = final_url.path().ends_with(".m3u8")
        || final_url.path().ends_with(".m3u")
        || content_type_playlist;
    let transform = playlist
        && request_method != Method::HEAD
        && status == StatusCode::OK
        && !cache_control_forbids_transform(&upstream_headers);

    if transform {
        if !content_encoding_is_identity_only(&upstream_headers) {
            return proxy_error_response(ProxyError::Upstream);
        }
        let body = match collect_playlist(upstream, &context).await {
            Ok(body) => body,
            Err(error) => return proxy_error_response(error),
        };
        let body = match String::from_utf8(body)
            .map_err(|_| ProxyError::Upstream)
            .and_then(|body| {
                rewrite_playlist_with_options(
                    &body,
                    &final_url,
                    &effective_custom_request_headers,
                    &effective_response_headers,
                )
            }) {
            Ok(body) => body,
            Err(error) => return proxy_error_response(error),
        };
        return build_proxy_response(
            status,
            &upstream_headers,
            &effective_response_headers,
            buffered_proxy_body(Bytes::from(body), context.into_producer_lease()),
            true,
            credential_bearing,
        );
    }

    let body = streaming_proxy_body(
        Box::pin(
            upstream
                .bytes_stream()
                .map(|item| item.map_err(|_| ProxySourceError)),
        ),
        context.into_producer_lease(),
    );
    build_proxy_response(
        status,
        &upstream_headers,
        &effective_response_headers,
        body,
        false,
        credential_bearing,
    )
}

fn content_type_is_playlist(value: &HeaderValue) -> bool {
    let media_type = trim_ascii_ows(
        value
            .as_bytes()
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default(),
    );
    let mut parts = media_type.split(|byte| *byte == b'/');
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    if parts.next().is_some()
        || kind.is_empty()
        || subtype.is_empty()
        || !kind.iter().chain(subtype).all(|byte| is_http_token(*byte))
    {
        return false;
    }
    subtype
        .windows(b"mpegurl".len())
        .any(|candidate| candidate.eq_ignore_ascii_case(b"mpegurl"))
}

fn cache_control_forbids_transform(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .any(|value| cache_control_has_no_transform(value.as_bytes()).unwrap_or(true))
}

fn cache_control_has_no_transform(value: &[u8]) -> Option<bool> {
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut no_transform = false;
    for (index, byte) in value.iter().copied().enumerate() {
        if quoted {
            if escaped {
                if !is_quoted_header_byte(byte) {
                    return None;
                }
                escaped = false;
            } else {
                match byte {
                    b'\\' => escaped = true,
                    b'"' => quoted = false,
                    byte if !is_quoted_header_byte(byte) => return None,
                    _ => {}
                }
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b',' => {
                    no_transform |= cache_control_directive(&value[start..index])?;
                    start = index + 1;
                }
                byte if byte >= 0x80 || (byte < 0x20 && !matches!(byte, b' ' | b'\t')) => {
                    return None;
                }
                0x7f => return None,
                _ => {}
            }
        }
    }
    if quoted || escaped {
        return None;
    }
    no_transform |= cache_control_directive(&value[start..])?;
    Some(no_transform)
}

fn cache_control_directive(value: &[u8]) -> Option<bool> {
    let value = trim_ascii_ows(value);
    let name_length = value
        .iter()
        .position(|byte| !is_http_token(*byte))
        .unwrap_or(value.len());
    if name_length == 0 {
        return None;
    }
    let name = &value[..name_length];
    let remainder = trim_ascii_ows(&value[name_length..]);
    if !remainder.is_empty() {
        let parameter = trim_ascii_ows(remainder.strip_prefix(b"=")?);
        if parameter.is_empty() {
            return None;
        }
        if parameter[0] == b'"' {
            if !valid_quoted_header_value(parameter) {
                return None;
            }
        } else if !parameter.iter().all(|byte| is_http_token(*byte)) {
            return None;
        }
    }
    Some(name.eq_ignore_ascii_case(b"no-transform"))
}

fn valid_quoted_header_value(value: &[u8]) -> bool {
    if value.len() < 2 || value[0] != b'"' {
        return false;
    }
    let mut escaped = false;
    for (index, byte) in value[1..].iter().copied().enumerate() {
        if escaped {
            if !is_quoted_header_byte(byte) {
                return false;
            }
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return trim_ascii_ows(&value[index + 2..]).is_empty(),
            byte if !is_quoted_header_byte(byte) => return false,
            _ => {}
        }
    }
    false
}

fn is_quoted_header_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn content_encoding_is_identity_only(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|value| {
            value.as_bytes().split(|byte| *byte == b',').all(|coding| {
                let coding = trim_ascii_ows(coding);
                !coding.is_empty() && coding.eq_ignore_ascii_case(b"identity")
            })
        })
}

fn trim_ascii_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn streaming_proxy_body(stream: UpstreamByteStream, lease: ProxyProducerLease) -> Body {
    spawn_proxy_body(ProxyBodySource::Streaming(stream), lease).0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProxySourceError;

type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, ProxySourceError>> + Send + 'static>>;

enum ProxyBodySource {
    Streaming(UpstreamByteStream),
    Buffered(Option<Bytes>),
}

enum ProxySourceItem {
    Chunk(Bytes),
    Eof,
    Failed,
}

impl ProxyBodySource {
    async fn next(&mut self) -> ProxySourceItem {
        match self {
            Self::Streaming(stream) => match stream.next().await {
                Some(Ok(bytes)) => ProxySourceItem::Chunk(bytes),
                Some(Err(_)) => ProxySourceItem::Failed,
                None => ProxySourceItem::Eof,
            },
            Self::Buffered(bytes) => bytes
                .take()
                .map_or(ProxySourceItem::Eof, ProxySourceItem::Chunk),
        }
    }
}

enum ProxyHandoffSlot {
    Empty,
    Reserved,
    Full {
        bytes: Bytes,
        deadline: tokio::time::Instant,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProxyHandoffTerminal {
    Running,
    Clean,
    FailedPending,
    FailedDelivered,
}

struct ProxyHandoffState {
    slot: ProxyHandoffSlot,
    terminal: ProxyHandoffTerminal,
    consumer_closed: bool,
}

struct ProxyHandoff {
    state: Mutex<ProxyHandoffState>,
    producer_notify: Notify,
    consumer_notify: Notify,
    cancellation: CancellationToken,
    #[cfg(test)]
    producer_probe: Option<ProxyProducerProbe>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProxyProducerStop {
    ConsumerClosed,
    Failed,
}

enum ProxyConsumerItem {
    Chunk(Bytes),
    Failed,
    Eof,
}

impl ProxyHandoff {
    fn new(cancellation: CancellationToken) -> Self {
        Self {
            state: Mutex::new(ProxyHandoffState {
                slot: ProxyHandoffSlot::Empty,
                terminal: ProxyHandoffTerminal::Running,
                consumer_closed: false,
            }),
            producer_notify: Notify::new(),
            consumer_notify: Notify::new(),
            cancellation,
            #[cfg(test)]
            producer_probe: None,
        }
    }

    #[cfg(test)]
    fn with_producer_probe(mut self, producer_probe: Option<ProxyProducerProbe>) -> Self {
        self.producer_probe = producer_probe;
        self
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ProxyHandoffState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fail_locked(state: &mut ProxyHandoffState) {
        if !state.consumer_closed && state.terminal == ProxyHandoffTerminal::Running {
            state.slot = ProxyHandoffSlot::Empty;
            state.terminal = ProxyHandoffTerminal::FailedPending;
        }
    }

    fn fail(&self) {
        let mut state = self.lock_state();
        Self::fail_locked(&mut state);
        drop(state);
        #[cfg(test)]
        if let Some(producer_probe) = &self.producer_probe {
            producer_probe.mark_terminated_before_ready();
        }
        self.producer_notify.notify_waiters();
        self.consumer_notify.notify_waiters();
    }

    fn close_consumer(&self) {
        let mut state = self.lock_state();
        state.consumer_closed = true;
        state.slot = ProxyHandoffSlot::Empty;
        drop(state);
        #[cfg(test)]
        if let Some(producer_probe) = &self.producer_probe {
            producer_probe.mark_terminated_before_ready();
        }
        self.producer_notify.notify_waiters();
        self.consumer_notify.notify_waiters();
    }

    async fn reserve(&self) -> Result<(), ProxyProducerStop> {
        loop {
            let notified = self.producer_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock_state();
                if state.consumer_closed {
                    return Err(ProxyProducerStop::ConsumerClosed);
                }
                if state.terminal != ProxyHandoffTerminal::Running {
                    return Err(ProxyProducerStop::Failed);
                }
                if matches!(state.slot, ProxyHandoffSlot::Empty) {
                    state.slot = ProxyHandoffSlot::Reserved;
                    return Ok(());
                }
            }
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => {
                    self.fail();
                    return Err(ProxyProducerStop::Failed);
                }
                _ = &mut notified => {}
            }
        }
    }

    fn publish(
        &self,
        bytes: Bytes,
        deadline: tokio::time::Instant,
    ) -> Result<(), ProxyProducerStop> {
        let mut state = self.lock_state();
        if state.consumer_closed {
            state.slot = ProxyHandoffSlot::Empty;
            return Err(ProxyProducerStop::ConsumerClosed);
        }
        if self.cancellation.is_cancelled() || state.terminal != ProxyHandoffTerminal::Running {
            Self::fail_locked(&mut state);
            drop(state);
            #[cfg(test)]
            if let Some(producer_probe) = &self.producer_probe {
                producer_probe.mark_terminated_before_ready();
            }
            self.consumer_notify.notify_waiters();
            return Err(ProxyProducerStop::Failed);
        }
        debug_assert!(matches!(state.slot, ProxyHandoffSlot::Reserved));
        state.slot = ProxyHandoffSlot::Full { bytes, deadline };
        #[cfg(test)]
        let consumer_notification_deferred = self.producer_probe.is_some();
        drop(state);
        #[cfg(test)]
        if consumer_notification_deferred {
            return Ok(());
        }
        self.consumer_notify.notify_waiters();
        Ok(())
    }

    async fn wait_until_consumed(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ProxyProducerStop> {
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        #[cfg(test)]
        std::future::poll_fn(|context| {
            let _ = sleep.as_mut().poll(context);
            Poll::Ready(())
        })
        .await;
        loop {
            let notified = self.producer_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.lock_state();
                if state.consumer_closed {
                    return Err(ProxyProducerStop::ConsumerClosed);
                }
                if state.terminal != ProxyHandoffTerminal::Running {
                    return Err(ProxyProducerStop::Failed);
                }
                if matches!(state.slot, ProxyHandoffSlot::Empty) {
                    return Ok(());
                }
                #[cfg(test)]
                if matches!(state.slot, ProxyHandoffSlot::Full { .. })
                    && let Some(producer_probe) = &self.producer_probe
                {
                    producer_probe.mark_full_deadline_armed();
                }
            }
            #[cfg(test)]
            if self.producer_probe.is_some() {
                self.consumer_notify.notify_waiters();
            }
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => {
                    self.fail();
                    return Err(ProxyProducerStop::Failed);
                }
                _ = &mut sleep => {
                    let mut state = self.lock_state();
                    if state.consumer_closed {
                        return Err(ProxyProducerStop::ConsumerClosed);
                    }
                    if state.terminal != ProxyHandoffTerminal::Running {
                        return Err(ProxyProducerStop::Failed);
                    }
                    if matches!(state.slot, ProxyHandoffSlot::Empty) {
                        return Ok(());
                    }
                    if let ProxyHandoffSlot::Full {
                        deadline: published_deadline,
                        ..
                    } = &state.slot
                    {
                        debug_assert_eq!(*published_deadline, deadline);
                    }
                    Self::fail_locked(&mut state);
                    drop(state);
                    #[cfg(test)]
                    if let Some(producer_probe) = &self.producer_probe {
                        producer_probe.mark_terminated_before_ready();
                    }
                    self.producer_notify.notify_waiters();
                    self.consumer_notify.notify_waiters();
                    return Err(ProxyProducerStop::Failed);
                }
                _ = &mut notified => {}
            }
        }
    }

    async fn consumer_closed(&self) {
        loop {
            let notified = self.producer_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.lock_state().consumer_closed {
                return;
            }
            notified.await;
        }
    }

    fn clean(&self) {
        let mut state = self.lock_state();
        if self.cancellation.is_cancelled() {
            Self::fail_locked(&mut state);
        } else if !state.consumer_closed && state.terminal == ProxyHandoffTerminal::Running {
            debug_assert!(matches!(state.slot, ProxyHandoffSlot::Reserved));
            state.slot = ProxyHandoffSlot::Empty;
            state.terminal = ProxyHandoffTerminal::Clean;
        }
        drop(state);
        #[cfg(test)]
        if let Some(producer_probe) = &self.producer_probe {
            producer_probe.mark_terminated_before_ready();
        }
        self.producer_notify.notify_waiters();
        self.consumer_notify.notify_waiters();
    }

    async fn take(&self) -> ProxyConsumerItem {
        loop {
            let notified = self.consumer_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock_state();
                if self.cancellation.is_cancelled() {
                    Self::fail_locked(&mut state);
                }
                if state.terminal == ProxyHandoffTerminal::Running
                    && let ProxyHandoffSlot::Full { deadline, .. } = &state.slot
                    && tokio::time::Instant::now() >= *deadline
                {
                    Self::fail_locked(&mut state);
                }
                #[cfg(test)]
                if state.terminal != ProxyHandoffTerminal::Running
                    && let Some(producer_probe) = &self.producer_probe
                {
                    producer_probe.mark_terminated_before_ready();
                }
                match state.terminal {
                    ProxyHandoffTerminal::FailedPending => {
                        state.slot = ProxyHandoffSlot::Empty;
                        state.terminal = ProxyHandoffTerminal::FailedDelivered;
                        drop(state);
                        self.producer_notify.notify_waiters();
                        return ProxyConsumerItem::Failed;
                    }
                    ProxyHandoffTerminal::FailedDelivered => return ProxyConsumerItem::Eof,
                    ProxyHandoffTerminal::Clean => {
                        debug_assert!(matches!(state.slot, ProxyHandoffSlot::Empty));
                        return ProxyConsumerItem::Eof;
                    }
                    ProxyHandoffTerminal::Running => {
                        #[cfg(test)]
                        let producer_probe_pending = self
                            .producer_probe
                            .as_ref()
                            .is_some_and(ProxyProducerProbe::is_pending);
                        #[cfg(not(test))]
                        let producer_probe_pending = false;
                        if matches!(state.slot, ProxyHandoffSlot::Full { .. })
                            && !producer_probe_pending
                        {
                            let ProxyHandoffSlot::Full { bytes, .. } =
                                std::mem::replace(&mut state.slot, ProxyHandoffSlot::Empty)
                            else {
                                unreachable!()
                            };
                            drop(state);
                            self.producer_notify.notify_waiters();
                            return ProxyConsumerItem::Chunk(bytes);
                        }
                    }
                }
            }
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => self.fail(),
                _ = &mut notified => {}
            }
        }
    }
}

struct ProxyProducerGuard {
    handoff: Arc<ProxyHandoff>,
    armed: bool,
}

struct ProxyProducerTask<F> {
    future: Option<Pin<Box<F>>>,
}

impl<F> ProxyProducerTask<F> {
    fn new(future: F) -> Self {
        Self {
            future: Some(Box::pin(future)),
        }
    }

    fn drop_future(&mut self) {
        let Some(future) = self.future.take() else {
            return;
        };
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(future))) {
            drop_panic_payload(payload);
        }
    }
}

impl<F> Future for ProxyProducerTask<F>
where
    F: Future<Output = ()>,
{
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            self.future
                .as_mut()
                .expect("proxy producer task polled after completion")
                .as_mut()
                .poll(context)
        }));
        match outcome {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(())) => {
                self.drop_future();
                Poll::Ready(())
            }
            Err(payload) => {
                drop_panic_payload(payload);
                self.drop_future();
                Poll::Ready(())
            }
        }
    }
}

impl<F> Drop for ProxyProducerTask<F> {
    fn drop(&mut self) {
        self.drop_future();
    }
}

fn drop_panic_payload(payload: Box<dyn std::any::Any + Send>) {
    let _ = catch_unwind(AssertUnwindSafe(|| drop(payload)));
}

impl ProxyProducerGuard {
    fn new(handoff: Arc<ProxyHandoff>) -> Self {
        Self {
            handoff,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProxyProducerGuard {
    fn drop(&mut self) {
        if self.armed {
            self.handoff.fail();
        }
    }
}

struct ProxyBodyConsumer {
    handoff: Arc<ProxyHandoff>,
    producer: JoinHandle<()>,
}

struct ProxyProducerResources {
    source: ProxyBodySource,
    _lease: ProxyProducerLease,
}

impl Drop for ProxyBodyConsumer {
    fn drop(&mut self) {
        self.handoff.close_consumer();
        self.producer.abort();
    }
}

async fn read_source_chunk(
    source: &mut ProxyBodySource,
    handoff: &ProxyHandoff,
) -> Result<Option<Bytes>, ProxyProducerStop> {
    let deadline = tokio::time::sleep(UPSTREAM_READ_IDLE_DEADLINE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            _ = handoff.cancellation.cancelled() => {
                handoff.fail();
                return Err(ProxyProducerStop::Failed);
            }
            _ = handoff.consumer_closed() => {
                return Err(ProxyProducerStop::ConsumerClosed);
            }
            _ = &mut deadline => {
                handoff.fail();
                return Err(ProxyProducerStop::Failed);
            }
            item = source.next() => match item {
                ProxySourceItem::Chunk(bytes) if bytes.is_empty() => {
                    tokio::task::yield_now().await;
                }
                ProxySourceItem::Chunk(bytes) => return Ok(Some(bytes)),
                ProxySourceItem::Eof => return Ok(None),
                ProxySourceItem::Failed => {
                    handoff.fail();
                    return Err(ProxyProducerStop::Failed);
                }
            }
        }
    }
}

async fn run_proxy_body_producer(
    mut resources: ProxyProducerResources,
    handoff: Arc<ProxyHandoff>,
    mut guard: ProxyProducerGuard,
) {
    loop {
        if handoff.reserve().await.is_err() {
            guard.disarm();
            return;
        }
        let bytes = match read_source_chunk(&mut resources.source, &handoff).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                drop(resources);
                handoff.clean();
                guard.disarm();
                return;
            }
            Err(_) => {
                guard.disarm();
                return;
            }
        };

        let mut offset = 0usize;
        while offset < bytes.len() {
            if offset != 0 && handoff.reserve().await.is_err() {
                guard.disarm();
                return;
            }
            let end = offset
                .saturating_add(PROXY_BODY_CHUNK_SIZE)
                .min(bytes.len());
            let chunk = Bytes::copy_from_slice(&bytes[offset..end]);
            let deadline = tokio::time::Instant::now() + DOWNSTREAM_NO_PROGRESS_DEADLINE;
            if handoff.publish(chunk, deadline).is_err() {
                guard.disarm();
                return;
            }
            if handoff.wait_until_consumed(deadline).await.is_err() {
                guard.disarm();
                return;
            }
            offset = end;
        }
    }
}

fn spawn_proxy_body(
    source: ProxyBodySource,
    lease: ProxyProducerLease,
) -> (Body, tokio::task::AbortHandle) {
    let handoff = ProxyHandoff::new(lease.cancellation().clone());
    #[cfg(test)]
    let handoff = handoff.with_producer_probe(lease.producer_probe());
    let handoff = Arc::new(handoff);
    let guard = ProxyProducerGuard::new(handoff.clone());
    let producer_handoff = handoff.clone();
    let producer = tokio::spawn(ProxyProducerTask::new(run_proxy_body_producer(
        ProxyProducerResources {
            source,
            _lease: lease,
        },
        producer_handoff,
        guard,
    )));
    let abort = producer.abort_handle();
    let consumer = ProxyBodyConsumer { handoff, producer };
    let stream = futures_util::stream::unfold(consumer, |consumer| async move {
        let item = consumer.handoff.take().await;
        match item {
            ProxyConsumerItem::Chunk(bytes) => Some((Ok(bytes), consumer)),
            ProxyConsumerItem::Failed => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "proxy response body failed",
                )),
                consumer,
            )),
            ProxyConsumerItem::Eof => None,
        }
    });
    (Body::from_stream(stream), abort)
}

fn buffered_proxy_body(bytes: Bytes, lease: ProxyProducerLease) -> Body {
    spawn_proxy_body(ProxyBodySource::Buffered(Some(bytes)), lease).0
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
    credential_bearing: bool,
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
        header::CACHE_CONTROL,
        header::EXPIRES,
        header::PRAGMA,
        header::VARY,
    ];
    let mut response = Response::new(body);
    *response.status_mut() = status;
    for name in SAFE_RESPONSE_HEADERS {
        for value in upstream.get_all(name).iter() {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }
    for (name, value) in custom {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    if rewritten {
        for name in [
            header::CONTENT_LENGTH,
            header::CONTENT_RANGE,
            header::CONTENT_ENCODING,
            header::ETAG,
            header::LAST_MODIFIED,
        ] {
            response.headers_mut().remove(name);
        }
        response
            .headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("none"));
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    } else if credential_bearing {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
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
    apply_route_owned_headers(&mut response);
    response
}

fn apply_route_owned_headers(response: &mut Response) {
    response.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox",
        ),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
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
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    apply_route_owned_headers(&mut response);
    response
}

const MAX_PLAYLIST_OUTPUT: usize = 16 * 1024 * 1024;

#[cfg(test)]
fn rewrite_playlist_bounded(body: &str, base_url: &Url) -> Result<String, ProxyError> {
    rewrite_playlist_with_options(body, base_url, &HeaderMap::new(), &HeaderMap::new())
}

fn rewrite_playlist_with_options(
    body: &str,
    base_url: &Url,
    request_headers: &HeaderMap,
    response_headers: &HeaderMap,
) -> Result<String, ProxyError> {
    let mut output = String::new();
    output
        .try_reserve_exact(body.len().min(MAX_PLAYLIST_OUTPUT))
        .map_err(|_| ProxyError::Upstream)?;
    for line_with_ending in body.split_inclusive('\n') {
        let (line, ending) = if let Some(line) = line_with_ending.strip_suffix("\r\n") {
            (line, "\r\n")
        } else if let Some(line) = line_with_ending.strip_suffix('\n') {
            (line, "\n")
        } else {
            (line_with_ending, "")
        };

        if line.starts_with("#EXT") {
            rewrite_playlist_tag(
                line,
                base_url,
                request_headers,
                response_headers,
                &mut output,
            )?;
        } else if line.starts_with('#') || line.bytes().all(|byte| matches!(byte, b' ' | b'\t')) {
            push_playlist(&mut output, line)?;
        } else {
            rewrite_playlist_reference(
                line,
                base_url,
                request_headers,
                response_headers,
                &mut output,
            )?;
        }
        push_playlist(&mut output, ending)?;
    }
    if body.is_empty() {
        return Ok(String::new());
    }
    Ok(output)
}

fn rewrite_playlist_tag(
    line: &str,
    base_url: &Url,
    request_headers: &HeaderMap,
    response_headers: &HeaderMap,
    output: &mut String,
) -> Result<(), ProxyError> {
    let Some(colon) = line.find(':') else {
        return push_playlist(output, line);
    };
    let bytes = line.as_bytes();
    let mut attribute_start = colon + 1;
    let mut copied = 0usize;
    while attribute_start < line.len() {
        let mut key_start = attribute_start;
        while bytes
            .get(key_start)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            key_start += 1;
        }
        let mut scan_start = attribute_start;
        if line[key_start..].starts_with("URI=\"") {
            let value_start = key_start + 5;
            let Some(value_end) = line[value_start..]
                .find('"')
                .map(|offset| value_start + offset)
            else {
                break;
            };
            push_playlist(output, &line[copied..value_start])?;
            let value = &line[value_start..value_end];
            rewrite_playlist_reference(value, base_url, request_headers, response_headers, output)?;
            copied = value_end;
            scan_start = value_end + 1;
        }

        let mut quoted = false;
        let mut next_attribute = None;
        for (offset, byte) in bytes[scan_start..].iter().copied().enumerate() {
            match byte {
                b'"' => quoted = !quoted,
                b',' if !quoted => {
                    next_attribute = Some(scan_start + offset + 1);
                    break;
                }
                _ => {}
            }
        }
        let Some(next_attribute) = next_attribute else {
            break;
        };
        attribute_start = next_attribute;
    }
    push_playlist(output, &line[copied..])
}

struct HlsVariableReplacement {
    token: String,
    placeholder: String,
    removed_with_fragment: bool,
}

struct HlsVariablePath {
    base_target: String,
    path: String,
    query: Option<String>,
}

struct ResolvedHlsReference {
    target: String,
    same_origin: bool,
    variable_path: Option<HlsVariablePath>,
}

fn rewrite_playlist_reference(
    reference: &str,
    base_url: &Url,
    request_headers: &HeaderMap,
    response_headers: &HeaderMap,
    output: &mut String,
) -> Result<(), ProxyError> {
    let Some(resolved) = resolve_hls_reference(reference, base_url)? else {
        return push_playlist(output, reference);
    };
    push_proxy_uri(output, &resolved, request_headers, response_headers)
}

fn resolve_hls_reference(
    reference: &str,
    base_url: &Url,
) -> Result<Option<ResolvedHlsReference>, ProxyError> {
    let scheme_colon = reference
        .bytes()
        .take(MAX_TARGET_URL + 1)
        .inspect(|_| {
            #[cfg(test)]
            HLS_SCHEME_PRESCAN_BYTES.with(|scans| scans.set(scans.get() + 1));
        })
        .position(|byte| matches!(byte, b':' | b'/' | b'?' | b'#'))
        .filter(|index| reference.as_bytes()[*index] == b':');
    if let Some(colon) = scheme_colon {
        let scheme = &reference[..colon];
        if valid_url_scheme(scheme)
            && !scheme.eq_ignore_ascii_case("http")
            && !scheme.eq_ignore_ascii_case("https")
        {
            return Ok(None);
        }
    }
    if reference.len() > MAX_TARGET_URL {
        return Err(ProxyError::Upstream);
    }
    let variables = hls_variable_ranges(reference);
    if scheme_colon.is_some_and(|colon| variables.iter().any(|(start, _)| *start < colon)) {
        return Ok(None);
    }

    let authority = authority_range(reference, scheme_colon);
    if authority.is_some_and(|(authority_start, authority_end)| {
        variables
            .iter()
            .any(|(start, end)| *start < authority_end && *end > authority_start)
    }) {
        return Ok(None);
    }

    let mut placeholder_generator = HlsPlaceholderGenerator::new(reference, base_url.as_str());
    let (substituted, mut replacements) =
        substitute_hls_variables(reference, &variables, &mut placeholder_generator)?;
    let Some(mut absolute) = resolve_substituted_hls_reference(base_url, &substituted)? else {
        return Ok(None);
    };
    if !hls_placeholders_are_safe(&absolute, &replacements) {
        placeholder_generator.occupy(absolute.as_str());
        let (retry, retry_replacements) =
            substitute_hls_variables(reference, &variables, &mut placeholder_generator)?;
        let Some(retry_absolute) = resolve_substituted_hls_reference(base_url, &retry)? else {
            return Ok(None);
        };
        if !hls_placeholders_are_safe(&retry_absolute, &retry_replacements) {
            return Ok(None);
        }
        absolute = retry_absolute;
        replacements = retry_replacements;
    }
    let same_origin = same_origin(base_url, &absolute);
    let target = restore_hls_variables(absolute.as_str(), &replacements)?;
    let variable_path = if replacements
        .iter()
        .any(|replacement| !replacement.removed_with_fragment)
    {
        let path = restore_hls_variables(absolute.path(), &replacements)?;
        let query = absolute
            .query()
            .map(|query| restore_hls_variables(query, &replacements))
            .transpose()?;
        if validate_percent_encoding(&path).is_err()
            || query
                .as_deref()
                .is_some_and(|query| validate_percent_encoding(query).is_err())
        {
            return Ok(None);
        }
        absolute.set_path("/");
        absolute.set_query(None);
        Some(HlsVariablePath {
            base_target: absolute.into(),
            path,
            query,
        })
    } else {
        None
    };
    Ok(Some(ResolvedHlsReference {
        target,
        same_origin,
        variable_path,
    }))
}

fn substitute_hls_variables(
    reference: &str,
    variables: &[(usize, usize)],
    placeholder_generator: &mut HlsPlaceholderGenerator,
) -> Result<(String, Vec<HlsVariableReplacement>), ProxyError> {
    let fragment = reference.find('#');
    let mut replacements = Vec::with_capacity(variables.len());
    let mut substituted = String::new();
    substituted
        .try_reserve_exact(reference.len())
        .map_err(|_| ProxyError::Upstream)?;
    let mut copied = 0usize;
    for (start, end) in variables.iter().copied() {
        push_target(&mut substituted, &reference[copied..start])?;
        let placeholder = placeholder_generator.next().ok_or(ProxyError::Upstream)?;
        push_target(&mut substituted, &placeholder)?;
        replacements.push(HlsVariableReplacement {
            token: reference[start..end].to_owned(),
            placeholder,
            removed_with_fragment: fragment.is_some_and(|fragment| start > fragment),
        });
        copied = end;
    }
    push_target(&mut substituted, &reference[copied..])?;
    Ok((substituted, replacements))
}

fn resolve_substituted_hls_reference(
    base_url: &Url,
    substituted: &str,
) -> Result<Option<Url>, ProxyError> {
    let absolute = match base_url.join(substituted) {
        Ok(absolute) => absolute,
        Err(_) => return Ok(None),
    };
    if !matches!(absolute.scheme(), "http" | "https") || absolute.host().is_none() {
        return Ok(None);
    }
    validate_proxy_target(absolute)
        .map(Some)
        .map_err(|_| ProxyError::Upstream)
}

fn hls_placeholders_are_safe(canonical: &Url, replacements: &[HlsVariableReplacement]) -> bool {
    let mut placeholder_indices = HashMap::with_capacity(replacements.len());
    for (index, replacement) in replacements.iter().enumerate() {
        let Ok(placeholder) = <[u8; 4]>::try_from(replacement.placeholder.as_bytes()) else {
            return false;
        };
        if placeholder_indices.insert(placeholder, index).is_some() {
            return false;
        }
    }
    let serialized = canonical.as_str();
    let path_query = &canonical[Position::BeforePath..Position::AfterQuery];
    let path_query_start = serialized.len() - canonical[Position::BeforePath..].len();
    let path_query_end = path_query_start + path_query.len();
    let mut occurrences = vec![(0usize, 0usize); replacements.len()];
    for (start, window) in serialized.as_bytes().windows(4).enumerate() {
        if let Some(index) = <[u8; 4]>::try_from(window)
            .ok()
            .and_then(|placeholder| placeholder_indices.get(&placeholder))
        {
            occurrences[*index].0 = occurrences[*index].0.saturating_add(1);
            if start >= path_query_start && start + window.len() <= path_query_end {
                occurrences[*index].1 = occurrences[*index].1.saturating_add(1);
            }
        }
    }
    replacements
        .iter()
        .zip(occurrences)
        .all(|(replacement, (total, in_path_query))| {
            if replacement.removed_with_fragment {
                total == 0
            } else {
                total == 1 && in_path_query == 1
            }
        })
}

fn valid_url_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn authority_range(reference: &str, scheme_colon: Option<usize>) -> Option<(usize, usize)> {
    let start = if reference.starts_with("//") {
        2
    } else {
        let colon = scheme_colon?;
        reference
            .get(colon + 1..)?
            .starts_with("//")
            .then_some(colon + 3)?
    };
    let end = reference[start..]
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .map_or(reference.len(), |offset| start + offset);
    Some((start, end))
}

#[cfg(test)]
thread_local! {
    static HLS_VARIABLE_RANGE_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static HLS_SCHEME_PRESCAN_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn hls_variable_ranges(value: &str) -> Vec<(usize, usize)> {
    #[cfg(test)]
    HLS_VARIABLE_RANGE_SCANS.with(|scans| scans.set(scans.get() + 1));

    let bytes = value.as_bytes();
    let mut variables = Vec::new();
    let mut index = 0usize;
    while index + 3 < bytes.len() {
        if bytes[index] != b'{' || bytes[index + 1] != b'$' {
            index += 1;
            continue;
        }
        let name_start = index + 2;
        let mut end = name_start;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-'))
        {
            end += 1;
        }
        if end > name_start && bytes.get(end) == Some(&b'}') {
            variables.push((index, end + 1));
            index = end + 1;
        } else {
            index += 1;
        }
    }
    variables
}

struct HlsPlaceholderGenerator {
    occupied: HashSet<[u8; 4]>,
    next: usize,
}

impl HlsPlaceholderGenerator {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

    fn new(reference: &str, base: &str) -> Self {
        let mut generator = Self {
            occupied: HashSet::new(),
            next: 0,
        };
        generator.occupy(reference);
        generator.occupy(base);
        generator
    }

    fn occupy(&mut self, value: &str) {
        for window in value.as_bytes().windows(4) {
            if window[0].eq_ignore_ascii_case(&b'x') {
                self.occupied.insert([
                    window[0].to_ascii_lowercase(),
                    window[1].to_ascii_lowercase(),
                    window[2].to_ascii_lowercase(),
                    window[3].to_ascii_lowercase(),
                ]);
            }
        }
    }

    fn next(&mut self) -> Option<String> {
        while self.next < 36usize.pow(3) {
            let number = self.next;
            self.next += 1;
            let candidate = [
                b'x',
                Self::DIGITS[(number / (36 * 36)) % 36],
                Self::DIGITS[(number / 36) % 36],
                Self::DIGITS[number % 36],
            ];
            if self.occupied.insert(candidate) {
                return std::str::from_utf8(&candidate).ok().map(str::to_owned);
            }
        }
        None
    }
}

fn restore_hls_variables(
    canonical: &str,
    replacements: &[HlsVariableReplacement],
) -> Result<String, ProxyError> {
    let ordinary = replacements
        .iter()
        .map(|replacement| (replacement.placeholder.as_str(), replacement.token.as_str()))
        .collect::<HashMap<_, _>>();
    let mut restored = String::new();
    restored
        .try_reserve_exact(canonical.len())
        .map_err(|_| ProxyError::Upstream)?;
    let mut index = 0;
    while index < canonical.len() {
        let replacement = canonical
            .get(index..index.saturating_add(4))
            .and_then(|candidate| ordinary.get(candidate).copied());
        if let Some(token) = replacement {
            push_target(&mut restored, token)?;
            index += 4;
        } else {
            let character = canonical[index..]
                .chars()
                .next()
                .ok_or(ProxyError::Upstream)?;
            let end = index + character.len_utf8();
            push_target(&mut restored, &canonical[index..end])?;
            index = end;
        }
    }
    Ok(restored)
}

fn push_target(output: &mut String, value: &str) -> Result<(), ProxyError> {
    reserve_bounded(output, value.len(), MAX_TARGET_URL)?;
    output.push_str(value);
    Ok(())
}

fn push_proxy_uri(
    output: &mut String,
    resolved: &ResolvedHlsReference,
    request_headers: &HeaderMap,
    response_headers: &HeaderMap,
) -> Result<(), ProxyError> {
    const ROUTE_PREFIX: &str = "/proxy";
    let (suffix_prefix, target, path) = if let Some(variable_path) = &resolved.variable_path {
        (
            "/d=",
            variable_path.base_target.as_str(),
            Some(variable_path),
        )
    } else {
        ("/?d=", resolved.target.as_str(), None)
    };
    let target_length = percent_encoded_length(target)?;
    let mut suffix_length = suffix_prefix
        .len()
        .checked_add(target_length)
        .ok_or(ProxyError::Upstream)?;
    let mut options = Vec::new();
    if resolved.same_origin {
        for (kind, headers) in [('h', request_headers), ('r', response_headers)] {
            for (name, value) in headers {
                if (kind == 'h' && request_header_forbidden(name))
                    || (kind == 'r' && response_header_forbidden(name))
                {
                    continue;
                }
                let value =
                    std::str::from_utf8(value.as_bytes()).map_err(|_| ProxyError::Upstream)?;
                let pair_length = name
                    .as_str()
                    .len()
                    .checked_add(value.len())
                    .and_then(|length| length.checked_add(1))
                    .ok_or(ProxyError::Upstream)?;
                if pair_length > MAX_HEADER_PAIR {
                    return Err(ProxyError::Upstream);
                }
                let name_length = percent_encoded_length(name.as_str())?;
                let value_length = percent_encoded_length(value)?;
                suffix_length = suffix_length
                    .checked_add(3)
                    .and_then(|length| length.checked_add(name_length))
                    .and_then(|length| length.checked_add(3))
                    .and_then(|length| length.checked_add(value_length))
                    .ok_or(ProxyError::Upstream)?;
                options.push((kind, name.as_str(), value));
            }
        }
        if options.len() > MAX_CUSTOM_OPTIONS {
            return Err(ProxyError::Upstream);
        }
        options.sort_unstable_by(|left, right| {
            (left.0, left.1, left.2.as_bytes()).cmp(&(right.0, right.1, right.2.as_bytes()))
        });
    }
    if let Some(variable_path) = path {
        validate_percent_encoding(&variable_path.path).map_err(|_| ProxyError::Upstream)?;
        if let Some(query) = &variable_path.query {
            validate_percent_encoding(query).map_err(|_| ProxyError::Upstream)?;
        }
        suffix_length = suffix_length
            .checked_add(RAW_CANONICAL_PATH_OPTION.len())
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(variable_path.path.len()))
            .and_then(|length| {
                variable_path.query.as_ref().map_or(Some(length), |query| {
                    length
                        .checked_add(1)
                        .and_then(|length| length.checked_add(query.len()))
                })
            })
            .ok_or(ProxyError::Upstream)?;
    }
    if suffix_length > MAX_PROXY_INPUT {
        return Err(ProxyError::Upstream);
    }
    let required = ROUTE_PREFIX
        .len()
        .checked_add(suffix_length)
        .ok_or(ProxyError::Upstream)?;
    reserve_playlist(output, required)?;
    output.push_str(ROUTE_PREFIX);
    output.push_str(suffix_prefix);
    append_percent_encoded(output, target);
    for (kind, name, value) in options {
        output.push('&');
        output.push(kind);
        output.push('=');
        append_percent_encoded(output, name);
        output.push_str("%3A");
        append_percent_encoded(output, value);
    }
    if let Some(variable_path) = path {
        output.push_str(RAW_CANONICAL_PATH_OPTION);
        output.push('/');
        output.push_str(&variable_path.path);
        if let Some(query) = &variable_path.query {
            output.push('?');
            output.push_str(query);
        }
    }
    Ok(())
}

fn percent_encoded_length(value: &str) -> Result<usize, ProxyError> {
    let mut length = 0usize;
    for byte in value.bytes() {
        length = length
            .checked_add(if percent_encoding_safe(byte) { 1 } else { 3 })
            .ok_or(ProxyError::Upstream)?;
    }
    Ok(length)
}

fn append_percent_encoded(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if percent_encoding_safe(byte) {
            output.push(char::from(byte));
        } else {
            let encoded = [b'%', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]];
            output.push_str(std::str::from_utf8(&encoded).unwrap());
        }
    }
}

fn percent_encoding_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn push_playlist(output: &mut String, value: &str) -> Result<(), ProxyError> {
    reserve_bounded(output, value.len(), MAX_PLAYLIST_OUTPUT)?;
    output.push_str(value);
    Ok(())
}

fn reserve_playlist(output: &mut String, additional: usize) -> Result<(), ProxyError> {
    reserve_bounded(output, additional, MAX_PLAYLIST_OUTPUT)
}

fn reserve_bounded(
    output: &mut String,
    additional: usize,
    maximum: usize,
) -> Result<(), ProxyError> {
    let next_length = output
        .len()
        .checked_add(additional)
        .ok_or(ProxyError::Upstream)?;
    if next_length > maximum {
        return Err(ProxyError::Upstream);
    }
    if next_length > output.capacity() {
        let desired_capacity = output
            .capacity()
            .max(1)
            .saturating_mul(2)
            .max(next_length)
            .min(maximum);
        output
            .try_reserve_exact(desired_capacity - output.len())
            .map_err(|_| ProxyError::Upstream)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DOWNSTREAM_NO_PROGRESS_DEADLINE, HLS_SCHEME_PRESCAN_BYTES, HLS_VARIABLE_RANGE_SCANS,
        MAX_HEADER_PAIR, MAX_PLAYLIST_INPUT, MAX_PLAYLIST_OUTPUT, MAX_PROXY_INPUT, MAX_TARGET_URL,
        PROXY_BODY_CHUNK_SIZE, ProxyBodySource, ProxyConsumerItem, ProxyError, ProxyHandoff,
        ProxyHandoffSlot, ProxyProducerStop, ProxySourceError, apply_redirect_origin_policy,
        await_response_headers, buffered_proxy_body, collect_playlist, fetch_with_redirects,
        handle_proxy, handle_proxy_suffix, parse_proxy_request, parse_proxy_suffix,
        proxy_error_response, resolve_hls_reference, rewrite_playlist_bounded,
        rewrite_playlist_with_options, runtime_service, same_origin, spawn_proxy_body,
        streaming_proxy_body,
    };
    use crate::network_security::{
        Clock, DestinationValidator, DnsResolver, LocalNetworkProvider, ProxyPolicySettings,
        ProxyRuntime,
    };
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        extract::Path,
        http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
        response::{IntoResponse, Response},
        routing::{any, get},
    };
    use futures_util::StreamExt;
    use std::{
        collections::VecDeque,
        future::Future,
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::{Duration, Instant},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;
    use url::Url;

    fn assert_response_isolated(response: &Response) {
        let expected = [
            (
                "content-security-policy",
                "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox",
            ),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("x-frame-options", "DENY"),
        ];
        for (name, value) in expected {
            assert_eq!(response.headers().get(name).unwrap(), value, "{name}");
        }
    }

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
    fn parse_path_tail_cannot_replace_the_declared_authority() {
        for (tail, expected_path) in [
            ("https://evil.example/steal", "/https://evil.example/steal"),
            ("//evil.example/steal", "//evil.example/steal"),
        ] {
            let rest =
                format!("d=https%3A%2F%2Ftrusted.example&h=Authorization%3ABearer%20secret/{tail}");
            let parsed = parse_proxy_request(&rest, None).unwrap();
            assert_eq!(parsed.target.host_str(), Some("trusted.example"), "{tail}");
            assert_eq!(parsed.target.path(), expected_path, "{tail}");
        }
    }

    #[test]
    fn parse_selects_the_form_structurally() {
        let parsed = parse_proxy_request(
            "d=https%3A%2F%2Ftrusted.example%2Fold%2Fbase/media/file",
            Some("d=https%3A%2F%2Fevil.example&h=Host%3Aevil&r=Set-Cookie%3Abad"),
        )
        .unwrap();
        assert_eq!(
            parsed.target.as_str(),
            "https://trusted.example/media/file?d=https%3A%2F%2Fevil.example&h=Host%3Aevil&r=Set-Cookie%3Abad"
        );

        assert!(matches!(
            parse_proxy_request("foo", Some("d=https%3A%2F%2Fexample.com")),
            Err(ProxyError::InvalidRequest)
        ));
    }

    #[test]
    fn parse_requires_exactly_one_decoded_lowercase_target_key() {
        for (rest, query) in [
            ("", Some("x=value")),
            (
                "",
                Some("d=https%3A%2F%2Fone.example&d=https%3A%2F%2Ftwo.example"),
            ),
            (
                "",
                Some("d=https%3A%2F%2Fone.example&%64=https%3A%2F%2Ftwo.example"),
            ),
            ("", Some("D=https%3A%2F%2Fexample.com")),
        ] {
            assert!(matches!(
                parse_proxy_request(rest, query),
                Err(ProxyError::InvalidRequest)
            ));
        }
    }

    #[test]
    fn parse_form_decodes_options_exactly_once() {
        let parsed = parse_proxy_request(
            "",
            Some("d=https%3A%2F%2Fexample.com%2F%252F&h=X-Test%3Aa%26b%3Dc%2Bd+e"),
        )
        .unwrap();
        assert_eq!(parsed.target.as_str(), "https://example.com/%2F");
        assert_eq!(parsed.request_headers["x-test"], "a&b=c+d e");
    }

    #[test]
    fn parse_path_decodes_once_with_path_semantics_and_replaces_base_components() {
        let parsed = parse_proxy_request(
            "d=https%3A%2F%2Fuser%3Apass%40example.com%2Fold%3Fbase%3D1%23fragment/a+b%2Fc%3Fd%23e",
            Some("outer=a%2Bb"),
        )
        .unwrap();
        assert_eq!(
            parsed.target.as_str(),
            "https://user:pass@example.com/a+b/c%3Fd%23e?outer=a%2Bb"
        );

        let no_tail = parse_proxy_request(
            "d=https%3A%2F%2Fuser%3Apass%40example.com%2Fold%3Fbase%3D1%23fragment",
            None,
        )
        .unwrap();
        assert_eq!(no_tail.target.as_str(), "https://user:pass@example.com/");

        let explicit_empty_query =
            parse_proxy_request("d=https%3A%2F%2Fexample.com%2Fold%3Fbase%3D1", Some("")).unwrap();
        assert_eq!(
            explicit_empty_query.target.as_str(),
            "https://example.com/?"
        );
    }

    #[test]
    fn parse_raw_canonical_path_mode_preserves_escapes_and_rejects_invalid_uses() {
        let parsed = parse_proxy_request(
            "d=https%3A%2F%2Fexample.com&x-stream-path=raw//media/a%2Fb%25%41%5C%FF",
            Some("token=%FF"),
        )
        .unwrap();
        assert_eq!(
            parsed.target.as_str(),
            "https://example.com/media/a%2Fb%25%41%5C%FF?token=%FF"
        );

        for (rest, query) in [
            (
                "d=https%3A%2F%2Fexample.com&x-stream-path=raw&x-stream-path=raw//media",
                None,
            ),
            (
                "d=https%3A%2F%2Fexample.com&x-stream-path=raw&x-stream-%70ath=raw//media",
                None,
            ),
            (
                "d=https%3A%2F%2Fexample.com&x-stream-path=legacy//media",
                None,
            ),
            ("d=https%3A%2F%2Fexample.com&x-stream-path=raw", None),
            ("d=https%3A%2F%2Fexample.com&x-stream-path=raw/", None),
            (
                "d=https%3A%2F%2Fexample.com&x-stream-path=raw/",
                Some("token=value"),
            ),
            ("d=https%3A%2F%2Fexample.com&x-stream-path=raw//bad%", None),
        ] {
            assert!(
                matches!(
                    parse_proxy_request(rest, query),
                    Err(ProxyError::InvalidRequest)
                ),
                "rest={rest:?}, query={query:?}"
            );
        }
        assert!(matches!(
            parse_proxy_request("", Some("d=https%3A%2F%2Fexample.com&x-stream-path=raw")),
            Err(ProxyError::InvalidRequest)
        ));

        let unknown = parse_proxy_request(
            "d=https%3A%2F%2Fexample.com&x-unknown=raw/media%2Fpart",
            None,
        )
        .unwrap();
        assert_eq!(unknown.target.as_str(), "https://example.com/media/part");
    }

    #[test]
    fn legacy_path_query_preserves_malformed_percent_text_but_raw_mode_rejects_it() {
        for (query, expected) in [
            ("token=%", "https://example.com/media?token=%"),
            ("token=%0", "https://example.com/media?token=%0"),
            ("token=%GG", "https://example.com/media?token=%GG"),
        ] {
            let legacy = parse_proxy_request("d=https%3A%2F%2Fexample.com/media", Some(query))
                .unwrap_or_else(|error| panic!("legacy query {query:?} failed: {error:?}"));
            assert_eq!(legacy.target.as_str(), expected, "query={query:?}");

            assert!(
                matches!(
                    parse_proxy_request(
                        "d=https%3A%2F%2Fexample.com&x-stream-path=raw//media",
                        Some(query),
                    ),
                    Err(ProxyError::InvalidRequest)
                ),
                "raw query {query:?}"
            );
        }
    }

    #[test]
    fn parse_rejects_malformed_percent_encoding_and_utf8() {
        for invalid in ["%", "%0", "%GG", "%FF"] {
            let query = format!("d=https%3A%2F%2Fexample.com&unknown={invalid}");
            assert!(
                matches!(
                    parse_proxy_request("", Some(&query)),
                    Err(ProxyError::InvalidRequest)
                ),
                "{invalid}"
            );

            let rest = format!("d=https%3A%2F%2Fexample.com/{invalid}");
            assert!(
                matches!(
                    parse_proxy_request(&rest, None),
                    Err(ProxyError::InvalidRequest)
                ),
                "{invalid}"
            );
        }
    }

    #[test]
    fn parse_query_preserves_userinfo_and_clears_fragment() {
        let parsed = parse_proxy_request(
            "",
            Some("d=https%3A%2F%2Fuser%3Apass%40example.com%2Fvideo%3Fx%3D1%23fragment"),
        )
        .unwrap();
        assert_eq!(
            parsed.target.as_str(),
            "https://user:pass@example.com/video?x=1"
        );
    }

    #[test]
    fn parse_accepts_exact_raw_and_canonical_limits() {
        let prefix = "?d=https%3A%2F%2Fexample.com&unknown=";
        let exact_raw = format!("{prefix}{}", "a".repeat(MAX_PROXY_INPUT - prefix.len()));
        assert_eq!(exact_raw.len(), MAX_PROXY_INPUT);
        assert!(parse_proxy_suffix(&exact_raw).is_ok());
        assert!(matches!(
            parse_proxy_suffix(&format!("{exact_raw}a")),
            Err(ProxyError::InvalidRequest)
        ));

        let target_prefix = "https://example.com/";
        let exact_target = format!(
            "{target_prefix}{}",
            "a".repeat(MAX_TARGET_URL - target_prefix.len())
        );
        let exact_query = format!("d={exact_target}");
        assert_eq!(
            parse_proxy_request("", Some(&exact_query))
                .unwrap()
                .target
                .as_str()
                .len(),
            MAX_TARGET_URL
        );
        let oversized_query = format!("d={exact_target}a");
        assert!(matches!(
            parse_proxy_request("", Some(&oversized_query)),
            Err(ProxyError::InvalidRequest)
        ));
    }

    #[test]
    fn parse_preserves_header_count_and_pair_limits() {
        let options = (0..64)
            .map(|index| format!("h=X-{index}%3Avalue"))
            .collect::<Vec<_>>()
            .join("&");
        let query = format!("d=https%3A%2F%2Fexample.com&{options}");
        assert_eq!(
            parse_proxy_request("", Some(&query))
                .unwrap()
                .request_headers
                .len(),
            64
        );

        let exact_pair = format!(
            "d=https%3A%2F%2Fexample.com&h=X:{}",
            "a".repeat(MAX_HEADER_PAIR - 2)
        );
        assert!(parse_proxy_request("", Some(&exact_pair)).is_ok());
        let oversized_pair = format!("{exact_pair}a");
        assert!(matches!(
            parse_proxy_request("", Some(&oversized_pair)),
            Err(ProxyError::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn overlong_raw_suffix_precedes_capacity_and_dns() {
        let (runtime, resolver) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let permits = (0..64)
            .map(|index| {
                runtime
                    .try_request_for_peer(Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                        index + 1,
                    ))))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(runtime.capacity_snapshot(), (64, 64));
        let prefix = "?d=http%3A%2F%2Fblocked.example&unknown=";
        let raw_suffix = format!("{prefix}{}", "a".repeat(MAX_PROXY_INPUT + 1 - prefix.len()));
        let response =
            handle_proxy_suffix(&runtime, &raw_suffix, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.capacity_snapshot(), (64, 64));

        let response = handle_proxy_suffix(
            &runtime,
            "?d=http%3A%2F%2Fblocked.example",
            HeaderMap::new(),
            Method::GET,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        drop(permits);
    }

    #[test]
    fn redirect_origin_uses_scheme_canonical_host_and_effective_port() {
        let http = Url::parse("http://example.test:443/source").unwrap();
        let https = Url::parse("https://example.test:443/destination").unwrap();
        let implicit_http = Url::parse("http://EXAMPLE.test/source").unwrap();
        let explicit_http = Url::parse("http://example.test:80/destination").unwrap();
        let other_port = Url::parse("http://example.test:81/destination").unwrap();

        assert!(!same_origin(&http, &https));
        assert!(same_origin(&implicit_http, &explicit_http));
        assert!(!same_origin(&implicit_http, &other_port));
    }

    #[test]
    fn http_to_https_same_host_and_port_clears_cross_origin_state() {
        let current = Url::parse("http://example.test:443/source").unwrap();
        let mut next =
            Url::parse("https://redirect-user:redirect-pass@example.test:443/destination").unwrap();
        let mut automatic = HeaderMap::from_iter([
            (header::RANGE, "bytes=10-".parse().unwrap()),
            (header::IF_RANGE, "origin-a-validator".parse().unwrap()),
        ]);
        let mut custom = HeaderMap::from_iter([
            (header::AUTHORIZATION, "Bearer secret".parse().unwrap()),
            ("x-api-key".parse().unwrap(), "secret".parse().unwrap()),
        ]);

        apply_redirect_origin_policy(&current, &mut next, &mut automatic, &mut custom);

        assert!(next.username().is_empty());
        assert!(next.password().is_none());
        assert!(!automatic.contains_key(header::IF_RANGE));
        assert_eq!(automatic[header::RANGE], "bytes=10-");
        assert!(custom.is_empty());
    }

    #[test]
    fn parse_query_format_accepts_full_url_and_repeated_options_last_wins() {
        let parsed = parse_proxy_request(
            "",
            Some(
                "d=https%3A%2F%2Fexample.com%2Fvideo%3Fx%3D1&h=X-Test%3Afirst&h=X-Test%3Asecond&r=Content-Type%3Atext%2Fplain&r=content-type%3Avideo%2Fmp4",
            ),
        )
        .unwrap();
        assert_eq!(parsed.target.as_str(), "https://example.com/video?x=1");
        assert_eq!(parsed.request_headers["x-test"], "second");
        assert_eq!(parsed.response_headers.len(), 1);
        assert_eq!(parsed.response_headers[header::CONTENT_TYPE], "video/mp4");
    }

    #[test]
    fn parse_rejects_non_token_alias_custom_header_names() {
        for name in ["X_Test", "X.Test", "", "X-É"] {
            let header = format!("{name}: value");
            let option = urlencoding::encode(&header);
            let query = format!("d=https%3A%2F%2Fexample.com&h={option}");
            assert!(
                matches!(
                    parse_proxy_request("", Some(&query)),
                    Err(ProxyError::InvalidRequest)
                ),
                "{name:?}"
            );
        }

        let parsed = parse_proxy_request(
            "",
            Some("d=https%3A%2F%2Fexample.com&h=X-Api-Key2%3Asecret&r=Content-Type%3Atext%2Fplain"),
        )
        .unwrap();
        assert_eq!(parsed.request_headers["x-api-key2"], "secret");
        assert_eq!(parsed.response_headers[header::CONTENT_TYPE], "text/plain");
    }

    #[test]
    fn parse_rejects_routing_header_aliases_case_insensitively() {
        for name in [
            "FoRwArDeD",
            "vIa",
            "Proxy-Connection",
            "HTTP2-Settings",
            "X-FoRwArDeD-For",
            "x-ORIGINAL-Uri",
            "X-Rewrite-URL",
            "x-REAL-ip",
            "X-hOsT",
        ] {
            let header = format!("{name}: attacker.example");
            let option = urlencoding::encode(&header);
            let query = format!("d=https%3A%2F%2Fexample.com&h={option}");
            assert!(
                matches!(
                    parse_proxy_request("", Some(&query)),
                    Err(ProxyError::InvalidRequest)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn parse_allows_legitimate_initial_hop_request_headers() {
        let parsed = parse_proxy_request(
            "",
            Some(concat!(
                "d=https%3A%2F%2Fexample.com",
                "&h=Authorization%3ABearer%20secret",
                "&h=Cookie%3Asession%3Dsecret",
                "&h=Origin%3Ahttps%3A%2F%2Fapp.example",
                "&h=Referer%3Ahttps%3A%2F%2Fapp.example%2Fplayer",
                "&h=X-Api-Key%3Asecret"
            )),
        )
        .unwrap();

        assert_eq!(
            parsed.request_headers[header::AUTHORIZATION],
            "Bearer secret"
        );
        assert_eq!(parsed.request_headers[header::COOKIE], "session=secret");
        assert_eq!(
            parsed.request_headers[header::ORIGIN],
            "https://app.example"
        );
        assert_eq!(
            parsed.request_headers[header::REFERER],
            "https://app.example/player"
        );
        assert_eq!(parsed.request_headers["x-api-key"], "secret");
    }

    #[test]
    fn parse_limits_custom_response_headers_to_content_type() {
        for name in [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "X-Frame-Options",
            "Clear-Site-Data",
            "Service-Worker-Allowed",
            "Access-Control-Allow-Origin",
            "Cache-Control",
            "ETag",
            "Content-Range",
            "X-Reply",
        ] {
            let header = format!("{name}: attacker-value");
            let option = urlencoding::encode(&header);
            let query = format!("d=https%3A%2F%2Fexample.com&r={option}");
            assert!(
                matches!(
                    parse_proxy_request("", Some(&query)),
                    Err(ProxyError::InvalidRequest)
                ),
                "{name}"
            );
        }
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
    fn every_stable_error_response_has_route_owned_isolation_headers() {
        for (error, status) in [
            (ProxyError::InvalidRequest, StatusCode::BAD_REQUEST),
            (ProxyError::Blocked, StatusCode::FORBIDDEN),
            (ProxyError::Upstream, StatusCode::BAD_GATEWAY),
            (ProxyError::Cancelled, StatusCode::BAD_GATEWAY),
            (ProxyError::Capacity, StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let response = proxy_error_response(error);
            assert_eq!(response.status(), status);
            assert_response_isolated(&response);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            if error == ProxyError::Capacity {
                assert_eq!(response.headers()[header::RETRY_AFTER], "1");
            }
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

        let prefix = "/d=https%3A%2F%2Fexample.com/";
        let raw_suffix = format!("{prefix}{}", "a".repeat(MAX_PROXY_INPUT + 1 - prefix.len()));
        assert_eq!(raw_suffix.len(), MAX_PROXY_INPUT + 1);
        assert!(matches!(
            parse_proxy_suffix(&raw_suffix),
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

    async fn stalled_upstream_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        fixture(Router::new().fallback(any(|| async {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, "1")
                .body(Body::from_stream(futures_util::stream::pending::<
                    Result<bytes::Bytes, std::io::Error>,
                >()))
                .unwrap()
        })))
        .await
    }

    async fn chunk_then_stalled_upstream_fixture() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        fixture(Router::new().fallback(any(|| async {
            let stream = futures_util::stream::iter([Ok::<_, std::io::Error>(
                bytes::Bytes::from_static(b"network-chunk"),
            )])
            .chain(futures_util::stream::pending());
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from_stream(stream))
                .unwrap()
        })))
        .await
    }

    async fn proxy_router_fixture(
        runtime: Arc<ProxyRuntime>,
        with_connect_info: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = runtime_service(runtime);
        let task = if with_connect_info {
            tokio::spawn(async move {
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            })
        } else {
            tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            })
        };
        (address, task)
    }

    async fn assert_capacity_response(response: reqwest::Response) {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"
        );
        assert_eq!(
            response.text().await.unwrap(),
            "Proxy capacity is exhausted"
        );
    }

    #[tokio::test]
    async fn router_uses_actual_connect_info_and_ignores_forwarded_peers() {
        let (upstream_address, upstream) = stalled_upstream_fixture().await;
        let (runtime, _) = test_runtime(
            upstream_address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let (proxy_address, proxy) = proxy_router_fixture(Arc::new(runtime), true).await;
        let target = format!(
            "http://stalled-upstream.test:{}/resource",
            upstream_address.port()
        );
        let url = format!(
            "http://{proxy_address}/proxy/?d={}",
            urlencoding::encode(&target)
        );
        let first_peer = reqwest::Client::builder()
            .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
            .build()
            .unwrap();
        let second_peer = reqwest::Client::builder()
            .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)))
            .build()
            .unwrap();
        let mut held = Vec::new();
        for index in 0..16 {
            let response = first_peer
                .get(&url)
                .header("forwarded", format!("for=198.51.100.{}", index + 1))
                .header("x-forwarded-for", format!("203.0.113.{}", index + 1))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            held.push(response);
        }

        let exhausted = first_peer
            .get(&url)
            .header("forwarded", "for=127.0.0.3")
            .header("x-forwarded-for", "127.0.0.3")
            .send()
            .await
            .unwrap();
        assert_capacity_response(exhausted).await;

        let other = second_peer
            .get(&url)
            .header("forwarded", "for=127.0.0.2")
            .header("x-forwarded-for", "127.0.0.2")
            .send()
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);

        drop(other);
        drop(held);
        proxy.abort();
        upstream.abort();
    }

    #[tokio::test]
    async fn router_without_connect_info_uses_one_unknown_peer_bucket() {
        let (upstream_address, upstream) = stalled_upstream_fixture().await;
        let (runtime, _) = test_runtime(
            upstream_address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let (proxy_address, proxy) = proxy_router_fixture(Arc::new(runtime), false).await;
        let target = format!(
            "http://stalled-upstream.test:{}/resource",
            upstream_address.port()
        );
        let url = format!(
            "http://{proxy_address}/proxy/?d={}",
            urlencoding::encode(&target)
        );
        let client = reqwest::Client::new();
        let mut held = Vec::new();
        for _ in 0..16 {
            let response = client.get(&url).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            held.push(response);
        }

        assert_capacity_response(client.get(&url).send().await.unwrap()).await;

        drop(held);
        proxy.abort();
        upstream.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn response_header_deadline_is_absolute_and_releases_admission() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                .await
                .unwrap();
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if stream.write_all(b"a").await.is_err() {
                    break;
                }
            }
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://slow-headers.test:{}/resource", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = tokio::time::timeout(
            Duration::from_secs(31),
            handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET),
        )
        .await
        .expect("the absolute header deadline must beat a drip-fed response");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_response_isolated(&response);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            "Proxy upstream request failed"
        );
        let permits: Vec<_> = (0..16).map(|_| runtime.try_request().unwrap()).collect();
        assert!(runtime.try_request().is_err());
        drop(permits);
        fixture.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn response_header_await_helper_has_an_absolute_thirty_second_deadline() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let started = tokio::time::Instant::now();

        let result = await_response_headers(
            &cancellation,
            futures_util::future::pending::<Result<(), ()>>(),
        )
        .await;

        assert!(matches!(result, Err(ProxyError::Upstream)));
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(30)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn response_header_await_helper_accepts_completion_before_deadline() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let started = tokio::time::Instant::now();

        let result = await_response_headers(&cancellation, async {
            tokio::time::sleep(Duration::from_secs(29)).await;
            Ok::<_, ()>("headers")
        })
        .await;

        assert_eq!(result.unwrap(), "headers");
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(29)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sequential_response_header_awaits_each_receive_a_fresh_deadline() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        let started = tokio::time::Instant::now();

        for expected in ["first", "second"] {
            let result = await_response_headers(&cancellation, async move {
                tokio::time::sleep(Duration::from_secs(29)).await;
                Ok::<_, ()>(expected)
            })
            .await;
            assert_eq!(result.unwrap(), expected);
        }

        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(58)
        );
    }

    #[tokio::test]
    async fn response_headers_completing_before_deadline_proceed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://just-in-time.test:{}/resource", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;

        assert_eq!(response.status(), StatusCode::OK);
        fixture.await.unwrap();
    }

    #[tokio::test]
    async fn every_redirect_hop_gets_a_fresh_response_header_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            for response in [
                b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n"
                    .as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                stream.write_all(response).await.unwrap();
            }
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://redirect-deadline.test:{}/start", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;

        assert_eq!(response.status(), StatusCode::OK);
        fixture.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn policy_cancellation_wins_while_response_headers_are_pending() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            futures_util::future::pending::<()>().await;
        });
        let settings = ProxyPolicySettings {
            allow_private_network_sources: true,
            allow_invalid_proxy_tls_certificates: false,
        };
        let (runtime, _) = test_runtime(address, settings);
        let request = parse_proxy_request(
            "",
            Some(&format!(
                "d=http%3A%2F%2Fcancel-headers.test%3A{}%2Fresource",
                address.port()
            )),
        )
        .unwrap();
        let context = runtime.try_request().unwrap();
        let cancel = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            runtime.begin_reconfigure(ProxyPolicySettings::default());
        };
        let incoming = HeaderMap::new();

        let (result, ()) = tokio::join!(
            fetch_with_redirects(&runtime, &context, &request, Method::GET, &incoming,),
            cancel,
        );

        assert!(matches!(result, Err(ProxyError::Cancelled)));
        fixture.abort();
    }

    #[tokio::test]
    async fn active_html_and_svg_responses_receive_fixed_isolation_headers() {
        async fn active(Path(kind): Path<String>) -> Response {
            let (content_type, body) = if kind == "html" {
                (
                    "text/html",
                    "<script>top.location='https://evil.example'</script>",
                )
            } else {
                (
                    "image/svg+xml",
                    "<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>",
                )
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, content_type)
                .header("content-security-policy", "script-src *")
                .header("x-content-type-options", "unsafe")
                .header("referrer-policy", "unsafe-url")
                .header("x-frame-options", "ALLOWALL")
                .body(Body::from(body))
                .unwrap()
        }

        let (address, fixture) = fixture(Router::new().route("/{kind}", get(active))).await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );

        for (kind, expected_content_type) in [("html", "text/html"), ("svg", "image/svg+xml")] {
            let target = format!("http://active.test:{}/{kind}", address.port());
            let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
                .parse()
                .unwrap();
            let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
            assert_eq!(response.status(), StatusCode::OK, "{kind}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                expected_content_type,
                "{kind}"
            );
            assert_response_isolated(&response);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(!body.is_empty(), "{kind}");
        }
        fixture.abort();
    }

    #[tokio::test]
    async fn connect_is_rejected_before_resolver_or_upstream_work() {
        let upstream_calls = Arc::new(AtomicUsize::new(0));
        let calls = upstream_calls.clone();
        let (address, fixture) = fixture(Router::new().fallback(any(move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                "unexpected upstream request"
            }
        })))
        .await;
        let (runtime, resolver) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://connect.test:{}/", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::CONNECT).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_response_isolated(&response);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(upstream_calls.load(Ordering::SeqCst), 0);
        fixture.abort();
    }

    #[tokio::test]
    async fn upstream_switching_protocols_is_rejected_as_isolated_bad_gateway() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            assert!(read > 0);
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: fixture\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let (runtime, resolver) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://upgrade.test:{}/upgrade", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;

        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_response_isolated(&response);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            "Proxy upstream request failed"
        );
        fixture.await.unwrap();
    }

    #[tokio::test]
    async fn legitimate_custom_request_headers_reach_the_initial_hop() {
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let seen_tx = Arc::new(std::sync::Mutex::new(Some(seen_tx)));
        let (address, fixture) = fixture(Router::new().route(
            "/headers",
            get(move |headers: HeaderMap| {
                let seen_tx = seen_tx.clone();
                async move {
                    if let Some(sender) = seen_tx.lock().unwrap().take() {
                        let _ = sender.send(headers);
                    }
                    "ok"
                }
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
        let target = format!("http://headers.test:{}/headers", address.port());
        let uri: Uri = format!(
            concat!(
                "/proxy/?d={}",
                "&h=Authorization%3ABearer%20secret",
                "&h=Cookie%3Asession%3Dsecret",
                "&h=Origin%3Ahttps%3A%2F%2Fapp.example",
                "&h=Referer%3Ahttps%3A%2F%2Fapp.example%2Fplayer",
                "&h=X-Api-Key%3Asecret"
            ),
            urlencoding::encode(&target)
        )
        .parse()
        .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = seen_rx.await.unwrap();
        assert_eq!(headers[header::AUTHORIZATION], "Bearer secret");
        assert_eq!(headers[header::COOKIE], "session=secret");
        assert_eq!(headers[header::ORIGIN], "https://app.example");
        assert_eq!(headers[header::REFERER], "https://app.example/player");
        assert_eq!(headers["x-api-key"], "secret");
        fixture.abort();
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
        let fetched = fetch_with_redirects(
            &runtime,
            &context,
            &parsed,
            reqwest::Method::GET,
            &HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(fetched.response.status(), StatusCode::OK);
        assert_eq!(fetched.response.bytes().await.unwrap(), "fixture-body");
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

    #[tokio::test]
    async fn oversized_redirect_target_is_rejected_before_resolution() {
        let location = format!("https://example.com/{}", "a".repeat(16 * 1024));
        let (address, fixture) = fixture(Router::new().route(
            "/redirect",
            get(move || {
                let location = location.clone();
                async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, location)],
                    )
                }
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
            Err(ProxyError::Upstream)
        ));
        fixture.abort();
    }

    #[tokio::test]
    async fn redirect_limit_allows_five_hops_and_rejects_a_sixth() {
        async fn chain(Path((kind, hop)): Path<(String, usize)>) -> Response {
            if kind == "five" && hop == 5 {
                return "done".into_response();
            }
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, format!("/{kind}/{}", hop + 1))],
            )
                .into_response()
        }

        let (address, fixture) = fixture(Router::new().route("/{kind}/{hop}", any(chain))).await;
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
                "d=http%3A%2F%2Fredirect.test%3A{}%2Ffive%2F0",
                address.port()
            )),
        )
        .unwrap();
        let context = runtime.try_request().unwrap();
        let fetched = fetch_with_redirects(
            &runtime,
            &context,
            &parsed,
            reqwest::Method::GET,
            &HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(fetched.response.text().await.unwrap(), "done");

        let parsed = parse_proxy_request(
            "",
            Some(&format!(
                "d=http%3A%2F%2Fredirect.test%3A{}%2Fsix%2F0",
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
            Err(ProxyError::Upstream)
        ));
        fixture.abort();
    }

    #[tokio::test]
    async fn redirects_preserve_method_and_strip_cross_authority_secrets() {
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let seen_tx = Arc::new(std::sync::Mutex::new(Some(seen_tx)));
        let final_handler = {
            let seen_tx = seen_tx.clone();
            move |method: reqwest::Method, headers: HeaderMap| {
                let seen_tx = seen_tx.clone();
                async move {
                    if let Some(sender) = seen_tx.lock().unwrap().take() {
                        let _ = sender.send((method, headers));
                    }
                    "done"
                }
            }
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_location = format!("http://other.test:{}/final", address.port());
        let router = Router::new()
            .route(
                "/redirect",
                any(move || {
                    let redirect_location = redirect_location.clone();
                    async move {
                        (
                            StatusCode::SEE_OTHER,
                            [(header::LOCATION, redirect_location)],
                        )
                    }
                }),
            )
            .route("/final", any(final_handler));
        let fixture = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
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
                concat!(
                    "d=http%3A%2F%2Fuser%3Asecret%40redirect.test%3A{}%2Fredirect",
                    "&h=Authorization%3ABearer%20secret",
                    "&h=Cookie%3Asession%3Dsecret",
                    "&h=X-Api-Key%3Asecret"
                ),
                address.port()
            )),
        )
        .unwrap();
        let context = runtime.try_request().unwrap();
        let fetched = fetch_with_redirects(
            &runtime,
            &context,
            &parsed,
            reqwest::Method::POST,
            &HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(fetched.response.text().await.unwrap(), "done");
        let (method, headers) = tokio::time::timeout(Duration::from_secs(2), seen_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, reqwest::Method::POST);
        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert!(!headers.contains_key(header::COOKIE));
        assert!(!headers.contains_key("x-api-key"));
        fixture.abort();
    }

    #[tokio::test]
    async fn redirect_origin_changes_drop_if_range_and_custom_headers_but_keep_range() {
        let (cross_tx, cross_rx) = tokio::sync::oneshot::channel();
        let cross_tx = Arc::new(std::sync::Mutex::new(Some(cross_tx)));
        let (same_tx, same_rx) = tokio::sync::oneshot::channel();
        let same_tx = Arc::new(std::sync::Mutex::new(Some(same_tx)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cross_location = format!(
            "http://redirect-user:redirect-secret@other.test:{}/final-cross",
            address.port()
        );
        let router = Router::new()
            .route(
                "/redirect-cross",
                any(move || {
                    let cross_location = cross_location.clone();
                    async move {
                        (
                            StatusCode::TEMPORARY_REDIRECT,
                            [(header::LOCATION, cross_location)],
                        )
                    }
                }),
            )
            .route(
                "/final-cross",
                any(move |headers: HeaderMap| {
                    let cross_tx = cross_tx.clone();
                    async move {
                        if let Some(sender) = cross_tx.lock().unwrap().take() {
                            let _ = sender.send(headers);
                        }
                        "cross"
                    }
                }),
            )
            .route(
                "/redirect-same",
                any(|| async {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, "/final-same")],
                    )
                }),
            )
            .route(
                "/final-same",
                any(move |headers: HeaderMap| {
                    let same_tx = same_tx.clone();
                    async move {
                        if let Some(sender) = same_tx.lock().unwrap().take() {
                            let _ = sender.send(headers);
                        }
                        "same"
                    }
                }),
            );
        let fixture = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let incoming = HeaderMap::from_iter([
            (header::RANGE, "bytes=10-".parse().unwrap()),
            (header::IF_RANGE, "origin-a-validator".parse().unwrap()),
        ]);

        for path in ["redirect-cross", "redirect-same"] {
            let parsed = parse_proxy_request(
                "",
                Some(&format!(
                    concat!(
                        "d=http%3A%2F%2Fuser%3Asecret%40redirect.test%3A{}%2F{}",
                        "&h=Authorization%3ABearer%20secret",
                        "&h=X-Api-Key%3Asecret",
                        "&r=Content-Type%3Avideo%2Fmp4"
                    ),
                    address.port(),
                    path
                )),
            )
            .unwrap();
            let context = runtime.try_request().unwrap();
            let fetched =
                fetch_with_redirects(&runtime, &context, &parsed, reqwest::Method::GET, &incoming)
                    .await
                    .unwrap();
            assert_eq!(fetched.response.status(), StatusCode::OK);
            assert_eq!(
                fetched.effective_response_headers[header::CONTENT_TYPE],
                "video/mp4"
            );
            if path == "redirect-cross" {
                assert!(fetched.effective_custom_request_headers.is_empty());
                assert!(fetched.final_url.username().is_empty());
                assert!(fetched.final_url.password().is_none());
            } else {
                assert_eq!(
                    fetched.effective_custom_request_headers[header::AUTHORIZATION],
                    "Bearer secret"
                );
                assert_eq!(
                    fetched.effective_custom_request_headers["x-api-key"],
                    "secret"
                );
            }
        }

        let cross = cross_rx.await.unwrap();
        assert_eq!(cross[header::RANGE], "bytes=10-");
        assert!(!cross.contains_key(header::IF_RANGE));
        assert!(!cross.contains_key(header::AUTHORIZATION));
        assert!(!cross.contains_key("x-api-key"));

        let same = same_rx.await.unwrap();
        assert_eq!(same[header::RANGE], "bytes=10-");
        assert_eq!(same[header::IF_RANGE], "origin-a-validator");
        assert_eq!(same[header::AUTHORIZATION], "Bearer secret");
        assert_eq!(same["x-api-key"], "secret");
        fixture.abort();
    }

    #[tokio::test]
    async fn relative_redirects_resolve_from_the_current_path_and_preserve_method() {
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        let seen_tx = Arc::new(std::sync::Mutex::new(Some(seen_tx)));
        let router = Router::new()
            .route(
                "/a/b",
                any(|| async {
                    (
                        StatusCode::FOUND,
                        [(header::LOCATION, "next?from=relative")],
                    )
                }),
            )
            .route(
                "/a/next",
                any(move |method: Method, uri: Uri| {
                    let seen_tx = seen_tx.clone();
                    async move {
                        if let Some(sender) = seen_tx.lock().unwrap().take() {
                            let _ = sender.send((method, uri));
                        }
                        "correct"
                    }
                }),
            )
            .route("/next", any(|| async { "wrong-root" }));
        let (address, fixture) = fixture(router).await;
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
                "d=http%3A%2F%2Fredirect.test%3A{}%2Fa%2Fb",
                address.port()
            )),
        )
        .unwrap();
        let context = runtime.try_request().unwrap();
        let fetched = fetch_with_redirects(
            &runtime,
            &context,
            &parsed,
            reqwest::Method::POST,
            &HeaderMap::new(),
        )
        .await
        .unwrap();

        assert_eq!(fetched.final_url.path(), "/a/next");
        assert_eq!(fetched.final_url.query(), Some("from=relative"));
        assert_eq!(fetched.response.text().await.unwrap(), "correct");
        let (method, uri) = seen_rx.await.unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(
            uri.path_and_query().unwrap().as_str(),
            "/a/next?from=relative"
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn public_unmodified_response_passes_safe_cache_metadata() {
        let router = Router::new().route(
            "/asset.bin",
            get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .header(header::CACHE_CONTROL, "public, max-age=3600")
                    .header(header::CACHE_CONTROL, "stale-if-error=60")
                    .header(header::EXPIRES, "Thu, 20 Aug 2026 12:00:00 GMT")
                    .header(header::PRAGMA, "custom-extension")
                    .header(header::VARY, "Accept-Language")
                    .header(header::VARY, "Origin")
                    .body(Body::from("asset"))
                    .unwrap()
            }),
        );
        let (address, fixture) = fixture(router).await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://cache.test:{}/asset.bin", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;

        assert_eq!(
            response
                .headers()
                .get_all(header::CACHE_CONTROL)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["public, max-age=3600", "stale-if-error=60"]
        );
        assert_eq!(
            response.headers()[header::EXPIRES],
            "Thu, 20 Aug 2026 12:00:00 GMT"
        );
        assert_eq!(response.headers()[header::PRAGMA], "custom-extension");
        assert_eq!(
            response
                .headers()
                .get_all(header::VARY)
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["Accept-Language", "Origin"]
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            "asset"
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn no_transform_and_incomplete_playlist_representations_stream_unchanged() {
        async fn representation(method: Method, Path(kind): Path<String>) -> Response {
            let (status, cache_control) = match kind.trim_end_matches(".m3u8") {
                "no-transform" => (
                    StatusCode::OK,
                    "public, max-age=60, No-TrAnSfOrM, stale-if-error=30",
                ),
                "partial" => (StatusCode::PARTIAL_CONTENT, "public, max-age=60"),
                "missing" => (StatusCode::NOT_FOUND, "public, max-age=60"),
                "multiple" => (StatusCode::MULTIPLE_CHOICES, "public, max-age=60"),
                "head" => (StatusCode::OK, "public, max-age=60"),
                _ => unreachable!(),
            };
            let body = if method == Method::HEAD {
                Body::empty()
            } else {
                Body::from("#EXTM3U\nsegment.ts\n")
            };
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                .header(header::CONTENT_LENGTH, "19")
                .header(header::CONTENT_RANGE, "bytes 0-18/19")
                .header(header::CONTENT_ENCODING, "identity")
                .header(header::ETAG, "\"source-validator\"")
                .header(header::LAST_MODIFIED, "Wed, 19 Aug 2026 12:00:00 GMT")
                .header(header::ACCEPT_RANGES, "bytes")
                .header(header::CACHE_CONTROL, cache_control)
                .body(body)
                .unwrap()
        }

        let (address, fixture) = fixture(Router::new().route("/{kind}", any(representation))).await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );

        for (kind, method, status) in [
            ("no-transform", Method::GET, StatusCode::OK),
            ("partial", Method::GET, StatusCode::PARTIAL_CONTENT),
            ("missing", Method::GET, StatusCode::NOT_FOUND),
            ("multiple", Method::GET, StatusCode::MULTIPLE_CHOICES),
            ("head", Method::HEAD, StatusCode::OK),
        ] {
            let target = format!("http://media.test:{}/{kind}.m3u8", address.port());
            let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
                .parse()
                .unwrap();
            let response = handle_proxy(&runtime, uri, HeaderMap::new(), method).await;
            assert_eq!(response.status(), status, "{kind}");
            assert_eq!(response.headers()[header::CONTENT_LENGTH], "19", "{kind}");
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                "bytes 0-18/19",
                "{kind}"
            );
            assert_eq!(
                response.headers()[header::CONTENT_ENCODING],
                "identity",
                "{kind}"
            );
            assert_eq!(
                response.headers()[header::ETAG],
                "\"source-validator\"",
                "{kind}"
            );
            assert_eq!(
                response.headers()[header::LAST_MODIFIED],
                "Wed, 19 Aug 2026 12:00:00 GMT",
                "{kind}"
            );
            assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes", "{kind}");
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                if kind == "no-transform" {
                    "public, max-age=60, No-TrAnSfOrM, stale-if-error=30"
                } else {
                    "public, max-age=60"
                },
                "{kind}"
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            if kind == "head" {
                assert!(body.is_empty());
            } else {
                assert_eq!(body, "#EXTM3U\nsegment.ts\n", "{kind}");
            }
        }
        fixture.abort();
    }

    #[tokio::test]
    async fn effective_content_type_controls_rewriting_and_transformed_metadata_is_final() {
        let router = Router::new()
            .route(
                "/opaque.bin",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .header(header::CONTENT_LENGTH, "11")
                        .header(header::CONTENT_RANGE, "bytes 0-10/11")
                        .header(header::CONTENT_ENCODING, "identity")
                        .header(header::ETAG, "\"opaque-etag\"")
                        .header(header::LAST_MODIFIED, "Wed, 19 Aug 2026 12:00:00 GMT")
                        .header(header::ACCEPT_RANGES, "bytes")
                        .header(header::CACHE_CONTROL, "public, max-age=3600")
                        .body(Body::from("segment.ts\n"))
                        .unwrap()
                }),
            )
            .route(
                "/manifest.bin",
                get(|| async {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                        .header(header::ETAG, "\"manifest-etag\"")
                        .body(Body::from("segment.ts\n"))
                        .unwrap()
                }),
            );
        let (address, fixture) = fixture(router).await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );

        let opaque = format!("http://media.test:{}/opaque.bin", address.port());
        let uri: Uri = format!(
            "/proxy/?d={}&r=Content-Type%3Aapplication%2Fvnd.apple.mpegurl",
            urlencoding::encode(&opaque)
        )
        .parse()
        .unwrap();
        let transformed = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(
            transformed.headers()[header::CONTENT_TYPE],
            "application/vnd.apple.mpegurl"
        );
        for removed in [
            header::CONTENT_LENGTH,
            header::CONTENT_RANGE,
            header::CONTENT_ENCODING,
            header::ETAG,
            header::LAST_MODIFIED,
        ] {
            assert!(!transformed.headers().contains_key(removed));
        }
        assert_eq!(transformed.headers()[header::ACCEPT_RANGES], "none");
        assert_eq!(
            transformed.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let transformed_body = axum::body::to_bytes(transformed.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&transformed_body).contains("/proxy/?d="));

        let manifest = format!("http://media.test:{}/manifest.bin", address.port());
        let uri: Uri = format!(
            "/proxy/?d={}&r=Content-Type%3Atext%2Fplain",
            urlencoding::encode(&manifest)
        )
        .parse()
        .unwrap();
        let raw = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(raw.headers()[header::CONTENT_TYPE], "text/plain");
        assert_eq!(raw.headers()[header::ETAG], "\"manifest-etag\"");
        assert_eq!(
            axum::body::to_bytes(raw.into_body(), usize::MAX)
                .await
                .unwrap(),
            "segment.ts\n"
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn request_credentials_force_no_store_even_after_redirect_clearing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_location = format!("http://other.test:{}/asset.bin", address.port());
        let router = Router::new()
            .route(
                "/redirect",
                get(move || {
                    let redirect_location = redirect_location.clone();
                    async move {
                        (
                            StatusCode::TEMPORARY_REDIRECT,
                            [(header::LOCATION, redirect_location)],
                        )
                    }
                }),
            )
            .route(
                "/asset.bin",
                get(|| async {
                    Response::builder()
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .header(header::CACHE_CONTROL, "public, max-age=3600")
                        .body(Body::from("asset"))
                        .unwrap()
                }),
            );
        let fixture = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );

        for query in [
            format!(
                "d={}",
                urlencoding::encode(&format!(
                    "http://user:secret@cache.test:{}/asset.bin",
                    address.port()
                ))
            ),
            format!(
                "d={}&h=X-Api-Key%3Asecret",
                urlencoding::encode(&format!("http://cache.test:{}/asset.bin", address.port()))
            ),
            format!(
                "d={}&h=X-Api-Key%3Asecret",
                urlencoding::encode(&format!("http://redirect.test:{}/redirect", address.port()))
            ),
        ] {
            let uri: Uri = format!("/proxy/?{query}").parse().unwrap();
            let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
        }
        fixture.abort();
    }

    #[tokio::test]
    async fn credential_bearing_upstream_and_rewrite_errors_are_no_store() {
        let (unreachable_runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let uri: Uri = "/proxy/?d=http%3A%2F%2Funreachable.test%3A1%2Fasset&h=X-Api-Key%3Asecret"
            .parse()
            .unwrap();
        let upstream_error =
            handle_proxy(&unreachable_runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(upstream_error.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            upstream_error.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_response_isolated(&upstream_error);

        let (address, fixture) = fixture(Router::new().route(
            "/invalid.m3u8",
            get(|| async {
                Response::builder()
                    .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                    .body(Body::from(bytes::Bytes::from_static(b"#EXTM3U\n\xff\n")))
                    .unwrap()
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
        let target = format!("http://playlist.test:{}/invalid.m3u8", address.port());
        let uri: Uri = format!(
            "/proxy/?d={}&h=X-Api-Key%3Asecret",
            urlencoding::encode(&target)
        )
        .parse()
        .unwrap();
        let rewrite_error = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(rewrite_error.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            rewrite_error.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_response_isolated(&rewrite_error);
        fixture.abort();
    }

    #[tokio::test]
    async fn playlist_content_encoding_requires_only_identity_in_every_field_and_coding() {
        async fn encoded(Path(kind): Path<String>) -> Response {
            let mut response = Response::new(Body::from("#EXTM3U\nsegment.ts\n"));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/vnd.apple.mpegurl"),
            );
            match kind.trim_end_matches(".m3u8") {
                "separate-gzip" => {
                    response.headers_mut().append(
                        header::CONTENT_ENCODING,
                        HeaderValue::from_static("identity"),
                    );
                    response
                        .headers_mut()
                        .append(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
                }
                "mixed-list" => {
                    response.headers_mut().insert(
                        header::CONTENT_ENCODING,
                        HeaderValue::from_static("identity, gzip"),
                    );
                }
                "repeated-identity" => {
                    response.headers_mut().append(
                        header::CONTENT_ENCODING,
                        HeaderValue::from_static("identity"),
                    );
                    response.headers_mut().append(
                        header::CONTENT_ENCODING,
                        HeaderValue::from_static("IDENTITY"),
                    );
                }
                "identity-list" => {
                    response.headers_mut().insert(
                        header::CONTENT_ENCODING,
                        HeaderValue::from_static(" identity ,\tIDENTITY "),
                    );
                }
                "non-ascii" => {
                    response.headers_mut().insert(
                        header::CONTENT_ENCODING,
                        HeaderValue::from_bytes(b"identity, \x80").unwrap(),
                    );
                }
                _ => unreachable!(),
            }
            response
        }

        let (address, fixture) = fixture(Router::new().route("/{kind}", get(encoded))).await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        for (kind, expected) in [
            ("separate-gzip", StatusCode::BAD_GATEWAY),
            ("mixed-list", StatusCode::BAD_GATEWAY),
            ("repeated-identity", StatusCode::OK),
            ("identity-list", StatusCode::OK),
            ("non-ascii", StatusCode::BAD_GATEWAY),
        ] {
            let target = format!("http://encoding.test:{}/{kind}.m3u8", address.port());
            let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
                .parse()
                .unwrap();
            let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
            assert_eq!(response.status(), expected, "{kind}");
            if expected == StatusCode::OK {
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert!(
                    String::from_utf8_lossy(&body).contains("/proxy/?d="),
                    "{kind}"
                );
            } else {
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    "private, no-store",
                    "{kind}"
                );
            }
        }
        fixture.abort();
    }

    #[tokio::test]
    async fn playlist_semantic_headers_are_byte_safe_and_quote_aware() {
        async fn semantic_headers(Path(kind): Path<String>) -> Response {
            let mut response = Response::new(Body::from("#EXTM3U\nsegment.ts\n"));
            response
                .headers_mut()
                .insert(header::ETAG, HeaderValue::from_static("\"source\""));
            match kind.trim_end_matches(".bin") {
                "actual-no-transform" => {
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/vnd.apple.mpegurl"),
                    );
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_bytes(b"extension=\"\x80\", no-transform").unwrap(),
                    );
                }
                "quoted-no-transform" => {
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/vnd.apple.mpegurl"),
                    );
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("extension=\"no-transform\""),
                    );
                }
                "invalid-cache-control" => {
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/vnd.apple.mpegurl"),
                    );
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("extension=\"unterminated"),
                    );
                }
                "obs-content-type" => {
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_bytes(
                            b"application/vnd.apple.mpegurl; extension=\"\x80\"",
                        )
                        .unwrap(),
                    );
                }
                "invalid-content-type" => {
                    response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application /vnd.apple.mpegurl"),
                    );
                }
                _ => unreachable!(),
            }
            response
        }

        let (address, fixture) =
            fixture(Router::new().route("/{kind}", get(semantic_headers))).await;
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        for (kind, rewritten) in [
            ("actual-no-transform", false),
            ("quoted-no-transform", true),
            ("invalid-cache-control", false),
            ("obs-content-type", true),
            ("invalid-content-type", false),
        ] {
            let target = format!("http://semantic.test:{}/{kind}.bin", address.port());
            let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
                .parse()
                .unwrap();
            let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
            assert_eq!(response.status(), StatusCode::OK, "{kind}");
            if rewritten {
                assert!(!response.headers().contains_key(header::ETAG), "{kind}");
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                assert!(
                    String::from_utf8_lossy(&body).contains("/proxy/?d="),
                    "{kind}"
                );
            } else {
                assert_eq!(response.headers()[header::ETAG], "\"source\"", "{kind}");
                assert_eq!(
                    axum::body::to_bytes(response.into_body(), usize::MAX)
                        .await
                        .unwrap(),
                    "#EXTM3U\nsegment.ts\n",
                    "{kind}"
                );
            }
        }
        fixture.abort();
    }

    #[tokio::test]
    async fn buffered_playlist_body_retains_capacity_and_observes_cancellation() {
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let cancellation = context.cancellation.clone();
        let lease = context.into_producer_lease();
        let body = buffered_proxy_body(bytes::Bytes::from_static(b"#EXTM3U\nsegment.ts\n"), lease);
        assert_eq!(runtime.capacity_snapshot(), (1, 1));
        cancellation.cancel();
        assert!(axum::body::to_bytes(body, usize::MAX).await.is_err());
        wait_for_capacity(&runtime, (0, 0)).await;
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    async fn wait_until(mut ready: impl FnMut() -> bool) {
        for _ in 0..64 {
            if ready() {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            ready(),
            "condition did not become ready after bounded yields"
        );
    }

    async fn wait_for_capacity(runtime: &ProxyRuntime, expected: (usize, usize)) {
        wait_until(|| runtime.capacity_snapshot() == expected).await;
    }

    fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
        let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
        future.as_mut().poll(&mut context)
    }

    async fn assert_body_error_then_eof(body: Body) {
        let mut stream = body.into_data_stream();
        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
    }

    enum TestStreamStep {
        Chunk(bytes::Bytes),
        Error,
        Pending,
        Panic,
        PanicWithPayload(Arc<AtomicUsize>),
    }

    struct TestByteStream {
        steps: VecDeque<TestStreamStep>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl TestByteStream {
        fn new(
            steps: impl IntoIterator<Item = TestStreamStep>,
        ) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    steps: steps.into_iter().collect(),
                    polls: polls.clone(),
                    drops: drops.clone(),
                },
                polls,
                drops,
            )
        }
    }

    impl futures_util::Stream for TestByteStream {
        type Item = Result<bytes::Bytes, ProxySourceError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            match self.steps.front() {
                Some(TestStreamStep::Pending) => Poll::Pending,
                Some(TestStreamStep::Error) => {
                    self.steps.pop_front();
                    Poll::Ready(Some(Err(ProxySourceError)))
                }
                Some(TestStreamStep::Panic) => {
                    self.steps.pop_front();
                    panic!("controlled proxy producer panic");
                }
                Some(TestStreamStep::PanicWithPayload(_)) => {
                    let Some(TestStreamStep::PanicWithPayload(drops)) = self.steps.pop_front()
                    else {
                        unreachable!()
                    };
                    std::panic::panic_any(TrackedPanicPayload { drops });
                }
                Some(TestStreamStep::Chunk(_)) => {
                    let Some(TestStreamStep::Chunk(bytes)) = self.steps.pop_front() else {
                        unreachable!()
                    };
                    Poll::Ready(Some(Ok(bytes)))
                }
                None => Poll::Ready(None),
            }
        }
    }

    impl Drop for TestByteStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TrackedBytesOwner {
        bytes: Vec<u8>,
        drops: Arc<AtomicUsize>,
    }

    impl AsRef<[u8]> for TrackedBytesOwner {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for TrackedBytesOwner {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TrackedPanicPayload {
        drops: Arc<AtomicUsize>,
    }

    impl Drop for TrackedPanicPayload {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PanicOnDropAfterEofStream {
        returned_eof: bool,
        payload_drops: Arc<AtomicUsize>,
    }

    impl futures_util::Stream for PanicOnDropAfterEofStream {
        type Item = Result<bytes::Bytes, ProxySourceError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.returned_eof = true;
            Poll::Ready(None)
        }
    }

    impl Drop for PanicOnDropAfterEofStream {
        fn drop(&mut self) {
            if self.returned_eof {
                std::panic::panic_any(TrackedPanicPayload {
                    drops: self.payload_drops.clone(),
                });
            }
        }
    }

    struct PanicOnDropPendingStream {
        polled: Arc<AtomicUsize>,
        payload_drops: Arc<AtomicUsize>,
    }

    impl futures_util::Stream for PanicOnDropPendingStream {
        type Item = Result<bytes::Bytes, ProxySourceError>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.polled.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    impl Drop for PanicOnDropPendingStream {
        fn drop(&mut self) {
            std::panic::panic_any(TrackedPanicPayload {
                drops: self.payload_drops.clone(),
            });
        }
    }

    struct ReadyEmptyStream {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl futures_util::Stream for ReadyEmptyStream {
        type Item = Result<bytes::Bytes, ProxySourceError>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(bytes::Bytes::new())))
        }
    }

    impl Drop for ReadyEmptyStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct CancelThenEofStream {
        cancellation: tokio_util::sync::CancellationToken,
    }

    impl futures_util::Stream for CancelThenEofStream {
        type Item = Result<bytes::Bytes, ProxySourceError>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.cancellation.cancel();
            Poll::Ready(None)
        }
    }

    struct OneThenPendingStream {
        chunk: Option<bytes::Bytes>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl futures_util::Stream for OneThenPendingStream {
        type Item = Result<bytes::Bytes, ProxySourceError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            self.chunk
                .take()
                .map_or(Poll::Pending, |chunk| Poll::Ready(Some(Ok(chunk))))
        }
    }

    impl Drop for OneThenPendingStream {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn request_probes_are_runtime_isolated_and_mark_only_a_full_handoff() {
        let (pending_runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let (full_runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let pending_probe = pending_runtime.probe_next_request_producer();
        let full_probe = full_runtime.probe_next_request_producer();
        let (pending_stream, pending_polls, _) = TestByteStream::new([TestStreamStep::Pending]);
        let pending_body = streaming_proxy_body(
            Box::pin(pending_stream),
            pending_runtime.try_request().unwrap().into_producer_lease(),
        );
        let (full_stream, _, _) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"full")),
            TestStreamStep::Pending,
        ]);
        let full_body = streaming_proxy_body(
            Box::pin(full_stream),
            full_runtime.try_request().unwrap().into_producer_lease(),
        );

        full_probe.wait_for_full_deadline_armed().await.unwrap();
        wait_until(|| pending_polls.load(Ordering::SeqCst) == 1).await;
        assert!(!pending_probe.is_full_deadline_armed());

        drop(pending_body);
        drop(full_body);
        assert!(pending_probe.wait_for_full_deadline_armed().await.is_err());
        wait_for_capacity(&pending_runtime, (0, 0)).await;
        wait_for_capacity(&full_runtime, (0, 0)).await;
    }

    #[tokio::test]
    async fn pending_probe_reports_cancellation_instead_of_stranding_its_waiter() {
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let producer_probe = runtime.probe_next_request_producer();
        let context = runtime.try_request().unwrap();
        let cancellation = context.cancellation.clone();
        let (stream, polls, _) = TestByteStream::new([TestStreamStep::Pending]);
        let body = streaming_proxy_body(Box::pin(stream), context.into_producer_lease());
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        cancellation.cancel();

        assert!(producer_probe.wait_for_full_deadline_armed().await.is_err());
        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
    }

    #[tokio::test]
    async fn waiting_consumer_stays_pending_until_the_full_deadline_is_armed() {
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let producer_probe = runtime.probe_next_request_producer();
        let lease = runtime.try_request().unwrap().into_producer_lease();
        let handoff = Arc::new(
            ProxyHandoff::new(lease.cancellation().clone())
                .with_producer_probe(lease.producer_probe()),
        );
        assert!(handoff.reserve().await.is_ok());
        let deadline = tokio::time::Instant::now() + DOWNSTREAM_NO_PROGRESS_DEADLINE;
        let mut consumer = Box::pin(handoff.take());
        assert!(poll_once(consumer.as_mut()).is_pending());
        assert!(
            handoff
                .publish(bytes::Bytes::from_static(b"published"), deadline)
                .is_ok()
        );
        assert!(poll_once(consumer.as_mut()).is_pending());

        let mut producer = Box::pin(handoff.wait_until_consumed(deadline));
        assert!(poll_once(producer.as_mut()).is_pending());
        assert!(producer_probe.is_full_deadline_armed());
        match poll_once(consumer.as_mut()) {
            Poll::Ready(ProxyConsumerItem::Chunk(bytes)) => assert_eq!(bytes, "published"),
            Poll::Pending => panic!("consumer stayed pending after deadline readiness"),
            Poll::Ready(ProxyConsumerItem::Failed | ProxyConsumerItem::Eof) => {
                panic!("consumer did not receive the published chunk")
            }
        }
        assert!(matches!(poll_once(producer.as_mut()), Poll::Ready(Ok(()))));

        drop(lease);
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn first_consumer_poll_after_full_waits_for_armed_deadline() {
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let producer_probe = runtime.probe_next_request_producer();
        let lease = runtime.try_request().unwrap().into_producer_lease();
        let handoff = Arc::new(
            ProxyHandoff::new(lease.cancellation().clone())
                .with_producer_probe(lease.producer_probe()),
        );
        assert!(handoff.reserve().await.is_ok());
        let deadline = tokio::time::Instant::now() + DOWNSTREAM_NO_PROGRESS_DEADLINE;
        assert!(
            handoff
                .publish(bytes::Bytes::from_static(b"published"), deadline)
                .is_ok()
        );

        let mut consumer = Box::pin(handoff.take());
        assert!(poll_once(consumer.as_mut()).is_pending());
        assert!(matches!(
            handoff.lock_state().slot,
            ProxyHandoffSlot::Full { .. }
        ));

        let mut producer = Box::pin(handoff.wait_until_consumed(deadline));
        assert!(poll_once(producer.as_mut()).is_pending());
        assert!(producer_probe.is_full_deadline_armed());
        match poll_once(consumer.as_mut()) {
            Poll::Ready(ProxyConsumerItem::Chunk(bytes)) => assert_eq!(bytes, "published"),
            Poll::Pending => panic!("consumer stayed pending after deadline readiness"),
            Poll::Ready(ProxyConsumerItem::Failed | ProxyConsumerItem::Eof) => {
                panic!("consumer did not receive the published chunk")
            }
        }
        assert!(matches!(poll_once(producer.as_mut()), Poll::Ready(Ok(()))));

        drop(lease);
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn timely_take_wins_when_producer_observes_notify_after_deadline() {
        let handoff = ProxyHandoff::new(CancellationToken::new());
        assert!(handoff.reserve().await.is_ok());
        let deadline = tokio::time::Instant::now() + DOWNSTREAM_NO_PROGRESS_DEADLINE;
        assert!(
            handoff
                .publish(bytes::Bytes::from_static(b"timely"), deadline)
                .is_ok()
        );
        let mut producer = Box::pin(handoff.wait_until_consumed(deadline));
        assert!(poll_once(producer.as_mut()).is_pending());

        tokio::time::advance(Duration::from_secs(119)).await;
        match handoff.take().await {
            ProxyConsumerItem::Chunk(bytes) => assert_eq!(bytes, "timely"),
            ProxyConsumerItem::Failed | ProxyConsumerItem::Eof => {
                panic!("timely consumer did not receive the published chunk")
            }
        }
        tokio::time::advance(Duration::from_secs(2)).await;

        assert!(matches!(poll_once(producer.as_mut()), Poll::Ready(Ok(()))));
    }

    #[tokio::test(start_paused = true)]
    async fn late_take_fails_without_delivering_expired_chunk() {
        let handoff = ProxyHandoff::new(CancellationToken::new());
        assert!(handoff.reserve().await.is_ok());
        let deadline = tokio::time::Instant::now() + DOWNSTREAM_NO_PROGRESS_DEADLINE;
        assert!(
            handoff
                .publish(bytes::Bytes::from_static(b"expired"), deadline)
                .is_ok()
        );
        let mut producer = Box::pin(handoff.wait_until_consumed(deadline));
        assert!(poll_once(producer.as_mut()).is_pending());

        tokio::time::advance(Duration::from_secs(121)).await;

        assert!(matches!(handoff.take().await, ProxyConsumerItem::Failed));
        assert!(matches!(handoff.take().await, ProxyConsumerItem::Eof));
        assert!(matches!(
            poll_once(producer.as_mut()),
            Poll::Ready(Err(ProxyProducerStop::Failed))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn unpolled_body_reads_one_chunk_then_stall_reclaims_capacity() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let payload_drops = Arc::new(AtomicUsize::new(0));
        let stream = OneThenPendingStream {
            chunk: Some(bytes::Bytes::from_owner(TrackedBytesOwner {
                bytes: b"queued".to_vec(),
                drops: payload_drops.clone(),
            })),
            polls: polls.clone(),
            drops: drops.clone(),
        };
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let (body, producer) = spawn_proxy_body(
            ProxyBodySource::Streaming(Box::pin(stream)),
            context.into_producer_lease(),
        );

        for _ in 0..16 {
            if polls.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.capacity_snapshot(), (1, 1));

        tokio::time::advance(Duration::from_secs(121)).await;
        for _ in 0..16 {
            if runtime.capacity_snapshot() == (0, 0) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
        wait_until(|| producer.is_finished()).await;
        assert!(producer.is_finished());

        let mut body = body.into_data_stream();
        assert!(body.next().await.unwrap().is_err());
        assert!(body.next().await.is_none());
    }

    #[tokio::test]
    async fn dropping_full_handoff_clears_payload_and_stops_before_a_second_poll() {
        let (stream, polls, drops) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"queued")),
            TestStreamStep::Pending,
        ]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        drop(body);

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_body_while_upstream_read_is_pending_reclaims_without_a_timer() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Pending]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        drop(body);

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_while_handoff_is_full_discards_data_then_errors_once() {
        let (stream, polls, drops) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"must-not-escape")),
            TestStreamStep::Pending,
        ]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let cancellation = context.cancellation.clone();
        let body = streaming_proxy_body(Box::pin(stream), context.into_producer_lease());
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        cancellation.cancel();

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_while_upstream_read_is_pending_errors_and_reclaims_immediately() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Pending]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let cancellation = context.cancellation.clone();
        let body = streaming_proxy_body(Box::pin(stream), context.into_producer_lease());
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        cancellation.cancel();

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_triggered_by_the_eof_poll_wins_over_clean_eof() {
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let stream = CancelThenEofStream {
            cancellation: context.cancellation.clone(),
        };
        let body = streaming_proxy_body(Box::pin(stream), context.into_producer_lease());

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn pending_upstream_read_times_out_with_one_error_then_eof() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Pending]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_body_error_then_eof(body).await;

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
    }

    #[tokio::test]
    async fn upstream_source_error_yields_one_generic_error_then_eof() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Error]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );

        assert_body_error_then_eof(body).await;

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn clean_finite_stream_preserves_content_order_and_reclaims_everything() {
        let (stream, polls, drops) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"first-")),
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"second")),
        ]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );

        assert_eq!(
            axum::body::to_bytes(body, usize::MAX).await.unwrap(),
            "first-second"
        );

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn producer_panic_wakes_retained_body_and_fails_closed() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Panic]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let (body, producer) = spawn_proxy_body(
            ProxyBodySource::Streaming(Box::pin(stream)),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        wait_until(|| producer.is_finished()).await;

        assert_body_error_then_eof(body).await;

        wait_for_capacity(&runtime, (0, 0)).await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn producer_panic_payload_is_dropped_while_body_remains_retained() {
        let payload_drops = Arc::new(AtomicUsize::new(0));
        let (stream, _, source_drops) =
            TestByteStream::new([TestStreamStep::PanicWithPayload(payload_drops.clone())]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );

        wait_until(|| source_drops.load(Ordering::SeqCst) == 1).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
        assert_body_error_then_eof(body).await;
    }

    #[tokio::test]
    async fn source_drop_panic_after_eof_overrides_clean_terminal_state() {
        let payload_drops = Arc::new(AtomicUsize::new(0));
        let stream = PanicOnDropAfterEofStream {
            returned_eof: false,
            payload_drops: payload_drops.clone(),
        };
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn explicit_producer_abort_wakes_retained_body_and_fails_closed() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Pending]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let (body, abort) = spawn_proxy_body(
            ProxyBodySource::Streaming(Box::pin(stream)),
            context.into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        abort.abort();
        wait_until(|| abort.is_finished()).await;
        assert!(abort.is_finished());

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
    }

    #[tokio::test]
    async fn explicit_abort_drops_a_panicking_source_without_retaining_its_payload() {
        let polls = Arc::new(AtomicUsize::new(0));
        let payload_drops = Arc::new(AtomicUsize::new(0));
        let stream = PanicOnDropPendingStream {
            polled: polls.clone(),
            payload_drops: payload_drops.clone(),
        };
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let (body, abort) = spawn_proxy_body(
            ProxyBodySource::Streaming(Box::pin(stream)),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        abort.abort();

        wait_for_capacity(&runtime, (0, 0)).await;
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
        assert_body_error_then_eof(body).await;
    }

    #[tokio::test]
    async fn abort_before_first_producer_poll_still_fails_closed_and_reclaims() {
        let (stream, polls, drops) = TestByteStream::new([TestStreamStep::Pending]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let (body, abort) = spawn_proxy_body(
            ProxyBodySource::Streaming(Box::pin(stream)),
            context.into_producer_lease(),
        );

        abort.abort();

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_progress_resets_each_downstream_deadline_without_a_total_limit() {
        let (stream, polls, drops) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"one")),
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"two")),
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"three")),
        ]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        let mut body = body.into_data_stream();
        let started = tokio::time::Instant::now();

        for (index, expected) in [b"one".as_slice(), b"two", b"three"]
            .into_iter()
            .enumerate()
        {
            wait_until(|| polls.load(Ordering::SeqCst) > index).await;
            tokio::time::advance(Duration::from_secs(119)).await;
            assert_eq!(body.next().await.unwrap().unwrap(), expected);
        }
        assert!(body.next().await.is_none());

        assert!(tokio::time::Instant::now().duration_since(started) > Duration::from_secs(350));
        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(polls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn buffered_large_source_crosses_as_independent_bounded_chunks() {
        let owner_drops = Arc::new(AtomicUsize::new(0));
        let source = bytes::Bytes::from_owner(TrackedBytesOwner {
            bytes: (0..PROXY_BODY_CHUNK_SIZE + 17)
                .map(|index| (index % 251) as u8)
                .collect(),
            drops: owner_drops.clone(),
        });
        let expected = source.to_vec();
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body =
            buffered_proxy_body(source, runtime.try_request().unwrap().into_producer_lease());
        let mut stream = body.into_data_stream();
        let mut retained_chunks = Vec::new();
        let mut actual = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            assert!(!chunk.is_empty());
            assert!(chunk.len() <= PROXY_BODY_CHUNK_SIZE);
            actual.extend_from_slice(&chunk);
            retained_chunks.push(chunk);
        }

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| owner_drops.load(Ordering::SeqCst) == 1).await;
        assert_eq!(retained_chunks.len(), 2);
        assert_eq!(actual, expected);
        assert_eq!(owner_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_unpolled_buffered_body_reclaims_its_source_and_permit() {
        let owner_drops = Arc::new(AtomicUsize::new(0));
        let source = bytes::Bytes::from_owner(TrackedBytesOwner {
            bytes: vec![b'x'; PROXY_BODY_CHUNK_SIZE + 1],
            drops: owner_drops.clone(),
        });
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body =
            buffered_proxy_body(source, runtime.try_request().unwrap().into_producer_lease());
        tokio::task::yield_now().await;
        assert_eq!(runtime.capacity_snapshot(), (1, 1));
        assert_eq!(owner_drops.load(Ordering::SeqCst), 0);

        drop(body);

        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| owner_drops.load(Ordering::SeqCst) == 1).await;
    }

    #[tokio::test(start_paused = true)]
    async fn empty_chunks_do_not_reset_the_persistent_upstream_idle_deadline() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
        let polls = Arc::new(AtomicUsize::new(0));
        let stream_polls = polls.clone();
        let stream = futures_util::stream::poll_fn(move |context| {
            stream_polls.fetch_add(1, Ordering::SeqCst);
            receiver
                .poll_recv(context)
                .map(|item| item.map(Ok::<_, ProxySourceError>))
        });
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) >= 1).await;

        tokio::time::advance(Duration::from_secs(29)).await;
        sender.send(bytes::Bytes::new()).unwrap();
        wait_until(|| polls.load(Ordering::SeqCst) >= 2).await;
        tokio::time::advance(Duration::from_secs(2)).await;

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn always_ready_empty_chunks_cannot_starve_the_read_idle_deadline() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let stream = ReadyEmptyStream {
            polls: polls.clone(),
            drops: drops.clone(),
        };
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        wait_until(|| polls.load(Ordering::SeqCst) >= 2).await;

        tokio::time::advance(Duration::from_secs(31)).await;

        assert_body_error_then_eof(body).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
    }

    #[tokio::test(start_paused = true)]
    async fn retained_stalled_body_releases_same_peer_capacity_for_re_admission() {
        let (stream, polls, drops) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"held")),
            TestStreamStep::Pending,
        ]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime.try_request().unwrap().into_producer_lease(),
        );
        let blockers: Vec<_> = (0..15).map(|_| runtime.try_request().unwrap()).collect();
        assert!(runtime.try_request().is_err());
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        tokio::time::advance(Duration::from_secs(121)).await;
        wait_for_capacity(&runtime, (15, 1)).await;
        let replacement = runtime.try_request().unwrap();

        assert_body_error_then_eof(body).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        drop(replacement);
        drop(blockers);
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn retained_stalled_body_releases_global_capacity_for_re_admission() {
        let (stream, polls, drops) = TestByteStream::new([
            TestStreamStep::Chunk(bytes::Bytes::from_static(b"held")),
            TestStreamStep::Pending,
        ]);
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let body = streaming_proxy_body(
            Box::pin(stream),
            runtime
                .try_request_for_peer(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))))
                .unwrap()
                .into_producer_lease(),
        );
        let blockers: Vec<_> = (2..=64u16)
            .map(|index| {
                runtime
                    .try_request_for_peer(Some(IpAddr::V6(Ipv6Addr::from(u128::from(index)))))
                    .unwrap()
            })
            .collect();
        assert!(
            runtime
                .try_request_for_peer(Some(IpAddr::V6(Ipv6Addr::from(65u128))))
                .is_err()
        );
        wait_until(|| polls.load(Ordering::SeqCst) == 1).await;

        tokio::time::advance(Duration::from_secs(121)).await;
        wait_for_capacity(&runtime, (63, 63)).await;
        let replacement = runtime
            .try_request_for_peer(Some(IpAddr::V6(Ipv6Addr::from(65u128))))
            .unwrap();

        assert_body_error_then_eof(body).await;
        wait_until(|| drops.load(Ordering::SeqCst) == 1).await;
        drop(replacement);
        drop(blockers);
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn retained_real_axum_handler_response_reclaims_its_producer() {
        let (upstream_address, upstream) = chunk_then_stalled_upstream_fixture().await;
        let (runtime, _) = test_runtime(
            upstream_address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://fixture.test:{}/body", upstream_address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();
        let producer_probe = runtime.probe_next_request_producer();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        producer_probe.wait_for_full_deadline_armed().await.unwrap();
        tokio::time::pause();

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(runtime.capacity_snapshot(), (1, 1));
        tokio::time::advance(Duration::from_secs(90)).await;
        wait_for_capacity(&runtime, (0, 0)).await;
        assert_body_error_then_eof(response.into_body()).await;
        upstream.abort();
    }

    #[tokio::test]
    async fn retained_real_axum_service_response_reclaims_its_producer() {
        let (upstream_address, upstream) = chunk_then_stalled_upstream_fixture().await;
        let (runtime, _) = test_runtime(
            upstream_address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let runtime = Arc::new(runtime);
        let (proxy_address, proxy) = proxy_router_fixture(runtime.clone(), true).await;
        let target = format!(
            "http://stalled-upstream.test:{}/resource",
            upstream_address.port()
        );
        let url = format!(
            "http://{proxy_address}/proxy/?d={}",
            urlencoding::encode(&target)
        );
        let producer_probe = runtime.probe_next_request_producer();

        let response = reqwest::Client::new().get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(runtime.capacity_snapshot(), (1, 1));
        producer_probe.wait_for_full_deadline_armed().await.unwrap();
        tokio::time::pause();

        tokio::time::advance(Duration::from_secs(121)).await;
        wait_for_capacity(&runtime, (0, 0)).await;

        drop(response);
        proxy.abort();
        upstream.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn streaming_body_times_out_once_and_releases_capacity() {
        let stream = futures_util::stream::pending::<Result<bytes::Bytes, ProxySourceError>>();
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let body = streaming_proxy_body(Box::pin(stream), context.into_producer_lease());
        let collect = tokio::spawn(axum::body::to_bytes(body, usize::MAX));
        tokio::task::yield_now().await;
        assert_eq!(runtime.capacity_snapshot(), (1, 1));
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(collect.await.unwrap().is_err());
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn dropping_streaming_body_releases_capacity() {
        let stream = futures_util::stream::pending::<Result<bytes::Bytes, ProxySourceError>>();
        let (runtime, _) = test_runtime(
            "127.0.0.1:1".parse().unwrap(),
            ProxyPolicySettings::default(),
        );
        let context = runtime.try_request().unwrap();
        let body = streaming_proxy_body(Box::pin(stream), context.into_producer_lease());
        assert_eq!(runtime.capacity_snapshot(), (1, 1));
        drop(body);
        for _ in 0..16 {
            if runtime.capacity_snapshot() == (0, 0) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.capacity_snapshot(), (0, 0));
    }

    #[tokio::test]
    async fn playlist_collection_accepts_exact_limit_and_rejects_streamed_overflow() {
        let exact = bytes::Bytes::from(vec![b'a'; MAX_PLAYLIST_INPUT]);
        let overflow_tail = bytes::Bytes::from_static(b"x");
        let (address, fixture) = fixture(
            Router::new()
                .route(
                    "/exact",
                    get({
                        let exact = exact.clone();
                        move || {
                            let exact = exact.clone();
                            async move {
                                Body::from_stream(futures_util::stream::once(async move {
                                    Ok::<_, std::io::Error>(exact)
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/overflow",
                    get(move || {
                        let exact = exact.clone();
                        let overflow_tail = overflow_tail.clone();
                        async move {
                            Body::from_stream(futures_util::stream::iter([
                                Ok::<_, std::io::Error>(exact),
                                Ok::<_, std::io::Error>(overflow_tail),
                            ]))
                        }
                    }),
                ),
        )
        .await;
        let client = reqwest::Client::new();
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );

        let context = runtime.try_request().unwrap();
        let response = client
            .get(format!("http://{address}/exact"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            collect_playlist(response, &context).await.unwrap().len(),
            MAX_PLAYLIST_INPUT
        );
        drop(context);

        let context = runtime.try_request().unwrap();
        let response = client
            .get(format!("http://{address}/overflow"))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            collect_playlist(response, &context).await,
            Err(ProxyError::Upstream)
        ));
        fixture.abort();
    }

    #[test]
    fn playlist_rewriter_preserves_non_http_and_malformed_references() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let body = concat!(
            "#EXTM3U\r\n",
            "\r\n",
            "# an unrelated comment\n",
            "data:text/plain,segment\n",
            "skd://license.example/key\r\n",
            "urn:example:asset\n",
            "http://[invalid\n",
            "//[invalid\r\n",
            "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"data:text/plain,key\"\r\n",
            "#EXT-X-MAP:URI=\"init.mp4\"\n",
            "segment.ts\n",
        );

        let rewritten = rewrite_playlist_bounded(body, &base).unwrap();

        assert!(rewritten.starts_with(concat!(
            "#EXTM3U\r\n",
            "\r\n",
            "# an unrelated comment\n",
            "data:text/plain,segment\n",
            "skd://license.example/key\r\n",
            "urn:example:asset\n",
            "http://[invalid\n",
            "//[invalid\r\n",
            "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"data:text/plain,key\"\r\n",
        )));
        assert_eq!(rewritten.matches("/proxy/?d=").count(), 2);
        assert!(rewritten.ends_with('\n'));
    }

    #[test]
    fn playlist_rewriter_preserves_space_and_tab_only_lines_byte_for_byte() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let body = " \r\n\t\n \t\r\n\t ";

        let rewritten = rewrite_playlist_bounded(body, &base).unwrap();

        assert_eq!(rewritten, body);
    }

    #[test]
    fn playlist_rewriter_keeps_valid_variables_visible_in_lines_and_attributes() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let body = concat!(
            "segments/{$segment}/part.ts?token={$token}\r\n",
            "#EXT-X-KEY:METHOD=AES-128,URI=\"keys/{$key}.bin?sig={$signature}\"\n",
            "#EXT-X-MEDIA:TYPE=AUDIO,URI=\"//{$host}/audio.m3u8\"\r\n",
        );

        let rewritten = rewrite_playlist_bounded(body, &base).unwrap();

        assert_eq!(rewritten.matches("/proxy/d=").count(), 2);
        for variable in ["{$segment}", "{$token}", "{$key}", "{$signature}"] {
            assert!(rewritten.contains(variable), "missing {variable:?}");
        }
        assert!(
            rewritten.contains(
                "&x-stream-path=raw//path/segments/{$segment}/part.ts?token={$token}\r\n"
            )
        );
        assert!(
            rewritten.contains("&x-stream-path=raw//path/keys/{$key}.bin?sig={$signature}\"\n")
        );
        assert!(rewritten.ends_with("//{$host}/audio.m3u8\"\r\n"));
    }

    #[test]
    fn playlist_children_inherit_options_only_for_the_same_complete_origin() {
        let base = Url::parse("https://MEDIA.example:443/path/master.m3u8").unwrap();
        let request_headers = HeaderMap::from_iter([
            ("x-z-last".parse().unwrap(), "z".parse().unwrap()),
            ("x-a-first".parse().unwrap(), "a".parse().unwrap()),
        ]);
        let response_headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            "application/vnd.apple.mpegurl".parse().unwrap(),
        )]);
        let body = concat!(
            "relative.ts\n",
            "/root.ts\n",
            "//media.example:443/protocol.ts\n",
            "https://media.example/absolute.ts\n",
            "http://media.example:443/different-scheme.ts\n",
            "//other.example/cross-protocol.ts\n",
            "https://other.example/cross-absolute.ts\n",
        );

        let rewritten =
            rewrite_playlist_with_options(body, &base, &request_headers, &response_headers)
                .unwrap();
        let links = rewritten.lines().collect::<Vec<_>>();
        assert_eq!(links.len(), 7);
        for (index, link) in links.iter().enumerate() {
            let parsed = parse_proxy_suffix(link.strip_prefix("/proxy").unwrap()).unwrap();
            if index < 4 {
                assert_eq!(parsed.request_headers["x-a-first"], "a", "{link}");
                assert_eq!(parsed.request_headers["x-z-last"], "z", "{link}");
                assert_eq!(
                    parsed.response_headers[header::CONTENT_TYPE],
                    "application/vnd.apple.mpegurl",
                    "{link}"
                );
                assert!(
                    link.contains("&h=x-a-first%3Aa&h=x-z-last%3Az&r=content-type%3Aapplication%2Fvnd.apple.mpegurl"),
                    "non-deterministic options: {link}"
                );
            } else {
                assert!(parsed.request_headers.is_empty(), "{link}");
                assert!(parsed.response_headers.is_empty(), "{link}");
            }
        }
    }

    #[test]
    fn playlist_variables_keep_path_options_but_make_origin_variables_indeterminate() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let request_headers =
            HeaderMap::from_iter([("x-token".parse().unwrap(), "secret".parse().unwrap())]);
        let response_headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            "application/vnd.apple.mpegurl".parse().unwrap(),
        )]);
        let body = concat!(
            "segments/{$segment}.ts?token={$token}\n",
            "#EXT-X-KEY:URI=\"keys/{$key}.bin?sig={$signature}\"\n",
            "//{$host}/audio.m3u8\n",
            "{$scheme}://media.example/video.m3u8\n",
            "https://{$user}@media.example/private.m3u8\n",
            "https://media.example:{$port}/video.m3u8\n",
        );

        let rewritten =
            rewrite_playlist_with_options(body, &base, &request_headers, &response_headers)
                .unwrap();
        for unchanged in [
            "//{$host}/audio.m3u8",
            "{$scheme}://media.example/video.m3u8",
            "https://{$user}@media.example/private.m3u8",
            "https://media.example:{$port}/video.m3u8",
        ] {
            assert!(
                rewritten.contains(unchanged),
                "rewritten playlist: {rewritten:?}"
            );
        }
        assert_eq!(rewritten.matches("/proxy/d=").count(), 2);
        assert!(!rewritten.contains("/proxy/?d="));
        assert!(rewritten.contains(
            "&h=x-token%3Asecret&r=content-type%3Aapplication%2Fvnd.apple.mpegurl&x-stream-path=raw//path/segments/{$segment}.ts?token={$token}"
        ));

        let substituted = rewritten
            .replace("{$segment}", "one")
            .replace("{$token}", "two")
            .replace("{$key}", "three")
            .replace("{$signature}", "four");
        let links = substituted
            .split(['\n', '"'])
            .filter(|part| part.starts_with("/proxy"))
            .collect::<Vec<_>>();
        assert_eq!(links.len(), 2, "rewritten playlist: {rewritten:?}");
        for link in links {
            let uri = link.parse::<Uri>().unwrap();
            let raw = uri.path_and_query().unwrap().as_str();
            let parsed = parse_proxy_suffix(raw.strip_prefix("/proxy").unwrap()).unwrap();
            assert_eq!(parsed.request_headers["x-token"], "secret", "{link}");
            assert_eq!(
                parsed.response_headers[header::CONTENT_TYPE],
                "application/vnd.apple.mpegurl",
                "{link}"
            );
        }
    }

    #[test]
    fn special_url_authority_variables_remain_unchanged_after_canonicalization() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        for reference in [
            "https:///{$host}/video.m3u8",
            "HTTPS:////{$host}/video.m3u8",
            r"https:\\{$host}\video.m3u8",
            r"https:/\{$host}/video.m3u8",
            "https:///{$user}@media.example/private.m3u8",
            "https:///user:{$password}@media.example/private.m3u8",
            "https:///media.example:{$port}/video.m3u8",
        ] {
            let rewritten = rewrite_playlist_bounded(reference, &base)
                .unwrap_or_else(|error| panic!("reference {reference:?} failed: {error:?}"));
            assert_eq!(rewritten, reference, "reference={reference:?}");
        }
    }

    #[test]
    fn variable_placeholders_do_not_collide_with_canonicalized_literals() {
        let base = Url::parse("https://media.example/master.m3u8").unwrap();
        for reference in [
            "https://X000.example/{$part}.ts",
            "https://%78%30%30%30.example/{$part}.ts",
        ] {
            let resolved = resolve_hls_reference(reference, &base).unwrap().unwrap();

            assert_eq!(
                Url::parse(&resolved.target).unwrap().host_str(),
                Some("x000.example"),
                "{reference}"
            );
            assert_eq!(resolved.target.matches("{$part}").count(), 1, "{reference}");
        }
    }

    #[test]
    fn overlapping_variable_placeholder_collision_retries_before_restoration() {
        let base = Url::parse("https://media.example/master.m3u8").unwrap();
        let mut reference = String::from("segments/");
        for index in 0..33 {
            reference.push_str("{$v");
            reference.push_str(&index.to_string());
            reference.push_str("}/");
        }
        reference.push_str("x00{$target}.ts");

        let resolved = resolve_hls_reference(&reference, &base).unwrap().unwrap();

        assert!(
            resolved.target.ends_with("/x00{$target}.ts"),
            "restored target: {:?}",
            resolved.target
        );
        for index in 0..33 {
            assert_eq!(
                resolved.target.matches(&format!("{{$v{index}}}")).count(),
                1,
                "restored target: {:?}",
                resolved.target
            );
        }
    }

    #[test]
    fn variable_substitutions_cannot_escape_path_form_or_change_proxy_options() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let request_headers =
            HeaderMap::from_iter([("x-token".parse().unwrap(), "secret".parse().unwrap())]);
        let rewritten = rewrite_playlist_with_options(
            "segments/{$path}.ts?token={$query}",
            &base,
            &request_headers,
            &HeaderMap::new(),
        )
        .unwrap();
        assert!(rewritten.starts_with("/proxy/d="), "{rewritten}");

        let parse_substitution = |path: &str, query: &str| {
            let link = rewritten
                .replace("{$path}", path)
                .replace("{$query}", query);
            let uri = link
                .parse::<Uri>()
                .map_err(|_| ProxyError::InvalidRequest)?;
            let raw = uri
                .path_and_query()
                .ok_or(ProxyError::InvalidRequest)?
                .as_str();
            let suffix = raw
                .strip_prefix("/proxy")
                .ok_or(ProxyError::InvalidRequest)?;
            parse_proxy_suffix(suffix)
        };

        let benign = parse_substitution("part", "value").unwrap();
        assert_eq!(
            benign.target.as_str(),
            "https://media.example/path/segments/part.ts?token=value"
        );
        assert_eq!(benign.request_headers, request_headers);
        assert!(benign.response_headers.is_empty());

        for encoded in ["%2F", "%25", "%41", "%5C", "%FF"] {
            for (path, query) in [
                (format!("one{encoded}two"), "value".to_owned()),
                ("one".to_owned(), format!("value{encoded}tail")),
            ] {
                let parsed = parse_substitution(&path, &query).unwrap_or_else(|error| {
                    panic!("valid substitution {path:?}, {query:?} failed: {error:?}")
                });
                let direct = base
                    .join(&format!("segments/{path}.ts?token={query}"))
                    .unwrap();
                assert_eq!(
                    parsed.target, direct,
                    "path={path:?}, query={query:?}, link={rewritten:?}"
                );
                assert_eq!(parsed.request_headers, request_headers);
                assert!(parsed.response_headers.is_empty());
            }
        }
        assert!(rewritten.contains("&x-stream-path=raw//path/segments/{$path}.ts"));

        for (path, query) in [
            ("one&h=x-added%3Aattacker", "value"),
            ("one&r=content-type%3Atext%2Fplain", "value"),
            ("one&d=https%3A%2F%2Fattacker.example%2F", "value"),
            ("one&ignored=1", "value"),
            ("one?nested=1", "value"),
            ("one#fragment", "value"),
            ("one%2Ftwo", "value"),
            ("one", "value&h=x-added%3Aattacker"),
            ("one", "value&r=content-type%3Atext%2Fplain"),
            ("one", "value&d=https%3A%2F%2Fattacker.example%2F"),
            ("one", "value&ignored=1"),
            ("one", "value?nested=1"),
            ("one", "value#fragment"),
            ("one", "value%2Ftail"),
        ] {
            let parsed = parse_substitution(path, query).unwrap_or_else(|error| {
                panic!("valid substitution {path:?}, {query:?} failed: {error:?}")
            });
            assert_eq!(
                parsed.request_headers, request_headers,
                "path={path:?}, query={query:?}"
            );
            assert!(
                parsed.response_headers.is_empty(),
                "path={path:?}, query={query:?}"
            );
        }

        for malformed in ["one%", "one%0", "one%GG"] {
            assert!(
                parse_substitution(malformed, "value").is_err(),
                "path={malformed:?}"
            );
            assert!(
                parse_substitution("one", malformed).is_err(),
                "query={malformed:?}"
            );
        }

        let double_slash = rewrite_playlist_with_options(
            "https://media.example//segments/{$path}.ts",
            &base,
            &request_headers,
            &HeaderMap::new(),
        )
        .unwrap()
        .replace("{$path}", "part");
        let uri = double_slash.parse::<Uri>().unwrap();
        let raw = uri.path_and_query().unwrap().as_str();
        let parsed = parse_proxy_suffix(raw.strip_prefix("/proxy").unwrap()).unwrap();
        assert_eq!(
            parsed.target.as_str(),
            "https://media.example//segments/part.ts"
        );
        assert_eq!(parsed.request_headers, request_headers);
    }

    #[test]
    fn malformed_percent_variable_references_remain_unchanged_before_emission() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        for reference in [
            "segments/{$part}%.ts",
            "segments/{$part}%0.ts",
            "segments/{$part}%GG.ts",
            "segments/{$part}.ts?token={$query}%",
            "segments/{$part}.ts?token={$query}%0",
            "segments/{$part}.ts?token={$query}%GG",
        ] {
            let rewritten = rewrite_playlist_bounded(reference, &base)
                .unwrap_or_else(|error| panic!("plain reference {reference:?}: {error:?}"));
            assert_eq!(rewritten, reference, "plain reference={reference:?}");

            let tag = format!("#EXT-X-MAP:URI=\"{reference}\"");
            let rewritten = rewrite_playlist_bounded(&tag, &base)
                .unwrap_or_else(|error| panic!("quoted reference {reference:?}: {error:?}"));
            assert_eq!(rewritten, tag, "quoted reference={reference:?}");
        }
    }

    #[test]
    fn overlong_variable_candidate_is_rejected_before_variable_collection() {
        let base = Url::parse("https://media.example/master.m3u8").unwrap();
        let reference = "{$v}".repeat((MAX_PLAYLIST_INPUT - 1) / 4);
        assert!(reference.len() > MAX_TARGET_URL);
        assert!(reference.len() < MAX_PLAYLIST_INPUT);
        HLS_VARIABLE_RANGE_SCANS.with(|scans| scans.set(0));

        assert!(matches!(
            resolve_hls_reference(&reference, &base),
            Err(ProxyError::Upstream)
        ));
        HLS_VARIABLE_RANGE_SCANS.with(|scans| assert_eq!(scans.get(), 0));
    }

    #[test]
    fn overlong_delimiter_free_candidate_bounds_initial_scheme_prescan() {
        let base = Url::parse("https://media.example/master.m3u8").unwrap();
        let reference = "a".repeat(MAX_PLAYLIST_INPUT - 1);
        HLS_SCHEME_PRESCAN_BYTES.with(|scans| scans.set(0));

        assert!(matches!(
            resolve_hls_reference(&reference, &base),
            Err(ProxyError::Upstream)
        ));
        HLS_SCHEME_PRESCAN_BYTES.with(|scans| {
            assert_eq!(scans.get(), MAX_TARGET_URL + 1);
        });

        for reference in [
            "data:text/plain,segment",
            "skd://license.example/key",
            "urn:example:asset",
        ] {
            assert!(resolve_hls_reference(reference, &base).unwrap().is_none());
        }
    }

    #[test]
    fn dense_path_variables_restore_without_placeholder_ambiguity() {
        let base = Url::parse("https://media.example/master.m3u8").unwrap();
        let reference = format!("/{}tail.ts", "{$v}/".repeat(2_000));
        assert!(reference.len() < MAX_TARGET_URL);

        let resolved = resolve_hls_reference(&reference, &base).unwrap().unwrap();

        assert_eq!(resolved.target.matches("{$v}").count(), 2_000);
        assert!(resolved.target.ends_with("/tail.ts"));
    }

    #[test]
    fn emitted_hls_links_round_trip_reserved_target_and_header_semantics() {
        let base = Url::parse("https://user:pass@media.example/dir/master.m3u8").unwrap();
        let request_headers = HeaderMap::from_iter([(
            "x-token".parse().unwrap(),
            "raw+plus&equals=value".parse().unwrap(),
        )]);
        let response_headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            "video/mp2t; note=raw+plus&equals=value".parse().unwrap(),
        )]);
        let body = concat!(
            "child%2Fname+raw.ts?one=a+b&two=c%2Bd&equal=x=y#removed\n",
            "#EXT-X-MAP:URI=\"/root%2Finit.mp4?x=a+b&y=%2B&z==#removed\"\n",
        );

        let rewritten =
            rewrite_playlist_with_options(body, &base, &request_headers, &response_headers)
                .unwrap();
        assert!(!rewritten.contains("removed"));
        let links = rewritten
            .split(['\n', '"'])
            .filter(|part| part.starts_with("/proxy"))
            .collect::<Vec<_>>();
        let expected_targets = [
            "https://user:pass@media.example/dir/child%2Fname+raw.ts?one=a+b&two=c%2Bd&equal=x=y",
            "https://user:pass@media.example/root%2Finit.mp4?x=a+b&y=%2B&z==",
        ];
        for (link, expected_target) in links.iter().zip(expected_targets) {
            let parsed = parse_proxy_suffix(link.strip_prefix("/proxy").unwrap()).unwrap();
            assert_eq!(parsed.target.as_str(), expected_target);
            assert_eq!(parsed.request_headers["x-token"], "raw+plus&equals=value");
            assert_eq!(
                parsed.response_headers[header::CONTENT_TYPE],
                "video/mp2t; note=raw+plus&equals=value"
            );
        }
    }

    #[test]
    fn parsed_utf8_obs_text_headers_round_trip_through_playlist_rewriting() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let original = parse_proxy_request(
            "",
            Some(concat!(
                "d=https%3A%2F%2Fmedia.example%2Fpath%2Fmaster.m3u8",
                "&h=X-Utf8%3Acaf%C3%A9-%C2%80",
                "&r=Content-Type%3Aapplication%2Fx.test%3Bnote%3Dcaf%C3%A9-%C2%80",
            )),
        )
        .unwrap();
        assert_eq!(
            original.request_headers["x-utf8"].as_bytes(),
            b"caf\xc3\xa9-\xc2\x80"
        );
        assert_eq!(
            original.response_headers[header::CONTENT_TYPE].as_bytes(),
            b"application/x.test;note=caf\xc3\xa9-\xc2\x80"
        );

        let rewritten = rewrite_playlist_with_options(
            "segment.ts",
            &base,
            &original.request_headers,
            &original.response_headers,
        )
        .unwrap();
        let reparsed = parse_proxy_suffix(rewritten.strip_prefix("/proxy").unwrap()).unwrap();

        assert_eq!(
            reparsed.request_headers["x-utf8"].as_bytes(),
            original.request_headers["x-utf8"].as_bytes()
        );
        assert_eq!(
            reparsed.response_headers[header::CONTENT_TYPE].as_bytes(),
            original.response_headers[header::CONTENT_TYPE].as_bytes()
        );
    }

    #[test]
    fn playlist_child_canonical_target_accepts_exact_limit_and_rejects_overflow() {
        let base = Url::parse("https://base.example/master.m3u8").unwrap();
        let prefix = "https://example.com/";
        let exact = format!("{prefix}{}", "a".repeat(MAX_TARGET_URL - prefix.len()));
        assert_eq!(exact.len(), MAX_TARGET_URL);
        let rewritten = rewrite_playlist_bounded(&exact, &base).unwrap();
        let parsed = parse_proxy_suffix(rewritten.strip_prefix("/proxy").unwrap()).unwrap();
        assert_eq!(parsed.target.as_str().len(), MAX_TARGET_URL);

        let over = format!("{exact}a");
        assert!(matches!(
            rewrite_playlist_bounded(&over, &base),
            Err(ProxyError::Upstream)
        ));
    }

    #[test]
    fn emitted_proxy_suffix_accepts_exact_limit_and_rejects_overflow() {
        const FIXED_SUFFIX_LENGTH: usize = 123;
        const FULL_VALUE_LENGTH: usize = MAX_HEADER_PAIR - "x-0:".len();
        let last_value_length = MAX_PROXY_INPUT - FIXED_SUFFIX_LENGTH - (7 * FULL_VALUE_LENGTH);
        assert_eq!(last_value_length, 8_097);
        let headers = |extra: usize| {
            let mut headers = HeaderMap::new();
            for index in 0..8 {
                let length = if index == 7 {
                    last_value_length + extra
                } else {
                    FULL_VALUE_LENGTH
                };
                headers.insert(
                    format!("x-{index}")
                        .parse::<axum::http::HeaderName>()
                        .unwrap(),
                    "a".repeat(length).parse::<HeaderValue>().unwrap(),
                );
            }
            headers
        };
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();

        let exact =
            rewrite_playlist_with_options("segment.ts", &base, &headers(0), &HeaderMap::new())
                .unwrap();
        let suffix = exact.strip_prefix("/proxy").unwrap();
        assert_eq!(suffix.len(), MAX_PROXY_INPUT);
        assert!(parse_proxy_suffix(suffix).is_ok());

        assert!(matches!(
            rewrite_playlist_with_options("segment.ts", &base, &headers(1), &HeaderMap::new(),),
            Err(ProxyError::Upstream)
        ));
    }

    #[test]
    fn emitted_raw_path_mode_counts_exact_option_and_suffix_bytes() {
        const FIXED_SUFFIX_LENGTH: usize = 134;
        const FULL_VALUE_LENGTH: usize = MAX_HEADER_PAIR - "x-0:".len();
        const LAST_VALUE_LENGTH: usize =
            MAX_PROXY_INPUT - FIXED_SUFFIX_LENGTH - (7 * FULL_VALUE_LENGTH);
        assert_eq!(LAST_VALUE_LENGTH, 8_086);
        let headers = |extra: usize| {
            let mut headers = HeaderMap::new();
            for index in 0..8 {
                let length = if index == 7 {
                    LAST_VALUE_LENGTH + extra
                } else {
                    FULL_VALUE_LENGTH
                };
                headers.insert(
                    format!("x-{index}")
                        .parse::<axum::http::HeaderName>()
                        .unwrap(),
                    "a".repeat(length).parse::<HeaderValue>().unwrap(),
                );
            }
            headers
        };
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();

        let exact =
            rewrite_playlist_with_options("{$v}", &base, &headers(0), &HeaderMap::new()).unwrap();
        let suffix = exact.strip_prefix("/proxy").unwrap();
        assert!(suffix.contains("&x-stream-path=raw//path/{$v}"));
        assert_eq!(suffix.len(), MAX_PROXY_INPUT);
        assert!(parse_proxy_suffix(suffix).is_ok());

        assert!(matches!(
            rewrite_playlist_with_options("{$v}", &base, &headers(1), &HeaderMap::new(),),
            Err(ProxyError::Upstream)
        ));
    }

    #[test]
    fn rewritten_playlist_accepts_exact_output_limit_and_rejects_one_more_byte() {
        const REWRITTEN_LINE_LENGTH: usize = 35;
        let base = Url::parse("https://a.test/master.m3u8").unwrap();
        let repeats = MAX_PLAYLIST_OUTPUT / REWRITTEN_LINE_LENGTH;
        let remainder = MAX_PLAYLIST_OUTPUT % REWRITTEN_LINE_LENGTH;
        assert_eq!(remainder, 1);
        let mut exact = "x\n".repeat(repeats);
        exact.push('#');
        assert!(exact.len() <= MAX_PLAYLIST_INPUT);

        let rewritten = rewrite_playlist_bounded(&exact, &base).unwrap();
        assert_eq!(rewritten.len(), MAX_PLAYLIST_OUTPUT);

        exact.push('a');
        assert!(matches!(
            rewrite_playlist_bounded(&exact, &base),
            Err(ProxyError::Upstream)
        ));
    }

    #[tokio::test]
    async fn overlong_valid_http_playlist_child_returns_bad_gateway() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let prefix = format!("http://child.test:{}/", address.port());
        let child = format!("{prefix}{}", "a".repeat(MAX_TARGET_URL + 1 - prefix.len()));
        let router = Router::new().route(
            "/master.m3u8",
            get(move || {
                let child = child.clone();
                async move {
                    Response::builder()
                        .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                        .body(Body::from(child))
                        .unwrap()
                }
            }),
        );
        let fixture = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://origin.test:{}/master.m3u8", address.port());
        let uri: Uri = format!("/proxy/?d={}", urlencoding::encode(&target))
            .parse()
            .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            "Proxy upstream request failed"
        );
        fixture.abort();
    }

    #[tokio::test]
    async fn emitted_hls_links_scope_options_by_final_child_origin_in_real_handlers() {
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cross_uri = format!("http://other.test:{}/cross.ts", address.port());
        let router = Router::new().fallback(any(move |uri: Uri, headers: HeaderMap| {
            let seen_tx = seen_tx.clone();
            let cross_uri = cross_uri.clone();
            async move {
                match uri.path() {
                    "/master.m3u8" => Response::builder()
                        .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                        .body(Body::from(format!("#EXTM3U\nsame.ts\n{cross_uri}\n")))
                        .unwrap(),
                    "/same.ts" | "/cross.ts" => {
                        seen_tx.send((uri.path().to_owned(), headers)).unwrap();
                        Response::new(Body::from("media"))
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }));
        let fixture = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://media.test:{}/master.m3u8", address.port());
        let uri: Uri = format!(
            concat!(
                "/proxy/?d={}",
                "&h=X-Api-Key%3Asame-secret",
                "&r=Content-Type%3Aapplication%2Fvnd.apple.mpegurl"
            ),
            urlencoding::encode(&target)
        )
        .parse()
        .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        let links = body
            .lines()
            .filter(|line| line.starts_with("/proxy"))
            .collect::<Vec<_>>();
        assert_eq!(links.len(), 2, "rewritten playlist: {body:?}");

        let same = parse_proxy_suffix(links[0].strip_prefix("/proxy").unwrap()).unwrap();
        assert_eq!(same.target.host_str(), Some("media.test"));
        assert_eq!(same.request_headers["x-api-key"], "same-secret");
        assert_eq!(
            same.response_headers[header::CONTENT_TYPE],
            "application/vnd.apple.mpegurl"
        );
        let cross = parse_proxy_suffix(links[1].strip_prefix("/proxy").unwrap()).unwrap();
        assert_eq!(cross.target.host_str(), Some("other.test"));
        assert!(cross.request_headers.is_empty());
        assert!(cross.response_headers.is_empty());

        for link in links {
            let child = handle_proxy(
                &runtime,
                link.parse().unwrap(),
                HeaderMap::new(),
                Method::GET,
            )
            .await;
            assert_eq!(child.status(), StatusCode::OK);
        }
        let (same_path, same_headers) = seen_rx.recv().await.unwrap();
        assert_eq!(same_path, "/same.ts");
        assert_eq!(same_headers["x-api-key"], "same-secret");
        let (cross_path, cross_headers) = seen_rx.recv().await.unwrap();
        assert_eq!(cross_path, "/cross.ts");
        assert!(!cross_headers.contains_key("x-api-key"));
        fixture.abort();
    }

    #[tokio::test]
    async fn redirected_playlist_children_use_cleared_h_and_retained_r() {
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_location = format!("http://origin-b.test:{}/final.m3u8", address.port());
        let router = Router::new().fallback(any(move |uri: Uri, headers: HeaderMap| {
            let seen_tx = seen_tx.clone();
            let redirect_location = redirect_location.clone();
            async move {
                match uri.path() {
                    "/redirect.m3u8" => (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, redirect_location)],
                    )
                        .into_response(),
                    "/final.m3u8" => {
                        seen_tx.send((uri.path().to_owned(), headers)).unwrap();
                        Response::builder()
                            .header(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")
                            .body(Body::from("#EXTM3U\nredirect-child.ts\n"))
                            .unwrap()
                    }
                    "/redirect-child.ts" => {
                        seen_tx.send((uri.path().to_owned(), headers)).unwrap();
                        Response::new(Body::from("media"))
                    }
                    _ => StatusCode::NOT_FOUND.into_response(),
                }
            }
        }));
        let fixture = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let (runtime, _) = test_runtime(
            address,
            ProxyPolicySettings {
                allow_private_network_sources: true,
                allow_invalid_proxy_tls_certificates: false,
            },
        );
        let target = format!("http://origin-a.test:{}/redirect.m3u8", address.port());
        let uri: Uri = format!(
            concat!(
                "/proxy/?d={}",
                "&h=X-Api-Key%3Aredirect-secret",
                "&r=Content-Type%3Aapplication%2Fvnd.apple.mpegurl"
            ),
            urlencoding::encode(&target)
        )
        .parse()
        .unwrap();

        let response = handle_proxy(&runtime, uri, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        let link = body
            .lines()
            .find(|line| line.starts_with("/proxy"))
            .unwrap();
        let parsed = parse_proxy_suffix(link.strip_prefix("/proxy").unwrap()).unwrap();
        assert_eq!(parsed.target.host_str(), Some("origin-b.test"));
        assert!(parsed.request_headers.is_empty());
        assert_eq!(
            parsed.response_headers[header::CONTENT_TYPE],
            "application/vnd.apple.mpegurl"
        );

        let child = handle_proxy(
            &runtime,
            link.parse().unwrap(),
            HeaderMap::new(),
            Method::GET,
        )
        .await;
        assert_eq!(child.status(), StatusCode::OK);
        for expected_path in ["/final.m3u8", "/redirect-child.ts"] {
            let (path, headers) = seen_rx.recv().await.unwrap();
            assert_eq!(path, expected_path);
            assert!(!headers.contains_key("x-api-key"));
        }
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
    fn playlist_rewriter_only_rewrites_exact_ext_uri_attributes() {
        let base = Url::parse("https://media.example/path/master.m3u8").unwrap();
        let preserved_prefix = concat!(
            "# an unrelated URI=\"comment.ts\"\r\n",
            "#COMMENT:URI=\"comment-tag.ts\"\n",
            "#EXT-X-TEST:NOTURI=\"not.ts\",X-URI=\"x.ts\"\r\n",
        );
        let body = format!(
            concat!(
                "{}",
                "#EXT-X-TEST:NOTURI=\"not.ts\", X-URI=\"x.ts\",\tURI=\"actual.ts\", FOO=1, URI=\"backup.ts\"\n",
                "#EXT-X-MAP: \tURI=\"leading.ts\"\r\n",
            ),
            preserved_prefix,
        );

        let rewritten = rewrite_playlist_bounded(&body, &base).unwrap();

        assert!(
            rewritten.starts_with(preserved_prefix),
            "rewritten playlist: {rewritten:?}"
        );
        assert!(rewritten.contains("NOTURI=\"not.ts\", X-URI=\"x.ts\",\tURI=\"/proxy/?d="));
        assert_eq!(rewritten.matches("/proxy/?d=").count(), 3);
        assert_eq!(rewritten.matches("\r\n").count(), 3);
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
