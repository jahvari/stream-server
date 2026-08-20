use crate::{
    network_security::{DestinationError, ProxyRequestContext, ProxyRuntime},
    state::AppState,
};
use axum::{
    Router,
    body::Body,
    extract::{OriginalUri, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
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
            _ => {}
        }
    }

    let target = target.ok_or(ProxyError::InvalidRequest)?;
    let mut target = Url::parse(&target).map_err(|_| ProxyError::InvalidRequest)?;
    if let Some(path_tail) = path_tail {
        let path_tail = strict_percent_decode(path_tail, false)?;
        target.set_path(if path_tail.is_empty() {
            "/"
        } else {
            &path_tail
        });
        target.set_query(upstream_query);
    }
    let target = validate_proxy_target(target)?;

    Ok(ParsedProxyRequest {
        target,
        request_headers,
        response_headers,
    })
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
        let response = tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => return Err(ProxyError::Cancelled),
            result = send => result.map_err(|_| ProxyError::Upstream)?,
        };

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
    Router::new().fallback(any(proxy_handler)).with_state(state)
}

async fn proxy_handler(
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    headers: HeaderMap,
    method: Method,
) -> Response {
    handle_proxy(&state.proxy_runtime, original_uri, headers, method).await
}

async fn handle_proxy(
    runtime: &ProxyRuntime,
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
    handle_proxy_suffix(runtime, raw_suffix, headers, method).await
}

async fn handle_proxy_suffix(
    runtime: &ProxyRuntime,
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
    let context = match runtime.try_request() {
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
        effective_custom_request_headers: _effective_custom_request_headers,
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
            .and_then(|body| rewrite_playlist_bounded(&body, &final_url))
        {
            Ok(body) => body,
            Err(error) => return proxy_error_response(error),
        };
        let ProxyRequestContext {
            cancellation,
            capacity,
            ..
        } = context;
        return build_proxy_response(
            status,
            &upstream_headers,
            &effective_response_headers,
            buffered_proxy_body(Bytes::from(body), cancellation, capacity),
            true,
            credential_bearing,
        );
    }

    let ProxyRequestContext {
        cancellation,
        capacity,
        ..
    } = context;
    let body = streaming_proxy_body(Box::pin(upstream.bytes_stream()), cancellation, capacity);
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

fn streaming_proxy_body(
    stream: UpstreamByteStream,
    cancellation: CancellationToken,
    capacity: OwnedSemaphorePermit,
) -> Body {
    let stream = ProxyBodyState {
        stream,
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
    Body::from_stream(stream)
}

type UpstreamByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

struct ProxyBodyState {
    stream: UpstreamByteStream,
    cancellation: CancellationToken,
    _capacity: OwnedSemaphorePermit,
    terminal: bool,
}

struct BufferedProxyBodyState {
    bytes: Bytes,
    offset: usize,
    cancellation: CancellationToken,
    _capacity: OwnedSemaphorePermit,
    terminal: bool,
}

fn buffered_proxy_body(
    bytes: Bytes,
    cancellation: CancellationToken,
    capacity: OwnedSemaphorePermit,
) -> Body {
    const CHUNK_SIZE: usize = 64 * 1024;
    let stream = futures_util::stream::unfold(
        BufferedProxyBodyState {
            bytes,
            offset: 0,
            cancellation,
            _capacity: capacity,
            terminal: false,
        },
        |mut state| async move {
            if state.terminal || state.offset == state.bytes.len() {
                return None;
            }
            if state.cancellation.is_cancelled() {
                state.terminal = true;
                return Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "proxy policy changed",
                    )),
                    state,
                ));
            }
            let end = state
                .offset
                .saturating_add(CHUNK_SIZE)
                .min(state.bytes.len());
            let chunk = state.bytes.slice(state.offset..end);
            state.offset = end;
            Some((Ok::<_, std::io::Error>(chunk), state))
        },
    );
    Body::from_stream(stream)
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
    let encoded = urlencoding::encode(absolute.as_str());
    let required = encoded
        .len()
        .checked_add(PREFIX.len())
        .ok_or(ProxyError::Upstream)?;
    let remaining = MAX_PLAYLIST_OUTPUT.saturating_sub(output.len());
    if required > remaining {
        return Err(ProxyError::Upstream);
    }
    push_playlist(output, PREFIX)?;
    push_playlist(output, &encoded)
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
    use super::{
        MAX_HEADER_PAIR, MAX_PLAYLIST_INPUT, MAX_PROXY_INPUT, MAX_TARGET_URL, ProxyError,
        apply_redirect_origin_policy, buffered_proxy_body, collect_playlist, fetch_with_redirects,
        handle_proxy, handle_proxy_suffix, parse_proxy_request, parse_proxy_suffix,
        proxy_error_response, rewrite_playlist_bounded, same_origin, streaming_proxy_body,
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
    use std::{
        io,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
            .map(|_| runtime.try_request().unwrap())
            .collect::<Vec<_>>();
        let prefix = "?d=http%3A%2F%2Fblocked.example&unknown=";
        let raw_suffix = format!("{prefix}{}", "a".repeat(MAX_PROXY_INPUT + 1 - prefix.len()));
        let response =
            handle_proxy_suffix(&runtime, &raw_suffix, HeaderMap::new(), Method::GET).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);

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
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let body = buffered_proxy_body(
            bytes::Bytes::from_static(b"#EXTM3U\nsegment.ts\n"),
            cancellation.clone(),
            permit,
        );
        assert!(semaphore.clone().try_acquire_owned().is_err());
        cancellation.cancel();
        assert!(axum::body::to_bytes(body, usize::MAX).await.is_err());
        assert!(semaphore.try_acquire_owned().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn streaming_body_times_out_once_and_releases_capacity() {
        let stream = futures_util::stream::pending::<Result<bytes::Bytes, reqwest::Error>>();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let body = streaming_proxy_body(
            Box::pin(stream),
            tokio_util::sync::CancellationToken::new(),
            permit,
        );
        let collect = tokio::spawn(axum::body::to_bytes(body, usize::MAX));
        tokio::task::yield_now().await;
        assert!(semaphore.clone().try_acquire_owned().is_err());
        tokio::time::advance(Duration::from_secs(31)).await;
        assert!(collect.await.unwrap().is_err());
        assert!(semaphore.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn dropping_streaming_body_releases_capacity() {
        let stream = futures_util::stream::pending::<Result<bytes::Bytes, reqwest::Error>>();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let body = streaming_proxy_body(
            Box::pin(stream),
            tokio_util::sync::CancellationToken::new(),
            permit,
        );
        assert!(semaphore.clone().try_acquire_owned().is_err());
        drop(body);
        assert!(semaphore.try_acquire_owned().is_ok());
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
