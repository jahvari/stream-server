use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::Response,
    routing::{get, post},
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::{
    AppState,
    settings_control::{SETTINGS_TOKEN_HEADER, SettingsMutationAuthority},
    transcoding::capability::{
        dto::DtoError,
        registry::{RefreshAdmission, RefreshCause, RegistryReason},
    },
};

static GET_BUILD_PERMITS: Semaphore = Semaphore::const_new(4);

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/transcoding/capabilities", get(get_capabilities))
        .route(
            "/transcoding/capabilities/refresh",
            post(refresh_capabilities),
        )
}

async fn get_capabilities(State(state): State<AppState>, request: Request) -> Response {
    let Some(peer) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0)
    else {
        return fixed_error(StatusCode::FORBIDDEN, "forbidden");
    };
    if !actual_peer_is_loopback(peer) || !browser_request_allowed(request.headers(), request.uri())
    {
        return fixed_error(StatusCode::FORBIDDEN, "forbidden");
    }
    let Ok(_permit) = GET_BUILD_PERMITS.try_acquire() else {
        return fixed_error(StatusCode::SERVICE_UNAVAILABLE, "capacity_exhausted");
    };
    match state.transcoding.capability_api_bytes().await {
        Ok(bytes) => json_response(StatusCode::OK, bytes),
        Err(DtoError::Bounds | DtoError::ResponseTooLarge | DtoError::UnsupportedSnapshot) => {
            fixed_error(StatusCode::INTERNAL_SERVER_ERROR, "response_too_large")
        }
    }
}

async fn refresh_capabilities(State(state): State<AppState>, request: Request) -> Response {
    let Some(peer) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect| connect.0)
    else {
        return fixed_error(StatusCode::FORBIDDEN, "forbidden");
    };
    if !actual_peer_is_loopback(peer)
        || headers_count(request.headers(), SETTINGS_TOKEN_HEADER) != 1
        || state
            .settings_control
            .authorize_http(peer, request.headers())
            != SettingsMutationAuthority::HttpAuthorized
        || !browser_request_allowed(request.headers(), request.uri())
    {
        return fixed_error(StatusCode::FORBIDDEN, "forbidden");
    }
    if !request_body_is_empty(request).await {
        return fixed_error(StatusCode::BAD_REQUEST, "request_body_not_allowed");
    }

    match state
        .transcoding
        .start_capability_refresh(RefreshCause::Manual)
        .await
    {
        RefreshAdmission::Started { id } | RefreshAdmission::Existing { id } => {
            match state.transcoding.capability_refresh_api_bytes(id).await {
                Ok(bytes) => json_response(StatusCode::ACCEPTED, bytes),
                Err(_) => fixed_error(StatusCode::INTERNAL_SERVER_ERROR, "response_too_large"),
            }
        }
        RefreshAdmission::RateLimited {
            retry_after_seconds,
        } => {
            let mut response = fixed_error(StatusCode::TOO_MANY_REQUESTS, "refresh_rate_limited");
            match HeaderValue::from_str(&retry_after_seconds.to_string()) {
                Ok(value) => {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                    response
                }
                Err(_) => fixed_error(StatusCode::SERVICE_UNAVAILABLE, "capacity_exhausted"),
            }
        }
        RefreshAdmission::Rejected {
            reason: RegistryReason::ServerShutdown,
        } => fixed_error(StatusCode::SERVICE_UNAVAILABLE, "server_shutdown"),
        RefreshAdmission::Rejected { .. } => {
            fixed_error(StatusCode::SERVICE_UNAVAILABLE, "capacity_exhausted")
        }
    }
}

async fn request_body_is_empty(request: Request) -> bool {
    if headers_count(request.headers(), header::TRANSFER_ENCODING.as_str()) != 0 {
        return false;
    }
    let content_length = match exactly_one_header(request.headers(), header::CONTENT_LENGTH) {
        Ok(None) => None,
        Ok(Some("0")) => Some(0_u8),
        Ok(Some(_)) | Err(()) => return false,
    };
    let _ = content_length;
    matches!(
        tokio::time::timeout(Duration::from_secs(1), to_bytes(request.into_body(), 0)).await,
        Ok(Ok(bytes)) if bytes.is_empty()
    )
}

fn headers_count(headers: &HeaderMap, name: &str) -> usize {
    headers.get_all(name).iter().count()
}

fn fixed_error(status: StatusCode, error: &'static str) -> Response {
    let bytes = match error {
        "forbidden" => br#"{"schemaVersion":1,"error":"forbidden"}"#.as_slice(),
        "capacity_exhausted" => br#"{"schemaVersion":1,"error":"capacity_exhausted"}"#.as_slice(),
        "response_too_large" => br#"{"schemaVersion":1,"error":"response_too_large"}"#.as_slice(),
        "request_body_not_allowed" => {
            br#"{"schemaVersion":1,"error":"request_body_not_allowed"}"#.as_slice()
        }
        "refresh_rate_limited" => {
            br#"{"schemaVersion":1,"error":"refresh_rate_limited"}"#.as_slice()
        }
        "server_shutdown" => br#"{"schemaVersion":1,"error":"server_shutdown"}"#.as_slice(),
        _ => br#"{"schemaVersion":1,"error":"server_shutdown"}"#.as_slice(),
    };
    json_response(status, bytes.to_vec())
}

fn json_response(status: StatusCode, bytes: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        axum::http::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert(
        axum::http::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LocalHost {
    Localhost,
    V4(Ipv4Addr),
    V6Loopback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalAuthority {
    host: LocalHost,
    port: Option<u16>,
}

fn actual_peer_is_loopback(peer: SocketAddr) -> bool {
    match peer.ip() {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) if address.is_loopback() => true,
        IpAddr::V6(address) => address.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback()),
    }
}

fn browser_request_allowed(headers: &HeaderMap, uri: &Uri) -> bool {
    if uri.authority().is_none() && uri.path().starts_with("//") {
        return false;
    }
    let host = match exactly_one_header(headers, header::HOST) {
        Ok(value) => match value.map(parse_local_authority).transpose() {
            Ok(value) => value,
            Err(()) => return false,
        },
        Err(()) => return false,
    };
    let uri_authority = match uri.authority() {
        Some(authority) => {
            if uri
                .scheme_str()
                .is_some_and(|scheme| !matches!(scheme, "http" | "https"))
            {
                return false;
            }
            match parse_local_authority(authority.as_str()) {
                Ok(authority) => Some(authority),
                Err(()) => return false,
            }
        }
        None => None,
    };
    let reference = match (host, uri_authority) {
        (Some(host), Some(uri)) if host != uri => return false,
        (Some(host), _) => Some(host),
        (_, Some(uri)) => Some(uri),
        (None, None) => None,
    };

    let fetch_site = match exactly_one_header(
        headers,
        axum::http::HeaderName::from_static("sec-fetch-site"),
    ) {
        Ok(Some(value)) if matches!(value, "none" | "same-origin" | "same-site") => Some(value),
        Ok(Some(_)) | Err(()) => return false,
        Ok(None) => None,
    };
    let origin = match exactly_one_header(headers, header::ORIGIN) {
        Ok(value) => value,
        Err(()) => return false,
    };

    match origin {
        Some(origin) => reference
            .as_ref()
            .is_some_and(|reference| origin_matches_reference(origin, reference)),
        None if fetch_site.is_some() => reference.is_some(),
        None => true,
    }
}

fn exactly_one_header(
    headers: &HeaderMap,
    name: axum::http::HeaderName,
) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

fn parse_local_authority(value: &str) -> Result<LocalAuthority, ()> {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || value.contains(['%', '@'])
        || value.ends_with('.')
    {
        return Err(());
    }

    if let Some(remainder) = value.strip_prefix('[') {
        let Some((host, suffix)) = remainder.split_once(']') else {
            return Err(());
        };
        if host != "::1" {
            return Err(());
        }
        let port = parse_port_suffix(suffix)?;
        return Ok(LocalAuthority {
            host: LocalHost::V6Loopback,
            port,
        });
    }

    let (host, port) = match value.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(parse_port(port)?)),
        Some(_) => return Err(()),
        None => (value, None),
    };
    let host = if host == "localhost" {
        LocalHost::Localhost
    } else {
        let address = host.parse::<Ipv4Addr>().map_err(|_| ())?;
        if !address.is_loopback() || address.to_string() != host {
            return Err(());
        }
        LocalHost::V4(address)
    };
    Ok(LocalAuthority { host, port })
}

fn parse_port_suffix(value: &str) -> Result<Option<u16>, ()> {
    if value.is_empty() {
        Ok(None)
    } else {
        let Some(port) = value.strip_prefix(':') else {
            return Err(());
        };
        parse_port(port).map(Some)
    }
}

fn parse_port(value: &str) -> Result<u16, ()> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    let port = value.parse::<u16>().map_err(|_| ())?;
    (port != 0 && port.to_string() == value)
        .then_some(port)
        .ok_or(())
}

fn origin_matches_reference(value: &str, reference: &LocalAuthority) -> bool {
    let (scheme, authority, default_port) = if let Some(authority) = value.strip_prefix("http://") {
        ("http", authority, 80)
    } else if let Some(authority) = value.strip_prefix("https://") {
        ("https", authority, 443)
    } else {
        return false;
    };
    let _ = scheme;
    if authority.contains(['/', '?', '#']) {
        return false;
    }
    let Ok(origin) = parse_local_authority(authority) else {
        return false;
    };
    if origin.host != reference.host {
        return false;
    }
    let effective_origin_port = origin.port.unwrap_or(default_port);
    reference
        .port
        .map_or(effective_origin_port == default_port, |port| {
            effective_origin_port == port
        })
}

#[cfg(test)]
mod tests;
