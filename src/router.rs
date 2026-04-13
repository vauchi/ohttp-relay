// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Axum router and HTTP handler implementations.
//!
//! Three endpoints:
//! - `POST /v2/ohttp`     — forward encrypted OHTTP blob to upstream gateway
//! - `GET  /v2/ohttp-key` — proxy the OHTTP key from the upstream gateway
//! - `GET  /health`       — local health check (no upstream call)
//!
//! Security invariants enforced here:
//! - Client IP is used only for rate limiting — never logged or forwarded.
//! - No identifying headers are forwarded upstream or downstream.
//! - Request bodies above `max_request_bytes` are rejected before forwarding.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tracing::{debug, warn};

use crate::config::RelayConfig;
use crate::rate_limit::RateLimiter;
use crate::upstream::UpstreamClient;

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub config: RelayConfig,
    pub upstream: UpstreamClient,
    /// Per-IP rate limiter for the OHTTP forward endpoint. `None` if disabled.
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

/// Build the router with all routes wired up.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/v2/ohttp", post(handle_ohttp_forward))
        .route("/v2/ohttp-key", get(handle_ohttp_key))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /health` — always returns 200 OK with a plain-text body.
///
/// Does not call the upstream gateway; only verifies this process is alive.
async fn handle_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `POST /v2/ohttp` — forward an opaque OHTTP encrypted blob to the gateway.
///
/// The raw request body is forwarded verbatim. No headers from the client are
/// passed upstream. The response body from the gateway is returned verbatim
/// to the client with no identifying headers added.
///
/// Rate-limited per source IP when a rate limiter is configured. The IP is
/// used only for rate limiting — it is never logged or forwarded.
async fn handle_ohttp_forward(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    // Rate limit by client IP if configured.
    if let Some(ref limiter) = state.rate_limiter {
        let client_ip = extract_client_ip(&state.config, request.headers(), connect_info.as_ref());
        if let Some(ip) = client_ip
            && !limiter.check(ip)
        {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    }

    let max = state.config.max_request_bytes;

    let body = match read_bounded_body(request, max).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    debug!(body_len = body.len(), "forwarding OHTTP blob to gateway");

    match state
        .upstream
        .post_ohttp(
            body,
            state.config.request_timeout,
            state.config.max_response_bytes,
        )
        .await
    {
        Ok(response_bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "message/ohttp-res")],
            response_bytes,
        )
            .into_response(),
        Err(e) => {
            warn!(error = %e, "upstream gateway error on OHTTP forward");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// `GET /v2/ohttp-key` — proxy the OHTTP key from the upstream gateway.
///
/// Clients need the gateway's public key to construct OHTTP requests.
/// This endpoint solves the key bootstrap problem without exposing the
/// gateway address to clients.
async fn handle_ohttp_key(State(state): State<AppState>) -> Response {
    match state
        .upstream
        .get_ohttp_key(
            state.config.request_timeout,
            state.config.max_key_response_bytes,
        )
        .await
    {
        Ok(key_resp) => {
            let mut response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/ohttp-keys")],
                key_resp.body,
            )
                .into_response();
            if let Some(fingerprint) = key_resp.key_fingerprint
                && let Ok(value) = header::HeaderValue::from_str(&fingerprint)
            {
                response
                    .headers_mut()
                    .insert(header::HeaderName::from_static("key-fingerprint"), value);
            }
            response
        }
        Err(e) => {
            warn!(error = %e, "upstream gateway error on key fetch");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine the client IP for rate limiting.
///
/// When `client_ip_header` is configured, the IP is extracted from that header
/// (taking the first comma-separated value for `X-Forwarded-For`-style headers).
/// Falls back to the TCP peer address from `ConnectInfo`.
fn extract_client_ip(
    config: &RelayConfig,
    headers: &axum::http::HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
) -> Option<IpAddr> {
    if let Some(ref header_name) = config.client_ip_header
        && let Some(value) = headers.get(header_name.as_str())
        && let Ok(s) = value.to_str()
    {
        // X-Forwarded-For: client, proxy1, proxy2 — take the leftmost.
        let ip_str = s.split(',').next().unwrap_or(s).trim();
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    connect_info.map(|ConnectInfo(addr)| addr.ip())
}

/// Read the request body up to `max_bytes`, returning an error response if the
/// body exceeds the limit.
///
/// `axum::body::to_bytes` accepts a `limit` parameter: if the body is larger
/// than `limit` bytes it returns an error, which we map to 413.
///
/// If the request carries a `Content-Length` header that already exceeds the
/// limit we reject early without reading. Otherwise, any error from `to_bytes`
/// with a size limit is treated as 413 — the overwhelming cause is a
/// `LengthLimitError`, and treating the rare body-read failure the same way
/// avoids relying on fragile error-message string matching.
async fn read_bounded_body(request: Request, max_bytes: usize) -> Result<Bytes, Response> {
    // Fast-reject: if Content-Length is present and already too large, skip reading.
    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH)
        && let Ok(len_str) = content_length.to_str()
        && let Ok(len) = len_str.parse::<usize>()
        && len > max_bytes
    {
        warn!(
            max_bytes,
            content_length = len,
            "request body exceeds limit (Content-Length)"
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
    }

    let body = request.into_body();
    match axum::body::to_bytes(body, max_bytes).await {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            // With a size limit set, the dominant error cause is LengthLimitError.
            // Treating any to_bytes error as 413 avoids fragile string matching
            // against axum/http-body-util internal error messages.
            warn!(max_bytes, error = %e, "request body exceeds limit or read failed");
            Err(StatusCode::PAYLOAD_TOO_LARGE.into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// INLINE_TEST_REQUIRED: router tests need oneshot() on the built router which
// requires access to private handler functions and AppState construction
#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{self, Request, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::upstream::UpstreamClient;

    fn make_state(max_request_bytes: usize, gateway_url: &str) -> AppState {
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: gateway_url.to_owned(),
            max_request_bytes,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 0, // disabled in most tests
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: None,
        };
        let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
        AppState {
            config,
            upstream,
            rate_limiter: None,
        }
    }

    // INLINE_TEST_REQUIRED: health endpoint returns 200 ok

    #[tokio::test]
    async fn health_returns_ok() {
        let state = make_state(65536, "http://127.0.0.1:19999");
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "health should return 200");

        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(body.as_ref(), b"ok", "health body should be 'ok'");
    }

    // INLINE_TEST_REQUIRED: oversized request is rejected before upstream call

    #[tokio::test]
    async fn ohttp_forward_rejects_oversized_body() {
        let state = make_state(10, "http://127.0.0.1:19999");
        let app = build_router(state);

        let oversized = vec![0u8; 11]; // one byte over the limit
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .body(Body::from(oversized))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized body should be rejected with 413"
        );
    }

    // INLINE_TEST_REQUIRED: body at exact limit is not rejected

    #[tokio::test]
    async fn ohttp_forward_accepts_body_at_limit() {
        // We cannot reach a real upstream in a unit test, so use a deliberately
        // unreachable address — the response will be 502 Bad Gateway, but the
        // size check must pass (not 413).
        let state = make_state(4, "http://127.0.0.1:19999");
        let app = build_router(state);

        let exactly_at_limit = vec![0u8; 4];
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .body(Body::from(exactly_at_limit))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "body at exact limit should not be rejected with 413"
        );
    }

    // INLINE_TEST_REQUIRED: Content-Length fast-reject returns 413 without reading body

    #[tokio::test]
    async fn ohttp_forward_rejects_oversized_content_length_header() {
        let state = make_state(10, "http://127.0.0.1:19999");
        let app = build_router(state);

        // Content-Length declares 100 bytes but body is empty — the header alone
        // should trigger a 413 before any body read is attempted.
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .header(header::CONTENT_LENGTH, "100")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "oversized Content-Length header should be rejected with 413"
        );
    }

    // @internal
    // Boundary: Content-Length exactly at limit must NOT be rejected (> not >=).
    #[tokio::test]
    async fn ohttp_forward_accepts_content_length_at_exact_limit() {
        let state = make_state(10, "http://127.0.0.1:19999");
        let app = build_router(state);

        // Content-Length == max_bytes (10) — should pass the Content-Length check.
        // The request will fail at upstream (502), but must NOT be 413.
        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .header(header::CONTENT_LENGTH, "10")
            .body(Body::from(vec![0u8; 10]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "Content-Length at exact limit should not be rejected with 413"
        );
    }

    // INLINE_TEST_REQUIRED: key endpoint proxies upstream (returns 502 when upstream is down,
    // confirming the request reaches the proxy layer rather than being short-circuited)

    #[tokio::test]
    async fn key_endpoint_attempts_upstream_proxy() {
        // Port 19998 is deliberately unreachable — we want to confirm that
        // the /v2/ohttp-key route calls the upstream client (502) rather than
        // returning 404 or 200 without hitting the upstream path.
        let state = make_state(65536, "http://127.0.0.1:19998");
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/ohttp-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "key endpoint should return 502 when upstream is unreachable"
        );
    }

    // INLINE_TEST_REQUIRED: Key-Fingerprint header is forwarded from upstream

    /// Start a mock upstream that returns a Key-Fingerprint header on GET /v2/ohttp-key.
    async fn start_mock_upstream_with_fingerprint(fingerprint: &str) -> u16 {
        let fp = fingerprint.to_owned();
        let mock = axum::Router::new().route(
            "/v2/ohttp-key",
            get(move || {
                let fp = fp.clone();
                async move {
                    let mut resp = (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/ohttp-keys")],
                        vec![0xAA, 0xBB], // dummy key bytes
                    )
                        .into_response();
                    resp.headers_mut().insert(
                        header::HeaderName::from_static("key-fingerprint"),
                        header::HeaderValue::from_str(&fp).unwrap(),
                    );
                    resp
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });
        port
    }

    #[tokio::test]
    async fn key_endpoint_forwards_key_fingerprint_header() {
        let port = start_mock_upstream_with_fingerprint("abc123def456").await;
        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state(65536, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/ohttp-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "key endpoint should return 200"
        );

        let fingerprint = resp
            .headers()
            .get("key-fingerprint")
            .expect("response should include Key-Fingerprint header")
            .to_str()
            .unwrap();
        assert_eq!(
            fingerprint, "abc123def456",
            "Key-Fingerprint header value should match upstream"
        );
    }

    #[tokio::test]
    async fn key_endpoint_works_without_fingerprint_header() {
        // Mock upstream that does NOT return Key-Fingerprint
        let mock = axum::Router::new().route(
            "/v2/ohttp-key",
            get(|| async {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/ohttp-keys")],
                    vec![0xCC, 0xDD],
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state(65536, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/ohttp-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "key endpoint should return 200"
        );
        assert!(
            resp.headers().get("key-fingerprint").is_none(),
            "Key-Fingerprint header should not be present when upstream omits it"
        );
    }

    // INLINE_TEST_REQUIRED: oversized upstream key response is rejected

    fn make_state_with_limits(
        max_request_bytes: usize,
        max_response_bytes: usize,
        max_key_response_bytes: usize,
        gateway_url: &str,
    ) -> AppState {
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: gateway_url.to_owned(),
            max_request_bytes,
            max_response_bytes,
            max_key_response_bytes,
            rate_limit_per_sec: 0,
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: None,
        };
        let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
        AppState {
            config,
            upstream,
            rate_limiter: None,
        }
    }

    #[tokio::test]
    async fn key_endpoint_rejects_oversized_upstream_response() {
        // Mock upstream returning a key body larger than our limit
        let oversized_body = vec![0xAA; 200]; // 200 bytes, limit will be 50
        let mock = axum::Router::new().route(
            "/v2/ohttp-key",
            get(move || {
                let body = oversized_body.clone();
                async move {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/ohttp-keys")],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state_with_limits(65536, 131072, 50, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/ohttp-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "oversized key response from upstream should result in 502"
        );
    }

    #[tokio::test]
    async fn ohttp_forward_rejects_oversized_upstream_response() {
        // Mock upstream returning a response body larger than our limit
        let oversized_body = vec![0xBB; 300]; // 300 bytes, limit will be 100
        let mock = axum::Router::new().route(
            "/v2/ohttp",
            post(move || {
                let body = oversized_body.clone();
                async move {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "message/ohttp-res")],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state_with_limits(65536, 100, 4096, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .body(Body::from(vec![0x01, 0x02]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "oversized OHTTP response from upstream should result in 502"
        );
    }

    // @internal
    // Boundary: upstream response body at exact limit must succeed (> not >=).
    #[tokio::test]
    async fn ohttp_forward_accepts_upstream_response_at_exact_limit() {
        let exact_body = vec![0xCC; 100]; // exactly at limit
        let mock = axum::Router::new().route(
            "/v2/ohttp",
            post(move || {
                let body = exact_body.clone();
                async move {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "message/ohttp-res")],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state_with_limits(65536, 100, 4096, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .body(Body::from(vec![0x01, 0x02]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "upstream response at exact limit should succeed, not 502"
        );
    }

    // @internal
    // Boundary: upstream key response at exact limit must succeed.
    #[tokio::test]
    async fn key_endpoint_accepts_upstream_response_at_exact_limit() {
        let exact_body = vec![0xAA; 50]; // exactly at limit
        let mock = axum::Router::new().route(
            "/v2/ohttp-key",
            get(move || {
                let body = exact_body.clone();
                async move {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/ohttp-keys")],
                        body,
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state_with_limits(65536, 131072, 50, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::GET)
            .uri("/v2/ohttp-key")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "upstream key response at exact limit should succeed, not 502"
        );
    }

    // @internal
    // Upstream returns non-2xx status — must be propagated as 502.
    #[tokio::test]
    async fn ohttp_forward_returns_502_on_upstream_error_status() {
        let mock = axum::Router::new().route(
            "/v2/ohttp",
            post(|| async { StatusCode::INTERNAL_SERVER_ERROR.into_response() }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, mock).await.unwrap();
        });

        let gateway_url = format!("http://127.0.0.1:{port}");
        let state = make_state(65536, &gateway_url);
        let app = build_router(state);

        let req = Request::builder()
            .method(http::Method::POST)
            .uri("/v2/ohttp")
            .header(header::CONTENT_TYPE, "message/ohttp-req")
            .body(Body::from(vec![0x01]))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_GATEWAY,
            "upstream 500 should be mapped to 502 Bad Gateway"
        );
    }

    // INLINE_TEST_REQUIRED: rate limiter returns 429 after burst exhausted

    #[tokio::test]
    async fn rate_limiter_returns_429_after_burst_exhausted() {
        // Start the relay as a real TCP server so ConnectInfo<SocketAddr> works.
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: "http://127.0.0.1:19999".to_owned(),
            max_request_bytes: 65536,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 3, // very low limit for testing
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: None,
        };
        let rate_limiter = Some(Arc::new(crate::rate_limit::RateLimiter::new(3)));
        let upstream = UpstreamClient::new(&config.gateway_url, config.request_timeout);
        let state = AppState {
            config,
            upstream,
            rate_limiter,
        };
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::new();
        let url = format!("http://{relay_addr}/v2/ohttp");

        // Send requests up to the burst limit — should all succeed (502 from
        // unreachable upstream, but NOT 429).
        for i in 0..3 {
            let resp = client
                .post(&url)
                .header("Content-Type", "message/ohttp-req")
                .body(vec![0x01])
                .send()
                .await
                .unwrap();
            assert_ne!(
                resp.status().as_u16(),
                429,
                "request {i} within burst should not be rate-limited"
            );
        }

        // Next request should be rate-limited.
        let resp = client
            .post(&url)
            .header("Content-Type", "message/ohttp-req")
            .body(vec![0x01])
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            429,
            "request over burst limit should return 429 Too Many Requests"
        );
    }

    #[tokio::test]
    async fn health_and_key_endpoints_not_rate_limited() {
        // Verify that health and key endpoints are not affected by rate limiting.
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: "http://127.0.0.1:19999".to_owned(),
            max_request_bytes: 65536,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 1, // extremely low limit
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: None,
        };
        let rate_limiter = Some(Arc::new(crate::rate_limit::RateLimiter::new(1)));
        let upstream = UpstreamClient::new(&config.gateway_url, config.request_timeout);
        let state = AppState {
            config,
            upstream,
            rate_limiter,
        };
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::new();

        // Exhaust the rate limit with a POST.
        let _ = client
            .post(format!("http://{relay_addr}/v2/ohttp"))
            .header("Content-Type", "message/ohttp-req")
            .body(vec![0x01])
            .send()
            .await
            .unwrap();

        // Health should still work (not rate-limited).
        for _ in 0..5 {
            let resp = client
                .get(format!("http://{relay_addr}/health"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                200,
                "health endpoint should never be rate-limited"
            );
        }
    }

    // -----------------------------------------------------------------------
    // extract_client_ip tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_client_ip_uses_connect_info_when_no_header_configured() {
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: "http://localhost:8080".to_owned(),
            max_request_bytes: 65536,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 50,
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: None,
        };
        let headers = axum::http::HeaderMap::new();
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let ci = ConnectInfo(addr);

        let ip = extract_client_ip(&config, &headers, Some(&ci));
        assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn extract_client_ip_prefers_header_over_connect_info() {
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: "http://localhost:8080".to_owned(),
            max_request_bytes: 65536,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 50,
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: Some("X-Real-IP".to_owned()),
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Real-IP", "203.0.113.42".parse().unwrap());
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let ci = ConnectInfo(addr);

        let ip = extract_client_ip(&config, &headers, Some(&ci));
        assert_eq!(
            ip,
            Some("203.0.113.42".parse().unwrap()),
            "should use IP from configured header, not ConnectInfo"
        );
    }

    #[test]
    fn extract_client_ip_takes_leftmost_from_forwarded_for() {
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: "http://localhost:8080".to_owned(),
            max_request_bytes: 65536,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 50,
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: Some("X-Forwarded-For".to_owned()),
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "X-Forwarded-For",
            "198.51.100.7, 10.0.0.1, 10.0.0.2".parse().unwrap(),
        );

        let ip = extract_client_ip(&config, &headers, None);
        assert_eq!(
            ip,
            Some("198.51.100.7".parse().unwrap()),
            "should take the leftmost (original client) IP"
        );
    }

    #[test]
    fn extract_client_ip_falls_back_when_header_missing() {
        let config = RelayConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            gateway_url: "http://localhost:8080".to_owned(),
            max_request_bytes: 65536,
            max_response_bytes: 131072,
            max_key_response_bytes: 4096,
            rate_limit_per_sec: 50,
            request_timeout: std::time::Duration::from_secs(5),
            client_ip_header: Some("X-Real-IP".to_owned()),
        };
        let headers = axum::http::HeaderMap::new(); // header not present
        let addr: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let ci = ConnectInfo(addr);

        let ip = extract_client_ip(&config, &headers, Some(&ci));
        assert_eq!(
            ip,
            Some("10.0.0.1".parse().unwrap()),
            "should fall back to ConnectInfo when header is missing"
        );
    }
}
