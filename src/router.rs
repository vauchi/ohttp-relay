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
//! - Client IP is never read, logged, or forwarded.
//! - No identifying headers are forwarded upstream or downstream.
//! - Request bodies above `max_request_bytes` are rejected before forwarding.

use axum::{
    Router,
    body::Bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tracing::{debug, warn};

use crate::config::RelayConfig;
use crate::upstream::UpstreamClient;

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub config: RelayConfig,
    pub upstream: UpstreamClient,
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
async fn handle_ohttp_forward(State(state): State<AppState>, request: Request) -> Response {
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
            request_timeout: std::time::Duration::from_secs(5),
        };
        let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
        AppState { config, upstream }
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
            request_timeout: std::time::Duration::from_secs(5),
        };
        let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
        AppState { config, upstream }
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
}
