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
        .post_ohttp(body, state.config.request_timeout)
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
        .get_ohttp_key(state.config.request_timeout)
        .await
    {
        Ok(key_bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/ohttp-keys")],
            key_bytes,
        )
            .into_response(),
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
async fn read_bounded_body(request: Request, max_bytes: usize) -> Result<Bytes, Response> {
    let body = request.into_body();
    match axum::body::to_bytes(body, max_bytes).await {
        Ok(bytes) => Ok(bytes),
        Err(e) => {
            // to_bytes returns an error when the body exceeds the limit.
            let msg = e.to_string();
            if msg.contains("length limit")
                || msg.contains("too large")
                || msg.contains("bytes remaining")
            {
                warn!(max_bytes, "request body exceeds limit");
                Err(StatusCode::PAYLOAD_TOO_LARGE.into_response())
            } else {
                warn!(error = %e, "failed to read request body");
                Err(StatusCode::BAD_REQUEST.into_response())
            }
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
}
