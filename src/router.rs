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

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tracing::{debug, warn};

use crate::config::RelayConfig;
use crate::key_cache::KeyConfigCache;
use crate::rate_limit::RateLimiter;
use crate::request::RequestContext;
use crate::upstream::UpstreamClient;

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub config: RelayConfig,
    pub upstream: UpstreamClient,
    /// Per-IP rate limiter for the OHTTP forward endpoint. `None` if disabled.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// TTL cache for upstream OHTTP key config. `None` if disabled (TTL = 0).
    pub key_cache: Option<Arc<KeyConfigCache>>,
}

/// Build the router with all routes wired up.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/v2/ohttp", post(handle_ohttp_forward))
        .route("/v2/ohttp-key", get(handle_ohttp_key))
        .with_state(state)
}

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
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.forward")]
async fn handle_ohttp_forward(State(state): State<AppState>, context: RequestContext) -> Response {
    let body = context.into_body();

    debug!(
        gateway_url = %state.config.gateway_url,
        body_len = body.len(),
        "forwarding OHTTP blob to upstream gateway"
    );

    match state
        .upstream
        .post_ohttp(body, state.config.max_response_bytes)
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
///
/// Responses are cached with a configurable TTL to avoid a thundering herd
/// on the upstream during mass client bootstrap.
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.key")]
async fn handle_ohttp_key(State(state): State<AppState>) -> Response {
    if let Some(ref cache) = state.key_cache
        && let Some((body, fingerprint)) = cache.get()
    {
        return build_key_response(body, fingerprint);
    }

    debug!(
        gateway_url = %state.config.gateway_url,
        "fetching OHTTP key from upstream gateway"
    );

    match state
        .upstream
        .get_ohttp_key(state.config.max_key_response_bytes)
        .await
    {
        Ok(key_resp) => {
            if let Some(ref cache) = state.key_cache {
                cache.set(key_resp.body.clone(), key_resp.key_fingerprint.clone());
            }
            build_key_response(key_resp.body, key_resp.key_fingerprint)
        }
        Err(e) => {
            warn!(error = %e, "upstream gateway error on key fetch");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Build a `200 OK` response with the OHTTP key config body and optional fingerprint.
fn build_key_response(body: Bytes, fingerprint: Option<String>) -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/ohttp-keys")],
        body,
    )
        .into_response();
    if let Some(fp) = fingerprint
        && let Ok(value) = header::HeaderValue::from_str(&fp)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("key-fingerprint"), value);
    }
    response
}
