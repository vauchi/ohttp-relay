// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Axum router and HTTP handler implementations.
//!
//! Production endpoints:
//! - `POST /v2/ohttp`     — forward encrypted OHTTP blob to upstream gateway
//! - `GET  /v2/ohttp-key` — proxy the OHTTP key from the upstream gateway
//! - `GET  /health`       — local health check (no upstream call)
//!
//! Security invariants enforced here:
//! - Client IP is used only for rate limiting — never logged or forwarded.
//! - No identifying headers are forwarded upstream or downstream.
//! - Request bodies above `max_request_bytes` are rejected before forwarding.

use std::sync::Arc;
#[cfg(feature = "e2e-faults")]
use std::sync::atomic::{AtomicBool, Ordering};

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
    /// E2E-only one-shot opaque-forward controller. Absent from production builds.
    #[cfg(feature = "e2e-faults")]
    pub e2e_fault_controller: Option<Arc<AtomicBool>>,
}

#[cfg(feature = "e2e-faults")]
impl AppState {
    /// Enable the E2E-only opaque-forward fault controller without arming it.
    pub fn with_e2e_fault_controller(mut self) -> Self {
        self.e2e_fault_controller = Some(Arc::new(AtomicBool::new(false)));
        self
    }

    /// Duplicate the next opaque forward and preserve its original response.
    pub fn with_duplicate_first_forward(self) -> Self {
        let state = self.with_e2e_fault_controller();
        state
            .e2e_fault_controller
            .as_ref()
            .expect("E2E fault controller is initialized")
            .store(true, Ordering::SeqCst);
        state
    }
}

/// Build the router with all routes wired up.
pub fn build_router(state: AppState) -> Router {
    let router = Router::new()
        .route("/health", get(handle_health))
        .route("/v2/ohttp", post(handle_ohttp_forward))
        .route("/v2/ohttp-key", get(handle_ohttp_key));
    #[cfg(feature = "e2e-faults")]
    let router = router.route(
        "/__e2e/duplicate-next-forward",
        post(handle_e2e_duplicate_next_forward),
    );
    router.with_state(state)
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

    #[cfg(feature = "e2e-faults")]
    let duplicate_body = state
        .e2e_fault_controller
        .as_ref()
        .filter(|remaining| remaining.swap(false, Ordering::SeqCst))
        .map(|_| body.clone());

    let first_response = state
        .upstream
        .post_ohttp(body, state.config.max_response_bytes)
        .await;

    #[cfg(feature = "e2e-faults")]
    if let Some(duplicate_body) = duplicate_body {
        let _ = state
            .upstream
            .post_ohttp(duplicate_body, state.config.max_response_bytes)
            .await;
    }

    match first_response {
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

#[cfg(feature = "e2e-faults")]
async fn handle_e2e_duplicate_next_forward(State(state): State<AppState>) -> StatusCode {
    let Some(controller) = state.e2e_fault_controller else {
        return StatusCode::NOT_FOUND;
    };
    controller.store(true, Ordering::SeqCst);
    StatusCode::NO_CONTENT
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
