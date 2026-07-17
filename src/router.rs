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
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tracing::{debug, warn};

#[cfg(feature = "e2e-faults")]
use tokio::{
    sync::oneshot,
    time::{Duration, timeout},
};

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
    pub e2e_fault_controller: Option<Arc<E2eFaultController>>,
}

#[cfg(feature = "e2e-faults")]
pub struct E2eFaultController {
    duplicate_next_forward: AtomicBool,
    reorder_next_forward: AtomicBool,
    pending_reorder: Mutex<Option<PendingReorder>>,
    next_reorder_id: AtomicU64,
}

#[cfg(feature = "e2e-faults")]
struct PendingReorder {
    id: u64,
    body: Bytes,
    response: oneshot::Sender<Response>,
}

#[cfg(feature = "e2e-faults")]
impl E2eFaultController {
    pub fn new() -> Self {
        Self {
            duplicate_next_forward: AtomicBool::new(false),
            reorder_next_forward: AtomicBool::new(false),
            pending_reorder: Mutex::new(None),
            next_reorder_id: AtomicU64::new(0),
        }
    }
}

#[cfg(feature = "e2e-faults")]
impl Default for E2eFaultController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "e2e-faults")]
impl AppState {
    /// Enable the E2E-only opaque-forward fault controller without arming it.
    pub fn with_e2e_fault_controller(mut self) -> Self {
        self.e2e_fault_controller = Some(Arc::new(E2eFaultController::new()));
        self
    }

    /// Duplicate the next opaque forward and preserve its original response.
    pub fn with_duplicate_first_forward(self) -> Self {
        let state = self.with_e2e_fault_controller();
        state
            .e2e_fault_controller
            .as_ref()
            .expect("E2E fault controller is initialized")
            .duplicate_next_forward
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
    #[cfg(feature = "e2e-faults")]
    let router = router.route(
        "/__e2e/reorder-next-forward",
        post(handle_e2e_reorder_next_forward),
    );
    #[cfg(feature = "e2e-faults")]
    let router = router.route("/__e2e/reorder-status", get(handle_e2e_reorder_status));
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
    if let Some(controller) = state.e2e_fault_controller.as_ref() {
        if controller
            .reorder_next_forward
            .swap(false, Ordering::SeqCst)
        {
            let id = controller.next_reorder_id.fetch_add(1, Ordering::SeqCst);
            let (response, receiver) = oneshot::channel();
            let queued = {
                let mut pending = controller.pending_reorder.lock().unwrap();
                if pending.is_some() {
                    false
                } else {
                    *pending = Some(PendingReorder { id, body, response });
                    true
                }
            };
            if !queued {
                return StatusCode::CONFLICT.into_response();
            }
            return match timeout(Duration::from_secs(15), receiver).await {
                Ok(Ok(response)) => response,
                Ok(Err(_)) | Err(_) => {
                    let mut pending = controller.pending_reorder.lock().unwrap();
                    if pending.as_ref().is_some_and(|pending| pending.id == id) {
                        pending.take();
                    }
                    StatusCode::GATEWAY_TIMEOUT.into_response()
                }
            };
        }

        let pending_reorder = controller.pending_reorder.lock().unwrap().take();
        if let Some(pending) = pending_reorder {
            let current_response = forward_ohttp_request(&state, body).await;
            let delayed_response = forward_ohttp_request(&state, pending.body).await;
            let _ = pending.response.send(delayed_response);
            return current_response;
        }
    }

    #[cfg(feature = "e2e-faults")]
    let duplicate_body = state.e2e_fault_controller.as_ref().and_then(|controller| {
        controller
            .duplicate_next_forward
            .swap(false, Ordering::SeqCst)
            .then(|| body.clone())
    });

    let first_response = forward_ohttp_request(&state, body).await;

    #[cfg(feature = "e2e-faults")]
    if let Some(duplicate_body) = duplicate_body {
        let _ = forward_ohttp_request(&state, duplicate_body).await;
    }

    first_response
}

async fn forward_ohttp_request(state: &AppState, body: Bytes) -> Response {
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

#[cfg(feature = "e2e-faults")]
async fn handle_e2e_duplicate_next_forward(State(state): State<AppState>) -> StatusCode {
    let Some(controller) = state.e2e_fault_controller else {
        return StatusCode::NOT_FOUND;
    };
    controller
        .duplicate_next_forward
        .store(true, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

#[cfg(feature = "e2e-faults")]
async fn handle_e2e_reorder_next_forward(State(state): State<AppState>) -> StatusCode {
    let Some(controller) = state.e2e_fault_controller else {
        return StatusCode::NOT_FOUND;
    };
    controller
        .reorder_next_forward
        .store(true, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

#[cfg(feature = "e2e-faults")]
async fn handle_e2e_reorder_status(State(state): State<AppState>) -> (StatusCode, &'static str) {
    let Some(controller) = state.e2e_fault_controller else {
        return (StatusCode::NOT_FOUND, "not found");
    };
    let status = if controller.pending_reorder.lock().unwrap().is_some() {
        "pending"
    } else {
        "idle"
    };
    (StatusCode::OK, status)
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
