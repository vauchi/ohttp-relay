// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Axum router and HTTP handler implementations.
//!
//! Production endpoints:
//! - `POST /v2/ohttp`     — forward encrypted OHTTP blob to upstream gateway
//! - `GET  /v2/ohttp-key-signed` — proxy the gateway's signed key record
//! - `GET  /v2/ohttp-anchor-rollover` — proxy the gateway's anchor rollover chain
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
    http::{HeaderValue, StatusCode, header},
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
use crate::delayed::{Admission, Collected, DelayedForwarding, Ticket};
use crate::rate_limit::RateLimiter;
use crate::request::RequestContext;
use crate::signed_key_cache::SignedKeyCache;
use crate::upstream::{UpstreamClient, UpstreamError};

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub config: RelayConfig,
    pub upstream: UpstreamClient,
    /// Per-IP rate limiter for the OHTTP forward endpoint. `None` if disabled.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Window-bounded cache for the signed key record. `None` if disabled.
    pub signed_key_cache: Option<Arc<SignedKeyCache>>,
    /// Ticketed requests forwarded after a random delay (#628). `None`
    /// leaves the asynchronous routes unanswered (404).
    pub delayed: Option<Arc<DelayedForwarding>>,
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
        .route("/v2/ohttp-async", post(handle_ohttp_async_post))
        .route("/v2/ohttp-async/:ticket", get(handle_ohttp_async_collect))
        .route("/v2/ohttp-key-signed", get(handle_ohttp_key_signed))
        .route(
            "/v2/ohttp-anchor-rollover",
            get(handle_ohttp_anchor_rollover),
        );
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
/// to the client with no identifying headers added; the only header added is
/// the delay window, the same for every client.
///
/// Rate-limited per source IP when a rate limiter is configured. The IP is
/// used only for rate limiting — it is never logged or forwarded.
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.forward")]
async fn handle_ohttp_forward(State(state): State<AppState>, context: RequestContext) -> Response {
    let window = advertised_delay_window(&state);
    let mut response = forward_synchronously(state, context).await;
    if let Some(window) = window {
        response
            .headers_mut()
            .insert(DELAY_WINDOW_HEADER, HeaderValue::from(window));
    }
    response
}

/// Advertises the delayed path (design D-F6, amended 2026-10-16): no relay
/// directory exists yet, so clients learn W from the synchronous answers
/// every sync already receives.
const DELAY_WINDOW_HEADER: &str = "vauchi-ohttp-delay-window";

/// W in whole seconds, rounded up; none without delayed forwarding or with
/// a zero window.
fn advertised_delay_window(state: &AppState) -> Option<u64> {
    let max = state.delayed.as_ref()?.policy().max();
    let seconds = max.as_secs() + u64::from(max.subsec_nanos() > 0);
    (seconds > 0).then_some(seconds)
}

async fn forward_synchronously(state: AppState, context: RequestContext) -> Response {
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

/// Header carrying the client-chosen ticket of an asynchronous request.
const TICKET_HEADER: &str = "vauchi-ticket";

/// `POST /v2/ohttp-async` — accept a ticketed request, forward it after a
/// random delay and hold the answer for collection (#628).
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.async_post")]
async fn handle_ohttp_async_post(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    context: RequestContext,
) -> Response {
    let Some(delayed) = state.delayed.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(ticket) = headers
        .get(TICKET_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(Ticket::parse)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match delayed.admit(ticket) {
        Admission::Duplicate => return StatusCode::CONFLICT.into_response(),
        Admission::Full => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Admission::Accepted => {}
    }
    let body = context.into_body();
    let delay = delayed.policy().sample();
    debug!(
        body_len = body.len(),
        "holding ticketed OHTTP request for a delayed forward"
    );
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        debug!("forwarding delayed OHTTP request to upstream gateway");
        let (status, answer) = match state
            .upstream
            .post_ohttp(body, state.config.max_response_bytes)
            .await
        {
            Ok(answer) => (StatusCode::OK, answer),
            Err(e) => {
                warn!(error = %e, "upstream gateway error on delayed OHTTP forward");
                (StatusCode::BAD_GATEWAY, Bytes::new())
            }
        };
        delayed.complete(ticket, status, answer);
    });
    StatusCode::ACCEPTED.into_response()
}

/// `GET /v2/ohttp-async/{ticket}` — hand over a held answer once.
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.async_collect")]
async fn handle_ohttp_async_collect(
    State(state): State<AppState>,
    axum::extract::Path(ticket): axum::extract::Path<String>,
) -> Response {
    let Some(delayed) = state.delayed.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(ticket) = Ticket::parse(&ticket) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let collected = delayed.collect(ticket);
    debug!(
        outcome = match &collected {
            Collected::Ready { .. } => "ready",
            Collected::Pending => "pending",
            Collected::Unknown => "unknown",
        },
        "ticketed OHTTP answer collected"
    );
    match collected {
        Collected::Ready { status, body } if status == StatusCode::OK => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "message/ohttp-res")],
            body,
        )
            .into_response(),
        Collected::Ready { status, .. } => status.into_response(),
        Collected::Pending => (StatusCode::ACCEPTED, [(header::RETRY_AFTER, "60")]).into_response(),
        Collected::Unknown => StatusCode::NOT_FOUND.into_response(),
    }
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

/// `GET /v2/ohttp-key-signed` — proxy the gateway's signed key record
/// (#288). Clients verify it; the relay only bounds its cache by the window
/// it signs. A 503 ("no signed key yet") passes through so clients can tell
/// it from an unreachable gateway; nothing but a 200 is cached.
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.key_signed")]
async fn handle_ohttp_key_signed(State(state): State<AppState>) -> Response {
    if let Some(body) = state
        .signed_key_cache
        .as_ref()
        .and_then(|cache| cache.get())
    {
        return signed_key_response(body);
    }
    match state
        .upstream
        .get_signed_key(state.config.max_key_response_bytes)
        .await
    {
        Ok(body) => {
            if let Some(ref cache) = state.signed_key_cache {
                cache.set(body.clone());
            }
            signed_key_response(body)
        }
        Err(UpstreamError::Status(503)) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(e) => {
            warn!(error = %e, "upstream gateway error on signed key fetch");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

fn signed_key_response(body: Bytes) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/vnd.vauchi.ohttp-key-signed",
        )],
        body,
    )
        .into_response()
}

/// `GET /v2/ohttp-anchor-rollover` — proxy the gateway's anchor rollover
/// chain (#288 decision 0.13). Uncached: clients ask only after their anchor
/// stopped verifying, and they verify the chain themselves. A 404 ("no
/// rollover") passes through so clients keep their anchor.
#[tracing::instrument(level = "debug", skip_all, name = "ohttp_relay.anchor_rollover")]
async fn handle_ohttp_anchor_rollover(State(state): State<AppState>) -> Response {
    match state.upstream.get_anchor_rollover().await {
        Ok(body) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/vnd.vauchi.ohttp-anchor-rollover",
            )],
            body,
        )
            .into_response(),
        Err(UpstreamError::Status(404)) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            warn!(error = %e, "upstream gateway error on anchor rollover fetch");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}
