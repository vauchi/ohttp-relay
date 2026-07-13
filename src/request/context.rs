// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Axum extractor that performs all request preprocessing for the OHTTP forward
//! endpoint.
//!
//! `RequestContext` combines:
//! - client-IP extraction for rate limiting,
//! - per-IP rate-limit enforcement,
//! - bounded body reading.
//!
//! This keeps `handle_ohttp_forward` focused on upstream forwarding and response
//! mapping.

use std::net::SocketAddr;

use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRef, FromRequest, Request};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use tracing::warn;

use crate::router::AppState;

use super::{BodyLimitError, extract_client_ip, read_bounded_body};

/// Preprocessed request context for the OHTTP forward endpoint.
///
/// Constructed via the Axum `FromRequest` extractor. If rate limiting or body
/// reading fails, the extractor returns the appropriate HTTP error response
/// directly.
#[derive(Debug)]
pub struct RequestContext {
    body: Bytes,
}

impl RequestContext {
    /// Consume the context and return the bounded request body.
    pub fn into_body(self) -> Bytes {
        self.body
    }
}

#[async_trait]
impl<S> FromRequest<S> for RequestContext
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        let connect_info = req.extensions().get::<ConnectInfo<SocketAddr>>().copied();

        if let Some(ref limiter) = state.rate_limiter {
            let client_ip = extract_client_ip(&state.config, req.headers(), connect_info.as_ref());
            if let Some(ip) = client_ip
                && !limiter.check(ip)
            {
                return Err(StatusCode::TOO_MANY_REQUESTS.into_response());
            }
        }

        let max = state.config.max_request_bytes;
        let body = match read_bounded_body(req, max).await {
            Ok(b) => b,
            Err(BodyLimitError::ContentLengthExceeded { content_length }) => {
                warn!(
                    max_bytes = max,
                    content_length, "request body exceeds limit (Content-Length)"
                );
                return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
            }
            Err(BodyLimitError::BodyReadFailed { source }) => {
                warn!(
                    max_bytes = max,
                    error = %source,
                    "request body exceeds limit or read failed"
                );
                return Err(StatusCode::PAYLOAD_TOO_LARGE.into_response());
            }
        };

        Ok(RequestContext { body })
    }
}
