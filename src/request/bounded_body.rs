// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bounded request body reading.
//!
//! Request bodies above the configured limit are rejected before forwarding.
//! Logging of limit violations is the responsibility of the caller.

use axum::{body::Bytes, extract::Request, http::header};

/// Error returned when a request body cannot be read because it exceeds the
/// configured size limit.
#[derive(Debug)]
pub enum BodyLimitError {
    /// The request's `Content-Length` header already exceeds the limit.
    ContentLengthExceeded { content_length: usize },
    /// Reading the body failed, typically because it exceeded the size limit.
    BodyReadFailed { source: axum::Error },
}

impl BodyLimitError {
    /// Returns the kind of limit violation as a short string for metrics or
    /// logging.
    pub fn kind(&self) -> &'static str {
        match self {
            BodyLimitError::ContentLengthExceeded { .. } => "content_length",
            BodyLimitError::BodyReadFailed { .. } => "body_read",
        }
    }
}

/// Read the request body up to `max_bytes`, returning an error if the
/// body exceeds the limit.
///
/// `axum::body::to_bytes` accepts a `limit` parameter: if the body is larger
/// than `limit` bytes it returns an error, which the caller should map to 413.
///
/// If the request carries a `Content-Length` header that already exceeds the
/// limit we reject early without reading. Otherwise, any error from `to_bytes`
/// with a size limit is treated as a limit violation — the overwhelming cause
/// is a `LengthLimitError`, and treating the rare body-read failure the same
/// avoids relying on fragile error-message string matching.
pub async fn read_bounded_body(
    request: Request,
    max_bytes: usize,
) -> Result<Bytes, BodyLimitError> {
    // Fast-reject: if Content-Length is present and already too large, skip reading.
    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH)
        && let Ok(len_str) = content_length.to_str()
        && let Ok(len) = len_str.parse::<usize>()
        && len > max_bytes
    {
        return Err(BodyLimitError::ContentLengthExceeded {
            content_length: len,
        });
    }

    let body = request.into_body();
    match axum::body::to_bytes(body, max_bytes).await {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(BodyLimitError::BodyReadFailed { source: e }),
    }
}
