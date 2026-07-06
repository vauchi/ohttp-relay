// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Upstream (gateway) HTTP client.
//!
//! Wraps a blocking `ureq` agent to forward blobs and key requests to the
//! vauchi-relay gateway. All calls strip identifying headers — only the raw
//! body is forwarded for OHTTP blobs; key fetches carry no client-derived data
//! at all.
//!
//! `ureq` is intentionally sync; the async router spawns each upstream call
//! onto tokio's blocking pool so the runtime is never blocked.

use std::io::Read;
use std::time::Duration;

use axum::body::Bytes;
use tracing::debug;

/// Thin wrapper around a `ureq` agent bound to a single gateway base URL.
#[derive(Clone)]
pub struct UpstreamClient {
    agent: ureq::Agent,
    gateway_url: String,
}

impl UpstreamClient {
    /// Create a new upstream client.
    ///
    /// `gateway_url` must have no trailing slash (validated by `RelayConfig`).
    /// `default_timeout` is used as the global timeout for the underlying
    /// agent; per-request timeouts are applied at call sites.
    pub fn new(gateway_url: &str, default_timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(default_timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build();

        let agent = config.new_agent();

        UpstreamClient {
            agent,
            gateway_url: gateway_url.to_owned(),
        }
    }

    /// Forward an opaque OHTTP blob to the gateway's `POST /v2/ohttp`.
    ///
    /// Only the raw bytes are sent — no headers from the original client
    /// request are forwarded. The response body is returned verbatim.
    ///
    /// `max_response_bytes` limits how much data we read from the upstream
    /// response, protecting against a compromised upstream returning gigabytes.
    pub async fn post_ohttp(
        &self,
        body: Bytes,
        max_response_bytes: usize,
    ) -> Result<Bytes, UpstreamError> {
        let url = format!("{}/v2/ohttp", self.gateway_url);
        debug!(url, body_len = body.len(), "POST upstream /v2/ohttp");

        let agent = self.agent.clone();
        tokio::task::spawn_blocking(move || {
            let response = agent
                .post(&url)
                .header("Content-Type", "message/ohttp-req")
                .send(&*body)
                .map_err(|e| UpstreamError::Request(e.to_string()))?;

            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                return Err(UpstreamError::Status(status));
            }

            read_bounded_response(response, max_response_bytes)
        })
        .await
        .map_err(|e| UpstreamError::Request(e.to_string()))?
    }

    /// Fetch the OHTTP key from the gateway's `GET /v2/ohttp-key`.
    ///
    /// No client-derived data is included in this request.
    /// Returns the key body and, if present, the `Key-Fingerprint` header value.
    ///
    /// `max_key_response_bytes` limits key config reads (typically ~100 bytes,
    /// default limit 4 KiB).
    pub async fn get_ohttp_key(
        &self,
        max_key_response_bytes: usize,
    ) -> Result<OhttpKeyResponse, UpstreamError> {
        let url = format!("{}/v2/ohttp-key", self.gateway_url);
        debug!(url, "GET upstream /v2/ohttp-key");

        let agent = self.agent.clone();
        tokio::task::spawn_blocking(move || {
            let response = agent
                .get(&url)
                .call()
                .map_err(|e| UpstreamError::Request(e.to_string()))?;

            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                return Err(UpstreamError::Status(status));
            }

            let key_fingerprint = response
                .headers()
                .get("Key-Fingerprint")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned());

            let body = read_bounded_response(response, max_key_response_bytes)?;

            Ok(OhttpKeyResponse {
                body,
                key_fingerprint,
            })
        })
        .await
        .map_err(|e| UpstreamError::Request(e.to_string()))?
    }
}

/// Read a response body up to `max_bytes`, rejecting oversized responses.
///
/// Checks `Content-Length` first for a fast reject, then reads chunks
/// incrementally to detect oversized bodies without unbounded allocation.
fn read_bounded_response(
    response: ureq::http::Response<ureq::Body>,
    max_bytes: usize,
) -> Result<Bytes, UpstreamError> {
    if let Some(content_length) = response
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        && content_length > max_bytes as u64
    {
        return Err(UpstreamError::ResponseTooLarge {
            limit: max_bytes,
            actual: Some(content_length),
        });
    }

    let mut reader = response.into_body().into_reader();
    let mut buf = Vec::with_capacity(max_bytes.min(8192));
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|e| UpstreamError::Request(e.to_string()))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max_bytes {
            return Err(UpstreamError::ResponseTooLarge {
                limit: max_bytes,
                actual: None,
            });
        }
    }

    Ok(Bytes::from(buf))
}

/// Response from `get_ohttp_key` containing the key body and optional fingerprint header.
pub struct OhttpKeyResponse {
    /// The raw OHTTP key configuration bytes.
    pub body: Bytes,
    /// The `Key-Fingerprint` header value, if the upstream included it.
    pub key_fingerprint: Option<String>,
}

/// Errors from upstream gateway calls.
#[derive(Debug)]
pub enum UpstreamError {
    /// A ureq-level transport or timeout error.
    Request(String),
    /// The gateway returned a non-2xx status code.
    Status(u16),
    /// The upstream response body exceeded the configured limit.
    ResponseTooLarge { limit: usize, actual: Option<u64> },
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Request(e) => write!(f, "upstream request error: {e}"),
            UpstreamError::Status(code) => write!(f, "upstream returned status {code}"),
            UpstreamError::ResponseTooLarge { limit, actual } => {
                write!(f, "upstream response exceeds {limit} byte limit")?;
                if let Some(len) = actual {
                    write!(f, " (Content-Length: {len})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

// INLINE_TEST_REQUIRED: Display impls are private formatting — testing alongside the type definition
#[cfg(test)]
mod tests {
    use super::*;

    // @internal
    #[test]
    fn display_status_error() {
        let err = UpstreamError::Status(502);
        assert_eq!(err.to_string(), "upstream returned status 502");
    }

    // @internal
    #[test]
    fn display_response_too_large_without_content_length() {
        let err = UpstreamError::ResponseTooLarge {
            limit: 1024,
            actual: None,
        };
        assert_eq!(err.to_string(), "upstream response exceeds 1024 byte limit");
    }

    // @internal
    #[test]
    fn display_response_too_large_with_content_length() {
        let err = UpstreamError::ResponseTooLarge {
            limit: 1024,
            actual: Some(9999),
        };
        assert_eq!(
            err.to_string(),
            "upstream response exceeds 1024 byte limit (Content-Length: 9999)"
        );
    }
}
