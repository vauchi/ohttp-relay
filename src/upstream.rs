// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Upstream (gateway) HTTP client.
//!
//! Wraps reqwest to forward blobs and key requests to the vauchi-relay gateway.
//! All calls strip identifying headers — only the raw body is forwarded for
//! OHTTP blobs; key fetches carry no client-derived data at all.

use std::time::Duration;

use axum::body::Bytes;
use reqwest::Client;
use tracing::debug;

/// Thin wrapper around a reqwest client bound to a single gateway base URL.
#[derive(Clone)]
pub struct UpstreamClient {
    client: Client,
    gateway_url: String,
}

impl UpstreamClient {
    /// Create a new upstream client.
    ///
    /// `gateway_url` must have no trailing slash (validated by `RelayConfig`).
    /// `default_timeout` is used as the connection timeout for the underlying
    /// client pool; per-request timeouts are applied at call sites.
    pub fn new(gateway_url: &str, default_timeout: Duration) -> Self {
        let client = Client::builder()
            .timeout(default_timeout)
            // Never follow redirects — the gateway should respond directly.
            .redirect(reqwest::redirect::Policy::none())
            // Use rustls (already a dep via reqwest feature flag).
            .use_rustls_tls()
            .build()
            .expect("reqwest client construction should not fail");

        UpstreamClient {
            client,
            gateway_url: gateway_url.to_owned(),
        }
    }

    /// Forward an opaque OHTTP blob to the gateway's `POST /v2/ohttp`.
    ///
    /// Only the raw bytes are sent — no headers from the original client
    /// request are forwarded. The response body is returned verbatim.
    pub async fn post_ohttp(&self, body: Bytes, timeout: Duration) -> Result<Bytes, UpstreamError> {
        let url = format!("{}/v2/ohttp", self.gateway_url);
        debug!(url, body_len = body.len(), "POST upstream /v2/ohttp");

        let resp = self
            .client
            .post(&url)
            .timeout(timeout)
            .header(reqwest::header::CONTENT_TYPE, "message/ohttp-req")
            .body(body)
            .send()
            .await
            .map_err(UpstreamError::Request)?;

        if !resp.status().is_success() {
            return Err(UpstreamError::Status(resp.status().as_u16()));
        }

        resp.bytes().await.map_err(UpstreamError::Request)
    }

    /// Fetch the OHTTP key from the gateway's `GET /v2/ohttp-key`.
    ///
    /// No client-derived data is included in this request.
    /// Returns the key body and, if present, the `Key-Fingerprint` header value.
    pub async fn get_ohttp_key(
        &self,
        timeout: Duration,
    ) -> Result<OhttpKeyResponse, UpstreamError> {
        let url = format!("{}/v2/ohttp-key", self.gateway_url);
        debug!(url, "GET upstream /v2/ohttp-key");

        let resp = self
            .client
            .get(&url)
            .timeout(timeout)
            .send()
            .await
            .map_err(UpstreamError::Request)?;

        if !resp.status().is_success() {
            return Err(UpstreamError::Status(resp.status().as_u16()));
        }

        let key_fingerprint = resp
            .headers()
            .get("Key-Fingerprint")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        let body = resp.bytes().await.map_err(UpstreamError::Request)?;

        Ok(OhttpKeyResponse {
            body,
            key_fingerprint,
        })
    }
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
    /// A reqwest-level transport or timeout error.
    Request(reqwest::Error),
    /// The gateway returned a non-2xx status code.
    Status(u16),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Request(e) => write!(f, "upstream request error: {e}"),
            UpstreamError::Status(code) => write!(f, "upstream returned status {code}"),
        }
    }
}

impl std::error::Error for UpstreamError {}
