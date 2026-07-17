// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(any(test, feature = "test-utils"))]

//! Shared test helpers for constructing relay state and driving real TCP
//! listeners in integration tests.

use std::sync::Arc;
use std::time::Duration;

use crate::config::RelayConfig;
use crate::rate_limit::RateLimiter;
use crate::router::AppState;
use crate::upstream::UpstreamClient;

/// Build an `AppState` with the given body limit and gateway URL.
///
/// Rate limiting and key caching are disabled; this is the minimal state
/// needed for most router integration tests.
pub fn build_test_state(max_request_bytes: usize, gateway_url: &str) -> AppState {
    let config = RelayConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        gateway_url: gateway_url.to_owned(),
        max_request_bytes,
        max_response_bytes: 131_072,
        max_key_response_bytes: 4_096,
        rate_limit_per_sec: 0, // disabled in most tests
        rate_limit_max_buckets: 100_000,
        request_timeout: Duration::from_secs(5),
        client_ip_header: None,
        client_ip_header_trusted_proxies: 0,
        key_cache_ttl: Duration::ZERO,
    };
    let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
    AppState {
        config,
        upstream,
        rate_limiter: None,
        key_cache: None,
        #[cfg(feature = "e2e-faults")]
        e2e_fault_controller: None,
    }
}

/// Build an `AppState` with independent request/response/key size limits.
pub fn build_test_state_with_limits(
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
        rate_limit_per_sec: 0,
        rate_limit_max_buckets: 100_000,
        request_timeout: Duration::from_secs(5),
        client_ip_header: None,
        client_ip_header_trusted_proxies: 0,
        key_cache_ttl: Duration::ZERO,
    };
    let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
    AppState {
        config,
        upstream,
        rate_limiter: None,
        key_cache: None,
        #[cfg(feature = "e2e-faults")]
        e2e_fault_controller: None,
    }
}

/// Build an `AppState` with a per-IP rate limiter enabled.
pub fn build_test_state_with_rate_limit(gateway_url: &str, rate_limit_per_sec: u32) -> AppState {
    let config = RelayConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        gateway_url: gateway_url.to_owned(),
        max_request_bytes: 65_536,
        max_response_bytes: 131_072,
        max_key_response_bytes: 4_096,
        rate_limit_per_sec,
        rate_limit_max_buckets: 100_000,
        request_timeout: Duration::from_secs(5),
        client_ip_header: None,
        client_ip_header_trusted_proxies: 0,
        key_cache_ttl: Duration::ZERO,
    };
    let rate_limiter = Some(Arc::new(RateLimiter::new(rate_limit_per_sec, 100_000)));
    let upstream = UpstreamClient::new(gateway_url, config.request_timeout);
    AppState {
        config,
        upstream,
        rate_limiter,
        key_cache: None,
        #[cfg(feature = "e2e-faults")]
        e2e_fault_controller: None,
    }
}

/// Minimal HTTP/1.1 client for tests that need to hit a real TCP listener.
///
/// Replaces the previous `reqwest` usage so the crate can drop that dependency.
pub mod test_client {
    use axum::body::Bytes;
    use http_body_util::Full;
    use hyper::Request;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    type HttpConnector = hyper_util::client::legacy::connect::HttpConnector;

    pub struct TestClient {
        client: Client<HttpConnector, Full<Bytes>>,
    }

    impl Default for TestClient {
        fn default() -> Self {
            Self::new()
        }
    }

    impl TestClient {
        pub fn new() -> Self {
            let connector = HttpConnector::new();
            let client = Client::builder(TokioExecutor::new()).build(connector);
            Self { client }
        }

        pub async fn post(
            &self,
            url: impl AsRef<str>,
            content_type: &str,
            body: Vec<u8>,
        ) -> hyper::Response<hyper::body::Incoming> {
            let request = Request::builder()
                .method("POST")
                .uri(url.as_ref())
                .header(hyper::header::CONTENT_TYPE, content_type)
                .body(Full::new(Bytes::from(body)))
                .expect("valid test request");
            self.client
                .request(request)
                .await
                .expect("test request should succeed")
        }

        pub async fn get(&self, url: impl AsRef<str>) -> hyper::Response<hyper::body::Incoming> {
            let request = Request::builder()
                .method("GET")
                .uri(url.as_ref())
                .body(Full::new(Bytes::new()))
                .expect("valid test request");
            self.client
                .request(request)
                .await
                .expect("test request should succeed")
        }
    }
}
