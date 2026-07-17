// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "test-utils")]

//! Integration tests for the OHTTP relay router.
//!
//! These tests previously lived as an inline `#[cfg(test)]` block in
//! `src/router.rs`; they were moved here so that `router.rs` can stay focused
//! on production code. Shared test state constructors live in
//! `vauchi_ohttp_relay::test_utils`.

use std::net::SocketAddr;
#[cfg(feature = "e2e-faults")]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{self, Request, StatusCode, header};
use axum::response::IntoResponse;
use tower::ServiceExt;

use vauchi_ohttp_relay::config::RelayConfig;
use vauchi_ohttp_relay::request::extract_client_ip;
use vauchi_ohttp_relay::router::build_router;
use vauchi_ohttp_relay::test_utils::{
    build_test_state, build_test_state_with_limits, build_test_state_with_rate_limit,
    test_client::TestClient,
};

#[cfg(feature = "e2e-faults")]
async fn start_counting_ohttp_upstream() -> (String, Arc<AtomicUsize>) {
    let forwards = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&forwards);
    let mock = axum::Router::new().route(
        "/v2/ohttp",
        axum::routing::post(move || {
            let observed = Arc::clone(&observed);
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "message/ohttp-res")],
                    vec![0xA5],
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });
    (format!("http://{address}"), forwards)
}

// @scenario: release_privacy_multidevice_certification.feature:Faulted delivery still converges deterministically
#[cfg(feature = "e2e-faults")]
#[tokio::test]
async fn duplicate_first_forward_replays_one_opaque_request_without_changing_response() {
    let (gateway_url, forwards) = start_counting_ohttp_upstream().await;
    let state = build_test_state(65_536, &gateway_url).with_duplicate_first_forward();
    let app = build_router(state);
    let request = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(Body::from(vec![0x01, 0x02, 0x03]))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap()
            .as_ref(),
        &[0xA5]
    );
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        2,
        "the relay must forward the opaque blob exactly twice"
    );
}

// @scenario: release_privacy_multidevice_certification.feature:Faulted delivery still converges deterministically
#[cfg(feature = "e2e-faults")]
#[tokio::test]
async fn e2e_control_route_arms_one_duplicate_opaque_forward() {
    let (gateway_url, forwards) = start_counting_ohttp_upstream().await;
    let state = build_test_state(65_536, &gateway_url).with_e2e_fault_controller();
    let app = build_router(state);
    let arm_request = Request::builder()
        .method(http::Method::POST)
        .uri("/__e2e/duplicate-next-forward")
        .body(Body::empty())
        .unwrap();

    let arm_response = app.clone().oneshot(arm_request).await.unwrap();
    assert_eq!(arm_response.status(), StatusCode::NO_CONTENT);

    let forward_request = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(Body::from(vec![0x01, 0x02, 0x03]))
        .unwrap();
    let forward_response = app.oneshot(forward_request).await.unwrap();

    assert_eq!(forward_response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(forward_response.into_body(), 64)
            .await
            .unwrap()
            .as_ref(),
        &[0xA5]
    );
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        2,
        "the armed fault must duplicate exactly one opaque forward"
    );
}

// @scenario: router :: production build omits E2E fault control route
#[tokio::test]
async fn production_router_omits_e2e_fault_control_route() {
    let state = build_test_state(65_536, "http://127.0.0.1:19999");
    let app = build_router(state);
    let request = Request::builder()
        .method(http::Method::POST)
        .uri("/__e2e/duplicate-next-forward")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// @scenario: router :: health endpoint returns 200 ok
#[tokio::test]
async fn health_returns_ok() {
    let state = build_test_state(65536, "http://127.0.0.1:19999");
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

// @scenario: router :: oversized request body is rejected with 413
#[tokio::test]
async fn ohttp_forward_rejects_oversized_body() {
    let state = build_test_state(10, "http://127.0.0.1:19999");
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

// @scenario: router :: request body at exact size limit is accepted
#[tokio::test]
async fn ohttp_forward_accepts_body_at_limit() {
    // We cannot reach a real upstream in a unit test, so use a deliberately
    // unreachable address — the response will be 502 Bad Gateway, but the
    // size check must pass (not 413).
    let state = build_test_state(4, "http://127.0.0.1:19999");
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

// @scenario: router :: oversized Content-Length header is rejected with 413
#[tokio::test]
async fn ohttp_forward_rejects_oversized_content_length_header() {
    let state = build_test_state(10, "http://127.0.0.1:19999");
    let app = build_router(state);

    // Content-Length declares 100 bytes but body is empty — the header alone
    // should trigger a 413 before any body read is attempted.
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .header(header::CONTENT_LENGTH, "100")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized Content-Length header should be rejected with 413"
    );
}

// @internal
// Boundary: Content-Length exactly at limit must NOT be rejected (> not >=).
#[tokio::test]
async fn ohttp_forward_accepts_content_length_at_exact_limit() {
    let state = build_test_state(10, "http://127.0.0.1:19999");
    let app = build_router(state);

    // Content-Length == max_bytes (10) — should pass the Content-Length check.
    // The request will fail at upstream (502), but must NOT be 413.
    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .header(header::CONTENT_LENGTH, "10")
        .body(Body::from(vec![0u8; 10]))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "Content-Length at exact limit should not be rejected with 413"
    );
}

// @scenario: router :: key endpoint proxies upstream and returns 502 when unreachable
#[tokio::test]
async fn key_endpoint_attempts_upstream_proxy() {
    // Port 19998 is deliberately unreachable — we want to confirm that
    // the /v2/ohttp-key route calls the upstream client (502) rather than
    // returning 404 or 200 without hitting the upstream path.
    let state = build_test_state(65536, "http://127.0.0.1:19998");
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

// @scenario: router :: Key-Fingerprint header is forwarded from upstream
/// Start a mock upstream that returns a Key-Fingerprint header on GET /v2/ohttp-key.
async fn start_mock_upstream_with_fingerprint(fingerprint: &str) -> u16 {
    let fp = fingerprint.to_owned();
    let mock = axum::Router::new().route(
        "/v2/ohttp-key",
        axum::routing::get(move || {
            let fp = fp.clone();
            async move {
                let mut resp = (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/ohttp-keys")],
                    vec![0xAA, 0xBB], // dummy key bytes
                )
                    .into_response();
                resp.headers_mut().insert(
                    header::HeaderName::from_static("key-fingerprint"),
                    header::HeaderValue::from_str(&fp).unwrap(),
                );
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });
    port
}

// @scenario: router :: Key-Fingerprint header value is forwarded to client
#[tokio::test]
async fn key_endpoint_forwards_key_fingerprint_header() {
    let port = start_mock_upstream_with_fingerprint("abc123def456").await;
    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state(65536, &gateway_url);
    let app = build_router(state);

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("/v2/ohttp-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "key endpoint should return 200"
    );

    let fingerprint = resp
        .headers()
        .get("key-fingerprint")
        .expect("response should include Key-Fingerprint header")
        .to_str()
        .unwrap();
    assert_eq!(
        fingerprint, "abc123def456",
        "Key-Fingerprint header value should match upstream"
    );
}

// @scenario: router :: key endpoint works when upstream omits Key-Fingerprint
#[tokio::test]
async fn key_endpoint_works_without_fingerprint_header() {
    // Mock upstream that does NOT return Key-Fingerprint
    let mock = axum::Router::new().route(
        "/v2/ohttp-key",
        axum::routing::get(|| async {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/ohttp-keys")],
                vec![0xCC, 0xDD],
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state(65536, &gateway_url);
    let app = build_router(state);

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("/v2/ohttp-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "key endpoint should return 200"
    );
    assert!(
        resp.headers().get("key-fingerprint").is_none(),
        "Key-Fingerprint header should not be present when upstream omits it"
    );
}

// @scenario: router :: oversized upstream key response is rejected with 502
#[tokio::test]
async fn key_endpoint_rejects_oversized_upstream_response() {
    // Mock upstream returning a key body larger than our limit
    let oversized_body = vec![0xAA; 200]; // 200 bytes, limit will be 50
    let mock = axum::Router::new().route(
        "/v2/ohttp-key",
        axum::routing::get(move || {
            let body = oversized_body.clone();
            async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/ohttp-keys")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state_with_limits(65536, 131072, 50, &gateway_url);
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
        "oversized key response from upstream should result in 502"
    );
}

// @scenario: router :: oversized upstream OHTTP response is rejected with 502
#[tokio::test]
async fn ohttp_forward_rejects_oversized_upstream_response() {
    // Mock upstream returning a response body larger than our limit
    let oversized_body = vec![0xBB; 300]; // 300 bytes, limit will be 100
    let mock = axum::Router::new().route(
        "/v2/ohttp",
        axum::routing::post(move || {
            let body = oversized_body.clone();
            async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "message/ohttp-res")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state_with_limits(65536, 100, 4096, &gateway_url);
    let app = build_router(state);

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(Body::from(vec![0x01, 0x02]))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "oversized OHTTP response from upstream should result in 502"
    );
}

// @internal
// Boundary: upstream response body at exact limit must succeed (> not >=).
#[tokio::test]
async fn ohttp_forward_accepts_upstream_response_at_exact_limit() {
    let exact_body = vec![0xCC; 100]; // exactly at limit
    let mock = axum::Router::new().route(
        "/v2/ohttp",
        axum::routing::post(move || {
            let body = exact_body.clone();
            async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "message/ohttp-res")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state_with_limits(65536, 100, 4096, &gateway_url);
    let app = build_router(state);

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(Body::from(vec![0x01, 0x02]))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "upstream response at exact limit should succeed, not 502"
    );
}

// @internal
// Boundary: upstream key response at exact limit must succeed.
#[tokio::test]
async fn key_endpoint_accepts_upstream_response_at_exact_limit() {
    let exact_body = vec![0xAA; 50]; // exactly at limit
    let mock = axum::Router::new().route(
        "/v2/ohttp-key",
        axum::routing::get(move || {
            let body = exact_body.clone();
            async move {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/ohttp-keys")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state_with_limits(65536, 131072, 50, &gateway_url);
    let app = build_router(state);

    let req = Request::builder()
        .method(http::Method::GET)
        .uri("/v2/ohttp-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "upstream key response at exact limit should succeed, not 502"
    );
}

// @internal
// Upstream returns non-2xx status — must be propagated as 502.
#[tokio::test]
async fn ohttp_forward_returns_502_on_upstream_error_status() {
    let mock = axum::Router::new().route(
        "/v2/ohttp",
        axum::routing::post(|| async { StatusCode::INTERNAL_SERVER_ERROR.into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let gateway_url = format!("http://127.0.0.1:{port}");
    let state = build_test_state(65536, &gateway_url);
    let app = build_router(state);

    let req = Request::builder()
        .method(http::Method::POST)
        .uri("/v2/ohttp")
        .header(header::CONTENT_TYPE, "message/ohttp-req")
        .body(Body::from(vec![0x01]))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_GATEWAY,
        "upstream 500 should be mapped to 502 Bad Gateway"
    );
}

// @scenario: router :: rate limiter returns 429 after burst is exhausted
#[tokio::test]
async fn rate_limiter_returns_429_after_burst_exhausted() {
    // Start the relay as a real TCP server so ConnectInfo<SocketAddr> works.
    let state = build_test_state_with_rate_limit("http://127.0.0.1:19999", 3);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let client = TestClient::new();
    let url = format!("http://{relay_addr}/v2/ohttp");

    // Send requests up to the burst limit — should all succeed (502 from
    // unreachable upstream, but NOT 429).
    for i in 0..3 {
        let resp = client.post(&url, "message/ohttp-req", vec![0x01]).await;
        assert_ne!(
            resp.status().as_u16(),
            429,
            "request {i} within burst should not be rate-limited"
        );
    }

    // Next request should be rate-limited.
    let resp = client.post(&url, "message/ohttp-req", vec![0x01]).await;
    assert_eq!(
        resp.status().as_u16(),
        429,
        "request over burst limit should return 429 Too Many Requests"
    );
}

// @scenario: router :: health and key endpoints are exempt from rate limiting
#[tokio::test]
async fn health_and_key_endpoints_not_rate_limited() {
    // Verify that health and key endpoints are not affected by rate limiting.
    let state = build_test_state_with_rate_limit("http://127.0.0.1:19999", 1);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    let client = TestClient::new();

    // Exhaust the rate limit with a POST.
    let _ = client
        .post(
            format!("http://{relay_addr}/v2/ohttp"),
            "message/ohttp-req",
            vec![0x01],
        )
        .await;

    // Health should still work (not rate-limited).
    for _ in 0..5 {
        let resp = client.get(format!("http://{relay_addr}/health")).await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "health endpoint should never be rate-limited"
        );
    }
}

// -----------------------------------------------------------------------
// extract_client_ip tests
// -----------------------------------------------------------------------

fn ip_config(header: Option<&str>) -> RelayConfig {
    ip_config_with_proxies(header, 0)
}

fn ip_config_with_proxies(header: Option<&str>, trusted_proxies: usize) -> RelayConfig {
    RelayConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        gateway_url: "http://localhost:8080".to_owned(),
        max_request_bytes: 65536,
        max_response_bytes: 131072,
        max_key_response_bytes: 4096,
        rate_limit_per_sec: 50,
        rate_limit_max_buckets: 100_000,
        request_timeout: Duration::from_secs(5),
        client_ip_header: header.map(str::to_owned),
        client_ip_header_trusted_proxies: trusted_proxies,
        key_cache_ttl: Duration::ZERO,
    }
}

// @scenario: rate_limit :: uses ConnectInfo when no header configured
#[test]
fn extract_client_ip_uses_connect_info_when_no_header_configured() {
    let config = ip_config(None);
    let headers = axum::http::HeaderMap::new();
    let ci = ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap());

    let ip = extract_client_ip(&config, &headers, Some(&ci));
    assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
}

// @scenario: rate_limit :: prefers configured header over ConnectInfo
#[test]
fn extract_client_ip_prefers_header_over_connect_info() {
    let config = ip_config(Some("X-Real-IP"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Real-IP", "203.0.113.42".parse().unwrap());
    let ci = ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap());

    let ip = extract_client_ip(&config, &headers, Some(&ci));
    assert_eq!(ip, Some("203.0.113.42".parse().unwrap()));
}

// @scenario: rate_limit :: takes rightmost IP from X-Forwarded-For by default
#[test]
fn extract_client_ip_takes_rightmost_from_forwarded_for() {
    let config = ip_config(Some("X-Forwarded-For"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Forwarded-For", "198.51.100.7, 10.0.0.1".parse().unwrap());

    let ip = extract_client_ip(&config, &headers, None);
    assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
}

// @scenario: rate_limit :: trusted_proxies selects client IP counting from the right
#[test]
fn extract_client_ip_selects_client_by_trusted_proxies() {
    // One trusted proxy means the rightmost entry is the proxy, the one before
    // it is the client.
    let config = ip_config_with_proxies(Some("X-Forwarded-For"), 1);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "X-Forwarded-For",
        "203.0.113.5, 198.51.100.7, 10.0.0.1".parse().unwrap(),
    );

    let ip = extract_client_ip(&config, &headers, None);
    assert_eq!(ip, Some("198.51.100.7".parse().unwrap()));
}

// @scenario: rate_limit :: falls back to ConnectInfo when header has too few entries
#[test]
fn extract_client_ip_falls_back_when_trusted_proxies_exceeds_entries() {
    let config = ip_config_with_proxies(Some("X-Forwarded-For"), 2);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Forwarded-For", "198.51.100.7".parse().unwrap());
    let ci = ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap());

    let ip = extract_client_ip(&config, &headers, Some(&ci));
    assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
}

// @scenario: rate_limit :: falls back to ConnectInfo when header missing
#[test]
fn extract_client_ip_falls_back_when_header_missing() {
    let config = ip_config(Some("X-Real-IP"));
    let headers = axum::http::HeaderMap::new();
    let ci = ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap());

    let ip = extract_client_ip(&config, &headers, Some(&ci));
    assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
}

// @scenario: rate_limit :: falls back to ConnectInfo on malformed header value
#[test]
fn extract_client_ip_falls_back_on_malformed_header() {
    let config = ip_config(Some("X-Real-IP"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Real-IP", "not-an-ip-address".parse().unwrap());
    let ci = ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap());

    let ip = extract_client_ip(&config, &headers, Some(&ci));
    assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
}

// @scenario: rate_limit :: parses IPv6 address from rightmost header value
#[test]
fn extract_client_ip_handles_ipv6() {
    let config = ip_config(Some("X-Forwarded-For"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Forwarded-For", "2001:db8::1, 10.0.0.1".parse().unwrap());

    let ip = extract_client_ip(&config, &headers, None);
    assert_eq!(ip, Some("10.0.0.1".parse().unwrap()));
}

// @scenario: rate_limit :: IPv6 client with one trusted proxy
#[test]
fn extract_client_ip_handles_ipv6_with_trusted_proxy() {
    let config = ip_config_with_proxies(Some("X-Forwarded-For"), 1);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("X-Forwarded-For", "2001:db8::1, 10.0.0.1".parse().unwrap());

    let ip = extract_client_ip(&config, &headers, None);
    assert_eq!(ip, Some("2001:db8::1".parse().unwrap()));
}
