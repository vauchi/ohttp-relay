// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "test-utils")]

//! `GET /v2/ohttp-key-signed` through the outer relay (#288 plan 3.1).
//!
//! The record is opaque here: clients verify its chain. The relay only reads
//! the window, so a cached record is never served past the window it signs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use tower::ServiceExt;

use vauchi_ohttp_relay::router::build_router;
use vauchi_ohttp_relay::test_utils::build_test_state_with_signed_key_cache;

const WINDOW_SECONDS: u64 = 86_400;
const WINDOW: u64 = 20_367;
const CONTENT_TYPE: &str = "application/vnd.vauchi.ohttp-key-signed";

/// A record as the gateway encodes it: version 1, then the window. The
/// rest is opaque to the outer relay.
fn record(window: u64) -> Vec<u8> {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&window.to_be_bytes());
    bytes.extend_from_slice(&[0xab; 300]);
    bytes
}

struct Gateway {
    url: String,
    fetches: Arc<AtomicUsize>,
}

/// A gateway answering `/v2/ohttp-key-signed` with `status` and `body`,
/// counting the fetches that reach it.
async fn gateway(status: StatusCode, body: Vec<u8>) -> Gateway {
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    let app = axum::Router::new().route(
        "/v2/ohttp-key-signed",
        axum::routing::get(move || {
            let counter = counter.clone();
            let body = body.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                (status, [(header::CONTENT_TYPE, CONTENT_TYPE)], body).into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Gateway {
        url: format!("http://127.0.0.1:{port}"),
        fetches,
    }
}

struct Relay {
    app: axum::Router,
    now: Arc<AtomicU64>,
}

impl Relay {
    fn new(gateway: &Gateway, cache_ttl: Duration, now: u64) -> Self {
        let now = Arc::new(AtomicU64::new(now));
        let clock = now.clone();
        let state = build_test_state_with_signed_key_cache(
            &gateway.url,
            cache_ttl,
            Arc::new(move || clock.load(Ordering::SeqCst)),
        );
        Self {
            app: build_router(state),
            now,
        }
    }

    fn at(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }

    async fn get(&self) -> (StatusCode, Option<String>, Vec<u8>) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v2/ohttp-key-signed")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned());
        let body = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap()
            .to_vec();
        (status, content_type, body)
    }
}

fn hour_into_window() -> u64 {
    WINDOW * WINDOW_SECONDS + 3_600
}

const LONG_TTL: Duration = Duration::from_secs(2 * 86_400);

// @scenario: release_privacy_multidevice_certification.feature:Neither relay can decrypt or identify application users
#[tokio::test]
async fn the_gateways_signed_record_passes_through_unchanged() {
    let gateway = gateway(StatusCode::OK, record(WINDOW)).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());

    let (status, content_type, body) = relay.get().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(CONTENT_TYPE));
    assert_eq!(body, record(WINDOW));
}

/// A mass bootstrap must not reach the gateway once per client.
// @internal
#[tokio::test]
async fn within_the_window_the_record_is_fetched_once() {
    let gateway = gateway(StatusCode::OK, record(WINDOW)).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());

    relay.get().await;
    relay.at(hour_into_window() + 3_600);
    let (status, _, body) = relay.get().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, record(WINDOW));
    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 1);
}

/// Serving yesterday's record after the boundary would hand clients a key
/// for a window they then refuse as stale.
// @internal
#[tokio::test]
async fn the_window_boundary_ends_the_cache_whatever_the_ttl() {
    let gateway = gateway(StatusCode::OK, record(WINDOW)).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());
    relay.get().await;

    relay.at((WINDOW + 1) * WINDOW_SECONDS);
    relay.get().await;

    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 2);
}

// @internal
#[tokio::test]
async fn a_shorter_ttl_ends_the_cache_first() {
    let gateway = gateway(StatusCode::OK, record(WINDOW)).await;
    let relay = Relay::new(&gateway, Duration::from_secs(300), hour_into_window());
    relay.get().await;

    relay.at(hour_into_window() + 299);
    relay.get().await;
    relay.at(hour_into_window() + 300);
    relay.get().await;

    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 2);
}

/// Just after a boundary the gateway may still sign the old window (clock
/// skew); that record must not be pinned in the cache for the new window.
// @internal
#[tokio::test]
async fn a_record_for_a_window_that_has_ended_is_not_cached() {
    let gateway = gateway(StatusCode::OK, record(WINDOW - 1)).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());

    let (status, _, body) = relay.get().await;
    relay.get().await;

    assert_eq!(status, StatusCode::OK, "still served: the client decides");
    assert_eq!(body, record(WINDOW - 1));
    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 2);
}

/// The window cannot be read from an unknown format, so only the TTL bounds
/// the cache.
// @internal
#[tokio::test]
async fn an_unreadable_record_is_cached_for_the_ttl_only() {
    let gateway = gateway(StatusCode::OK, b"\x09not-a-record".to_vec()).await;
    let relay = Relay::new(&gateway, Duration::from_secs(300), hour_into_window());

    relay.get().await;
    relay.at(hour_into_window() + 299);
    let (status, _, body) = relay.get().await;
    relay.at(hour_into_window() + 300);
    relay.get().await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"\x09not-a-record");
    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 2);
}

/// 503 means "no signed key yet"; clients treat it differently from an
/// unreachable gateway (502). Neither is cached.
// @internal
#[tokio::test]
async fn a_gateway_without_a_signed_key_answers_503_uncached() {
    let gateway = gateway(StatusCode::SERVICE_UNAVAILABLE, Vec::new()).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());

    let (first, _, _) = relay.get().await;
    let (second, _, _) = relay.get().await;

    assert_eq!(first, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(second, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 2);
}

// @internal
#[tokio::test]
async fn other_gateway_errors_answer_502() {
    let gateway = gateway(StatusCode::INTERNAL_SERVER_ERROR, Vec::new()).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());

    let (status, _, _) = relay.get().await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// DC-04: the response size bound holds here as on the key route.
// @internal
#[tokio::test]
async fn an_oversized_record_answers_502() {
    let gateway = gateway(StatusCode::OK, vec![1u8; 5_000]).await;
    let relay = Relay::new(&gateway, LONG_TTL, hour_into_window());

    let (status, _, _) = relay.get().await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
}
