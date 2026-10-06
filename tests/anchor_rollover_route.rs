// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "test-utils")]

//! `GET /v2/ohttp-anchor-rollover` through the outer relay (#288 plan 2.10,
//! decision 0.13): the relay's rollover chain passes through unchanged and
//! uncached — clients ask for it only after their anchor stopped verifying,
//! and they verify it themselves.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use tower::ServiceExt;

use vauchi_ohttp_relay::router::build_router;
use vauchi_ohttp_relay::test_utils::build_test_state;

const CONTENT_TYPE: &str = "application/vnd.vauchi.ohttp-anchor-rollover";

struct Gateway {
    url: String,
    fetches: Arc<AtomicUsize>,
}

async fn gateway(status: StatusCode, body: Vec<u8>) -> Gateway {
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    let app = axum::Router::new().route(
        "/v2/ohttp-anchor-rollover",
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

async fn get(gateway: &Gateway) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = build_router(build_test_state(65_536, &gateway.url))
        .oneshot(
            Request::builder()
                .uri("/v2/ohttp-anchor-rollover")
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

fn chain() -> Vec<u8> {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&[0x5a; 129]);
    bytes
}

// @internal
#[tokio::test]
async fn the_chain_passes_through_unchanged_and_uncached() {
    let gateway = gateway(StatusCode::OK, chain()).await;

    let (status, content_type, body) = get(&gateway).await;
    get(&gateway).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some(CONTENT_TYPE));
    assert_eq!(body, chain());
    assert_eq!(gateway.fetches.load(Ordering::SeqCst), 2, "never cached");
}

/// 404 is the normal "no rollover yet"; clients keep their anchor.
// @internal
#[tokio::test]
async fn no_rollover_passes_through_as_404() {
    let gateway = gateway(StatusCode::NOT_FOUND, Vec::new()).await;

    let (status, _, _) = get(&gateway).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// @internal
#[tokio::test]
async fn other_gateway_failures_answer_502() {
    let failing = gateway(StatusCode::INTERNAL_SERVER_ERROR, Vec::new()).await;
    let oversized = gateway(StatusCode::OK, vec![1u8; 5_000]).await;

    assert_eq!(get(&failing).await.0, StatusCode::BAD_GATEWAY);
    assert_eq!(get(&oversized).await.0, StatusCode::BAD_GATEWAY);
}
