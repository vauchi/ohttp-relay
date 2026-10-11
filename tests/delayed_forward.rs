// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "test-utils")]

//! Asynchronous OHTTP with a forwarding delay (vauchi/private#628, design
//! `2026-10-11-outer-relay-delayed-forwarding-design`): the outer relay
//! accepts a request under a client-chosen ticket, forwards it after a
//! random delay so the gateway's view of the fetch no longer lines up with
//! the client's connection, and holds the encapsulated answer until the
//! client collects it. Time is tokio's paused clock: no real waits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use tower::ServiceExt;
use vauchi_ohttp_relay::delayed::{DelayPolicy, DelayedForwarding};
use vauchi_ohttp_relay::router::build_router;
use vauchi_ohttp_relay::test_utils::{build_test_state, build_test_state_with_delayed_forwarding};

const TICKET: &str = "00112233445566778899aabbccddeeff";
const OTHER: &str = "ffeeddccbbaa99887766554433221100";
const DELAY: Duration = Duration::from_secs(600);
const ANSWER: &[u8] = b"encapsulated-answer";

struct Gateway {
    url: String,
    forwards: Arc<AtomicUsize>,
}

/// A gateway answering `POST /v2/ohttp` with `status` and a fixed body,
/// counting the requests that reach it.
async fn gateway(status: StatusCode) -> Gateway {
    let forwards = Arc::new(AtomicUsize::new(0));
    let counter = forwards.clone();
    let app = axum::Router::new().route(
        "/v2/ohttp",
        axum::routing::post(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                (
                    status,
                    [(header::CONTENT_TYPE, "message/ohttp-res")],
                    ANSWER,
                )
                    .into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Gateway { url, forwards }
}

/// The router and a handle on its store of pending and held answers.
fn app(
    gateway: &Gateway,
    policy: DelayPolicy,
    budget_bytes: usize,
) -> (axum::Router, Arc<DelayedForwarding>) {
    let state = build_test_state_with_delayed_forwarding(&gateway.url, policy, budget_bytes);
    let store = state
        .delayed
        .clone()
        .expect("delayed forwarding configured");
    (build_router(state), store)
}

async fn post(app: &axum::Router, ticket: Option<&str>) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v2/ohttp-async")
        .header(header::CONTENT_TYPE, "message/ohttp-req");
    if let Some(ticket) = ticket {
        request = request.header("vauchi-ticket", ticket);
    }
    app.clone()
        .oneshot(request.body(Body::from(vec![0x42; 64])).unwrap())
        .await
        .unwrap()
        .status()
}

async fn collect(app: &axum::Router, ticket: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v2/ohttp-async/{ticket}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

/// Waits until `bytes` of answers are held. The forward runs on the
/// blocking pool, outside the paused clock, so the store's completion signal
/// is awaited rather than a timer.
async fn until_held(store: &DelayedForwarding, bytes: usize) {
    while store.held_bytes() < bytes {
        store.answer_held().await;
    }
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_request_reaches_the_gateway_only_after_its_delay() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, store) = app(&gateway, DelayPolicy::Fixed(DELAY), 1 << 20);

    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::ACCEPTED);
    tokio::time::advance(DELAY - Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    assert_eq!(gateway.forwards.load(Ordering::SeqCst), 0);
    assert_eq!(collect(&app, TICKET).await.0, StatusCode::ACCEPTED);

    tokio::time::advance(Duration::from_secs(2)).await;
    until_held(&store, ANSWER.len()).await;
    assert_eq!(
        collect(&app, TICKET).await,
        (StatusCode::OK, ANSWER.to_vec())
    );
    assert_eq!(gateway.forwards.load(Ordering::SeqCst), 1);
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_collected_answer_is_gone_and_frees_its_bytes() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, store) = app(&gateway, DelayPolicy::Fixed(Duration::ZERO), 1 << 20);
    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::ACCEPTED);
    until_held(&store, ANSWER.len()).await;

    assert_eq!(collect(&app, TICKET).await.0, StatusCode::OK);
    assert_eq!(collect(&app, TICKET).await.0, StatusCode::NOT_FOUND);
    assert_eq!(store.held_bytes(), 0);
}

// @internal
#[tokio::test(start_paused = true)]
async fn an_unknown_ticket_is_not_found() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, _) = app(&gateway, DelayPolicy::Fixed(DELAY), 1 << 20);

    assert_eq!(collect(&app, TICKET).await.0, StatusCode::NOT_FOUND);
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_malformed_or_missing_ticket_is_refused() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, _) = app(&gateway, DelayPolicy::Fixed(Duration::ZERO), 1 << 20);

    for ticket in [
        None,
        Some(""),
        Some("short"),
        Some("zz112233445566778899aabbccddeeff"),
        Some("00112233445566778899aabbccddeeff00"),
    ] {
        assert_eq!(
            post(&app, ticket).await,
            StatusCode::BAD_REQUEST,
            "{ticket:?}"
        );
    }
    assert_eq!(collect(&app, "not-hex").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(gateway.forwards.load(Ordering::SeqCst), 0);
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_ticket_already_pending_is_refused() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, _) = app(&gateway, DelayPolicy::Fixed(DELAY), 1 << 20);

    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::ACCEPTED);
    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::CONFLICT);
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_full_budget_refuses_new_requests() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, store) = app(&gateway, DelayPolicy::Fixed(Duration::ZERO), ANSWER.len());
    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::ACCEPTED);
    until_held(&store, ANSWER.len()).await;

    assert_eq!(
        post(&app, Some(OTHER)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );

    assert_eq!(collect(&app, TICKET).await.0, StatusCode::OK);
    assert_eq!(post(&app, Some(OTHER)).await, StatusCode::ACCEPTED);
}

// @internal
#[tokio::test(start_paused = true)]
async fn an_answer_nobody_collects_expires_after_twice_the_maximum_delay() {
    let gateway = gateway(StatusCode::OK).await;
    let (app, store) = app(&gateway, DelayPolicy::Fixed(DELAY), 1 << 20);
    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::ACCEPTED);
    tokio::time::advance(DELAY + Duration::from_secs(1)).await;
    until_held(&store, ANSWER.len()).await;

    tokio::time::advance(2 * DELAY - Duration::from_secs(5)).await;
    assert_eq!(collect(&app, OTHER).await.0, StatusCode::NOT_FOUND);
    assert_eq!(store.held_bytes(), ANSWER.len(), "still held before expiry");

    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(collect(&app, TICKET).await.0, StatusCode::NOT_FOUND);
    assert_eq!(store.held_bytes(), 0);
}

// @internal
#[tokio::test(start_paused = true)]
async fn a_gateway_failure_is_collected_as_bad_gateway() {
    let gateway = gateway(StatusCode::INTERNAL_SERVER_ERROR).await;
    let (app, store) = app(&gateway, DelayPolicy::Fixed(Duration::ZERO), 1 << 20);
    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::ACCEPTED);

    store.answer_held().await;

    assert_eq!(collect(&app, TICKET).await.0, StatusCode::BAD_GATEWAY);
}

// @internal
#[tokio::test(start_paused = true)]
async fn without_delayed_forwarding_configured_the_routes_are_absent() {
    let gateway = gateway(StatusCode::OK).await;
    let app = build_router(build_test_state(65_536, &gateway.url));

    assert_eq!(post(&app, Some(TICKET)).await, StatusCode::NOT_FOUND);
    assert_eq!(collect(&app, TICKET).await.0, StatusCode::NOT_FOUND);
}

// @internal
#[test]
fn a_uniform_delay_stays_within_its_window_and_varies() {
    let policy = DelayPolicy::Uniform { max: DELAY };
    let samples: Vec<Duration> = (0..2_000).map(|_| policy.sample()).collect();

    assert!(samples.iter().all(|delay| *delay <= DELAY));
    let below_half = samples.iter().filter(|delay| **delay < DELAY / 2).count();
    // Uniform on [0, W]: about half below W/2.
    assert!(
        (850..=1_150).contains(&below_half),
        "{below_half} of 2000 below W/2"
    );
}
