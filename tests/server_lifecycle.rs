// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use vauchi_ohttp_relay::server;

#[tokio::test(start_paused = true)]
async fn server_without_shutdown_remains_running_past_drain_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(server::serve_until_shutdown(
        listener,
        Router::new(),
        async move {
            let _ = shutdown_rx.await;
        },
        Duration::from_secs(30),
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;

    assert!(
        !server.is_finished(),
        "the drain timeout must not start before a shutdown signal"
    );
    server.abort();
}
