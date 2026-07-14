// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn serve(listen_addr: SocketAddr, app: Router) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            error!(addr = %listen_addr, error = %error, "failed to bind listener");
            std::process::exit(1);
        }
    };

    info!(addr = %listen_addr, "listening");

    let shutdown = async {
        shutdown_signal().await;
        info!("shutdown signal received");
    };

    match tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown),
    )
    .await
    {
        Ok(Ok(())) => info!("server stopped gracefully"),
        Ok(Err(error)) => error!(error = %error, "server error"),
        Err(_) => warn!(
            timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
            "graceful shutdown timed out; forcing stop"
        ),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
