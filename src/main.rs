// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Vauchi OHTTP Relay Server
//!
//! A minimal OHTTP forwarding proxy that sits between clients and the
//! vauchi-relay gateway. The relay:
//!
//! - Receives encrypted OHTTP blobs from clients
//! - Forwards them to the upstream gateway verbatim
//! - Returns the response to the client
//! - Proxies the gateway's OHTTP public key for client bootstrap
//!
//! All configuration is via environment variables. See `config::RelayConfig`.

use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

use vauchi_ohttp_relay::config::RelayConfig;
use vauchi_ohttp_relay::router::{AppState, build_router};
use vauchi_ohttp_relay::upstream::UpstreamClient;

#[tokio::main]
async fn main() {
    init_tracing();

    let config = match RelayConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    info!(
        listen_addr = %config.listen_addr,
        gateway_url = %config.gateway_url,
        max_request_bytes = config.max_request_bytes,
        request_timeout_secs = config.request_timeout.as_secs(),
        "vauchi-ohttp-relay starting"
    );

    let upstream = UpstreamClient::new(&config.gateway_url, config.request_timeout);
    let state = AppState {
        config: config.clone(),
        upstream,
    };

    let app = build_router(state);

    let listener = match TcpListener::bind(config.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %config.listen_addr, error = %e, "failed to bind listener");
            std::process::exit(1);
        }
    };

    info!(addr = %config.listen_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| error!(error = %e, "server error"));

    info!("vauchi-ohttp-relay stopped");
}

/// Wait for SIGTERM or SIGINT and return.
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

    info!("shutdown signal received");
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        // Default to INFO; override via RUST_LOG env var.
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        // Omit the hostname/target fields to avoid leaking deployment details.
        .with_target(false)
        .init();
}
