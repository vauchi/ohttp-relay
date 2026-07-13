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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

use vauchi_ohttp_relay::config::RelayConfig;
use vauchi_ohttp_relay::key_cache::KeyConfigCache;
use vauchi_ohttp_relay::rate_limit::RateLimiter;
use vauchi_ohttp_relay::router::{AppState, build_router};
use vauchi_ohttp_relay::upstream::UpstreamClient;

#[tokio::main]
async fn main() {
    // With the `flame` feature, the flame init replaces `init_tracing()`.
    #[cfg(feature = "flame")]
    vauchi_ohttp_relay::flame::init();
    #[cfg(not(feature = "flame"))]
    init_tracing();

    let config = match RelayConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    log_startup(&config);

    let rate_limiter = build_rate_limiter(config.rate_limit_per_sec, config.rate_limit_max_buckets);
    let key_cache = build_key_cache(config.key_cache_ttl);
    let upstream = UpstreamClient::new(&config.gateway_url, config.request_timeout);

    let state = AppState {
        config: config.clone(),
        upstream,
        rate_limiter,
        key_cache,
    };
    let app = build_router(state);

    serve(config.listen_addr, app).await;

    info!("vauchi-ohttp-relay stopped");
}

/// Log configuration at startup.
fn log_startup(config: &RelayConfig) {
    info!(
        listen_addr = %config.listen_addr,
        gateway_url = %config.gateway_url,
        max_request_bytes = config.max_request_bytes,
        max_response_bytes = config.max_response_bytes,
        max_key_response_bytes = config.max_key_response_bytes,
        rate_limit_per_sec = config.rate_limit_per_sec,
        request_timeout_secs = config.request_timeout.as_secs(),
        client_ip_header = config.client_ip_header.as_deref().unwrap_or("(none — using TCP peer)"),
        key_cache_ttl_secs = config.key_cache_ttl.as_secs(),
        "vauchi-ohttp-relay starting"
    );
}

/// Build the rate limiter and, if enabled, spawn a background task to evict
/// stale entries so memory does not grow unbounded under diverse source IPs.
fn build_rate_limiter(
    rate_limit_per_sec: u32,
    rate_limit_max_buckets: usize,
) -> Option<Arc<RateLimiter>> {
    if rate_limit_per_sec == 0 {
        info!("rate limiting disabled (OHTTP_RELAY_RATE_LIMIT_PER_SEC=0)");
        return None;
    }

    let limiter = Arc::new(RateLimiter::new(rate_limit_per_sec, rate_limit_max_buckets));
    let limiter_cleanup = Arc::clone(&limiter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        interval.tick().await; // skip initial immediate tick
        loop {
            interval.tick().await;
            limiter_cleanup.evict_stale(Duration::from_secs(1800));
        }
    });

    Some(limiter)
}

/// Build the key config cache if a non-zero TTL is configured.
fn build_key_cache(key_cache_ttl: Duration) -> Option<Arc<KeyConfigCache>> {
    if key_cache_ttl.is_zero() {
        info!("key config caching disabled (OHTTP_RELAY_KEY_CACHE_TTL_SECS=0)");
        return None;
    }

    Some(Arc::new(KeyConfigCache::new(key_cache_ttl)))
}

/// Maximum time to wait for active connections to drain after a shutdown signal.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Bind to the listen address and run the server with graceful shutdown.
///
/// If active connections do not drain within [`SHUTDOWN_TIMEOUT`], the server
/// is forced stopped so a stuck upstream call cannot delay shutdown
/// indefinitely.
async fn serve(listen_addr: SocketAddr, app: Router) {
    let listener = match TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %listen_addr, error = %e, "failed to bind listener");
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
        Ok(Err(e)) => error!(error = %e, "server error"),
        Err(_) => warn!(
            timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
            "graceful shutdown timed out; forcing stop"
        ),
    }
}

/// Wait for SIGTERM or SIGINT and return.
///
/// This function is intentionally pure: it does not log. The caller decides
/// what to log when the signal arrives.
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

#[cfg(not(feature = "flame"))]
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        // Default to INFO; override via RUST_LOG env var.
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        // Omit the hostname/target fields to avoid leaking deployment details.
        .with_target(false)
        .init();
}
