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

#[cfg(feature = "e2e-faults")]
use std::sync::Arc;

use tracing::{error, info};

use vauchi_ohttp_relay::config::RelayConfig;
use vauchi_ohttp_relay::key_cache::KeyConfigCache;
use vauchi_ohttp_relay::rate_limit::RateLimiter;
#[cfg(feature = "e2e-faults")]
use vauchi_ohttp_relay::router::E2eFaultController;
use vauchi_ohttp_relay::router::{AppState, build_router};
use vauchi_ohttp_relay::server;
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

    let rate_limiter =
        RateLimiter::spawn_if_enabled(config.rate_limit_per_sec, config.rate_limit_max_buckets);
    let key_cache = KeyConfigCache::if_enabled(config.key_cache_ttl);
    let upstream = UpstreamClient::new(&config.gateway_url, config.request_timeout);

    let state = AppState {
        config: config.clone(),
        upstream,
        rate_limiter,
        key_cache,
        #[cfg(feature = "e2e-faults")]
        e2e_fault_controller: Some(Arc::new(E2eFaultController::new())),
    };
    let app = build_router(state);

    server::serve(config.listen_addr, app).await;

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
