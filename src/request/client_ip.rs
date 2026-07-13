// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Client IP extraction for rate limiting.
//!
//! The IP is used only for rate limiting — it is never logged or forwarded.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;

use crate::config::RelayConfig;

/// Determine the client IP for rate limiting.
///
/// When `client_ip_header` is configured, the IP is extracted from that header.
/// For comma-separated headers such as `X-Forwarded-For`, the value is selected
/// from the **right** end, counting back by `client_ip_header_trusted_proxies`.
/// This prevents direct clients from prepending spoofed IPs and evading rate
/// limits. Falls back to the TCP peer address from `ConnectInfo` when the
/// header is missing, malformed, or does not contain enough entries.
///
/// Example with `client_ip_header_trusted_proxies = 1`:
/// `X-Forwarded-For: 198.51.100.7, 10.0.0.1` selects `10.0.0.1`.
pub fn extract_client_ip(
    config: &RelayConfig,
    headers: &axum::http::HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
) -> Option<IpAddr> {
    if let Some(ref header_name) = config.client_ip_header
        && let Some(value) = headers.get(header_name.as_str())
        && let Ok(s) = value.to_str()
    {
        let entries: Vec<&str> = s
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .collect();

        if !entries.is_empty() {
            // Select from the right to prevent untrusted clients from spoofing.
            // The rightmost entry is the closest proxy; count back by the number
            // of trusted proxies to reach the client. If the list is shorter than
            // the configured proxy count, the header is incomplete — fall back.
            if config.client_ip_header_trusted_proxies < entries.len() {
                let idx = entries.len() - 1 - config.client_ip_header_trusted_proxies;
                if let Ok(ip) = entries[idx].parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    connect_info.map(|ConnectInfo(addr)| addr.ip())
}
