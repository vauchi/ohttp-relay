// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "test-utils")]

//! Tests for client IP extraction.
//!
//! `extract_client_ip` decides which IP a request is rate-limited under.
//! It is fully public, so these exercise it through the crate's API rather
//! than from inside `src/` (see `router_integration.rs` for the same move).

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue};
use vauchi_ohttp_relay::config::RelayConfig;
use vauchi_ohttp_relay::request::extract_client_ip;
use vauchi_ohttp_relay::test_utils::test_config;

const PEER: &str = "203.0.113.9";

fn config_with_header(trusted_proxies: usize) -> RelayConfig {
    RelayConfig {
        client_ip_header: Some("x-forwarded-for".to_owned()),
        client_ip_header_trusted_proxies: trusted_proxies,
        ..test_config("http://gateway.invalid")
    }
}

fn forwarded_for(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
    headers
}

fn peer() -> ConnectInfo<SocketAddr> {
    ConnectInfo(format!("{PEER}:44321").parse().unwrap())
}

fn extract(config: &RelayConfig, headers: &HeaderMap) -> Option<IpAddr> {
    extract_client_ip(config, headers, Some(&peer()))
}

fn ip(s: &str) -> Option<IpAddr> {
    Some(s.parse().unwrap())
}

// @internal
#[test]
fn peer_address_is_used_when_no_header_is_configured() {
    let config = test_config("http://gateway.invalid");

    let resolved = extract(&config, &forwarded_for("198.51.100.7"));

    assert_eq!(resolved, ip(PEER));
}

// @internal
#[test]
fn peer_address_is_used_when_the_configured_header_is_absent() {
    let resolved = extract(&config_with_header(0), &HeaderMap::new());

    assert_eq!(resolved, ip(PEER));
}

// @internal
#[test]
fn a_single_entry_is_used_when_no_proxies_are_trusted() {
    let resolved = extract(&config_with_header(0), &forwarded_for("198.51.100.7"));

    assert_eq!(resolved, ip("198.51.100.7"));
}

// @internal
#[test]
fn the_rightmost_entry_wins_when_no_proxies_are_trusted() {
    let resolved = extract(
        &config_with_header(0),
        &forwarded_for("198.51.100.7, 10.0.0.1"),
    );

    assert_eq!(resolved, ip("10.0.0.1"));
}

// @internal
#[test]
fn one_trusted_proxy_selects_the_entry_before_it() {
    let resolved = extract(
        &config_with_header(1),
        &forwarded_for("198.51.100.7, 10.0.0.1"),
    );

    assert_eq!(resolved, ip("198.51.100.7"));
}

// @internal
#[test]
fn two_trusted_proxies_count_back_two_from_the_right() {
    let resolved = extract(
        &config_with_header(2),
        &forwarded_for("198.51.100.7, 10.0.0.1, 10.0.0.2"),
    );

    assert_eq!(resolved, ip("198.51.100.7"));
}

/// A client that controls its own request can prepend anything it likes;
/// counting from the right is what makes those entries unreachable.
// @internal
#[test]
fn prepended_entries_cannot_displace_the_selected_ip() {
    let config = config_with_header(1);
    let honest = forwarded_for("198.51.100.7, 10.0.0.1");
    let spoofed = forwarded_for("1.1.1.1, 2.2.2.2, 198.51.100.7, 10.0.0.1");

    assert_eq!(extract(&config, &honest), ip("198.51.100.7"));
    assert_eq!(extract(&config, &spoofed), ip("198.51.100.7"));
}

// @internal
#[test]
fn a_spoofed_entry_never_becomes_the_selected_ip() {
    let resolved = extract(
        &config_with_header(1),
        &forwarded_for("6.6.6.6, 198.51.100.7, 10.0.0.1"),
    );

    assert_ne!(resolved, ip("6.6.6.6"));
    assert_eq!(resolved, ip("198.51.100.7"));
}

/// A header shorter than the configured proxy count cannot be trusted to
/// contain the client, so the peer address is used instead of guessing.
// @internal
#[test]
fn a_header_with_too_few_entries_falls_back_to_the_peer() {
    let resolved = extract(&config_with_header(2), &forwarded_for("198.51.100.7"));

    assert_eq!(resolved, ip(PEER));
}

// @internal
#[test]
fn an_entry_count_equal_to_the_proxy_count_falls_back_to_the_peer() {
    let resolved = extract(
        &config_with_header(2),
        &forwarded_for("198.51.100.7, 10.0.0.1"),
    );

    assert_eq!(resolved, ip(PEER));
}

// @internal
#[test]
fn surrounding_whitespace_is_ignored() {
    let resolved = extract(
        &config_with_header(1),
        &forwarded_for("  198.51.100.7  ,\t10.0.0.1 "),
    );

    assert_eq!(resolved, ip("198.51.100.7"));
}

// @internal
#[test]
fn empty_entries_are_skipped_before_counting() {
    let resolved = extract(
        &config_with_header(1),
        &forwarded_for(",, 198.51.100.7 ,,, 10.0.0.1 ,"),
    );

    assert_eq!(resolved, ip("198.51.100.7"));
}

// @internal
#[test]
fn an_all_empty_header_falls_back_to_the_peer() {
    let resolved = extract(&config_with_header(0), &forwarded_for(" , , "));

    assert_eq!(resolved, ip(PEER));
}

// @internal
#[test]
fn an_unparsable_selected_entry_falls_back_to_the_peer() {
    for value in [
        "not-an-ip",
        "999.999.999.999",
        "198.51.100.7:443",
        "[2001:db8::1]:443",
        "0x7f000001",
        "localhost",
        "198.51.100.7/24",
    ] {
        let resolved = extract(&config_with_header(0), &forwarded_for(value));

        assert_eq!(resolved, ip(PEER), "unexpectedly accepted {value:?}");
    }
}

/// Only the selected entry is parsed, so noise elsewhere in the list is
/// irrelevant — including noise a client planted to force a fallback.
// @internal
#[test]
fn unparsable_entries_elsewhere_do_not_affect_the_result() {
    let resolved = extract(
        &config_with_header(1),
        &forwarded_for("garbage, 198.51.100.7, 10.0.0.1"),
    );

    assert_eq!(resolved, ip("198.51.100.7"));
}

// @internal
#[test]
fn ipv6_entries_are_supported() {
    let resolved = extract(
        &config_with_header(1),
        &forwarded_for("2001:db8::1, 2001:db8::2"),
    );

    assert_eq!(resolved, ip("2001:db8::1"));
}

// @internal
#[test]
fn a_non_ascii_header_value_falls_back_to_the_peer() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );

    let resolved = extract(&config_with_header(0), &headers);

    assert_eq!(resolved, ip(PEER));
}

// @internal
#[test]
fn a_missing_peer_and_an_unusable_header_yield_no_ip() {
    let resolved = extract_client_ip(&config_with_header(0), &HeaderMap::new(), None);

    assert_eq!(resolved, None);
}

// @internal
#[test]
fn a_usable_header_still_wins_without_a_peer_address() {
    let resolved = extract_client_ip(&config_with_header(0), &forwarded_for("198.51.100.7"), None);

    assert_eq!(resolved, ip("198.51.100.7"));
}

// @internal
#[test]
fn a_differently_named_header_is_honoured() {
    let config = RelayConfig {
        client_ip_header: Some("cf-connecting-ip".to_owned()),
        ..test_config("http://gateway.invalid")
    };
    let mut headers = HeaderMap::new();
    headers.insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.7"));

    assert_eq!(extract(&config, &headers), ip("198.51.100.7"));
}

// @internal
#[test]
fn a_configured_header_is_matched_case_insensitively() {
    let config = RelayConfig {
        client_ip_header: Some("X-Forwarded-For".to_owned()),
        ..test_config("http://gateway.invalid")
    };

    assert_eq!(
        extract(&config, &forwarded_for("198.51.100.7")),
        ip("198.51.100.7")
    );
}
