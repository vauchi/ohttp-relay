// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The production signed-key cache: off at a zero TTL, on the real clock
//! otherwise, so a record for a window that has already ended is never
//! served (vauchi/private#553).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use vauchi_ohttp_relay::signed_key_cache::SignedKeyCache;

/// A version-1 record header for `window`, the only part the cache reads.
fn record_for_window(window: u64) -> Bytes {
    let mut body = vec![1u8];
    body.extend_from_slice(&window.to_be_bytes());
    Bytes::from(body)
}

fn today() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400
}

// @internal
#[test]
fn a_zero_ttl_disables_the_cache() {
    assert!(SignedKeyCache::if_enabled(Duration::ZERO).is_none());
    assert!(SignedKeyCache::if_enabled(Duration::from_secs(60)).is_some());
}

// @internal
#[test]
fn the_production_cache_runs_on_the_real_clock() {
    let cache = SignedKeyCache::if_enabled(Duration::from_secs(60)).unwrap();

    cache.set(record_for_window(0));
    assert_eq!(cache.get(), None, "the 1970 window ended long ago");

    let current = record_for_window(today());
    cache.set(current.clone());
    assert_eq!(cache.get(), Some(current));
}

// @internal
#[test]
fn debug_output_shows_the_ttl() {
    let cache = SignedKeyCache::if_enabled(Duration::from_secs(60)).unwrap();

    assert_eq!(format!("{cache:?}"), "SignedKeyCache { ttl_secs: 60, .. }");
}
