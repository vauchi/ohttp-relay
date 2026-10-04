// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The optional components the server starts from its configuration
//! (vauchi/private#504).

use std::time::Duration;

use vauchi_ohttp_relay::key_cache::KeyConfigCache;
use vauchi_ohttp_relay::rate_limit::RateLimiter;

// @internal
#[tokio::test]
async fn a_zero_rate_disables_the_limiter_and_any_other_rate_enables_it() {
    assert!(RateLimiter::spawn_if_enabled(0, 1000).is_none());
    assert!(RateLimiter::spawn_if_enabled(1, 1000).is_some());
}

// @internal
#[test]
fn a_zero_ttl_disables_the_key_cache_and_any_other_ttl_enables_it() {
    assert!(KeyConfigCache::if_enabled(Duration::ZERO).is_none());
    assert!(KeyConfigCache::if_enabled(Duration::from_secs(60)).is_some());
}
