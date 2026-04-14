// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! TTL cache for upstream OHTTP key config responses.
//!
//! The gateway's key config changes at most once per rotation period (default
//! 24 hours). Caching prevents a thundering herd on the upstream when many
//! clients bootstrap simultaneously (app update rollout, relay restart).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Bytes;

struct CachedEntry {
    body: Bytes,
    fingerprint: Option<String>,
    fetched_at: Instant,
}

/// In-memory TTL cache for the upstream OHTTP key config.
pub struct KeyConfigCache {
    ttl: Duration,
    state: Mutex<Option<CachedEntry>>,
}

impl KeyConfigCache {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            state: Mutex::new(None),
        }
    }

    /// Return the cached key config if it exists and is still fresh.
    pub fn get(&self) -> Option<(Bytes, Option<String>)> {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.as_ref()
            && entry.fetched_at.elapsed() < self.ttl
        {
            return Some((entry.body.clone(), entry.fingerprint.clone()));
        }
        None
    }

    /// Store a fresh key config response.
    pub fn set(&self, body: Bytes, fingerprint: Option<String>) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(CachedEntry {
            body,
            fingerprint,
            fetched_at: Instant::now(),
        });
    }
}

// INLINE_TEST_REQUIRED: cache is a single-module state machine — splitting
// tests would require re-exporting internal CachedEntry or duplicating setup
#[cfg(test)]
mod tests {
    use super::*;

    // @scenario: key_cache :: empty cache returns None
    #[test]
    fn returns_none_when_empty() {
        let cache = KeyConfigCache::new(Duration::from_secs(60));
        assert!(cache.get().is_none());
    }

    // @scenario: key_cache :: cached value returned within TTL
    #[test]
    fn returns_cached_value_within_ttl() {
        let cache = KeyConfigCache::new(Duration::from_secs(60));
        let body = Bytes::from_static(b"key-config-bytes");
        cache.set(body.clone(), Some("fp-123".to_owned()));

        let (cached_body, cached_fp) = cache.get().expect("should hit cache");
        assert_eq!(cached_body, body);
        assert_eq!(cached_fp.as_deref(), Some("fp-123"));
    }

    // @scenario: key_cache :: expired entry returns None
    #[test]
    fn returns_none_after_ttl_expires() {
        let cache = KeyConfigCache::new(Duration::ZERO);
        cache.set(Bytes::from_static(b"stale"), None);

        // With zero TTL, every get() is a miss.
        assert!(
            cache.get().is_none(),
            "expired entry should not be returned"
        );
    }

    // @scenario: key_cache :: new entry overwrites previous
    #[test]
    fn overwrites_previous_entry() {
        let cache = KeyConfigCache::new(Duration::from_secs(60));
        cache.set(Bytes::from_static(b"old"), Some("fp-old".to_owned()));
        cache.set(Bytes::from_static(b"new"), Some("fp-new".to_owned()));

        let (body, fp) = cache.get().expect("should hit cache");
        assert_eq!(body, Bytes::from_static(b"new"));
        assert_eq!(fp.as_deref(), Some("fp-new"));
    }

    // @scenario: key_cache :: entry expires after non-zero TTL elapses
    #[test]
    fn returns_none_after_nonzero_ttl_elapses() {
        let cache = KeyConfigCache::new(Duration::from_millis(50));
        cache.set(Bytes::from_static(b"expiring"), Some("fp".to_owned()));

        // Fresh — should hit.
        assert!(cache.get().is_some(), "fresh entry should be cached");

        // Wait past TTL.
        std::thread::sleep(Duration::from_millis(60));

        assert!(
            cache.get().is_none(),
            "entry past TTL should not be returned"
        );
    }

    // @scenario: key_cache :: cache works without fingerprint header
    #[test]
    fn works_without_fingerprint() {
        let cache = KeyConfigCache::new(Duration::from_secs(60));
        cache.set(Bytes::from_static(b"key"), None);

        let (_, fp) = cache.get().expect("should hit cache");
        assert!(fp.is_none());
    }
}
