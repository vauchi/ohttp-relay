// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! TTL cache for upstream OHTTP key config responses.
//!
//! The gateway's key config changes at most once per rotation period (default
//! 24 hours). Caching prevents a thundering herd on the upstream when many
//! clients bootstrap simultaneously (app update rollout, relay restart).
//!
//! The clock is injectable via the [`Clock`] trait so tests can verify TTL
//! behavior deterministically without `thread::sleep`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;

use crate::clock::{Clock, StdClock};

#[derive(Debug)]
struct CachedEntry {
    body: Bytes,
    fingerprint: Option<String>,
    fetched_at: Instant,
}

/// In-memory TTL cache for the upstream OHTTP key config.
#[derive(Debug)]
pub struct KeyConfigCache {
    ttl: Duration,
    clock: Arc<dyn Clock>,
    state: Mutex<Option<CachedEntry>>,
}

impl KeyConfigCache {
    /// Create a new cache with the given TTL using the system clock.
    pub fn new(ttl: Duration) -> Self {
        Self::with_clock(ttl, Arc::new(StdClock))
    }

    /// Create a new cache with the given TTL and clock.
    ///
    /// Useful in tests that need deterministic control over time.
    pub fn with_clock<C>(ttl: Duration, clock: Arc<C>) -> Self
    where
        C: Clock + 'static,
    {
        Self {
            ttl,
            clock,
            state: Mutex::new(None),
        }
    }

    /// Return the cached key config if it exists and is still fresh.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get(&self) -> Option<(Bytes, Option<String>)> {
        let guard = self.state.lock().expect("key cache mutex poisoned");
        if let Some(entry) = guard.as_ref() {
            let age = self.clock.now().duration_since(entry.fetched_at);
            if age < self.ttl {
                return Some((entry.body.clone(), entry.fingerprint.clone()));
            }
        }
        None
    }

    /// Store a fresh key config response.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set(&self, body: Bytes, fingerprint: Option<String>) {
        let mut guard = self.state.lock().expect("key cache mutex poisoned");
        *guard = Some(CachedEntry {
            body,
            fingerprint,
            fetched_at: self.clock.now(),
        });
    }
}

// INLINE_TEST_REQUIRED: Tests access the internal mutex and `CachedEntry` directly;
// integration tests cannot reach these crate-private internals.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;

    /// Deterministic clock for tests.
    #[derive(Debug)]
    struct FakeClock {
        now: Mutex<Instant>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                now: Mutex::new(Instant::now()),
            }
        }

        fn advance(&self, duration: Duration) {
            *self.now.lock().unwrap() += duration;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

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
        let clock = Arc::new(FakeClock::new());
        let cache = KeyConfigCache::with_clock(Duration::from_millis(50), Arc::clone(&clock));
        cache.set(Bytes::from_static(b"expiring"), Some("fp".to_owned()));

        // Fresh — should hit.
        assert!(cache.get().is_some(), "fresh entry should be cached");

        // Advance past TTL.
        clock.advance(Duration::from_millis(60));

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

    // @internal
    #[test]
    #[should_panic(expected = "key cache mutex poisoned")]
    fn panics_on_mutex_poisoning() {
        let cache = KeyConfigCache::new(Duration::from_secs(60));

        // Poison the mutex by panicking while holding the lock.
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.state.lock().unwrap();
            panic!("intentional panic while holding mutex");
        });

        // The next get must panic instead of silently recovering from poisoning.
        let _ = cache.get();
    }
}
