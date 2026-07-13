// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-IP token bucket rate limiter.
//!
//! Provides a simple in-memory rate limiter keyed by IP address. Each IP gets
//! a token bucket that refills at a configurable rate. When the bucket is
//! empty, requests are rejected with 429 Too Many Requests.
//!
//! The rate limiter does not log or store IP addresses beyond the HashMap key
//! needed for rate tracking. Entries are evicted lazily when stale.
//!
//! The clock is injectable via the [`Clock`] trait so tests can control time
//! deterministically without `thread::sleep`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::clock::{Clock, StdClock};

/// Mutable token-bucket state for a single IP.
///
/// This type is intentionally small and pure: all time-dependent mutations are
/// performed by [`TokenBucket::check`], which receives the current time and the
/// rate-limit parameters from the caller. The mutex that guards the per-IP map
/// lives in [`RateLimiter`], not here.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    /// Current token count.
    tokens: f64,
    /// Last time the bucket was refilled.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a full bucket.
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
        }
    }

    /// Refill the bucket based on elapsed time and try to consume one token.
    ///
    /// Returns `true` if a token was consumed (request allowed), `false` if the
    /// bucket is empty (request rate-limited).
    fn check(&mut self, capacity: f64, refill_rate: f64, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_rate).min(capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A per-IP token bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum tokens (burst capacity) per IP.
    capacity: u32,
    /// Token refill rate (tokens per second).
    refill_rate: f64,
    /// Source of current time; injectable for testing.
    clock: Arc<dyn Clock>,
    /// Per-IP bucket state, protected by a mutex.
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    /// Maximum number of buckets to retain. When exceeded, the oldest entries
    /// are evicted in a batch so memory does not grow unbounded under a burst
    /// of unique source IPs.
    max_buckets: usize,
}

impl RateLimiter {
    /// Create a new rate limiter using the system clock.
    ///
    /// `requests_per_sec` controls both the refill rate and the burst capacity
    /// (burst = requests_per_sec, allowing short bursts up to 1 second's worth).
    /// `max_buckets` bounds the per-IP map size; set to 0 to disable the cap.
    pub fn new(requests_per_sec: u32, max_buckets: usize) -> Self {
        Self::with_clock(requests_per_sec, max_buckets, Arc::new(StdClock))
    }

    /// Create a new rate limiter with the given clock.
    ///
    /// Useful in tests that need deterministic control over time.
    pub fn with_clock<C>(requests_per_sec: u32, max_buckets: usize, clock: Arc<C>) -> Self
    where
        C: Clock + 'static,
    {
        RateLimiter {
            capacity: requests_per_sec,
            refill_rate: f64::from(requests_per_sec),
            clock,
            buckets: Mutex::new(HashMap::new()),
            max_buckets,
        }
    }

    /// Try to consume one token for the given IP.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned. Mutex poisoning indicates a
    /// thread panicked while holding the lock; silently recovering could leave
    /// the bucket state inconsistent, so we treat it as a fatal error.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let now = self.clock.now();

        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(f64::from(self.capacity), now));

        let allowed = bucket.check(f64::from(self.capacity), self.refill_rate, now);

        // Enforce a hard memory cap by evicting the oldest entries when the map
        // grows too large. Eviction happens after the current request so that
        // the request itself is always counted.
        if self.max_buckets > 0 && buckets.len() > self.max_buckets {
            Self::evict_oldest_to_target(&mut buckets, self.max_buckets * 3 / 4);
        }

        allowed
    }

    /// Remove the oldest entries until the bucket count is at most `target`.
    fn evict_oldest_to_target(buckets: &mut HashMap<IpAddr, TokenBucket>, target: usize) {
        if buckets.len() <= target {
            return;
        }

        // Find the `excess` oldest entries by last_refill time. A full sort is
        // acceptable because this runs only when the cap is exceeded, which
        // should be rare under normal traffic patterns.
        let mut oldest: Vec<(IpAddr, Instant)> = buckets
            .iter()
            .map(|(ip, bucket)| (*ip, bucket.last_refill))
            .collect();
        oldest.sort_by_key(|(_, last_refill)| *last_refill);

        let excess = buckets.len() - target;
        for (ip, _) in oldest.into_iter().take(excess) {
            buckets.remove(&ip);
        }
    }

    /// Remove stale entries older than the given duration.
    ///
    /// Should be called periodically to prevent unbounded memory growth.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn evict_stale(&self, max_age: Duration) {
        let mut buckets = self.buckets.lock().expect("rate limiter mutex poisoned");
        let now = self.clock.now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

// INLINE_TEST_REQUIRED: Tests exercise the internal `TokenBucket`, mutex, and
// clock injection that are not exposed outside this module.
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

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(5, 100_000);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Should allow up to 5 requests (burst capacity).
        for i in 0..5 {
            assert!(limiter.check(ip), "request {i} should be allowed");
        }
    }

    #[test]
    fn rejects_requests_over_limit() {
        let limiter = RateLimiter::new(3, 100_000);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();

        // Exhaust the bucket.
        for _ in 0..3 {
            assert!(limiter.check(ip));
        }

        // Next request should be rejected.
        assert!(!limiter.check(ip), "request over limit should be rejected");
    }

    #[test]
    fn different_ips_have_separate_buckets() {
        let limiter = RateLimiter::new(2, 100_000);
        let ip_a: IpAddr = "10.0.0.3".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.4".parse().unwrap();

        // Exhaust IP A's bucket.
        assert!(limiter.check(ip_a));
        assert!(limiter.check(ip_a));
        assert!(!limiter.check(ip_a), "IP A should be rate-limited");

        // IP B should still have its own fresh bucket.
        assert!(limiter.check(ip_b), "IP B should not be affected by IP A");
    }

    // @internal
    #[test]
    fn tokens_refill_over_time() {
        let clock = Arc::new(FakeClock::new());
        let limiter = RateLimiter::with_clock(2, 100_000, Arc::clone(&clock));
        let ip: IpAddr = "10.0.0.6".parse().unwrap();

        // Exhaust the bucket.
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip), "bucket should be empty");

        // Advance time long enough for at least 1 token to refill.
        // With refill_rate=2.0 tokens/sec, 600ms should yield ~1.2 tokens.
        clock.advance(Duration::from_millis(600));

        // Should be allowed again after refill.
        assert!(
            limiter.check(ip),
            "token should have refilled after waiting"
        );
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let limiter = RateLimiter::new(10, 100_000);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        limiter.check(ip);

        // With zero max_age, everything is stale.
        limiter.evict_stale(Duration::ZERO);

        let buckets = limiter.buckets.lock().unwrap();
        assert!(buckets.is_empty(), "stale entries should be evicted");
    }

    // @scenario: rate_limit :: evict with nonzero max_age removes old entries
    #[test]
    fn evict_stale_removes_entries_older_than_nonzero_max_age() {
        let clock = Arc::new(FakeClock::new());
        let limiter = RateLimiter::with_clock(10, 100_000, Arc::clone(&clock));
        let ip: IpAddr = "10.0.0.8".parse().unwrap();

        limiter.check(ip);

        // Advance past the max_age threshold.
        clock.advance(Duration::from_millis(60));

        // Entry is ~60ms old; evict anything older than 30ms.
        limiter.evict_stale(Duration::from_millis(30));

        let buckets = limiter.buckets.lock().unwrap();
        assert!(
            !buckets.contains_key(&ip),
            "entry older than max_age should be evicted"
        );
    }

    // @internal
    #[test]
    fn evict_stale_retains_fresh_entries() {
        let limiter = RateLimiter::new(10, 100_000);
        let ip: IpAddr = "10.0.0.7".parse().unwrap();

        // Create an entry just now.
        limiter.check(ip);

        // With a large max_age, the fresh entry should survive eviction.
        limiter.evict_stale(Duration::from_secs(3600));

        let buckets = limiter.buckets.lock().unwrap();
        assert!(
            buckets.contains_key(&ip),
            "fresh entries should not be evicted with large max_age"
        );
    }

    // @scenario: rate_limit :: memory cap evicts oldest buckets
    #[test]
    fn evict_oldest_when_max_buckets_exceeded() {
        let limiter = RateLimiter::new(10, 3);

        // Create three buckets with a small delay so they have distinct last_refill
        // times. Use IPv4 addresses that sort predictably by value, but eviction
        // uses last_refill time, not IP value.
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        let ip_c: IpAddr = "10.0.0.3".parse().unwrap();
        let ip_d: IpAddr = "10.0.0.4".parse().unwrap();

        assert!(limiter.check(ip_a));
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check(ip_b));
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check(ip_c));

        // A fourth unique IP should trigger eviction down to target = 3 * 3/4 = 2.
        assert!(limiter.check(ip_d));

        let buckets = limiter.buckets.lock().unwrap();
        assert_eq!(
            buckets.len(),
            2,
            "cap should evict oldest down to 75% target"
        );
        assert!(
            !buckets.contains_key(&ip_a),
            "oldest bucket should be evicted"
        );
        assert!(buckets.contains_key(&ip_c), "newer bucket should remain");
        assert!(
            buckets.contains_key(&ip_d),
            "just-used bucket should remain"
        );
    }

    // @scenario: rate_limit :: mutex poisoning is not silently recovered
    #[test]
    #[should_panic(expected = "rate limiter mutex poisoned")]
    fn panics_on_mutex_poisoning() {
        let limiter = RateLimiter::new(5, 100_000);
        let ip: IpAddr = "10.0.0.9".parse().unwrap();

        // Poison the mutex by panicking while holding the lock.
        let _ = std::panic::catch_unwind(|| {
            let _guard = limiter.buckets.lock().unwrap();
            panic!("intentional panic while holding mutex");
        });

        // The next check must panic instead of silently recovering from poisoning.
        limiter.check(ip);
    }
}
