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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// A per-IP token bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum tokens (burst capacity) per IP.
    capacity: u32,
    /// Token refill rate (tokens per second).
    refill_rate: f64,
    /// Per-IP bucket state, protected by a mutex.
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `requests_per_sec` controls both the refill rate and the burst capacity
    /// (burst = requests_per_sec, allowing short bursts up to 1 second's worth).
    pub fn new(requests_per_sec: u32) -> Self {
        RateLimiter {
            capacity: requests_per_sec,
            refill_rate: f64::from(requests_per_sec),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Try to consume one token for the given IP.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: f64::from(self.capacity),
            last_refill: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(f64::from(self.capacity));
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove stale entries older than the given duration.
    ///
    /// Should be called periodically to prevent unbounded memory growth.
    pub fn evict_stale(&self, max_age: std::time::Duration) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(5);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Should allow up to 5 requests (burst capacity).
        for i in 0..5 {
            assert!(limiter.check(ip), "request {i} should be allowed");
        }
    }

    #[test]
    fn rejects_requests_over_limit() {
        let limiter = RateLimiter::new(3);
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
        let limiter = RateLimiter::new(2);
        let ip_a: IpAddr = "10.0.0.3".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.4".parse().unwrap();

        // Exhaust IP A's bucket.
        assert!(limiter.check(ip_a));
        assert!(limiter.check(ip_a));
        assert!(!limiter.check(ip_a), "IP A should be rate-limited");

        // IP B should still have its own fresh bucket.
        assert!(limiter.check(ip_b), "IP B should not be affected by IP A");
    }

    #[test]
    fn evict_stale_removes_old_entries() {
        let limiter = RateLimiter::new(10);
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        limiter.check(ip);

        // With zero max_age, everything is stale.
        limiter.evict_stale(std::time::Duration::ZERO);

        let buckets = limiter.buckets.lock().unwrap();
        assert!(buckets.is_empty(), "stale entries should be evicted");
    }
}
