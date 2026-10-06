// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cache for the gateway's signed key record (#288 plan 3.1).
//!
//! A record signs one 24 h UTC window's key, so it is cached until the
//! earlier of the configured TTL and the end of that window: never past the
//! boundary, where clients would get a key for a window they already left.
//! The record stays opaque: the outer relay reads only the window and
//! verifies nothing, because clients verify the signature chain themselves.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;

/// Seconds since the Unix epoch; injectable so tests cross a window
/// boundary without waiting for one.
pub type UnixClock = Arc<dyn Fn() -> u64 + Send + Sync>;

const WINDOW_SECONDS: u64 = 86_400;
/// `vauchi_protocol::ohttp_key::RECORD_VERSION`; the outer relay does not
/// depend on core, so the layout it reads is restated here.
const RECORD_VERSION: u8 = 1;

pub struct SignedKeyCache {
    ttl_secs: u64,
    clock: UnixClock,
    entry: Mutex<Option<(Bytes, u64)>>,
}

impl SignedKeyCache {
    /// The shared cache the server runs with, or `None` when the TTL is 0.
    pub fn if_enabled(ttl: Duration) -> Option<Arc<Self>> {
        (!ttl.is_zero()).then(|| Arc::new(Self::with_clock(ttl, Arc::new(system_unix_now))))
    }

    pub fn with_clock(ttl: Duration, clock: UnixClock) -> Self {
        Self {
            ttl_secs: ttl.as_secs(),
            clock,
            entry: Mutex::new(None),
        }
    }

    /// The cached record, while it is fresh.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn get(&self) -> Option<Bytes> {
        let now = (self.clock)();
        let guard = self.entry.lock().expect("signed key cache mutex poisoned");
        guard
            .as_ref()
            .filter(|(_, expires_at)| now < *expires_at)
            .map(|(body, _)| body.clone())
    }

    /// Keep `body` until the TTL or its window ends; a record whose window
    /// has already ended is not kept at all.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn set(&self, body: Bytes) {
        let now = (self.clock)();
        let by_ttl = now.saturating_add(self.ttl_secs);
        let expires_at = window_end(&body).map_or(by_ttl, |end| end.min(by_ttl));
        let mut guard = self.entry.lock().expect("signed key cache mutex poisoned");
        *guard = (expires_at > now).then_some((body, expires_at));
    }
}

impl std::fmt::Debug for SignedKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedKeyCache")
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

/// Record layout: version (1) | window (u64 BE) | …
fn window_end(record: &[u8]) -> Option<u64> {
    let (&version, rest) = record.split_first()?;
    if version != RECORD_VERSION {
        return None;
    }
    let window = u64::from_be_bytes(rest.get(..8)?.try_into().ok()?);
    window.checked_add(1)?.checked_mul(WINDOW_SECONDS)
}

fn system_unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
