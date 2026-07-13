// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Injectable clock abstraction for deterministic time-based logic.
//!
//! Production code uses [`StdClock`]; tests use a fake clock so TTL and rate
//! logic can be verified without `thread::sleep`.

use std::time::Instant;

/// Source of time for caches, rate limiters, and other time-dependent
/// components.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current time.
    fn now(&self) -> Instant;
}

/// System clock backed by [`Instant::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StdClock;

impl Clock for StdClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
