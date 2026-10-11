// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Asynchronous OHTTP with a forwarding delay (vauchi/private#628).
//!
//! One hop plus netflow links a client's IP to its mailbox tokens when the
//! gateway sees a fetch the moment the client connects. Here the client
//! posts its encapsulated request under a ticket it chose; the outer relay
//! forwards it after a random delay and holds the encapsulated answer,
//! which only the client can open (RFC 9458 §4.4), until the client
//! collects it on a later poll. Design:
//! `2026-10-11-outer-relay-delayed-forwarding-design`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use axum::body::Bytes;
use axum::http::StatusCode;
use tokio::sync::Notify;
use tokio::time::Instant;

/// How long a request waits at the outer relay before it is forwarded.
#[derive(Debug, Clone, Copy)]
pub enum DelayPolicy {
    /// Uniform on `[0, max]`, drawn from the system CSPRNG: a predictable
    /// delay could be subtracted back out.
    Uniform { max: Duration },
    /// Always the same delay. For tests.
    Fixed(Duration),
}

impl DelayPolicy {
    pub fn sample(&self) -> Duration {
        match *self {
            Self::Fixed(delay) => delay,
            Self::Uniform { max } => {
                let span = max.as_millis() as u64;
                if span == 0 {
                    return Duration::ZERO;
                }
                let mut bytes = [0u8; 8];
                SystemRandom::new()
                    .fill(&mut bytes)
                    .expect("system RNG unavailable");
                Duration::from_millis(u64::from_le_bytes(bytes) % (span + 1))
            }
        }
    }

    pub fn max(&self) -> Duration {
        match *self {
            Self::Fixed(delay) => delay,
            Self::Uniform { max } => max,
        }
    }
}

/// A client-chosen 128-bit ticket, written as 32 lowercase or uppercase
/// hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ticket([u8; 16]);

impl Ticket {
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

/// The outcome of offering a new ticket.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    Accepted,
    /// The ticket is already pending or held.
    Duplicate,
    /// Held answers fill the byte budget.
    Full,
}

/// What a collect finds under a ticket.
#[derive(Debug, PartialEq, Eq)]
pub enum Collected {
    Ready { status: StatusCode, body: Bytes },
    Pending,
    Unknown,
}

enum Entry {
    Waiting,
    Ready {
        status: StatusCode,
        body: Bytes,
        expires: Instant,
    },
}

struct Store {
    entries: HashMap<Ticket, Entry>,
    held_bytes: usize,
}

/// Pending requests and held answers, bounded in time and bytes.
pub struct DelayedForwarding {
    policy: DelayPolicy,
    budget_bytes: usize,
    store: Mutex<Store>,
    completed: Notify,
}

impl DelayedForwarding {
    pub fn new(policy: DelayPolicy, budget_bytes: usize) -> Self {
        Self {
            policy,
            budget_bytes,
            store: Mutex::new(Store {
                entries: HashMap::new(),
                held_bytes: 0,
            }),
            completed: Notify::new(),
        }
    }

    pub fn policy(&self) -> DelayPolicy {
        self.policy
    }

    /// How long a held answer waits for its client: twice the maximum
    /// delay, and at least a minute so a client polling about every minute
    /// can still reach it when the delay is short.
    fn time_to_live(&self) -> Duration {
        (2 * self.policy.max()).max(Duration::from_secs(60))
    }

    /// Bytes of encapsulated answers currently held.
    pub fn held_bytes(&self) -> usize {
        self.lock().held_bytes
    }

    pub fn admit(&self, ticket: Ticket) -> Admission {
        let mut store = self.lock();
        Self::purge(&mut store);
        if store.entries.contains_key(&ticket) {
            return Admission::Duplicate;
        }
        if store.held_bytes >= self.budget_bytes {
            return Admission::Full;
        }
        store.entries.insert(ticket, Entry::Waiting);
        Admission::Accepted
    }

    /// Holds the gateway's answer for a forwarded request.
    pub fn complete(&self, ticket: Ticket, status: StatusCode, body: Bytes) {
        let expires = Instant::now() + self.time_to_live();
        let mut store = self.lock();
        store.held_bytes += body.len();
        store.entries.insert(
            ticket,
            Entry::Ready {
                status,
                body,
                expires,
            },
        );
        drop(store);
        self.completed.notify_one();
    }

    /// Resolves after the next answer is held (or one already was since the
    /// last wait). Lets callers wait for a forward without polling a clock.
    pub async fn answer_held(&self) {
        self.completed.notified().await;
    }

    /// Hands a held answer over once; it is gone afterwards.
    pub fn collect(&self, ticket: Ticket) -> Collected {
        let mut store = self.lock();
        Self::purge(&mut store);
        match store.entries.get(&ticket) {
            None => Collected::Unknown,
            Some(Entry::Waiting) => Collected::Pending,
            Some(Entry::Ready { .. }) => match store.entries.remove(&ticket) {
                Some(Entry::Ready { status, body, .. }) => {
                    store.held_bytes -= body.len();
                    Collected::Ready { status, body }
                }
                _ => Collected::Unknown,
            },
        }
    }

    fn purge(store: &mut Store) {
        let now = Instant::now();
        let mut freed = 0;
        store.entries.retain(|_, entry| match entry {
            Entry::Ready { expires, body, .. } if *expires <= now => {
                freed += body.len();
                false
            }
            _ => true,
        });
        store.held_bytes -= freed;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
