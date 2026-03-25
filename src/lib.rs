// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `vauchi-ohttp-relay` — minimal OHTTP forwarding proxy.
//!
//! This crate is a pure HTTP pass-through proxy. It does **not** decrypt or
//! inspect OHTTP payloads. Its only responsibilities are:
//!
//! 1. Receive opaque encrypted blobs from clients and forward them to an
//!    upstream vauchi-relay gateway.
//! 2. Proxy the gateway's OHTTP public key so clients can bootstrap without
//!    knowing the gateway's address.
//! 3. Enforce request size limits and strip identifying headers before any
//!    upstream call.
//!
//! # Security invariants
//! - Client IPs are never read, logged, or forwarded.
//! - No headers from client requests are propagated upstream.
//! - No state is stored between requests.

pub mod config;
pub mod rate_limit;
pub mod router;
pub mod upstream;
