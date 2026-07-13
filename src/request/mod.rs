// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Request preprocessing utilities.
//!
//! These helpers live outside the router so that `router.rs` stays focused on
//! route wiring and handler orchestration.

pub mod bounded_body;
pub mod client_ip;
pub mod context;

pub use bounded_body::{BodyLimitError, read_bounded_body};
pub use client_ip::extract_client_ip;
pub use context::RequestContext;
