// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // Exercise URL validation with arbitrary strings.
    // Should never panic — only return Ok/Err.
    let _ = vauchi_ohttp_relay::config::validate_gateway_url(data);
});
