// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OHTTP Relay Configuration
//!
//! All configuration is loaded from environment variables. No file-based
//! config is supported to keep the binary stateless.

use std::net::SocketAddr;
use std::time::Duration;

/// Configuration for the OHTTP relay server.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Address the relay HTTP server listens on.
    pub listen_addr: SocketAddr,
    /// Base URL of the upstream vauchi-relay gateway (no trailing slash).
    /// Example: `http://vauchi-relay:8080`
    pub gateway_url: String,
    /// Maximum allowed request body size in bytes.
    pub max_request_bytes: usize,
    /// Maximum allowed upstream response body size in bytes (default: 128 KiB).
    pub max_response_bytes: usize,
    /// Maximum allowed upstream key response body size in bytes (default: 4 KiB).
    pub max_key_response_bytes: usize,
    /// Timeout for upstream requests.
    pub request_timeout: Duration,
}

impl RelayConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns an error if any required variable is missing or malformed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = env_or("OHTTP_RELAY_LISTEN_ADDR", "0.0.0.0:8082")
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::parse("OHTTP_RELAY_LISTEN_ADDR", e.to_string()))?;

        let gateway_url = std::env::var("OHTTP_RELAY_GATEWAY_URL")
            .map_err(|_| ConfigError::missing("OHTTP_RELAY_GATEWAY_URL"))?;
        validate_gateway_url(&gateway_url)?;

        let max_request_bytes = env_or("OHTTP_RELAY_MAX_REQUEST_BYTES", "65536")
            .parse::<usize>()
            .map_err(|e| ConfigError::parse("OHTTP_RELAY_MAX_REQUEST_BYTES", e.to_string()))?;

        let max_response_bytes = env_or("OHTTP_RELAY_MAX_RESPONSE_BYTES", "131072")
            .parse::<usize>()
            .map_err(|e| ConfigError::parse("OHTTP_RELAY_MAX_RESPONSE_BYTES", e.to_string()))?;

        let max_key_response_bytes = env_or("OHTTP_RELAY_MAX_KEY_RESPONSE_BYTES", "4096")
            .parse::<usize>()
            .map_err(|e| ConfigError::parse("OHTTP_RELAY_MAX_KEY_RESPONSE_BYTES", e.to_string()))?;

        let timeout_secs = env_or("OHTTP_RELAY_REQUEST_TIMEOUT_SECS", "30")
            .parse::<u64>()
            .map_err(|e| ConfigError::parse("OHTTP_RELAY_REQUEST_TIMEOUT_SECS", e.to_string()))?;

        Ok(RelayConfig {
            listen_addr,
            gateway_url,
            max_request_bytes,
            max_response_bytes,
            max_key_response_bytes,
            request_timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn validate_gateway_url(url: &str) -> Result<(), ConfigError> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "must start with http:// or https://".to_owned(),
        ));
    }
    if url.ends_with('/') {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "must not have a trailing slash".to_owned(),
        ));
    }
    Ok(())
}

/// Configuration loading error.
#[derive(Debug)]
pub enum ConfigError {
    Missing { var: &'static str },
    Parse { var: &'static str, detail: String },
}

impl ConfigError {
    fn missing(var: &'static str) -> Self {
        ConfigError::Missing { var }
    }

    fn parse(var: &'static str, detail: String) -> Self {
        ConfigError::Parse { var, detail }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Missing { var } => write!(f, "required env var {var} is not set"),
            ConfigError::Parse { var, detail } => {
                write!(f, "env var {var} is invalid: {detail}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    // INLINE_TEST_REQUIRED: config defaults and validation

    #[test]
    fn validate_gateway_url_rejects_missing_scheme() {
        let err = validate_gateway_url("vauchi-relay:8080").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for missing scheme"
        );
    }

    #[test]
    fn validate_gateway_url_rejects_trailing_slash() {
        let err = validate_gateway_url("http://vauchi-relay:8080/").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for trailing slash"
        );
    }

    #[test]
    fn validate_gateway_url_accepts_valid_http() {
        validate_gateway_url("http://vauchi-relay:8080")
            .expect("valid http URL should be accepted");
    }

    #[test]
    fn validate_gateway_url_accepts_valid_https() {
        validate_gateway_url("https://vauchi-relay:8080")
            .expect("valid https URL should be accepted");
    }

    // Tests that call RelayConfig::from_env() must run serially because they
    // mutate process-wide environment variables.  We achieve this by running
    // the env-touching assertions inside a single test function guarded by a
    // mutex rather than relying on separate test functions (which could run in
    // parallel under the default multi-threaded test harness).

    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn from_env_requires_gateway_url_and_applies_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();

        // Part 1: missing required var returns an error.
        // SAFETY: held under ENV_LOCK, so no other test thread is touching these vars.
        unsafe { std::env::remove_var("OHTTP_RELAY_GATEWAY_URL") };

        let err = RelayConfig::from_env().unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Missing {
                    var: "OHTTP_RELAY_GATEWAY_URL"
                }
            ),
            "expected missing error for OHTTP_RELAY_GATEWAY_URL"
        );

        // Part 2: with only the required var, defaults are applied correctly.
        // SAFETY: held under ENV_LOCK.
        unsafe {
            std::env::set_var("OHTTP_RELAY_GATEWAY_URL", "http://localhost:8080");
            std::env::remove_var("OHTTP_RELAY_LISTEN_ADDR");
            std::env::remove_var("OHTTP_RELAY_MAX_REQUEST_BYTES");
            std::env::remove_var("OHTTP_RELAY_REQUEST_TIMEOUT_SECS");
        }

        let cfg = RelayConfig::from_env().expect("config with only required var should succeed");
        assert_eq!(cfg.listen_addr.to_string(), "0.0.0.0:8082");
        assert_eq!(cfg.max_request_bytes, 65536);
        assert_eq!(
            cfg.max_response_bytes, 131072,
            "default max_response_bytes should be 128 KiB"
        );
        assert_eq!(
            cfg.max_key_response_bytes, 4096,
            "default max_key_response_bytes should be 4 KiB"
        );
        assert_eq!(cfg.request_timeout, std::time::Duration::from_secs(30));
        assert_eq!(cfg.gateway_url, "http://localhost:8080");

        // Cleanup — leave env in a known state for other tests.
        // SAFETY: held under ENV_LOCK.
        unsafe { std::env::remove_var("OHTTP_RELAY_GATEWAY_URL") };
    }
}
