// SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OHTTP Relay Configuration
//!
//! All configuration is loaded from environment variables. No file-based
//! config is supported to keep the binary stateless.
//!
//! Parsing is separated from environment I/O: [`RelayConfig::from_env`] reads
//! the process environment into a map and delegates to [`RelayConfig::from_map`],
//! which is pure and testable without mutating global state.

use std::collections::HashMap;
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
    /// Per-IP rate limit for the OHTTP forward endpoint (requests per second).
    /// Set to 0 to disable rate limiting.
    pub rate_limit_per_sec: u32,
    /// Maximum number of per-IP rate-limit buckets kept in memory. A burst of
    /// unique source IPs can otherwise exhaust memory before stale-entry
    /// eviction runs. Set to 0 to disable the cap. Default: 100_000.
    pub rate_limit_max_buckets: usize,
    /// Timeout for upstream requests.
    pub request_timeout: Duration,
    /// Optional HTTP header name to extract the real client IP from.
    ///
    /// When the relay sits behind a load balancer or CDN, `ConnectInfo` yields
    /// the proxy's IP, making per-client rate limiting useless. Set this to the
    /// header your proxy injects (e.g. `X-Forwarded-For`, `X-Real-IP`,
    /// `CF-Connecting-IP`) so the rate limiter keys on the real client IP.
    ///
    /// When using a multi-hop header like `X-Forwarded-For`, set
    /// `client_ip_header_trusted_proxies` to the number of proxies between this
    /// relay and the client; the extractor then selects the client IP from the
    /// right end of the list, counting back by that many entries. A value of `0`
    /// means the rightmost value is trusted (e.g. `X-Real-IP` set by the closest
    /// proxy). Without this, clients can prepend arbitrary IPs and evade or
    /// bloat rate limiting.
    pub client_ip_header: Option<String>,
    /// Number of trusted proxies between this relay and the client for the
    /// configured `client_ip_header`. Used to select the correct IP from the
    /// right end of comma-separated lists like `X-Forwarded-For`. Default: 0.
    pub client_ip_header_trusted_proxies: usize,
    /// TTL for caching upstream `/v2/ohttp-key` responses.
    /// Prevents thunder herd when many clients bootstrap simultaneously.
    /// Set to 0 to disable caching. Default: 300 seconds (5 minutes).
    pub key_cache_ttl: Duration,
}

impl RelayConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns an error if any required variable is missing or malformed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&vars)
    }

    /// Parse configuration from a key/value map.
    ///
    /// Pure function: tests can call this without touching process-wide
    /// environment variables.
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self, ConfigError> {
        let listen_addr = get_or(vars, "OHTTP_RELAY_LISTEN_ADDR", "0.0.0.0:8082")
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::parse("OHTTP_RELAY_LISTEN_ADDR", e.to_string()))?;

        let gateway_url = get_required(vars, "OHTTP_RELAY_GATEWAY_URL")?;
        let gateway_url = validate_gateway_url(&gateway_url)?;

        let max_request_bytes = parse_usize(vars, "OHTTP_RELAY_MAX_REQUEST_BYTES", "65536")?;
        let max_response_bytes = parse_usize(vars, "OHTTP_RELAY_MAX_RESPONSE_BYTES", "131072")?;
        let max_key_response_bytes =
            parse_usize(vars, "OHTTP_RELAY_MAX_KEY_RESPONSE_BYTES", "4096")?;
        let rate_limit_per_sec = parse_u32(vars, "OHTTP_RELAY_RATE_LIMIT_PER_SEC", "50")?;
        let rate_limit_max_buckets =
            parse_usize(vars, "OHTTP_RELAY_RATE_LIMIT_MAX_BUCKETS", "100000")?;
        let timeout_secs = parse_u64(vars, "OHTTP_RELAY_REQUEST_TIMEOUT_SECS", "30")?;

        let client_ip_header = vars
            .get("OHTTP_RELAY_CLIENT_IP_HEADER")
            .cloned()
            .filter(|s| !s.is_empty());
        let client_ip_header_trusted_proxies =
            parse_usize(vars, "OHTTP_RELAY_CLIENT_IP_HEADER_TRUSTED_PROXIES", "0")?;

        let key_cache_ttl_secs = parse_u64(vars, "OHTTP_RELAY_KEY_CACHE_TTL_SECS", "300")?;
        Ok(RelayConfig {
            listen_addr,
            gateway_url,
            max_request_bytes,
            max_response_bytes,
            max_key_response_bytes,
            rate_limit_per_sec,
            rate_limit_max_buckets,
            request_timeout: Duration::from_secs(timeout_secs),
            client_ip_header,
            client_ip_header_trusted_proxies,
            key_cache_ttl: Duration::from_secs(key_cache_ttl_secs),
        })
    }
}

fn get_required(vars: &HashMap<String, String>, key: &'static str) -> Result<String, ConfigError> {
    vars.get(key)
        .cloned()
        .ok_or_else(|| ConfigError::missing(key))
}

fn get_or<'a>(vars: &'a HashMap<String, String>, key: &'static str, default: &'a str) -> &'a str {
    vars.get(key).map(String::as_str).unwrap_or(default)
}

fn parse_usize(
    vars: &HashMap<String, String>,
    key: &'static str,
    default: &str,
) -> Result<usize, ConfigError> {
    get_or(vars, key, default)
        .parse::<usize>()
        .map_err(|e| ConfigError::parse(key, e.to_string()))
}

fn parse_u32(
    vars: &HashMap<String, String>,
    key: &'static str,
    default: &str,
) -> Result<u32, ConfigError> {
    get_or(vars, key, default)
        .parse::<u32>()
        .map_err(|e| ConfigError::parse(key, e.to_string()))
}

fn parse_u64(
    vars: &HashMap<String, String>,
    key: &'static str,
    default: &str,
) -> Result<u64, ConfigError> {
    get_or(vars, key, default)
        .parse::<u64>()
        .map_err(|e| ConfigError::parse(key, e.to_string()))
}

/// Validate and normalize a gateway URL.
///
/// Accepts only `http(s)://host[:port]` with no path, query, fragment, or
/// embedded credentials. Returns the URL without a trailing slash.
pub fn validate_gateway_url(url: &str) -> Result<String, ConfigError> {
    let parsed = url::Url::parse(url).map_err(|e| {
        ConfigError::parse("OHTTP_RELAY_GATEWAY_URL", format!("not a valid URL: {e}"))
    })?;

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "scheme must be http or https".to_owned(),
        ));
    }

    if parsed.username() != "" || parsed.password().is_some() {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "must not contain credentials".to_owned(),
        ));
    }

    if parsed.query().is_some() {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "must not contain a query string".to_owned(),
        ));
    }

    if parsed.fragment().is_some() {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "must not contain a fragment".to_owned(),
        ));
    }

    // url::Url normalizes an empty path to "/"; reject anything else.
    if parsed.path() != "/" {
        return Err(ConfigError::parse(
            "OHTTP_RELAY_GATEWAY_URL",
            "must not contain a path".to_owned(),
        ));
    }

    let mut normalized = parsed.to_string();
    if normalized.ends_with('/') {
        normalized.pop();
    }

    Ok(normalized)
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

// INLINE_TEST_REQUIRED: `from_map`/`validate_gateway_url` tests exercise
// private helpers and error constructors that are not exposed outside this module.
#[cfg(test)]
mod tests {
    use super::*;

    fn vars_with_gateway(url: &str) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("OHTTP_RELAY_GATEWAY_URL".to_owned(), url.to_owned());
        vars
    }

    #[test]
    fn validate_gateway_url_rejects_missing_scheme() {
        let err = validate_gateway_url("vauchi-relay:8080").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for missing scheme"
        );
    }

    // @scenario: config :: trailing slash is normalized away
    #[test]
    fn validate_gateway_url_rejects_trailing_slash() {
        let url = validate_gateway_url("http://vauchi-relay:8080/").unwrap();
        assert_eq!(url, "http://vauchi-relay:8080");
    }

    // @scenario: config :: path in gateway URL is rejected
    #[test]
    fn validate_gateway_url_rejects_path() {
        let err = validate_gateway_url("http://vauchi-relay:8080/path").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for path"
        );
    }

    // @scenario: config :: query string in gateway URL is rejected
    #[test]
    fn validate_gateway_url_rejects_query() {
        let err = validate_gateway_url("http://vauchi-relay:8080?foo=bar").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for query"
        );
    }

    // @scenario: config :: fragment in gateway URL is rejected
    #[test]
    fn validate_gateway_url_rejects_fragment() {
        let err = validate_gateway_url("http://vauchi-relay:8080#frag").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for fragment"
        );
    }

    // @scenario: config :: embedded credentials in gateway URL are rejected
    #[test]
    fn validate_gateway_url_rejects_credentials() {
        let err = validate_gateway_url("http://user:pass@vauchi-relay:8080").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for credentials"
        );
    }

    // @scenario: config :: valid HTTP gateway URL is accepted
    #[test]
    fn validate_gateway_url_accepts_valid_http() {
        let url = validate_gateway_url("http://vauchi-relay:8080").unwrap();
        assert_eq!(url, "http://vauchi-relay:8080");
    }

    // @scenario: config :: valid HTTPS gateway URL is accepted
    #[test]
    fn validate_gateway_url_accepts_valid_https() {
        let url = validate_gateway_url("https://vauchi-relay:8080").unwrap();
        assert_eq!(url, "https://vauchi-relay:8080");
    }

    // @scenario: config :: gateway URL without port is accepted
    #[test]
    fn validate_gateway_url_accepts_host_without_port() {
        let url = validate_gateway_url("http://vauchi-relay").unwrap();
        assert_eq!(url, "http://vauchi-relay");
    }

    // @scenario: config :: empty host in gateway URL is rejected
    #[test]
    fn validate_gateway_url_rejects_empty_host() {
        let err = validate_gateway_url("http://").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected parse error for empty host"
        );
    }

    // @internal
    #[test]
    fn config_error_display_missing() {
        let err = ConfigError::missing("MY_VAR");
        let msg = err.to_string();
        assert_eq!(msg, "required env var MY_VAR is not set");
    }

    // @internal
    #[test]
    fn config_error_display_parse() {
        let err = ConfigError::parse("MY_VAR", "not a number".to_owned());
        let msg = err.to_string();
        assert_eq!(msg, "env var MY_VAR is invalid: not a number");
    }

    // @scenario: config :: required gateway URL and defaults are applied
    #[test]
    fn from_map_requires_gateway_url_and_applies_defaults() {
        let mut vars = HashMap::new();
        vars.insert(
            "OHTTP_RELAY_GATEWAY_URL".to_owned(),
            "http://localhost:8080".to_owned(),
        );

        let cfg =
            RelayConfig::from_map(&vars).expect("config with only required var should succeed");
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
        assert_eq!(
            cfg.rate_limit_per_sec, 50,
            "default rate_limit_per_sec should be 50"
        );
        assert_eq!(
            cfg.rate_limit_max_buckets, 100_000,
            "default rate_limit_max_buckets should be 100_000"
        );
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.gateway_url, "http://localhost:8080");
        assert!(
            cfg.client_ip_header.is_none(),
            "client_ip_header should default to None"
        );
        assert_eq!(
            cfg.client_ip_header_trusted_proxies, 0,
            "client_ip_header_trusted_proxies should default to 0"
        );
        assert_eq!(
            cfg.key_cache_ttl,
            Duration::from_secs(300),
            "default key_cache_ttl should be 300 seconds"
        );
    }

    // @scenario: config :: missing gateway URL produces an error
    #[test]
    fn from_map_missing_gateway_url_errors() {
        let vars = HashMap::new();
        let err = RelayConfig::from_map(&vars).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Missing {
                    var: "OHTTP_RELAY_GATEWAY_URL"
                }
            ),
            "expected missing error for OHTTP_RELAY_GATEWAY_URL"
        );
    }

    // @scenario: config :: non-empty client_ip_header is preserved
    #[test]
    fn from_map_preserves_non_empty_client_ip_header() {
        let mut vars = vars_with_gateway("http://localhost:8080");
        vars.insert(
            "OHTTP_RELAY_CLIENT_IP_HEADER".to_owned(),
            "X-Real-IP".to_owned(),
        );

        let cfg = RelayConfig::from_map(&vars).expect("config should succeed");
        assert_eq!(
            cfg.client_ip_header.as_deref(),
            Some("X-Real-IP"),
            "non-empty client_ip_header should be preserved"
        );
    }

    // @scenario: config :: empty client_ip_header is filtered out
    #[test]
    fn from_map_filters_empty_client_ip_header() {
        let mut vars = vars_with_gateway("http://localhost:8080");
        vars.insert("OHTTP_RELAY_CLIENT_IP_HEADER".to_owned(), "".to_owned());

        let cfg = RelayConfig::from_map(&vars).expect("config should succeed");
        assert!(
            cfg.client_ip_header.is_none(),
            "empty client_ip_header should be filtered to None"
        );
    }

    // @scenario: config :: trusted proxy count is parsed
    #[test]
    fn from_map_parses_client_ip_header_trusted_proxies() {
        let mut vars = vars_with_gateway("http://localhost:8080");
        vars.insert(
            "OHTTP_RELAY_CLIENT_IP_HEADER_TRUSTED_PROXIES".to_owned(),
            "2".to_owned(),
        );

        let cfg = RelayConfig::from_map(&vars).expect("config should succeed");
        assert_eq!(cfg.client_ip_header_trusted_proxies, 2);
    }

    // @scenario: config :: rate-limit bucket cap is parsed
    #[test]
    fn from_map_parses_rate_limit_max_buckets() {
        let mut vars = vars_with_gateway("http://localhost:8080");
        vars.insert(
            "OHTTP_RELAY_RATE_LIMIT_MAX_BUCKETS".to_owned(),
            "50000".to_owned(),
        );

        let cfg = RelayConfig::from_map(&vars).expect("config should succeed");
        assert_eq!(cfg.rate_limit_max_buckets, 50_000);
    }
}
