//! Shared HTTP constants

/// User agent for scanning live sites (browser-like to avoid blocking)
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Request timeout in seconds
pub const TIMEOUT_SECS: u64 = 30;

/// User agent for the vulnerability API: it names the tool, so the free,
/// volunteer-run service can see who is calling and reach the project
pub const API_USER_AGENT: &str = concat!(
    "wordpress-vulnerable-scanner/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/robdotec/wordpress-vulnerable-scanner)"
);
