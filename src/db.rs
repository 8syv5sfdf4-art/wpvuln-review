//! Local vulnerability database
//!
//! `pull` downloads WPVulnerability records for a set of components into a
//! directory; [`Source::Local`](crate::vulnerability::Source::Local) then lets
//! the scanner work from that directory with no network access.
//!
//! Layout (one raw API response per component, so the files stay identical
//! to what the API returns and can be inspected or diffed):
//!
//! ```text
//! <dir>/wpvuln-db.json            metadata: format, source, last pull
//! <dir>/plugin/<slug>.json
//! <dir>/theme/<slug>.json
//! <dir>/core/<version>.json
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::stream::{self, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::http::USER_AGENT;
use crate::scanner::ComponentType;
use crate::vulnerability::{api_url, record_count};

/// Database layout version, bumped on incompatible changes
pub const FORMAT_VERSION: u32 = 1;

const META_FILE: &str = "wpvuln-db.json";

/// Metadata stored at the root of a local database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbMeta {
    /// Layout version
    pub format: u32,
    /// API base URL the records were pulled from
    pub source: String,
    /// Unix time of the last pull
    pub pulled_at: u64,
}

fn dir_name(kind: ComponentType) -> &'static str {
    match kind {
        ComponentType::Core => "core",
        ComponentType::Plugin => "plugin",
        ComponentType::Theme => "theme",
    }
}

/// Slugs and versions become file names, so only allow characters that
/// cannot escape the database directory.
pub fn is_safe_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 200
        && !key.starts_with('.')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Path of the record for one component, or `None` for an unsafe key
pub fn record_path(dir: &Path, kind: ComponentType, key: &str) -> Option<PathBuf> {
    is_safe_key(key).then(|| dir.join(dir_name(kind)).join(format!("{key}.json")))
}

/// Options for [`pull`]
#[derive(Debug, Clone)]
pub struct PullOptions {
    /// API base URL
    pub api_url: String,
    /// Requests in flight at once
    pub jobs: usize,
    /// Attempts per component (network errors, 429 and 5xx are retried)
    pub attempts: u32,
    /// Pause before each request, to stay polite to a free API
    pub delay: Duration,
    /// Re-download records that are newer than this; `None` = always
    pub max_age: Option<Duration>,
}

impl Default for PullOptions {
    fn default() -> Self {
        Self {
            api_url: crate::vulnerability::WPVULN_API.to_string(),
            jobs: 4,
            attempts: 3,
            delay: Duration::from_millis(250),
            max_age: None,
        }
    }
}

/// Outcome for one component
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullStatus {
    /// Saved; holds the number of vulnerability records
    Saved(usize),
    /// Already present and fresh enough (see [`PullOptions::max_age`])
    Fresh(usize),
    /// The API has no data for it (404 or an API-level error); an empty
    /// record is stored so offline scans know it was checked
    NoData,
    /// The slug or version contains characters that are not allowed
    Invalid,
    /// Gave up after all attempts; the previous file (if any) is kept
    Failed(String),
}

/// One finished component, reported to the progress callback
#[derive(Debug, Clone)]
pub struct PullEvent {
    /// Component type
    pub kind: ComponentType,
    /// Slug, or core version
    pub key: String,
    /// What happened
    pub status: PullStatus,
    /// Components finished so far
    pub done: usize,
    /// Total components
    pub total: usize,
}

/// Totals for a pull
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullSummary {
    /// Components saved (with or without records)
    pub saved: usize,
    /// Skipped because already fresh
    pub fresh: usize,
    /// No data upstream
    pub no_data: usize,
    /// Rejected keys
    pub invalid: usize,
    /// Failed after retries
    pub failed: usize,
    /// Vulnerability records across saved and fresh components
    pub records: usize,
}

const EMPTY_RECORD: &str = r#"{"error":0,"message":null,"data":{"vulnerability":[]}}"#;

/// Download records for `items` into `dir`.
///
/// Every component is attempted; one failure never stops the rest.
/// `on_event` is called once per component as it finishes.
pub async fn pull(
    dir: &Path,
    items: &[(ComponentType, String)],
    opts: &PullOptions,
    mut on_event: impl FnMut(&PullEvent),
) -> Result<PullSummary> {
    for kind in [
        ComponentType::Core,
        ComponentType::Plugin,
        ComponentType::Theme,
    ] {
        std::fs::create_dir_all(dir.join(dir_name(kind)))?;
    }
    let client = Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::HttpClient(e.to_string()))?;

    let mut unique: Vec<(ComponentType, String)> = Vec::new();
    for item in items {
        if !unique.contains(item) {
            unique.push(item.clone());
        }
    }
    let total = unique.len();
    let base = opts.api_url.trim_end_matches('/').to_string();

    let mut results = stream::iter(unique.into_iter().map(|(kind, key)| {
        let client = &client;
        let base = &base;
        async move {
            let status = pull_one(client, base, dir, kind, &key, opts).await;
            (kind, key, status)
        }
    }))
    .buffer_unordered(opts.jobs.max(1));

    let mut summary = PullSummary::default();
    let mut done = 0;
    while let Some((kind, key, status)) = results.next().await {
        done += 1;
        match &status {
            PullStatus::Saved(n) => {
                summary.saved += 1;
                summary.records += n;
            }
            PullStatus::Fresh(n) => {
                summary.fresh += 1;
                summary.records += n;
            }
            PullStatus::NoData => summary.no_data += 1,
            PullStatus::Invalid => summary.invalid += 1,
            PullStatus::Failed(_) => summary.failed += 1,
        }
        on_event(&PullEvent {
            kind,
            key,
            status,
            done,
            total,
        });
    }
    drop(results);

    write_meta(
        dir,
        &DbMeta {
            format: FORMAT_VERSION,
            source: base,
            pulled_at: now(),
        },
    )?;
    Ok(summary)
}

async fn pull_one(
    client: &Client,
    base: &str,
    dir: &Path,
    kind: ComponentType,
    key: &str,
    opts: &PullOptions,
) -> PullStatus {
    let Some(path) = record_path(dir, kind, key) else {
        return PullStatus::Invalid;
    };

    if let Some(max_age) = opts.max_age
        && let Ok(meta) = std::fs::metadata(&path)
        && meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age < max_age)
        && let Some(n) = std::fs::read_to_string(&path)
            .ok()
            .as_deref()
            .and_then(record_count)
    {
        return PullStatus::Fresh(n);
    }

    let url = api_url(base, kind, key);
    let mut last_error = String::new();
    for attempt in 0..opts.attempts.max(1) {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1 << (attempt - 1).min(4))).await;
        }
        tokio::time::sleep(opts.delay).await;

        let response = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                last_error = short_error(&e);
                continue;
            }
        };
        let code = response.status();
        if code == StatusCode::NOT_FOUND {
            return save(&path, EMPTY_RECORD, PullStatus::NoData);
        }
        if code == StatusCode::TOO_MANY_REQUESTS || code.is_server_error() {
            last_error = format!("HTTP {}", code.as_u16());
            continue;
        }
        if !code.is_success() {
            return PullStatus::Failed(format!("HTTP {}", code.as_u16()));
        }
        let body = match response.text().await {
            Ok(b) => b,
            Err(e) => {
                last_error = short_error(&e);
                continue;
            }
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
            last_error = "response is not JSON (blocked or rate limited?)".to_string();
            continue;
        };
        if value.get("error").and_then(|e| e.as_i64()).unwrap_or(0) != 0 {
            return save(&path, EMPTY_RECORD, PullStatus::NoData);
        }
        let n = record_count(&body).unwrap_or(0);
        return save(&path, &body, PullStatus::Saved(n));
    }
    PullStatus::Failed(last_error)
}

/// Write via a temp file and rename, so an interrupted pull never leaves
/// a half-written record behind.
fn save(path: &Path, body: &str, ok: PullStatus) -> PullStatus {
    let tmp = path.with_extension("json.tmp");
    match std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, path)) {
        Ok(()) => ok,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            PullStatus::Failed(format!("write failed: {e}"))
        }
    }
}

fn short_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".to_string()
    } else if e.is_connect() {
        "connection failed".to_string()
    } else {
        e.to_string()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_meta(dir: &Path, meta: &DbMeta) -> Result<()> {
    let json = serde_json::to_string_pretty(meta)?;
    std::fs::write(dir.join(META_FILE), json)?;
    Ok(())
}

/// Contents of a local database
#[derive(Debug, Clone, Default, Serialize)]
pub struct DbStatus {
    /// Metadata, if the directory has been pulled into
    pub meta: Option<DbMeta>,
    /// Stored plugin records
    pub plugins: usize,
    /// Stored theme records
    pub themes: usize,
    /// Stored core records
    pub core: usize,
    /// Total vulnerability records across all files
    pub records: usize,
    /// Unix time of the oldest record file
    pub oldest: Option<u64>,
}

/// Inspect a local database directory
pub fn status(dir: &Path) -> Result<DbStatus> {
    let mut st = DbStatus {
        meta: std::fs::read_to_string(dir.join(META_FILE))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok()),
        ..Default::default()
    };
    for kind in [
        ComponentType::Core,
        ComponentType::Plugin,
        ComponentType::Theme,
    ] {
        let Ok(entries) = std::fs::read_dir(dir.join(dir_name(kind))) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match kind {
                ComponentType::Core => st.core += 1,
                ComponentType::Plugin => st.plugins += 1,
                ComponentType::Theme => st.themes += 1,
            }
            st.records += std::fs::read_to_string(&path)
                .ok()
                .as_deref()
                .and_then(record_count)
                .unwrap_or(0);
            if let Some(t) = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
            {
                st.oldest = Some(st.oldest.map_or(t, |o| o.min(t)));
            }
        }
    }
    Ok(st)
}

/// Components from `items` that have no record in `dir`
pub fn missing<'a>(
    dir: &Path,
    items: impl IntoIterator<Item = (ComponentType, &'a str)>,
) -> Vec<&'a str> {
    items
        .into_iter()
        .filter(|(kind, key)| !record_path(dir, *kind, key).is_some_and(|p| p.is_file()))
        .map(|(_, key)| key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_keys() {
        assert!(is_safe_key("woocommerce"));
        assert!(is_safe_key("6.4.3"));
        assert!(is_safe_key("wp_rocket-2"));
        assert!(!is_safe_key(""));
        assert!(!is_safe_key("../etc/passwd"));
        assert!(!is_safe_key("a/b"));
        assert!(!is_safe_key(".hidden"));
        assert!(!is_safe_key("wp-rocket--:x"));
    }

    #[test]
    fn record_paths() {
        let d = Path::new("/db");
        assert_eq!(
            record_path(d, ComponentType::Plugin, "akismet"),
            Some(PathBuf::from("/db/plugin/akismet.json"))
        );
        assert_eq!(
            record_path(d, ComponentType::Core, "6.4.3"),
            Some(PathBuf::from("/db/core/6.4.3.json"))
        );
        assert_eq!(record_path(d, ComponentType::Theme, "../x"), None);
    }
}
