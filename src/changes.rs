//! What changed in the local database
//!
//! Whenever a pull or update replaces a record whose content differs, the
//! difference is recorded per vulnerability and appended to
//! `<db>/changes/<YYYY-MM-DD>.json`: the "what is new since last time"
//! view of an audit.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::db::{EntryKind, IndexEntry};
use crate::error::Result;
use crate::vulnerability::record_details;

/// Kind of change to one record
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A vulnerability was published for the component
    Added,
    /// A vulnerability was withdrawn or merged upstream
    Removed,
    /// A vulnerability's details changed (affected versions, score, ...)
    Changed,
    /// The component was not tracked before and now is: it can be checked
    NowTracked,
    /// The component was tracked and no longer is: it is not checked now
    NoLongerTracked,
}

/// One change, as written to the change log
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Unix time it was noticed
    pub at: u64,
    /// Record key, such as `plugin/akismet`
    pub key: String,
    /// What happened
    pub change: ChangeKind,
    /// Vulnerability uuid, for per-vulnerability changes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Vulnerability title, when known
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// CVE ids, when known
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cves: Vec<String>,
}

/// Differences between the stored record (`old` entry, and its body when
/// the file could still be read) and a freshly downloaded `new_body`
pub fn diff(
    key: &str,
    old: &IndexEntry,
    old_body: Option<&str>,
    new: &IndexEntry,
    new_body: &str,
    at: u64,
) -> Vec<Change> {
    let change =
        |change, uuid: Option<&str>, detail: Option<&crate::vulnerability::RecordDetail>| Change {
            at,
            key: key.to_string(),
            change,
            uuid: uuid.map(str::to_string),
            title: detail.and_then(|d| d.title.clone()),
            cves: detail.map(|d| d.cves.clone()).unwrap_or_default(),
        };
    let mut out = Vec::new();
    match (old.kind, new.kind) {
        (EntryKind::Untracked, EntryKind::Tracked) => {
            out.push(change(ChangeKind::NowTracked, None, None))
        }
        (EntryKind::Tracked, EntryKind::Untracked) => {
            out.push(change(ChangeKind::NoLongerTracked, None, None))
        }
        _ => {}
    }
    let before: BTreeSet<&String> = old.uuids.iter().collect();
    let after: BTreeSet<&String> = new.uuids.iter().collect();
    let old_details = old_body.map(record_details).unwrap_or_default();
    let new_details = record_details(new_body);
    for uuid in after.difference(&before) {
        out.push(change(
            ChangeKind::Added,
            Some(uuid),
            new_details.get(*uuid),
        ));
    }
    for uuid in before.difference(&after) {
        out.push(change(
            ChangeKind::Removed,
            Some(uuid),
            old_details.get(*uuid),
        ));
    }
    for uuid in before.intersection(&after) {
        if let (Some(o), Some(n)) = (old_details.get(*uuid), new_details.get(*uuid))
            && o.raw != n.raw
        {
            out.push(change(ChangeKind::Changed, Some(uuid), Some(n)));
        }
    }
    out
}

/// Append `changes` to `<dir>/changes/<YYYY-MM-DD>.json` (UTC date of the
/// first change), keeping what earlier runs that day wrote
pub fn append_log(dir: &Path, changes: &[Change]) -> Result<()> {
    let Some(first) = changes.first() else {
        return Ok(());
    };
    let folder = dir.join("changes");
    std::fs::create_dir_all(&folder)?;
    let date = &crate::analyze::iso_date(first.at)[..10];
    let path = folder.join(format!("{date}.json"));
    let mut all: Vec<Change> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    all.extend_from_slice(changes);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&all)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}
