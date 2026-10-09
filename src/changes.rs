//! What changed in the local database
//!
//! Whenever a pull or update replaces a record whose content differs, the
//! difference is recorded per vulnerability and appended to
//! `<db>/changes/<YYYY-MM-DD>.json`: the "what is new since last time"
//! view of an audit.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::db::{EntryKind, IndexEntry};
use crate::error::Result;
use crate::scanner::ComponentType;
use crate::vulnerability::{Vulnerability, record_details};

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
    /// Data source the change was seen in, when it is not WPVulnerability
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
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
            source: None,
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

/// Differences between two snapshots of one source, per component: what
/// was published, withdrawn or edited. Components are keyed by (type,
/// slug); vulnerabilities by id (CVE, or the source's own id). This is the
/// building block for "what is new since last time" and for
/// notifications, whatever the source.
pub fn diff_snapshots(
    old: &HashMap<(ComponentType, String), Vec<Vulnerability>>,
    new: &HashMap<(ComponentType, String), Vec<Vulnerability>>,
    source: &str,
    at: u64,
) -> Vec<Change> {
    let empty = Vec::new();
    let mut keys: Vec<&(ComponentType, String)> = old.keys().chain(new.keys()).collect();
    keys.sort_by(|a, b| (a.0 as u8, &a.1).cmp(&(b.0 as u8, &b.1)));
    keys.dedup();
    let mut out = Vec::new();
    for key in keys {
        let label = format!("{}/{}", key.0, key.1);
        let before = old.get(key).unwrap_or(&empty);
        let after = new.get(key).unwrap_or(&empty);
        let by_id = |list: &[Vulnerability]| -> BTreeMap<String, Vulnerability> {
            list.iter().map(|v| (v.id.clone(), v.clone())).collect()
        };
        let (b, a) = (by_id(before), by_id(after));
        let change = |kind, v: &Vulnerability| Change {
            at,
            key: label.clone(),
            change: kind,
            uuid: Some(v.id.clone()),
            title: Some(v.title.clone()),
            cves: v.cves.clone(),
            source: Some(source.to_string()),
        };
        for (id, v) in &a {
            match b.get(id) {
                None => out.push(change(ChangeKind::Added, v)),
                Some(old) if serde_json::to_string(old).ok() != serde_json::to_string(v).ok() => {
                    out.push(change(ChangeKind::Changed, v))
                }
                Some(_) => {}
            }
        }
        for (id, v) in &b {
            if !a.contains_key(id) {
                out.push(change(ChangeKind::Removed, v));
            }
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
