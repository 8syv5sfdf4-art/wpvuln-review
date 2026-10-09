//! Wordfence Intelligence as a vulnerability source
//!
//! Two file formats carry the same data:
//!
//! - **wpprobe** (`[...]`): the keyless file wpprobe rebuilds from
//!   Wordfence every few hours. One flat record per vulnerability, software
//!   and affected range; bounds `0.0.0` / `999999.0.0` mean unlimited. Records
//!   without a CVE were dropped by wpprobe.
//! - **raw** (`{...}`): the official Intelligence v3 feed, keyed by UUID,
//!   with every record, `patched_versions`, references and CWE.
//!
//! Both are parsed as a stream, so a several-hundred-megabyte feed never
//! sits in memory, and normalised into [`Vulnerability`] values with all
//! affected ranges, indexed by component type and slug.
//!
//! Wordfence lists only software with known vulnerabilities. A slug it does
//! not know is therefore "untracked", which is not proof of safety.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::scanner::ComponentType;
use crate::vulnerability::{
    Bound, Severity, SourceKind, VersionRange, Vulnerability, decode_entities,
};

/// Attribution required by the Wordfence Intelligence terms (§3.1)
pub const ATTRIBUTION: &str = "Vulnerability data from Wordfence Intelligence, \
     Copyright (c) Defiant, Inc. (https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/). \
     CVE records Copyright (c) The MITRE Corporation.";

/// Which file format a feed is in
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputFormat {
    /// wpprobe's flat array
    Wpprobe,
    /// The official Intelligence v3 feed
    WordfenceRaw,
}

/// Which components to keep while parsing
#[derive(Debug, Clone)]
pub enum Keep {
    /// Everything
    All,
    /// Only these (type, lowercase slug) pairs; what a scan needs
    Only(HashSet<(ComponentType, String)>),
    /// Nothing, only count (to validate a download)
    Count,
}

impl Keep {
    fn wants(&self, key: &(ComponentType, String)) -> bool {
        match self {
            Keep::All => true,
            Keep::Only(set) => set.contains(key),
            Keep::Count => false,
        }
    }
}

/// A parsed Wordfence feed, indexed by component
#[derive(Debug, Default)]
pub struct WordfenceIndex {
    /// File format it came from
    pub format: Option<InputFormat>,
    /// Records in the file (before grouping)
    pub records: usize,
    /// Distinct software entries (type and slug) in the file
    pub slugs: usize,
    entries: HashMap<(ComponentType, String), Vec<Vulnerability>>,
}

impl WordfenceIndex {
    /// Parse a feed file
    pub fn load(path: &Path, keep: &Keep) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| Error::Wordfence(format!("{}: {e}", path.display())))?;
        Self::from_reader(file, keep)
            .map_err(|e| Error::Wordfence(format!("{}: {e}", path.display())))
    }

    /// Parse a feed from any reader; the format is told by its first byte
    pub fn from_reader(reader: impl Read, keep: &Keep) -> std::result::Result<Self, String> {
        let mut reader = BufReader::with_capacity(1 << 16, reader);
        let format = sniff(&mut reader)?;
        let mut builder = Builder {
            keep,
            index: WordfenceIndex {
                format: Some(format),
                ..Default::default()
            },
            seen: HashSet::new(),
            groups: HashMap::new(),
        };
        let mut de = serde_json::Deserializer::from_reader(reader);
        let result = match format {
            InputFormat::Wpprobe => de.deserialize_seq(&mut builder),
            InputFormat::WordfenceRaw => de.deserialize_map(&mut builder),
        };
        result.map_err(|e| format!("not a valid Wordfence feed ({e})"))?;
        de.end()
            .map_err(|e| format!("unexpected data after the feed ({e})"))?;
        let mut index = builder.index;
        index.slugs = builder.seen.len();
        if index.records == 0 {
            return Err("the feed holds no records".to_string());
        }
        Ok(index)
    }

    /// Vulnerabilities for one component; `None` when Wordfence has no entry
    /// for it (or it was not kept)
    pub fn lookup(&self, kind: ComponentType, slug: &str) -> Option<&[Vulnerability]> {
        self.entries
            .get(&(kind, slug.to_ascii_lowercase()))
            .map(Vec::as_slice)
    }

    /// Distinct vulnerabilities kept
    pub fn vulnerabilities(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    /// Everything kept, keyed by (type, slug): for comparing two snapshots
    pub fn entries(&self) -> &HashMap<(ComponentType, String), Vec<Vulnerability>> {
        &self.entries
    }
}

/// `[` means wpprobe, `{` the raw feed; anything else (an HTML block page,
/// an error message) is refused
fn sniff(reader: &mut impl BufRead) -> std::result::Result<InputFormat, String> {
    loop {
        let buf = reader.fill_buf().map_err(|e| e.to_string())?;
        let Some(&first) = buf.first() else {
            return Err("the file is empty".to_string());
        };
        let skip = buf
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count()
            .max(if buf.starts_with(b"\xEF\xBB\xBF") {
                3
            } else {
                0
            });
        if skip == 0 {
            return match first {
                b'[' => Ok(InputFormat::Wpprobe),
                b'{' => Ok(InputFormat::WordfenceRaw),
                b'<' => Err(
                    "this is HTML, not JSON: probably a login, block or captive portal page \
                     instead of the feed"
                        .to_string(),
                ),
                _ => {
                    Err("not JSON: expected a list (wpprobe) or an object (Wordfence feed)".into())
                }
            };
        }
        reader.consume(skip);
    }
}

fn component_type(kind: &str) -> Option<ComponentType> {
    match kind {
        "plugin" => Some(ComponentType::Plugin),
        "theme" => Some(ComponentType::Theme),
        "core" => Some(ComponentType::Core),
        _ => None,
    }
}

/// A bound, where wpprobe's `0.0.0` (from) and `999999.0.0` (to), and `*`
/// or nothing, mean no limit
fn bound(version: Option<&str>, inclusive: Option<bool>, sentinel: &str) -> Bound {
    match version.map(str::trim) {
        Some(v) if v == sentinel => Bound::Unbounded,
        v => Bound::new(v, inclusive.unwrap_or(true)),
    }
}

/// Authentication needed, from wpprobe's `auth_type` or the CVSS vector
fn auth_from_vector(vector: Option<&str>) -> Option<String> {
    let pr = vector?.split('/').find_map(|p| p.strip_prefix("PR:"))?;
    Some(
        match pr {
            "N" => "Unauth",
            "L" => "Auth",
            "H" => "Privileged",
            _ => return None,
        }
        .to_string(),
    )
}

fn severity(score: Option<f32>, label: Option<&str>) -> Severity {
    match (score, label.map(str::to_ascii_lowercase).as_deref()) {
        (Some(s), _) if s > 0.0 => Severity::from_cvss(s),
        (_, Some("critical")) => Severity::Critical,
        (_, Some("high")) => Severity::High,
        (_, Some("low" | "none")) => Severity::Low,
        _ => Severity::Medium,
    }
}

fn number<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<f32>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        F(f64),
        S(String),
    }
    Ok(match Option::<N>::deserialize(d)? {
        Some(N::F(f)) => Some(f as f32),
        Some(N::S(s)) => s.trim().parse().ok(),
        None => None,
    })
}

/// One wpprobe record: one vulnerability, one software, one range
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ProbeRecord {
    title: String,
    slug: String,
    #[serde(rename = "type")]
    kind: String,
    from_version: Option<String>,
    from_inclusive: Option<bool>,
    to_version: Option<String>,
    to_inclusive: Option<bool>,
    severity: Option<String>,
    cve: Option<String>,
    cve_link: Option<String>,
    auth_type: Option<String>,
    #[serde(deserialize_with = "number")]
    cvss_score: Option<f32>,
    cvss_vector: Option<String>,
}

/// One record of the official feed
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRecord {
    id: String,
    title: String,
    software: Vec<RawSoftware>,
    informational: bool,
    description: Option<String>,
    references: Vec<String>,
    cwe: Option<RawCwe>,
    cvss: Option<RawCvss>,
    cve: Option<String>,
    cve_link: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawSoftware {
    #[serde(rename = "type")]
    kind: String,
    slug: String,
    affected_versions: HashMap<String, RawRange>,
    patched: bool,
    patched_versions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRange {
    from_version: Option<String>,
    from_inclusive: Option<bool>,
    to_version: Option<String>,
    to_inclusive: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawCwe {
    id: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawCvss {
    vector: Option<String>,
    #[serde(deserialize_with = "number")]
    score: Option<f32>,
    rating: Option<String>,
}

/// Builds the index while the feed streams past
struct Builder<'a> {
    keep: &'a Keep,
    index: WordfenceIndex,
    seen: HashSet<(ComponentType, String)>,
    /// wpprobe: (type, slug, cve, title) -> position in the entry list
    groups: HashMap<(ComponentType, String, String, String), usize>,
}

fn base(title: &str, cve: Option<String>, uuid: String) -> Vulnerability {
    let cve = cve.filter(|c| !c.trim().is_empty());
    Vulnerability {
        id: cve.clone().unwrap_or_else(|| uuid.clone()),
        title: decode_entities(title),
        severity: Severity::Medium,
        cvss_score: None,
        affected_max: None,
        max_op: None,
        affected_min: None,
        min_op: None,
        fixed_in: None,
        references: Vec::new(),
        uuid,
        cves: cve.into_iter().collect(),
        affected: String::new(),
        unfixed: false,
        cvss_vector: None,
        cwes: Vec::new(),
        known_exploited: None,
        epss: None,
        description: None,
        ranges: Vec::new(),
        sources: vec![SourceKind::Wordfence],
        patched_versions: Vec::new(),
        informational: false,
        auth: None,
        fixed_branch: None,
    }
}

impl Builder<'_> {
    fn probe(&mut self, r: ProbeRecord) {
        self.index.records += 1;
        let Some(kind) = component_type(&r.kind) else {
            return;
        };
        let key = (kind, r.slug.to_ascii_lowercase());
        self.seen.insert(key.clone());
        if !self.keep.wants(&key) {
            return;
        }
        let range = VersionRange {
            from: bound(r.from_version.as_deref(), r.from_inclusive, "0.0.0"),
            to: bound(r.to_version.as_deref(), r.to_inclusive, "999999.0.0"),
        };
        let cve = r.cve.clone().unwrap_or_default();
        let group = (kind, key.1.clone(), cve.clone(), r.title.clone());
        let list = self.index.entries.entry(key).or_default();
        if let Some(&i) = self.groups.get(&group) {
            if !list[i].ranges.contains(&range) {
                list[i].ranges.push(range);
            }
            return;
        }
        let mut v = base(&r.title, r.cve, cve);
        v.cvss_score = r.cvss_score.filter(|s| *s > 0.0);
        v.severity = severity(v.cvss_score, r.severity.as_deref());
        v.auth = r
            .auth_type
            .or_else(|| auth_from_vector(r.cvss_vector.as_deref()));
        v.cvss_vector = r.cvss_vector.filter(|s| !s.is_empty());
        v.references = r.cve_link.into_iter().filter(|l| !l.is_empty()).collect();
        v.ranges = vec![range];
        self.groups.insert(group, list.len());
        list.push(v);
    }

    fn raw(&mut self, uuid: String, r: RawRecord) {
        self.index.records += 1;
        let cvss = r.cvss.unwrap_or_default();
        for sw in &r.software {
            let Some(kind) = component_type(&sw.kind) else {
                continue;
            };
            let key = (kind, sw.slug.to_ascii_lowercase());
            self.seen.insert(key.clone());
            if !self.keep.wants(&key) {
                continue;
            }
            let id = if r.id.is_empty() {
                uuid.clone()
            } else {
                r.id.clone()
            };
            let mut v = base(&r.title, r.cve.clone(), id);
            v.cvss_score = cvss.score.filter(|s| *s > 0.0);
            v.severity = severity(v.cvss_score, cvss.rating.as_deref());
            v.cvss_vector = cvss.vector.clone().filter(|s| !s.is_empty());
            v.auth = auth_from_vector(v.cvss_vector.as_deref());
            v.informational = r.informational;
            v.description = r
                .description
                .as_deref()
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(decode_entities);
            v.references = r.references.clone();
            if let Some(link) = r.cve_link.clone().filter(|l| !l.is_empty())
                && !v.references.contains(&link)
            {
                v.references.insert(0, link);
            }
            v.cwes = r
                .cwe
                .as_ref()
                .and_then(|c| c.id)
                .map(|id| format!("CWE-{id}"))
                .into_iter()
                .collect();
            v.patched_versions = sw.patched_versions.clone();
            v.unfixed = !sw.patched && sw.patched_versions.is_empty();
            let mut labels: Vec<&String> = sw.affected_versions.keys().collect();
            labels.sort();
            for label in labels {
                let a = &sw.affected_versions[label];
                let range = VersionRange {
                    from: bound(a.from_version.as_deref(), a.from_inclusive, "*"),
                    to: bound(a.to_version.as_deref(), a.to_inclusive, "*"),
                };
                if !v.ranges.contains(&range) {
                    v.ranges.push(range);
                }
            }
            if v.ranges.is_empty() {
                v.ranges.push(VersionRange::all());
            }
            self.index.entries.entry(key).or_default().push(v);
        }
    }
}

impl<'de> Visitor<'de> for &mut Builder<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a Wordfence feed (a list of records, or an object of records by id)")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while let Some(record) = seq.next_element::<ProbeRecord>()? {
            self.probe(record);
        }
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        while let Some((uuid, record)) = map.next_entry::<String, RawRecord>()? {
            self.raw(uuid, record);
        }
        Ok(())
    }
}
