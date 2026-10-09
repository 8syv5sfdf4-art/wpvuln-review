//! Analysis logic for vulnerability scanning

use crate::aliases::MatchedVia;
use crate::scanner::{ComponentInfo, ComponentType, ScanResult};
use crate::vulnerability::{RecordLookup, Severity, Vulnerability, VulnerabilityClient};
use futures::future::join_all;
use serde::{Deserialize, Serialize};

/// What the scan could say about one component. Exactly one applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    /// Tracked, and the installed version is inside an affected range
    Vulnerable,
    /// Like `Vulnerable`, but found through an alias: premium editions may
    /// number versions differently, so confirm before acting
    AliasMatch,
    /// Tracked, and no affected range contains the installed version
    Clean,
    /// The data source has no entry for it: not checked
    Untracked,
    /// The local database never pulled it: not checked
    NotInDb,
    /// No installed version is known, so ranges cannot be compared: not
    /// checked
    UnknownVersion,
    /// The lookup failed (network error, damaged record): not checked
    Failed,
}

impl ComponentState {
    /// Whether the component was actually compared with vulnerability data
    pub fn checked(self) -> bool {
        matches!(self, Self::Vulnerable | Self::AliasMatch | Self::Clean)
    }

    /// Short human label
    pub fn label(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::AliasMatch => "vulnerable (via alias, confirm)",
            Self::Clean => "clean",
            Self::Untracked => "not tracked",
            Self::NotInDb => "not in the local database",
            Self::UnknownVersion => "version unknown",
            Self::Failed => "lookup failed",
        }
    }
}

/// How many components ended in each state
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StateCounts {
    /// See [`ComponentState::Vulnerable`]
    pub vulnerable: usize,
    /// See [`ComponentState::AliasMatch`]
    pub alias_match: usize,
    /// See [`ComponentState::Clean`]
    pub clean: usize,
    /// See [`ComponentState::Untracked`]
    pub untracked: usize,
    /// See [`ComponentState::NotInDb`]
    pub not_in_db: usize,
    /// See [`ComponentState::UnknownVersion`]
    pub unknown_version: usize,
    /// See [`ComponentState::Failed`]
    pub failed: usize,
}

impl StateCounts {
    fn add(&mut self, state: ComponentState) {
        use ComponentState::*;
        *match state {
            Vulnerable => &mut self.vulnerable,
            AliasMatch => &mut self.alias_match,
            Clean => &mut self.clean,
            Untracked => &mut self.untracked,
            NotInDb => &mut self.not_in_db,
            UnknownVersion => &mut self.unknown_version,
            Failed => &mut self.failed,
        } += 1;
    }

    /// Components that were not compared with any data
    pub fn not_checked(&self) -> usize {
        self.untracked + self.not_in_db + self.unknown_version + self.failed
    }
}

/// Vulnerability analysis for a single component
#[derive(Debug, Clone, Serialize)]
pub struct ComponentVulnerabilities {
    /// Component type
    pub component_type: ComponentType,
    /// Component slug
    pub slug: String,
    /// Detected version
    pub version: Option<String>,
    /// Vulnerabilities affecting this component
    pub vulnerabilities: Vec<Vulnerability>,
    /// Highest severity
    pub max_severity: Option<Severity>,
    /// What the scan could say about it
    pub state: ComponentState,
    /// Looked up under its own slug or through an alias
    pub matched_via: MatchedVia,
    /// Installed slug, when looked up through an alias
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_as: Option<String>,
    /// Why it was not checked, or what to keep in mind about the result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl ComponentVulnerabilities {
    /// Check if there are any vulnerabilities
    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    /// Count vulnerabilities
    pub fn vuln_count(&self) -> usize {
        self.vulnerabilities.len()
    }
}

/// Summary of vulnerability counts
#[derive(Debug, Clone, Default, Serialize)]
pub struct VulnerabilitySummary {
    /// Count of critical vulnerabilities
    pub critical: usize,
    /// Count of high severity vulnerabilities
    pub high: usize,
    /// Count of medium severity vulnerabilities
    pub medium: usize,
    /// Count of low severity vulnerabilities
    pub low: usize,
    /// Total count
    pub total: usize,
    /// Components that could not be compared with any data
    pub not_checked: usize,
    /// Components per state
    pub components: StateCounts,
}

impl VulnerabilitySummary {
    /// Create from a list of vulnerabilities
    pub fn from_vulnerabilities(vulns: &[Vulnerability]) -> Self {
        let mut summary = Self::default();
        for v in vulns {
            summary.add_severity(v.severity);
        }
        summary
    }

    /// Create from a list of vulnerability references (avoids cloning)
    pub fn from_refs(vulns: &[&Vulnerability]) -> Self {
        let mut summary = Self::default();
        for v in vulns {
            summary.add_severity(v.severity);
        }
        summary
    }

    /// Add a severity to the counts
    fn add_severity(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
        }
        self.total += 1;
    }

    /// Check if there are any critical or high severity vulnerabilities
    pub fn has_critical_or_high(&self) -> bool {
        self.critical > 0 || self.high > 0
    }

    /// Check if there are any vulnerabilities
    pub fn has_any(&self) -> bool {
        self.total > 0
    }

    /// Get the highest severity level
    pub fn max_severity(&self) -> Option<Severity> {
        if self.critical > 0 {
            Some(Severity::Critical)
        } else if self.high > 0 {
            Some(Severity::High)
        } else if self.medium > 0 {
            Some(Severity::Medium)
        } else if self.low > 0 {
            Some(Severity::Low)
        } else {
            None
        }
    }
}

/// Complete vulnerability analysis
#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    /// Target URL (if scanned from URL)
    pub url: Option<String>,
    /// Scan timestamp
    pub scan_date: String,
    /// Component vulnerability reports
    pub components: Vec<ComponentVulnerabilities>,
    /// Overall summary
    pub summary: VulnerabilitySummary,
}

impl Analysis {
    /// Get all vulnerabilities across all components
    pub fn all_vulnerabilities(&self) -> Vec<&Vulnerability> {
        self.components
            .iter()
            .flat_map(|c| c.vulnerabilities.iter())
            .collect()
    }

    /// Filter components to only those with vulnerabilities
    pub fn vulnerable_components(&self) -> impl Iterator<Item = &ComponentVulnerabilities> {
        self.components.iter().filter(|c| c.has_vulnerabilities())
    }

    /// Get components by severity
    pub fn components_by_severity(&self, severity: Severity) -> Vec<&ComponentVulnerabilities> {
        self.components
            .iter()
            .filter(|c| c.max_severity == Some(severity))
            .collect()
    }
}

/// Analyzer for scan results
pub struct Analyzer {
    client: VulnerabilityClient,
}

impl Analyzer {
    /// Create a new analyzer
    pub fn new() -> crate::error::Result<Self> {
        Self::with_source(crate::vulnerability::Source::default())
    }

    /// Create an analyzer that reads from a specific source
    /// (a mirror of the API, or a local database directory)
    pub fn with_source(source: crate::vulnerability::Source) -> crate::error::Result<Self> {
        Ok(Self {
            client: VulnerabilityClient::with_source(source)?,
        })
    }

    /// Analyze scan results for vulnerabilities
    pub async fn analyze(&self, scan: &ScanResult) -> Analysis {
        // Fetch all vulnerability reports in parallel
        let futures: Vec<_> = scan
            .components
            .iter()
            .map(|component| self.analyze_component(component))
            .collect();

        let components: Vec<ComponentVulnerabilities> = join_all(futures).await;

        // Build summary from all vulnerabilities
        let all_vulns: Vec<&Vulnerability> = components
            .iter()
            .flat_map(|c| c.vulnerabilities.iter())
            .collect();

        let mut summary = VulnerabilitySummary::from_refs(&all_vulns);
        for c in &components {
            summary.components.add(c.state);
        }
        summary.not_checked = summary.components.not_checked();

        Analysis {
            url: if scan.url.is_empty() {
                None
            } else {
                Some(scan.url.clone())
            },
            scan_date: chrono_lite_now(),
            components,
            summary,
        }
    }

    /// Analyze a single component
    async fn analyze_component(&self, component: &ComponentInfo) -> ComponentVulnerabilities {
        let via = if component.installed_as.is_some() {
            MatchedVia::Alias
        } else {
            MatchedVia::Slug
        };
        let key = match component.component_type {
            ComponentType::Core => component.version.as_deref(),
            _ => Some(component.slug.as_str()),
        };
        let looked = match key {
            Some(key) => self.client.lookup(component.component_type, key).await,
            // Core is looked up by version, so there is nothing to ask
            None => RecordLookup::Found(Default::default()),
        };

        let (state, vulnerabilities, note) = match (looked, component.version.as_deref()) {
            (RecordLookup::Failed(why), _) => (ComponentState::Failed, Vec::new(), Some(why)),
            (RecordLookup::Missing, _) => (
                ComponentState::NotInDb,
                Vec::new(),
                Some(
                    "never pulled into the local database; run `db pull` with the same inputs"
                        .into(),
                ),
            ),
            (RecordLookup::Untracked, _) => (
                ComponentState::Untracked,
                Vec::new(),
                Some(
                    "the data source has no entry for it (common for premium and custom code)"
                        .into(),
                ),
            ),
            (RecordLookup::Found(report), None) => {
                let note = match report.vulnerabilities.len() {
                    0 => "no version could be read".to_string(),
                    n => format!(
                        "no version could be read; {n} known vulnerabilit{} affect some versions",
                        if n == 1 { "y" } else { "ies" }
                    ),
                };
                (ComponentState::UnknownVersion, Vec::new(), Some(note))
            }
            (RecordLookup::Found(report), Some(version)) => {
                let found = report.filter_by_version(Some(version)).vulnerabilities;
                let state = match (found.is_empty(), via) {
                    (true, _) => ComponentState::Clean,
                    (false, MatchedVia::Alias) => ComponentState::AliasMatch,
                    (false, MatchedVia::Slug) => ComponentState::Vulnerable,
                };
                let note = (via == MatchedVia::Alias).then(|| {
                    format!(
                        "installed as {}, looked up as {}; premium editions may number versions \
                         differently",
                        component.installed_as.as_deref().unwrap_or_default(),
                        component.slug
                    )
                });
                (state, found, note)
            }
        };

        let max_severity = vulnerabilities.iter().map(|v| v.severity).max();
        ComponentVulnerabilities {
            component_type: component.component_type,
            slug: component.slug.clone(),
            version: component.version.clone(),
            vulnerabilities,
            max_severity,
            state,
            matched_via: via,
            installed_as: component.installed_as.clone(),
            note,
        }
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create analyzer")
    }
}

/// Get current timestamp in ISO format (lightweight, no chrono dependency)
pub(crate) fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    iso_date(duration.as_secs())
}

/// Unix time as `YYYY-MM-DDTHH:MM:SSZ`
pub(crate) fn iso_date(secs: u64) -> String {
    // Calculate date/time components
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let mins = (time_secs % 3600) / 60;
    let secs = time_secs % 60;

    // Days since 1970-01-01
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for days_in_month in days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && !year.is_multiple_of(100) || year.is_multiple_of(400)
}
