//! Analysis logic for vulnerability scanning

use crate::scanner::{ComponentInfo, ComponentType, ScanResult};
use crate::vulnerability::{Severity, Vulnerability, VulnerabilityClient};
use futures::future::join_all;
use serde::Serialize;

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
        Ok(Self {
            client: VulnerabilityClient::new()?,
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

        let summary = VulnerabilitySummary::from_refs(&all_vulns);

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
        let report = match component.component_type {
            ComponentType::Core => {
                if let Some(ref version) = component.version {
                    self.client.fetch_core_vulns(version).await
                } else {
                    None
                }
            }
            ComponentType::Plugin => self.client.fetch_plugin_vulns(&component.slug).await,
            ComponentType::Theme => self.client.fetch_theme_vulns(&component.slug).await,
        };

        let filtered = report
            .unwrap_or_default()
            .filter_by_version(component.version.as_deref());

        let max_severity = filtered.max_severity();

        ComponentVulnerabilities {
            component_type: component.component_type,
            slug: component.slug.clone(),
            version: component.version.clone(),
            vulnerabilities: filtered.vulnerabilities,
            max_severity,
        }
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create analyzer")
    }
}

/// Get current timestamp in ISO format (lightweight, no chrono dependency)
fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();

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
