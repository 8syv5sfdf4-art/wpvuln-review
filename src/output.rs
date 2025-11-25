//! Output formatting for vulnerability scan results

use crate::analyze::{Analysis, ComponentVulnerabilities};
use crate::error::{Error, Result};
use crate::vulnerability::Severity;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table, presets::UTF8_FULL};
use std::io::Write;
use std::str::FromStr;

/// Output format for results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Human-readable table output
    #[default]
    Human,
    /// JSON output
    Json,
    /// No output (silent mode)
    None,
}

impl FromStr for OutputFormat {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            "none" => Ok(Self::None),
            _ => Err(Error::InvalidOutputFormat(s.to_string())),
        }
    }
}

/// Configuration for output formatting
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Minimum severity to display
    pub min_severity: Severity,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Human,
            min_severity: Severity::Low,
        }
    }
}

impl OutputConfig {
    /// Create a new output config
    pub fn new(format: OutputFormat, min_severity: Severity) -> Self {
        Self {
            format,
            min_severity,
        }
    }
}

/// Output the analysis results
pub fn output_analysis<W: Write>(
    analysis: &Analysis,
    config: &OutputConfig,
    writer: &mut W,
) -> Result<()> {
    match config.format {
        OutputFormat::Human => output_human(analysis, config, writer),
        OutputFormat::Json => output_json(analysis, writer),
        OutputFormat::None => Ok(()),
    }
}

/// Output JSON format
fn output_json<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    serde_json::to_writer_pretty(&mut *writer, analysis)?;
    writeln!(writer)?;
    Ok(())
}

/// Output human-readable format
fn output_human<W: Write>(
    analysis: &Analysis,
    config: &OutputConfig,
    writer: &mut W,
) -> Result<()> {
    // Print target URL if available
    if let Some(ref url) = analysis.url {
        writeln!(writer, "Target: {}", url)?;
        writeln!(writer)?;
    }

    // Check if any vulnerabilities found
    if !analysis.summary.has_any() {
        writeln!(writer, "No vulnerabilities found.")?;
        return Ok(());
    }

    // Group and display by severity (highest first)
    let severities = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    for severity in severities {
        if severity < config.min_severity {
            continue;
        }

        let components: Vec<_> = analysis
            .components
            .iter()
            .filter(|c| c.vulnerabilities.iter().any(|v| v.severity == severity))
            .collect();

        if components.is_empty() {
            continue;
        }

        let count: usize = components
            .iter()
            .map(|c| {
                c.vulnerabilities
                    .iter()
                    .filter(|v| v.severity == severity)
                    .count()
            })
            .sum();

        // Severity header
        let header = format!("{} ({})", severity.to_string().to_uppercase(), count);
        let header_color = severity_color(severity);
        writeln!(writer, "{}", colorize(&header, header_color))?;

        // Build table for this severity level
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Component").add_attribute(Attribute::Bold),
                Cell::new("Version").add_attribute(Attribute::Bold),
                Cell::new("Vulnerability").add_attribute(Attribute::Bold),
                Cell::new("Fixed").add_attribute(Attribute::Bold),
            ]);

        for component in &components {
            for vuln in component
                .vulnerabilities
                .iter()
                .filter(|v| v.severity == severity)
            {
                add_vulnerability_row(&mut table, component, vuln);
            }
        }

        writeln!(writer, "{}", table)?;
        writeln!(writer)?;
    }

    // Summary
    writeln!(
        writer,
        "Summary: {} Critical, {} High, {} Medium, {} Low",
        analysis.summary.critical,
        analysis.summary.high,
        analysis.summary.medium,
        analysis.summary.low
    )?;

    Ok(())
}

/// Add a row for a vulnerability
fn add_vulnerability_row(
    table: &mut Table,
    component: &ComponentVulnerabilities,
    vuln: &crate::vulnerability::Vulnerability,
) {
    let component_name = match component.component_type {
        crate::scanner::ComponentType::Core => "WordPress".to_string(),
        crate::scanner::ComponentType::Plugin => component.slug.clone(),
        crate::scanner::ComponentType::Theme => format!("Theme: {}", component.slug),
    };

    let version = component.version.as_deref().unwrap_or("-");

    let title = truncate_title(&vuln.title);

    let vuln_desc = format!("{}: {}", vuln.id, title);

    let fixed = vuln
        .fixed_in
        .as_deref()
        .or(vuln.affected_max.as_deref())
        .map(|v| format!(">{}", v))
        .unwrap_or_else(|| "-".to_string());

    table.add_row(vec![
        Cell::new(component_name),
        Cell::new(version),
        Cell::new(vuln_desc),
        Cell::new(fixed),
    ]);
}

/// Get color for severity level
fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => Color::Red,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::DarkYellow,
    }
}

/// Maximum title length before truncation
const MAX_TITLE_LENGTH: usize = 40;

/// Truncate title if too long, adding ellipsis
fn truncate_title(title: &str) -> String {
    if title.len() > MAX_TITLE_LENGTH {
        format!("{}...", &title[..MAX_TITLE_LENGTH - 3])
    } else {
        title.to_string()
    }
}

/// Apply ANSI color to text
fn colorize(text: &str, color: Color) -> String {
    let code = match color {
        Color::Red => "31",
        Color::Yellow => "33",
        Color::DarkYellow => "33",
        Color::Green => "32",
        _ => "0",
    };
    format!("\x1b[{}m{}\x1b[0m", code, text)
}
