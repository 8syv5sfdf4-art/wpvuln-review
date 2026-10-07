//! Output formatting for vulnerability scan results

use crate::analyze::{Analysis, ComponentState, ComponentVulnerabilities};
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

    let summary = &analysis.summary;
    // Check if any vulnerabilities found
    if !summary.has_any() {
        if summary.not_checked == 0 {
            writeln!(writer, "No vulnerabilities found.")?;
            return Ok(());
        }
        writeln!(
            writer,
            "No vulnerabilities found in the {} components that could be checked.\n",
            analysis.components.len() - summary.not_checked
        )?;
        write_not_checked(analysis, writer)?;
        write_summary(analysis, writer)?;
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

    write_alias_notes(analysis, writer)?;
    write_not_checked(analysis, writer)?;
    write_summary(analysis, writer)?;
    Ok(())
}

/// Name of a component as shown in reports: installed slug, plus what it
/// was looked up as when that differs
fn display_name(c: &ComponentVulnerabilities) -> String {
    let base = match (c.component_type, c.installed_as.as_deref()) {
        (crate::scanner::ComponentType::Core, _) => "WordPress".to_string(),
        (_, Some(installed)) => format!("{installed} (as {})", c.slug),
        (_, None) => c.slug.clone(),
    };
    match c.component_type {
        crate::scanner::ComponentType::Theme => format!("Theme: {base}"),
        _ => base,
    }
}

/// Findings that came through an alias need a human to confirm them
fn write_alias_notes<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    let via_alias: Vec<_> = analysis
        .components
        .iter()
        .filter(|c| c.state == ComponentState::AliasMatch)
        .collect();
    if via_alias.is_empty() {
        return Ok(());
    }
    writeln!(
        writer,
        "{}",
        colorize(
            "Found through an alias, confirm before acting",
            Color::Yellow
        )
    )?;
    for c in via_alias {
        writeln!(
            writer,
            "  {} {}: premium editions may number versions differently",
            display_name(c),
            c.version.as_deref().unwrap_or("-")
        )?;
    }
    writeln!(writer)?;
    Ok(())
}

/// Everything that was not compared with any data, grouped by why: these
/// are neither safe nor vulnerable as far as this scan knows
fn write_not_checked<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    if analysis.summary.not_checked == 0 {
        return Ok(());
    }
    writeln!(
        writer,
        "{}",
        colorize(
            &format!(
                "NOT CHECKED ({}): not known to be safe, review by hand",
                analysis.summary.not_checked
            ),
            Color::Yellow
        )
    )?;
    for (state, why) in [
        (
            ComponentState::Untracked,
            "the data source has no entry (common for premium and custom code)",
        ),
        (
            ComponentState::NotInDb,
            "never pulled into the local database; run `db pull` with the same inputs",
        ),
        (
            ComponentState::UnknownVersion,
            "no version could be read, so ranges cannot be compared",
        ),
        (
            ComponentState::Failed,
            "the lookup failed; run the scan again",
        ),
    ] {
        let hits: Vec<_> = analysis
            .components
            .iter()
            .filter(|c| c.state == state)
            .collect();
        if hits.is_empty() {
            continue;
        }
        writeln!(writer, "  {} ({}): {why}", state.label(), hits.len())?;
        for c in hits {
            let detail = match state {
                ComponentState::UnknownVersion | ComponentState::Failed => c
                    .note
                    .as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default(),
                _ => String::new(),
            };
            writeln!(writer, "    {}{detail}", display_name(c))?;
        }
    }
    writeln!(writer)?;
    Ok(())
}

fn write_summary<W: Write>(analysis: &Analysis, writer: &mut W) -> Result<()> {
    let s = &analysis.summary;
    let n = &s.components;
    writeln!(
        writer,
        "Summary: {} Critical, {} High, {} Medium, {} Low; {} components: {} vulnerable, {} clean, {} not checked",
        s.critical,
        s.high,
        s.medium,
        s.low,
        analysis.components.len(),
        n.vulnerable + n.alias_match,
        n.clean,
        s.not_checked
    )?;
    Ok(())
}

/// Add a row for a vulnerability
fn add_vulnerability_row(
    table: &mut Table,
    component: &ComponentVulnerabilities,
    vuln: &crate::vulnerability::Vulnerability,
) {
    let component_name = display_name(component);

    let version = component.version.as_deref().unwrap_or("-");

    let title = truncate_title(&vuln.title);

    let vuln_desc = format!("{}: {}", vuln.id, title);

    let fixed = match (vuln.fixed_in.as_deref(), vuln.affected_max.as_deref()) {
        (Some(f), _) => format!(">={}", f), // "< X": X is the first fixed version
        (None, Some(m)) => format!(">{}", m), // "<= X": fixed after X
        _ => "-".to_string(),
    };

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
    // count characters, not bytes, so Persian/CJK titles don't panic
    if title.chars().count() > MAX_TITLE_LENGTH {
        let cut: String = title.chars().take(MAX_TITLE_LENGTH - 3).collect();
        format!("{}...", cut)
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
