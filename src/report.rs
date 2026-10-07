//! Report formats for people and other tools: CSV and Markdown
//!
//! Every format lists every component, including the ones that could not
//! be checked, with their state and the reason, so no report can be read as
//! "all clear" when parts were never checked.

use std::io::Write;

use crate::analyze::{Analysis, ComponentState, ComponentVulnerabilities};
use crate::error::Result;
use crate::scanner::ComponentType;
use crate::vulnerability::{Severity, Vulnerability};

fn kind_name(t: ComponentType) -> &'static str {
    match t {
        ComponentType::Core => "core",
        ComponentType::Plugin => "plugin",
        ComponentType::Theme => "theme",
    }
}

/// Installed name, as people know the component
fn installed_name(c: &ComponentVulnerabilities) -> &str {
    c.installed_as.as_deref().unwrap_or(&c.slug)
}

fn shown_findings(c: &ComponentVulnerabilities, min: Severity) -> Vec<&Vulnerability> {
    c.vulnerabilities
        .iter()
        .filter(|v| v.severity >= min)
        .collect()
}

fn fixed(v: &Vulnerability) -> String {
    match (v.unfixed, v.fixed_in.as_deref()) {
        (true, _) => "no fix yet".to_string(),
        (false, Some(f)) => f.to_string(),
        (false, None) => String::new(),
    }
}

/// One CSV field, quoted when it needs to be (RFC 4180)
fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

const CSV_HEADER: [&str; 17] = [
    "type",
    "component",
    "looked_up_as",
    "version",
    "state",
    "matched_via",
    "id",
    "cves",
    "title",
    "severity",
    "cvss",
    "affected",
    "fixed_in",
    "known_exploited",
    "cwes",
    "references",
    "note",
];

/// One row per finding, and one row for each component without findings
/// (clean or not checked), so the sheet accounts for every component
pub fn write_csv<W: Write>(analysis: &Analysis, min: Severity, w: &mut W) -> Result<()> {
    writeln!(w, "{}", CSV_HEADER.join(","))?;
    for c in &analysis.components {
        let base = [
            kind_name(c.component_type).to_string(),
            installed_name(c).to_string(),
            c.slug.clone(),
            c.version.clone().unwrap_or_default(),
            serde_name(c.state),
            serde_name(c.matched_via),
        ];
        let note = c.note.clone().unwrap_or_default();
        let findings = shown_findings(c, min);
        let rows: Vec<[String; 11]> = if findings.is_empty() {
            vec![[
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                note,
            ]]
        } else {
            findings
                .into_iter()
                .map(|v| {
                    [
                        v.id.clone(),
                        v.cves.join(" "),
                        v.title.clone(),
                        v.severity.to_string(),
                        v.cvss_score.map(|s| format!("{s:.1}")).unwrap_or_default(),
                        v.affected.clone(),
                        fixed(v),
                        v.known_exploited.map(|k| k.to_string()).unwrap_or_default(),
                        v.cwes.join(" "),
                        v.references.join(" "),
                        note.clone(),
                    ]
                })
                .collect()
        };
        for row in rows {
            let fields: Vec<String> = base
                .iter()
                .chain(row.iter())
                .map(|f| csv_field(f))
                .collect();
            writeln!(w, "{}", fields.join(","))?;
        }
    }
    Ok(())
}

/// The serde name of a unit enum value (`not_in_db`, `alias`, ...)
fn serde_name(value: impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Text safe inside a Markdown table cell
fn md_cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn md_name(c: &ComponentVulnerabilities) -> String {
    let name = match (c.component_type, c.installed_as.as_deref()) {
        (ComponentType::Core, _) => "WordPress".to_string(),
        (_, Some(installed)) => format!("{installed} (as {})", c.slug),
        (_, None) => c.slug.clone(),
    };
    match c.component_type {
        ComponentType::Theme => format!("theme {name}"),
        _ => name,
    }
}

/// A report for people: summary, findings by severity, alias findings to
/// confirm, everything not checked (by reason), and what was clean
pub fn write_markdown<W: Write>(analysis: &Analysis, min: Severity, w: &mut W) -> Result<()> {
    let s = &analysis.summary;
    let n = &s.components;
    writeln!(w, "# WordPress vulnerability report\n")?;
    if let Some(ref url) = analysis.url {
        writeln!(w, "Target: {url}  ")?;
    }
    writeln!(w, "Scanned: {}\n", analysis.scan_date)?;

    writeln!(w, "## Summary\n")?;
    writeln!(
        w,
        "**{} vulnerabilities** ({} critical, {} high, {} medium, {} low) in {} components. \
         **{} components were not checked** and are not known to be safe.\n",
        s.total,
        s.critical,
        s.high,
        s.medium,
        s.low,
        n.vulnerable + n.alias_match,
        s.not_checked
    )?;
    writeln!(w, "| State | Components |\n|---|---|")?;
    for (label, count) in [
        ("vulnerable", n.vulnerable),
        ("vulnerable through an alias (confirm)", n.alias_match),
        ("clean", n.clean),
        ("not checked: not tracked", n.untracked),
        ("not checked: not in the local database", n.not_in_db),
        ("not checked: version unknown", n.unknown_version),
        ("not checked: lookup failed", n.failed),
    ] {
        writeln!(w, "| {label} | {count} |")?;
    }
    writeln!(w)?;

    if s.total > 0 {
        writeln!(w, "## Findings\n")?;
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            if sev < min {
                continue;
            }
            let rows: Vec<(&ComponentVulnerabilities, &Vulnerability)> = analysis
                .components
                .iter()
                .flat_map(|c| c.vulnerabilities.iter().map(move |v| (c, v)))
                .filter(|(_, v)| v.severity == sev)
                .collect();
            if rows.is_empty() {
                continue;
            }
            writeln!(w, "### {sev} ({})\n", rows.len())?;
            writeln!(
                w,
                "| Component | Version | Vulnerability | CVSS | Affected | Fixed in |\n|---|---|---|---|---|---|"
            )?;
            for (c, v) in rows {
                let link = v
                    .references
                    .first()
                    .map(|r| format!("[{}]({r})", md_cell(&v.id)))
                    .unwrap_or_else(|| md_cell(&v.id));
                writeln!(
                    w,
                    "| {} | {} | {link}: {}{} | {} | {} | {} |",
                    md_cell(&md_name(c)),
                    md_cell(c.version.as_deref().unwrap_or("-")),
                    md_cell(&v.title),
                    if v.known_exploited == Some(true) {
                        " **(known exploited)**"
                    } else {
                        ""
                    },
                    v.cvss_score.map(|s| format!("{s:.1}")).unwrap_or_default(),
                    md_cell(&v.affected),
                    md_cell(&fixed(v)),
                )?;
            }
            writeln!(w)?;
        }
    }

    let alias: Vec<_> = analysis
        .components
        .iter()
        .filter(|c| c.state == ComponentState::AliasMatch)
        .collect();
    if !alias.is_empty() {
        writeln!(w, "## Found through an alias: confirm before acting\n")?;
        writeln!(
            w,
            "These were looked up under another slug. Premium editions may number their \
             versions differently from the free plugin.\n"
        )?;
        for c in alias {
            writeln!(
                w,
                "- {} {}",
                md_name(c),
                c.version.as_deref().unwrap_or("-")
            )?;
        }
        writeln!(w)?;
    }

    if s.not_checked > 0 {
        writeln!(w, "## Not checked\n")?;
        writeln!(
            w,
            "Nothing is known about these: they are neither safe nor vulnerable as far as this \
             scan can tell. Review them by hand.\n"
        )?;
        for (state, heading) in [
            (
                ComponentState::Untracked,
                "Not tracked by the data source (common for premium and custom code)",
            ),
            (
                ComponentState::NotInDb,
                "Never pulled into the local database (run `db pull` with the same inputs)",
            ),
            (
                ComponentState::UnknownVersion,
                "Version unknown, so ranges cannot be compared",
            ),
            (ComponentState::Failed, "Lookup failed (run the scan again)"),
        ] {
            let hits: Vec<_> = analysis
                .components
                .iter()
                .filter(|c| c.state == state)
                .collect();
            if hits.is_empty() {
                continue;
            }
            writeln!(w, "### {heading} ({})\n", hits.len())?;
            for c in hits {
                let detail = match state {
                    ComponentState::UnknownVersion | ComponentState::Failed => c
                        .note
                        .as_deref()
                        .map(|n| format!(": {n}"))
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                let name = format!("{} {}", md_name(c), c.version.as_deref().unwrap_or(""));
                writeln!(w, "- {}{detail}", name.trim_end())?;
            }
            writeln!(w)?;
        }
    }

    let clean: Vec<String> = analysis
        .components
        .iter()
        .filter(|c| c.state == ComponentState::Clean)
        .map(|c| format!("{} {}", md_name(c), c.version.as_deref().unwrap_or("")))
        .collect();
    if !clean.is_empty() {
        writeln!(w, "## Clean ({})\n", clean.len())?;
        writeln!(
            w,
            "Tracked, and no known vulnerability affects the installed version: {}\n",
            clean.join(", ")
        )?;
    }
    Ok(())
}

/// An f32 as the decimal number it was written as (9.8, not
/// 9.800000190734863 after widening to f64)
fn decimal(value: f32, places: usize) -> f64 {
    format!("{value:.places$}").parse().unwrap_or_default()
}

/// Title limit of DefectDojo's Generic Findings Import
const DOJO_TITLE_MAX: usize = 511;

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let cut: String = text.chars().take(max.saturating_sub(3)).collect();
        format!("{cut}...")
    }
}

/// DefectDojo's Generic Findings Import JSON (fields as documented for
/// DefectDojo 3; any other key would abort the import). Every finding
/// becomes one DefectDojo finding. Every component that could not be
/// checked becomes an Info finding tagged `not-checked`, so it stays
/// visible in the tracker instead of disappearing.
pub fn write_defectdojo<W: Write>(analysis: &Analysis, min: Severity, w: &mut W) -> Result<()> {
    use serde_json::{Map, Value, json};

    let mut findings = Vec::new();
    for c in &analysis.components {
        let name = installed_name(c);
        let version = c.version.as_deref().unwrap_or("unknown");
        let kind = kind_name(c.component_type);
        let mut tags = vec!["wordpress".to_string(), kind.to_string()];
        if c.state == ComponentState::AliasMatch {
            tags.push("alias-match".to_string());
        }

        for v in shown_findings(c, min) {
            let mut f = Map::new();
            let mut put = |k: &str, v: Value| {
                f.insert(k.to_string(), v);
            };
            put(
                "title",
                json!(truncate(
                    &format!("{name} {version}: {}", v.title),
                    DOJO_TITLE_MAX
                )),
            );
            put("severity", json!(v.severity.to_string()));
            let mut description = vec![
                format!("**Component:** {kind} `{name}` version {version}"),
                format!("**Affected versions:** {}", v.affected),
            ];
            if let Some(ref d) = v.description {
                description.push(d.clone());
            }
            if let Some(ref note) = c.note {
                description.push(format!("**Note:** {note}"));
            }
            put("description", json!(description.join("\n\n")));
            if let Some(cve) = v.cves.first() {
                put("cve", json!(cve));
            }
            if v.cves.len() > 1 {
                put("vulnerability_ids", json!(v.cves[1..]));
            }
            if let Some(ref vector) = v.cvss_vector
                && vector.starts_with("CVSS:3.")
            {
                put("cvssv3", json!(vector));
            }
            if let Some(score) = v.cvss_score {
                put("cvssv3_score", json!(decimal(score, 1)));
                put(
                    "severity_justification",
                    json!(format!("CVSS {score:.1} as published by the data source")),
                );
            } else {
                put(
                    "severity_justification",
                    json!("No CVSS score published; Medium assumed"),
                );
            }
            if let Some(cwe) = v
                .cwes
                .first()
                .and_then(|c| c.trim_start_matches("CWE-").parse::<u32>().ok())
            {
                put("cwe", json!(cwe));
            }
            put("component_name", json!(truncate(name, 500)));
            put("component_version", json!(truncate(version, 100)));
            if !v.references.is_empty() {
                put("references", json!(v.references.join("\n")));
            }
            let fix = (!v.unfixed).then_some(v.fixed_in.as_deref()).flatten();
            put("fix_available", json!(fix.is_some()));
            match fix {
                Some(fixed) => {
                    put("fix_version", json!(truncate(fixed, 100)));
                    put(
                        "mitigation",
                        json!(format!("Update {name} to {fixed} or later.")),
                    );
                }
                None => put(
                    "mitigation",
                    json!(format!(
                        "No fixed version is known. Disable or remove {name} if it is not \
                         needed, and watch for an update."
                    )),
                ),
            }
            if v.known_exploited == Some(true) {
                put("known_exploited", json!(true));
            }
            if let Some(epss) = v.epss {
                put("epss_score", json!(decimal(epss, 4)));
            }
            put(
                "unique_id_from_tool",
                json!(truncate(&format!("{kind}/{name}/{}", v.uuid), 500)),
            );
            put("vuln_id_from_tool", json!(truncate(&v.uuid, 500)));
            put("active", json!(true));
            put("verified", json!(false));
            put("tags", json!(tags));
            findings.push(Value::Object(f));
        }

        if !c.state.checked() {
            let reason = c
                .note
                .clone()
                .unwrap_or_else(|| c.state.label().to_string());
            let mut not_checked = tags.clone();
            not_checked.push("not-checked".to_string());
            findings.push(json!({
                "title": truncate(
                    &format!("Not checked: {name} {version} ({})", c.state.label()),
                    DOJO_TITLE_MAX
                ),
                "severity": "Info",
                "description": format!(
                    "**Component:** {kind} `{name}` version {version}\n\n\
                     This component could not be compared with vulnerability data: {reason}. \
                     It is not known to be safe; review it by hand."
                ),
                "component_name": truncate(name, 500),
                "component_version": truncate(version, 100),
                "unique_id_from_tool": truncate(&format!("not-checked/{kind}/{name}"), 500),
                "active": true,
                "verified": false,
                "tags": not_checked,
            }));
        }
    }

    let s = &analysis.summary;
    let report = json!({
        "type": "WordPress Vulnerable Scanner",
        "version": env!("CARGO_PKG_VERSION"),
        "description": format!(
            "Scan of {}: {} vulnerabilities ({} critical, {} high, {} medium, {} low); \
             {} of {} components could not be checked (Info findings tagged not-checked).",
            analysis.url.as_deref().unwrap_or("an inventory"),
            s.total, s.critical, s.high, s.medium, s.low,
            s.not_checked,
            analysis.components.len()
        ),
        "findings": findings,
    });
    serde_json::to_writer_pretty(&mut *w, &report)?;
    writeln!(w)?;
    Ok(())
}
