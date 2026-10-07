//! Report formats against golden files. Run with UPDATE_GOLDEN=1 to
//! rewrite them after an intended change, then review the diff.

use std::path::{Path, PathBuf};

use wordpress_vulnerable_scanner::scanner::{ComponentInfo, ComponentType, ScanResult};
use wordpress_vulnerable_scanner::{
    Analysis, Analyzer, OutputConfig, OutputFormat, Severity, Source, output_analysis,
};

fn record(entries: &str) -> String {
    format!(r#"{{"error":0,"message":null,"data":{{"name":"x","vulnerability":[{entries}]}}}}"#)
}

const CRITICAL: &str = r#"{"uuid":"u-crit","name":"Akismet &lt;= 5.3 &#8211; Unauthenticated RCE | \"quoted\", with comma",
  "operator":{"min_version":"5.0","min_operator":"ge","max_version":"5.3.1","max_operator":"lt","unfixed":"0"},
  "source":[{"id":"CVE-2026-0001","name":"CVE","link":"https://www.cve.org/CVERecord?id=CVE-2026-0001","description":"[en] Remote code execution."},
            {"id":"wf-1","name":"Wordfence","link":"https://example.org/wf-1","description":""}],
  "impact":{"cvss":{"version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":"9.8"},
            "cwe":[{"cwe":"CWE-94","name":"Code Injection","description":"x"}],
            "ssvc":{"kev":true}}}"#;

const UNFIXED_LOW: &str = r#"{"uuid":"u-low","name":"Akismet info leak",
  "operator":{"max_version":"9.9","max_operator":"le","unfixed":"1"},
  "source":[],"impact":{"cvss":{"score":"3.1"}}}"#;

const HIGH: &str = r#"{"uuid":"u-high","name":"Chaty Pro &lt; 3.5.6 - SQL Injection",
  "operator":{"max_version":"3.5.6","max_operator":"lt"},
  "source":[{"id":"CVE-2026-6251","link":"https://www.cve.org/CVERecord?id=CVE-2026-6251","description":"SQLi via widget id."}],
  "impact":{"cvss":{"score":"7.5","vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},"cwe":[{"cwe":"CWE-89"}]}}"#;

/// A scan touching every state, with a fixed date so output is stable
async fn analysis() -> Analysis {
    // Tests run in parallel: each needs its own database directory
    static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let run = RUN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let db = std::env::temp_dir().join(format!("wvs-reports-{}-{run}", std::process::id()));
    let _ = std::fs::remove_dir_all(&db);
    for sub in ["plugin", "core", "theme"] {
        std::fs::create_dir_all(db.join(sub)).unwrap();
    }
    let put = |p: &str, body: &str| std::fs::write(db.join(p), body).unwrap();
    put("core/6.6.2.json", &record(""));
    put(
        "plugin/akismet.json",
        &record(&format!("{CRITICAL},{UNFIXED_LOW}")),
    );
    put("plugin/chaty-pro.json", &record(HIGH));
    put("plugin/hello-dolly.json", &record(""));
    put(
        "plugin/zhaket-woo-sep.json",
        r#"{"error":0,"message":null,"data":null}"#,
    );
    put("plugin/custom-thing.json", &record(HIGH));
    put("plugin/broken.json", "<html>blocked</html>");
    put("theme/storefront.json", &record(""));

    let c = |t, slug: &str, version: Option<&str>, installed: Option<&str>| ComponentInfo {
        component_type: t,
        slug: slug.to_string(),
        version: version.map(str::to_string),
        installed_as: installed.map(str::to_string),
    };
    use ComponentType::*;
    let scan = ScanResult::from_components(vec![
        c(Core, "wordpress", Some("6.6.2"), None),
        c(Plugin, "akismet", Some("5.3"), None),
        c(Plugin, "chaty-pro", Some("3.3.6"), Some("chaty-pro2")),
        c(Plugin, "hello-dolly", Some("1.7.2"), None),
        // a renamed copy whose original the database tracks
        c(Plugin, "hello-dolly2", Some("1.6.0"), None),
        c(Plugin, "zhaket-woo-sep", Some("1.2.1"), None),
        c(Plugin, "never-pulled", Some("1.0"), None),
        c(Plugin, "custom-thing", None, None),
        c(Plugin, "broken", Some("1.0"), None),
        c(Theme, "storefront", Some("4.5.0"), None),
    ]);
    let mut a = Analyzer::with_source(Source::Local(db))
        .unwrap()
        .analyze(&scan)
        .await;
    a.scan_date = "2026-10-07T00:00:00Z".to_string();
    a.warnings = vec![
        "aliases [plugin] \"gone-plugin\": no installed plugin has this slug, so the alias \
         does nothing. Remove it if the plugin was uninstalled."
            .to_string(),
    ];
    a
}

fn render(a: &Analysis, format: OutputFormat) -> String {
    let mut out = Vec::new();
    let config = OutputConfig::new(format, Severity::Low).with_color(false);
    output_analysis(a, &config, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn golden(name: &str, actual: &str) {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{name} missing; run with UPDATE_GOLDEN=1"));
    assert_eq!(
        actual, expected,
        "{name} changed; rerun with UPDATE_GOLDEN=1 if intended"
    );
}

/// Minimal RFC 4180 reader, to prove the CSV parses back
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let (mut row, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            ('"', _) => quoted = !quoted,
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\n', false) => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (c, _) => field.push(c),
        }
    }
    rows
}

#[tokio::test]
async fn json_report() {
    let a = analysis().await;
    golden("report.json", &render(&a, OutputFormat::Json));
}

#[tokio::test]
async fn markdown_report() {
    let a = analysis().await;
    let md = render(&a, OutputFormat::Markdown);
    assert!(md.contains("**5 components were not checked**"));
    assert!(md.contains("```toml\n[plugin]\n\"hello-dolly2\" = \"hello-dolly\""));
    assert!(md.contains("## Warnings (1)"));
    assert!(md.contains("RCE \\| \"quoted\""), "pipes escaped in tables");
    golden("report.md", &md);
}

#[tokio::test]
async fn csv_report_accounts_for_every_component() {
    let a = analysis().await;
    let csv = render(&a, OutputFormat::Csv);
    let rows = parse_csv(&csv);
    assert!(rows.iter().all(|r| r.len() == rows[0].len()), "{rows:#?}");
    let components: std::collections::BTreeSet<&str> =
        rows[1..].iter().map(|r| r[1].as_str()).collect();
    assert_eq!(components.len(), a.components.len());
    let crit = rows.iter().find(|r| r[6] == "CVE-2026-0001").unwrap();
    assert_eq!(
        crit[8],
        "Akismet <= 5.3 \u{2013} Unauthenticated RCE | \"quoted\", with comma"
    );
    assert_eq!(crit[13], "true");
    golden("report.csv", &csv);
}

/// Finding keys DefectDojo's Generic Findings Import accepts (from its
/// documentation); any other key makes it reject the whole file
const DOJO_FINDING_KEYS: &[&str] = &[
    "title",
    "severity",
    "description",
    "date",
    "cwe",
    "cwes",
    "cve",
    "vulnerability_ids",
    "epss_score",
    "epss_percentile",
    "cvssv3",
    "cvssv3_score",
    "cvssv4",
    "cvssv4_score",
    "mitigation",
    "impact",
    "steps_to_reproduce",
    "severity_justification",
    "references",
    "active",
    "verified",
    "false_p",
    "out_of_scope",
    "risk_accepted",
    "under_review",
    "is_mitigated",
    "mitigated",
    "thread_id",
    "param",
    "payload",
    "line",
    "file_path",
    "component_name",
    "component_version",
    "static_finding",
    "dynamic_finding",
    "scanner_confidence",
    "unique_id_from_tool",
    "vuln_id_from_tool",
    "sast_source_object",
    "sast_sink_object",
    "sast_source_line",
    "sast_source_file_path",
    "nb_occurences",
    "publish_date",
    "service",
    "planned_remediation_date",
    "planned_remediation_version",
    "effort_for_fixing",
    "kev_date",
    "known_exploited",
    "ransomware_used",
    "fix_available",
    "fix_version",
    "tags",
    "endpoints",
    "files",
    "numerical_severity",
];
const DOJO_REPORT_KEYS: &[&str] = &[
    "findings",
    "type",
    "name",
    "version",
    "description",
    "static_tool",
    "dynamic_tool",
];
const DOJO_BOOL_KEYS: &[&str] = &[
    "active",
    "verified",
    "false_p",
    "out_of_scope",
    "risk_accepted",
    "under_review",
    "is_mitigated",
    "static_finding",
    "dynamic_finding",
    "known_exploited",
    "ransomware_used",
    "fix_available",
];

#[tokio::test]
async fn defectdojo_report_uses_only_accepted_fields() {
    let a = analysis().await;
    let text = render(&a, OutputFormat::DefectDojo);
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    for key in json.as_object().unwrap().keys() {
        assert!(DOJO_REPORT_KEYS.contains(&key.as_str()), "report key {key}");
    }
    let findings = json["findings"].as_array().unwrap();
    for f in findings {
        for (key, value) in f.as_object().unwrap() {
            assert!(
                DOJO_FINDING_KEYS.contains(&key.as_str()),
                "finding key {key}"
            );
            if DOJO_BOOL_KEYS.contains(&key.as_str()) {
                assert!(value.is_boolean(), "{key} must be a JSON boolean");
            }
        }
        for required in ["title", "severity", "description"] {
            assert!(f.get(required).is_some(), "{required} missing: {f}");
        }
        let sev = f["severity"].as_str().unwrap();
        assert!(["Critical", "High", "Medium", "Low", "Info"].contains(&sev));
        assert!(f["title"].as_str().unwrap().chars().count() <= 511);
        if let Some(cwe) = f.get("cwe") {
            assert!(cwe.is_u64(), "cwe is a number");
        }
    }

    // 3 findings, plus one Info finding per component not checked
    let not_checked = findings
        .iter()
        .filter(|f| {
            f["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "not-checked")
        })
        .count();
    assert_eq!((findings.len(), not_checked), (3 + 5, 5));
    let renamed = findings
        .iter()
        .find(|f| f["component_name"] == "hello-dolly2")
        .unwrap();
    assert!(
        renamed["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "naming-problem")
    );
    assert!(
        json["description"]
            .as_str()
            .unwrap()
            .contains("1 warning(s)")
    );
    let crit = findings
        .iter()
        .find(|f| f["cve"] == "CVE-2026-0001")
        .unwrap();
    assert_eq!(crit["cve"], "CVE-2026-0001");
    assert_eq!(crit["known_exploited"], true);
    assert_eq!(crit["cwe"], 94);
    assert_eq!(crit["fix_version"], "5.3.1");
    golden("defectdojo.json", &text);
}
