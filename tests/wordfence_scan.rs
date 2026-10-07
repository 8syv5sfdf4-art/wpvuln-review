//! Scanning with Wordfence alone and combined with WPVulnerability.

use std::path::{Path, PathBuf};

use wordpress_vulnerable_scanner::analyze::{ComponentState, Coverage};
use wordpress_vulnerable_scanner::scanner::{ComponentInfo, ComponentType, ScanResult};
use wordpress_vulnerable_scanner::vulnerability::SourceKind;
use wordpress_vulnerable_scanner::wordfence::{Keep, WordfenceIndex};
use wordpress_vulnerable_scanner::{Analysis, Analyzer, ComponentVulnerabilities, Source};

fn feed() -> WordfenceIndex {
    WordfenceIndex::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wordfence/wpprobe-sample.json"),
        &Keep::All,
    )
    .unwrap()
}

fn record(entries: &str) -> String {
    format!(r#"{{"error":0,"message":null,"data":{{"name":"x","vulnerability":[{entries}]}}}}"#)
}

/// A WPVulnerability database matching the real-site comparison: WooCommerce
/// with one wide range for CVE-2025-15033, Loco Translate (Wordfence has no
/// record), WP Rocket with a finding without CVE, and no chaty-pro
fn wpvuln_db(name: &str) -> PathBuf {
    let db = std::env::temp_dir().join(format!("wvs-wfscan-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&db);
    std::fs::create_dir_all(db.join("plugin")).unwrap();
    let put = |p: &str, body: &str| std::fs::write(db.join(p), body).unwrap();
    put(
        "plugin/woocommerce.json",
        &record(
            r#"{"uuid":"wv-woo","name":"WooCommerce <= 10.4.2 - Information Exposure",
                "operator":{"max_version":"10.4.2","max_operator":"le"},
                "source":[{"id":"CVE-2025-15033","link":"https://www.cve.org/CVERecord?id=CVE-2025-15033"}],
                "impact":{"cvss":{"score":"4.3"}}}"#,
        ),
    );
    put(
        "plugin/loco-translate.json",
        &record(
            r#"{"uuid":"wv-loco","name":"Loco Translate < 2.8.9",
                "operator":{"max_version":"2.8.9","max_operator":"lt"},
                "source":[{"id":"CVE-2026-94238"}],"impact":{"cvss":{"score":"6.5"}}}"#,
        ),
    );
    put(
        "plugin/wp-rocket.json",
        &record(
            r#"{"uuid":"908926c3","name":"WP Rocket < 3.23.3.3",
                "operator":{"min_version":"3.23.1","min_operator":"ge","max_version":"3.23.3.3","max_operator":"lt"},
                "source":[{"id":"wf-only-id","link":"https://example.org/rocket"}],"impact":{"cvss":{"score":"5.3"}}}"#,
        ),
    );
    put(
        "plugin/chaty-pro.json",
        r#"{"error":0,"message":null,"data":null}"#,
    );
    db
}

fn plugin(slug: &str, version: &str) -> ComponentInfo {
    ComponentInfo {
        component_type: ComponentType::Plugin,
        slug: slug.to_string(),
        version: Some(version.to_string()),
        installed_as: None,
    }
}

async fn scan(analyzer: Analyzer, components: Vec<ComponentInfo>) -> Analysis {
    analyzer
        .analyze(&ScanResult::from_components(components))
        .await
}

fn get<'a>(a: &'a Analysis, slug: &str, version: &str) -> &'a ComponentVulnerabilities {
    a.components
        .iter()
        .find(|c| c.slug == slug && c.version.as_deref() == Some(version))
        .unwrap_or_else(|| panic!("{slug} {version} missing"))
}

#[tokio::test]
async fn wordfence_alone() {
    let a = scan(
        Analyzer::wordfence_only(feed(), "fixture".into()),
        vec![
            plugin("chaty-pro", "3.3.6"),
            plugin("woocommerce", "10.3.7"),
            plugin("woocommerce", "10.3.6"),
            plugin("akismet", "5.3"),
        ],
    )
    .await;
    assert_eq!(
        get(&a, "chaty-pro", "3.3.6").state,
        ComponentState::Vulnerable
    );
    assert_eq!(
        get(&a, "woocommerce", "10.3.7").state,
        ComponentState::Clean
    );
    let woo = get(&a, "woocommerce", "10.3.6");
    assert_eq!(woo.vulnerabilities[0].affected, ">= 10.3.0, <= 10.3.6");
    let akismet = get(&a, "akismet", "5.3");
    assert_eq!(akismet.state, ComponentState::Untracked);
    assert!(
        akismet
            .note
            .as_deref()
            .unwrap()
            .contains("not proof of safety")
    );
    assert!(
        akismet.coverage.is_empty(),
        "coverage only with several sources"
    );
    assert_eq!(a.sources.len(), 1);
    assert!(
        a.sources[0]
            .attribution
            .as_deref()
            .unwrap()
            .contains("Defiant")
    );
}

#[tokio::test]
async fn combined_sources_fill_each_others_gaps() {
    let db = wpvuln_db("combined");
    let analyzer = Analyzer::with_source(Source::Local(db))
        .unwrap()
        .with_wordfence(feed(), "fixture".into());
    let a = scan(
        analyzer,
        vec![
            plugin("loco-translate", "2.8.8"),
            plugin("wp-rocket", "3.23.2.2"),
            plugin("chaty-pro", "3.3.6"),
            plugin("woocommerce", "10.3.6"),
            plugin("never-heard-of", "1.0"),
        ],
    )
    .await;
    use SourceKind::*;

    // WPVulnerability only (Wordfence has no record): affected
    let loco = get(&a, "loco-translate", "2.8.8");
    assert_eq!(loco.state, ComponentState::Vulnerable);
    assert_eq!(loco.vulnerabilities[0].sources, vec![WpVulnerability]);
    assert_eq!(loco.coverage[&Wordfence], Coverage::Untracked);
    assert!(
        loco.note
            .as_deref()
            .unwrap()
            .starts_with("Wordfence: Wordfence has no entry")
    );

    // No CVE (wpprobe drops those): still affected via WPVulnerability
    assert_eq!(
        get(&a, "wp-rocket", "3.23.2.2").state,
        ComponentState::Vulnerable
    );

    // Untracked by WPVulnerability, affected per Wordfence
    let chaty = get(&a, "chaty-pro", "3.3.6");
    assert_eq!(chaty.state, ComponentState::Vulnerable);
    assert_eq!(chaty.vulnerabilities[0].sources, vec![Wordfence]);
    assert_eq!(chaty.coverage[&WpVulnerability], Coverage::Untracked);

    // Both agree: one finding, both sources
    let woo = get(&a, "woocommerce", "10.3.6");
    assert_eq!(woo.vulnerabilities.len(), 1);
    assert_eq!(
        woo.vulnerabilities[0].sources,
        vec![WpVulnerability, Wordfence]
    );

    // Not checked only when no source has data
    let unknown = get(&a, "never-heard-of", "1.0");
    assert_eq!(unknown.state, ComponentState::NotInDb);
    assert_eq!(a.summary.not_checked, 1);
    assert_eq!(
        a.summary.not_checked_by[&WpVulnerability], 2,
        "never-heard-of, chaty-pro"
    );
    assert_eq!(
        a.summary.not_checked_by[&Wordfence], 3,
        "loco, wp-rocket (no CVE, so not in wpprobe), never-heard-of"
    );
}

#[tokio::test]
async fn naming_hints_also_come_from_wordfence() {
    let a = scan(
        Analyzer::wordfence_only(feed(), "fixture".into()),
        vec![plugin("chaty-pro2", "3.3.6")],
    )
    .await;
    let c = &a.components[0];
    assert_eq!(c.suggested_alias.as_deref(), Some("chaty-pro"));
    assert!(
        c.note
            .as_deref()
            .unwrap()
            .contains("Wordfence tracks \"chaty-pro\"")
    );
}

#[test]
fn cli_wordfence_alone_needs_no_network() {
    let dir = std::env::temp_dir().join(format!("wvs-wfscan-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let feed_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wordfence/wpprobe-sample.json");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args([
            "scan",
            "-o",
            "json",
            "-p",
            "chaty-pro:3.3.6,woocommerce:10.3.7",
        ])
        .arg("--wordfence")
        .arg(&feed_path)
        // an API that cannot answer: it must not be asked
        .env("WPVULN_API", "http://127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let states: Vec<&str> = json["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, vec!["vulnerable", "clean"]);
    assert!(
        json["sources"][0]["attribution"]
            .as_str()
            .unwrap()
            .contains("Defiant")
    );

    // `auto` needs a database
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["scan", "-p", "x:1", "--wordfence", "auto"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs --db"));
}
