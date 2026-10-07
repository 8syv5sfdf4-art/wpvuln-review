//! Local database: `db::pull` against a mock API, then offline analysis.

use std::path::PathBuf;
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wordpress_vulnerable_scanner::db::{self, PullOptions, PullStatus};
use wordpress_vulnerable_scanner::scanner::{ComponentInfo, ComponentType, ScanResult};
use wordpress_vulnerable_scanner::{Analyzer, Source};

fn temp_db(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wvs-test-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn record(entries: &str) -> String {
    format!(r#"{{"error":0,"message":null,"data":{{"name":"x","vulnerability":[{entries}]}}}}"#)
}

const ELEMENTOR: &str = r#"
 {"uuid":"u1","name":"Elementor Pro < 4.2.2 - XSS",
  "operator":{"min_version":null,"min_operator":null,"max_version":"4.2.2","max_operator":"lt"},
  "source":[{"id":"CVE-2026-32475","name":"CVE","link":"https://example.org/1","description":"d"}],
  "impact":{"cvss":{"score":"9.1"}}}"#;

const PERSIAN: &str = r#"
 {"uuid":"u3","name":"افزونه پیامک ووکامرس | Persian WooCommerce SMS <= 7.1.1",
  "operator":{"max_version":"7.1.1","max_operator":"le"},
  "source":[{"id":"CVE-2026-1111"}],"impact":{"cvss":{"score":"7.5"}}}"#;

fn opts(server: &MockServer) -> PullOptions {
    PullOptions {
        api_url: server.uri(),
        jobs: 2,
        attempts: 2,
        delay: Duration::ZERO,
        max_age: None,
        untracked_max_age: None,
    }
}

async fn mount(server: &MockServer, p: &str, status: u16, body: &str) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn pull_continues_past_empty_missing_and_failing_components() {
    let server = MockServer::start().await;
    mount(&server, "/plugin/elementor-pro/", 200, &record(ELEMENTOR)).await;
    // zero records in the middle of the list: must not stop the pull
    mount(&server, "/plugin/buy-with-digikala/", 200, &record("")).await;
    mount(
        &server,
        "/plugin/persian-woocommerce-sms/",
        200,
        &record(PERSIAN),
    )
    .await;
    mount(&server, "/plugin/premium-only/", 404, "").await;
    mount(&server, "/plugin/flaky/", 503, "down").await;

    let dir = temp_db("pull");
    let items: Vec<_> = [
        "elementor-pro",
        "buy-with-digikala",
        "persian-woocommerce-sms",
        "premium-only",
        "flaky",
        "../escape",
        "elementor-pro", // duplicate
    ]
    .iter()
    .map(|s| (ComponentType::Plugin, s.to_string()))
    .collect();

    let mut events = Vec::new();
    let summary = db::pull(&dir, &items, &opts(&server), |e| {
        events.push((e.key.clone(), e.status.clone()))
    })
    .await
    .unwrap();

    assert_eq!(events.len(), 6, "every unique component reported");
    assert_eq!(summary.saved, 3);
    assert_eq!(summary.records, 2);
    assert_eq!(summary.no_data, 1);
    assert_eq!(summary.invalid, 1);
    assert_eq!(summary.failed, 1);
    assert!(events.contains(&("buy-with-digikala".into(), PullStatus::Saved(0))));
    assert!(dir.join("plugin/buy-with-digikala.json").is_file());
    assert!(
        dir.join("plugin/premium-only.json").is_file(),
        "404 stored as checked-empty"
    );
    assert!(!dir.join("plugin/flaky.json").exists());
    assert!(dir.join("wpvuln-db.json").is_file());

    let st = db::status(&dir).unwrap();
    assert_eq!(st.plugins, 4);
    assert_eq!(st.untracked, 1, "the 404 is stored as untracked, not clean");
    assert_eq!(st.records, 2);
    assert_eq!(st.meta.unwrap().source, server.uri());
}

#[tokio::test]
async fn retries_transient_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/plugin/akismet/"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    mount(&server, "/plugin/akismet/", 200, &record(ELEMENTOR)).await;

    let dir = temp_db("retry");
    let items = vec![(ComponentType::Plugin, "akismet".to_string())];
    let summary = db::pull(&dir, &items, &opts(&server), |_| {})
        .await
        .unwrap();
    assert_eq!(summary.saved, 1);
    assert_eq!(summary.failed, 0);
}

#[tokio::test]
async fn offline_analysis_reads_local_records() {
    let server = MockServer::start().await;
    mount(&server, "/plugin/elementor-pro/", 200, &record(ELEMENTOR)).await;
    mount(
        &server,
        "/plugin/persian-woocommerce-sms/",
        200,
        &record(PERSIAN),
    )
    .await;

    let dir = temp_db("offline");
    let items = vec![
        (ComponentType::Plugin, "elementor-pro".to_string()),
        (ComponentType::Plugin, "persian-woocommerce-sms".to_string()),
    ];
    db::pull(&dir, &items, &opts(&server), |_| {})
        .await
        .unwrap();
    drop(server); // no network from here on

    let plugin = |slug: &str, v: &str| ComponentInfo {
        component_type: ComponentType::Plugin,
        slug: slug.into(),
        version: Some(v.into()),
        installed_as: None,
    };
    let scan = ScanResult::from_components(vec![
        plugin("elementor-pro", "4.2.2"), // the fixed version: clean
        plugin("persian-woocommerce-sms", "7.0.3"), // affected
        plugin("never-pulled", "1.0"),    // absent: no data
    ]);
    let analysis = Analyzer::with_source(Source::Local(dir.clone()))
        .unwrap()
        .analyze(&scan)
        .await;

    let by_slug = |s: &str| analysis.components.iter().find(|c| c.slug == s).unwrap();
    assert!(by_slug("elementor-pro").vulnerabilities.is_empty());
    assert_eq!(by_slug("persian-woocommerce-sms").vulnerabilities.len(), 1);
    assert!(by_slug("never-pulled").vulnerabilities.is_empty());
    assert_eq!(analysis.summary.total, 1);

    let missing = db::missing(
        &dir,
        scan.components
            .iter()
            .map(|c| (c.component_type, c.slug.as_str())),
    );
    assert_eq!(missing, vec!["never-pulled"]);
}

#[tokio::test]
async fn untracked_is_not_the_same_as_clean() {
    let server = MockServer::start().await;
    // what WPVulnerability returns for slugs it doesn't know
    mount(
        &server,
        "/plugin/woodmart-core/",
        200,
        r#"{"error":0,"message":null,"data":null}"#,
    )
    .await;
    mount(
        &server,
        "/plugin/zhaket-woo-sep/",
        200,
        r#"{"error":0,"message":null,"data":{"name":null,"plugin":null,"vulnerability":null}}"#,
    )
    .await;
    // a known plugin with no vulnerabilities
    mount(
        &server,
        "/plugin/wp-crontrol/",
        200,
        r#"{"error":0,"message":null,"data":{"name":"WP Crontrol","vulnerability":null}}"#,
    )
    .await;

    let dir = temp_db("untracked");
    let slugs = ["woodmart-core", "zhaket-woo-sep", "wp-crontrol"];
    let items: Vec<_> = slugs
        .iter()
        .map(|s| (ComponentType::Plugin, s.to_string()))
        .collect();
    let mut events = Vec::new();
    let summary = db::pull(&dir, &items, &opts(&server), |e| {
        events.push((e.key.clone(), e.status.clone()))
    })
    .await
    .unwrap();

    assert_eq!(summary.no_data, 2);
    assert_eq!(summary.saved, 1);
    assert!(events.contains(&("woodmart-core".into(), PullStatus::NoData)));
    assert!(events.contains(&("zhaket-woo-sep".into(), PullStatus::NoData)));
    assert!(events.contains(&("wp-crontrol".into(), PullStatus::Saved(0))));

    let keys = slugs.iter().map(|s| (ComponentType::Plugin, *s));
    assert_eq!(
        db::untracked(&dir, keys),
        vec!["woodmart-core", "zhaket-woo-sep"]
    );
    let st = db::status(&dir).unwrap();
    assert_eq!((st.plugins, st.untracked, st.records), (3, 2, 0));

    // a re-pull within max_age keeps them untracked without re-downloading
    drop(server);
    let fresh = PullOptions {
        api_url: "http://127.0.0.1:9".into(),
        max_age: Some(Duration::from_secs(3600)),
        ..opts_offline()
    };
    let again = db::pull(&dir, &items, &fresh, |_| {}).await.unwrap();
    assert_eq!((again.no_data, again.fresh, again.failed), (2, 1, 0));
}

fn opts_offline() -> PullOptions {
    PullOptions {
        api_url: String::new(),
        jobs: 2,
        attempts: 1,
        delay: Duration::ZERO,
        max_age: None,
        untracked_max_age: None,
    }
}

#[tokio::test]
async fn pull_identifies_itself() {
    use wiremock::matchers::header_regex;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/plugin/akismet/"))
        .and(header_regex(
            "user-agent",
            r"^wordpress-vulnerable-scanner/\d+\.\d+\.\d+ \(\+https://",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(record("")))
        .expect(1)
        .mount(&server)
        .await;
    let dir = temp_db("ua");
    let items = vec![(ComponentType::Plugin, "akismet".to_string())];
    let summary = db::pull(&dir, &items, &opts(&server), |_| {})
        .await
        .unwrap();
    assert_eq!(summary.saved, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn pull_from_an_inventory_uses_aliases() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(record("")))
        .mount(&server)
        .await;
    let dir = temp_db("inventory");
    let aliases = dir.with_extension("toml");
    std::fs::write(
        &aliases,
        "[plugin]\n\"chaty-pro2\" = \"chaty\"\n\"hello\" = { theme = \"storefront\" }\n",
    )
    .unwrap();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let (db_dir, uri) = (dir.clone(), server.uri());
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
            .args(["db", "pull", "-j", "1", "--db"])
            .arg(&db_dir)
            .arg("--api-url")
            .arg(&uri)
            .arg("--inventory")
            .arg(&fixture)
            .arg("--aliases")
            .arg(&aliases)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut paths: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    paths.sort();
    let has = |p: &str| paths.iter().any(|x| x == p);
    assert!(has("/core/6.6.2/"));
    assert!(has("/plugin/chaty/"), "alias used: {paths:?}");
    assert!(!has("/plugin/chaty-pro2/"));
    assert!(!has("/plugin/hello/"), "covered by the theme");
    assert!(has("/theme/storefront/"));
    assert!(
        has("/plugin/akismet-old/"),
        "unloaded copies are pulled too"
    );
    assert!(
        has("/plugin/edge-after/"),
        "no version, but the record is still worth having"
    );
    assert!(
        !has("/plugin/loader/") && !has("/plugin/object-cache/"),
        "mu-plugins and drop-ins are never looked up"
    );
    // Every key exactly once
    let mut unique = paths.clone();
    unique.dedup();
    assert_eq!(unique, paths);
}

/// A record with one vulnerability affecting versions below `fixed`
fn affected_below(fixed: &str) -> String {
    record(&format!(
        r#"{{"uuid":"u-{fixed}","name":"XSS < {fixed}","operator":{{"max_version":"{fixed}","max_operator":"lt"}},"source":[{{"id":"CVE-2026-0001"}}],"impact":{{"cvss":{{"score":"7.5"}}}}}}"#
    ))
}

#[test]
fn every_component_ends_in_exactly_one_state() {
    let dir = temp_db("states");
    for sub in ["plugin", "core", "theme"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    let put = |p: &str, body: &str| std::fs::write(dir.join(p), body).unwrap();
    put("plugin/akismet.json", &affected_below("9.0")); // 5.3 -> vulnerable
    put("plugin/chaty.json", &affected_below("4.0")); // via alias -> alias_match
    put("plugin/hello.json", &record("")); // tracked, no vulns -> clean
    put(
        "plugin/bom-plugin.json",
        r#"{"error":0,"message":null,"data":null}"#,
    ); // untracked
    put("plugin/edge-after.json", &affected_below("9.0")); // no version
    put("plugin/latin1.json", "<html>blocked</html>"); // damaged -> failed
    put("core/6.6.2.json", &record("")); // clean
    let aliases = dir.join("aliases.toml");
    std::fs::write(&aliases, "[plugin]\n\"chaty-pro2\" = \"chaty\"\n").unwrap();

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["-o", "json", "--db"])
        .arg(&dir)
        .arg("--inventory")
        .arg(&fixture)
        .arg("--aliases")
        .arg(&aliases)
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let state = |name: &str| {
        json["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                c["installed_as"]
                    .as_str()
                    .unwrap_or(c["slug"].as_str().unwrap())
                    == name
            })
            .unwrap_or_else(|| panic!("{name} missing"))["state"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(state("akismet"), "vulnerable");
    assert_eq!(state("chaty-pro2"), "alias_match");
    assert_eq!(state("hello"), "clean");
    assert_eq!(state("wordpress"), "clean");
    assert_eq!(state("bom-plugin"), "untracked");
    assert_eq!(state("RTL-CareUnit"), "not_in_db");
    assert_eq!(state("edge-after"), "unknown_version");
    assert_eq!(state("latin1"), "failed");

    let summary = &json["summary"];
    assert_eq!(summary["components"]["alias_match"], 1);
    let total = json["components"].as_array().unwrap().len() as u64;
    let checked = ["vulnerable", "alias_match", "clean"]
        .iter()
        .map(|k| summary["components"][k].as_u64().unwrap())
        .sum::<u64>();
    assert_eq!(checked + summary["not_checked"].as_u64().unwrap(), total);
    // Existing fields are still there
    assert!(summary["total"].as_u64().unwrap() >= 2 && summary.get("high").is_some());

    // The human report says what was not checked, and why
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["--db"])
        .arg(&dir)
        .arg("--inventory")
        .arg(&fixture)
        .arg("--aliases")
        .arg(&aliases)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains('\u{1b}'),
        "no ANSI codes when piped: {text:?}"
    );
    assert!(text.contains("NOT CHECKED ("), "{text}");
    assert!(text.contains("chaty-pro2 (as chaty)"));
    assert!(
        text.contains("not checked\n"),
        "summary counts unchecked: {text}"
    );
}

#[tokio::test]
async fn live_api_mode_never_reports_unknowns_as_clean() {
    let server = MockServer::start().await;
    mount(&server, "/plugin/akismet/", 200, &record("")).await;
    mount(&server, "/plugin/premium/", 404, "").await;
    mount(&server, "/plugin/broken/", 500, "").await;
    let scan = ScanResult::from_components(
        ["akismet", "premium", "broken"]
            .iter()
            .map(|s| ComponentInfo {
                component_type: ComponentType::Plugin,
                slug: s.to_string(),
                version: Some("1.0".into()),
                installed_as: None,
            })
            .collect(),
    );
    let analysis = Analyzer::with_source(Source::Api(server.uri()))
        .unwrap()
        .analyze(&scan)
        .await;
    use wordpress_vulnerable_scanner::analyze::ComponentState::*;
    let states: Vec<_> = analysis.components.iter().map(|c| c.state).collect();
    assert_eq!(states, vec![Clean, Untracked, Failed]);
    assert_eq!(analysis.summary.not_checked, 2);
}

/// Run the CLI against `db`; returns (exit code, stdout)
fn cli(db: &std::path::Path, args: &[&str]) -> (i32, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(args)
        .arg("--db")
        .arg(db)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn scan_subcommand_and_exit_code_controls() {
    let dir = temp_db("fail-on");
    std::fs::create_dir_all(dir.join("plugin")).unwrap();
    // akismet 5.3: one High (7.5) finding; premium: untracked
    std::fs::write(dir.join("plugin/akismet.json"), affected_below("9.0")).unwrap();
    std::fs::write(
        dir.join("plugin/premium.json"),
        r#"{"error":0,"message":null,"data":null}"#,
    )
    .unwrap();

    let without_date = |json: &str| {
        let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
        v.as_object_mut().unwrap().remove("scan_date");
        v
    };
    let (top, top_out) = cli(&dir, &["-o", "json", "-p", "akismet:5.3"]);
    let (sub, sub_out) = cli(&dir, &["scan", "-o", "json", "-p", "akismet:5.3"]);
    assert_eq!((top, sub), (1, 1));
    assert_eq!(without_date(&top_out), without_date(&sub_out));

    let code = |args: &[&str]| cli(&dir, &[&["scan", "-o", "none"], args].concat()).0;
    assert_eq!(code(&["-p", "akismet:5.3", "--fail-on", "high"]), 1);
    assert_eq!(code(&["-p", "akismet:5.3", "--fail-on", "critical"]), 0);
    assert_eq!(code(&["-p", "akismet:5.3", "--fail-on", "none"]), 0);
    assert_eq!(
        code(&["-p", "premium:1.0"]),
        0,
        "unchecked alone does not fail"
    );
    assert_eq!(code(&["-p", "premium:1.0", "--fail-on-unchecked"]), 1);
    assert_eq!(
        code(&["-p", "akismet", "--fail-on-unchecked"]),
        1,
        "no version"
    );
}
