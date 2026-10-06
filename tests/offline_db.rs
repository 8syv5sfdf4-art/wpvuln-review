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
