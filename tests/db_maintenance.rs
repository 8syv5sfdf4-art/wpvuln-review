//! Database provenance, updates, verification and transfer, against a mock API.

use std::path::{Path, PathBuf};
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wordpress_vulnerable_scanner::db::{self, EntryKind, PullOptions, PullStatus};
use wordpress_vulnerable_scanner::scanner::ComponentType;

fn temp_db(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wvs-maint-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A tracked record with these vulnerability uuids
fn record(uuids: &[&str]) -> String {
    let entries: Vec<String> = uuids
        .iter()
        .map(|u| {
            format!(
                r#"{{"uuid":"{u}","name":"Vuln {u}","operator":{{"max_version":"9.0","max_operator":"lt"}},"source":[{{"id":"CVE-2026-{u}","name":"CVE","link":"https://example.org/{u}"}}]}}"#
            )
        })
        .collect();
    format!(
        r#"{{"error":0,"message":null,"data":{{"name":"x","vulnerability":[{}]}}}}"#,
        entries.join(",")
    )
}

const UNTRACKED: &str = r#"{"error":0,"message":null,"data":null}"#;

fn opts(server: &MockServer) -> PullOptions {
    PullOptions {
        api_url: server.uri(),
        jobs: 2,
        attempts: 1,
        delay: Duration::ZERO,
        max_age: None,
    }
}

fn items(keys: &[&str]) -> Vec<(ComponentType, String)> {
    keys.iter()
        .map(|k| (ComponentType::Plugin, k.to_string()))
        .collect()
}

async fn serve(server: &MockServer, p: &str, status: u16, body: &str, etag: Option<&str>) {
    let mut response = ResponseTemplate::new(status).set_body_string(body);
    if let Some(tag) = etag {
        response = response
            .insert_header("ETag", tag)
            .insert_header("Last-Modified", "Tue, 06 Oct 2026 23:11:50 GMT");
    }
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(response)
        .mount(server)
        .await;
}

fn sha_of(p: &Path) -> String {
    db::sha256_hex(&std::fs::read(p).unwrap())
}

#[tokio::test]
async fn pull_records_provenance_for_every_record() {
    let server = MockServer::start().await;
    serve(
        &server,
        "/plugin/akismet/",
        200,
        &record(&["b", "a"]),
        Some("W/\"v1\""),
    )
    .await;
    serve(&server, "/plugin/premium/", 200, UNTRACKED, None).await;
    serve(&server, "/plugin/gone/", 404, "", None).await;
    let dir = temp_db("provenance");

    db::pull(
        &dir,
        &items(&["akismet", "premium", "gone"]),
        &opts(&server),
        |_| {},
    )
    .await
    .unwrap();
    let index = db::read_index(&dir).unwrap().unwrap();
    assert_eq!(index.format, db::FORMAT_VERSION);

    let a = &index.records["plugin/akismet"];
    assert_eq!(a.kind, EntryKind::Tracked);
    assert_eq!(
        (a.records, a.uuids.clone()),
        (2, vec!["a".to_string(), "b".to_string()])
    );
    assert_eq!(a.sha256, sha_of(&dir.join("plugin/akismet.json")));
    assert_eq!(a.http_status, Some(200));
    assert_eq!(a.etag.as_deref(), Some("W/\"v1\""));
    assert_eq!(
        a.last_modified.as_deref(),
        Some("Tue, 06 Oct 2026 23:11:50 GMT")
    );
    assert_eq!(a.url, format!("{}/plugin/akismet/", server.uri()));
    assert!(!a.rebuilt);

    let p = &index.records["plugin/premium"];
    assert_eq!(
        (p.kind, p.records, p.http_status),
        (EntryKind::Untracked, 0, Some(200))
    );
    let g = &index.records["plugin/gone"];
    assert_eq!((g.kind, g.http_status), (EntryKind::Untracked, Some(404)));
    assert_eq!(g.sha256, sha_of(&dir.join("plugin/gone.json")));
}

#[tokio::test]
async fn format_1_databases_are_migrated_on_pull() {
    let server = MockServer::start().await;
    serve(&server, "/plugin/new/", 200, &record(&[]), None).await;
    let dir = temp_db("migrate");
    std::fs::create_dir_all(dir.join("plugin")).unwrap();
    std::fs::write(
        dir.join("wpvuln-db.json"),
        r#"{"format":1,"source":"https://www.wpvulnerability.net","pulled_at":1}"#,
    )
    .unwrap();
    std::fs::write(dir.join("plugin/old.json"), record(&["x"])).unwrap();
    assert_eq!(db::status(&dir).unwrap().indexed, None);

    db::pull(&dir, &items(&["new"]), &opts(&server), |_| {})
        .await
        .unwrap();
    let index = db::read_index(&dir).unwrap().unwrap();
    let old = &index.records["plugin/old"];
    assert!(old.rebuilt);
    assert_eq!(old.http_status, None);
    assert_eq!(old.checked_at, 0, "never confirmed, so stale");
    assert!(old.fetched_at <= 1, "capped at the last pull");
    assert_eq!(old.uuids, vec!["x".to_string()]);
    assert_eq!(old.sha256, sha_of(&dir.join("plugin/old.json")));
    assert!(!index.records["plugin/new"].rebuilt);

    let st = db::status(&dir).unwrap();
    assert_eq!(st.meta.unwrap().format, 2);
    assert_eq!((st.indexed, st.rebuilt, st.unconfirmed), (Some(2), 1, 1));
    assert!(st.oldest_check.is_some());
}

#[tokio::test]
async fn newer_formats_are_refused_not_misread() {
    let server = MockServer::start().await;
    let dir = temp_db("newer");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("wpvuln-db.json"),
        r#"{"format":99,"source":"x","pulled_at":1}"#,
    )
    .unwrap();
    let err = db::pull(&dir, &items(&["a"]), &opts(&server), |_| {})
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("format 99"), "{err}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn freshness_comes_from_the_index() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/plugin/akismet/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(record(&["a"])))
        .expect(1)
        .mount(&server)
        .await;
    let dir = temp_db("fresh");
    let o = PullOptions {
        max_age: Some(Duration::from_secs(3600)),
        ..opts(&server)
    };
    db::pull(&dir, &items(&["akismet"]), &o, |_| {})
        .await
        .unwrap();
    let mut second = Vec::new();
    db::pull(&dir, &items(&["akismet"]), &o, |e| {
        second.push(e.status.clone())
    })
    .await
    .unwrap();
    assert_eq!(second, vec![PullStatus::Fresh(1)]);
}
