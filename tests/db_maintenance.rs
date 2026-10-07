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
        untracked_max_age: None,
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

fn read_changes(dir: &Path) -> Vec<serde_json::Value> {
    let folder = dir.join("changes");
    let mut all = Vec::new();
    for e in std::fs::read_dir(folder).into_iter().flatten().flatten() {
        let v: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(e.path()).unwrap()).unwrap();
        all.extend(v);
    }
    all
}

/// Serve `first` once, then `second` for every later request
async fn serve_twice(server: &MockServer, p: &str, first: (u16, String), second: (u16, String)) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(first.0).set_body_string(first.1))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(second.0).set_body_string(second.1))
        .with_priority(2)
        .mount(server)
        .await;
}

#[tokio::test]
async fn not_modified_confirms_only_an_intact_record() {
    use wiremock::matchers::{header, header_regex};
    let server = MockServer::start().await;
    let body = record(&["a"]);
    Mock::given(method("GET"))
        .and(path("/plugin/akismet/"))
        .and(header("if-none-match", "W/\"v1\""))
        // header() would split the date at its comma
        .and(header_regex(
            "if-modified-since",
            "^Tue, 06 Oct 2026 23:11:50 GMT$",
        ))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&server)
        .await;
    serve(&server, "/plugin/akismet/", 200, &body, Some("W/\"v1\"")).await;
    let dir = temp_db("conditional");
    let akismet = items(&["akismet"]);

    db::pull(&dir, &akismet, &opts(&server), |_| {})
        .await
        .unwrap();
    let before = db::read_index(&dir).unwrap().unwrap().records["plugin/akismet"].clone();

    let summary = db::pull(&dir, &akismet, &opts(&server), |_| {})
        .await
        .unwrap();
    assert_eq!(
        (summary.unchanged, summary.saved),
        (1, 0),
        "304 confirms it"
    );
    let after = db::read_index(&dir).unwrap().unwrap().records["plugin/akismet"].clone();
    assert_eq!(after.sha256, before.sha256);
    assert!(after.checked_at >= before.checked_at);

    // A tampered file must not be confirmed: no conditional headers, full download
    std::fs::write(dir.join("plugin/akismet.json"), record(&["a", "fake"])).unwrap();
    let summary = db::pull(&dir, &akismet, &opts(&server), |_| {})
        .await
        .unwrap();
    assert_eq!((summary.unchanged, summary.saved), (0, 1));
    assert_eq!(
        std::fs::read_to_string(dir.join("plugin/akismet.json")).unwrap(),
        body
    );
}

#[tokio::test]
async fn changes_are_detected_and_logged() {
    let server = MockServer::start().await;
    let v1 = record(&["a", "b"]);
    // "b" gets a new affected range, "a" is withdrawn, "c" is new
    let v2 = record(&["b", "c"]).replace(
        r#""uuid":"b","name":"Vuln b","operator":{"max_version":"9.0""#,
        r#""uuid":"b","name":"Vuln b","operator":{"max_version":"9.1""#,
    );
    serve_twice(&server, "/plugin/akismet/", (200, v1), (200, v2)).await;
    serve_twice(
        &server,
        "/plugin/chaty-pro/",
        (404, String::new()),
        (200, record(&["d"])),
    )
    .await;
    let dir = temp_db("changes");
    let both = items(&["akismet", "chaty-pro"]);

    let first = db::pull(&dir, &both, &opts(&server), |_| {}).await.unwrap();
    assert!(first.changes.is_empty(), "new records are not changes");

    let second = db::pull(&dir, &both, &opts(&server), |_| {}).await.unwrap();
    use wordpress_vulnerable_scanner::changes::ChangeKind::*;
    let got: Vec<_> = second
        .changes
        .iter()
        .map(|c| (c.key.as_str(), c.change, c.uuid.as_deref()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("plugin/akismet", Added, Some("c")),
            ("plugin/akismet", Removed, Some("a")),
            ("plugin/akismet", Changed, Some("b")),
            ("plugin/chaty-pro", Added, Some("d")),
            ("plugin/chaty-pro", NowTracked, None),
        ]
    );
    let added = &second.changes[0];
    assert_eq!(added.title.as_deref(), Some("Vuln c"));
    assert_eq!(added.cves, vec!["CVE-2026-c".to_string()]);
    let removed = &second.changes[1];
    assert_eq!(
        removed.title.as_deref(),
        Some("Vuln a"),
        "title from the old file"
    );

    let logged = read_changes(&dir);
    assert_eq!(logged.len(), 5);
    assert_eq!(logged[0]["change"], "added");
    assert_eq!(logged[4]["change"], "now_tracked");
}

#[tokio::test]
async fn untracked_records_have_their_own_interval() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/plugin/akismet/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(record(&["a"])))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/plugin/premium/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(UNTRACKED))
        .expect(1)
        .mount(&server)
        .await;
    let dir = temp_db("intervals");
    let both = items(&["akismet", "premium"]);
    db::pull(&dir, &both, &opts(&server), |_| {}).await.unwrap();

    // Tracked: always re-check; untracked: only after a week
    let update = PullOptions {
        max_age: Some(Duration::ZERO),
        untracked_max_age: Some(Duration::from_secs(7 * 24 * 3600)),
        ..opts(&server)
    };
    db::pull(&dir, &both, &update, |_| {}).await.unwrap();
    assert_eq!(
        db::stored(&dir).unwrap(),
        vec![
            (ComponentType::Plugin, "akismet".to_string()),
            (ComponentType::Plugin, "premium".to_string())
        ]
    );
}

/// A pulled database with akismet (tracked) and premium (untracked)
async fn pulled(name: &str) -> PathBuf {
    let server = MockServer::start().await;
    serve(&server, "/plugin/akismet/", 200, &record(&["a"]), None).await;
    serve(&server, "/plugin/premium/", 200, UNTRACKED, None).await;
    let dir = temp_db(name);
    db::pull(
        &dir,
        &items(&["akismet", "premium"]),
        &opts(&server),
        |_| {},
    )
    .await
    .unwrap();
    dir
}

fn problems(dir: &Path) -> Vec<String> {
    db::verify(dir, &[]).problems
}

#[tokio::test]
async fn verify_passes_a_clean_database() {
    let dir = pulled("verify-clean").await;
    let v = db::verify(&dir, &items(&["akismet"]));
    assert!(v.ok(), "{v:#?}");
    assert_eq!((v.records, v.untracked), (2, 1));
}

#[tokio::test]
async fn verify_catches_tampering_and_damage() {
    let dir = pulled("verify-tamper").await;
    std::fs::write(dir.join("plugin/akismet.json"), record(&["a", "planted"])).unwrap();
    let p = problems(&dir);
    assert_eq!(p.len(), 1, "{p:#?}");
    assert!(p[0].starts_with("plugin/akismet.json: content differs from what was downloaded"));

    std::fs::write(dir.join("plugin/akismet.json"), "<html>blocked</html>").unwrap();
    assert!(problems(&dir)[0].contains("not a valid WPVulnerability response"));
}

#[tokio::test]
async fn verify_catches_missing_stray_and_unindexed_files() {
    let dir = pulled("verify-files").await;
    std::fs::remove_file(dir.join("plugin/premium.json")).unwrap();
    std::fs::write(dir.join("plugin/akismet.json.tmp"), "x").unwrap();
    std::fs::write(dir.join("plugin/handmade.json"), record(&[])).unwrap();
    std::fs::write(dir.join("notes.txt"), "x").unwrap();
    let p = problems(&dir).join("\n");
    assert!(
        p.contains("plugin/premium: listed in the index but its file is missing"),
        "{p}"
    );
    assert!(p.contains("plugin/akismet.json.tmp: left over from an interrupted write"));
    assert!(p.contains("plugin/handmade.json: not in the index"));
    assert!(p.contains("notes.txt: unexpected"));
}

#[tokio::test]
async fn verify_reports_inventory_gaps_and_unknown_formats() {
    let dir = pulled("verify-gaps").await;
    let v = db::verify(
        &dir,
        &[
            (ComponentType::Plugin, "akismet".to_string()),
            (ComponentType::Plugin, "never-pulled".to_string()),
            (ComponentType::Core, "6.6.2".to_string()),
        ],
    );
    assert!(v.problems.is_empty());
    assert_eq!(v.missing, vec!["plugin/never-pulled", "core/6.6.2"]);
    assert!(!v.ok());

    std::fs::write(
        dir.join("wpvuln-db.json"),
        r#"{"format":9,"source":"x","pulled_at":1}"#,
    )
    .unwrap();
    assert!(problems(&dir)[0].contains("format 9 is newer than this tool understands"));
    assert!(problems(&temp_db("verify-none"))[0].contains("not a directory"));
}
