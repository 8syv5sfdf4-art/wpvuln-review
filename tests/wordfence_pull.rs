//! `wordfence_db::pull` against a mock server: sources, errors, guards.

use std::path::{Path, PathBuf};

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wordpress_vulnerable_scanner::wordfence::InputFormat;
use wordpress_vulnerable_scanner::wordfence_db::{
    self, Feed, FeedSource, PullOptions, PullOutcome,
};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/wordfence")
            .join(name),
    )
    .unwrap()
}

fn temp_db(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wvs-wf-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const KEY: &str = "secret-intelligence-key-123";

fn github(server: &MockServer, p: &str) -> PullOptions {
    PullOptions {
        from: FeedSource::Github,
        feed: Feed::Production,
        api_key: None,
        url: Some(format!("{}{p}", server.uri())),
        force: false,
        max_bytes: wordfence_db::DEFAULT_MAX_BYTES,
    }
}

fn api(server: &MockServer) -> PullOptions {
    PullOptions {
        from: FeedSource::Api,
        api_key: Some(KEY.to_string()),
        ..github(server, "/v3/vulnerabilities/production")
    }
}

async fn serve(server: &MockServer, p: &str, status: u16, body: &str) {
    Mock::given(method("GET"))
        .and(path(p))
        .respond_with(ResponseTemplate::new(status).set_body_string(body))
        .mount(server)
        .await;
}

async fn pull(db: &Path, opts: &PullOptions) -> Result<PullOutcome, String> {
    wordfence_db::pull(db, opts, |_, _| {}, |_, _| {})
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn github_download_follows_the_redirect_and_stores_meta_and_notice() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/releases/download/db/wordfence_vulnerabilities.json"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", format!("{}/asset", server.uri())),
        )
        .mount(&server)
        .await;
    serve(&server, "/asset", 200, &fixture("wpprobe-sample.json")).await;
    let db = temp_db("github");

    let outcome = pull(
        &db,
        &github(
            &server,
            "/releases/download/db/wordfence_vulnerabilities.json",
        ),
    )
    .await
    .unwrap();
    let PullOutcome::Updated { meta, previous } = outcome else {
        panic!("expected a download")
    };
    assert!(previous.is_none());
    assert_eq!((meta.source, meta.feed), (FeedSource::Github, None));
    assert_eq!((meta.records, meta.slugs), (7, 5));
    assert_eq!(meta.input_format, InputFormat::Wpprobe);
    let feed = wordfence_db::feed_path(&db);
    assert_eq!(meta.sha256, wordfence_db::sha256_file(&feed).unwrap());
    assert_eq!(meta.bytes, std::fs::metadata(&feed).unwrap().len());
    let notice = std::fs::read_to_string(db.join("wordfence/wordfence.NOTICE.txt")).unwrap();
    assert!(notice.contains("Copyright (c) Defiant, Inc."));
    assert!(notice.contains("The MITRE Corporation"));
    assert_eq!(wordfence_db::read_meta(&db).unwrap(), meta);
    assert!(wordfence_db::verify(&db).is_empty());
}

#[tokio::test]
async fn api_download_sends_the_key_and_respects_the_interval() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v3/vulnerabilities/production"))
        .and(header("authorization", format!("Bearer {KEY}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("raw-sample.json")))
        .expect(2)
        .mount(&server)
        .await;
    let db = temp_db("api");

    let PullOutcome::Updated { meta, .. } = pull(&db, &api(&server)).await.unwrap() else {
        panic!("expected a download")
    };
    assert_eq!(
        (meta.source, meta.feed),
        (FeedSource::Api, Some(Feed::Production))
    );
    assert_eq!(meta.input_format, InputFormat::WordfenceRaw);

    // A second download within 30 minutes is skipped, unless forced
    let again = pull(&db, &api(&server)).await.unwrap();
    assert!(matches!(again, PullOutcome::TooSoon { wait, .. } if wait.as_secs() > 25 * 60));
    let forced = PullOptions {
        force: true,
        ..api(&server)
    };
    assert!(matches!(
        pull(&db, &forced).await.unwrap(),
        PullOutcome::Updated { .. }
    ));
}

#[tokio::test]
async fn api_errors_are_explained_and_never_show_the_key() {
    let server = MockServer::start().await;
    let cases = [
        (
            "/401",
            ResponseTemplate::new(401),
            "the API key was refused",
        ),
        (
            "/403",
            ResponseTemplate::new(403),
            "not a plugin license key",
        ),
        ("/410", ResponseTemplate::new(410), "keyless v2 API is gone"),
        (
            "/429",
            ResponseTemplate::new(429).insert_header("Retry-After", "1800"),
            "Retry after: 1800",
        ),
        ("/500", ResponseTemplate::new(500), "HTTP 500"),
    ];
    for (p, response, _) in &cases {
        Mock::given(method("GET"))
            .and(path(*p))
            .respond_with(response.clone())
            .mount(&server)
            .await;
    }
    for (p, _, expected) in cases {
        let db = temp_db(&format!("err{}", &p[1..]));
        let opts = PullOptions {
            url: Some(format!("{}{p}", server.uri())),
            ..api(&server)
        };
        let err = pull(&db, &opts).await.unwrap_err();
        assert!(err.contains(expected), "{p}: {err}");
        assert!(!err.contains(KEY), "{p} leaks the key: {err}");
        assert!(!wordfence_db::feed_path(&db).exists());
    }

    let no_key = PullOptions {
        api_key: None,
        ..api(&server)
    };
    let err = pull(&temp_db("nokey"), &no_key).await.unwrap_err();
    assert!(err.contains("needs a key"), "{err}");
}

#[tokio::test]
async fn a_bad_download_never_replaces_a_good_feed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("wpprobe-sample.json")))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/feed"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><body>Captive portal</body></html>"),
        )
        .with_priority(2)
        .mount(&server)
        .await;
    serve(
        &server,
        "/truncated",
        200,
        "[{\"title\":\"x\",\"slug\":\"y\"",
    )
    .await;
    let db = temp_db("bad");
    pull(&db, &github(&server, "/feed")).await.unwrap();
    let good = wordfence_db::sha256_file(&wordfence_db::feed_path(&db)).unwrap();

    let err = pull(&db, &github(&server, "/feed")).await.unwrap_err();
    assert!(err.contains("HTML"), "{err}");
    let err = pull(&db, &github(&server, "/truncated")).await.unwrap_err();
    assert!(err.contains("not a usable feed"), "{err}");
    assert_eq!(
        wordfence_db::sha256_file(&wordfence_db::feed_path(&db)).unwrap(),
        good
    );
    assert!(!db.join("wordfence/wordfence.json.tmp").exists());

    // The size cap stops a download early
    let small = PullOptions {
        max_bytes: 10,
        ..github(&server, "/truncated")
    };
    assert!(pull(&db, &small).await.unwrap_err().contains("larger than"));
}

#[tokio::test]
async fn not_modified_only_updates_the_time() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/feed"))
        .and(header("if-none-match", "W/\"wf1\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/feed"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("ETag", "W/\"wf1\"")
                .set_body_string(fixture("wpprobe-sample.json")),
        )
        .with_priority(2)
        .mount(&server)
        .await;
    let db = temp_db("304");
    let PullOutcome::Updated { meta: first, .. } =
        pull(&db, &github(&server, "/feed")).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(first.http_etag.as_deref(), Some("W/\"wf1\""));
    let PullOutcome::NotModified(second) = pull(&db, &github(&server, "/feed")).await.unwrap()
    else {
        panic!("expected 304")
    };
    assert_eq!(second.sha256, first.sha256);
    assert!(second.fetched_at >= first.fetched_at);
}

#[tokio::test]
async fn verify_and_transfer_cover_the_feed() {
    let server = MockServer::start().await;
    serve(&server, "/feed", 200, &fixture("wpprobe-sample.json")).await;
    let db = temp_db("verify");
    pull(&db, &github(&server, "/feed")).await.unwrap();
    // db verify accepts the folder (no "unexpected" for wordfence/)
    assert!(
        wordpress_vulnerable_scanner::db::verify(&db, &[])
            .problems
            .iter()
            .all(|p| !p.contains("wordfence")),
    );

    // export / import carry it along
    std::fs::write(
        db.join("wpvuln-db.json"),
        r#"{"format":2,"source":"x","pulled_at":1}"#,
    )
    .unwrap();
    std::fs::write(db.join("index.json"), r#"{"format":2,"records":{}}"#).unwrap();
    let bundle = db.with_extension("tar.gz");
    let m = wordpress_vulnerable_scanner::transfer::export(&db, &bundle).unwrap();
    assert!(m.files.contains_key("wordfence/wordfence.json"));
    assert!(m.files.contains_key("wordfence/wordfence.NOTICE.txt"));
    let target = temp_db("verify-imported");
    wordpress_vulnerable_scanner::transfer::import(&bundle, &target).unwrap();
    assert!(wordfence_db::verify(&target).is_empty());

    // Tampering and a missing notice are caught
    std::fs::write(wordfence_db::feed_path(&db), fixture("raw-sample.json")).unwrap();
    std::fs::remove_file(db.join("wordfence/wordfence.NOTICE.txt")).unwrap();
    let problems = wordfence_db::verify(&db).join("\n");
    assert!(problems.contains("sha256 mismatch"), "{problems}");
    assert!(problems.contains("NOTICE.txt: missing"));
}

#[test]
fn import_validates_and_stores_with_notice() {
    let db = temp_db("import");
    let file = db.with_extension("json");
    std::fs::write(&file, fixture("raw-sample.json")).unwrap();
    let meta = wordfence_db::import(&db, &file).unwrap();
    assert_eq!(
        (meta.records, meta.input_format),
        (4, InputFormat::WordfenceRaw)
    );
    assert!(wordfence_db::verify(&db).is_empty());
    std::fs::write(&file, "<html>no</html>").unwrap();
    assert!(wordfence_db::import(&db, &file).is_err());
    assert_eq!(
        wordfence_db::read_meta(&db).unwrap().records,
        4,
        "old feed kept"
    );
}

#[tokio::test]
async fn keyless_downloads_retry_transient_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/flaky"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    serve(&server, "/flaky", 200, &fixture("wpprobe-sample.json")).await;
    let db = temp_db("retry");
    let mut seen = 0;
    let outcome = wordfence_db::pull(&db, &github(&server, "/flaky"), |b, _| seen = b, |_, _| {})
        .await
        .unwrap();
    assert!(matches!(outcome, PullOutcome::Updated { .. }));
    assert!(seen > 0, "progress reported");

    // A first pull that fails for good leaves no empty folder behind
    serve(&server, "/gone", 404, "").await;
    let fresh = temp_db("no-leftover");
    assert!(pull(&fresh, &github(&server, "/gone")).await.is_err());
    assert!(!fresh.join("wordfence").exists());
}
