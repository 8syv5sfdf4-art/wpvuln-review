//! Alias resolution against the fixture inventory in `tests/fixtures/wp`.

use std::path::Path;

use wordpress_vulnerable_scanner::aliases::{Aliases, Known, Lookup, MatchedVia, render, suggest};
use wordpress_vulnerable_scanner::inventory::{self, Component, Inventory, Kind};

fn fixture() -> Inventory {
    inventory::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp")).unwrap()
}

fn find<'a>(inv: &'a Inventory, kind: Kind, slug: &str) -> &'a Component {
    inv.components
        .iter()
        .find(|c| c.kind == kind && c.slug == slug)
        .unwrap_or_else(|| panic!("{slug} not found"))
}

fn lookup(kind: Kind, slug: &str, version: Option<&str>, via: MatchedVia) -> Option<Lookup> {
    Some(Lookup {
        kind,
        slug: slug.to_string(),
        version: version.map(str::to_string),
        matched_via: via,
    })
}

const ALIASES: &str = r#"
[plugin]
"chaty-pro2" = "chaty"
"akismet-old" = "akismet"
"hello" = { theme = "storefront" }
"gone-plugin" = "gone"
"latin1" = { theme = "not-installed" }

[theme]
"storefront-child" = "storefront"
"#;

#[test]
fn resolves_own_slugs_aliases_and_cross_type_targets() {
    let inv = fixture();
    let a = Aliases::parse(ALIASES).unwrap();
    let r = |kind, slug| a.resolve(&inv, find(&inv, kind, slug));

    use MatchedVia::*;
    assert_eq!(
        r(Kind::Plugin, "akismet"),
        lookup(Kind::Plugin, "akismet", Some("5.3"), Slug)
    );
    assert_eq!(
        r(Kind::Plugin, "chaty-pro2"),
        lookup(Kind::Plugin, "chaty", Some("3.3.6"), Alias)
    );
    // Unloaded copies use the [plugin] table too
    assert_eq!(
        r(Kind::Unloaded, "akismet-old"),
        lookup(Kind::Plugin, "akismet", Some("4.0"), Alias)
    );
    // Shipped with a theme: the theme's version counts
    assert_eq!(
        r(Kind::Plugin, "hello"),
        lookup(Kind::Theme, "storefront", Some("4.5.0"), Alias)
    );
    assert_eq!(
        r(Kind::Plugin, "latin1"),
        lookup(Kind::Theme, "not-installed", None, Alias)
    );
    assert_eq!(
        r(Kind::Theme, "storefront-child"),
        lookup(Kind::Theme, "storefront", Some("1.0.0"), Alias)
    );
    // Never looked up
    assert_eq!(r(Kind::MuPlugin, "loader"), None);
    assert_eq!(r(Kind::Dropin, "object-cache"), None);
}

#[test]
fn explains_aliases_that_cannot_work() {
    let inv = fixture();
    let warnings = Aliases::parse(ALIASES).unwrap().check(&inv);
    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    assert!(warnings[0].starts_with(
        "aliases [plugin] \"gone-plugin\": no installed plugin has this slug, so the alias does nothing."
    ));
    assert!(warnings[1].starts_with(
        "aliases [plugin] \"latin1\" = { theme = \"not-installed\" }: no theme \"not-installed\" is installed, so the version of latin1 is unknown and it is not checked."
    ));
}

#[test]
fn load_names_the_file_in_errors() {
    let dir = std::env::temp_dir().join(format!("wvs-aliases-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("aliases.toml");
    std::fs::write(&path, "[plugin]\n\"x\" = \"Bad Slug\"\n").unwrap();
    let err = Aliases::load(&path).unwrap_err().to_string();
    assert!(err.contains("aliases.toml: [plugin] \"x\""), "{err}");
    assert!(Aliases::load(&dir.join("missing.toml")).is_err());
}

#[test]
fn applied_aliases_shape_the_list_output() {
    let mut inv = fixture();
    Aliases::parse(ALIASES).unwrap().apply(&mut inv);

    let chaty = find(&inv, Kind::Plugin, "chaty-pro2");
    assert_eq!(chaty.lookup_slug.as_deref(), Some("chaty"));
    assert_eq!(chaty.lookup_type, None);
    let hello = find(&inv, Kind::Plugin, "hello");
    assert_eq!(hello.lookup_slug.as_deref(), Some("storefront"));
    assert_eq!(hello.lookup_type, Some(Kind::Theme));
    assert_eq!(find(&inv, Kind::Plugin, "akismet").lookup_slug, None);
    assert!(
        inv.warnings
            .iter()
            .any(|w| w.starts_with("aliases [plugin] \"gone-plugin\""))
    );

    let list = inv.to_list(wordpress_vulnerable_scanner::ComponentType::Plugin);
    assert!(list.contains(
        "# chaty-pro2 checked as \"chaty\" through an alias; premium editions may number versions differently\nchaty:3.3.6\n"
    ), "{list}");
    assert!(list.contains("# hello: covered by the check of theme \"storefront\" (alias)\n"));
    assert!(
        !list
            .lines()
            .any(|l| l.starts_with("hello") || l.starts_with("storefront"))
    );
    assert!(list.contains(
        "# not loaded by WordPress, but on disk: Old Plugins/akismet-old/akismet.php\n# akismet-old checked as \"akismet\" through an alias; premium editions may number versions differently\nakismet:4.0\n"
    ));
    let themes = inv.to_list(wordpress_vulnerable_scanner::ComponentType::Theme);
    assert!(themes.contains("# storefront-child checked as \"storefront\" through an alias; premium editions may number versions differently\nstorefront:1.0.0\n"));
}

#[test]
fn cli_inventory_takes_an_aliases_file() {
    let dir = std::env::temp_dir().join(format!("wvs-aliases-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("aliases.toml");
    std::fs::write(&path, ALIASES).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["inventory", "--format", "list", "--aliases"])
        .arg(&path)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stdout.contains("\nchaty:3.3.6\n"), "{stdout}");
    assert!(
        stderr.contains("aliases [plugin] \"gone-plugin\""),
        "{stderr}"
    );

    std::fs::write(&path, "[plugin]\n\"x\" = \"../x\"\n").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["inventory", "--aliases"])
        .arg(&path)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a valid slug"));
}

fn targets(inv: &Inventory, slug: &str) -> Vec<(Kind, String, String)> {
    let c = inv.components.iter().find(|c| c.slug == slug).unwrap();
    wordpress_vulnerable_scanner::aliases::candidates(inv, c)
        .into_iter()
        .map(|c| (c.target.kind, c.target.slug, c.reasons.join(" | ")))
        .collect()
}

fn t(kind: Kind, slug: &str, why: &str) -> (Kind, String, String) {
    (kind, slug.to_string(), why.to_string())
}

#[test]
fn candidate_heuristics() {
    let mut inv = fixture();
    use Kind::*;
    assert_eq!(
        targets(&inv, "chaty-pro2"),
        vec![
            t(Plugin, "chaty-pro", "dropped trailing digits"),
            t(
                Plugin,
                "chaty",
                "dropped trailing digits, dropped \"-pro\" | Text Domain header"
            ),
        ]
    );
    assert_eq!(
        targets(&inv, "RTL-CareUnit"),
        vec![t(Plugin, "rtl-careunit", "lowercased")]
    );
    assert_eq!(
        targets(&inv, "yith-woocommerce-product-bundles-premium"),
        vec![t(
            Plugin,
            "yith-woocommerce-product-bundles",
            "dropped \"-premium\" | Text Domain header"
        )]
    );
    assert_eq!(
        targets(&inv, "hello"),
        vec![t(
            Plugin,
            "hello-dolly",
            "Plugin/Theme URI points to wordpress.org"
        )]
    );
    assert_eq!(targets(&inv, "akismet"), vec![]);

    // A plugin named after an installed theme is covered by that theme
    let mut extra = inv.components[0].clone();
    extra.slug = "storefront-plus".to_string();
    extra.text_domain = None;
    inv.components.push(extra);
    let found = targets(&inv, "storefront-plus");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].0, found[0].1.as_str()), (Theme, "storefront"));
    assert!(
        found[0]
            .2
            .starts_with("named after the installed theme \"storefront\"")
    );
}

/// Pretend database: these slugs are tracked, the rest untracked,
/// "chaty-pro" was never pulled
fn fake_known(kind: Kind, slug: &str) -> Known {
    match (kind, slug) {
        (Kind::Plugin, "akismet") => Known::Tracked(5),
        (Kind::Plugin, "chaty") => Known::Tracked(2),
        (Kind::Plugin, "chaty-pro") => Known::Missing,
        (Kind::Theme, "storefront") => Known::Tracked(0),
        _ => Known::Untracked,
    }
}

#[test]
fn suggestions_are_confirmed_against_a_database() {
    let inv = fixture();
    let existing = Aliases::parse("[plugin]\n\"RTL-CareUnit\" = \"rtl-careunit\"\n").unwrap();
    let all = suggest(&inv, &existing, Some(&fake_known));
    let get = |slug: &str| all.iter().find(|s| s.slug == slug);

    // Tracked under its own slug, or already aliased: nothing to suggest
    assert!(get("akismet").is_none());
    assert!(get("storefront").is_none());
    assert!(get("RTL-CareUnit").is_none());

    let chaty = get("chaty-pro2").unwrap();
    assert_eq!(chaty.own, Some(Known::Untracked));
    assert_eq!(chaty.chosen, Some(1));
    assert_eq!(chaty.candidates[1].target.slug, "chaty");
    assert_eq!(chaty.candidates[0].known, Some(Known::Missing));

    // Untracked with no candidates is still listed, to be explained
    assert!(get("edge-after").unwrap().candidates.is_empty());

    // Without a database, only components with candidates are listed
    let unchecked = suggest(&inv, &existing, None);
    assert!(
        unchecked
            .iter()
            .all(|s| !s.candidates.is_empty() && s.chosen.is_none())
    );
}

#[test]
fn rendered_suggestions_match_golden_and_are_valid_toml() {
    let inv = fixture();
    let all = suggest(&inv, &Aliases::default(), Some(&fake_known));
    let text = render(&all, "test database");

    // Only confirmed lines are active, and they form a valid aliases file
    let parsed = Aliases::parse(&text).unwrap();
    assert_eq!(parsed.plugin.len(), 2);
    assert_eq!(parsed.plugin["akismet-old"].slug, "akismet");
    assert_eq!(parsed.plugin["chaty-pro2"].slug, "chaty");

    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/aliases-suggest.toml");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
        std::fs::write(&golden, &text).unwrap();
    }
    let expected = std::fs::read_to_string(&golden)
        .expect("golden file missing; run with UPDATE_GOLDEN=1 to create it");
    assert_eq!(
        text, expected,
        "rerun with UPDATE_GOLDEN=1 if the change is intended"
    );
}

#[tokio::test]
async fn online_suggestions_fetch_only_what_the_database_lacks() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wordpress_vulnerable_scanner::aliases::suggest_online;
    use wordpress_vulnerable_scanner::db::PullOptions;

    let tracked = |n: usize| {
        let entries: Vec<String> = (0..n)
            .map(|i| format!(r#"{{"uuid":"u{i}","name":"v{i}","operator":{{"max_version":"1.0","max_operator":"lt"}}}}"#))
            .collect();
        format!(
            r#"{{"error":0,"message":null,"data":{{"name":"x","vulnerability":[{}]}}}}"#,
            entries.join(",")
        )
    };
    let server = MockServer::start().await;
    for (p, status, body) in [
        ("/plugin/akismet/", 200, tracked(3)),
        ("/plugin/chaty/", 200, tracked(2)),
        ("/plugin/chaty-pro/", 500, String::new()),
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
    }
    // Already in the local database: must not be fetched again
    Mock::given(method("GET"))
        .and(path("/plugin/hello-dolly/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(tracked(1)))
        .expect(0)
        .mount(&server)
        .await;

    let db = std::env::temp_dir().join(format!("wvs-online-db-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&db);
    std::fs::create_dir_all(db.join("plugin")).unwrap();
    std::fs::write(db.join("plugin/hello-dolly.json"), tracked(1)).unwrap();

    let opts = PullOptions {
        api_url: server.uri(),
        attempts: 1,
        delay: std::time::Duration::ZERO,
        ..PullOptions::default()
    };
    let inv = fixture();
    let (all, failed) = suggest_online(&inv, &Aliases::default(), Some(&db), &opts)
        .await
        .unwrap();
    let get = |slug: &str| all.iter().find(|s| s.slug == slug);

    assert!(get("akismet").is_none(), "tracked under its own slug");
    let chaty = get("chaty-pro2").unwrap();
    assert_eq!(chaty.candidates[chaty.chosen.unwrap()].target.slug, "chaty");
    assert_eq!(chaty.candidates[0].known, Some(Known::Missing));
    assert_eq!(failed, vec!["chaty-pro: HTTP 500".to_string()]);
    let hello = get("hello").unwrap();
    assert_eq!(
        hello.candidates[hello.chosen.unwrap()].target.slug,
        "hello-dolly"
    );
    // 404 means not tracked
    assert_eq!(get("RTL-CareUnit").unwrap().own, Some(Known::Untracked));

    // The local database is left exactly as it was
    let files: Vec<_> = std::fs::read_dir(db.join("plugin"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(files.len(), 1);
    assert!(!db.join("wpvuln-db.json").exists());
}
