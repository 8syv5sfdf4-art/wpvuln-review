//! Alias resolution against the fixture inventory in `tests/fixtures/wp`.

use std::path::Path;

use wordpress_vulnerable_scanner::aliases::{Aliases, Lookup, MatchedVia};
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
