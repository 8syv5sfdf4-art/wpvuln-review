//! `inventory::read` against the fixture tree in `tests/fixtures/wp`.

use std::path::{Path, PathBuf};

use wordpress_vulnerable_scanner::inventory::{self, Component, Inventory, Kind, Layout};
use wordpress_vulnerable_scanner::scanner::{ComponentType, parse_component_list};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wp")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wvs-inv-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// (kind, slug, version, main_file) for compact comparisons
fn summary(inv: &Inventory) -> Vec<(Kind, &str, Option<&str>, &str)> {
    inv.components
        .iter()
        .map(|c| {
            (
                c.kind,
                c.slug.as_str(),
                c.version.as_deref(),
                c.main_file.as_str(),
            )
        })
        .collect()
}

fn find<'a>(inv: &'a Inventory, slug: &str) -> &'a Component {
    inv.components
        .iter()
        .find(|c| c.slug == slug)
        .unwrap_or_else(|| panic!("{slug} not found"))
}

fn warned(inv: &Inventory, needle: &str) -> bool {
    inv.warnings.iter().any(|w| w.contains(needle))
}

#[test]
fn reads_a_wordpress_root_like_wordpress_does() {
    let inv = inventory::read(&fixture()).unwrap();
    assert_eq!(inv.format, 1);
    assert_eq!(inv.source.layout, Layout::Wordpress);
    assert_eq!(inv.core.as_ref().unwrap().version.as_deref(), Some("6.6.2"));

    use Kind::*;
    assert_eq!(
        summary(&inv),
        vec![
            (
                Plugin,
                "RTL-CareUnit",
                Some("1.7"),
                "RTL-CareUnit/RTL-CareUnit.php"
            ),
            (Plugin, "akismet", Some("5.3"), "akismet/akismet.php"),
            (
                Plugin,
                "bom-plugin",
                Some("1.0.0"),
                "bom-plugin/bom-plugin.php"
            ),
            (
                Plugin,
                "chaty-pro2",
                Some("3.3.6"),
                "chaty-pro2/cht-icons.php"
            ),
            (
                Plugin,
                "crlf-plugin",
                Some("2.0.1"),
                "crlf-plugin/crlf-plugin.php"
            ),
            (Plugin, "edge-after", None, "edge-after/edge-after.php"),
            (
                Plugin,
                "edge-before",
                Some("1.2.3"),
                "edge-before/edge-before.php"
            ),
            (
                Plugin,
                "empty-version",
                None,
                "empty-version/empty-version.php"
            ),
            (Plugin, "hello", Some("1.7.2"), "hello.php"),
            (Plugin, "latin1", Some("0.9"), "latin1/latin1.php"),
            (Plugin, "two-headers", Some("1.0"), "two-headers/a.php"),
            (Plugin, "two-headers", Some("2.0"), "two-headers/b.php"),
            (
                Plugin,
                "yith-woocommerce-product-bundles-premium",
                Some("2.18.0"),
                "yith-woocommerce-product-bundles-premium/init.php"
            ),
            (MuPlugin, "loader", None, "loader.php"),
            (Dropin, "object-cache", Some("1.5.9"), "object-cache.php"),
            (Theme, "storefront", Some("4.5.0"), "storefront/style.css"),
            (
                Theme,
                "storefront-child",
                Some("1.0.0"),
                "storefront-child/style.css"
            ),
        ]
    );
}

#[test]
fn keeps_header_details() {
    let inv = inventory::read(&fixture()).unwrap();
    let chaty = find(&inv, "chaty-pro2");
    assert_eq!(chaty.name, "Chaty Pro");
    assert_eq!(chaty.text_domain.as_deref(), Some("chaty"));
    assert_eq!(
        chaty.uri.as_deref(),
        Some("https://premio.io/downloads/chaty/")
    );
    assert_eq!(chaty.update_uri.as_deref(), Some("https://premio.io/"));
    assert_eq!(chaty.status, None);

    assert_eq!(
        find(&inv, "crlf-plugin").author.as_deref(),
        Some("Windows Editor")
    );
    assert_eq!(
        find(&inv, "latin1").author.as_deref(),
        Some("Jos\u{FFFD} Garc\u{FFFD}a")
    );
    assert_eq!(find(&inv, "loader").name, "loader.php");
    assert_eq!(
        find(&inv, "storefront-child").parent.as_deref(),
        Some("storefront")
    );
    assert_eq!(find(&inv, "storefront").parent, None);
}

#[test]
fn warns_instead_of_guessing() {
    let inv = inventory::read(&fixture()).unwrap();
    assert!(warned(
        &inv,
        "plugins/no-header: no file with a Plugin Name header"
    ));
    assert!(warned(&inv, "edge-after/edge-after.php: no Version header"));
    assert!(warned(
        &inv,
        "empty-version/empty-version.php: no Version header"
    ));
    assert!(warned(
        &inv,
        "plugins/two-headers: 2 files have a Plugin Name header"
    ));
    assert!(warned(&inv, "themes/broken: no style.css"));
    // Silent files WordPress ignores too
    assert!(!warned(&inv, "plugins/index.php"));
    assert!(!warned(&inv, "notes.txt"));
    assert!(!warned(&inv, "akismet"));
}

#[test]
fn accepts_wp_content_and_plugins_directories() {
    let content = inventory::read(&fixture().join("wp-content")).unwrap();
    assert_eq!(content.source.layout, Layout::WpContent);
    assert!(content.core.is_none());

    let plugins = inventory::read(&fixture().join("wp-content/plugins")).unwrap();
    assert_eq!(plugins.source.layout, Layout::Plugins);
    assert!(plugins.components.iter().all(|c| c.kind == Kind::Plugin));

    let root = inventory::read(&fixture()).unwrap();
    let only_plugins = |inv: &Inventory| {
        inv.components
            .iter()
            .filter(|c| c.kind == Kind::Plugin)
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(only_plugins(&plugins), only_plugins(&root));
    assert_eq!(only_plugins(&content), only_plugins(&root));
}

#[test]
fn descends_into_a_single_wrapper_folder() {
    let dir = temp_dir("wrapper");
    let plugin = dir.join("backup-2026/plugins/akismet");
    std::fs::create_dir_all(&plugin).unwrap();
    std::fs::copy(
        fixture().join("wp-content/plugins/akismet/akismet.php"),
        plugin.join("akismet.php"),
    )
    .unwrap();
    let inv = inventory::read(&dir).unwrap();
    assert_eq!(inv.source.layout, Layout::Plugins);
    assert_eq!(summary(&inv)[0].1, "akismet");

    // A lone plugin folder is a plugin, not a wrapper
    let inv = inventory::read(&dir.join("backup-2026/plugins")).unwrap();
    assert_eq!(summary(&inv)[0].1, "akismet");
}

#[test]
fn list_output_round_trips() {
    let inv = inventory::read(&fixture()).unwrap();
    let list = inv.to_list(ComponentType::Plugin);
    assert!(list.contains("chaty-pro2:3.3.6\n"));
    assert!(list.contains("edge-after\n"));
    let parsed = parse_component_list(&list, ComponentType::Plugin).unwrap();
    assert_eq!(
        parsed.len(),
        inv.components
            .iter()
            .filter(|c| c.kind == Kind::Plugin)
            .count()
    );

    let themes = inv.to_list(ComponentType::Theme);
    assert_eq!(themes, "storefront:4.5.0\nstorefront-child:1.0.0\n");
    assert_eq!(inv.to_list(ComponentType::Core), "6.6.2\n");
}

#[test]
fn json_round_trips() {
    let inv = inventory::read(&fixture()).unwrap();
    let json = serde_json::to_string(&inv).unwrap();
    assert!(json.contains(r#""type":"mu-plugin""#));
    assert!(json.contains(r#""layout":"wordpress""#));
    let back: Inventory = serde_json::from_str(&json).unwrap();
    assert_eq!(back.components, inv.components);
}

#[cfg(unix)]
#[test]
fn symlinks_stay_inside_the_tree() {
    use std::os::unix::fs::symlink;
    let dir = temp_dir("symlink");
    let outside = dir.join("outside");
    let plugins = dir.join("site/plugins");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(plugins.join("real")).unwrap();
    let header = "<?php\n/*\nPlugin Name: X\nVersion: 1\n*/\n";
    std::fs::write(outside.join("evil.php"), header).unwrap();
    std::fs::write(plugins.join("real/real.php"), header).unwrap();
    symlink(&outside, plugins.join("escape")).unwrap();
    symlink(outside.join("evil.php"), plugins.join("evil.php")).unwrap();
    symlink(plugins.join("real"), plugins.join("linked")).unwrap();

    let inv = inventory::read(&plugins).unwrap();
    let slugs: Vec<_> = inv.components.iter().map(|c| c.slug.as_str()).collect();
    assert_eq!(slugs, vec!["linked", "real"]);
    assert!(warned(&inv, "escape: symlink leads outside"));
    assert!(warned(&inv, "evil.php: symlink leads outside"));
}

#[test]
fn rejects_a_missing_path() {
    assert!(inventory::read(Path::new("/nonexistent/wp")).is_err());
}
