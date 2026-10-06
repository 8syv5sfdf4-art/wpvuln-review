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
            (Theme, "orphan-child", Some("0.1"), "orphan-child/style.css"),
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
        "plugins/no-header: 1 .php file at its top level but none with a Plugin Name header"
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
    assert!(warned(
        &inv,
        "plugins/leftover: no .php file at its top level (it holds images)"
    ));
    assert!(warned(&inv, "plugins/__MACOSX: macOS archive metadata"));
    assert!(warned(
        &inv,
        "plugins: 1 archive file (old-backup.zip) not scanned"
    ));
    assert!(warned(
        &inv,
        "themes/orphan-child: child theme of \"missing-parent\", which is not installed"
    ));
    // Every warning says what it means, not just what happened
    for w in &inv.warnings {
        assert!(w.matches(". ").count() >= 1, "unexplained warning: {w}");
    }
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
    assert_eq!(
        themes,
        "orphan-child:0.1\nstorefront:4.5.0\nstorefront-child:1.0.0\n"
    );
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
    assert!(warned(
        &inv,
        "escape: symlink leads outside the scanned tree"
    ));
    assert!(warned(&inv, "evil.php: symlink leads outside"));
}

#[cfg(unix)]
#[test]
fn broken_links_and_unreadable_folders_are_explained() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = temp_dir("unreadable");
    let plugins = dir.join("plugins");
    std::fs::create_dir_all(plugins.join("locked")).unwrap();
    std::fs::write(
        plugins.join("locked/locked.php"),
        "<?php\n/*\nPlugin Name: Locked\n*/\n",
    )
    .unwrap();
    symlink(dir.join("gone"), plugins.join("dangling")).unwrap();
    std::fs::set_permissions(
        plugins.join("locked"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    let inv = inventory::read(&plugins).unwrap();
    std::fs::set_permissions(
        plugins.join("locked"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(warned(&inv, "dangling: broken symlink"));
    // root can read anything, so only check when the lock held
    if std::fs::read_dir("/root").is_err() {
        assert!(warned(&inv, "locked: could not list this directory"));
    }
}

#[test]
fn rejects_a_missing_path() {
    assert!(inventory::read(Path::new("/nonexistent/wp")).is_err());
}

/// Every file under `root`, as (relative path, bytes), sorted
fn files(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// The fixture as `site/<files>` in a .tar.gz
fn fixture_tar_gz(dest: &Path) {
    let gz = flate2::write::GzEncoder::new(
        std::fs::File::create(dest).unwrap(),
        flate2::Compression::fast(),
    );
    let mut tar = tar::Builder::new(gz);
    for (rel, bytes) in files(&fixture()) {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, format!("site/{rel}"), bytes.as_slice())
            .unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
}

/// The fixture as `site/<files>` in a .zip, with macOS litter
fn fixture_zip(dest: &Path) {
    use std::io::Write;
    let mut zip = zip::ZipWriter::new(std::fs::File::create(dest).unwrap());
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.add_directory("__MACOSX/site/", opts).unwrap();
    zip.start_file("__MACOSX/site/._wp-includes", opts).unwrap();
    for (rel, bytes) in files(&fixture()) {
        zip.start_file(format!("site/{rel}"), opts).unwrap();
        zip.write_all(&bytes).unwrap();
    }
    zip.finish().unwrap();
}

#[test]
fn archives_read_like_the_directory() {
    let dir = temp_dir("archives");
    let on_disk = inventory::read(&fixture()).unwrap();

    for (name, build) in [
        ("site.tar.gz", fixture_tar_gz as fn(&Path)),
        ("site.zip", fixture_zip),
    ] {
        let path = dir.join(name);
        build(&path);
        let inv = inventory::read(&path).unwrap();
        assert_eq!(inv.source.kind, inventory::SourceKind::Archive, "{name}");
        assert_eq!(inv.source.layout, Layout::Wordpress, "{name}");
        assert_eq!(inv.core.unwrap().version.as_deref(), Some("6.6.2"));
        assert_eq!(inv.components, on_disk.components, "{name}");
        let strip = |w: &String| w.trim_start_matches("site/").to_string();
        let warnings: Vec<_> = inv.warnings.iter().map(strip).collect();
        let expected: Vec<_> = on_disk.warnings.iter().map(strip).collect();
        assert_eq!(warnings, expected, "{name}");
    }
}

#[test]
fn plain_tar_of_a_plugins_folder() {
    let dir = temp_dir("plain-tar");
    let path = dir.join("plugins.tar");
    let mut tar = tar::Builder::new(std::fs::File::create(&path).unwrap());
    tar.append_dir_all("plugins", fixture().join("wp-content/plugins"))
        .unwrap();
    tar.finish().unwrap();

    let inv = inventory::read(&path).unwrap();
    assert_eq!(inv.source.layout, Layout::Plugins);
    let from_dir = inventory::read(&fixture().join("wp-content/plugins")).unwrap();
    assert_eq!(inv.components, from_dir.components);
}

/// A tar entry with a raw name, bypassing the builder's path checks
fn raw_entry(tar: &mut tar::Builder<std::fs::File>, name: &str, body: &[u8]) {
    let mut h = tar::Header::new_old();
    h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    tar.append(&h, body).unwrap();
}

#[test]
fn archive_paths_cannot_escape() {
    let dir = temp_dir("evil");
    let path = dir.join("evil.tar");
    let header = b"<?php\n/*\nPlugin Name: Evil\nVersion: 6.6.6\n*/\n";
    let mut tar = tar::Builder::new(std::fs::File::create(&path).unwrap());
    raw_entry(
        &mut tar,
        "plugins/ok/ok.php",
        b"<?php\n/*\nPlugin Name: Ok\nVersion: 1\n*/\n",
    );
    raw_entry(&mut tar, "plugins/../evil/evil.php", header);
    raw_entry(&mut tar, "/plugins/abs/abs.php", header);
    raw_entry(&mut tar, "C:\\plugins\\win\\win.php", header);
    tar.finish().unwrap();
    drop(tar);

    let inv = inventory::read(&path).unwrap();
    let slugs: Vec<_> = inv.components.iter().map(|c| c.slug.as_str()).collect();
    assert_eq!(slugs, vec!["ok"]);
    assert!(warned(&inv, "skipped 3 entries (e.g. "));
    assert!(warned(&inv, "with unsafe paths"));
}

#[test]
fn rejects_unknown_file_types() {
    let dir = temp_dir("not-archive");
    let path = dir.join("plugins.rar");
    std::fs::write(&path, b"Rar!\x1a\x07\x00 not supported").unwrap();
    let err = inventory::read(&path).unwrap_err().to_string();
    assert!(
        err.contains("not a directory, .tar, .tar.gz or .zip"),
        "{err}"
    );
}

#[test]
fn cli_writes_a_clean_list_to_stdout() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["inventory", "--format", "list"])
        .arg(fixture())
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stdout.starts_with("RTL-CareUnit:1.7\nakismet:5.3\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("warning"));
    assert!(
        stderr
            .contains("13 plugins, 3 themes, 1 must-use plugin, 1 drop-in, core 6.6.2, 9 warnings"),
        "{stderr}"
    );
    parse_component_list(&stdout, ComponentType::Plugin).unwrap();
}

#[test]
fn cli_fails_with_exit_10_on_bad_input() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["inventory", "/nonexistent/wp"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
}

/// A stand-in `wp` that prints canned JSON and records its arguments
#[cfg(unix)]
fn fake_wp(dir: &Path, plugins: &str, themes: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("wp");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >> \"{log}\"\ncase \"$1\" in\n  plugin) echo 'PHP Notice: noise'; echo '{plugins}' ;;\n  theme) echo '{themes}' ;;\nesac\n",
            log = dir.join("args.log").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

#[cfg(unix)]
#[test]
fn wp_cli_adds_status_and_updates() {
    let dir = temp_dir("wp-cli");
    let plugins = r#"[{"name":"akismet","status":"active","update":"available","version":"5.3","update_version":"5.4"},
        {"name":"hello","status":"inactive","update":"none","version":"1.7.2","update_version":""},
        {"name":"chaty-pro2","status":"active","update":"none","version":"3.3.5","update_version":""},
        {"name":"loader","status":"must-use","version":"","update_version":""},
        {"name":"object-cache.php","status":"dropin","version":"1.5.9","update_version":""},
        {"name":"ghost","status":"active","version":"1.0","update_version":""}]"#
        .replace('\n', "");
    let themes = r#"[{"name":"storefront","status":"parent","version":"4.5.0","update_version":"4.6.0"},{"name":"storefront-child","status":"active","version":"1.0.0","update_version":""}]"#;
    let wp = inventory::WpCli {
        program: fake_wp(&dir, &plugins, themes),
        path: Some(PathBuf::from("/srv/www")),
        allow_root: true,
    };
    let mut inv = inventory::read(&fixture()).unwrap();
    inventory::enrich_with_wp_cli(&mut inv, &wp);

    assert!(inv.source.wp_cli);
    let akismet = find(&inv, "akismet");
    assert_eq!(akismet.status.as_deref(), Some("active"));
    assert_eq!(akismet.update_version.as_deref(), Some("5.4"));
    assert_eq!(find(&inv, "hello").status.as_deref(), Some("inactive"));
    assert_eq!(find(&inv, "hello").update_version, None);
    assert_eq!(find(&inv, "loader").status.as_deref(), Some("must-use"));
    assert_eq!(find(&inv, "object-cache").status.as_deref(), Some("dropin"));
    assert_eq!(
        find(&inv, "storefront-child").status.as_deref(),
        Some("active")
    );
    assert_eq!(find(&inv, "latin1").status, None);

    // Files win on versions; disagreements and extras are reported
    assert_eq!(find(&inv, "chaty-pro2").version.as_deref(), Some("3.3.6"));
    assert!(warned(
        &inv,
        "chaty-pro2: files say version 3.3.6, WP-CLI says 3.3.5"
    ));
    assert_eq!(find(&inv, "ghost").version.as_deref(), Some("1.0"));
    assert!(warned(
        &inv,
        "plugin ghost: listed by WP-CLI but not found in the files"
    ));

    let log = std::fs::read_to_string(dir.join("args.log")).unwrap();
    assert_eq!(
        log,
        "plugin list --format=json --path=/srv/www --allow-root\ntheme list --format=json --path=/srv/www --allow-root\n"
    );
}

#[test]
fn wp_cli_failure_keeps_file_data() {
    let mut inv = inventory::read(&fixture()).unwrap();
    let before = inv.components.clone();
    let wp = inventory::WpCli {
        program: PathBuf::from("/nonexistent/wp"),
        ..Default::default()
    };
    inventory::enrich_with_wp_cli(&mut inv, &wp);
    assert!(!inv.source.wp_cli);
    assert_eq!(inv.components, before);
    assert!(warned(
        &inv,
        "wp plugin list failed, keeping file data only"
    ));
    assert!(warned(&inv, "wp theme list failed"));
}

#[test]
fn cli_refuses_wp_cli_on_archives() {
    let dir = temp_dir("wp-cli-archive");
    let path = dir.join("site.zip");
    fixture_zip(&path);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_wordpress-vulnerable-scanner"))
        .args(["inventory", "--with-wp-cli"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not an archive"));
}
