//! Native inventory of a WordPress installation
//!
//! Lists core, plugins, must-use plugins, drop-ins and themes with their
//! versions by reading files the way WordPress itself does, so the result
//! matches what wp-admin shows. No PHP is executed and nothing touches the
//! network, so it runs on locked-down servers.
//!
//! The rules mirrored here:
//!
//! - `get_plugins()`: every `*.php` directly in `plugins/`, and every `*.php`
//!   one level inside each plugin folder, whose headers carry a non-empty
//!   `Plugin Name`. Dotfiles are skipped, and the `.php` suffix is case-sensitive.
//! - `get_file_data()`: only the first 8 KiB is read, `\r` becomes `\n`, and
//!   each header matches `^(?:[ \t]*<\?php)?[ \t/*#@]*<Header>:(.*)$`
//!   (case-insensitive, multiline), cleaned by `_cleanup_header_comment()`.
//! - `get_mu_plugins()`, `get_dropins()`, `search_theme_directories()` and
//!   `$wp_version` in `wp-includes/version.php`.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::scanner::ComponentType;

/// Inventory file format version, bumped on incompatible changes
pub const FORMAT_VERSION: u32 = 1;

/// Bytes of each file that are read, like `get_file_data()`
pub const HEAD_LEN: usize = 8192;

/// Drop-in files WordPress recognises in `wp-content` (`_get_dropins()`)
const DROPINS: [&str; 12] = [
    "advanced-cache.php",
    "db.php",
    "db-error.php",
    "install.php",
    "maintenance.php",
    "object-cache.php",
    "php-error.php",
    "fatal-error-handler.php",
    "sunrise.php",
    "blog-deleted.php",
    "blog-inactive.php",
    "blog-suspended.php",
];

const PLUGIN_HEADERS: [&str; 6] = [
    "Plugin Name",
    "Plugin URI",
    "Version",
    "Author",
    "Text Domain",
    "Update URI",
];

const THEME_HEADERS: [&str; 7] = [
    "Theme Name",
    "Theme URI",
    "Version",
    "Author",
    "Text Domain",
    "Update URI",
    "Template",
];

/// Everything found in one WordPress installation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    /// Format version ([`FORMAT_VERSION`])
    pub format: u32,
    /// When the inventory was taken (UTC, ISO 8601)
    pub generated_at: String,
    /// What was read
    pub source: InventorySource,
    /// WordPress core, when the input contains `wp-includes/version.php`
    pub core: Option<Core>,
    /// Plugins, must-use plugins, drop-ins and themes
    pub components: Vec<Component>,
    /// Anything that could not be read or looked odd
    pub warnings: Vec<String>,
}

/// Where an inventory came from
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySource {
    /// Path given on the command line
    pub path: String,
    /// A directory or an archive
    pub kind: SourceKind,
    /// What the input turned out to contain
    pub layout: Layout,
    /// Whether WP-CLI data was merged in
    pub wp_cli: bool,
}

/// Directory or archive input
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceKind {
    /// A directory on disk
    Directory,
    /// A `.tar`, `.tar.gz` or `.zip` file
    Archive,
}

/// What part of an installation the input holds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layout {
    /// A WordPress root (has `wp-includes/version.php`)
    Wordpress,
    /// A `wp-content` directory
    WpContent,
    /// A bare plugins directory
    Plugins,
}

/// WordPress core
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Core {
    /// `$wp_version`, if it could be read
    pub version: Option<String>,
}

/// Kind of installed component
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Regular plugin in `plugins/`
    Plugin,
    /// Theme in `themes/`
    Theme,
    /// Must-use plugin in `mu-plugins/`
    MuPlugin,
    /// Drop-in file in `wp-content/`
    Dropin,
}

/// One installed plugin, theme, must-use plugin or drop-in
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Component kind
    #[serde(rename = "type")]
    pub kind: Kind,
    /// Folder name (or file name without `.php`), as installed
    pub slug: String,
    /// `Plugin Name` / `Theme Name` header
    pub name: String,
    /// `Version` header; `None` when missing or empty
    pub version: Option<String>,
    /// File the headers were read from, relative to its kind's directory
    /// (`akismet/akismet.php`, `hello.php`, `twentytwenty/style.css`)
    pub main_file: String,
    /// `Plugin URI` / `Theme URI` header
    #[serde(default)]
    pub uri: Option<String>,
    /// `Update URI` header
    #[serde(default)]
    pub update_uri: Option<String>,
    /// `Author` header
    #[serde(default)]
    pub author: Option<String>,
    /// `Text Domain` header
    #[serde(default)]
    pub text_domain: Option<String>,
    /// Parent theme of a child theme (`Template` header)
    #[serde(default)]
    pub parent: Option<String>,
    /// Status from WP-CLI (`active`, `inactive`, ...); unknown without it
    #[serde(default)]
    pub status: Option<String>,
    /// Available update reported by WP-CLI
    #[serde(default)]
    pub update_version: Option<String>,
    /// Slug to look up in vulnerability data, when it differs from `slug`
    #[serde(default)]
    pub lookup_slug: Option<String>,
}

impl Inventory {
    /// `slug:version` lines (one version line for core), the format read by
    /// `--plugins-file`, `--themes-file` and `parse_component_list`
    pub fn to_list(&self, kind: ComponentType) -> String {
        let mut out = String::new();
        if kind == ComponentType::Core {
            if let Some(v) = self.core.as_ref().and_then(|c| c.version.as_deref()) {
                out.push_str(v);
                out.push('\n');
            }
            return out;
        }
        let want = match kind {
            ComponentType::Theme => Kind::Theme,
            _ => Kind::Plugin,
        };
        for c in self.components.iter().filter(|c| c.kind == want) {
            if !crate::db::is_safe_key(&c.slug) {
                out.push_str(&format!("# skipped {:?}: not a valid slug\n", c.slug));
                continue;
            }
            match &c.version {
                Some(v) => out.push_str(&format!("{}:{}\n", c.slug, v)),
                None => out.push_str(&format!("{}\n", c.slug)),
            }
        }
        out
    }
}

/// Take an inventory of a WordPress root, a `wp-content` directory or a
/// plugins directory
pub fn read(path: &Path) -> Result<Inventory> {
    if !path.is_dir() {
        return Err(Error::Inventory(format!(
            "{}: not a directory",
            path.display()
        )));
    }
    let mut tree = FsTree::new(path)?;
    let mut inv = walk(&mut tree)?;
    inv.source.path = path.display().to_string();
    Ok(inv)
}

/// Precompiled `get_file_data()` header patterns
struct Headers(Vec<(&'static str, Regex)>);

impl Headers {
    fn new(names: &[&'static str]) -> Self {
        Self(
            names
                .iter()
                .map(|&name| {
                    let re = format!(
                        r"(?mi)^(?:[ \t]*<\?php)?[ \t/*#@]*{}:(.*)$",
                        regex::escape(name)
                    );
                    (name, Regex::new(&re).expect("valid header regex"))
                })
                .collect(),
        )
    }

    /// Non-empty header values found in the first [`HEAD_LEN`] bytes
    fn parse(&self, bytes: &[u8]) -> HashMap<&'static str, String> {
        let text = file_data(bytes);
        let mut out = HashMap::new();
        for (name, re) in &self.0 {
            let Some(raw) = re.captures(&text).and_then(|c| c.get(1)) else {
                continue;
            };
            // PHP tests `$match[1]` for truthiness, and "0" is falsy
            if raw.as_str() == "0" {
                continue;
            }
            let value = cleanup_header_comment(raw.as_str());
            if !value.is_empty() {
                out.insert(*name, value.to_string());
            }
        }
        out
    }
}

/// The text `get_file_data()` matches against: the first 8 KiB, with every
/// `\r` turned into `\n`. Invalid UTF-8 is replaced, not rejected.
fn file_data(bytes: &[u8]) -> String {
    let head = &bytes[..bytes.len().min(HEAD_LEN)];
    String::from_utf8_lossy(head).replace('\r', "\n")
}

/// `_cleanup_header_comment()`: cut at the first `*/` or `?>`, then trim
fn cleanup_header_comment(s: &str) -> &str {
    let cut = [s.find("*/"), s.find("?>")]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(s.len());
    // PHP's trim() set
    s[..cut].trim_matches([' ', '\t', '\n', '\r', '\0', '\x0B'])
}

/// `$wp_version = '6.6.2';` from `wp-includes/version.php`
fn core_version(bytes: &[u8]) -> Option<String> {
    let re = Regex::new(r#"\$wp_version\s*=\s*['"]([^'"]+)['"]"#).expect("valid regex");
    re.captures(&file_data(bytes))
        .map(|c| c[1].trim().to_string())
        .filter(|v| !v.is_empty())
}

/// A directory entry; anything that is not a regular file or a directory
/// is left out
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    name: String,
    is_dir: bool,
}

/// Read-only view of a directory tree. Paths are relative, `/`-separated,
/// and `""` is the root.
trait Tree {
    /// Entries of `dir`, sorted by name
    fn list(&mut self, dir: &str, warnings: &mut Vec<String>) -> Vec<Entry>;
    /// The first [`HEAD_LEN`] bytes of each readable file in `paths`
    fn heads(&mut self, paths: &[String], warnings: &mut Vec<String>) -> HashMap<String, Vec<u8>>;
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// A directory on disk. Symlinks are followed only when they stay inside it.
struct FsTree {
    root: PathBuf,
}

impl FsTree {
    fn new(path: &Path) -> Result<Self> {
        let root = path
            .canonicalize()
            .map_err(|e| Error::Inventory(format!("{}: {e}", path.display())))?;
        Ok(Self { root })
    }
}

impl Tree for FsTree {
    fn list(&mut self, dir: &str, warnings: &mut Vec<String>) -> Vec<Entry> {
        let Ok(read) = std::fs::read_dir(self.root.join(dir)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in read.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                warnings.push(format!(
                    "{}: file name is not valid UTF-8, skipped",
                    join(dir, &entry.file_name().to_string_lossy())
                ));
                continue;
            };
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let meta = if meta.file_type().is_symlink() {
                match path.canonicalize() {
                    Ok(target) if target.starts_with(&self.root) => {
                        match std::fs::metadata(&target) {
                            Ok(m) => m,
                            Err(_) => continue,
                        }
                    }
                    _ => {
                        warnings.push(format!(
                            "{}: symlink leads outside the scanned tree, skipped",
                            join(dir, &name)
                        ));
                        continue;
                    }
                }
            } else {
                meta
            };
            if meta.is_dir() || meta.is_file() {
                out.push(Entry {
                    name,
                    is_dir: meta.is_dir(),
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    fn heads(&mut self, paths: &[String], warnings: &mut Vec<String>) -> HashMap<String, Vec<u8>> {
        let mut out = HashMap::new();
        for p in paths {
            let mut buf = Vec::new();
            match std::fs::File::open(self.root.join(p))
                .and_then(|f| f.take(HEAD_LEN as u64).read_to_end(&mut buf))
            {
                Ok(_) => {
                    out.insert(p.clone(), buf);
                }
                Err(e) => warnings.push(format!("{p}: unreadable ({e})")),
            }
        }
        out
    }
}

/// Find what the tree holds. A single wrapper folder (as archives often
/// have) is descended into, unless it looks like a plugin itself.
fn detect(tree: &mut impl Tree, warnings: &mut Vec<String>) -> (Layout, String) {
    let mut base = String::new();
    for _ in 0..4 {
        let entries = tree.list(&base, warnings);
        let has_dir = |n: &str| entries.iter().any(|e| e.is_dir && e.name == n);
        if has_dir("wp-includes")
            && tree
                .list(&join(&base, "wp-includes"), warnings)
                .iter()
                .any(|e| !e.is_dir && e.name == "version.php")
        {
            return (Layout::Wordpress, base);
        }
        let visible: Vec<&Entry> = entries
            .iter()
            .filter(|e| !e.name.starts_with('.') && e.name != "__MACOSX")
            .collect();
        // A lone `plugins/` folder is a wrapper (`tar czf x.tgz plugins`)
        if has_dir("themes") || has_dir("mu-plugins") || (has_dir("plugins") && visible.len() > 1) {
            return (Layout::WpContent, base);
        }
        if !base.is_empty() && base.rsplit('/').next() == Some("plugins") {
            return (Layout::Plugins, base);
        }
        if let [only] = visible.as_slice()
            && only.is_dir
        {
            let child = join(&base, &only.name);
            let looks_like_plugin = tree
                .list(&child, warnings)
                .iter()
                .any(|e| !e.is_dir && e.name.ends_with(".php") && e.name != "index.php");
            if !looks_like_plugin {
                base = child;
                continue;
            }
        }
        break;
    }
    (Layout::Plugins, base)
}

/// Inventory of any [`Tree`]
fn walk(tree: &mut impl Tree) -> Result<Inventory> {
    let mut warnings = Vec::new();
    let (layout, base) = detect(tree, &mut warnings);
    let content = match layout {
        Layout::Wordpress => join(&base, "wp-content"),
        _ => base.clone(),
    };
    let plugins_dir = match layout {
        Layout::Plugins => base.clone(),
        _ => join(&content, "plugins"),
    };

    // Collect candidate files first, so archives can be read in one pass
    let mut plugin_files: Vec<(String, String)> = Vec::new(); // (slug, main_file)
    let mut folders: Vec<String> = Vec::new();
    for e in tree.list(&plugins_dir, &mut warnings) {
        if e.name.starts_with('.') {
            continue;
        }
        if e.is_dir {
            folders.push(e.name.clone());
            for f in tree.list(&join(&plugins_dir, &e.name), &mut warnings) {
                if !f.is_dir && !f.name.starts_with('.') && f.name.ends_with(".php") {
                    plugin_files.push((e.name.clone(), format!("{}/{}", e.name, f.name)));
                }
            }
        } else if e.name.ends_with(".php") {
            let slug = e.name.trim_end_matches(".php").to_string();
            plugin_files.push((slug, e.name.clone()));
        }
    }

    let mut mu_files = Vec::new();
    let mut dropin_files = Vec::new();
    let mut theme_dirs = Vec::new();
    if layout != Layout::Plugins {
        let mu_dir = join(&content, "mu-plugins");
        for e in tree.list(&mu_dir, &mut warnings) {
            if !e.is_dir && !e.name.starts_with('.') && e.name.ends_with(".php") {
                mu_files.push(e.name);
            }
        }
        for e in tree.list(&content, &mut warnings) {
            if !e.is_dir && DROPINS.contains(&e.name.as_str()) {
                dropin_files.push(e.name);
            }
        }
        let themes_dir = join(&content, "themes");
        for e in tree.list(&themes_dir, &mut warnings) {
            if !e.is_dir || e.name.starts_with('.') || e.name == "CVS" {
                continue;
            }
            let has_style = tree
                .list(&join(&themes_dir, &e.name), &mut warnings)
                .iter()
                .any(|f| !f.is_dir && f.name == "style.css");
            if has_style {
                theme_dirs.push(e.name);
            } else {
                warnings.push(format!(
                    "{}: no style.css, not a theme",
                    join(&themes_dir, &e.name)
                ));
            }
        }
    }

    let core_file = join(&base, "wp-includes/version.php");
    let mut wanted: Vec<String> = plugin_files
        .iter()
        .map(|(_, f)| join(&plugins_dir, f))
        .collect();
    wanted.extend(
        mu_files
            .iter()
            .map(|f| join(&content, &format!("mu-plugins/{f}"))),
    );
    wanted.extend(dropin_files.iter().map(|f| join(&content, f)));
    wanted.extend(
        theme_dirs
            .iter()
            .map(|d| join(&content, &format!("themes/{d}/style.css"))),
    );
    if layout == Layout::Wordpress {
        wanted.push(core_file.clone());
    }
    let heads = tree.heads(&wanted, &mut warnings);
    let head = |p: &str| heads.get(p).map(Vec::as_slice);

    let plugin_headers = Headers::new(&PLUGIN_HEADERS);
    let mut components = Vec::new();

    // Plugins: every file with a Plugin Name header counts, as in get_plugins()
    let mut found_in: HashMap<&str, Vec<&str>> = HashMap::new();
    for (slug, file) in &plugin_files {
        let path = join(&plugins_dir, file);
        let Some(bytes) = head(&path) else { continue };
        let h = plugin_headers.parse(bytes);
        let Some(name) = h.get("Plugin Name") else {
            if !file.contains('/') && file != "index.php" {
                warnings.push(format!("{path}: no Plugin Name header, not a plugin"));
            }
            continue;
        };
        if file.contains('/') {
            found_in.entry(slug).or_default().push(file);
        }
        if !h.contains_key("Version") {
            warnings.push(format!("{path}: no Version header, version unknown"));
        }
        components.push(component(Kind::Plugin, slug, name, file, &h));
    }
    for folder in &folders {
        match found_in.get(folder.as_str()).map(Vec::as_slice) {
            None => warnings.push(format!(
                "{}: no file with a Plugin Name header, not a plugin",
                join(&plugins_dir, folder)
            )),
            Some([_]) => {}
            Some(files) => warnings.push(format!(
                "{}: {} files have a Plugin Name header ({}); WordPress lists each as a separate plugin",
                join(&plugins_dir, folder),
                files.len(),
                files.join(", ")
            )),
        }
    }

    // Must-use plugins: every .php counts; the name defaults to the file name
    for file in &mu_files {
        let Some(bytes) = head(&join(&content, &format!("mu-plugins/{file}"))) else {
            continue;
        };
        // get_mu_plugins() drops a "Silence is golden" index.php
        if file == "index.php" && bytes.len() <= 30 {
            continue;
        }
        let h = plugin_headers.parse(bytes);
        let name = h
            .get("Plugin Name")
            .cloned()
            .unwrap_or_else(|| file.clone());
        let slug = file.trim_end_matches(".php");
        components.push(component(Kind::MuPlugin, slug, &name, file, &h));
    }

    for file in &dropin_files {
        let Some(bytes) = head(&join(&content, file)) else {
            continue;
        };
        let h = plugin_headers.parse(bytes);
        let name = h
            .get("Plugin Name")
            .cloned()
            .unwrap_or_else(|| file.clone());
        let slug = file.trim_end_matches(".php");
        components.push(component(Kind::Dropin, slug, &name, file, &h));
    }

    let theme_headers = Headers::new(&THEME_HEADERS);
    for dir in &theme_dirs {
        let path = join(&content, &format!("themes/{dir}/style.css"));
        let Some(bytes) = head(&path) else { continue };
        let h = theme_headers.parse(bytes);
        let Some(name) = h.get("Theme Name") else {
            warnings.push(format!("{path}: no Theme Name header, not a theme"));
            continue;
        };
        if !h.contains_key("Version") {
            warnings.push(format!("{path}: no Version header, version unknown"));
        }
        let mut c = component(Kind::Theme, dir, name, &format!("{dir}/style.css"), &h);
        c.uri = h.get("Theme URI").cloned();
        c.parent = h.get("Template").filter(|t| *t != dir).cloned();
        components.push(c);
    }

    let core = (layout == Layout::Wordpress).then(|| {
        let version = head(&core_file).and_then(core_version);
        if version.is_none() {
            warnings.push(format!("{core_file}: no $wp_version found"));
        }
        Core { version }
    });

    Ok(Inventory {
        format: FORMAT_VERSION,
        generated_at: crate::analyze::chrono_lite_now(),
        source: InventorySource {
            path: String::new(),
            kind: SourceKind::Directory,
            layout,
            wp_cli: false,
        },
        core,
        components,
        warnings,
    })
}

fn component(
    kind: Kind,
    slug: &str,
    name: &str,
    main_file: &str,
    h: &HashMap<&'static str, String>,
) -> Component {
    Component {
        kind,
        slug: slug.to_string(),
        name: name.to_string(),
        version: h.get("Version").cloned(),
        main_file: main_file.to_string(),
        uri: h.get("Plugin URI").cloned(),
        update_uri: h.get("Update URI").cloned(),
        author: h.get("Author").cloned(),
        text_domain: h.get("Text Domain").cloned(),
        parent: None,
        status: None,
        update_version: None,
        lookup_slug: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(text: &[u8]) -> HashMap<&'static str, String> {
        Headers::new(&PLUGIN_HEADERS).parse(text)
    }

    #[test]
    fn reads_docblock_headers() {
        let h = plugin(b"<?php\n/**\n * Plugin Name: Akismet Anti-spam\n * Version: 5.3\n * Text Domain: akismet\n */\n");
        assert_eq!(h["Plugin Name"], "Akismet Anti-spam");
        assert_eq!(h["Version"], "5.3");
        assert_eq!(h["Text Domain"], "akismet");
    }

    #[test]
    fn header_prefixes_and_case() {
        assert_eq!(
            plugin(b"<?php plugin name: Inline")["Plugin Name"],
            "Inline"
        );
        assert_eq!(plugin(b"# Plugin Name: Hash")["Plugin Name"], "Hash");
        assert_eq!(plugin(b"  @Plugin Name: At")["Plugin Name"], "At");
        // Text before the header on the same line does not match
        assert!(!plugin(b"$x = 1; // Plugin Name: Code").contains_key("Plugin Name"));
    }

    #[test]
    fn cleanup_cuts_comment_end_and_php_close() {
        assert_eq!(plugin(b"/* Plugin Name: One */")["Plugin Name"], "One");
        assert_eq!(plugin(b"<?php /* Version: 1.2 */ ?>")["Version"], "1.2");
        assert_eq!(cleanup_header_comment("  a */ b ?> c "), "a");
    }

    #[test]
    fn crlf_and_lone_cr() {
        let h = plugin(b"<?php\r\n/*\r\nPlugin Name: Crlf\r\nVersion: 2.0.1\r\n*/");
        assert_eq!(h["Plugin Name"], "Crlf");
        assert_eq!(h["Version"], "2.0.1");
        assert_eq!(plugin(b"/*\rPlugin Name: Mac\r*/")["Plugin Name"], "Mac");
    }

    #[test]
    fn bom_and_invalid_utf8() {
        let h =
            plugin(b"\xEF\xBB\xBF<?php\n/*\nPlugin Name: Bom\nAuthor: Jos\xE9\nVersion: 1.0\n*/");
        assert_eq!(h["Plugin Name"], "Bom");
        assert_eq!(h["Author"], "Jos\u{FFFD}");
        assert_eq!(h["Version"], "1.0");
    }

    #[test]
    fn only_the_first_8_kib_counts() {
        let mut text = b"<?php\n/*\nPlugin Name: Edge\n".to_vec();
        let line = b"Version: 1.2.3";
        text.resize(HEAD_LEN - line.len(), b' ');
        text.extend_from_slice(line);
        assert_eq!(text.len(), HEAD_LEN);
        assert_eq!(plugin(&text)["Version"], "1.2.3");

        // "Vers" fits in the head, "ion: 9.9.9" does not
        text.truncate(HEAD_LEN - 5);
        text.extend_from_slice(b"\nVersion: 9.9.9");
        assert!(text.len() > HEAD_LEN);
        assert!(!plugin(&text).contains_key("Version"));
    }

    #[test]
    fn empty_and_zero_values_count_as_missing() {
        let h = plugin(b"/*\nPlugin Name: X\nVersion:\nAuthor:0\n*/");
        assert!(!h.contains_key("Version"));
        assert!(!h.contains_key("Author"));
    }

    #[test]
    fn first_match_wins() {
        let h = plugin(b"/*\nPlugin Name: First\nPlugin Name: Second\n*/");
        assert_eq!(h["Plugin Name"], "First");
    }

    #[test]
    fn reads_core_version() {
        let v = core_version(
            b"<?php\n/**\n * @global string $wp_version\n */\n$wp_version = '6.6.2';\n",
        );
        assert_eq!(v.as_deref(), Some("6.6.2"));
        assert_eq!(core_version(b"<?php\n"), None);
    }
}
