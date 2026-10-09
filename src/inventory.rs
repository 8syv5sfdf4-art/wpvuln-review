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
    /// Plugin inside a folder WordPress does not load, such as a backup
    /// copy in `plugins/Old Plugins/`. It is not active, but its files are
    /// still on disk and may be reachable over the web, so it is scanned.
    Unloaded,
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
    /// Where `version` came from; `None` when there is no version
    #[serde(default)]
    pub version_source: Option<VersionSource>,
}

/// Where a component's version was read from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionSource {
    /// The `Version` header, as WordPress reads it
    Header,
    /// `Stable tag` in readme.txt, used only when the header is missing
    Readme,
    /// WP-CLI, for a component it lists that the files lacked
    #[serde(rename = "wp-cli")]
    WpCli,
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
        let want: &[Kind] = match kind {
            ComponentType::Theme => &[Kind::Theme],
            _ => &[Kind::Plugin, Kind::Unloaded],
        };
        for c in self.components.iter().filter(|c| want.contains(&c.kind)) {
            if c.kind == Kind::Unloaded {
                out.push_str(&format!(
                    "# not loaded by WordPress, but on disk: {}\n",
                    c.main_file
                ));
            }
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
/// plugins directory, either on disk or inside a `.tar`, `.tar.gz`/`.tgz`
/// or `.zip` file. Archives are read in place, never extracted.
pub fn read(path: &Path) -> Result<Inventory> {
    let (mut inv, kind) = if path.is_dir() {
        (walk(&mut FsTree::new(path)?)?, SourceKind::Directory)
    } else if path.is_file() {
        let mut warnings = Vec::new();
        let mut tree = ArchiveTree::open(path, &mut warnings)?;
        let mut inv = walk(&mut tree)?;
        warnings.append(&mut inv.warnings);
        inv.warnings = warnings;
        (inv, SourceKind::Archive)
    } else {
        return Err(Error::Inventory(format!("{}: not found", path.display())));
    };
    inv.source.path = path.display().to_string();
    inv.source.kind = kind;
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
        let read = match std::fs::read_dir(self.root.join(dir)) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                warnings.push(format!(
                    "{}: could not list this directory ({e}), so nothing inside it was checked. \
                     Run inventory as a user that can read wp-content (for example the web \
                     server user).",
                    display_dir(dir)
                ));
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for entry in read.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                warnings.push(format!(
                    "{}: file name is not valid UTF-8, so it was skipped and not checked. \
                     Rename it to plain UTF-8 (WordPress plugin and theme names always are).",
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
                    Ok(target) => {
                        warnings.push(format!(
                            "{}: symlink leads outside the scanned tree (to {}), so it was not \
                             followed: a link must not pull in files from elsewhere. If it is a \
                             real plugin or theme, run inventory on that directory too.",
                            join(dir, &name),
                            target.display()
                        ));
                        continue;
                    }
                    Err(_) => {
                        warnings.push(format!(
                            "{}: broken symlink (its target does not exist), skipped. \
                             WordPress cannot load it either; delete it.",
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
                Err(e) => warnings.push(unreadable(p, &e)),
            }
        }
        out
    }
}

/// Most entries an archive may have
pub const MAX_ARCHIVE_ENTRIES: usize = 500_000;

/// Most uncompressed bytes a tar archive may declare (it is streamed twice)
pub const MAX_ARCHIVE_BYTES: u64 = 16 << 30;

#[derive(Debug, Clone, Copy)]
enum ArchiveFormat {
    Tar,
    TarGz,
    Zip,
}

/// The structure of an archive, read without extracting it. File heads
/// are loaded on demand: tar archives are streamed again, zip entries are
/// read directly.
struct ArchiveTree {
    path: PathBuf,
    format: ArchiveFormat,
    /// Directory -> its entries (name -> is_dir)
    dirs: HashMap<String, std::collections::BTreeMap<String, bool>>,
    /// Zip entry index for each file path
    zip_index: HashMap<String, usize>,
}

/// Why an archive entry was skipped
enum Skip {
    Unsafe,
    NotUtf8,
    Link,
}

/// A safe relative path for an archive entry: `\` counts as a separator,
/// `.` and empty parts are dropped, and absolute paths, drive letters and
/// `..` are refused. `Some("")` is the archive root.
fn clean_entry_path(raw: &[u8]) -> std::result::Result<String, Skip> {
    let s = std::str::from_utf8(raw).map_err(|_| Skip::NotUtf8)?;
    let s = s.replace('\\', "/");
    if s.starts_with('/') || s.as_bytes().get(1) == Some(&b':') {
        return Err(Skip::Unsafe);
    }
    let mut parts = Vec::new();
    for part in s.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(Skip::Unsafe),
            p => parts.push(p),
        }
    }
    Ok(parts.join("/"))
}

impl ArchiveTree {
    fn open(path: &Path, warnings: &mut Vec<String>) -> Result<Self> {
        let err = |e: &dyn std::fmt::Display| Error::Inventory(format!("{}: {e}", path.display()));
        let mut magic = [0u8; 512];
        let mut f = std::fs::File::open(path).map_err(|e| err(&e))?;
        let n = read_up_to(&mut f, &mut magic).map_err(|e| err(&e))?;
        let magic = &magic[..n];
        let format = if magic.starts_with(&[0x1f, 0x8b]) {
            ArchiveFormat::TarGz
        } else if magic.starts_with(b"PK\x03\x04") || magic.starts_with(b"PK\x05\x06") {
            ArchiveFormat::Zip
        } else if is_tar_header(magic) {
            ArchiveFormat::Tar
        } else {
            return Err(err(&"not a directory, .tar, .tar.gz or .zip file"));
        };
        let mut tree = Self {
            path: path.to_path_buf(),
            format,
            dirs: HashMap::new(),
            zip_index: HashMap::new(),
        };
        let mut skipped: Vec<(Skip, String)> = Vec::new();
        match format {
            ArchiveFormat::Zip => {
                let mut zip = zip::ZipArchive::new(f).map_err(|e| err(&e))?;
                if zip.len() > MAX_ARCHIVE_ENTRIES {
                    return Err(err(&format!(
                        "more than {MAX_ARCHIVE_ENTRIES} entries, refusing to read"
                    )));
                }
                for i in 0..zip.len() {
                    let entry = zip.by_index_raw(i).map_err(|e| err(&e))?;
                    let raw = entry.name_raw().to_vec();
                    let (is_dir, is_link) = (entry.is_dir(), entry.is_symlink());
                    drop(entry);
                    tree.add(i, &raw, is_dir, is_link, &mut skipped);
                }
            }
            ArchiveFormat::Tar | ArchiveFormat::TarGz => {
                let mut archive = tar::Archive::new(tree.tar_reader()?);
                let (mut count, mut bytes) = (0usize, 0u64);
                for entry in archive.entries().map_err(|e| err(&e))? {
                    let entry = entry.map_err(|e| err(&e))?;
                    count += 1;
                    bytes = bytes.saturating_add(entry.size());
                    if count > MAX_ARCHIVE_ENTRIES || bytes > MAX_ARCHIVE_BYTES {
                        return Err(err(&format!(
                            "more than {MAX_ARCHIVE_ENTRIES} entries or {} GiB, refusing to read",
                            MAX_ARCHIVE_BYTES >> 30
                        )));
                    }
                    use tar::EntryType as T;
                    let (is_dir, is_link) = match entry.header().entry_type() {
                        T::Regular | T::Continuous => (false, false),
                        T::Directory => (true, false),
                        T::Symlink | T::Link => (false, true),
                        _ => continue,
                    };
                    tree.add(count, &entry.path_bytes(), is_dir, is_link, &mut skipped);
                }
            }
        }
        for (what, label) in [
            (
                Skip::Unsafe,
                "with unsafe paths (absolute, a drive letter, or ..). Normal tar and zip tools \
                 do not create these, so the archive may have been tampered with. Nothing \
                 outside it was touched, but check where the archive came from",
            ),
            (
                Skip::NotUtf8,
                "whose names are not valid UTF-8, so they were not checked. Recreate the \
                 archive on a system with UTF-8 file names",
            ),
            (
                Skip::Link,
                "that are links, which are not followed inside archives. If a plugin or theme \
                 is a symlink on the server, run inventory on the server directory instead",
            ),
        ] {
            let hits: Vec<&String> = skipped
                .iter()
                .filter(|(s, _)| std::mem::discriminant(s) == std::mem::discriminant(&what))
                .map(|(_, p)| p)
                .collect();
            if let Some(first) = hits.first() {
                warnings.push(format!(
                    "{}: skipped {} entr{} (e.g. {first}) {label}.",
                    path.display(),
                    hits.len(),
                    if hits.len() == 1 { "y" } else { "ies" }
                ));
            }
        }
        Ok(tree)
    }

    fn tar_reader(&self) -> Result<Box<dyn Read>> {
        let f = std::fs::File::open(&self.path)
            .map_err(|e| Error::Inventory(format!("{}: {e}", self.path.display())))?;
        let f = std::io::BufReader::new(f);
        Ok(match self.format {
            ArchiveFormat::TarGz => Box::new(flate2::read::MultiGzDecoder::new(f)),
            _ => Box::new(f),
        })
    }

    /// Record one entry and all its parent directories
    fn add(
        &mut self,
        index: usize,
        raw: &[u8],
        is_dir: bool,
        is_link: bool,
        skipped: &mut Vec<(Skip, String)>,
    ) {
        let shown = || String::from_utf8_lossy(raw).into_owned();
        let path = match clean_entry_path(raw) {
            Ok(p) if p.is_empty() => return,
            Ok(_) if is_link => return skipped.push((Skip::Link, shown())),
            Ok(p) => p,
            Err(why) => return skipped.push((why, shown())),
        };
        if !is_dir {
            self.zip_index.insert(path.clone(), index);
        }
        let mut child = path.as_str();
        let mut child_is_dir = is_dir;
        loop {
            let (parent, name) = child.rsplit_once('/').unwrap_or(("", child));
            let entries = self.dirs.entry(parent.to_string()).or_default();
            let known = entries.insert(name.to_string(), child_is_dir).is_some();
            if parent.is_empty() || (known && child_is_dir) {
                break;
            }
            child = parent;
            child_is_dir = true;
        }
    }
}

/// Is this a tar header block? Old v7 archives have no `ustar` magic, so
/// check the header checksum (the sum of all bytes, with the checksum
/// field itself counted as spaces).
fn is_tar_header(block: &[u8]) -> bool {
    let Some(block) = block.get(..512) else {
        return false;
    };
    let field = String::from_utf8_lossy(&block[148..156]);
    let Ok(stored) = u32::from_str_radix(field.trim_matches([' ', '\0']), 8) else {
        return false;
    };
    let sum: u32 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                b as u32
            }
        })
        .sum();
    stored == sum
}

/// Fill `buf` as far as the reader allows
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

impl Tree for ArchiveTree {
    fn list(&mut self, dir: &str, _warnings: &mut Vec<String>) -> Vec<Entry> {
        self.dirs
            .get(dir)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(name, &is_dir)| Entry {
                        name: name.clone(),
                        is_dir,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn heads(&mut self, paths: &[String], warnings: &mut Vec<String>) -> HashMap<String, Vec<u8>> {
        let mut out = HashMap::new();
        let wanted: std::collections::HashSet<&str> = paths.iter().map(String::as_str).collect();
        let fail = |warnings: &mut Vec<String>, e: &dyn std::fmt::Display| {
            warnings.push(format!("{}: {e}", self.path.display()));
        };
        match self.format {
            ArchiveFormat::Zip => {
                let f = match std::fs::File::open(&self.path) {
                    Ok(f) => f,
                    Err(e) => {
                        fail(warnings, &e);
                        return out;
                    }
                };
                let mut zip = match zip::ZipArchive::new(f) {
                    Ok(z) => z,
                    Err(e) => {
                        fail(warnings, &e);
                        return out;
                    }
                };
                for p in paths {
                    let Some(&i) = self.zip_index.get(p) else {
                        continue;
                    };
                    let mut buf = Vec::new();
                    match zip
                        .by_index(i)
                        .map_err(std::io::Error::other)
                        .and_then(|f| f.take(HEAD_LEN as u64).read_to_end(&mut buf))
                    {
                        Ok(_) => {
                            out.insert(p.clone(), buf);
                        }
                        Err(e) => warnings.push(unreadable(p, &e)),
                    }
                }
            }
            ArchiveFormat::Tar | ArchiveFormat::TarGz => {
                let reader = match self.tar_reader() {
                    Ok(r) => r,
                    Err(e) => {
                        fail(warnings, &e);
                        return out;
                    }
                };
                let mut archive = tar::Archive::new(reader);
                let entries = match archive.entries() {
                    Ok(e) => e,
                    Err(e) => {
                        fail(warnings, &e);
                        return out;
                    }
                };
                for entry in entries {
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => {
                            fail(warnings, &e);
                            break;
                        }
                    };
                    if !matches!(
                        entry.header().entry_type(),
                        tar::EntryType::Regular | tar::EntryType::Continuous
                    ) {
                        continue;
                    }
                    let Ok(path) = clean_entry_path(&entry.path_bytes()) else {
                        continue;
                    };
                    if !wanted.contains(path.as_str()) {
                        continue;
                    }
                    let mut buf = Vec::new();
                    match entry.take(HEAD_LEN as u64).read_to_end(&mut buf) {
                        Ok(_) => {
                            out.insert(path, buf);
                        }
                        Err(e) => warnings.push(unreadable(&path, &e)),
                    }
                    if out.len() == wanted.len() {
                        break;
                    }
                }
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
            let known = only.name == "plugins" || only.name == "wp-content";
            if known
                || !tree
                    .list(&child, warnings)
                    .iter()
                    .any(|e| !e.is_dir && e.name.ends_with(".php") && e.name != "index.php")
            {
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
    let mut folders: Vec<(String, Vec<Entry>)> = Vec::new();
    let mut archives = Vec::new();
    let mut nested_files: Vec<(String, String, String)> = Vec::new(); // (folder, slug, file)
    let mut readmes: HashMap<String, String> = HashMap::new(); // plugin dir -> readme.txt
    for e in tree.list(&plugins_dir, &mut warnings) {
        if e.name.starts_with('.') {
            continue;
        }
        if e.is_dir {
            let entries = tree.list(&join(&plugins_dir, &e.name), &mut warnings);
            if let Some(r) = find_readme(&entries) {
                readmes.insert(e.name.clone(), format!("{}/{r}", e.name));
            }
            for f in &entries {
                if !f.is_dir && !f.name.starts_with('.') && f.name.ends_with(".php") {
                    plugin_files.push((e.name.clone(), format!("{}/{}", e.name, f.name)));
                }
            }
            // A folder without PHP of its own may hold plugin copies one level down
            let holds_php = entries
                .iter()
                .any(|f| !f.is_dir && !f.name.starts_with('.') && f.name.ends_with(".php"));
            if !holds_php && e.name != "__MACOSX" {
                for sub in entries
                    .iter()
                    .filter(|f| f.is_dir && !f.name.starts_with('.'))
                {
                    let sub_dir = format!("{}/{}", e.name, sub.name);
                    let sub_entries = tree.list(&join(&plugins_dir, &sub_dir), &mut warnings);
                    if let Some(r) = find_readme(&sub_entries) {
                        readmes.insert(sub_dir.clone(), format!("{sub_dir}/{r}"));
                    }
                    for f in sub_entries {
                        if !f.is_dir && !f.name.starts_with('.') && f.name.ends_with(".php") {
                            nested_files.push((
                                e.name.clone(),
                                sub.name.clone(),
                                format!("{sub_dir}/{}", f.name),
                            ));
                        }
                    }
                }
            }
            folders.push((e.name, entries));
        } else if e.name.ends_with(".php") {
            let slug = e.name.trim_end_matches(".php").to_string();
            plugin_files.push((slug, e.name.clone()));
        } else if is_archive_name(&e.name) {
            archives.push(e.name);
        }
    }
    if !archives.is_empty() {
        warnings.push(format!(
            "{}: {} archive file{} ({}) not scanned. WordPress ignores archive files, but if \
             this directory is reachable over the web anyone can download them. Delete them, \
             or run `inventory` on one to scan what it contains.",
            display_dir(&plugins_dir),
            archives.len(),
            if archives.len() == 1 { "" } else { "s" },
            preview(&archives)
        ));
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
            let entries = tree.list(&join(&themes_dir, &e.name), &mut warnings);
            if entries.iter().any(|f| !f.is_dir && f.name == "style.css") {
                theme_dirs.push(e.name);
                continue;
            }
            // search_theme_directories() also accepts themes one level down
            let mut nested = Vec::new();
            for sub in entries
                .iter()
                .filter(|f| f.is_dir && !f.name.starts_with('.'))
            {
                let sub_dir = format!("{}/{}", e.name, sub.name);
                if tree
                    .list(&join(&themes_dir, &sub_dir), &mut warnings)
                    .iter()
                    .any(|f| !f.is_dir && f.name == "style.css")
                {
                    nested.push(sub_dir);
                }
            }
            if nested.is_empty() {
                warnings.push(format!(
                    "{}: no style.css, so WordPress does not list it as a theme and it is not \
                     scanned. Probably a leftover of a removed theme; check and delete it.",
                    join(&themes_dir, &e.name)
                ));
            } else {
                warnings.push(format!(
                    "{}: no style.css of its own, but WordPress also looks one level deeper and \
                     loads the theme{} found there ({}), usually the result of unzipping a theme \
                     into a folder of the same name. {} inventoried and scanned under the inner \
                     folder name; reinstalling at themes/<name> avoids the extra level.",
                    join(&themes_dir, &e.name),
                    if nested.len() == 1 { "" } else { "s" },
                    preview(&nested),
                    if nested.len() == 1 {
                        "It is"
                    } else {
                        "They are"
                    }
                ));
                theme_dirs.extend(nested);
            }
        }
    }

    let core_file = join(&base, "wp-includes/version.php");
    let mut wanted: Vec<String> = plugin_files
        .iter()
        .map(|(_, f)| f)
        .chain(nested_files.iter().map(|(_, _, f)| f))
        .chain(readmes.values())
        .map(|f| join(&plugins_dir, f))
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
    let readme_for = |file: &str| {
        file.rsplit_once('/')
            .and_then(|(dir, _)| readmes.get(dir))
            .map(String::as_str)
    };
    let mut components = Vec::new();

    // Plugins: every file with a Plugin Name header counts, as in get_plugins()
    let mut found_in: HashMap<&str, Vec<&str>> = HashMap::new();
    for (slug, file) in &plugin_files {
        let path = join(&plugins_dir, file);
        let Some(bytes) = head(&path) else { continue };
        let h = plugin_headers.parse(bytes);
        let Some(name) = h.get("Plugin Name") else {
            if !file.contains('/') && file != "index.php" {
                warnings.push(format!(
                    "{path}: .php file without a Plugin Name header, so WordPress does not load \
                     it as a plugin and it is not scanned. Unless another plugin includes it, it \
                     is a leftover and can be removed."
                ));
            }
            continue;
        };
        if file.contains('/') {
            found_in.entry(slug).or_default().push(file);
        }
        let mut c = component(Kind::Plugin, slug, name, file, &h);
        let readme = readme_for(file).map(|r| join(&plugins_dir, r));
        settle_version(&mut c, &path, readme.as_deref(), &head, &mut warnings);
        components.push(c);
    }
    // Plugin copies inside folders WordPress does not load
    let mut nested_in: HashMap<&str, Vec<String>> = HashMap::new();
    for (folder, slug, file) in &nested_files {
        let path = join(&plugins_dir, file);
        let Some(bytes) = head(&path) else { continue };
        let h = plugin_headers.parse(bytes);
        let Some(name) = h.get("Plugin Name") else {
            continue;
        };
        let mut c = component(Kind::Unloaded, slug, name, file, &h);
        let readme = readme_for(file).map(|r| join(&plugins_dir, r));
        settle_version(&mut c, &path, readme.as_deref(), &head, &mut warnings);
        let version = c.version.as_deref().unwrap_or("no version");
        nested_in
            .entry(folder)
            .or_default()
            .push(format!("{slug} = {name} {version}"));
        components.push(c);
    }

    for (folder, entries) in &folders {
        let path = join(&plugins_dir, folder);
        let php = entries
            .iter()
            .filter(|e| !e.is_dir && !e.name.starts_with('.') && e.name.ends_with(".php"))
            .count();
        match found_in.get(folder.as_str()).map(Vec::as_slice) {
            None if folder == "__MACOSX" => warnings.push(format!(
                "{path}: macOS archive metadata (left behind when a zip made on a Mac is \
                 unpacked), not code. WordPress ignores it; it is safe to delete."
            )),
            None if nested_in.contains_key(folder.as_str()) => {
                let found = &nested_in[folder.as_str()];
                warnings.push(format!(
                    "{path}: not a plugin itself, but it holds {} plugin cop{} WordPress does \
                     not load ({}). The files are still on disk, and if this folder is reachable \
                     over the web the PHP can be requested directly, so each copy is inventoried \
                     as type \"unloaded\" and scanned. Delete the folder if it only holds old \
                     copies.",
                    found.len(),
                    if found.len() == 1 { "y" } else { "ies" },
                    preview(found)
                ));
            }
            None if php == 0 => {
                let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
                warnings.push(format!(
                    "{path}: no .php file at its top level ({}), so WordPress does not load it as \
                     a plugin and it is not scanned. If it is left over from a removed plugin, \
                     delete it; if it is other data, keep it outside the web root.",
                    if names.is_empty() {
                        "the folder is empty".to_string()
                    } else {
                        format!("it holds {}", preview(&names))
                    }
                ));
            }
            None => warnings.push(format!(
                "{path}: {php} .php file{} at its top level but none with a Plugin Name header, so \
                 WordPress does not load it as a plugin and it is not scanned. It may be a \
                 partial upload or a damaged copy; compare it with the original plugin.",
                if php == 1 { "" } else { "s" }
            )),
            Some([_]) => {}
            Some(files) => warnings.push(format!(
                "{path}: {} files have a Plugin Name header ({}). WordPress lists each as a \
                 separate plugin, so each is inventoried and scanned under the slug {folder}.",
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
            warnings.push(format!(
                "{path}: no Theme Name header, so WordPress lists it as a broken theme and it is \
                 not scanned. Reinstall the theme or delete the folder."
            ));
            continue;
        };
        if !h.contains_key("Version") {
            warnings.push(no_version(&path, "theme"));
        }
        let slug = dir.rsplit('/').next().unwrap_or(dir);
        let mut c = component(Kind::Theme, slug, name, &format!("{dir}/style.css"), &h);
        c.uri = h.get("Theme URI").cloned();
        c.parent = h
            .get("Template")
            .filter(|t| *t != dir && *t != slug)
            .cloned();
        components.push(c);
    }
    for c in components.iter().filter(|c| c.kind == Kind::Theme) {
        let installed = |p: &str| {
            theme_dirs
                .iter()
                .any(|d| d == p || d.rsplit('/').next() == Some(p))
        };
        if let Some(ref parent) = c.parent
            && !installed(parent)
        {
            warnings.push(format!(
                "{}: child theme of \"{parent}\", which is not installed. WordPress shows it as \
                 broken and cannot use it; install the parent theme or delete the child. The \
                 child itself is still scanned.",
                join(
                    &content,
                    &format!("themes/{}", c.main_file.trim_end_matches("/style.css"))
                )
            ));
        }
    }

    let core = (layout == Layout::Wordpress).then(|| {
        let version = head(&core_file).and_then(core_version);
        if version.is_none() {
            warnings.push(format!(
                "{core_file}: no $wp_version found, so the WordPress version is unknown and core \
                 is not scanned. The file may have been modified; compare it with a clean \
                 WordPress download, or check the version in wp-admin."
            ));
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

/// Warning for a plugin or theme without a usable version
fn no_version(path: &str, what: &str) -> String {
    let tried = if what == "plugin" {
        "no Version header and no readme.txt Stable tag"
    } else {
        "no Version header"
    };
    format!(
        "{path}: {tried}, so the installed version is unknown. The scan cannot compare it \
         with vulnerable version ranges and will list it as not checked. A {what} without a \
         version is usually custom code: review it by hand, or look up the version in wp-admin."
    )
}

/// `readme.txt` in a plugin folder, matched case-insensitively
fn find_readme(entries: &[Entry]) -> Option<&str> {
    entries
        .iter()
        .find(|e| !e.is_dir && e.name.eq_ignore_ascii_case("readme.txt"))
        .map(|e| e.name.as_str())
}

/// `Stable tag:` from a wordpress.org style readme.txt; `trunk` means none
fn stable_tag(bytes: &[u8]) -> Option<String> {
    let re = Regex::new(r"(?mi)^[ \t*=#]*Stable tag:[ \t]*([^\s]+)").expect("valid regex");
    re.captures(&file_data(bytes))
        .map(|c| c[1].to_string())
        .filter(|v| !v.eq_ignore_ascii_case("trunk"))
}

/// Keep the header version; without one, fall back to readme.txt and say
/// so, or warn that the version is unknown
fn settle_version<'a>(
    c: &mut Component,
    path: &str,
    readme: Option<&str>,
    head: &impl Fn(&str) -> Option<&'a [u8]>,
    warnings: &mut Vec<String>,
) {
    if c.version.is_some() {
        return;
    }
    match readme.and_then(|r| head(r).and_then(stable_tag).map(|v| (r, v))) {
        Some((readme, tag)) => {
            warnings.push(format!(
                "{path}: no Version header, so the version {tag} was taken from \"Stable tag\" \
                 in {readme}. A readme usually matches the code it ships with, but it can be \
                 edited separately, so confirm the version in wp-admin before acting on \
                 findings for this plugin."
            ));
            c.version = Some(tag);
            c.version_source = Some(VersionSource::Readme);
        }
        None => warnings.push(no_version(path, "plugin")),
    }
}

/// Warning for a file whose headers could not be read
fn unreadable(path: &str, e: &dyn std::fmt::Display) -> String {
    format!(
        "{path}: could not be read ({e}), so its headers were not checked and whatever it \
         declares is missing from this inventory. Run inventory as a user that can read \
         wp-content (for example the web server user), or re-copy the file."
    )
}

/// Up to three names, then how many more: `a, b, c and 4 more`
fn preview(names: &[String]) -> String {
    let shown = names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    match names.len() {
        0..=3 => shown,
        n => format!("{shown} and {} more", n - 3),
    }
}

/// Root-relative directory for messages
fn display_dir(dir: &str) -> &str {
    if dir.is_empty() { "top level" } else { dir }
}

/// File names that look like archives someone left behind
fn is_archive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".zst", ".bz2", ".xz",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
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
        version_source: h.get("Version").map(|_| VersionSource::Header),
    }
}

/// How to run WP-CLI for [`enrich_with_wp_cli`]
#[derive(Debug, Clone)]
pub struct WpCli {
    /// The `wp` executable
    pub program: PathBuf,
    /// WordPress root (`--path`); WP-CLI's own lookup when `None`
    pub path: Option<PathBuf>,
    /// Pass `--allow-root` (WP-CLI refuses to run as root otherwise)
    pub allow_root: bool,
}

impl Default for WpCli {
    fn default() -> Self {
        Self {
            program: PathBuf::from("wp"),
            path: None,
            allow_root: false,
        }
    }
}

/// One row of `wp plugin list --format=json` / `wp theme list --format=json`
#[derive(Debug, Deserialize)]
struct WpCliItem {
    name: String,
    status: Option<String>,
    version: Option<String>,
    update_version: Option<String>,
}

/// Merge `status` and `update_version` from WP-CLI, which reads the
/// WordPress database and so knows what files alone cannot (active or
/// not). Files stay the source of truth for versions: a disagreement is a
/// warning, and a component WP-CLI lists that the files lacked is added
/// with a warning. Any failure is a warning, never an error; the native
/// inventory is still complete without WP-CLI.
pub fn enrich_with_wp_cli(inv: &mut Inventory, wp: &WpCli) {
    let mut any = false;
    for (what, kinds) in [
        ("plugin", &[Kind::Plugin, Kind::MuPlugin, Kind::Dropin][..]),
        ("theme", &[Kind::Theme][..]),
    ] {
        let items = match run_wp_cli(wp, what) {
            Ok(items) => items,
            Err(e) => {
                inv.warnings.push(format!(
                    "wp {what} list failed, keeping file data only ({e}). The inventory is \
                     still complete, only {what} status and available updates are missing. \
                     Check that `wp {what} list` works here; pass --wp-path for a different \
                     directory, or --allow-root when running as root."
                ));
                continue;
            }
        };
        any = true;
        for item in items {
            let blank = |v: Option<String>| v.filter(|s| !s.is_empty());
            let (status, update) = (blank(item.status), blank(item.update_version));
            let version = blank(item.version);
            let found = inv.components.iter_mut().find(|c| {
                kinds.contains(&c.kind) && (c.slug == item.name || c.main_file == item.name)
            });
            match found {
                Some(c) => {
                    if c.version.is_some() && version.is_some() && c.version != version {
                        inv.warnings.push(format!(
                            "{what} {}: files say version {}, WP-CLI says {}. WP-CLI reads \
                             the same headers, so it probably looked at a different copy of \
                             the site (check --wp-path). The version from the files is used.",
                            c.slug,
                            c.version.as_deref().unwrap_or_default(),
                            version.as_deref().unwrap_or_default()
                        ));
                    }
                    c.status = status;
                    c.update_version = update;
                }
                None => {
                    inv.warnings.push(format!(
                        "{what} {}: listed by WP-CLI but not found in the files, so WP-CLI \
                         probably looked at a different copy of the site (check --wp-path). \
                         Added with WP-CLI's version so it is still scanned.",
                        item.name
                    ));
                    let kind = match (what, status.as_deref()) {
                        ("theme", _) => Kind::Theme,
                        (_, Some("must-use")) => Kind::MuPlugin,
                        (_, Some("dropin")) => Kind::Dropin,
                        _ => Kind::Plugin,
                    };
                    let mut c = component(kind, &item.name, &item.name, "", &HashMap::new());
                    c.version_source = version.as_ref().map(|_| VersionSource::WpCli);
                    c.version = version;
                    c.status = status;
                    c.update_version = update;
                    inv.components.push(c);
                }
            }
        }
    }
    inv.source.wp_cli = any;
}

fn run_wp_cli(wp: &WpCli, what: &str) -> std::result::Result<Vec<WpCliItem>, String> {
    let mut cmd = std::process::Command::new(&wp.program);
    cmd.args([what, "list", "--format=json"]);
    if let Some(ref path) = wp.path {
        cmd.arg(format!("--path={}", path.display()));
    }
    if wp.allow_root {
        cmd.arg("--allow-root");
    }
    let out = cmd
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", wp.program.display()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        return Err(format!("{} {first}", out.status));
    }
    // WP-CLI may print PHP notices before the JSON
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json = stdout.find('[').map_or("", |i| &stdout[i..]);
    serde_json::from_str(json).map_err(|e| format!("unexpected output: {e}"))
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
