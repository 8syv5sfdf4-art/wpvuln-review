//! Moving a database to an air-gapped machine
//!
//! `export` packs a verified database into one `.tar.gz` with a
//! `MANIFEST.json` listing every file's sha256. `import` unpacks such a
//! bundle into a temporary directory next to the target, checks it against
//! the manifest and with [`db::verify`], and only then
//! swaps it in, keeping the previous database as a backup.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::archive::clean_entry_path;
use crate::db;
use crate::error::{Error, Result};

const MANIFEST: &str = "MANIFEST.json";

/// Manifest format, bumped on incompatible changes
pub const MANIFEST_FORMAT: u32 = 1;

/// Most files a bundle may hold
const MAX_FILES: usize = 200_000;
/// Largest single file in a bundle
const MAX_FILE_BYTES: u64 = 32 << 20;
/// Most bytes a bundle may unpack to
const MAX_TOTAL_BYTES: u64 = 4 << 30;

/// `MANIFEST.json` inside a bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format ([`MANIFEST_FORMAT`])
    pub format: u32,
    /// Database format of the packed files
    pub db_format: u32,
    /// When the bundle was made (UTC, ISO 8601)
    pub created_at: String,
    /// Every packed file but the manifest, with its sha256
    pub files: BTreeMap<String, String>,
}

/// What `import` did
#[derive(Debug, Clone)]
pub struct Imported {
    /// Files unpacked and checked
    pub files: usize,
    /// Where the previous database was moved, if there was one
    pub backup: Option<PathBuf>,
}

fn bad(what: impl std::fmt::Display) -> Error {
    Error::Database(what.to_string())
}

/// Every file under `dir`, relative and `/`-separated, sorted
fn files_under(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for entry in std::fs::read_dir(dir.join(&rel))? {
            let entry = entry?;
            let path = rel.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else {
                out.push(path.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Pack the database at `dir` into `out` (`.tar.gz`). Refuses a database
/// that does not pass [`db::verify`], so a bundle is always trustworthy.
pub fn export(dir: &Path, out: &Path) -> Result<Manifest> {
    let check = db::verify(dir, &[]);
    if !check.problems.is_empty() {
        return Err(bad(format!(
            "{} does not pass `db verify`, so it is not exported:\n  {}",
            dir.display(),
            check.problems.join("\n  ")
        )));
    }
    let mut files = BTreeMap::new();
    for rel in files_under(dir)? {
        if rel == MANIFEST {
            continue;
        }
        files.insert(rel.clone(), db::sha256_hex(&std::fs::read(dir.join(&rel))?));
    }
    let manifest = Manifest {
        format: MANIFEST_FORMAT,
        db_format: db::FORMAT_VERSION,
        created_at: crate::analyze::chrono_lite_now(),
        files,
    };

    let tmp = out.with_extension("tmp");
    let gz =
        flate2::write::GzEncoder::new(std::fs::File::create(&tmp)?, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    let mut add = |name: &str, bytes: &[u8]| -> std::io::Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        tar.append_data(&mut h, name, bytes)
    };
    add(
        MANIFEST,
        serde_json::to_string_pretty(&manifest)?.as_bytes(),
    )?;
    for rel in manifest.files.keys() {
        add(rel, &std::fs::read(dir.join(rel))?)?;
    }
    tar.into_inner()?.finish()?;
    std::fs::rename(&tmp, out)?;
    Ok(manifest)
}

/// Unpack `bundle` and replace the database at `dir` with it, only if every
/// file matches the manifest and the result passes [`db::verify`]. On any
/// failure the existing database is left untouched.
pub fn import(bundle: &Path, dir: &Path) -> Result<Imported> {
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = dir
        .file_name()
        .ok_or_else(|| bad(format!("{}: not a directory name", dir.display())))?
        .to_string_lossy();
    let staging = parent.join(format!(".{name}.import-{}", std::process::id()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    let result = unpack_and_check(bundle, &staging);
    let files = match result {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };

    let backup = if dir.exists() {
        let stamp = crate::analyze::chrono_lite_now().replace(':', "");
        let backup = parent.join(format!("{name}.bak-{stamp}"));
        std::fs::rename(dir, &backup)?;
        Some(backup)
    } else {
        None
    };
    if let Err(e) = std::fs::rename(&staging, dir) {
        // Put the old database back rather than leave none
        if let Some(ref b) = backup {
            let _ = std::fs::rename(b, dir);
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e.into());
    }
    Ok(Imported { files, backup })
}

fn unpack_and_check(bundle: &Path, staging: &Path) -> Result<usize> {
    let what = |e: &dyn std::fmt::Display| bad(format!("{}: {e}", bundle.display()));
    let file = std::fs::File::open(bundle).map_err(|e| what(&e))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(std::io::BufReader::new(file)));
    let (mut count, mut total) = (0usize, 0u64);
    for entry in tar.entries().map_err(|e| what(&e))? {
        let mut entry = entry.map_err(|e| what(&e))?;
        let raw = entry.path_bytes().into_owned();
        let shown = String::from_utf8_lossy(&raw).into_owned();
        match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => {}
            tar::EntryType::Directory => continue,
            _ => {
                return Err(what(&format!(
                    "{shown}: not a regular file; a database bundle holds only files, so this \
                     one was not made by `db export`"
                )));
            }
        }
        let rel = clean_entry_path(&raw)
            .ok()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| what(&format!("{shown}: unsafe path, refusing the whole bundle")))?;
        count += 1;
        total = total.saturating_add(entry.size());
        // A Wordfence feed is far larger than any single record
        let file_cap = if rel.starts_with(&format!("{}/", crate::wordfence_db::DIR)) {
            crate::wordfence_db::DEFAULT_MAX_BYTES
        } else {
            MAX_FILE_BYTES
        };
        if count > MAX_FILES || entry.size() > file_cap || total > MAX_TOTAL_BYTES {
            return Err(what(
                &"larger than any database bundle should be, refusing it",
            ));
        }
        let dest = staging.join(&rel);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut bytes = Vec::new();
        entry.by_ref().take(file_cap + 1).read_to_end(&mut bytes)?;
        std::fs::write(dest, bytes)?;
    }

    let manifest: Manifest = std::fs::read_to_string(staging.join(MANIFEST))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or_else(|| {
            what(&"no readable MANIFEST.json, so it was not made by `db export`; refusing it")
        })?;
    if manifest.format > MANIFEST_FORMAT || manifest.db_format > db::FORMAT_VERSION {
        return Err(what(
            &"made by a newer version of this tool; use that version to import it",
        ));
    }
    let present: Vec<String> = files_under(staging)?
        .into_iter()
        .filter(|f| f != MANIFEST)
        .collect();
    for f in &present {
        match manifest.files.get(f) {
            None => {
                return Err(what(&format!(
                    "{f}: not listed in the manifest, refusing the bundle"
                )));
            }
            Some(sum) if *sum != db::sha256_hex(&std::fs::read(staging.join(f))?) => {
                return Err(what(&format!(
                    "{f}: does not match the manifest (sha256), so the bundle was damaged or \
                     changed in transit; refusing it"
                )));
            }
            Some(_) => {}
        }
    }
    if let Some(f) = manifest.files.keys().find(|f| !present.contains(f)) {
        return Err(what(&format!(
            "{f}: listed in the manifest but missing, refusing the bundle"
        )));
    }
    let check = db::verify(staging, &[]);
    if !check.problems.is_empty() {
        return Err(what(&format!(
            "the unpacked database does not pass `db verify`:\n  {}",
            check.problems.join("\n  ")
        )));
    }
    Ok(present.len())
}
