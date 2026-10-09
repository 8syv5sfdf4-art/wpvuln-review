//! Path safety shared by everything that reads untrusted archives
//! (inventory input, database import)

/// Why an archive entry was skipped
pub(crate) enum Skip {
    Unsafe,
    NotUtf8,
    Link,
}

/// A safe relative path for an archive entry: `\` counts as a separator,
/// `.` and empty parts are dropped, and absolute paths, drive letters and
/// `..` are refused. `Some("")` is the archive root.
pub(crate) fn clean_entry_path(raw: &[u8]) -> std::result::Result<String, Skip> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_paths() {
        let ok = |p: &str| clean_entry_path(p.as_bytes()).ok();
        assert_eq!(ok("./plugins/a.php").as_deref(), Some("plugins/a.php"));
        assert_eq!(
            ok("site\\plugins\\a.php").as_deref(),
            Some("site/plugins/a.php")
        );
        assert_eq!(ok("./").as_deref(), Some(""));
        assert!(ok("../x").is_none());
        assert!(ok("a/../../x").is_none());
        assert!(ok("/etc/passwd").is_none());
        assert!(ok("C:/x").is_none());
        assert!(matches!(clean_entry_path(b"\xff"), Err(Skip::NotUtf8)));
    }
}
