//! Wordfence feeds: parsing both formats, grouping and range matching.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use wordpress_vulnerable_scanner::scanner::ComponentType;
use wordpress_vulnerable_scanner::vulnerability::{Bound, SourceKind, VulnerabilityReport};
use wordpress_vulnerable_scanner::wordfence::{InputFormat, Keep, WordfenceIndex};
use wordpress_vulnerable_scanner::{Severity, Vulnerability};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wordfence")
        .join(name)
}

fn load(name: &str) -> WordfenceIndex {
    WordfenceIndex::load(&fixture(name), &Keep::All).unwrap()
}

/// Which of `vulns` affect `version` (with the matched range applied)
fn affecting(vulns: &[Vulnerability], version: &str) -> Vec<Vulnerability> {
    VulnerabilityReport {
        vulnerabilities: vulns.to_vec(),
    }
    .filter_by_version(Some(version))
    .vulnerabilities
}

use ComponentType::*;

#[test]
fn wpprobe_records_are_grouped_into_one_vulnerability_with_all_ranges() {
    let idx = load("wpprobe-sample.json");
    assert_eq!(idx.format, Some(InputFormat::Wpprobe));
    assert_eq!((idx.records, idx.slugs), (7, 5));
    let woo = idx.lookup(Plugin, "woocommerce").unwrap();
    assert_eq!(woo.len(), 1, "3 records, one vulnerability");
    let v = &woo[0];
    assert_eq!((v.id.as_str(), v.ranges.len()), ("CVE-2025-15033", 3));
    assert_eq!(v.sources, vec![SourceKind::Wordfence]);
    assert_eq!(v.auth.as_deref(), Some("Auth"));
    assert_eq!(
        v.ranges[2].from,
        Bound::Unbounded,
        "0.0.0 means no lower limit"
    );

    // Branch-aware: the 10.3 backport is clean
    assert_eq!(affecting(woo, "10.3.6").len(), 1);
    assert!(affecting(woo, "10.3.7").is_empty());
    assert!(affecting(woo, "10.4.0").is_empty());
    assert_eq!(affecting(woo, "8.0").len(), 1);
    let hit = &affecting(woo, "10.2.1")[0];
    assert_eq!(hit.affected, ">= 10.2.0, <= 10.2.2");
}

#[test]
fn wpprobe_details() {
    let idx = load("wpprobe-sample.json");
    let chaty = &idx.lookup(Plugin, "chaty-pro").unwrap()[0];
    assert_eq!(
        chaty.title,
        "Chaty Pro <= 3.3.7 - Unauthenticated Stored Cross-Site Scripting"
    );
    assert_eq!(
        (chaty.cvss_score, chaty.severity),
        (Some(7.0), Severity::High)
    );
    assert_eq!(chaty.auth.as_deref(), Some("Unauth"));
    assert_eq!(
        chaty.references,
        vec!["https://www.cve.org/CVERecord?id=CVE-2026-73360"]
    );

    // 999999.0.0 means no upper limit
    let every = idx.lookup(Plugin, "everything").unwrap();
    assert_eq!(every[0].ranges[0].to, Bound::Unbounded);
    assert_eq!(affecting(every, "99.9").len(), 1);
    assert_eq!(every[0].severity, Severity::Critical);

    // Core and themes; cvss_score as a string; exclusive bound
    let core = idx.lookup(Core, "wordpress").unwrap();
    assert_eq!(affecting(core, "6.6.1").len(), 1);
    assert!(affecting(core, "6.6.2").is_empty());
    let theme = idx.lookup(Theme, "flatsome").unwrap();
    assert_eq!(theme[0].cvss_score, Some(6.1));
    let hit = &affecting(theme, "3.18.6")[0];
    assert_eq!(hit.fixed_in.as_deref(), Some("3.18.7"));
    assert!(affecting(theme, "3.18.7").is_empty());

    assert!(idx.lookup(Plugin, "akismet").is_none(), "untracked");
    assert!(
        idx.lookup(Plugin, "WooCommerce").is_some(),
        "slugs are case-insensitive"
    );
}

#[test]
fn raw_feed_keeps_what_wpprobe_drops() {
    let idx = load("raw-sample.json");
    assert_eq!(idx.format, Some(InputFormat::WordfenceRaw));
    assert_eq!(idx.records, 4);

    // One record, two software entries: indexed under both slugs
    for slug in ["chaty", "chaty-pro"] {
        let v = &idx.lookup(Plugin, slug).unwrap()[0];
        assert_eq!(v.id, "CVE-2026-73360");
        assert_eq!(v.uuid, "5b9f1b1e-0000-4000-8000-000000000001");
        assert_eq!(v.ranges[0].from, Bound::Unbounded, "* means no limit");
        assert_eq!(v.cwes, vec!["CWE-79"]);
        assert_eq!(v.auth.as_deref(), Some("Unauth"), "from PR:N in the vector");
        assert_eq!(
            v.title,
            "Chaty <= 3.3.7 - Unauthenticated Stored Cross-Site Scripting"
        );
        assert_eq!(
            v.references[0],
            "https://www.cve.org/CVERecord?id=CVE-2026-73360"
        );
        assert_eq!(
            affecting(&idx.lookup(Plugin, slug).unwrap()[..1], "3.3.6")[0]
                .fixed_in
                .as_deref(),
            Some("3.3.8")
        );
    }

    // Without a CVE: kept, identified by its UUID
    let rocket = &idx.lookup(Plugin, "wp-rocket").unwrap()[0];
    assert_eq!(rocket.id, "5b9f1b1e-0000-4000-8000-000000000002");
    assert!(rocket.cves.is_empty());

    // Informational records are marked; branch fixes come from patched_versions
    let woo = idx.lookup(Plugin, "woocommerce").unwrap();
    assert_eq!(woo.len(), 2);
    assert!(woo.iter().any(|v| v.informational));
    let real: Vec<_> = woo.iter().filter(|v| !v.informational).cloned().collect();
    let hit = &affecting(&real, "10.3.6")[0];
    assert_eq!(hit.fixed_in.as_deref(), Some("10.3.7"));
    assert_eq!(hit.fixed_branch.as_deref(), Some("10.3"));
    assert!(affecting(&real, "10.3.7").is_empty());
}

#[test]
fn keep_filters_while_parsing() {
    let only: HashSet<_> = [(Plugin, "woocommerce".to_string())].into();
    let idx = WordfenceIndex::load(&fixture("wpprobe-sample.json"), &Keep::Only(only)).unwrap();
    assert!(idx.lookup(Plugin, "woocommerce").is_some());
    assert!(idx.lookup(Plugin, "chaty-pro").is_none());
    assert_eq!(
        (idx.records, idx.slugs),
        (7, 5),
        "everything is still counted"
    );

    let counted = WordfenceIndex::load(&fixture("raw-sample.json"), &Keep::Count).unwrap();
    assert_eq!((counted.records, counted.vulnerabilities()), (4, 0));
}

#[test]
fn refuses_what_is_not_a_feed() {
    let err = |text: &str| {
        WordfenceIndex::from_reader(text.as_bytes(), &Keep::All)
            .unwrap_err()
            .to_string()
    };
    assert!(err("<!DOCTYPE html><html>Please log in</html>").contains("HTML"));
    assert!(err("").contains("empty"));
    assert!(err("[]").contains("no records"));
    assert!(err("[{\"slug\": \"x\"").contains("not a valid Wordfence feed"));
    assert!(err("Rate limit exceeded").contains("not JSON"));
    // Whitespace and a byte order mark before the JSON are fine
    let ok = "\u{feff}\n  [{\"title\":\"t\",\"slug\":\"s\",\"type\":\"plugin\",\"cve\":\"CVE-1\"}]";
    assert!(WordfenceIndex::from_reader(ok.as_bytes(), &Keep::All).is_ok());
}

/// Run with WPVULN_WORDFENCE_REAL=/path/to/wordfence_vulnerabilities.json
#[test]
#[ignore]
fn real_feed_smoke_test() {
    let path = std::env::var("WPVULN_WORDFENCE_REAL").expect("set WPVULN_WORDFENCE_REAL");
    let started = std::time::Instant::now();
    let idx = WordfenceIndex::load(Path::new(&path), &Keep::All).unwrap();
    let took = started.elapsed();
    println!(
        "{:?}: {} records, {} slugs, {} vulnerabilities in {took:.2?}",
        idx.format,
        idx.records,
        idx.slugs,
        idx.vulnerabilities()
    );
    assert!(idx.records > 10_000);
    let woo = idx.lookup(Plugin, "woocommerce").unwrap();
    let cve = woo.iter().find(|v| v.id == "CVE-2025-15033").unwrap();
    assert!(cve.ranges.len() > 3, "per-branch ranges grouped");
    assert!(affecting(std::slice::from_ref(cve), "10.3.7").is_empty());
    assert!(took.as_secs_f32() < 5.0, "too slow: {took:?}");
}
