# wordpress-vulnerable-scanner

A fast, safe Rust CLI tool for detecting known CVE vulnerabilities in WordPress core, plugins, and themes using the WPVulnerability.net API.

[![Crates.io](https://img.shields.io/crates/v/wordpress-vulnerable-scanner.svg)](https://crates.io/crates/wordpress-vulnerable-scanner)
[![Documentation](https://docs.rs/wordpress-vulnerable-scanner/badge.svg)](https://docs.rs/wordpress-vulnerable-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Multiple input modes** - scan live sites, JSON manifests, or specify components directly
- **Parallel API requests** - fast vulnerability lookups using concurrent requests
- **Version-aware filtering** - only reports vulnerabilities affecting installed versions
- **CVSS scoring** - severity levels (Critical/High/Medium/Low) from CVSS scores
- **Multiple output formats** - human-readable tables or JSON for automation
- **Exit codes** - integrate with CI/CD pipelines
- **Security hardened** - URL encoding, file size limits, safe HTTP defaults

## Installation

### Pre-built binaries

Download from [GitHub Releases](https://github.com/robdotec/wordpress-vulnerable-scanner/releases):

| Platform | Architecture | File |
|----------|--------------|------|
| Linux | x86_64 | `wordpress-vulnerable-scanner-linux-x86_64.tar.gz` |
| Linux | x86_64 (static) | `wordpress-vulnerable-scanner-linux-x86_64-musl.tar.gz` |
| Linux | ARM64 | `wordpress-vulnerable-scanner-linux-aarch64.tar.gz` |
| macOS | Intel | `wordpress-vulnerable-scanner-macos-x86_64.tar.gz` |
| macOS | Apple Silicon | `wordpress-vulnerable-scanner-macos-aarch64.tar.gz` |
| Windows | x86_64 | `wordpress-vulnerable-scanner-windows-x86_64.zip` |

### Cargo

```bash
cargo install wordpress-vulnerable-scanner
```

### Build from source

```bash
git clone https://github.com/robdotec/wordpress-vulnerable-scanner
cd wordpress-vulnerable-scanner
cargo build --release
```

## Quick Start

### Scan a live WordPress site

```bash
wordpress-vulnerable-scanner https://example.com
```

### Scan with auto-detected scheme

```bash
wordpress-vulnerable-scanner example.com
```

### Check specific components

```bash
# Check WordPress core version
wordpress-vulnerable-scanner -c 6.4.1

# Check plugins (slug:version format)
wordpress-vulnerable-scanner -p "elementor:3.18.0,contact-form-7:5.8"

# Check themes
wordpress-vulnerable-scanner -t "flavor:1.3.4,flavor-developer:1.3.4"

# Combined check
wordpress-vulnerable-scanner -c 6.4.1 -p "elementor:3.18.0" -t "flavor:1.3.4"
```

### Use JSON manifest from wordpress-audit

```bash
# First, audit a WordPress installation
wordpress-audit https://example.com -o json > manifest.json

# Then scan for vulnerabilities
wordpress-vulnerable-scanner -m manifest.json
```

### Filter by severity

```bash
# Only show high and critical vulnerabilities
wordpress-vulnerable-scanner example.com --severity high
```

### JSON output for automation

```bash
wordpress-vulnerable-scanner example.com -o json | jq '.summary'
```

## Input Modes

| Mode | Flag | Description |
|------|------|-------------|
| URL scan | (positional) | Scan a live WordPress site |
| Core version | `-c, --core` | Check specific WordPress version |
| Plugins | `-p, --plugins` | Check plugins (slug:version,...) |
| Themes | `-t, --themes` | Check themes (slug:version,...) |
| Plugin list file | `--plugins-file` | One `slug:version` per line |
| Theme list file | `--themes-file` | One `slug:version` per line |
| Manifest | `-m, --manifest` | JSON file from wordpress-audit |

List files accept `slug:version`, `slug version` or `slug,version`, skip blank
lines and `#` comments, and read the CSV printed by WP-CLI directly:

```bash
wp plugin list --fields=name,version --format=csv > plugins.csv
wordpress-vulnerable-scanner --plugins-file plugins.csv
```

## Inventory: list what is installed

`inventory` reads versions straight from the files, the way WordPress itself
does (plugin headers in the first 8 KiB of each file, theme `style.css`,
`wp-includes/version.php`), so it matches wp-admin. It never runs PHP and never
touches the network, so it works on locked-down servers:

```bash
# a WordPress root, wp-content, or a plugins directory
wordpress-vulnerable-scanner inventory /var/www/html -o inventory.json

# or an archive, read in place without extracting (.tar, .tar.gz/.tgz, .zip)
tar czf plugins.tar.gz -C /var/www/html/wp-content plugins
wordpress-vulnerable-scanner inventory plugins.tar.gz --format list > plugins.txt
wordpress-vulnerable-scanner --plugins-file plugins.txt
```

`--format json` (the default) records plugins, must-use plugins, drop-ins,
themes (with their parent theme), core, and header details such as the text
domain and plugin URI. `--format list` prints `slug:version` lines for
`--plugins-file`; add `--type theme` or `--type core` for the other lists.

When a plugin has no `Version` header, the `Stable tag` from its `readme.txt` is
used instead, marked `"version_source": "readme"` and with a warning to confirm
it. Header versions are `"header"`.

Plugin copies sitting one folder too deep (say `plugins/Old Plugins/elementor/`)
are not loaded by WordPress, but their files are still on disk and may be
reachable over the web. They are listed as type `unloaded` and included in the
plugin list (after a `#` comment), so they get scanned too.

Files alone cannot tell whether a plugin is active. Where WP-CLI is installed,
`--with-wp-cli` (plus `--wp-path DIR` and `--allow-root` if needed) adds each
component's `status` and `update_version` from `wp plugin list` and
`wp theme list`. Versions still come from the files; if WP-CLI fails, the
inventory is kept as is and the failure is reported.

Anything the inventory could not resolve is listed as a warning on stderr (and in the
JSON) instead of being skipped silently: folders without a plugin header,
missing versions, folders with several plugin headers, symlinks leaving the
tree, and unsafe archive paths. Each warning says what it means for the scan
and what to do about it.

## Aliases: folder name to wordpress.org slug

Vulnerability data is keyed by wordpress.org slug, but WordPress folders are
often named differently: premium editions (`chaty-pro2`), backup copies
(`elementor2`), or plugins that ship with a theme (`woodmart-plus`). Without a
mapping those look untracked and are not checked. Write the mapping by hand in
`aliases.toml`:

```toml
[plugin]
"chaty-pro2" = "chaty"
"yith-woocommerce-product-bundles-premium" = "yith-woocommerce-product-bundles"
"woodmart-plus" = { theme = "woodmart" }   # covered by the theme's own check

[theme]
"flatsome-old" = "flatsome"
```

```bash
wordpress-vulnerable-scanner inventory plugins.tar.gz --aliases aliases.toml --format list
```

`aliases suggest` proposes entries. It never writes a file; it prints TOML to
review:

```bash
wordpress-vulnerable-scanner aliases suggest inventory.json --db wpvuln-db > suggested.toml
```

Candidates come from the folder name (lowercased; `-premium`, `-pro`, `-old`,
`-main`, `-master`, `--` and trailing digits dropped), the Text Domain header,
a Plugin URI on wordpress.org, and plugins named after an installed theme. With
`--db`, components already tracked under their own slug are skipped, and only a
candidate the database tracks becomes an active line; everything else stays
commented out with the reason. Components with no candidate at all are listed
too, so custom code is never silently assumed covered.

Add `--online` to ask the API about slugs the local database does not have
(politely, 4 at a time). The answers go to a temporary directory that is
deleted afterwards, so `--db` is never modified.

With `--aliases` the inventory records each component's `lookup_slug` (and
`lookup_type` for the `{ theme = ... }` form), and the list output uses the
lookup slug with a comment naming the installed folder. Matches found through
an alias should be confirmed: premium editions do not always number their
versions like the free plugin. Entries that cannot work (the plugin is not
installed, or the target theme is missing) are reported as warnings.

## Offline scans (local database)

For air-gapped servers, CI without outbound access, or simply to avoid
re-querying the API, pull the records for your components once and scan
from disk:

```bash
# 1. where the internet works: download records into ./wpvuln-db
wordpress-vulnerable-scanner db pull --plugins-file plugins.csv

# 2. anywhere, offline (copy the wpvuln-db directory along)
wordpress-vulnerable-scanner --db wpvuln-db --plugins-file plugins.csv

# what's in the database
wordpress-vulnerable-scanner db status
```

With an inventory, the whole site is one input, and aliases decide what is
looked up:

```bash
# on the server (no network)
wordpress-vulnerable-scanner inventory /var/www/html -o inventory.json

# where the internet works
wordpress-vulnerable-scanner db pull --inventory inventory.json --aliases aliases.toml

# anywhere, offline
wordpress-vulnerable-scanner --db wpvuln-db --inventory inventory.json --aliases aliases.toml
```

Scans leave out inventory components whose version could not be read, and say
so, since they cannot be compared with vulnerable version ranges. `db pull`
still fetches their records.

`db pull` takes the same inputs as a scan (`-p`, `-t`, `-c`, `-m`, list files,
`--inventory`) and:

- runs a few requests in parallel (`-j`, default 4) with a short pause between
  them, since WPVulnerability is a free service
- retries timeouts, HTTP 429 and 5xx, and keeps going when one component fails;
  re-run the same command to retry only what's missing
- skips records newer than `--max-age <hours>`
- tells three cases apart: tracked with vulnerabilities, tracked with none, and
  **not tracked** (WPVulnerability has no entry, common for premium and custom
  plugins). Not-tracked components are stored too, and offline scans list them
  as "not checked" rather than letting them look clean

Each record is the raw API response, one file per component, and `index.json`
records where each one came from:

```text
wpvuln-db/
├── wpvuln-db.json          # format (2), source URL, last pull
├── index.json              # per record: fetched/checked time, URL, HTTP status,
│                           #   sha256, tracked or not, vulnerability uuids, ETag
├── plugin/<slug>.json
├── theme/<slug>.json
└── core/<version>.json
```

A format 1 database (no index) still works for scans and is migrated by the next
`db pull`. Records found without an index entry are indexed from the file but
marked unconfirmed: copying a database resets file times, so nothing says how
old they are, and the next pull or `db update` re-checks them.

A scan with `--db` prints a note for components that are not tracked and a
warning for components that were never pulled, since neither has been checked. `--db` and `--api-url`
(for a self-hosted mirror) can also be set with `WPVULN_DB` and `WPVULN_API`.

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Human | `-o human` | Colored table (default) |
| JSON | `-o json` | Machine-readable JSON |
| None | `-o none` | Silent (exit code only) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (non-critical) |
| 2 | Critical vulnerabilities found |
| 10 | Error (network, parsing, etc.) |

## Severity Levels

Based on CVSS v3 scores:

| Level | CVSS Range | Color |
|-------|------------|-------|
| Critical | 9.0 - 10.0 | Red |
| High | 7.0 - 8.9 | Orange |
| Medium | 4.0 - 6.9 | Yellow |
| Low | 0.1 - 3.9 | Green |

## Security

### Input Validation

- **URL encoding** - Component slugs are URL-encoded to prevent injection
- **File size limits** - Manifest files limited to 10 MB to prevent memory exhaustion
- **Safe HTTP defaults** - TLS verification enabled, reasonable timeouts

### Data Source

Vulnerability data is fetched from [WPVulnerability.net](https://www.wpvulnerability.net/), a free CVE database for WordPress.

## API Reference

The scanner can also be used as a library:

```rust
use wordpress_vulnerable_scanner::{Analyzer, Scanner, Severity};
use wordpress_vulnerable_scanner::output::{OutputConfig, OutputFormat, output_analysis};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Scan a site
    let scanner = Scanner::new("https://example.com")?;
    let scan_result = scanner.scan().await?;

    // Analyze for vulnerabilities
    let analyzer = Analyzer::new()?;
    let analysis = analyzer.analyze(&scan_result).await;

    // Output results
    let config = OutputConfig::new(OutputFormat::Human, Severity::Low);
    let mut stdout = std::io::stdout();
    output_analysis(&analysis, &config, &mut stdout)?;

    Ok(())
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
