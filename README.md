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

`db pull` takes the same inputs as a scan (`-p`, `-t`, `-c`, `-m`, list files)
and:

- runs a few requests in parallel (`-j`, default 4) with a short pause between
  them, since WPVulnerability is a free service
- retries timeouts, HTTP 429 and 5xx, and keeps going when one component fails;
  re-run the same command to retry only what's missing
- skips records newer than `--max-age <hours>`
- tells three cases apart: tracked with vulnerabilities, tracked with none, and
  **not tracked** (WPVulnerability has no entry, common for premium and custom
  plugins). Not-tracked components are stored too, and offline scans list them
  as "not checked" rather than letting them look clean

Each record is the raw API response, one file per component:

```text
wpvuln-db/
├── wpvuln-db.json          # format, source URL, last pull
├── plugin/<slug>.json
├── theme/<slug>.json
└── core/<version>.json
```

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
