# WordPress vulnerability report

Scanned: 2026-10-07T00:00:00Z

## Summary

**3 vulnerabilities** (1 critical, 1 high, 0 medium, 1 low) in 2 components. **4 components were not checked** and are not known to be safe.

| State | Components |
|---|---|
| vulnerable | 1 |
| vulnerable through an alias (confirm) | 1 |
| clean | 3 |
| not checked: not tracked | 1 |
| not checked: not in the local database | 1 |
| not checked: version unknown | 1 |
| not checked: lookup failed | 1 |

## Findings

### Critical (1)

| Component | Version | Vulnerability | CVSS | Affected | Fixed in |
|---|---|---|---|---|---|
| akismet | 5.3 | [CVE-2026-0001](https://www.cve.org/CVERecord?id=CVE-2026-0001): Akismet <= 5.3 – Unauthenticated RCE \| "quoted", with comma **(known exploited)** | 9.8 | >= 5.0, < 5.3.1 | 5.3.1 |

### High (1)

| Component | Version | Vulnerability | CVSS | Affected | Fixed in |
|---|---|---|---|---|---|
| chaty-pro2 (as chaty-pro) | 3.3.6 | [CVE-2026-6251](https://www.cve.org/CVERecord?id=CVE-2026-6251): Chaty Pro < 3.5.6 - SQL Injection | 7.5 | < 3.5.6 | 3.5.6 |

### Low (1)

| Component | Version | Vulnerability | CVSS | Affected | Fixed in |
|---|---|---|---|---|---|
| akismet | 5.3 | u-low: Akismet info leak | 3.1 | <= 9.9 | no fix yet |

## Found through an alias: confirm before acting

These were looked up under another slug. Premium editions may number their versions differently from the free plugin.

- chaty-pro2 (as chaty-pro) 3.3.6

## Not checked

Nothing is known about these: they are neither safe nor vulnerable as far as this scan can tell. Review them by hand.

### Not tracked by the data source (common for premium and custom code) (1)

- zhaket-woo-sep 1.2.1

### Never pulled into the local database (run `db pull` with the same inputs) (1)

- never-pulled 1.0

### Version unknown, so ranges cannot be compared (1)

- custom-thing: no version could be read; 1 known vulnerability affects some versions

### Lookup failed (run the scan again) (1)

- broken 1.0: not a valid WPVulnerability response (blocked, or a damaged record)

## Clean (3)

Tracked, and no known vulnerability affects the installed version: WordPress 6.6.2, hello-dolly 1.7.2, theme storefront 4.5.0

