//! WordPress Vulnerable Scanner
//!
//! A tool for detecting known security vulnerabilities in WordPress installations.
//!
//! # Features
//!
//! - Scans WordPress sites to detect core version, plugins, and themes
//! - Queries WPVulnerability API for known CVEs
//! - Supports multiple input modes: URL, direct component list, list file, or JSON manifest
//! - Can pull records into a local database and scan fully offline ([`db`])
//! - Lists installed plugins, themes and core from a directory or an archive ([`inventory`])
//! - Maps installed folder names to wordpress.org slugs ([`aliases`])
//! - Outputs results in human-readable or JSON format
//!
//! # Example
//!
//! ```no_run
//! use wordpress_vulnerable_scanner::{Scanner, Analyzer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let scanner = Scanner::new("https://example.com")?;
//!     let scan_result = scanner.scan().await?;
//!
//!     let analyzer = Analyzer::new()?;
//!     let analysis = analyzer.analyze(&scan_result).await;
//!
//!     println!("Found {} vulnerabilities", analysis.summary.total);
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

pub mod aliases;
pub mod analyze;
pub mod db;
pub mod error;
pub(crate) mod http;
pub mod inventory;
pub mod output;
pub mod scanner;
pub mod vulnerability;

// Re-export main types
pub use analyze::{Analysis, Analyzer, ComponentVulnerabilities, VulnerabilitySummary};
pub use error::{Error, Result};
pub use output::{OutputConfig, OutputFormat, output_analysis};
pub use scanner::{ComponentInfo, ComponentType, ScanResult, Scanner};
pub use vulnerability::{
    Severity, Source, Vulnerability, VulnerabilityClient, VulnerabilityReport,
};
