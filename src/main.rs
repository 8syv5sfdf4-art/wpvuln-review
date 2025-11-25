//! WordPress Vulnerable Scanner CLI

use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

use wordpress_vulnerable_scanner::{
    Analyzer, Severity,
    output::{OutputConfig, OutputFormat, output_analysis},
    scanner::{ComponentInfo, ComponentType, ScanResult, Scanner, parse_component},
};

/// WordPress vulnerability scanner - detects known CVEs in core, plugins, and themes
#[derive(Parser, Debug)]
#[command(name = "wordpress-vulnerable-scanner")]
#[command(version, about, long_about = None)]
struct Args {
    /// URL of the WordPress site to scan
    url: Option<String>,

    /// Plugins to check (slug:version,slug:version,...)
    #[arg(long, short = 'p')]
    plugins: Option<String>,

    /// Themes to check (slug:version,slug:version,...)
    #[arg(long, short = 't')]
    themes: Option<String>,

    /// WordPress core version to check
    #[arg(long, short = 'c')]
    core: Option<String>,

    /// JSON manifest file (output from wordpress-audit)
    #[arg(long, short = 'm')]
    manifest: Option<PathBuf>,

    /// Output format
    #[arg(short = 'o', long = "output", default_value = "human", value_enum)]
    output_format: OutputFormatArg,

    /// Minimum severity level to report
    #[arg(long = "severity", default_value = "low", value_enum)]
    min_severity: SeverityArg,
}

/// Output format argument
#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormatArg {
    Human,
    Json,
    None,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Human => OutputFormat::Human,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::None => OutputFormat::None,
        }
    }
}

/// Severity argument
#[derive(Clone, Copy, Debug, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(arg: SeverityArg) -> Self {
        match arg {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Print banner for human output
    if matches!(args.output_format, OutputFormatArg::Human) {
        print_banner();
    }

    let output_config = OutputConfig::new(args.output_format.into(), args.min_severity.into());

    match run_scan(&args, &output_config).await {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(10)
        }
    }
}

async fn run_scan(
    args: &Args,
    output_config: &OutputConfig,
) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    // Build scan result from various input sources
    let scan_result = build_scan_result(args).await?;

    // Analyze for vulnerabilities
    let analyzer = Analyzer::new()?;
    let analysis = analyzer.analyze(&scan_result).await;

    // Output results
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    output_analysis(&analysis, output_config, &mut writer)?;

    // Return appropriate exit code
    Ok(if analysis.summary.critical > 0 {
        ExitCode::from(2) // Critical vulnerabilities
    } else if analysis.summary.has_any() {
        ExitCode::from(1) // Some vulnerabilities
    } else {
        ExitCode::SUCCESS // No vulnerabilities
    })
}

async fn build_scan_result(args: &Args) -> wordpress_vulnerable_scanner::Result<ScanResult> {
    let mut components = Vec::new();

    // URL scan mode
    if let Some(ref url) = args.url {
        // Add http:// if no scheme provided
        let url = if !url.contains("://") {
            format!("http://{}", url)
        } else {
            url.clone()
        };
        let scanner = Scanner::new(&url)?;
        let result = scanner.scan().await?;
        return Ok(result);
    }

    // Manifest file mode
    if let Some(ref manifest_path) = args.manifest {
        // Security: Limit manifest file size to 10MB to prevent memory exhaustion
        const MAX_MANIFEST_SIZE: u64 = 10 * 1024 * 1024;

        let metadata = std::fs::metadata(manifest_path)
            .map_err(|e| wordpress_vulnerable_scanner::Error::ManifestRead(e.to_string()))?;

        if metadata.len() > MAX_MANIFEST_SIZE {
            return Err(wordpress_vulnerable_scanner::Error::ManifestRead(format!(
                "file too large ({} bytes, max {} bytes)",
                metadata.len(),
                MAX_MANIFEST_SIZE
            )));
        }

        let contents = std::fs::read_to_string(manifest_path)
            .map_err(|e| wordpress_vulnerable_scanner::Error::ManifestRead(e.to_string()))?;

        // Try to parse as wordpress-audit JSON output
        let manifest: serde_json::Value = serde_json::from_str(&contents)
            .map_err(|e| wordpress_vulnerable_scanner::Error::ManifestParse(e.to_string()))?;

        // Extract WordPress version
        if let Some(wp) = manifest.get("wordpress")
            && let Some(version) = wp.get("version").and_then(|v| v.as_str())
            && version != "-"
        {
            components.push(ComponentInfo {
                component_type: ComponentType::Core,
                slug: "wordpress".to_string(),
                version: Some(version.to_string()),
            });
        }

        // Extract theme
        if let Some(theme) = manifest.get("theme")
            && let Some(name) = theme.get("name").and_then(|v| v.as_str())
        {
            let version = theme
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|v| *v != "-")
                .map(|s| s.to_string());

            components.push(ComponentInfo {
                component_type: ComponentType::Theme,
                slug: name.to_string(),
                version,
            });
        }

        // Extract plugins
        if let Some(plugins) = manifest.get("plugins").and_then(|p| p.as_object()) {
            for (slug, plugin_data) in plugins {
                let version = plugin_data
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|v| *v != "-")
                    .map(|s| s.to_string());

                components.push(ComponentInfo {
                    component_type: ComponentType::Plugin,
                    slug: slug.clone(),
                    version,
                });
            }
        }

        return Ok(ScanResult::from_components(components));
    }

    // Direct input mode
    if let Some(ref core_version) = args.core {
        components.push(ComponentInfo {
            component_type: ComponentType::Core,
            slug: "wordpress".to_string(),
            version: Some(core_version.clone()),
        });
    }

    if let Some(ref plugins_str) = args.plugins {
        for plugin in plugins_str.split(',') {
            let plugin = plugin.trim();
            if !plugin.is_empty() {
                components.push(parse_component(plugin, ComponentType::Plugin)?);
            }
        }
    }

    if let Some(ref themes_str) = args.themes {
        for theme in themes_str.split(',') {
            let theme = theme.trim();
            if !theme.is_empty() {
                components.push(parse_component(theme, ComponentType::Theme)?);
            }
        }
    }

    // Check we have something to scan
    if components.is_empty() {
        return Err(wordpress_vulnerable_scanner::Error::NoInput);
    }

    Ok(ScanResult::from_components(components))
}

fn print_banner() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("WordPress Vulnerable Scanner v{}", VERSION);
    println!("by Robert F. Ecker <robert@robdotec.com>");
    println!();
}
