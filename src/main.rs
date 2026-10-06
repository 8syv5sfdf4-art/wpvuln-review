//! WordPress Vulnerable Scanner CLI

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use wordpress_vulnerable_scanner::{
    Analyzer, Severity, Source,
    db::{self, PullEvent, PullOptions, PullStatus},
    output::{OutputConfig, OutputFormat, output_analysis},
    scanner::{
        ComponentInfo, ComponentType, ScanResult, Scanner, parse_component, parse_component_list,
    },
    vulnerability::WPVULN_API,
};

/// WordPress vulnerability scanner - detects known CVEs in core, plugins, and themes
#[derive(Parser, Debug)]
#[command(name = "wordpress-vulnerable-scanner")]
#[command(version, about, long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// URL of the WordPress site to scan
    url: Option<String>,

    #[command(flatten)]
    inputs: Inputs,

    /// Read vulnerability data from a local database (see `db pull`) instead of the API
    #[arg(long, env = "WPVULN_DB", value_name = "DIR")]
    db: Option<PathBuf>,

    /// WPVulnerability API base URL (for mirrors)
    #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
    api_url: String,

    /// Output format
    #[arg(short = 'o', long = "output", default_value = "human", value_enum)]
    output_format: OutputFormatArg,

    /// Minimum severity level to report
    #[arg(long = "severity", default_value = "low", value_enum)]
    min_severity: SeverityArg,
}

/// Component inputs shared by scanning and `db pull`
#[derive(ClapArgs, Debug, Clone, Default)]
struct Inputs {
    /// Plugins to check (slug:version,slug:version,...)
    #[arg(long, short = 'p')]
    plugins: Option<String>,

    /// File with one plugin per line (slug:version; `wp plugin list --format=csv` also works)
    #[arg(long, value_name = "FILE")]
    plugins_file: Option<PathBuf>,

    /// Themes to check (slug:version,slug:version,...)
    #[arg(long, short = 't')]
    themes: Option<String>,

    /// File with one theme per line (slug:version)
    #[arg(long, value_name = "FILE")]
    themes_file: Option<PathBuf>,

    /// WordPress core version to check
    #[arg(long, short = 'c')]
    core: Option<String>,

    /// JSON manifest file (output from wordpress-audit)
    #[arg(long, short = 'm')]
    manifest: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage a local vulnerability database for offline scans
    #[command(subcommand)]
    Db(DbCommand),
}

#[derive(Subcommand, Debug)]
enum DbCommand {
    /// Download records for the given components into a local database
    Pull {
        /// Database directory (created if missing)
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        #[command(flatten)]
        inputs: Inputs,

        /// WPVulnerability API base URL
        #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
        api_url: String,

        /// Requests in flight at once (please keep this low; the API is free)
        #[arg(long, short = 'j', default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=16))]
        jobs: u64,

        /// Skip records downloaded less than this many hours ago (0 = always download)
        #[arg(long, default_value_t = 0, value_name = "HOURS")]
        max_age: u64,
    },
    /// Show what a local database contains
    Status {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
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

    let result = match args.command {
        Some(Command::Db(ref cmd)) => run_db(cmd).await,
        None => {
            // Print banner for human output
            if matches!(args.output_format, OutputFormatArg::Human) {
                print_banner();
            }
            let output_config =
                OutputConfig::new(args.output_format.into(), args.min_severity.into());
            run_scan(&args, &output_config).await
        }
    };

    match result {
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

    let source = match args.db {
        Some(ref dir) => {
            warn_missing(dir, &scan_result.components);
            Source::Local(dir.clone())
        }
        None => Source::Api(args.api_url.clone()),
    };

    // Analyze for vulnerabilities
    let analyzer = Analyzer::with_source(source)?;
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

/// In offline mode, a component missing from the database would silently
/// look clean; say so on stderr instead.
fn warn_missing(dir: &Path, components: &[ComponentInfo]) {
    let keys = components.iter().filter_map(|c| match c.component_type {
        ComponentType::Core => c.version.as_deref().map(|v| (c.component_type, v)),
        _ => Some((c.component_type, c.slug.as_str())),
    });
    let keys: Vec<_> = keys.collect();
    let untracked = db::untracked(dir, keys.iter().copied());
    if !untracked.is_empty() {
        let s = Style::stderr();
        eprintln!(
            "{} {} not tracked by WPVulnerability, so not checked (common for premium/custom plugins): {}\n",
            s.yellow("note:"),
            untracked.len(),
            untracked.join(", ")
        );
    }
    let missing = db::missing(dir, keys.iter().copied());
    if !missing.is_empty() {
        let s = Style::stderr();
        eprintln!(
            "{} {} not in the local database (reported as clean): {}",
            s.yellow("warning:"),
            missing.len(),
            missing.join(", ")
        );
        eprintln!(
            "         run `wordpress-vulnerable-scanner db pull` with the same inputs to add them\n"
        );
    }
}

async fn build_scan_result(args: &Args) -> wordpress_vulnerable_scanner::Result<ScanResult> {
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

    Ok(ScanResult::from_components(build_components(&args.inputs)?))
}

fn build_components(inputs: &Inputs) -> wordpress_vulnerable_scanner::Result<Vec<ComponentInfo>> {
    let mut components = Vec::new();

    // Manifest file mode
    if let Some(ref manifest_path) = inputs.manifest {
        read_manifest(manifest_path, &mut components)?;
        return Ok(components);
    }

    // Direct input mode
    if let Some(ref core_version) = inputs.core {
        components.push(ComponentInfo {
            component_type: ComponentType::Core,
            slug: "wordpress".to_string(),
            version: Some(core_version.clone()),
        });
    }

    for (list, file, kind) in [
        (&inputs.plugins, &inputs.plugins_file, ComponentType::Plugin),
        (&inputs.themes, &inputs.themes_file, ComponentType::Theme),
    ] {
        if let Some(list) = list {
            for item in list.split(',') {
                let item = item.trim();
                if !item.is_empty() {
                    components.push(parse_component(item, kind)?);
                }
            }
        }
        if let Some(path) = file {
            let text = std::fs::read_to_string(path).map_err(|e| {
                wordpress_vulnerable_scanner::Error::ManifestRead(format!(
                    "{}: {}",
                    path.display(),
                    e
                ))
            })?;
            components.extend(parse_component_list(&text, kind)?);
        }
    }

    // Check we have something to scan
    if components.is_empty() {
        return Err(wordpress_vulnerable_scanner::Error::NoInput);
    }

    Ok(components)
}

fn read_manifest(
    manifest_path: &Path,
    components: &mut Vec<ComponentInfo>,
) -> wordpress_vulnerable_scanner::Result<()> {
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
    Ok(())
}

async fn run_db(cmd: &DbCommand) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    match cmd {
        DbCommand::Pull {
            db: dir,
            inputs,
            api_url,
            jobs,
            max_age,
        } => {
            let items: Vec<(ComponentType, String)> = build_components(inputs)?
                .into_iter()
                .filter_map(|c| match c.component_type {
                    ComponentType::Core => c.version.map(|v| (ComponentType::Core, v)),
                    kind => Some((kind, c.slug)),
                })
                .collect();
            let opts = PullOptions {
                api_url: api_url.clone(),
                jobs: *jobs as usize,
                max_age: (*max_age > 0).then(|| Duration::from_secs(max_age * 3600)),
                ..PullOptions::default()
            };
            pull_cli(dir, &items, &opts).await
        }
        DbCommand::Status { db: dir, json } => {
            let st = db::status(dir)?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&st)?);
                return Ok(ExitCode::SUCCESS);
            }
            let s = Style::stdout();
            println!("{} {}", s.bold("Database"), dir.display());
            match st.meta {
                Some(ref m) => {
                    println!("  source      {}", m.source);
                    println!("  last pull   {}", ago(m.pulled_at));
                }
                None => println!("  {}", s.yellow("not a database yet; run `db pull` first")),
            }
            println!("  plugins     {}", st.plugins);
            println!("  themes      {}", st.themes);
            println!("  core        {}", st.core);
            if st.untracked > 0 {
                println!(
                    "  untracked   {} {}",
                    st.untracked,
                    s.dim("(no WPVulnerability entry, not checked)")
                );
            }
            println!("  records     {}", st.records);
            if let Some(t) = st.oldest {
                println!("  oldest file {}", ago(t));
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn pull_cli(
    dir: &Path,
    items: &[(ComponentType, String)],
    opts: &PullOptions,
) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let s = Style::stdout();
    let total = items.len();
    let width = items
        .iter()
        .map(|(_, k)| k.chars().count())
        .max()
        .unwrap_or(10)
        .min(48);
    let digits = total.to_string().len();
    println!(
        "{} {} component{} from {} into {} ({} parallel)\n",
        s.bold("Pulling"),
        total,
        if total == 1 { "" } else { "s" },
        opts.api_url,
        dir.display(),
        opts.jobs
    );

    let started = Instant::now();
    let summary = db::pull(dir, items, opts, |e: &PullEvent| {
        let (mark, detail) = match &e.status {
            PullStatus::Saved(0) => (s.green("✓"), s.dim("tracked, no known vulnerabilities")),
            PullStatus::Saved(n) => (
                s.green("✓"),
                format!("{n} record{}", if *n == 1 { "" } else { "s" }),
            ),
            PullStatus::Fresh(n) => (s.dim("="), s.dim(&format!("{n} records, up to date"))),
            PullStatus::NoData => (
                s.yellow("?"),
                s.yellow("not tracked by WPVulnerability (not checked)"),
            ),
            PullStatus::Invalid => (s.red("✗"), s.red("invalid slug, skipped")),
            PullStatus::Failed(why) => (
                s.red("✗"),
                s.red(&format!("{why} (after {} attempts)", opts.attempts)),
            ),
        };
        let kind = match e.kind {
            ComponentType::Core => "core ",
            ComponentType::Plugin => "",
            ComponentType::Theme => "theme ",
        };
        println!(
            "  {} {} {}{:<width$}  {}",
            s.dim(&format!("[{:>digits$}/{}]", e.done, e.total)),
            mark,
            kind,
            e.key,
            detail,
        );
    })
    .await?;

    let mut parts = vec![format!(
        "{} saved ({} records)",
        summary.saved, summary.records
    )];
    if summary.fresh > 0 {
        parts.push(format!("{} up to date", summary.fresh));
    }
    if summary.no_data > 0 {
        parts.push(s.yellow(&format!("{} not tracked", summary.no_data)));
    }
    if summary.invalid > 0 {
        parts.push(s.red(&format!("{} invalid", summary.invalid)));
    }
    if summary.failed > 0 {
        parts.push(s.red(&format!("{} failed", summary.failed)));
    }
    println!(
        "\n{} in {:.0?}: {}",
        s.bold("Done"),
        started.elapsed(),
        parts.join(", ")
    );
    if summary.failed > 0 {
        println!(
            "{}",
            s.yellow("Re-run the same command to retry the failed ones; saved records are kept.")
        );
    }
    println!(
        "Scan offline with: {}",
        s.bold(&format!(
            "wordpress-vulnerable-scanner --db {} ...",
            dir.display()
        ))
    );

    Ok(if summary.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn ago(unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(unix);
    let secs = now.saturating_sub(unix);
    match secs {
        0..=59 => "just now".to_string(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

/// ANSI styling, only when writing to a terminal and NO_COLOR is unset
struct Style(bool);

impl Style {
    fn stdout() -> Self {
        Style(std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }
    fn stderr() -> Self {
        Style(std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none())
    }
    fn paint(&self, code: &str, text: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
}

fn print_banner() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("WordPress Vulnerable Scanner v{}", VERSION);
    println!("by Robert F. Ecker <robert@robdotec.com>");
    println!();
}
