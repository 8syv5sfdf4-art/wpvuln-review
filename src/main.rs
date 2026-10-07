//! WordPress Vulnerable Scanner CLI

use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use wordpress_vulnerable_scanner::{
    Analyzer, Severity, Source,
    aliases::{Aliases, MatchedVia},
    changes::{Change, ChangeKind},
    db::{self, PullEvent, PullOptions, PullStatus},
    inventory::{self, Kind},
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

    #[command(flatten)]
    scan: ScanArgs,
}

/// Everything a scan takes; the same flags work with and without `scan`
#[derive(ClapArgs, Debug)]
struct ScanArgs {
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

    /// Exit non-zero only for vulnerabilities at or above this severity
    /// (none: never); without it, any vulnerability exits 1 and critical 2
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<FailOn>,

    /// Also exit 1 when any component could not be checked
    #[arg(long)]
    fail_on_unchecked: bool,
}

/// Threshold for `--fail-on`
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FailOn {
    None,
    Low,
    Medium,
    High,
    Critical,
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

    /// Inventory to check: inventory.json, or a directory or archive to inventory
    #[arg(long, value_name = "PATH")]
    inventory: Option<PathBuf>,

    /// Aliases file mapping inventory folder names to wordpress.org slugs
    #[arg(
        long,
        env = "WPVULN_ALIASES",
        value_name = "FILE",
        requires = "inventory"
    )]
    aliases: Option<PathBuf>,
}

// Parsed once per run, so the size difference between variants is irrelevant
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Command {
    /// Check components for known vulnerabilities (the default when no
    /// subcommand is given)
    Scan(ScanArgs),
    /// Manage a local vulnerability database for offline scans
    #[command(subcommand)]
    Db(DbCommand),
    /// List installed core, plugins and themes from files (no network, no PHP)
    Inventory(InventoryArgs),
    /// Work with slug aliases (installed folder name -> wordpress.org slug)
    #[command(subcommand)]
    Aliases(AliasesCommand),
}

#[derive(Subcommand, Debug)]
enum AliasesCommand {
    /// Propose aliases for an inventory; prints TOML to review, never writes files
    Suggest {
        /// inventory.json, or a directory or archive to inventory first
        input: PathBuf,

        /// Confirm candidates against this local database
        #[arg(long, env = "WPVULN_DB", value_name = "DIR")]
        db: Option<PathBuf>,

        /// Existing aliases file; components it already maps are skipped
        #[arg(long, env = "WPVULN_ALIASES", value_name = "FILE")]
        aliases: Option<PathBuf>,

        /// Ask the API about slugs the local database lacks (nothing is saved)
        #[arg(long)]
        online: bool,

        /// WPVulnerability API base URL, for --online
        #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
        api_url: String,
    },
}

#[derive(ClapArgs, Debug)]
struct InventoryArgs {
    /// WordPress root, wp-content or plugins directory, or a .tar, .tar.gz or .zip of one
    path: PathBuf,

    /// Write to this file instead of stdout
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// json: full inventory; list: slug:version lines for --plugins-file / --themes-file
    #[arg(long, default_value = "json", value_enum)]
    format: InventoryFormat,

    /// Which components a list contains
    #[arg(long = "type", default_value = "plugin", value_enum)]
    list_type: ListType,

    /// Also ask WP-CLI (`wp` on PATH) for active/inactive status and available updates
    #[arg(long)]
    with_wp_cli: bool,

    /// WordPress root for WP-CLI (default: PATH, when it is a WordPress root)
    #[arg(long, value_name = "DIR", requires = "with_wp_cli")]
    wp_path: Option<PathBuf>,

    /// Pass --allow-root to WP-CLI
    #[arg(long, requires = "with_wp_cli")]
    allow_root: bool,

    /// Map folder names to wordpress.org slugs (see `aliases suggest`)
    #[arg(long, env = "WPVULN_ALIASES", value_name = "FILE")]
    aliases: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum InventoryFormat {
    Json,
    List,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ListType {
    Plugin,
    Theme,
    Core,
}

// Parsed once per run, so the size difference between variants is irrelevant
#[allow(clippy::large_enum_variant)]
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
    /// Re-check stored records that are older than their interval, and
    /// report what changed since the last check
    Update {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// WPVulnerability API base URL
        #[arg(long, env = "WPVULN_API", value_name = "URL", default_value = WPVULN_API)]
        api_url: String,

        /// Requests in flight at once (please keep this low; the API is free)
        #[arg(long, short = 'j', default_value_t = 4, value_parser = clap::value_parser!(u64).range(1..=16))]
        jobs: u64,

        /// Re-check records last confirmed more than this many hours ago (0 = all)
        #[arg(long, default_value_t = 24, value_name = "HOURS")]
        max_age: u64,

        /// The same for untracked components, which rarely change
        #[arg(long, default_value_t = 168, value_name = "HOURS")]
        untracked_max_age: u64,
    },
    /// Check a database: format, index, every record's sha256, stray files,
    /// and optionally that it covers an inventory (exit 1 on problems)
    Verify {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// Also check that every lookup this inventory needs is present
        #[arg(long, value_name = "PATH")]
        inventory: Option<PathBuf>,

        /// Aliases to apply to the inventory
        #[arg(
            long,
            env = "WPVULN_ALIASES",
            value_name = "FILE",
            requires = "inventory"
        )]
        aliases: Option<PathBuf>,
    },
    /// Pack a verified database into one file with checksums, for transfer
    Export {
        /// Database directory
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,

        /// Bundle to write
        #[arg(
            short = 'o',
            long,
            value_name = "FILE",
            default_value = "wpvuln-db.tar.gz"
        )]
        output: PathBuf,
    },
    /// Replace a database with a bundle from `db export`, after checking it
    Import {
        /// Bundle made by `db export`
        bundle: PathBuf,

        /// Database directory to replace (the old one is kept as a backup)
        #[arg(
            long,
            env = "WPVULN_DB",
            value_name = "DIR",
            default_value = "wpvuln-db"
        )]
        db: PathBuf,
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
    Csv,
    Markdown,
    #[value(name = "defectdojo")]
    DefectDojo,
    None,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(arg: OutputFormatArg) -> Self {
        match arg {
            OutputFormatArg::Human => OutputFormat::Human,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Csv => OutputFormat::Csv,
            OutputFormatArg::Markdown => OutputFormat::Markdown,
            OutputFormatArg::DefectDojo => OutputFormat::DefectDojo,
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
        Some(Command::Inventory(ref inv)) => run_inventory(inv),
        Some(Command::Aliases(ref cmd)) => run_aliases(cmd).await,
        Some(Command::Scan(ref scan)) => run_scan(scan).await,
        None => run_scan(&args.scan).await,
    };

    match result {
        Ok(exit_code) => exit_code,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(10)
        }
    }
}

async fn run_scan(args: &ScanArgs) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    // Print banner for human output
    if matches!(args.output_format, OutputFormatArg::Human) {
        print_banner();
    }
    let output_config = &OutputConfig::new(args.output_format.into(), args.min_severity.into())
        .with_color(Style::stdout().0);
    // Build scan result from various input sources
    let scan_result = build_scan_result(args).await?;

    let source = match args.db {
        Some(ref dir) => Source::Local(dir.clone()),
        None => Source::Api(args.api_url.clone()),
    };

    // Analyze for vulnerabilities
    let analyzer = Analyzer::with_source(source)?;
    let analysis = analyzer.analyze(&scan_result).await;

    // Output results
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    output_analysis(&analysis, output_config, &mut writer)?;

    Ok(ExitCode::from(exit_code(
        &analysis,
        args.fail_on,
        args.fail_on_unchecked,
    )))
}

/// 2 for critical, 1 for other vulnerabilities, 0 otherwise. `fail_on`
/// ignores findings below a severity; `fail_unchecked` turns a would-be 0
/// into 1 when anything could not be checked.
fn exit_code(
    analysis: &wordpress_vulnerable_scanner::Analysis,
    fail_on: Option<FailOn>,
    fail_unchecked: bool,
) -> u8 {
    let s = &analysis.summary;
    let threshold = match fail_on {
        None | Some(FailOn::Low) => Some(Severity::Low),
        Some(FailOn::Medium) => Some(Severity::Medium),
        Some(FailOn::High) => Some(Severity::High),
        Some(FailOn::Critical) => Some(Severity::Critical),
        Some(FailOn::None) => None,
    };
    let at_least = |sev: Severity| threshold.is_some_and(|t| sev >= t);
    let count = |sev: Severity| match sev {
        Severity::Critical => s.critical,
        Severity::High => s.high,
        Severity::Medium => s.medium,
        Severity::Low => s.low,
    };
    let failing = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter(|&sev| at_least(sev))
    .map(count)
    .sum::<usize>();
    if at_least(Severity::Critical) && s.critical > 0 {
        2
    } else if failing > 0 || (fail_unchecked && s.not_checked > 0) {
        1
    } else {
        0
    }
}

async fn build_scan_result(args: &ScanArgs) -> wordpress_vulnerable_scanner::Result<ScanResult> {
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

/// Components named by the inputs
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
            installed_as: None,
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

    if let Some(ref path) = inputs.inventory {
        components.extend(inventory_components(path, inputs.aliases.as_deref())?);
    }

    // Check we have something to scan
    if components.is_empty() {
        return Err(wordpress_vulnerable_scanner::Error::NoInput);
    }

    Ok(components)
}

fn inventory_components(
    path: &Path,
    aliases: Option<&Path>,
) -> wordpress_vulnerable_scanner::Result<Vec<ComponentInfo>> {
    let inv = inventory::load(path)?;
    let aliases = match aliases {
        Some(p) => Aliases::load(p)?,
        None => Aliases::default(),
    };
    let s = Style::stderr();
    for w in aliases.check(&inv) {
        eprintln!("{} {w}", s.yellow("warning:"));
    }

    let mut out = Vec::new();
    if let Some(version) = inv.core.as_ref().and_then(|c| c.version.clone()) {
        out.push(ComponentInfo {
            component_type: ComponentType::Core,
            slug: "wordpress".to_string(),
            version: Some(version),
            installed_as: None,
        });
    }
    for l in wordpress_vulnerable_scanner::aliases::lookups(&inv, &aliases) {
        out.push(ComponentInfo {
            component_type: match l.kind {
                Kind::Theme => ComponentType::Theme,
                _ => ComponentType::Plugin,
            },
            installed_as: (l.matched_via == MatchedVia::Alias).then_some(l.installed),
            slug: l.slug,
            version: l.version,
        });
    }
    Ok(out)
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
            installed_as: None,
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
            installed_as: None,
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
                installed_as: None,
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
            pull_cli("Pulling", dir, &items, &opts).await
        }
        DbCommand::Update {
            db: dir,
            api_url,
            jobs,
            max_age,
            untracked_max_age,
        } => {
            let items = db::stored(dir)?;
            if items.is_empty() {
                return Err(wordpress_vulnerable_scanner::Error::Database(format!(
                    "{} holds no records yet; run `db pull` first",
                    dir.display()
                )));
            }
            let hours = |h: u64| (h > 0).then(|| Duration::from_secs(h * 3600));
            let opts = PullOptions {
                api_url: api_url.clone(),
                jobs: *jobs as usize,
                max_age: hours(*max_age),
                untracked_max_age: hours(*untracked_max_age),
                ..PullOptions::default()
            };
            pull_cli("Updating", dir, &items, &opts).await
        }
        DbCommand::Verify {
            db: dir,
            inventory,
            aliases,
        } => verify_cli(dir, inventory.as_deref(), aliases.as_deref()),
        DbCommand::Export { db: dir, output } => {
            let m = wordpress_vulnerable_scanner::transfer::export(dir, output)?;
            let s = Style::stdout();
            println!(
                "{} {} files from {} into {}",
                s.bold("Exported"),
                m.files.len(),
                dir.display(),
                output.display()
            );
            println!(
                "Copy it to the offline machine, then: {}",
                s.bold(&format!(
                    "wordpress-vulnerable-scanner db import {}",
                    output
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ))
            );
            Ok(ExitCode::SUCCESS)
        }
        DbCommand::Import { bundle, db: dir } => {
            let done = wordpress_vulnerable_scanner::transfer::import(bundle, dir)?;
            let s = Style::stdout();
            println!(
                "{} {} files into {}: every file matched the manifest and `db verify` passed",
                s.bold("Imported"),
                done.files,
                dir.display()
            );
            if let Some(b) = done.backup {
                println!("The previous database was moved to {}", b.display());
            }
            Ok(ExitCode::SUCCESS)
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
                    match st.indexed {
                        Some(n) => println!(
                            "  format      {} (index: {n} records{})",
                            m.format,
                            match st.rebuilt {
                                0 => String::new(),
                                r => format!(", {r} rebuilt from files, download details unknown"),
                            }
                        ),
                        None => println!(
                            "  format      {} {}",
                            m.format,
                            s.dim("(no index yet; the next `db pull` adds one)")
                        ),
                    }
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
            match (st.indexed, st.oldest_check, st.oldest) {
                (Some(_), Some(t), _) => println!("  oldest check {}", ago(t)),
                (None, _, Some(t)) => println!(
                    "  oldest file {} {}",
                    ago(t),
                    s.dim("(file times reset when a database is copied)")
                ),
                _ => {}
            }
            if st.unconfirmed > 0 {
                println!(
                    "  {} {} never confirmed: rebuilt from files, so when they were fetched is \
                     unknown. `db update` re-checks them.",
                    s.yellow("unconfirmed"),
                    st.unconfirmed
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn pull_cli(
    verb: &str,
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
        s.bold(verb),
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
            PullStatus::Unchanged(n) => (
                s.dim("="),
                s.dim(&format!("{n} records, unchanged (confirmed by the API)")),
            ),
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
    if summary.unchanged > 0 {
        parts.push(format!("{} unchanged", summary.unchanged));
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
    print_changes(&s, dir, &summary.changes, verb == "Updating");
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

fn verify_cli(
    dir: &Path,
    inventory: Option<&Path>,
    aliases: Option<&Path>,
) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let needed: Vec<(ComponentType, String)> = match inventory {
        Some(path) => inventory_components(path, aliases)?
            .into_iter()
            .filter_map(|c| match c.component_type {
                ComponentType::Core => c.version.map(|v| (ComponentType::Core, v)),
                kind => Some((kind, c.slug)),
            })
            .collect(),
        None => Vec::new(),
    };
    let v = db::verify(dir, &needed);
    let s = Style::stdout();
    println!("{} {}", s.bold("Verifying"), dir.display());
    println!("  {} record files checked", v.records);
    if v.untracked > 0 {
        println!(
            "  {} untracked {}",
            v.untracked,
            s.dim(
                "(not a problem: WPVulnerability has no entry for them, so they are not checked)"
            )
        );
    }
    if let Some(path) = inventory {
        println!(
            "  {} lookups needed by {}, {} missing",
            needed.len(),
            path.display(),
            v.missing.len()
        );
    }
    if !v.problems.is_empty() {
        println!("\n{} ({})", s.red("Problems"), v.problems.len());
        let digits = v.problems.len().to_string().len();
        for (i, p) in v.problems.iter().enumerate() {
            let indent = " ".repeat(digits + 4);
            println!(
                "  {} {}",
                s.dim(&format!("{:>digits$}.", i + 1)),
                wrap(p, 96 - indent.len()).join(&format!("\n{indent}"))
            );
        }
    }
    if !v.missing.is_empty() {
        println!(
            "\n{} ({}): {}",
            s.red("Missing for the inventory"),
            v.missing.len(),
            v.missing.join(", ")
        );
        println!(
            "  They were never pulled, so a scan would report them as not checked. Fix with:\n  \
             wordpress-vulnerable-scanner db pull --db {} --inventory {}{}",
            dir.display(),
            inventory
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            aliases
                .map(|a| format!(" --aliases {}", a.display()))
                .unwrap_or_default()
        );
    }
    if v.ok() {
        println!(
            "\n{}",
            s.green("OK: every record matches what was downloaded.")
        );
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

/// The "what is new since last time" view of a pull or update
fn print_changes(s: &Style, dir: &Path, changes: &[Change], always: bool) {
    if changes.is_empty() {
        if always {
            println!("\n{}", s.bold("No changes since the last check."));
        }
        return;
    }
    println!("\n{}", s.bold("Changes since the last check"));
    let width = changes
        .iter()
        .map(|c| c.key.chars().count())
        .max()
        .unwrap_or(0)
        .min(48);
    for c in changes {
        let what = c
            .cves
            .first()
            .map(|cve| format!("{cve}: "))
            .unwrap_or_default()
            + c.title.as_deref().or(c.uuid.as_deref()).unwrap_or_default();
        let (mark, text) = match c.change {
            ChangeKind::Added => (s.red("+"), format!("{what} (new vulnerability)")),
            ChangeKind::Removed => (
                s.green("-"),
                format!("{what} (withdrawn or merged upstream)"),
            ),
            ChangeKind::Changed => (
                s.yellow("~"),
                format!("{what} (details changed: affected versions, score or references)"),
            ),
            ChangeKind::NowTracked => (
                s.green("!"),
                "now tracked by WPVulnerability: it is checked from now on".to_string(),
            ),
            ChangeKind::NoLongerTracked => (
                s.red("!"),
                "no longer tracked by WPVulnerability: it is not checked any more".to_string(),
            ),
        };
        println!("  {mark} {:<width$}  {text}", c.key);
    }
    println!(
        "{}",
        s.dim(&format!(
            "Logged in {}",
            dir.join("changes").join("<date>.json").display()
        ))
    );
}

fn run_inventory(args: &InventoryArgs) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let mut inv = inventory::read(&args.path)?;
    if args.with_wp_cli {
        if inv.source.kind == inventory::SourceKind::Archive {
            return Err(wordpress_vulnerable_scanner::Error::Inventory(
                "--with-wp-cli needs a live WordPress directory, not an archive".to_string(),
            ));
        }
        let path = args.wp_path.clone().or_else(|| {
            (inv.source.layout == inventory::Layout::Wordpress).then(|| args.path.clone())
        });
        let wp = inventory::WpCli {
            path,
            allow_root: args.allow_root,
            ..Default::default()
        };
        inventory::enrich_with_wp_cli(&mut inv, &wp);
    }
    if let Some(ref path) = args.aliases {
        Aliases::load(path)?.apply(&mut inv);
    }
    let text = match args.format {
        InventoryFormat::Json => serde_json::to_string_pretty(&inv)? + "\n",
        InventoryFormat::List => inv.to_list(match args.list_type {
            ListType::Plugin => ComponentType::Plugin,
            ListType::Theme => ComponentType::Theme,
            ListType::Core => ComponentType::Core,
        }),
    };
    match args.output {
        Some(ref path) => std::fs::write(path, text)?,
        None => {
            use std::io::Write;
            std::io::stdout().lock().write_all(text.as_bytes())?;
        }
    }

    // Everything else goes to stderr, so stdout stays a clean file
    let s = Style::stderr();
    let plural = |n: usize, noun: &str| format!("{n} {noun}{}", if n == 1 { "" } else { "s" });
    let count = |kind: Kind| inv.components.iter().filter(|c| c.kind == kind).count();
    let mut parts = vec![
        plural(count(Kind::Plugin), "plugin"),
        plural(count(Kind::Theme), "theme"),
    ];
    for (kind, noun) in [
        (Kind::MuPlugin, "must-use plugin"),
        (Kind::Dropin, "drop-in"),
        (Kind::Unloaded, "unloaded plugin"),
    ] {
        if count(kind) > 0 {
            parts.push(plural(count(kind), noun));
        }
    }
    if let Some(ref core) = inv.core {
        parts.push(format!(
            "core {}",
            core.version.as_deref().unwrap_or("unknown")
        ));
    }
    eprintln!(
        "{} {} ({} layout): {}{}",
        s.bold("Inventory"),
        inv.source.path,
        serde_json::to_value(inv.source.layout)?
            .as_str()
            .unwrap_or_default(),
        parts.join(", "),
        match inv.warnings.len() {
            0 => String::new(),
            n => format!(", {}", s.yellow(&plural(n, "warning"))),
        }
    );
    if !inv.warnings.is_empty() {
        eprintln!("\n{}", s.yellow("Warnings"));
        let digits = inv.warnings.len().to_string().len();
        for (i, w) in inv.warnings.iter().enumerate() {
            let number = format!("{:>digits$}.", i + 1);
            let indent = " ".repeat(digits + 4);
            let lines = wrap(w, 96 - indent.len());
            eprintln!(
                "  {} {}",
                s.dim(&number),
                lines.join(&format!("\n{indent}"))
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn run_aliases(cmd: &AliasesCommand) -> wordpress_vulnerable_scanner::Result<ExitCode> {
    let AliasesCommand::Suggest {
        input,
        db: db_dir,
        aliases,
        online,
        api_url,
    } = cmd;
    let inv = inventory::load(input)?;
    let existing = match aliases {
        Some(path) => Aliases::load(path)?,
        None => Aliases::default(),
    };
    let lookup = |kind: Kind, slug: &str| {
        let kind = match kind {
            Kind::Theme => ComponentType::Theme,
            _ => ComponentType::Plugin,
        };
        db::known(db_dir.as_deref().unwrap_or(Path::new("")), kind, slug)
    };
    let known: Option<wordpress_vulnerable_scanner::aliases::KnownFn> = match db_dir {
        Some(_) => Some(&lookup),
        None => None,
    };
    let s = Style::stderr();
    let (suggestions, failed) = if *online {
        eprintln!(
            "{} candidates at {api_url} (4 requests at a time, nothing is saved)",
            s.bold("Checking")
        );
        let opts = PullOptions {
            api_url: api_url.clone(),
            ..PullOptions::default()
        };
        wordpress_vulnerable_scanner::aliases::suggest_online(
            &inv,
            &existing,
            db_dir.as_deref(),
            &opts,
        )
        .await?
    } else {
        let found = wordpress_vulnerable_scanner::aliases::suggest(&inv, &existing, known);
        (found, Vec::new())
    };
    let checked = match (db_dir, online) {
        (Some(dir), true) => format!("local database {}, then {api_url}", dir.display()),
        (None, true) => api_url.clone(),
        (Some(dir), false) => format!("local database {}", dir.display()),
        (None, false) => "nothing (add --db DIR or --online to confirm them)".to_string(),
    };
    print!(
        "{}",
        wordpress_vulnerable_scanner::aliases::render(&suggestions, &checked)
    );

    if !failed.is_empty() {
        eprintln!(
            "{} {} lookup{} failed, so those slugs read as \"not in the database\"; run again \
             to retry: {}",
            s.yellow("warning:"),
            failed.len(),
            if failed.len() == 1 { "" } else { "s" },
            failed.join(", ")
        );
    }
    let confirmed = suggestions.iter().filter(|x| x.chosen.is_some()).count();
    let without = suggestions
        .iter()
        .filter(|x| x.candidates.is_empty())
        .count();
    eprintln!(
        "{} {} component{}: {confirmed} confirmed, {} to review, {without} without candidates",
        s.bold("Suggestions for"),
        suggestions.len(),
        if suggestions.len() == 1 { "" } else { "s" },
        suggestions.len() - confirmed - without
    );
    Ok(ExitCode::SUCCESS)
}

/// Greedy word wrap for terminal messages
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split_whitespace() {
        let line = lines.last_mut().expect("never empty");
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(word.to_string());
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    lines
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
