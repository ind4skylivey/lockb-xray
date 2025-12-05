use anyhow::{Context, Result};
use binrw::Error as BinrwError;
use bun_xray_core::{
    load_package_json, parse_lockfile_with_warnings, PackageJson, ParseError, ScanResult,
    SecurityScanner,
};
use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
use serde::Serialize;
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Audit Bun bun.lockb for supply chain risks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Audit a bun.lockb file
    Audit {
        /// Path to bun.lockb
        path: PathBuf,
        /// Output JSON only
        #[arg(long)]
        json: bool,
        /// Verbose parser diagnostics
        #[arg(long)]
        verbose: bool,
        /// Minimum severity that triggers non-zero exit (info|warn|high)
        #[arg(long, default_value = "warn")]
        severity_threshold: String,
        /// Allow registries (host substring). If set, only these are considered trusted.
        #[arg(long = "allow-registry")]
        allow_registry: Vec<String>,
        /// Ignore registries (host substring). Skip warnings for these registries.
        #[arg(long = "ignore-registry")]
        ignore_registry: Vec<String>,
        /// Ignore specific package names (exact match).
        #[arg(long = "ignore-package")]
        ignore_package: Vec<String>,
        /// Optional package.json path (defaults to sibling of lockfile)
        #[arg(long = "package-json", value_name = "PATH")]
        package_json: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info = 0,
    Warn = 1,
    High = 2,
}

impl Severity {
    fn color(&self) -> comfy_table::Color {
        match self {
            Severity::Info => comfy_table::Color::Green,
            Severity::Warn => comfy_table::Color::Yellow,
            Severity::High => comfy_table::Color::Red,
        }
    }
    fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warn" | "warning" => Some(Severity::Warn),
            "high" | "critical" => Some(Severity::High),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::High => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Issue {
    id: usize,
    severity: Severity,
    kind: String,
    package: String,
    version: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    total_packages: usize,
    issues_total: usize,
    high_count: usize,
    warn_count: usize,
    info_count: usize,
    exit_code: i32,
    parser_warnings: Vec<String>,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    summary: &'a Summary,
    issues: &'a [Issue],
    #[serde(skip_serializing_if = "Option::is_none")]
    trailers: Option<&'a bun_xray_core::model::TrailerInfo>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Audit {
            path,
            json,
            verbose,
            severity_threshold,
            allow_registry,
            ignore_registry,
            ignore_package,
            package_json,
        } => run_audit(
            path,
            json,
            verbose,
            &severity_threshold,
            allow_registry,
            ignore_registry,
            ignore_package,
            package_json,
        )?,
    }
    Ok(())
}

fn run_audit(
    path: PathBuf,
    json: bool,
    verbose: bool,
    severity_threshold: &str,
    allow_registry: Vec<String>,
    ignore_registry: Vec<String>,
    ignore_package: Vec<String>,
    package_json: Option<PathBuf>,
) -> Result<()> {
    let (lockfile, parser_warnings) =
        parse_lockfile_with_warnings(path.as_path()).map_err(map_binrw_error)?;

    let package_json = resolve_package_json(&path, package_json)?;
    let scan = lockfile.scan(package_json.as_ref());

    let issues = collect_issues(
        &scan,
        &lockfile,
        parser_warnings,
        &allow_registry,
        &ignore_registry,
        &ignore_package,
    );

    let sev_threshold = Severity::from_str(severity_threshold).unwrap_or(Severity::Warn);
    let exit_code = decide_exit_code(&issues, sev_threshold);

    let summary = Summary {
        total_packages: scan.total_packages,
        issues_total: issues.len(),
        high_count: issues.iter().filter(|i| i.severity == Severity::High).count(),
        warn_count: issues.iter().filter(|i| i.severity == Severity::Warn).count(),
        info_count: issues.iter().filter(|i| i.severity == Severity::Info).count(),
        exit_code,
        parser_warnings: issues
            .iter()
            .filter(|i| i.kind == "parser_warning")
            .map(|i| i.detail.clone())
            .collect(),
    };

    if json {
        let report = JsonReport {
            summary: &summary,
            issues: &issues,
            trailers: if verbose { Some(&lockfile.trailers) } else { None },
        };
        let output = serde_json::to_string_pretty(&report)?;
        println!("{}", output);
    } else {
        if verbose {
            for w in &summary.parser_warnings {
                eprintln!("[warn] {}", w);
            }
            eprintln!(
                "[info] trailers: trusted={} overrides={} patched={} catalogs={} workspaces={}",
                lockfile.trailers.trusted_hashes.len(),
                lockfile.trailers.overrides.len(),
                lockfile.trailers.patched.len(),
                lockfile.trailers.catalogs.len(),
                lockfile.trailers.workspaces_count
            );
        }
        render_summary(&summary);
        render_tables(&issues);
    }

    std::process::exit(exit_code);
}

fn collect_issues(
    scan: &ScanResult,
    lockfile: &bun_xray_core::Lockfile,
    parser_warnings: Vec<String>,
    allow_registry: &[String],
    ignore_registry: &[String],
    ignore_package: &[String],
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut id = 1usize;
    let ignore_pkg: HashSet<String> = ignore_package.iter().cloned().collect();

    let mut push_issue = |severity: Severity, kind: &str, pkg: &bun_xray_core::Package, detail: String| {
        if ignore_pkg.contains(&pkg.name) {
            return;
        }
        issues.push(Issue {
            id,
            severity,
            kind: kind.to_string(),
            package: pkg.name.clone(),
            version: pkg.version.clone(),
            detail,
        });
        id += 1;
    };

    for pkg in &scan.integrity_mismatches {
        push_issue(
            Severity::High,
            "integrity_mismatch",
            pkg,
            pkg.integrity_hash.clone().unwrap_or_default(),
        );
    }
    for pkg in &scan.phantom_dependencies {
        push_issue(Severity::Warn, "phantom_dependency", pkg, "Not declared in package.json".into());
    }
    for pkg in &scan.suspicious_versions {
        push_issue(Severity::Warn, "suspicious_version", pkg, pkg.version.clone());
    }
    for pkg in &scan.untrusted_registries {
        if registry_allowed(&pkg.registry_url, allow_registry, ignore_registry) {
            continue;
        }
        push_issue(
            Severity::Warn,
            "untrusted_registry",
            pkg,
            pkg.registry_url.clone(),
        );
    }
    for pkg in &lockfile.packages {
        if pkg.integrity_hash.is_none() && !ignore_pkg.contains(&pkg.name) {
            issues.push(Issue {
                id,
                severity: Severity::Warn,
                kind: "missing_integrity".into(),
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                detail: "No integrity hash".into(),
            });
            id += 1;
        }
    }

    for w in parser_warnings {
        issues.push(Issue {
            id,
            severity: Severity::Warn,
            kind: "parser_warning".into(),
            package: "-".into(),
            version: "-".into(),
            detail: w,
        });
        id += 1;
    }

    issues
}

fn registry_allowed(registry: &str, allow: &[String], ignore: &[String]) -> bool {
    let host = extract_host(registry).unwrap_or(registry).to_ascii_lowercase();
    if ignore.iter().any(|r| host.contains(&r.to_ascii_lowercase())) {
        return true;
    }
    if allow.is_empty() {
        return false;
    }
    allow.iter().any(|r| host.contains(&r.to_ascii_lowercase()))
}

fn decide_exit_code(issues: &[Issue], threshold: Severity) -> i32 {
    let high = issues.iter().any(|i| i.severity == Severity::High);
    let warn = issues.iter().any(|i| i.severity == Severity::Warn);
    let info = issues.iter().any(|i| i.severity == Severity::Info);
    if high && Severity::High >= threshold {
        2
    } else if warn && Severity::Warn >= threshold {
        1
    } else if info && Severity::Info >= threshold {
        1
    } else {
        0
    }
}

fn resolve_package_json(
    lockfile_path: &PathBuf,
    explicit: Option<PathBuf>,
) -> Result<Option<PackageJson>> {
    let candidate = if let Some(path) = explicit {
        Some(path)
    } else {
        lockfile_path
            .parent()
            .map(|p| p.join("package.json"))
            .filter(|p| p.exists())
    };

    match candidate {
        Some(path) => {
            let pkg = load_package_json(path.as_path())
                .with_context(|| format!("failed to load package.json at {}", path.display()))?;
            Ok(Some(pkg))
        }
        None => Ok(None),
    }
}

fn render_summary(sum: &Summary) {
    println!("{} {} packages parsed", "✅".green(), sum.total_packages);
    if sum.high_count == 0 && sum.warn_count == 0 && sum.info_count == 0 {
        println!("{} No findings", "✅".green());
    } else {
        println!(
            "{} Findings: high={}, warn={}, info={}",
            "⚠️".yellow(),
            sum.high_count,
            sum.warn_count,
            sum.info_count
        );
    }
    println!("Exit code on current threshold: {}", sum.exit_code);
}

fn render_tables(issues: &[Issue]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Severity").fg(comfy_table::Color::Blue),
            Cell::new("Package").fg(comfy_table::Color::Blue),
            Cell::new("Version").fg(comfy_table::Color::Blue),
            Cell::new("Kind").fg(comfy_table::Color::Blue),
            Cell::new("Details").fg(comfy_table::Color::Blue),
        ]);

    for issue in issues {
        table.add_row(vec![
            Cell::new(issue.severity.as_str()).fg(issue.severity.color()),
            Cell::new(issue.package.as_str()),
            Cell::new(issue.version.as_str()),
            Cell::new(issue.kind.as_str()),
            Cell::new(issue.detail.as_str()),
        ]);
    }

    if !issues.is_empty() {
        println!("\n{}", table);
    }
}

fn extract_host(url: &str) -> Option<&str> {
    if let Some(rest) = url.split("://").nth(1) {
        return rest.split('/').next();
    }
    url.split('/').next()
}

fn map_binrw_error(err: ParseError) -> anyhow::Error {
    match err {
        ParseError::Binrw(BinrwError::Io(e)) => e.into(),
        _ => err.into(),
    }
}
