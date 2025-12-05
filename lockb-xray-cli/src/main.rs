use anyhow::{Context, Result};
use binrw::Error as BinrwError;
use bun_xray_core::{
    load_package_json, parse_lockfile_with_warnings, PackageJson, ParseError, ScanResult,
    SecurityScanner,
};
use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
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
        /// Optional package.json path (defaults to sibling of lockfile)
        #[arg(long = "package-json", value_name = "PATH")]
        package_json: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Audit {
            path,
            json,
            verbose,
            package_json,
        } => run_audit(path, json, verbose, package_json)?,
    }
    Ok(())
}

fn run_audit(path: PathBuf, json: bool, verbose: bool, package_json: Option<PathBuf>) -> Result<()> {
    let lockfile_path = path.clone();
    let (lockfile, warnings) =
        parse_lockfile_with_warnings(lockfile_path.as_path()).map_err(map_binrw_error)?;

    let package_json = resolve_package_json(&lockfile_path, package_json)?;
    let scan = lockfile.scan(package_json.as_ref());

    if verbose {
        for w in warnings {
            eprintln!("[warn] {}", w);
        }
        if lockfile.trailers.has_empty_trusted {
            eprintln!("[info] trustedDependencies present but empty");
        }
        if !lockfile.trailers.trusted_hashes.is_empty() {
            eprintln!(
                "[info] trustedDependencies count={}",
                lockfile.trailers.trusted_hashes.len()
            );
        }
        if lockfile.trailers.overrides_count > 0 {
            eprintln!(
                "[info] overrides entries={}",
                lockfile.trailers.overrides_count
            );
        }
        if lockfile.trailers.patched_count > 0 {
            eprintln!(
                "[info] patched dependencies={}",
                lockfile.trailers.patched_count
            );
        }
        if lockfile.trailers.catalogs_count > 0 {
            eprintln!("[info] catalogs groups={}", lockfile.trailers.catalogs_count);
        }
        if lockfile.trailers.workspaces_count > 0 {
            eprintln!(
                "[info] workspace packages={}",
                lockfile.trailers.workspaces_count
            );
        }
    }

    if json {
        let output = serde_json::to_string_pretty(&scan)?;
        println!("{}", output);
        return Ok(());
    }

    render_summary(&scan);
    render_tables(&scan);
    Ok(())
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

fn render_summary(scan: &ScanResult) {
    println!("{} {} packages parsed", "✅".green(), scan.total_packages);

    if scan.phantom_dependencies.is_empty() {
        println!("{} No phantom dependencies", "✅".green());
    } else {
        println!(
            "{} {} phantom dependencies",
            "🚨".red(),
            scan.phantom_dependencies.len()
        );
    }

    if scan.untrusted_registries.is_empty() {
        println!("{} All registries trusted", "✅".green());
    } else {
        let summary = summarize_registry_counts(&scan.untrusted_registries);
        println!(
            "{} {} packages from untrusted registry ({})",
            "⚠️".yellow(),
            scan.untrusted_registries.len(),
            summary
        );
    }

    if scan.integrity_mismatches.is_empty() {
        println!("{} Integrity OK", "✅".green());
    } else {
        let top = &scan.integrity_mismatches[0];
        println!(
            "{} HIGH: {}@{} integrity mismatch",
            "🚨".red(),
            top.name,
            top.version
        );
    }
}

fn render_tables(scan: &ScanResult) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Issue").fg(comfy_table::Color::Blue),
            Cell::new("Package").fg(comfy_table::Color::Blue),
            Cell::new("Version").fg(comfy_table::Color::Blue),
            Cell::new("Registry").fg(comfy_table::Color::Blue),
        ]);

    for pkg in &scan.phantom_dependencies {
        table.add_row(vec![
            Cell::new("Phantom").fg(comfy_table::Color::Red),
            Cell::new(pkg.name.as_str()),
            Cell::new(pkg.version.as_str()),
            Cell::new(pkg.registry_url.as_str()),
        ]);
    }

    for pkg in &scan.untrusted_registries {
        table.add_row(vec![
            Cell::new("Untrusted Registry").fg(comfy_table::Color::Yellow),
            Cell::new(pkg.name.as_str()),
            Cell::new(pkg.version.as_str()),
            Cell::new(pkg.registry_url.as_str()),
        ]);
    }

    for pkg in &scan.integrity_mismatches {
        table.add_row(vec![
            Cell::new("Integrity Mismatch").fg(comfy_table::Color::Red),
            Cell::new(pkg.name.as_str()),
            Cell::new(pkg.version.as_str()),
            Cell::new(pkg.registry_url.as_str()),
        ]);
    }

    for pkg in &scan.suspicious_versions {
        table.add_row(vec![
            Cell::new("Suspicious Version").fg(comfy_table::Color::Yellow),
            Cell::new(pkg.name.as_str()),
            Cell::new(pkg.version.as_str()),
            Cell::new(pkg.registry_url.as_str()),
        ]);
    }

    if !table.is_empty() {
        println!("\n{}", table);
    }
}

fn summarize_registry_counts(packages: &[bun_xray_core::Package]) -> String {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for pkg in packages {
        let host = extract_host(&pkg.registry_url).unwrap_or("unknown").to_string();
        *counts.entry(host).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(host, count)| format!("{}: {}", host, count))
        .collect::<Vec<_>>()
        .join(", ")
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
