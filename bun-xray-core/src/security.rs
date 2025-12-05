use crate::{Lockfile, Package, PackageJson};
use serde::Serialize;
use std::collections::HashSet;

pub trait SecurityScanner {
    fn scan(&self, package_json: Option<&PackageJson>) -> ScanResult;
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub total_packages: usize,
    pub phantom_dependencies: Vec<Package>,
    pub untrusted_registries: Vec<Package>,
    pub integrity_mismatches: Vec<Package>,
    pub suspicious_versions: Vec<Package>,
}

impl SecurityScanner for Lockfile {
    fn scan(&self, package_json: Option<&PackageJson>) -> ScanResult {
        let declared = build_declared_set(package_json);

        let mut phantom_dependencies = Vec::new();
        let mut untrusted_registries = Vec::new();
        let mut integrity_mismatches = Vec::new();
        let mut suspicious_versions = Vec::new();

        for pkg in &self.packages {
            if let Some(ref deps) = declared {
                if !deps.contains(&pkg.name) {
                    phantom_dependencies.push(pkg.clone());
                }
            }

            if !is_registry_trusted(&pkg.registry_url) {
                untrusted_registries.push(pkg.clone());
            }

            if let Some(ref hash) = pkg.integrity_hash {
                if !is_integrity_valid(hash) {
                    integrity_mismatches.push(pkg.clone());
                }
            }

            if is_version_suspicious(&pkg.version) {
                suspicious_versions.push(pkg.clone());
            }
        }

        ScanResult {
            total_packages: self.packages.len(),
            phantom_dependencies,
            untrusted_registries,
            integrity_mismatches,
            suspicious_versions,
        }
    }
}

fn build_declared_set(package_json: Option<&PackageJson>) -> Option<HashSet<String>> {
    let pj = package_json?;
    let mut set = HashSet::new();
    if let Some(ref deps) = pj.dependencies {
        set.extend(deps.keys().cloned());
    }
    if let Some(ref dev_deps) = pj.dev_dependencies {
        set.extend(dev_deps.keys().cloned());
    }
    Some(set)
}

fn is_registry_trusted(registry_url: &str) -> bool {
    let host = extract_host(registry_url).unwrap_or_default().to_ascii_lowercase();
    host.contains("npmjs.org")
        || host.contains("npmjs.com")
        || host == "npm"
        || host.contains("jsr")
        || host.contains("github.com")
}

fn extract_host(url: &str) -> Option<&str> {
    if let Some(rest) = url.split("://").nth(1) {
        return rest.split('/').next();
    }
    url.split('/').next()
}

fn is_integrity_valid(hash: &str) -> bool {
    let h = hash.trim().to_ascii_lowercase();
    h.starts_with("sha") && h.len() > 10
}

fn is_version_suspicious(version: &str) -> bool {
    let v = version.trim();
    v.starts_with("git+")
        || v.contains("://")
        || v.starts_with("file:")
        || v.contains('#')
        || v.contains('-')
}
