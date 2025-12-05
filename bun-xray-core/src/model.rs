use bitflags::bitflags;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ResolutionKind {
    Root,
    Npm { version: String, registry: String },
    Git { repo: String, commit: String },
    Github { owner: String, repo: String, reference: String },
    Folder { path: String },
    Symlink { path: String },
    Workspace { name: String },
    LocalTarball { path: String },
    RemoteTarball { url: String },
    SingleFileModule { url: String },
    Unknown(String),
}

bitflags! {
    #[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
    pub struct BehaviorFlags: u8 {
        const PROD      = 1 << 1;
        const OPTIONAL  = 1 << 2;
        const DEV       = 1 << 3;
        const PEER      = 1 << 4;
        const WORKSPACE = 1 << 5;
        const BUNDLED   = 1 << 6;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DependencyEntry {
    pub name: String,
    pub req: String,
    pub behavior: BehaviorFlags,
    pub resolved_package_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub registry_url: String,
    pub integrity_hash: Option<String>,
    pub resolution: ResolutionKind,
    pub dependencies: Vec<DependencyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub format_version: u32,
    pub meta_hash: [u8; 32],
    pub packages: Vec<Package>,
    pub trailers: TrailerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrailerInfo {
    pub trusted_hashes: Vec<u32>,
    pub has_empty_trusted: bool,
    pub overrides: Vec<OverrideEntry>,
    pub patched: Vec<PatchedEntry>,
    pub catalogs: Vec<CatalogGroup>,
    pub default_catalog: Vec<DependencyEntry>,
    pub workspaces_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverrideEntry {
    pub name_hash: u64,
    pub dependency: DependencyEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchedEntry {
    pub name_version_hash: u64,
    pub path: String,
    pub patch_hash: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogGroup {
    pub name: String,
    pub dependencies: Vec<DependencyEntry>,
}
