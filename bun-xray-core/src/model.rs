use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub registry_url: String,
    pub integrity_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    pub version: u32,
    pub packages: Vec<Package>,
}
