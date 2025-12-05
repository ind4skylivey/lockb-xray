use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct PackageJson {
    #[serde(rename = "dependencies")]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(rename = "devDependencies")]
    pub dev_dependencies: Option<HashMap<String, String>>,
}

#[derive(Debug, Error)]
pub enum PackageJsonError {
    #[error("failed to read package.json: {0}")]
    Io(#[from] io::Error),
    #[error("failed to parse package.json: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn load_package_json(path: &Path) -> Result<PackageJson, PackageJsonError> {
    let data = fs::read(path)?;
    let parsed = serde_json::from_slice(&data)?;
    Ok(parsed)
}
