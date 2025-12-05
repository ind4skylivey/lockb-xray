use crate::model::{Lockfile, Package};
use binrw::{binrw, BinReaderExt};
use std::fs;
use std::io::Cursor;
use std::path::Path;
use thiserror::Error;

#[binrw]
#[derive(Debug, Clone)]
#[brw(little)]
struct RawHeader {
    magic: [u8; 7],
    version: u32,
    package_count: u64,
}

#[binrw]
#[derive(Debug, Clone)]
#[brw(little)]
struct RawPackageEntry {
    name_offset: u32,
    version_offset: u32,
    registry_offset: u32,
    integrity_offset: u32,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid bun.lockb magic header")]
    InvalidMagic,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("binary parsing error: {0}")]
    Binrw(#[from] binrw::Error),
    #[error("offset {0} out of bounds")]
    OffsetOutOfBounds(u32),
    #[error("string decode error at offset {0}")]
    StringDecode(u32),
}

pub fn parse_lockfile(path: &Path) -> Result<Lockfile, ParseError> {
    let bytes = fs::read(path)?;
    let mut cursor = Cursor::new(&bytes);

    let header: RawHeader = cursor.read_le()?;
    if &header.magic != b"BUNLOCK" {
        return Err(ParseError::InvalidMagic);
    }

    let mut entries = Vec::with_capacity(header.package_count as usize);
    for _ in 0..header.package_count {
        entries.push(cursor.read_le::<RawPackageEntry>()?);
    }

    let string_table_start = cursor.position() as usize;
    let string_table = &bytes[string_table_start..];

    let mut packages = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = resolve_string(string_table, entry.name_offset)?;
        let version = resolve_string(string_table, entry.version_offset)?;
        let registry_url = resolve_string(string_table, entry.registry_offset)?;
        let integrity_hash = if entry.integrity_offset == 0 {
            None
        } else {
            Some(resolve_string(string_table, entry.integrity_offset)?)
        };

        packages.push(Package {
            name,
            version,
            registry_url,
            integrity_hash,
        });
    }

    Ok(Lockfile {
        version: header.version,
        packages,
    })
}

fn resolve_string(table: &[u8], offset: u32) -> Result<String, ParseError> {
    let start = offset as usize;
    if start >= table.len() {
        return Err(ParseError::OffsetOutOfBounds(offset));
    }

    let slice = &table[start..];
    let end = slice
        .iter()
        .position(|b| *b == 0)
        .unwrap_or_else(|| slice.len());
    let raw = &slice[..end];
    let value = std::str::from_utf8(raw).map_err(|_| ParseError::StringDecode(offset))?;
    Ok(value.to_owned())
}
