use crate::model::{BehaviorFlags, DependencyEntry, Lockfile, Package, ResolutionKind};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use binrw::{binrw, BinRead, BinReaderExt};
use std::fs;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

const MAGIC: &[u8; 42] = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n";
const SUPPORTED_FORMAT: u32 = 3;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid lockfile magic header")]
    InvalidMagic,
    #[error("unsupported lockfile format version {0}")]
    UnsupportedFormat(u32),
    #[error("outdated lockfile format {0}")]
    OutdatedFormat(u32),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("binary parsing error: {0}")]
    Binrw(#[from] binrw::Error),
    #[error("corrupt offsets (start={0}, end={1}, len={2})")]
    CorruptOffsets(u64, u64, usize),
    #[error("string pointer out of bounds (off={0}, len={1})")]
    StringPointer(u32, u32),
    #[error("utf8 error")]
    Utf8,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct PackageTableHeader {
    len: u64,
    alignment: u64,
    field_count: u64,
    begin: u64,
    end: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct ExternalSlice {
    off: u32,
    len: u32,
}

#[binrw]
#[derive(Debug, Clone, Copy)]
struct SemverString {
    bytes: [u8; 8],
}

impl SemverString {
    fn is_inline(&self) -> bool {
        self.bytes[7] & 0x80 == 0
    }
    fn decode(&self, string_bytes: &[u8]) -> Result<String, ParseError> {
        if self.is_inline() {
            let end = self
                .bytes
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(self.bytes.len());
            return std::str::from_utf8(&self.bytes[..end])
                .map(|s| s.to_string())
                .map_err(|_| ParseError::Utf8);
        }
        let raw = u64::from_le_bytes(self.bytes);
        let cleared = raw & !(1u64 << 63);
        let off = (cleared & 0xFFFF_FFFF) as u32;
        let len = (cleared >> 32) as u32;
        let start = off as usize;
        let end = start.checked_add(len as usize).ok_or(ParseError::StringPointer(off, len))?;
        if end > string_bytes.len() {
            return Err(ParseError::StringPointer(off, len));
        }
        std::str::from_utf8(&string_bytes[start..end])
            .map(|s| s.to_string())
            .map_err(|_| ParseError::Utf8)
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct ExternalString {
    value: SemverString,
    hash: u64,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct SemverVersionTag {
    pre: ExternalString,
    build: ExternalString,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct SemverVersion {
    major: u64,
    minor: u64,
    patch: u64,
    tag: SemverVersionTag,
}

impl SemverVersion {
    fn to_string(&self, strings: &[u8]) -> Result<String, ParseError> {
        let mut out = format!("{}.{}.{}", self.major, self.minor, self.patch);
        let pre = self.tag.pre.value.decode(strings)?;
        if !pre.is_empty() {
            out.push('-');
            out.push_str(&pre);
        }
        let build = self.tag.build.value.decode(strings)?;
        if !build.is_empty() {
            out.push('+');
            out.push_str(&build);
        }
        Ok(out)
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct VersionedUrl {
    url: SemverString,
    version: SemverVersion,
}

#[binrw]
#[brw(repr = u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolutionTag {
    Uninitialized = 0,
    Root = 1,
    Npm = 2,
    Folder = 4,
    LocalTarball = 8,
    Github = 16,
    Git = 32,
    Symlink = 64,
    Workspace = 72,
    RemoteTarball = 80,
    SingleFileModule = 100,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct Repository {
    owner: SemverString,
    repo: SemverString,
    committish: SemverString,
    resolved: SemverString,
    package_name: SemverString,
}

#[binrw]
#[derive(Debug, Clone)]
#[br(import(tag: ResolutionTag))]
enum ResolutionValue {
    #[br(pre_assert(tag == ResolutionTag::Uninitialized))]
    Uninitialized,
    #[br(pre_assert(tag == ResolutionTag::Root))]
    Root,
    #[br(pre_assert(tag == ResolutionTag::Npm))]
    Npm(VersionedUrl),
    #[br(pre_assert(tag == ResolutionTag::Folder))]
    Folder(SemverString),
    #[br(pre_assert(tag == ResolutionTag::LocalTarball))]
    LocalTarball(SemverString),
    #[br(pre_assert(tag == ResolutionTag::Github))]
    Github(Repository),
    #[br(pre_assert(tag == ResolutionTag::Git))]
    Git(Repository),
    #[br(pre_assert(tag == ResolutionTag::Symlink))]
    Symlink(SemverString),
    #[br(pre_assert(tag == ResolutionTag::Workspace))]
    Workspace(SemverString),
    #[br(pre_assert(tag == ResolutionTag::RemoteTarball))]
    RemoteTarball(SemverString),
    #[br(pre_assert(tag == ResolutionTag::SingleFileModule))]
    SingleFileModule(SemverString),
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct Resolution {
    tag: ResolutionTag,
    _padding: [u8; 7],
    #[br(args(tag))]
    value: ResolutionValue,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct Integrity {
    tag: u8,
    value: [u8; 64],
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct Meta {
    origin: u8,
    _padding_origin: u8,
    arch: u16,
    os: u16,
    _padding_os: u16,
    id: u32,
    man_dir: SemverString,
    integrity: Integrity,
    has_install_script: u8,
    _padding_integrity: [u8; 2],
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct Bin {
    tag: u8,
    _pad: [u8; 3],
    value: [u8; 16],
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct Scripts {
    preinstall: SemverString,
    install: SemverString,
    postinstall: SemverString,
    preprepare: SemverString,
    prepare: SemverString,
    postprepare: SemverString,
    filled: u8,
    #[br(pad_after = 1)]
    _pad: [u8; 1],
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct DependencyExternal {
    name: SemverString,
    name_hash: u64,
    behavior: u8,
    version_tag: u8,
    version_literal: SemverString,
}

const BUFFER_KINDS: &[BufferKind] = &[
    BufferKind::Dependencies,
    BufferKind::ExternStrings,
    BufferKind::Trees,
    BufferKind::HoistedDependencies,
    BufferKind::Resolutions,
    BufferKind::StringBytes,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferKind {
    Dependencies,
    ExternStrings,
    Trees,
    HoistedDependencies,
    Resolutions,
    StringBytes,
}

impl BufferKind {
    fn alignment(&self) -> usize {
        match self {
            BufferKind::Dependencies => 8,
            BufferKind::ExternStrings => 8,
            BufferKind::Trees => 4,
            BufferKind::HoistedDependencies => 4,
            BufferKind::Resolutions => 4,
            BufferKind::StringBytes => 1,
        }
    }
}

pub fn parse_lockfile(path: &Path) -> Result<Lockfile, ParseError> {
    let bytes = fs::read(path)?;
    let mut cursor = Cursor::new(bytes.as_slice());

    // Header magic
    let mut magic_buf = [0u8; MAGIC.len()];
    cursor.read_exact(&mut magic_buf)?;
    if magic_buf != *MAGIC {
        return Err(ParseError::InvalidMagic);
    }

    let format_version = cursor.read_le::<u32>()?;
    if format_version > SUPPORTED_FORMAT {
        return Err(ParseError::UnsupportedFormat(format_version));
    }

    let mut meta_hash = [0u8; 32];
    cursor.read_exact(&mut meta_hash)?;

    let total_size = cursor.read_le::<u64>()?;
    if total_size as usize > bytes.len() {
        return Err(ParseError::CorruptOffsets(0, total_size, bytes.len()));
    }

    let pkg_header: PackageTableHeader = cursor.read_le()?;
    if pkg_header.end as usize > bytes.len() {
        return Err(ParseError::CorruptOffsets(pkg_header.begin, pkg_header.end, bytes.len()));
    }

    if pkg_header.field_count < 7 {
        return Err(ParseError::OutdatedFormat(format_version));
    }

    // Parse package columns
    let mut pkg_cursor = Cursor::new(bytes.as_slice());
    pkg_cursor.seek(SeekFrom::Start(pkg_header.begin))?;

    let names: Vec<SemverString> = read_array::<SemverString>(&mut pkg_cursor, pkg_header.len as usize)?;
    let _name_hashes: Vec<u64> = read_array::<u64>(&mut pkg_cursor, pkg_header.len as usize)?;
    let resolutions: Vec<Resolution> = read_array::<Resolution>(&mut pkg_cursor, pkg_header.len as usize)?;
    let dep_slices: Vec<ExternalSlice> = read_array::<ExternalSlice>(&mut pkg_cursor, pkg_header.len as usize)?;
    let res_slices: Vec<ExternalSlice> = read_array::<ExternalSlice>(&mut pkg_cursor, pkg_header.len as usize)?;
    let metas: Vec<Meta> = read_array::<Meta>(&mut pkg_cursor, pkg_header.len as usize)?;
    let _bins: Vec<Bin> = read_array::<Bin>(&mut pkg_cursor, pkg_header.len as usize)?;

    let _scripts: Vec<Scripts> = if pkg_header.field_count == 8 {
        read_array::<Scripts>(&mut pkg_cursor, pkg_header.len as usize)?
    } else {
        vec![]
    };

    // Parse buffers
    let buffers_start = pkg_header.end;
    let parsed_buffers = parse_buffers(&bytes, buffers_start as usize)?;

    // Move cursor to end of buffers and read sentinel
    let mut tail_cursor = Cursor::new(bytes.as_slice());
    tail_cursor.seek(SeekFrom::Start(parsed_buffers.end_pos as u64))?;
    let sentinel = tail_cursor.read_le::<u64>()?;
    if sentinel != 0 {
        return Err(ParseError::CorruptOffsets(parsed_buffers.end_pos as u64, sentinel, bytes.len()));
    }

    // Trailers: best-effort skip
    parse_trailers(&mut tail_cursor, total_size)?;

    // Build packages
    let string_bytes = parsed_buffers.string_bytes.as_slice();
    let dependencies = parsed_buffers.dependencies;
    let resolutions_buf = parsed_buffers.resolutions;

    let mut packages = Vec::with_capacity(pkg_header.len as usize);
    for idx in 0..(pkg_header.len as usize) {
        let name = names[idx].decode(string_bytes)?;

        let resolution = decode_resolution(&resolutions[idx], string_bytes)?;
        let integrity_hash = decode_integrity(&metas[idx].integrity);
        let version = resolution
            .as_ref()
            .map(|r| match r {
                ResolutionKind::Npm { version, .. } => version.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let registry_url = resolution
            .as_ref()
            .map(|r| match r {
                ResolutionKind::Npm { registry, .. } => registry.clone(),
                ResolutionKind::RemoteTarball { url } => url.clone(),
                ResolutionKind::LocalTarball { path } => path.clone(),
                ResolutionKind::Git { repo, .. } => repo.clone(),
                ResolutionKind::Github { owner, repo, .. } => format!("{}/{}", owner, repo),
                ResolutionKind::Folder { path } => path.clone(),
                ResolutionKind::Symlink { path } => path.clone(),
                ResolutionKind::Workspace { name } => name.clone(),
                ResolutionKind::SingleFileModule { url } => url.clone(),
                ResolutionKind::Root => String::from("root"),
                ResolutionKind::Unknown(s) => s.clone(),
            })
            .unwrap_or_default();

        let deps = gather_dependencies(
            &dep_slices[idx],
            &res_slices[idx],
            &dependencies,
            &resolutions_buf,
            string_bytes,
        )?;

        packages.push(Package {
            name,
            version,
            registry_url,
            integrity_hash,
            resolution: resolution.unwrap_or(ResolutionKind::Unknown(String::new())),
            dependencies: deps,
        });
    }

    Ok(Lockfile {
        format_version,
        meta_hash,
        packages,
    })
}

fn read_array<T>(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<T>, ParseError>
where
    for<'a> T: BinRead<Args<'a> = ()> + Clone,
{
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let item: T = cursor.read_le()?;
        out.push(item);
    }
    Ok(out)
}

#[derive(Debug)]
struct BuffersParseResult {
    dependencies: Vec<DependencyExternal>,
    resolutions: Vec<u32>,
    string_bytes: Vec<u8>,
    end_pos: usize,
}

fn parse_buffers(bytes: &[u8], start: usize) -> Result<BuffersParseResult, ParseError> {
    // order by alignment desc, tie-stable
    let mut kinds: Vec<BufferKind> = BUFFER_KINDS.to_vec();
    kinds.sort_by(|a, b| b.alignment().cmp(&a.alignment()));

    let mut cursor = Cursor::new(bytes.as_ref());
    cursor.seek(SeekFrom::Start(start as u64))?;

    let mut locations = Vec::with_capacity(kinds.len());
    for _ in &kinds {
        let begin = cursor.read_le::<u64>()?;
        let end = cursor.read_le::<u64>()?;
        locations.push((begin, end));
    }

    let mut deps = Vec::new();
    let mut res = Vec::new();
    let mut string_bytes = Vec::new();
    let mut max_end = start;

    for (kind, (begin_ref, end_ref)) in kinds.iter().zip(locations.iter()) {
        let begin = *begin_ref;
        let end = *end_ref;
        if end < begin || end as usize > bytes.len() {
            return Err(ParseError::CorruptOffsets(begin, end, bytes.len()));
        }
        max_end = max_end.max(end as usize);
        if begin == end {
            continue;
        }
        let slice = &bytes[begin as usize..end as usize];
        match kind {
            BufferKind::Dependencies => {
                let record_size = std::mem::size_of::<DependencyExternal>();
                if slice.len() % record_size != 0 {
                    return Err(ParseError::CorruptOffsets(begin, end, bytes.len()));
                }
                let mut dep_cursor = Cursor::new(slice);
                while (dep_cursor.position() as usize) < slice.len() {
                    let d: DependencyExternal = dep_cursor.read_le()?;
                    deps.push(d);
                }
            }
            BufferKind::Resolutions => {
                let mut res_cursor = Cursor::new(slice);
                while (res_cursor.position() as usize) < slice.len() {
                    res.push(res_cursor.read_le::<u32>()?);
                }
            }
            BufferKind::StringBytes => {
                string_bytes.extend_from_slice(slice);
            }
            _ => {
                // skip trees, hoisted, extern_strings for now
            }
        }
    }

    let ptr_block_end = cursor.position() as usize;

    Ok(BuffersParseResult {
        dependencies: deps,
        resolutions: res,
        string_bytes,
        end_pos: max_end.max(ptr_block_end),
    })
}

fn decode_resolution(res: &Resolution, strings: &[u8]) -> Result<Option<ResolutionKind>, ParseError> {
    let val = match &res.value {
        ResolutionValue::Uninitialized => None,
        ResolutionValue::Root => Some(ResolutionKind::Root),
        ResolutionValue::Npm(vu) => {
            let version = vu.version.to_string(strings)?;
            let registry = vu.url.decode(strings)?;
            Some(ResolutionKind::Npm { version, registry })
        }
        ResolutionValue::Folder(s) => Some(ResolutionKind::Folder {
            path: s.decode(strings)?,
        }),
        ResolutionValue::LocalTarball(s) => Some(ResolutionKind::LocalTarball {
            path: s.decode(strings)?,
        }),
        ResolutionValue::RemoteTarball(s) => Some(ResolutionKind::RemoteTarball {
            url: s.decode(strings)?,
        }),
        ResolutionValue::Symlink(s) => Some(ResolutionKind::Symlink {
            path: s.decode(strings)?,
        }),
        ResolutionValue::Workspace(s) => Some(ResolutionKind::Workspace {
            name: s.decode(strings)?,
        }),
        ResolutionValue::SingleFileModule(s) => Some(ResolutionKind::SingleFileModule {
            url: s.decode(strings)?,
        }),
        ResolutionValue::Git(repo) => Some(ResolutionKind::Git {
            repo: repo.repo.decode(strings)?,
            commit: repo.committish.decode(strings)?,
        }),
        ResolutionValue::Github(repo) => Some(ResolutionKind::Github {
            owner: repo.owner.decode(strings)?,
            repo: repo.repo.decode(strings)?,
            reference: repo.committish.decode(strings)?,
        }),
    };
    Ok(val)
}

fn decode_integrity(int: &Integrity) -> Option<String> {
    match int.tag {
        0 => None,
        1 => Some(format!("sha1-{}", STANDARD_NO_PAD.encode(&int.value[0..20]))),
        2 => Some(format!("sha256-{}", STANDARD_NO_PAD.encode(&int.value[0..32]))),
        3 => Some(format!("sha384-{}", STANDARD_NO_PAD.encode(&int.value[0..48]))),
        4 => Some(format!("sha512-{}", STANDARD_NO_PAD.encode(&int.value[0..64]))),
        _ => None,
    }
}

fn gather_dependencies(
    dep_slice: &ExternalSlice,
    res_slice: &ExternalSlice,
    deps_buf: &[DependencyExternal],
    res_buf: &[u32],
    strings: &[u8],
) -> Result<Vec<DependencyEntry>, ParseError> {
    if dep_slice.off as usize + dep_slice.len as usize > deps_buf.len() {
        return Ok(vec![]);
    }
    let deps = &deps_buf[dep_slice.off as usize..dep_slice.off as usize + dep_slice.len as usize];

    let resolved_ids = if res_slice.off as usize + res_slice.len as usize <= res_buf.len() {
        Some(&res_buf[res_slice.off as usize..res_slice.off as usize + res_slice.len as usize])
    } else {
        None
    };

    let mut out = Vec::with_capacity(deps.len());
    for (i, d) in deps.iter().enumerate() {
        let name = d.name.decode(strings)?;
        let req = d.version_literal.decode(strings)?;
        let behavior = BehaviorFlags::from_bits_truncate(d.behavior);
        let resolved_package_id = resolved_ids.and_then(|ids| ids.get(i)).copied();
        out.push(DependencyEntry {
            name,
            req,
            behavior,
            resolved_package_id,
        });
    }
    Ok(out)
}

fn parse_trailers(cursor: &mut Cursor<&[u8]>, total_size: u64) -> Result<(), ParseError> {
    loop {
        let pos = cursor.position();
        if pos + 8 > total_size {
            break;
        }
        let tag = cursor.read_le::<u64>()?;
        match tag {
            // known tags; skip their payloads using readArray semantics
            t if t == u64::from_le_bytes(*b"wOrKsPaC") => {
                skip_array(cursor)?; // workspace name hashes
                skip_array(cursor)?; // workspace versions
                skip_array(cursor)?; // workspace path hashes
                skip_array(cursor)?; // workspace path strings
            }
            t if t == u64::from_le_bytes(*b"tRuStEDd") => {
                skip_array(cursor)?; // trusted dependencies
            }
            t if t == u64::from_le_bytes(*b"eMpTrUsT") => {
                // empty trusted deps; nothing more
            }
            t if t == u64::from_le_bytes(*b"oVeRriDs") => {
                skip_array(cursor)?; // override name hashes
                skip_array(cursor)?; // override deps
            }
            t if t == u64::from_le_bytes(*b"pAtChEdD") => {
                skip_array(cursor)?; // name+version hashes
                skip_array(cursor)?; // patched deps
            }
            t if t == u64::from_le_bytes(*b"cAtAlOgS") => {
                skip_array(cursor)?; // default names
                skip_array(cursor)?; // default deps
                skip_array(cursor)?; // catalog names
                // inner catalog groups vary; best effort: stop parsing further
                break;
            }
            t if t == u64::from_le_bytes(*b"cNfGvRsN") => {
                // config version u64
                let _ = cursor.read_le::<u64>()?;
            }
            _ => {
                // unknown tag, rewind and stop
                cursor.seek(SeekFrom::Current(-8))?;
                break;
            }
        }
    }
    Ok(())
}

fn skip_array(cursor: &mut Cursor<&[u8]>) -> Result<(), ParseError> {
    let start = cursor.read_le::<u64>()?;
    let end = cursor.read_le::<u64>()?;
    if end < start {
        return Err(ParseError::CorruptOffsets(start, end, 0));
    }
    cursor.seek(SeekFrom::Start(end))?;
    Ok(())
}
