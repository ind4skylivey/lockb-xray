use bun_xray_core::parser::parse_lockfile;
use std::io::Write;
use tempfile::NamedTempFile;

fn encode_inline(s: &str) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    let slice = s.as_bytes();
    let n = slice.len().min(8);
    bytes[..n].copy_from_slice(&slice[..n]);
    bytes
}

fn build_min_lockb() -> Vec<u8> {
    const MAGIC: &[u8; 42] = b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n";
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);

    // format version
    buf.extend_from_slice(&3u32.to_le_bytes());
    // meta hash
    buf.extend_from_slice(&[0u8; 32]);
    // placeholder total_size
    buf.extend_from_slice(&[0u8; 8]);

    // package table header placeholders (len=1, alignment=8, field_count=7)
    let len = 1u64;
    let alignment = 8u64;
    let field_count = 7u64;

    // we will fill begin/end later
    let begin_off_pos = buf.len() + 8 + 8 + 8; // after len,alignment,field_count

    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&alignment.to_le_bytes());
    buf.extend_from_slice(&field_count.to_le_bytes());
    buf.extend_from_slice(&[0u8; 8]); // begin
    buf.extend_from_slice(&[0u8; 8]); // end

    // align to 8 (already aligned)
    let begin_at = buf.len();

    // column: names (SemverString) length 1
    buf.extend_from_slice(&encode_inline("foo"));
    // name_hash u64
    buf.extend_from_slice(&0u64.to_le_bytes());

    // resolution (tag=2 npm)
    buf.push(2u8); // tag
    buf.extend_from_slice(&[0u8; 7]); // padding
    // VersionedUrl.url
    buf.extend_from_slice(&encode_inline("npm"));
    // SemverVersion
    buf.extend_from_slice(&1u64.to_le_bytes()); // major
    buf.extend_from_slice(&0u64.to_le_bytes()); // minor
    buf.extend_from_slice(&0u64.to_le_bytes()); // patch
    // tag.pre ExternalString (SemverString + hash)
    buf.extend_from_slice(&[0u8; 8]); // pre value
    buf.extend_from_slice(&0u64.to_le_bytes()); // pre hash
    // tag.build ExternalString
    buf.extend_from_slice(&[0u8; 8]); // build value
    buf.extend_from_slice(&0u64.to_le_bytes()); // build hash

    // dep slice
    buf.extend_from_slice(&0u32.to_le_bytes()); // off
    buf.extend_from_slice(&0u32.to_le_bytes()); // len
    // res slice
    buf.extend_from_slice(&0u32.to_le_bytes()); // off
    buf.extend_from_slice(&0u32.to_le_bytes()); // len

    // meta
    buf.push(1u8); // origin npm
    buf.push(0u8); // padding origin
    buf.extend_from_slice(&0u16.to_le_bytes()); // arch
    buf.extend_from_slice(&0u16.to_le_bytes()); // os
    buf.extend_from_slice(&0u16.to_le_bytes()); // padding os
    buf.extend_from_slice(&0u32.to_le_bytes()); // id
    buf.extend_from_slice(&encode_inline("")); // man_dir empty
    // integrity (tag sha1, 20 bytes of 0x11)
    buf.push(1u8); // tag
    let mut integrity = [0u8; 64];
    for b in integrity[..20].iter_mut() {
        *b = 0x11;
    }
    buf.extend_from_slice(&integrity);
    buf.push(1u8); // has_install_script = false (1)
    buf.extend_from_slice(&[0u8; 2]); // padding

    // bin
    buf.push(0u8); // tag none
    buf.extend_from_slice(&[0u8; 3]); // pad
    buf.extend_from_slice(&[0u8; 16]); // value

    let end_at = buf.len();

    // backfill begin/end
    let begin_bytes = (begin_at as u64).to_le_bytes();
    let end_bytes = (end_at as u64).to_le_bytes();
    buf[begin_off_pos..begin_off_pos + 8].copy_from_slice(&begin_bytes);
    buf[begin_off_pos + 8..begin_off_pos + 16].copy_from_slice(&end_bytes);

    // buffer pointers (6 kinds)
    // Dependencies, ExternStrings, Trees, HoistedDeps, Resolutions, StringBytes
    let _ptr_block_start = buf.len();
    for _ in 0..6 {
        buf.extend_from_slice(&(end_at as u64).to_le_bytes()); // begin
        buf.extend_from_slice(&(end_at as u64).to_le_bytes()); // end
    }

    // sentinel
    buf.extend_from_slice(&0u64.to_le_bytes());

    // trailers none

    // total_size = buf.len()
    let total_size = buf.len() as u64;
    let total_bytes = total_size.to_le_bytes();
    let total_pos = MAGIC.len() + 4 + 32; // after magic+format+meta_hash
    buf[total_pos..total_pos + 8].copy_from_slice(&total_bytes);

    buf
}

#[test]
fn parse_min_lockb() {
    let data = build_min_lockb();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&data).unwrap();
    let lock = parse_lockfile(tmp.path()).expect("parse");
    assert_eq!(lock.packages.len(), 1);
    let pkg = &lock.packages[0];
    assert_eq!(pkg.name, "foo");
    assert_eq!(pkg.version, "1.0.0");
    assert_eq!(pkg.registry_url, "npm");
    assert!(pkg.integrity_hash.is_some());
}
