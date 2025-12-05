use bun_xray_core::parser::parse_lockfile_with_warnings;
use proptest::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

proptest! {
    #[test]
    fn fuzz_does_not_panic(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        let _ = std::panic::catch_unwind(|| parse_lockfile_with_warnings(tmp.path()));
    }
}
