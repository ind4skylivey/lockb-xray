# Changelog

## v0.1.0
- Initial public release of `lockb-xray`.
- Full `bun.lockb` v3 parser with columnar offsets, trailers, integrity decoding.
- Security scanning: phantom deps, untrusted registries, integrity mismatches, suspicious versions.
- CLI: JSON contract (`summary`, `issues`), severity thresholds, CI-friendly exit codes, verbose trailers, registry/package ignore lists.
- Examples: minimal and tampered lockfiles for demos/tests.
- Fuzz/property test to avoid panics on corrupt lockfiles.
