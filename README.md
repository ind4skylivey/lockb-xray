# lockb-xray

> Zero-trust auditor for Bun’s binary lockfile (`bun.lockb`). Supply-chain visibility, CI-friendly exits, and stable JSON reports.

![status](https://img.shields.io/badge/status-stable-brightgreen) ![crates.io](https://img.shields.io/crates/v/lockb-xray) ![license](https://img.shields.io/badge/license-MIT-blue)

## Why use it
- **Bun’s lockfile is binary**: invisible to git diffs, easy to smuggle phantom deps or shady registries.
- **Deep parse, no guesses**: `binrw` parser for resolutions (npm/git/github/tarball/workspace), SRI integrity, and trailers (trusted deps, overrides, patched deps, catalogs).
- **Built for CI**: deterministic exit codes, severity thresholds, clean JSON, and knobs to whitelist/ignore registries and packages.

## Install
```bash
cargo install lockb-xray
```

## Quickstart
```bash
lockb-xray audit ./bun.lockb
```
Sample:
```
✅ 1,247 packages parsed
⚠️ Findings: high=1, warn=3, info=0
🚨 high express@4.18.2 integrity_mismatch sha512-...
⚠️ warn lodash@4.17.21 untrusted_registry cdn.jsdelivr.net
```

## CLI essentials
- `--json`                       → JSON only (quiet)
- `--verbose`                   → add parser warnings + trailers to output
- `--severity-threshold <lvl>`  → info|warn|high controls exit code
- `--allow-registry <host>`     → corporate allowlist
- `--ignore-registry <host>`    → silence specific hosts
- `--ignore-package <name>`     → suppress known false positives

Exit codes:
- `0` no findings at/above threshold
- `1` warnings/info (threshold met)
- `2` high/critical (threshold met)

## Stable JSON contract
```jsonc
{
  "summary": {
    "total_packages": 1247,
    "issues_total": 4,
    "high_count": 1,
    "warn_count": 3,
    "info_count": 0,
    "exit_code": 2,
    "parser_warnings": []
  },
  "issues": [
    {
      "id": 1,
      "severity": "high",
      "kind": "integrity_mismatch",
      "package": "express",
      "version": "4.18.2",
      "detail": "sha512-..."
    }
  ],
  "trailers": { /* present only with --verbose */ }
}
```

## CI snippets
### GitHub Actions
```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install lockb-xray
      - run: lockb-xray audit ./bun.lockb --json --severity-threshold warn > lockb-report.json
```

### GitLab CI
```yaml
audit:
  image: rust:latest
  script:
    - cargo install lockb-xray
    - lockb-xray audit ./bun.lockb --json --severity-threshold warn > lockb-report.json
  artifacts:
    paths: [lockb-report.json]
```

## Examples
- `examples/minimal/bun.lockb` — clean baseline.
- `examples/tampered-registry/bun.lockb` — malicious registry (`evil.com`) to trigger warnings.

## Features
- Binary, zero-copy parser with `binrw`.
- Resolutions: npm/git/github/tarball/workspace; SRI integrity decoding.
- Trailers: trusted deps, overrides, patched deps, catalogs, workspaces.
- Fuzz/property tests to guard against crashes on corrupt lockfiles.

## Development
```bash
cargo build --workspace
cargo test
```

## Limitations / Notes
- Future Bun lockfile versions may require parser adjustments.
- Mitigation policies (e.g., blocking registries) are left to your CI/CD or policy engine; we surface findings with clear severities.
