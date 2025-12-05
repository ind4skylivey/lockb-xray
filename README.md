# lockb-xray · 🔎🛡️

*For when `bun.lockb` looks clean in Git, but your gut says “something’s off.”*

[![crates.io](https://img.shields.io/crates/v/lockb-xray?color=4caf50&logo=rust)](https://crates.io/crates/lockb-xray)
[![docs](https://img.shields.io/badge/docs-usage-blueviolet)](USAGE.md)
[![schema](https://img.shields.io/badge/json-schema-teal)](SCHEMA.md)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

`lockb-xray` is a Rust forensic CLI that opens Bun’s binary lockfile (`bun.lockb`) and asks the only supply-chain question that matters: **what is actually going to be installed?** It turns Bun’s opaque, columnar lockfile into a clear, security-focused report for CI, code review, and incident response.

## Why use it
- **Bun’s lockfile is binary** → invisible to git diffs; perfect for phantom deps and registry swaps.
- **Deterministic parser** → `binrw` structs for resolutions, integrity, trailers (trusted deps, overrides, patches, catalogs).
- **CI-native** → severity thresholds, clean JSON, exit codes 0/1/2, allow/ignore knobs.
- **Local & read-only** → never crawls the web; only parses your existing `bun.lockb`.

## Features at a glance
- 🔍 Binary lockfile introspection (columnar tables, shared buffers, trailers).
- 🧠 Supply-chain checks: phantom deps, untrusted registries, suspicious git/file/tarball resolutions, integrity gaps.
- 🧪 Fuzz/property tests to guard against corrupt lockfiles.
- 🛠️ Workspace-aware: understands Bun trailers (trusted deps, overrides, patches, catalogs, workspaces).
- 🖥️ CI-ready: colorful human output + stable JSON contract and deterministic exit codes.

## Install
```bash
cargo install lockb-xray
```

## Quick start
```bash
# Simple run
lockb-xray audit ./bun.lockb

# Explicit manifest (monorepo / non-standard layout)
lockb-xray audit ./bun.lockb --package-json ./package.json

# Verbose: include trailers and parser warnings
lockb-xray audit ./bun.lockb --verbose
```

Example (verbose):
```
✅ 1,247 packages parsed
✅ No phantom dependencies
⚠️  3 packages from untrusted registry (jsdelivr)
⚠️  2 overrides modify resolution URLs
🚨 HIGH: express@4.18.2 integrity mismatch
```

## Exit codes & CI
- `0` – No issues at/above threshold.
- `1` – Warnings/info (threshold met).
- `2` – At least one HIGH finding (integrity mismatch, malicious registry, etc.).

GitHub Actions (minimal):
```yaml
- name: Audit Bun lockfile
  run: |
    lockb-xray audit ./bun.lockb --json --severity-threshold warn > lockb-report.json
```
Use the JSON for policy, or rely on exit codes.

## JSON contract (stable)
See **SCHEMA.md** for full details. Shape (TypeScript):
```ts
interface Summary {
  total_packages: number;
  issues_total: number;
  high_count: number;
  warn_count: number;
  info_count: number;
  exit_code: number;
  parser_warnings: string[];
}

interface Issue {
  id: number;
  severity: "info" | "warn" | "high";
  kind: string;
  package: string;
  version: string;
  detail: string;
}

interface Report { summary: Summary; issues: Issue[]; trailers?: any; }
```

## What lockb-xray inspects
- Packages: name, version, registry/URL.
- Resolutions: npm/git/github/tarball/workspace (owner/repo/commit for git).
- Integrity: SRI-like strings or unknown.
- Behavior flags: prod/dev/optional/peer/workspace bitfield.
- Trailers: workspaces, trusted deps, overrides, patched deps, catalogs.

Findings include:
- “Package X only exists in bun.lockb, not in package.json (phantom dep).”
- “Dependency Y resolves from untrusted registry Z.”
- “Patched dependency modifies its resolved URL away from the canonical registry.”
- “Lockfile format version is newer than supported; refuse to trust it.”

## When to run it
- Before merging any PR that changes `bun.lockb`.
- As a mandatory CI step for Bun services and monorepos.
- During incident response when a dependency, override, or patch looks suspicious.

## Lockfile layout (mental map)
```
magic + format + meta_hash
package table:
  [names][name_hashes][resolutions][dep_slices][res_slices][meta][bin][scripts?]
buffers:
  dependencies | resolutions | string_bytes | ...
sentinel (0)
trailers: trusted / overrides / patched / catalogs / workspaces / config_version
```

## Examples
- `examples/minimal/bun.lockb` — clean baseline.
- `examples/tampered-registry/bun.lockb` — malicious registry (`evil.com`) to trigger warnings.
- `examples/override-malicious/` — override trailer illustration.
- `examples/patched-dep/` — patched dependency illustration.
- CI snippets in `examples/ci-github` and `examples/ci-gitlab`.

## Development
```bash
cargo build --workspace
cargo test
```

## Limitations / Notes
- Future Bun lockfile versions may need parser tweaks.
- Mitigation/enforcement is up to your policy layer; lockb-xray reports with severities and exit codes.

## Design notes
- Parser fidelity: the binary layout (header, columnar tables, buffers, trailers) follows Bun’s own implementation and public docs; no guessing.
- Semantics: workspaces, trusted dependencies, overrides, patches, and catalogs are interpreted per Bun’s package manager behavior (including newer trailers).
- Forward path: as Bun moves toward text lockfiles, lockb-xray remains a faithful, independent implementation of the legacy binary format for audits and forensics.
