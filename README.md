# lockb-xray · 🔎🛡️

<p align="center">
  <img src="docs/assets/banner.png" alt="lockb-xray banner" width="90%" />
</p>

*For when `bun.lockb` looks clean in Git, but your gut says “something’s off.”*

[![crates.io](https://img.shields.io/crates/v/lockb-xray?color=4caf50&logo=rust)](https://crates.io/crates/lockb-xray)
[![docs](https://img.shields.io/badge/docs-usage-blueviolet)](USAGE.md)
[![schema](https://img.shields.io/badge/json-schema-teal)](SCHEMA.md)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

`lockb-xray` is a Rust forensic CLI that opens Bun’s binary lockfile (`bun.lockb`) and asks the only supply-chain question that really matters: **what is actually going to be installed?** It turns Bun’s opaque, columnar lockfile into a clear, security-focused report for CI, code review, and incident response.

---

## Why this exists

Bun’s original `.lockb` format is compact and fast, but it’s also binary and columnar—almost invisible in a PR diff. That’s great for performance, but not great when you’re trying to spot:

- a dependency that appears *only* in the lockfile,
- a registry URL that suddenly points somewhere new, or
- an override or patch that quietly changes what gets pulled into production.

`lockb-xray` exists because “just trust the lockfile” is not an acceptable answer when you care about supply-chain security.

---

## Why use it

- **Bun’s lockfile is binary** → invisible to git diffs; perfect for phantom deps and registry swaps if nobody is watching.
- **Deterministic parser** → `binrw`-based decoding of resolutions, integrity, and trailers (trusted deps, overrides, patches, catalogs, workspaces).
- **CI-native** → severity thresholds, clean JSON, exit codes 0/1/2, allow/ignore knobs, designed to live in pipelines.
- **Local & read-only** → never crawls the web; it only parses your existing `bun.lockb` and optional `package.json`.

---

## Features at a glance

- 🔍 **Binary lockfile introspection** — understands Bun’s columnar package tables, shared buffers, and trailer sections (trusted, overrides, patched, catalogs, workspaces, config version).
- 🧠 **Supply-chain checks** — detects phantom deps, untrusted registries, suspicious git/file/tarball resolutions, integrity gaps, and format/version issues you shouldn’t ignore.
- 🧪 **Safety under fuzz** — structured parsing plus corruption tests to avoid panics when `bun.lockb` is truncated, malformed, or hostile.
- 🛠️ **Workspace-aware** — understands Bun trailers for workspaces, trusted dependencies, overrides, patches, and catalogs, so modern monorepos don’t confuse the analysis.
- 🖥️ **CI-ready** — colorful human output for local runs, and a stable JSON contract + deterministic exit codes for machines.

---

## Install

### Easiest (published crate)
```bash
cargo install lockb-xray
```

### From source
```bash
git clone https://github.com/ind4skylivey/lockb-xray.git
cd lockb-xray
cargo build --release
# binary at target/release/lockb-xray
```

---

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

Exactly the kind of output you want to see in CI logs at 03:00 when something feels off.

---

## Exit codes & CI

- `0` – No issues at/above the configured severity threshold.
- `1` – Only warnings/info at or above threshold.
- `2` – At least one HIGH severity finding (integrity mismatch, clearly suspicious registry, etc.).

Minimal GitHub Actions example:
```yaml
- name: Audit Bun lockfile
  run: |
    lockb-xray audit ./bun.lockb --json --severity-threshold warn > lockb-report.json
```
Use the JSON for policy enforcement, or rely on exit codes to fail the job.

---

## JSON contract (stable)

See **SCHEMA.md** for full details. In TypeScript notation:
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

interface Report {
  summary: Summary;
  issues: Issue[];
  trailers?: any;
}
```

This is the contract `--json` adheres to so you can build policies, dashboards, or alerts on top.

---

## What lockb-xray inspects

At a high level, the tool reconstructs a semantic model of your lockfile:

- **Packages** — name, version, registry/URL.
- **Resolutions** — npm/git/github/tarball/workspace, including owner/repo/commit for git-like variants.
- **Integrity** — mapped into SRI-like strings where possible, or flagged as unknown.
- **Behavior flags** — prod/dev/optional/peer/workspace bitfield, mapped to a strongly-typed representation.
- **Trailers** — workspaces, trusted dependencies, overrides, patched deps, catalogs, and config version.

Typical findings include:

- “Package X only exists in bun.lockb, not in package.json (phantom dep).”
- “Dependency Y resolves from untrusted registry Z.”
- “Patched dependency modifies its resolved URL away from the canonical registry.”
- “Lockfile format version is newer than supported; refuse to trust it.”

---

## When to run it

- Before merging any PR that changes `bun.lockb`.
- As a mandatory CI step for services and monorepos using Bun’s package manager.
- During incident response when a dependency, override, or patch looks suspicious.
- Whenever a binary lockfile deciding your dependency tree makes you raise an eyebrow.

---

## Lockfile layout (mental map)

You don’t need to know this to use the tool, but it helps understand what `lockb-xray` walks through:
```
magic + format + meta_hash
package table:
  [names][name_hashes][resolutions][dep_slices][res_slices][meta][bin][scripts?]
buffers:
  dependencies | resolutions | string_bytes | ...
sentinel (0)
trailers:
  trusted / overrides / patched / catalogs / workspaces / config_version
```

---

## Examples

- `examples/minimal/bun.lockb` — clean baseline.
- `examples/tampered-registry/bun.lockb` — malicious registry (`evil.com`) to trigger warnings.
- `examples/override-malicious/` — override trailer illustration.
- `examples/patched-dep/` — patched dependency illustration.
- CI snippets in `examples/ci-github` and `examples/ci-gitlab`.

---

## From the author

`lockb-xray` started with a simple, slightly uncomfortable moment: staring at a `bun.lockb` in a security review and realizing that a binary blob was effectively deciding my dependency tree.

As someone who lives between backend work, reverse engineering, and malware analysis, “it’s probably fine” is not a workflow. This project became a way to:

- treat Bun’s lockfile format as something to be **understood**, not just trusted,
- have a small, focused tool that can drop into CI and stay silent until it needs to scream, and
- use Rust as a forensic language against a real, fast-moving ecosystem instead of a toy binary.

If you also get uneasy when a lockfile is too binary and too quiet, this tool is for you.

---

## Development

```bash
cargo build --workspace
cargo test
```

---

## Limitations / Notes

- Future Bun lockfile versions may require parser tweaks or additional rules as the ecosystem shifts (especially with the move toward text lockfiles).
- Mitigation and enforcement are intentionally left to your policy layer; `lockb-xray` focuses on accurate parsing, classification, and clear severities/exit codes.

---

## Design notes

- **Parser fidelity** — The binary layout (header, columnar tables, buffers, trailers) follows Bun’s implementation and published lockfile documentation; there is no speculative guessing.
- **Semantics** — Workspaces, trusted dependencies, overrides, patches, and catalogs are interpreted according to Bun’s package manager behavior, including newer trailers like trusted deps and workspace metadata.
- **Forward path** — As Bun moves toward a text lockfile, `lockb-xray` aims to remain a faithful, independent implementation of the legacy binary format for long-lived projects, audits, and post-incident forensics.
