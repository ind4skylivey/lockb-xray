# Security Notes

## Threat model
- **Phantom dependencies**: packages present in `bun.lockb` but not declared in `package.json`.
- **Registry hijack / spoofing**: dependencies resolved from non-standard or malicious registries.
- **Integrity gaps**: missing or mismatched SRI hashes on resolved artifacts.
- **Override / patched manipulation**: trailers carrying overrides or patch directives that change what gets installed.

## What lockb-xray checks
- Parses `bun.lockb` binary format (v3) including trailers.
- Flags phantom deps, untrusted registries, suspicious versions (git/file/prerelease), integrity mismatches/absent hashes.
- Surfaces trailers: trusted deps, overrides, patched deps, catalogs, workspaces.
- Validates offsets and ranges to avoid panic on corrupt files.

## What it does NOT do
- It does not fetch/install packages or verify remote signatures.
- It does not enforce policies; it reports findings with severities.
- It does not yet validate SRI hashes against downloaded content.

## Safe handling
- lockb-xray is read-only: it does not execute scripts or load remote code.
- Use `--json` for CI to avoid mixed logs; `--severity-threshold` to gate builds.
- Keep Bun versions aligned; future lockfile versions may require parser updates.
