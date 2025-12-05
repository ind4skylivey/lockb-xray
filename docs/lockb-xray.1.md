# lockb-xray(1)

CLI auditor for Bun `bun.lockb` lockfiles.

## SYNOPSIS
```
lockb-xray audit <path> [--json] [--verbose] [--severity-threshold <lvl>]
                  [--allow-registry <host>]... [--ignore-registry <host>]...
                  [--ignore-package <name>]... [--package-json <path>]
```

## DESCRIPTION
Parses Bun binary lockfiles, surfaces supply-chain risks, and exits with CI-friendly codes.

## OPTIONS
- `--json`  
  Emit JSON only.
- `--verbose`  
  Add parser warnings and trailers to output.
- `--severity-threshold <info|warn|high>`  
  Controls exit code gate (default: warn).
- `--allow-registry <host>`  
  Registries considered trusted (may be repeated).
- `--ignore-registry <host>`  
  Silence findings for specific registries (may be repeated).
- `--ignore-package <name>`  
  Ignore findings for packages (may be repeated).
- `--package-json <path>`  
  Optional path to `package.json` for phantom-dependency detection.

## EXIT STATUS
0: no findings at/above threshold  
1: info/warn findings (threshold met)  
2: high findings (threshold met)

## EXAMPLES
```
lockb-xray audit bun.lockb
lockb-xray audit bun.lockb --json --severity-threshold high
lockb-xray audit bun.lockb --allow-registry registry.internal --verbose
```
