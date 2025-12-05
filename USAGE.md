# lockb-xray – Usage Guide

## Flags (quick matrix)

| Flag | Purpose | Example |
| --- | --- | --- |
| `--json` | Emit JSON only (no tables/logs) | `lockb-xray audit bun.lockb --json` |
| `--verbose` | Include parser warnings + trailers in JSON/stdout | `lockb-xray audit bun.lockb --verbose` |
| `--severity-threshold <info|warn|high>` | Controls exit code gate | `--severity-threshold high` |
| `--allow-registry <host>` | Whitelist registries (multiple allowed) | `--allow-registry npmjs.org --allow-registry registry.internal` |
| `--ignore-registry <host>` | Silence warnings for specific hosts | `--ignore-registry cdn.jsdelivr.net` |
| `--ignore-package <name>` | Suppress findings for packages | `--ignore-package left-pad` |

Exit codes:
- `0` no findings at/above threshold
- `1` info/warn triggered (threshold met)
- `2` high triggered (threshold met)

## Common recipes

**Fail only on HIGH**
```bash
lockb-xray audit bun.lockb --severity-threshold high
```

**Whitelist internal registry, warn on others**
```bash
lockb-xray audit bun.lockb \
  --allow-registry registry.mycorp.local \
  --severity-threshold warn
```

**Quiet JSON for CI artifacts**
```bash
lockb-xray audit bun.lockb --json --severity-threshold warn > lockb-report.json
```

**Ignore a known noisy package**
```bash
lockb-xray audit bun.lockb --ignore-package debug
```

**Verbose parsing + trailers**
```bash
lockb-xray audit bun.lockb --verbose --json > report.json
```
