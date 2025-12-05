# lockb-xray

CLI forensic tool to audit Bun `bun.lockb` binary lockfiles for supply chain risks.

## Workspace

```
lockb-xray/
├── Cargo.toml
├── bun-xray-core/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── model.rs
│       ├── package_json.rs
│       ├── parser.rs
│       └── security.rs
└── lockb-xray-cli/
    ├── Cargo.toml
    └── src/
        └── main.rs
```

## Install

```bash
cargo install --path lockb-xray-cli
```

## Usage

```bash
lockb-xray audit ./bun.lockb
```

Example output:

```
$ lockb-xray audit ./bun.lockb
✅ 1,247 packages parsed
✅ No phantom dependencies
⚠️ 3 packages from untrusted registry (jsdelivr)
🚨 HIGH: express@4.18.2 integrity mismatch
```

JSON mode:

```bash
lockb-xray audit ./bun.lockb --json
```

## Development

```bash
cargo build --workspace
```
