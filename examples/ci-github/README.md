# GitHub Actions example

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install lockb-xray
      - run: lockb-xray audit ./bun.lockb --json --severity-threshold warn > lockb-report.json
    artifacts:
      name: lockb-xray
      files: lockb-report.json
```
