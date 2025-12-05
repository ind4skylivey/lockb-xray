# GitLab CI example

```yaml
audit:
  image: rust:latest
  script:
    - cargo install lockb-xray
    - lockb-xray audit ./bun.lockb --json --severity-threshold warn > lockb-report.json
  artifacts:
    paths:
      - lockb-report.json
```
