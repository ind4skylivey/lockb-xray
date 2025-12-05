# lockb-xray JSON Schema (stable contract)

Versioning: maintained under semver. For 0.x we keep the structure compatible; new fields will be additive.

## TypeScript interfaces (source of truth)
```ts
export interface Summary {
  total_packages: number;
  issues_total: number;
  high_count: number;
  warn_count: number;
  info_count: number;
  exit_code: number;
  parser_warnings: string[];
}

export interface Issue {
  id: number;
  severity: "info" | "warn" | "high";
  kind: string;          // e.g. integrity_mismatch, phantom_dependency, untrusted_registry
  package: string;
  version: string;
  detail: string;
}

export interface Report {
  summary: Summary;
  issues: Issue[];
  trailers?: any; // only when --verbose, mirrors Bun trailer data
}
```

## Example: clean lockfile
```json
{
  "summary": {
    "total_packages": 3,
    "issues_total": 0,
    "high_count": 0,
    "warn_count": 0,
    "info_count": 0,
    "exit_code": 0,
    "parser_warnings": []
  },
  "issues": []
}
```

## Example: tampered registry + override
```json
{
  "summary": {
    "total_packages": 2,
    "issues_total": 2,
    "high_count": 1,
    "warn_count": 1,
    "info_count": 0,
    "exit_code": 2,
    "parser_warnings": []
  },
  "issues": [
    {
      "id": 1,
      "severity": "high",
      "kind": "untrusted_registry",
      "package": "lodash",
      "version": "4.17.21",
      "detail": "evil.com"
    },
    {
      "id": 2,
      "severity": "warn",
      "kind": "override_applied",
      "package": "left-pad",
      "version": "1.3.0",
      "detail": "override from overrides trailer"
    }
  ],
  "trailers": {
    "trusted_hashes": [],
    "has_empty_trusted": false,
    "overrides": [
      {
        "name_hash": 123456789,
        "dependency": {
          "name": "left-pad",
          "req": "1.3.0",
          "behavior": 2,
          "resolved_package_id": null
        }
      }
    ],
    "patched": [],
    "catalogs": [],
    "default_catalog": [],
    "workspaces_count": 0
  }
}
```
