# Override trailer example

This example illustrates a lockfile with an override trailer and the resulting JSON finding.

Sample JSON snippet (produced with `--verbose --json`):

```json
{
  "summary": {
    "total_packages": 2,
    "issues_total": 1,
    "high_count": 0,
    "warn_count": 1,
    "info_count": 0,
    "exit_code": 1,
    "parser_warnings": []
  },
  "issues": [
    {
      "id": 1,
      "severity": "warn",
      "kind": "override_applied",
      "package": "left-pad",
      "version": "1.3.0",
      "detail": "override from overrides trailer"
    }
  ],
  "trailers": {
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
    "trusted_hashes": [],
    "has_empty_trusted": false,
    "patched": [],
    "catalogs": [],
    "default_catalog": [],
    "workspaces_count": 0
  }
}
```

(Use your real lockfile to reproduce; this directory is documentation-only.)
