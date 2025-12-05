# Patched dependency trailer example

Sample JSON (`--verbose --json`):

```json
{
  "issues": [
    {
      "id": 1,
      "severity": "warn",
      "kind": "patched_dependency",
      "package": "is-even",
      "version": "1.0.0",
      "detail": "patch applied from patches/is-even.patch"
    }
  ],
  "trailers": {
    "patched": [
      {
        "name_version_hash": 987654321,
        "path": "patches/is-even.patch",
        "patch_hash": 123456789
      }
    ]
  }
}
```

Use this as a reference when inspecting your own lockfile; the directory itself holds no binary fixture.
