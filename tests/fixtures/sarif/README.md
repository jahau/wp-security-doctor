# SARIF test fixtures

- `sarif-schema-2.1.0.json` is the official OASIS SARIF 2.1.0 JSON schema (Errata 01), unmodified.
  It is vendored so schema validation runs offline.
  Source: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
  SHA-256: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- `expected-issues.sarif` is the golden output for the synthetic site that `issues_site()` in
  `tests/test_sarif.py` builds (`--checks config,files --sarif-path-prefix public_html`). The tool
  version is replaced with `<version>`. Regenerate it with
  `WPSD_UPDATE_GOLDEN=1 pytest tests/test_sarif.py`.
