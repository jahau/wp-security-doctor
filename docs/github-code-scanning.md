# GitHub code scanning (SARIF)

`wp-security-doctor scan --format sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
log for GitHub code scanning, IDE SARIF viewers and other SARIF tools. The scan stays read-only
and offline by default. Exit codes are the same as with `text` and `json`.

## Quick start

```bash
wp-security-doctor scan ./public_html --format sarif --sarif-path-prefix public_html \
    --fail-on never -o /tmp/wp-security-doctor.sarif
```

[examples/wp-security-doctor-code-scanning.yml](examples/wp-security-doctor-code-scanning.yml)
is a complete workflow. Copy it to `.github/workflows/` in the repository that holds your
WordPress files and set `WP_PATH`. The workflow needs `security-events: write`. Private
repositories also need `actions: read` and GitHub Code Security (or Advanced Security) enabled.

Notes:

- `--output` must point outside the scanned directory, so the workflow writes the file to
  `$RUNNER_TEMP`.
- Run the SARIF step with `--fail-on never` so a report is always produced. Then gate the job
  in a separate step, or rely on code scanning's own pull-request checks.
- Use a fixed `category` (`wp-security-doctor`). Each upload then replaces the previous results
  for the same tool and category.

## Paths: `--sarif-path-prefix`

GitHub resolves artifact URIs against the repository root. The scanner reports paths relative
to the directory it scanned. When you scan a subdirectory, pass that directory as
`--sarif-path-prefix`. An alert for `wp-content/uploads/x.php` then points to
`public_html/wp-content/uploads/x.php`.

The prefix must be a relative path inside the repository. Absolute paths and `..` are rejected
with exit code 2. With a prefix, the exporter can also locate a `wp-config.php` in the parent
directory of the scanned path. For example, when you scan `public_html`, a `wp-config.php` at
the repository root is reported as `wp-config.php`. Without a prefix, a parent-directory
`wp-config.php` cannot be expressed as a repository path, so those findings use the fallback
anchor described below.

## How findings are mapped

| WP Security Doctor | SARIF |
| --- | --- |
| Rule (`WPSD-…`, see `wp-security-doctor rules`) | `tool.driver.rules[]` with the same `id`. Every rule is always listed, in ID order. |
| Title / explanation / remediation / docs | `shortDescription` / `fullDescription` / `help` (text and Markdown) / `helpUri` |
| Category | rule `properties.tags`: `security`, `wordpress` and the category |
| Severity CRITICAL, HIGH | `level: error`; rule `security-severity` 9.5 / 8.0 |
| Severity MEDIUM | `level: warning`; `security-severity` 5.5 |
| Severity LOW, INFO | `level: note`; `security-severity` 3.0 (LOW), none (INFO) |
| FAIL or WARN finding | one `result` (`kind: fail`) **per location**. `properties` carry `status`, `basis`, `severity` and `category`. |
| Location `path`, `path:LINE`, `path (detail)` | `physicalLocation.artifactLocation.uri` (relative, percent-encoded, `uriBaseId: %SRCROOT%`) and `region.startLine` (1 when there is no line) |
| `wp-config.php` constant findings | the line of the `define()` when known |
| Evidence | appended to `message.text` |
| Finding without a file location | anchored to `wp-config.php` (config category) or `wp-includes/version.php`, with `properties.locationKind: fallback` |
| UNKNOWN, SKIPPED | `invocations[0].toolExecutionNotifications`, not alerts. A check that crashed (`WPSD-SCAN-002`) has `level: error` and sets `executionSuccessful: false`. |
| PASS | counted in `runs[0].properties.summary` only |

Each result has a `partialFingerprints["wpsdLocationHash/v1"]` value built from the rule, path,
line and detail. Other SARIF tools can use it to de-duplicate results across runs. GitHub
ignores it and computes its own `primaryLocationLineHash`.

A rule's `security-severity` reflects the rule's default severity. When a finding's severity
differs from that default (for example `WPSD-PERM-002`), the actual value is in the result's
`level` and `properties.severity`.

## Privacy

A SARIF log is meant to be uploaded, so it contains less than the JSON report:

- The same secret redaction as every other format applies (`DB_PASSWORD`, `FTP_PASS`, keys and
  salts).
- No absolute paths. The scan root becomes `<scan-root>` and its parent becomes
  `<scan-root-parent>`. Any other absolute path in evidence, such as a custom `WP_DEBUG_LOG`
  location, is reduced to `<abs-path>/<file name>`.
- No command line, host name, user name, working directory, platform or timestamps. The output
  is deterministic for the same tree.

The JSON report still includes `target.scan_root`, as before. Use SARIF when the report leaves
the machine.

## Validation

The test suite checks generated logs in three ways:

- It validates them against the official OASIS schema, which is vendored in
  [`tests/fixtures/sarif/`](../tests/fixtures/sarif/).
- It compares a synthetic scan with the golden file `expected-issues.sarif`.
- It checks the ingestion constraints GitHub documents: one location per result, relative URIs,
  rule description length, tag count and `security-severity` range.

After an intended change, regenerate the golden file with:

```bash
WPSD_UPDATE_GOLDEN=1 pytest tests/test_sarif.py
```
