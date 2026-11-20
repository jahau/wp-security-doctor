# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-11-20

Adds SARIF output so findings can be shown in GitHub code scanning. Nothing else in the
scan changes: it stays read-only and offline by default, and the text output, JSON output
(`schema_version: 1`) and exit codes are unchanged.

### Added

- `--format sarif`: a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
  log for GitHub code scanning and other SARIF tools.
  - Every rule is listed under its stable `WPSD-*` ID, with title, explanation, remediation
    (text and Markdown) and documentation link.
  - Severity maps to the SARIF `level` (CRITICAL/HIGH `error`, MEDIUM `warning`, LOW/INFO
    `note`) and to GitHub's `security-severity` (9.5 / 8.0 / 5.5 / 3.0).
  - Each FAIL/WARN location becomes one result with a relative file URI. Line numbers are
    included for code-pattern hits and for `wp-config.php` constants.
  - UNKNOWN and SKIPPED findings become tool execution notifications, not alerts. A crashed
    check sets `executionSuccessful: false`.
- `--sarif-path-prefix DIR` maps paths to the repository root when a subdirectory is scanned.
  It rejects absolute paths and `..`.
- [GitHub code scanning guide](docs/github-code-scanning.md) and an
  [example workflow](docs/examples/wp-security-doctor-code-scanning.yml) using
  `github/codeql-action/upload-sarif@v4`.
- Tests that validate SARIF against the vendored official OASIS schema, compare a synthetic scan
  with a golden SARIF file, and check GitHub's ingestion constraints. They also verify
  that exit codes are the same for every format, and that a SARIF scan leaves the tree
  unchanged and makes no network or process calls. `jsonschema` is a new development-only
  dependency. The tool itself still has no runtime dependencies.
- More package keywords and classifiers, and project URLs for the changelog and issues.

### Security

- SARIF output never contains absolute paths (the scan root, its parent, or absolute paths in
  evidence such as a custom `WP_DEBUG_LOG`), the command line, host or user names, or timestamps.
  It applies the same secret redaction as the other formats.

## [0.2.0] - 2026-11-14

The single-file prototype is now a tested, installable package. The scan stays read-only and is
offline by default.

### Added

- `wp-security-doctor` command with `scan` and `rules` subcommands, plus `python -m wp_security_doctor`.
- Structured findings with rule ID, severity (INFO to CRITICAL), status (PASS, WARN, FAIL,
  SKIPPED, UNKNOWN), basis (verified, observed, heuristic, none), locations, evidence,
  explanation, remediation and official documentation links.
- Terminal report (with color, honoring `NO_COLOR`) and deterministic JSON report (`schema_version: 1`).
- `--checks` to select `core`, `config`, `files`, `permissions` and `plugins`.
- `--fail-on` severity threshold for exit codes. `--output` writes the report to a file and
  refuses paths inside the scanned installation.
- Detection of the standard layout, `wp-config.php` in the parent directory, WordPress in a
  subdirectory, and Bedrock.
- Configuration checks: `WP_DEBUG`, `WP_DEBUG_DISPLAY`, `WP_DEBUG_LOG`, `SCRIPT_DEBUG`,
  `DISALLOW_FILE_EDIT`/`DISALLOW_FILE_MODS`, `FORCE_SSL_ADMIN`, keys and salts, automatic
  updates, `WP_ALLOW_REPAIR` and `ALLOW_UNFILTERED_UPLOADS`. Values computed at runtime are
  reported as UNKNOWN.
- File checks: PHP in uploads, PHP disguised as media, hidden or double-extension PHP files,
  web-shell and obfuscation patterns with line numbers, `wp-config.php` backups, database dumps
  and archives, log files, and development artefacts.
- POSIX permission checks for world-writable entries and `wp-config.php`. They are reported as
  SKIPPED on Windows.
- Core integrity verification against official checksums from a local file (`--core-checksums`,
  offline) or downloaded on request (`--fetch-checksums`). Reports modified, unexpected and
  missing core files.
- Optional WP-CLI integration (`--wp-cli`, `--wp-cli-path`) for `wp core verify-checksums` and
  `wp plugin verify-checksums --all`, run with `--skip-plugins --skip-themes --skip-packages`.
- Plugin inventory from plugin headers, plus a review list of must-use plugins and drop-ins.
- Scan coverage reporting: limits reached, unreadable paths, and symlinks that were not followed.
- pytest suite on synthetic WordPress fixtures, Ruff linting and formatting, strict mypy, and
  GitHub Actions CI on Linux, Windows and macOS.

### Changed

- The project is now the `wp_security_doctor` package. `python wp_doctor.py <path>` still works
  and accepts every `scan` option.
- PHP files in uploads are no longer silently capped at 30. Each finding lists up to 50 sorted
  locations plus an "... and N more" line. The terminal shows the first 10 unless `--verbose` is given.

### Security

- Symlinks that resolve outside the scan root are never followed or read.
- Directory traversal, entry count and bytes read per file are bounded.
- Secrets from `wp-config.php` (`DB_PASSWORD`, `FTP_PASS`, keys and salts) are redacted from
  every report field.
- The scanner never executes PHP and never writes inside the installation.

## [0.1.0]

- Initial prototype: `python wp_doctor.py <path>`, with basic `WP_DEBUG`/`DISALLOW_FILE_EDIT`
  checks, PHP files in uploads, and world-writable directories.

[0.3.0]: https://github.com/jahau/wp-security-doctor/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jahau/wp-security-doctor/compare/6e7d9f2...v0.2.0
[0.1.0]: https://github.com/jahau/wp-security-doctor/commit/6e7d9f2
