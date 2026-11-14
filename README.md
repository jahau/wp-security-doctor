# WP Security Doctor

A **read-only, offline-by-default** security audit for WordPress installations on disk.
It inspects configuration, file locations, permissions and core integrity, then reports
structured findings with evidence, remediation and links to the official WordPress
documentation.

- **Read-only.** It never writes, renames, deletes or chmods anything inside the installation.
- **Offline by default.** No network access unless you explicitly opt in.
- **Never executes site code.** `wp-config.php` is parsed as text; plugins and themes are never loaded.
- **No dependencies.** Python 3.10+ standard library only. Works on Linux, macOS and Windows.

> WP Security Doctor is an *audit* tool, not a malware scanner or a guarantee of safety.
> See [Security audit vs. malware detection](#security-audit-vs-malware-detection) and
> [Limitations](#limitations).

## Installation

Requires Python 3.10 or newer.

```bash
# Recommended: isolated install of the CLI
pipx install git+https://github.com/jahau/wp-security-doctor.git@v0.2.0

# Or with pip
pip install git+https://github.com/jahau/wp-security-doctor.git@v0.2.0

# Or straight from a checkout, no install needed
git clone https://github.com/jahau/wp-security-doctor.git
cd wp-security-doctor
python wp_doctor.py /path/to/wordpress
```

Run it as a user that can **read** the WordPress files. It does not need write access, and
you should not run it as root unless reading the files requires that.

## Usage

```bash
wp-security-doctor scan /path/to/wordpress                       # all checks, terminal output
wp-security-doctor scan /path/to/wordpress --format json         # machine-readable report
wp-security-doctor scan /path/to/wordpress --checks core,files,config
wp-security-doctor scan /path/to/wordpress --offline             # guarantee: no network at all
wp-security-doctor scan /path/to/wordpress -o /tmp/report.json --format json
wp-security-doctor rules                                         # list every rule ID

python wp_doctor.py /path/to/wordpress                           # 0.1 command, still supported
python -m wp_security_doctor scan /path/to/wordpress
```

| Option | Meaning |
| --- | --- |
| `--format text\|json` | Output format (default `text`). |
| `--checks LIST` | Comma-separated subset of `core,config,files,permissions,plugins`. |
| `--offline` | Explicitly forbid network access. This is already the default; combining it with `--fetch-checksums` or `--wp-cli` is an error. |
| `--core-checksums FILE` | Verify core against an official checksum JSON file, fully offline (see below). |
| `--fetch-checksums` | **Network:** download core checksums from `api.wordpress.org`. |
| `--wp-cli`, `--wp-cli-path PATH` | **Network:** run `wp core verify-checksums` and `wp plugin verify-checksums --all`. |
| `--fail-on LEVEL` | Exit with 1 if a FAIL/WARN finding has at least this severity: `info`, `low`, `medium`, `high` (default), `critical` or `never`. |
| `--output FILE` | Write the report to a file. The file must be outside the scanned directory. |
| `--verbose` | Show every location and the evidence behind PASS results. |
| `--max-files`, `--max-depth`, `--max-read-bytes` | Traversal and read limits (defaults: 200 000 entries, depth 40, 2 MiB per file). |
| `--color auto\|always\|never` | Terminal colors (also respects `NO_COLOR`). |

**Exit codes:** `0` = no open finding at or above `--fail-on`; `1` = at least one; `2` = usage
error, not a WordPress directory, or the scan could not run.

### Supported layouts

| Layout | Example |
| --- | --- |
| Standard | `wp-config.php`, `wp-admin/`, `wp-includes/`, `wp-content/` in one directory |
| Parent config | `wp-config.php` one level above the WordPress directory. It is read as a single file and the parent directory is not traversed. |
| Subdirectory | Scan target contains core in `wordpress/`, `wp/`, `public_html/`, `htdocs/`, `public/`, `www/`, `web/` or `html/` |
| Bedrock | `web/wp` core, `web/app` content, `web/wp-config.php` and `config/application.php` |

## Example output

This is an excerpt from a scan of a deliberately misconfigured copy of WordPress 7.1.4 (path
shortened). The issues were planted for the demo.

```text
$ wp-security-doctor scan /var/www/example.com --checks core,config,files,plugins \
      --core-checksums checksums-7.1.4.json
WP Security Doctor 0.2.0 - read-only WordPress audit
Target   /var/www/example.com
Core     . (WordPress 7.1.4, layout: standard)
Config   wp-config.php
Content  wp-content
Mode     offline | checks: core,config,files,plugins

[FAIL]    HIGH     WPSD-CONFIG-008  Authentication keys/salts are missing or weak
    Location    wp-config.php
    Evidence    placeholder, empty or shorter than 32 characters: NONCE_SALT
    Basis       observed
    Why         The eight keys/salts sign login cookies and nonces. Missing, placeholder or short
                values make cookies easier to forge.
    Fix         Generate fresh values from the official generator and replace all eight definitions.
                This logs out every user, which is intended.
    Docs        https://api.wordpress.org/secret-key/1.1/salt/
                https://developer.wordpress.org/apis/wp-config-php/

[FAIL]    HIGH     WPSD-CORE-002  Core files differ from official checksums
    Location    wp-includes/load.php
    Evidence    checksum source: local file checksums-7.1.4.json; 3782 entries
                1 modified file(s)
    Basis       verified
    Why         These core files do not match the official WordPress.org checksums for the declared
                version and locale. Core files should never be edited; a mismatch is a confirmed
                modification (malicious or not).
    Fix         Compare the files with a clean copy of the same version, then reinstall core
                (Dashboard > Updates > Re-install, or wp core download --force --skip-content). If
                the changes are malicious, treat the site as compromised.
    Docs        https://developer.wordpress.org/cli/commands/core/verify-checksums/
                https://wordpress.org/documentation/article/faq-my-site-was-hacked/

[WARN]    HIGH     WPSD-FILES-003  Code patterns associated with web shells or obfuscation
    Location    wp-content/uploads/2026/10/cache-img.php:1 (eval of decoded/obfuscated data)
                wp-includes/load.php:2051 (execution of request input)
    Evidence    1515 PHP-like file(s) scanned (first 2048 KiB of each)
                2 pattern match(es)
    Basis       heuristic
    ...

[WARN]    HIGH     WPSD-FILES-005  Backup copies of wp-config.php
    Location    wp-config.php.bak
    ...

Passed checks
  PASS  WPSD-CONFIG-001   wp-config.php located and parsed
  PASS  WPSD-CONFIG-005   SCRIPT_DEBUG is off
  PASS  WPSD-CORE-003     No unexpected files in core directories
  PASS  WPSD-FILES-004    No PHP code hidden in media files
  ...

Summary  PASS 15  WARN 8  FAIL 3  SKIPPED 0  UNKNOWN 0

Note: This is a read-only configuration and file-system audit. Passing every check does not mean the
site is secure: it does not test the running site, the database, user accounts, server configuration
or known plugin vulnerabilities, and its heuristics can miss malware or flag legitimate code.
No files were modified.
```

Notice the difference between the two `load.php` findings. **CORE-002** is *verified*: the file's
hash does not match the official release. **FILES-003** is *heuristic*: it points at the suspicious
line so a person can review it.

### JSON output

`--format json` produces a stable, deterministic document (`schema_version: 1`). Findings are
sorted by status, then severity, then rule ID. Excerpt:

```json
{
  "schema_version": 1,
  "tool": { "name": "wp-security-doctor", "version": "0.2.0" },
  "target": {
    "scan_root": "/var/www/example.com",
    "core_dir": ".",
    "layout": "standard",
    "wordpress_version": "7.1.4",
    "locale": null,
    "config_file": "wp-config.php",
    "content_dir": "wp-content"
  },
  "scan": {
    "checks": ["core", "config", "files", "plugins"],
    "offline": true,
    "network_integrations": [],
    "read_only": true,
    "platform": "Linux"
  },
  "summary": {
    "counts": { "PASS": 15, "WARN": 8, "FAIL": 3, "SKIPPED": 0, "UNKNOWN": 0 },
    "highest_open_severity": "HIGH"
  },
  "disclaimer": "This is a read-only configuration and file-system audit. Passing every check does not mean the site is secure: ...",
  "findings": [
    {
      "rule_id": "WPSD-CORE-002",
      "title": "Core files differ from official checksums",
      "category": "core",
      "severity": "HIGH",
      "status": "FAIL",
      "basis": "verified",
      "locations": ["wp-includes/load.php"],
      "evidence": ["checksum source: local file checksums-7.1.4.json; 3782 entries", "1 modified file(s)"],
      "explanation": "These core files do not match the official WordPress.org checksums ...",
      "remediation": "Compare the files with a clean copy of the same version, then reinstall core ...",
      "references": [
        "https://developer.wordpress.org/cli/commands/core/verify-checksums/",
        "https://wordpress.org/documentation/article/faq-my-site-was-hacked/"
      ]
    }
  ]
}
```

## Reading the results

Each finding carries three independent labels:

| Field | Values | Meaning |
| --- | --- | --- |
| **status** | `FAIL` | A confirmed problem: a checksum mismatch or an insecure setting observed directly. |
| | `WARN` | Needs human review: a heuristic match or a missing hardening measure. |
| | `UNKNOWN` | The check ran but could not decide, e.g. a constant is set from `getenv()`, or a scan limit was hit. |
| | `SKIPPED` | The check did not run: unsupported platform, missing tool, or an opt-in integration that was not enabled. |
| | `PASS` | Nothing found **by this check**. |
| **severity** | `INFO` `LOW` `MEDIUM` `HIGH` `CRITICAL` | Potential impact if the finding is real. PASS and SKIPPED results are `INFO`. |
| **basis** | `verified` | Compared against an authoritative reference (official checksums). |
| | `observed` | Read directly from disk (a config value, permission bits, a file's presence). |
| | `heuristic` | Based on name, location or pattern matching. False positives are possible. |
| | `none` | Nothing was evaluated. |

There is deliberately **no numeric "security score"**. A score built from these checks would
suggest more certainty than a file-system audit can give.

## Supported checks

Run `wp-security-doctor rules` for the full list.

| Rule | Severity | What it looks for |
| --- | --- | --- |
| **core** | | |
| WPSD-CORE-001 | INFO | Declared version, locale and layout |
| WPSD-CORE-002 | HIGH | Core files whose MD5 differs from the official checksums (*verified*) |
| WPSD-CORE-003 | MEDIUM | Files in `wp-admin/`, `wp-includes/` or core-root `*.php` that are not part of the release |
| WPSD-CORE-004 | LOW | Core files that are missing |
| WPSD-CORE-005 | HIGH | `wp core verify-checksums` result (opt-in, `--wp-cli`) |
| **config** | | |
| WPSD-CONFIG-001 | MEDIUM | `wp-config.php` located (root or parent) and parsed; `UNKNOWN` if missing or unreadable |
| WPSD-CONFIG-002 | MEDIUM | `WP_DEBUG` enabled |
| WPSD-CONFIG-003 | MEDIUM | Errors displayed (`WP_DEBUG` on and `WP_DEBUG_DISPLAY` not `false`) |
| WPSD-CONFIG-004 | MEDIUM | `WP_DEBUG_LOG` writing to the public default `wp-content/debug.log` |
| WPSD-CONFIG-005 | LOW | `SCRIPT_DEBUG` enabled |
| WPSD-CONFIG-006 | MEDIUM | Dashboard file editor enabled (no `DISALLOW_FILE_EDIT` or `DISALLOW_FILE_MODS`) |
| WPSD-CONFIG-007 | LOW | `FORCE_SSL_ADMIN` not enabled |
| WPSD-CONFIG-008 | HIGH | Keys/salts missing, placeholder, short or duplicated (values are never printed) |
| WPSD-CONFIG-009 | LOW | Automatic core updates disabled |
| WPSD-CONFIG-010 | MEDIUM | `WP_ALLOW_REPAIR` enabled (unauthenticated repair page) |
| WPSD-CONFIG-011 | HIGH | `ALLOW_UNFILTERED_UPLOADS` enabled |
| **files** | | |
| WPSD-FILES-001 | HIGH | PHP-like files in `uploads/` ("Silence is golden" stubs are ignored) |
| WPSD-FILES-002 | MEDIUM | Hidden PHP files, double extensions (`x.jpg.php`), unknown PHP directly in `wp-content/`, leftovers in `wp-content/upgrade/` |
| WPSD-FILES-003 | HIGH | Web-shell and obfuscation patterns, reported with line numbers |
| WPSD-FILES-004 | HIGH | Media files in uploads that contain a PHP open tag |
| WPSD-FILES-005 | HIGH | `wp-config.php` backups (`.bak`, `~`, `.old`, `.save`, `.swp` ...) |
| WPSD-FILES-006 | HIGH | SQL dumps and site archives in the web root |
| WPSD-FILES-007 | MEDIUM | `debug.log` / `error_log` files |
| WPSD-FILES-008 | MEDIUM | `phpinfo()` pages, Adminer, `.env`, `.git/` and similar |
| **permissions** (POSIX only) | | |
| WPSD-PERM-001 | HIGH | World-writable files and directories |
| WPSD-PERM-002 | MEDIUM | `wp-config.php` readable by others, or writable by group/others |
| **plugins** | | |
| WPSD-PLUGIN-001 | INFO | Plugin inventory with declared versions |
| WPSD-PLUGIN-002 | INFO | Must-use plugins and drop-ins to review |
| WPSD-PLUGIN-003 | HIGH | `wp plugin verify-checksums --all` mismatches (opt-in, `--wp-cli`) |
| WPSD-PLUGIN-004 | INFO | Plugins WordPress.org cannot verify (premium/custom) |
| **scan** | | |
| WPSD-SCAN-001 | INFO | Coverage: limits reached, unreadable paths, symlinks not followed |
| WPSD-SCAN-002 | INFO | A check category crashed; the other categories still ran |

## Core integrity verification

Without a checksum source, the integrity rules are reported as `SKIPPED`, never as `PASS`.
There are three ways to provide one:

1. **Fully offline:** `--core-checksums FILE`. On any machine with internet access, download the
   official list for the installed version and locale, then copy it to the server:

   ```bash
   curl -o checksums.json "https://api.wordpress.org/core/checksums/1.0/?version=6.6.2&locale=en_US"
   wp-security-doctor scan /var/www/site --core-checksums checksums.json
   ```

2. **Network, Python only:** `--fetch-checksums` downloads the same file directly. Nothing else is
   sent: the request contains only the version and locale, with the User-Agent
   `wp-security-doctor/<version>`.

3. **Network, WP-CLI:** `--wp-cli` (or `--wp-cli-path /path/to/wp`) runs
   `wp core verify-checksums` and `wp plugin verify-checksums --all`. It always passes
   `--skip-plugins --skip-themes --skip-packages`. Be aware of two things:
   - `wp core verify-checksums` runs before WordPress is loaded.
   - `wp plugin verify-checksums` has to bootstrap WordPress, so **WP-CLI executes `wp-config.php`
     and WordPress core** (but not plugins or themes). The scanner itself still never runs PHP.
     Only use this on installations you are prepared to load with WP-CLI.

   If WP-CLI is not installed, the WP-CLI rules are reported as `SKIPPED`. Timeouts and errors are
   reported as `UNKNOWN`.

Like WP-CLI, checksum verification skips `wp-content/`, because bundled themes and plugins are
often updated independently of core.

## Safety and privacy

- **Read-only.** Files are opened for reading only. `--output` refuses to write into the scanned
  directory. The test suite snapshots the fixture tree (size, mtime, SHA-256) before and after a
  scan and checks that nothing changed.
- **No code execution.** PHP is never executed by the scanner. `wp-config.php` is parsed
  statically, and values computed at runtime (`getenv()`, `$_ENV`, conditionals) are reported as
  `UNKNOWN` rather than guessed.
- **Secrets stay local.** Key/salt findings list constant *names* only. As a final safeguard,
  the values of `DB_PASSWORD`, `FTP_PASS` and all keys/salts are replaced with `[REDACTED]`
  anywhere they appear in a report, including in file names.
- **Bounded traversal.** Directory symlinks are never followed. File symlinks are read only if
  they resolve inside the scan root. `.git`, `.svn`, `.hg` and `node_modules` are not descended
  into. Entry count, depth and bytes read per file are capped, and anything skipped is reported
  in `WPSD-SCAN-001`.
- **No telemetry.** No network access at all unless `--fetch-checksums` or `--wp-cli` is given.

## Security audit vs. malware detection

WP Security Doctor answers the question *"Is this installation configured and laid out the way a
hardened WordPress site should be, and does core match the official release?"*

It does **not** answer *"Is this site free of malware?"*:

- The code-pattern rules (FILES-003) are a short, intentionally narrow list. They do not compare
  against a malware signature database, do not emulate or deobfuscate code beyond decoding simple
  hex escapes, and will miss novel or well-hidden malware.
- Plugins and themes are only verified when WP-CLI can fetch checksums for them from WordPress.org.
  Premium and custom code is never verified.
- The database (where many injections live: options, posts, users) is not inspected.

If you suspect a compromise, treat this tool as one input and follow the official
[FAQ: My site was hacked](https://wordpress.org/documentation/article/faq-my-site-was-hacked/).

## False positives

Heuristic findings are hints for a reviewer, not verdicts. Known sources of false positives:

| Rule | Common legitimate cause |
| --- | --- |
| FILES-001 | Some security, backup, form and cache plugins write PHP files into `uploads/` (for example `index.php` guards or protected-download handlers). |
| FILES-002 | Hosting tools placing PHP files in `wp-content/`. Interrupted updates leaving files in `wp-content/upgrade/`. |
| FILES-003 | Commercial licensing or encoding systems, minified or bundled libraries, and code that embeds large base64 assets (fonts, images). |
| FILES-004 | Files that only *mention* PHP, such as an SVG or PDF tutorial that contains `<?php` in its text. |
| FILES-006 | Archive names such as `*.zip` used for legitimate downloads in the first two directory levels. |
| CORE-003 | Files added by managed hosts or left over from older WordPress versions. |
| PLUGIN-002 | Must-use plugins installed by managed hosts; caching drop-ins (`advanced-cache.php`, `object-cache.php`). |
| CONFIG-007 | HTTPS enforced at the web server, load balancer or CDN instead of in `wp-config.php`. |

As a reference point, the 0.2.0 heuristics produced **no** FILES-003 matches on WordPress 7.1.4
core plus WooCommerce, Yoast SEO, Elementor, Jetpack, Wordfence, UpdraftPlus and Contact Form 7
(about 13 000 PHP files).

## Limitations

- **Not a vulnerability scanner.** Versions are listed but not compared to vulnerability
  databases (planned as an opt-in integration).
- **Static view of the configuration.** Constants defined in included files, environment
  variables, `php.ini`, `.user.ini` or server configuration are not evaluated. Unset constants in
  a `wp-config.php` that includes other files are reported with a note that they may be defined
  elsewhere.
- **No web-server view.** The tool cannot tell whether a file is actually reachable over HTTP,
  whether PHP execution is blocked in `uploads/`, or whether HTTPS is enforced upstream.
- **Permissions** are evaluated only on POSIX systems. On Windows they are `SKIPPED`, because NTFS
  ACLs are not analysed. Ownership and the web server's user are not checked.
- **Multisite** is scanned like a single site. Network-specific settings are not interpreted.
- **Declared versions can be forged** by an attacker. Only checksum verification confirms core.
- **Large installations:** by default the scan stops indexing after 200 000 entries and reads at
  most 2 MiB per file for pattern matching. Truncation is reported as `UNKNOWN` in `WPSD-SCAN-001`.

## Development

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest              # unit and integration tests on synthetic WordPress fixtures
ruff check . && ruff format --check .
mypy                # strict mode
```

CI runs lint, type checking and the test suite on Linux, Windows and macOS with Python 3.10 and
3.13. Tests build synthetic WordPress trees in temporary directories and never touch real sites.
Symlink and permission tests are skipped where the OS does not support them.

## License

MIT. See [LICENSE](LICENSE).
