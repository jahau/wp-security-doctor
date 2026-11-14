# WP Security Doctor

A **read-only, local** WordPress security hygiene inspector. No network scan or malware-removal claims.

## Usage

```bash
python wp_doctor.py /path/to/wordpress
```

Checks for WordPress core version declared in `wp-includes/version.php`, risky `WP_DEBUG` settings, world-writable directories and executable PHP files in uploads. Results are indicators, not proof of compromise. The script never changes files or accesses the WordPress database.

## Roadmap
- Hardened WP-CLI adapter and supported version checks
- Optional WP-Cron and XML-RPC configuration inspection
- JSON and SARIF output with severity and false-positive explanations
- WordPress multisite support

MIT License. Contributions welcome.
