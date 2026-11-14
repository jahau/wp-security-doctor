#!/usr/bin/env python3
"""Read-only local WordPress configuration hygiene scan."""
from pathlib import Path
import argparse
import re


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('wordpress_root', type=Path)
    args = ap.parse_args()
    root = args.wordpress_root.resolve()
    if not (root / 'wp-includes' / 'version.php').exists():
        raise SystemExit('Not a WordPress root (wp-includes/version.php missing).')
    print(f'WP Security Doctor — {root}')
    version_text = (root / 'wp-includes' / 'version.php').read_text(errors='replace')
    m = re.search(r"""\$wp_version\s*=\s*['"]([^'"]+)""", version_text)
    print('Core declared version:', m.group(1) if m else 'unknown')
    config = root / 'wp-config.php'
    if config.exists():
        data = config.read_text(errors='replace')
        for key in ('WP_DEBUG', 'WP_DEBUG_DISPLAY', 'DISALLOW_FILE_EDIT'):
            found = re.search(r"""define\s*\(\s*['"]""" + key + r"""['"]\s*,\s*(true|false|1|0)""", data, re.I)
            print(f'{key}:', found.group(1) if found else 'not directly set')
    else:
        print('wp-config.php not found in root; it may be in parent directory.')
    uploads = root / 'wp-content' / 'uploads'
    php_files = []
    if uploads.exists():
        for p in uploads.rglob('*'):
            if p.is_file() and p.suffix.lower() in ('.php', '.phtml', '.phar'):
                php_files.append(str(p.relative_to(root)))
                if len(php_files) >= 30: break
    print('PHP-like files under uploads:', len(php_files), '(capped at 30)')
    for p in php_files: print('  REVIEW:', p)
    for folder in (root, root / 'wp-content', uploads):
        if folder.exists() and folder.stat().st_mode & 0o002:
            print('WARNING: world-writable directory:', folder)
    print('Scan complete. Review findings manually; no files were changed.')


if __name__ == '__main__': main()
