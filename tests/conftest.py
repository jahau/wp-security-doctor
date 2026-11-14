"""Synthetic WordPress fixtures. Nothing here resembles a real site's data."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wp_security_doctor.context import ScanContext, ScanOptions
from wp_security_doctor.detect import detect
from wp_security_doctor.models import Finding

VERSION = "6.6.2"
DB_PASSWORD = "Synthetic-Db-Pass-7Q2x"

# 64-char synthetic salts, all different.
SALT_NAMES = (
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
)
SALTS = {name: hashlib.sha256(name.encode()).hexdigest() for name in SALT_NAMES}

CORE_FILES = {
    "index.php": "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
    "wp-blog-header.php": "<?php\n// synthetic\n",
    "wp-load.php": "<?php\n// synthetic\n",
    "wp-settings.php": "<?php\n// synthetic\n",
    "wp-config-sample.php": "<?php\ndefine( 'AUTH_KEY', 'put your unique phrase here' );\n",
    "wp-admin/index.php": "<?php\n// synthetic admin\n",
    "wp-admin/includes/file.php": "<?php\nfunction synthetic_file() {}\n",
    "wp-includes/version.php": f"<?php\n$wp_version = '{VERSION}';\n$wp_db_version = 57155;\n",
    "wp-includes/functions.php": "<?php\nfunction synthetic() { return base64_decode( 'eA==' ); }\n",
    "wp-includes/js/jquery.js": "/* synthetic */\n",
    "wp-content/index.php": "<?php\n// Silence is golden.\n",
    "wp-content/plugins/index.php": "<?php\n// Silence is golden.\n",
    "wp-content/themes/index.php": "<?php\n// Silence is golden.\n",
}


def config_php(extra: str = "", *, salts: dict[str, str] | None = None, hardened: bool = True) -> str:
    salts = SALTS if salts is None else salts
    lines = [
        "<?php",
        "/** Synthetic test configuration */",
        "define( 'DB_NAME', 'synthetic_db' );",
        "define( 'DB_USER', 'synthetic_user' );",
        f"define( 'DB_PASSWORD', '{DB_PASSWORD}' );",
        "define( 'DB_HOST', 'localhost' );",
    ]
    lines += [f"define( '{k}', '{v}' );" for k, v in salts.items()]
    lines.append("$table_prefix = 'wp_';")
    if hardened:
        lines += [
            "define( 'WP_DEBUG', false );",
            "define( 'DISALLOW_FILE_EDIT', true );",
            "define( 'FORCE_SSL_ADMIN', true );",
        ]
    if extra:
        lines.append(extra)
    lines += [
        "if ( ! defined( 'ABSPATH' ) ) {",
        "\tdefine( 'ABSPATH', __DIR__ . '/' );",
        "}",
        "require_once ABSPATH . 'wp-settings.php';",
    ]
    return "\n".join(lines) + "\n"


def write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="\n")
    return path


def make_core(core: Path) -> Path:
    for rel, text in CORE_FILES.items():
        write(core / rel, text)
    (core / "wp-content" / "uploads" / "2024" / "05").mkdir(parents=True, exist_ok=True)
    write(core / "wp-content" / "uploads" / "2024" / "05" / "photo.jpg", b"\xff\xd8\xff\xe0synthetic-jpeg")
    write(
        core / "wp-content" / "plugins" / "hello-synthetic" / "hello-synthetic.php",
        "<?php\n/**\n * Plugin Name: Hello Synthetic\n * Version: 1.2.3\n */\n",
    )
    return core


def checksums_for(core: Path) -> dict[str, str]:
    return {rel: hashlib.md5((core / rel).read_bytes()).hexdigest() for rel in CORE_FILES}


@pytest.fixture
def wp(tmp_path: Path) -> Path:
    """Standard layout with a hardened wp-config.php in the WordPress root."""
    root = make_core(tmp_path / "site")
    write(root / "wp-config.php", config_php())
    return root


@pytest.fixture
def checksum_file(tmp_path: Path) -> Path:
    core = tmp_path / "reference"
    make_core(core)
    path = tmp_path / f"checksums-{VERSION}.json"
    path.write_text(json.dumps({"checksums": {VERSION: checksums_for(core)}}), encoding="utf-8")
    return path


def run_checks(root: Path, check: str, **opts: object) -> list[Finding]:
    from wp_security_doctor.checks import REGISTRY

    options = ScanOptions(**opts)  # type: ignore[arg-type]
    ctx = ScanContext(installation=detect(root), options=options)
    return REGISTRY[check](ctx)


def by_rule(findings: list[Finding]) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings}


def snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    """Path -> (size, mtime_ns, sha256) for every file; used to prove read-only behaviour."""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            st = p.lstat()
            digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else ""
            out[str(p.relative_to(root))] = (st.st_size, st.st_mtime_ns, digest)
    return out


def can_symlink(tmp_path: Path) -> bool:
    try:
        (tmp_path / "_probe_target").write_text("x")
        (tmp_path / "_probe_link").symlink_to(tmp_path / "_probe_target")
    except (OSError, NotImplementedError):
        return False
    return True
