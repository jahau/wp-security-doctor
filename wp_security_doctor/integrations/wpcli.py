"""Optional WP-CLI integration for checksum verification.

Only used when the user passes ``--wp-cli``. Important side effects, which the
CLI documents and the report repeats:

* ``wp core verify-checksums`` and ``wp plugin verify-checksums`` download
  checksums from api.wordpress.org / downloads.wordpress.org (network access).
* ``wp core verify-checksums`` runs before WordPress is loaded.
  ``wp plugin verify-checksums`` has to bootstrap WordPress to list plugins,
  which executes wp-config.php and core. Plugins, themes and WP-CLI packages
  are skipped with ``--skip-plugins --skip-themes --skip-packages``.
* WP-CLI is run as the current user with an argument list (never a shell).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SAFE_FLAGS = ("--skip-plugins", "--skip-themes", "--skip-packages", "--no-color")


@dataclass
class CliResult:
    ok: bool  # command ran (regardless of exit code)
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None


@dataclass
class CoreVerification:
    success: bool
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    unexpected: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class PluginVerification:
    modified: dict[str, list[str]] = field(default_factory=dict)  # plugin -> files
    missing: dict[str, list[str]] = field(default_factory=dict)
    added: dict[str, list[str]] = field(default_factory=dict)
    unverifiable: list[str] = field(default_factory=list)
    summary: str | None = None
    errors: list[str] = field(default_factory=list)


def find_wp(explicit: str | None) -> str | None:
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        return shutil.which(explicit)
    return shutil.which("wp")


def run_wp(wp: str, args: list[str], timeout: float) -> CliResult:
    env = dict(os.environ)
    env["WP_CLI_DISABLE_AUTO_CHECK_UPDATE"] = "1"
    cmd = [wp, *args]
    # A .phar has to be run through PHP; everything else (wp, wp.bat) directly.
    if wp.lower().endswith(".phar"):
        php = shutil.which("php")
        if php is None:
            return CliResult(False, None, "", "", "php executable not found for running the WP-CLI phar")
        cmd = [php, *cmd]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argument list, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return CliResult(False, None, "", "", f"WP-CLI executable not found: {wp}")
    except subprocess.TimeoutExpired:
        return CliResult(False, None, "", "", f"WP-CLI timed out after {timeout:.0f}s")
    except OSError as exc:
        return CliResult(False, None, "", "", f"could not run WP-CLI: {exc}")
    return CliResult(True, proc.returncode, proc.stdout or "", proc.stderr or "")


_CORE_PATTERNS = (
    ("modified", re.compile(r"File doesn't verify against checksum:\s*(.+)$")),
    ("missing", re.compile(r"File doesn't exist:\s*(.+)$")),
    ("unexpected", re.compile(r"File should not exist:\s*(.+)$")),
)


def parse_core(result: CliResult) -> CoreVerification:
    out = CoreVerification(success=False)
    for raw in (result.stdout + "\n" + result.stderr).splitlines():
        line = raw.strip()
        for kind, pattern in _CORE_PATTERNS:
            m = pattern.search(line)
            if m:
                getattr(out, kind).append(m.group(1).strip())
                break
        else:
            if line.startswith("Success:") and "verifies against checksums" in line:
                out.success = True
            elif line.startswith("Error:") and "doesn't verify" not in line:
                out.errors.append(line)
    if not out.success and not (out.modified or out.missing or out.unexpected) and not out.errors:
        out.errors.append(f"unrecognised WP-CLI output (exit code {result.returncode})")
    for lst in (out.modified, out.missing, out.unexpected):
        lst.sort()
    return out


_UNVERIFIABLE_RE = re.compile(
    r"Could not retrieve the checksums for (?:version \S+ of )?plugin (\S+?),? skipping", re.I
)


def parse_plugins(result: CliResult) -> PluginVerification:
    out = PluginVerification()
    stdout = result.stdout.strip()
    rows: list[object] = []
    if stdout:
        start = stdout.find("[")
        try:
            parsed = json.loads(stdout[start:]) if start != -1 else []
            rows = parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            out.errors.append("could not parse WP-CLI JSON output")
    for row in rows:
        if not isinstance(row, dict):
            continue
        plugin = str(row.get("plugin_name", "?"))
        file = str(row.get("file", "?"))
        msg = str(row.get("message", "")).lower()
        if "missing" in msg:
            out.missing.setdefault(plugin, []).append(file)
        elif "added" in msg or "should not exist" in msg:
            out.added.setdefault(plugin, []).append(file)
        else:
            out.modified.setdefault(plugin, []).append(file)
    for raw in result.stderr.splitlines():
        line = raw.strip()
        m = _UNVERIFIABLE_RE.search(line)
        if m:
            out.unverifiable.append(m.group(1))
        elif line.startswith("Success:") or (line.startswith("Error:") and "Only verified" in line):
            out.summary = line
        elif line.startswith("Error:"):
            out.errors.append(line)
    if result.returncode not in (0, None) and out.summary is None and not rows and not out.errors:
        out.errors.append(f"WP-CLI exited with code {result.returncode}")
    out.unverifiable.sort()
    for d in (out.modified, out.missing, out.added):
        for files in d.values():
            files.sort()
    return out


def core_args(core_dir: Path) -> list[str]:
    return ["core", "verify-checksums", f"--path={core_dir}", *SAFE_FLAGS]


def plugin_args(core_dir: Path) -> list[str]:
    return ["plugin", "verify-checksums", "--all", "--format=json", f"--path={core_dir}", *SAFE_FLAGS]
