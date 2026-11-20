"""CI smoke test: run the installed CLI with --format sarif and validate the log.

Usage: python tests/sarif_smoke.py WORKDIR

Builds a synthetic WordPress tree in WORKDIR, runs the ``wp-security-doctor`` entry point
exactly as a workflow would, validates the SARIF file against the vendored OASIS schema and
checks that the tree is unchanged. Not collected by pytest.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from conftest import config_php, make_core, snapshot, write  # noqa: E402
from jsonschema import Draft4Validator  # noqa: E402


def main(workdir: Path) -> int:
    shutil.rmtree(workdir, ignore_errors=True)
    site = workdir / "repo"
    core = make_core(site / "public_html")
    write(site / "wp-config.php", config_php("define( 'WP_DEBUG', true );", hardened=False))
    write(core / "wp-content" / "uploads" / "x.php", "<?php eval(base64_decode('eA=='));")
    before = snapshot(site)
    out = workdir / "wp-security-doctor.sarif"
    exe = shutil.which("wp-security-doctor")
    cmd = [exe] if exe else [sys.executable, "-m", "wp_security_doctor"]
    proc = subprocess.run(
        [
            *cmd,
            "scan",
            str(core),
            "--offline",
            "--format",
            "sarif",
            "--sarif-path-prefix",
            "public_html",
            "-o",
            str(out),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 1:  # HIGH findings present, default --fail-on high
        print(f"unexpected exit code {proc.returncode}: {proc.stderr}", file=sys.stderr)
        return 1
    log = json.loads(out.read_text(encoding="utf-8"))
    schema = json.loads((HERE / "fixtures" / "sarif" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    errors = list(Draft4Validator(schema).iter_errors(log))
    for e in errors[:10]:
        print(f"schema error at {list(e.absolute_path)}: {e.message}", file=sys.stderr)
    if errors:
        return 1
    if snapshot(site) != before:
        print("the scan modified the tree", file=sys.stderr)
        return 1
    text = out.read_text(encoding="utf-8")
    if str(workdir) in text or workdir.as_posix() in text:
        print("absolute path leaked into SARIF", file=sys.stderr)
        return 1
    results = log["runs"][0]["results"]
    print(f"SARIF OK: {len(results)} result(s), {len(log['runs'][0]['tool']['driver']['rules'])} rule(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
