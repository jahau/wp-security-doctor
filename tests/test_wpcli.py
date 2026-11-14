import json
from pathlib import Path

import pytest
from conftest import by_rule, run_checks

from wp_security_doctor.integrations import wpcli
from wp_security_doctor.integrations.wpcli import CliResult
from wp_security_doctor.models import Basis, Status

CORE_FAIL_STDERR = """Warning: File doesn't verify against checksum: wp-includes/functions.php
Warning: File should not exist: wp-includes/evil.php
Warning: File doesn't exist: readme.html
Error: WordPress installation doesn't verify against checksums.
"""

PLUGIN_STDOUT = json.dumps(
    [
        {"plugin_name": "akismet", "file": "akismet.php", "message": "Checksum does not match"},
        {"plugin_name": "akismet", "file": "x.php", "message": "File was added"},
        {"plugin_name": "hello", "file": "readme.txt", "message": "File is missing"},
    ]
)
PLUGIN_STDERR = """Warning: Could not retrieve the checksums for version 2.0 of plugin premium-thing, skipping.
Error: Only verified 1 of 3 plugins (2 failed).
"""


def test_parse_core_failure() -> None:
    parsed = wpcli.parse_core(CliResult(True, 1, "", CORE_FAIL_STDERR))
    assert parsed.modified == ["wp-includes/functions.php"]
    assert parsed.unexpected == ["wp-includes/evil.php"]
    assert parsed.missing == ["readme.html"]
    assert not parsed.success


def test_parse_core_success() -> None:
    parsed = wpcli.parse_core(CliResult(True, 0, "Success: WordPress installation verifies against checksums.\n", ""))
    assert parsed.success and not parsed.errors


def test_parse_core_unrecognised_output() -> None:
    parsed = wpcli.parse_core(CliResult(True, 255, "", "PHP Fatal error: something"))
    assert parsed.errors


def test_parse_plugins() -> None:
    parsed = wpcli.parse_plugins(CliResult(True, 1, PLUGIN_STDOUT, PLUGIN_STDERR))
    assert parsed.modified == {"akismet": ["akismet.php"]}
    assert parsed.added == {"akismet": ["x.php"]}
    assert parsed.missing == {"hello": ["readme.txt"]}
    assert parsed.unverifiable == ["premium-thing"]
    assert parsed.summary and "Only verified" in parsed.summary


def test_safe_flags_always_present(tmp_path: Path) -> None:
    for args in (wpcli.core_args(tmp_path), wpcli.plugin_args(tmp_path)):
        for flag in ("--skip-plugins", "--skip-themes", "--skip-packages"):
            assert flag in args


def test_wp_cli_missing_is_skipped(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wpcli, "find_wp", lambda explicit: None)
    core = by_rule(run_checks(wp, "core", wp_cli=True, offline=False))
    plugins = by_rule(run_checks(wp, "plugins", wp_cli=True, offline=False))
    assert core["WPSD-CORE-005"].status is Status.SKIPPED
    assert plugins["WPSD-PLUGIN-003"].status is Status.SKIPPED


def test_wp_cli_results_become_verified_findings(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(wp_bin: str, args: list[str], timeout: float) -> CliResult:
        calls.append(args)
        if args[0] == "core":
            return CliResult(True, 1, "", CORE_FAIL_STDERR)
        return CliResult(True, 1, PLUGIN_STDOUT, PLUGIN_STDERR)

    monkeypatch.setattr(wpcli, "find_wp", lambda explicit: "wp")
    monkeypatch.setattr(wpcli, "run_wp", fake_run)
    core = by_rule(run_checks(wp, "core", wp_cli=True, offline=False))["WPSD-CORE-005"]
    assert core.status is Status.FAIL and core.basis is Basis.VERIFIED
    assert "wp-includes/functions.php" in core.locations
    plugins = by_rule(run_checks(wp, "plugins", wp_cli=True, offline=False))
    assert plugins["WPSD-PLUGIN-003"].status is Status.FAIL
    assert "akismet: akismet.php (modified)" in plugins["WPSD-PLUGIN-003"].locations
    assert plugins["WPSD-PLUGIN-004"].status is Status.SKIPPED
    assert plugins["WPSD-PLUGIN-004"].locations == ["premium-thing"]
    assert [c[0] for c in calls] == ["core", "plugin"]


def test_wp_cli_timeout_is_unknown(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wpcli, "find_wp", lambda explicit: "wp")
    monkeypatch.setattr(wpcli, "run_wp", lambda *a: CliResult(False, None, "", "", "WP-CLI timed out after 1s"))
    f = by_rule(run_checks(wp, "core", wp_cli=True, offline=False))["WPSD-CORE-005"]
    assert f.status is Status.UNKNOWN
    assert "timed out" in f.evidence[0]


def test_run_wp_handles_missing_binary(tmp_path: Path) -> None:
    result = wpcli.run_wp(str(tmp_path / "definitely-not-wp"), ["--info"], 5)
    assert not result.ok and result.error
