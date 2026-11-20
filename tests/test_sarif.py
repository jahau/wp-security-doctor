"""SARIF 2.1.0 export: schema validity, GitHub constraints, privacy and compatibility."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from conftest import DB_PASSWORD, SALTS, config_php, make_core, snapshot, write
from jsonschema import Draft4Validator

from wp_security_doctor import __version__, checks
from wp_security_doctor.cli import all_rules, main
from wp_security_doctor.sarif import _Locator, _Scrubber, normalise_prefix

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sarif"
SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
GOLDEN = FIXTURES / "expected-issues.sarif"
VALIDATOR = Draft4Validator(SCHEMA)


def run_sarif(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, dict[str, Any]]:
    code = main(["scan", *args, "--format", "sarif"])
    return code, json.loads(capsys.readouterr().out)


def assert_valid(log: dict[str, Any]) -> None:
    errors = sorted(VALIDATOR.iter_errors(log), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message}" for e in errors[:10])


def assert_github_compatible(log: dict[str, Any]) -> None:
    """Constraints from GitHub's 'SARIF support for code scanning' documentation."""
    assert log["version"] == "2.1.0" and log["$schema"]
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) <= 25_000 and len(run["results"]) <= 5_000
    for rule in rules:
        assert len(rule["shortDescription"]["text"]) <= 1024
        assert len(rule["fullDescription"]["text"]) <= 1024
        props = rule.get("properties", {})
        assert len(props.get("tags", [])) <= 20
        if "security-severity" in props:
            assert "security" in props["tags"]
            assert 0.1 <= float(props["security-severity"]) <= 10.0
    for result in run["results"]:
        assert result["message"]["text"]
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert len(result["locations"]) == 1, result
        phys = result["locations"][0]["physicalLocation"]
        uri = phys["artifactLocation"]["uri"]
        assert not uri.startswith("/") and ".." not in uri.split("/") and ":" not in uri and "\\" not in uri
        assert phys["region"]["startLine"] >= 1


def issues_site(root: Path) -> Path:
    """Parent-config layout with a selection of problems; nothing platform dependent."""
    core = make_core(root / "public_html")
    write(
        root / "wp-config.php",
        config_php(
            "define( 'WP_DEBUG', true );\ndefine( 'WP_DEBUG_LOG', '/srv/private-host-name/logs/debug.log' );",
            hardened=False,
        ),
    )
    write(core / "wp-content" / "uploads" / "2024" / "05" / "shell me.php", "<?php eval(base64_decode('eA=='));")
    write(core / "wp-content" / "uploads" / f"{DB_PASSWORD}.php", "<?php")
    write(core / "wp-config.php.bak", "<?php // copy")
    write(core / "backup.sql", "-- dump")
    return core


GOLDEN_ARGS = ("--checks", "config,files", "--sarif-path-prefix", "public_html", "--fail-on", "never")


def normalised(log: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(log).replace(f'"{__version__}"', '"<version>"')
    return json.loads(text)  # type: ignore[no-any-return]


def test_golden_fixture_matches_and_validates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    core = issues_site(tmp_path / "site")
    code, log = run_sarif(capsys, str(core), *GOLDEN_ARGS)
    assert code == 0
    assert_valid(log)
    assert_github_compatible(log)
    if os.environ.get("WPSD_UPDATE_GOLDEN"):
        GOLDEN.write_text(json.dumps(normalised(log), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert normalised(log) == expected, "run with WPSD_UPDATE_GOLDEN=1 to refresh after an intended change"


def test_golden_fixture_itself_is_schema_valid() -> None:
    log = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert_valid(json.loads(json.dumps(log).replace('"<version>"', '"0.0.0"')))


@pytest.mark.parametrize("extra", [[], ["--verbose"], ["--checks", "core"], ["--checks", "permissions,plugins"]])
def test_clean_site_is_valid(wp: Path, capsys: pytest.CaptureFixture[str], extra: list[str]) -> None:
    code, log = run_sarif(capsys, str(wp), *extra)
    assert code == 0
    assert_valid(log)
    assert_github_compatible(log)


def test_checksum_mismatch_is_valid_and_verified(
    wp: Path, checksum_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write(wp / "wp-includes" / "functions.php", "<?php // tampered")
    write(wp / "wp-admin" / "extra.php", "<?php")
    code, log = run_sarif(capsys, str(wp), "--core-checksums", str(checksum_file))
    assert code == 1
    assert_valid(log)
    assert_github_compatible(log)
    by_rule = {r["ruleId"]: r for r in log["runs"][0]["results"]}
    hit = by_rule["WPSD-CORE-002"]
    assert hit["level"] == "error" and hit["properties"]["basis"] == "verified"
    assert hit["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "wp-includes/functions.php"
    assert (
        by_rule["WPSD-CORE-003"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "wp-admin/extra.php"
    )


def test_rules_are_stable_and_complete(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, log = run_sarif(capsys, str(wp))
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "wp-security-doctor" and driver["version"] == __version__
    assert [r["id"] for r in driver["rules"]] == [r.rule_id for r in all_rules()]
    levels = {r["id"]: r["defaultConfiguration"]["level"] for r in driver["rules"]}
    assert levels["WPSD-CONFIG-008"] == "error"  # HIGH
    assert levels["WPSD-CONFIG-002"] == "warning"  # MEDIUM
    assert levels["WPSD-CONFIG-005"] == "note"  # LOW
    sev = {r["id"]: r["properties"].get("security-severity") for r in driver["rules"]}
    assert sev["WPSD-FILES-001"] == "8.0" and sev["WPSD-CONFIG-002"] == "5.5" and sev["WPSD-CORE-001"] is None


def test_results_notifications_and_locations(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    core = issues_site(tmp_path / "site")
    _, log = run_sarif(capsys, str(core), *GOLDEN_ARGS)
    run = log["runs"][0]
    results = run["results"]
    statuses = {r["properties"]["status"] for r in results}
    assert statuses <= {"FAIL", "WARN"}
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert "public_html/wp-content/uploads/2024/05/shell%20me.php" in uris
    assert "wp-config.php" in uris  # parent-directory config resolved through the prefix
    code_hit = next(r for r in results if r["ruleId"] == "WPSD-FILES-003")
    assert code_hit["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    debug = next(r for r in results if r["ruleId"] == "WPSD-CONFIG-002")
    assert debug["locations"][0]["physicalLocation"]["region"]["startLine"] > 1  # line of the define()
    fps = [r["partialFingerprints"]["wpsdLocationHash/v1"] for r in results]
    assert len(fps) == len(set(fps))
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert all(n["associatedRule"]["id"].startswith("WPSD-") for n in notes)
    assert run["invocations"][0]["executionSuccessful"] is True


def test_no_secrets_or_absolute_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    core = issues_site(tmp_path / "site")
    for extra in ([], ["--sarif-path-prefix", "public_html"]):
        main(["scan", str(core), "--format", "sarif", "--verbose", *extra])
        out = capsys.readouterr().out
        assert DB_PASSWORD not in out
        for salt in SALTS.values():
            assert salt not in out
        for form in {str(tmp_path), tmp_path.as_posix(), str(tmp_path).replace("\\", "\\\\")}:
            assert form not in out
        assert "private-host-name" not in out
        assert os.path.expanduser("~").replace("\\", "/").rstrip("/") not in out.replace("\\\\", "/")
        assert "%5BREDACTED%5D.php" in out


def test_scrubber_removes_absolute_paths() -> None:
    scrub = _Scrubber(Path("/home/alice/site"))
    assert scrub("indexed under /home/alice/site") == "indexed under <scan-root>"
    assert scrub("config at /home/alice/wp-config.php") == "config at <scan-root-parent>/wp-config.php"
    assert scrub("WP_DEBUG_LOG = '/var/log/host/debug.log'") == "WP_DEBUG_LOG = '<abs-path>/debug.log'"
    assert scrub(r"error C:\Users\bob\x.json here") == "error <abs-path>/x.json here"
    assert scrub("see https://developer.wordpress.org/a/b/") == "see https://developer.wordpress.org/a/b/"
    assert scrub("wp-content/uploads/a.php and entr(y/ies)") == "wp-content/uploads/a.php and entr(y/ies)"


def test_location_parsing(wp: Path) -> None:
    from wp_security_doctor.context import ScanOptions
    from wp_security_doctor.detect import detect
    from wp_security_doctor.scanner import ScanReport

    loc = _Locator(ScanReport(detect(wp), ScanOptions(), []), "")
    assert loc.parse("WPSD-FILES-003", "a/b.php:42 (eval)") == ("a/b.php", 42, "eval")
    assert loc.parse("WPSD-PERM-001", "wp-content/ drwxrwxrwx (0777)") == ("wp-content", None, "drwxrwxrwx (0777)")
    assert loc.parse("WPSD-FILES-008", ".git/ (version control directory)") == (
        ".git",
        None,
        "version control directory",
    )
    assert loc.parse("WPSD-PLUGIN-003", "akismet: x/y.php (modified)") == (
        "wp-content/plugins/akismet/x/y.php",
        None,
        "modified",
    )
    assert loc.parse("WPSD-FILES-001", "... and 7 more") == (None, None, None)
    assert loc.parse("WPSD-PLUGIN-001", "hello 1.2.3") == (None, None, None)
    assert loc.parse("WPSD-FILES-001", "/etc/passwd")[0] is None
    assert loc.parse("WPSD-FILES-001", "../outside.php")[0] is None


@pytest.mark.parametrize("prefix,expected", [("", ""), ("web/", "web"), ("./a//b", "a/b"), ("a\\b", "a/b"), (".", "")])
def test_prefix_normalisation(prefix: str, expected: str) -> None:
    assert normalise_prefix(prefix) == expected


@pytest.mark.parametrize("prefix", ["../x", "/abs", "C:\\x", "a/../../b"])
def test_bad_prefix_is_usage_error(wp: Path, prefix: str) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(wp), "--format", "sarif", "--sarif-path-prefix", prefix])
    assert exc.value.code == 2


def test_prefix_requires_sarif_format(wp: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(wp), "--sarif-path-prefix", "web"])
    assert exc.value.code == 2


def test_exit_codes_match_other_formats(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    core = issues_site(tmp_path / "site")
    for fail_on in ("high", "medium", "never", "critical"):
        codes = {
            fmt: main(["scan", str(core), "--format", fmt, "--fail-on", fail_on]) for fmt in ("text", "json", "sarif")
        }
        assert len(set(codes.values())) == 1, (fail_on, codes)
    capsys.readouterr()
    assert main(["scan", str(tmp_path / "nothing-here"), "--format", "sarif"]) == 2


def test_json_output_unchanged_by_sarif_support(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    core = issues_site(tmp_path / "site")
    main(["scan", str(core), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == 1
    assert set(data) == {"schema_version", "tool", "target", "scan", "summary", "disclaimer", "findings"}
    assert "sarif" not in json.dumps(data).lower()


def test_sarif_scan_is_read_only_deterministic_and_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*a: object, **k: object) -> None:
        raise AssertionError("must not be called in default mode")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    core = issues_site(tmp_path / "site")
    before = snapshot(tmp_path / "site")
    _, first = run_sarif(capsys, str(core), "--offline")
    _, second = run_sarif(capsys, str(core), "--offline")
    assert snapshot(tmp_path / "site") == before
    assert first == second
    inv = first["runs"][0]["invocations"][0]
    assert inv["properties"] == {
        "readOnly": True,
        "offline": True,
        "networkIntegrations": [],
        "checks": ["core", "config", "files", "permissions", "plugins"],
    }
    assert not re.search(r"\d{4}-\d{2}-\d{2}T", json.dumps(first))  # no timestamps


def test_output_file_and_check_failure(
    wp: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(ctx: object) -> list[object]:
        raise RuntimeError(f"failure while reading {wp / 'wp-content'}")

    monkeypatch.setitem(checks.REGISTRY, "plugins", boom)
    out = tmp_path / "report.sarif"
    assert main(["scan", str(wp), "--format", "sarif", "--output", str(out)]) == 0
    assert capsys.readouterr().out == ""
    log = json.loads(out.read_text(encoding="utf-8"))
    assert_valid(log)
    inv = log["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    err = next(n for n in inv["toolExecutionNotifications"] if n["associatedRule"]["id"] == "WPSD-SCAN-002")
    assert err["level"] == "error"
    assert re.search(r"<scan-root>[/\\]wp-content", err["message"]["text"])
    assert str(wp) not in out.read_text(encoding="utf-8")
