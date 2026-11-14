"""End-to-end tests through the CLI entry points."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import DB_PASSWORD, SALTS, config_php, make_core, snapshot, write

from wp_security_doctor import __version__
from wp_security_doctor.cli import all_rules, main

REPO = Path(__file__).resolve().parents[1]


def run_json(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    code = main(["scan", *args, "--format", "json"])
    return code, json.loads(capsys.readouterr().out)


def test_json_report_structure(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, data = run_json(capsys, str(wp))
    assert code == 0
    assert data["schema_version"] == 1
    assert data["tool"] == {"name": "wp-security-doctor", "version": __version__}
    assert data["scan"]["offline"] is True and data["scan"]["read_only"] is True
    assert data["target"]["wordpress_version"] == "6.6.2"
    assert "does not mean the site is secure" in data["disclaimer"]
    required = {
        "rule_id",
        "severity",
        "status",
        "basis",
        "locations",
        "evidence",
        "explanation",
        "remediation",
        "references",
        "title",
        "category",
    }
    for f in data["findings"]:
        assert required <= f.keys()
        assert f["severity"] in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert f["status"] in {"PASS", "WARN", "FAIL", "SKIPPED", "UNKNOWN"}
    assert sum(data["summary"]["counts"].values()) == len(data["findings"])


def test_scan_is_read_only_and_deterministic(wp: Path, checksum_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(wp / "wp-content" / "uploads" / "x.php", "<?php eval(base64_decode('eA=='));")
    before = snapshot(wp)
    _, first = run_json(capsys, str(wp), "--core-checksums", str(checksum_file))
    _, second = run_json(capsys, str(wp), "--core-checksums", str(checksum_file))
    assert snapshot(wp) == before
    assert first == second


def test_checks_filter(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, data = run_json(capsys, str(wp), "--checks", "config")
    assert {f["category"] for f in data["findings"]} == {"config"}
    assert data["scan"]["checks"] == ["config"]


def test_unknown_check_is_usage_error(wp: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(wp), "--checks", "core,bogus"])
    assert exc.value.code == 2


def test_offline_conflicts_with_network_options(wp: Path) -> None:
    for extra in (["--wp-cli"], ["--fetch-checksums"], ["--wp-cli-path", "wp"]):
        with pytest.raises(SystemExit) as exc:
            main(["scan", str(wp), "--offline", *extra])
        assert exc.value.code == 2


def test_default_scan_never_spawns_processes_or_uses_network(
    wp: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*a: object, **k: object) -> None:
        raise AssertionError("must not be called in default mode")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    assert main(["scan", str(wp), "--offline"]) == 0
    assert "No files were modified." in capsys.readouterr().out


def test_not_wordpress_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path)]) == 2
    assert "No WordPress core found" in capsys.readouterr().err


def test_fail_on_threshold(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(wp / "wp-config.php", config_php(hardened=False))  # MEDIUM/LOW warnings only
    assert main(["scan", str(wp)]) == 0  # default threshold: high
    assert main(["scan", str(wp), "--fail-on", "medium"]) == 1
    assert main(["scan", str(wp), "--fail-on", "never"]) == 0
    write(wp / "wp-config.php", config_php(salts={}))
    assert main(["scan", str(wp)]) == 1
    capsys.readouterr()


def test_output_file_must_be_outside_scan_root(wp: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(wp), "--output", str(wp / "report.json")]) == 2
    assert not (wp / "report.json").exists()
    out = tmp_path / "report.json"
    assert main(["scan", str(wp), "--format", "json", "--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["tool"]["version"] == __version__
    capsys.readouterr()


def test_secrets_are_redacted_everywhere(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A file whose *name* contains the DB password must not leak it through a location.
    write(wp / "wp-content" / "uploads" / f"{DB_PASSWORD}.php", "<?php")
    write(wp / "wp-config.php.bak", config_php())
    for fmt in ("json", "text"):
        main(["scan", str(wp), "--format", fmt, "--verbose"])
        out = capsys.readouterr().out
        assert DB_PASSWORD not in out
        for salt in SALTS.values():
            assert salt not in out
    assert "[REDACTED].php" in out


def test_parent_config_layout_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    core = make_core(tmp_path / "public_html")
    write(tmp_path / "wp-config.php", config_php("define('WP_DEBUG', true);", hardened=False))
    code, data = run_json(capsys, str(core), "--fail-on", "never")
    assert code == 0
    assert data["target"]["layout"] == "parent-config"
    statuses = {f["rule_id"]: f["status"] for f in data["findings"]}
    assert statuses["WPSD-CONFIG-002"] == "WARN"
    assert statuses["WPSD-CONFIG-003"] == "FAIL"


def test_text_output_lists_pass_with_neutral_titles(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main(["scan", str(wp), "--color", "never"])
    out = capsys.readouterr().out
    assert "PASS  WPSD-CONFIG-002   WP_DEBUG is off" in out
    assert "\033[" not in out


def test_rules_command_lists_unique_ids(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules"]) == 0
    ids = [line.split()[0] for line in capsys.readouterr().out.splitlines()]
    assert len(ids) == len(set(ids)) == len(all_rules())
    for rule in all_rules():
        assert rule.pass_title, rule.rule_id
        assert rule.references or rule.category == "scan", rule.rule_id


def test_bare_path_is_treated_as_scan(wp: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(wp), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["tool"]["name"] == "wp-security-doctor"


@pytest.mark.parametrize("entry", [["wp_doctor.py"], ["-m", "wp_security_doctor", "scan"]])
def test_legacy_and_module_entry_points(wp: Path, entry: list[str]) -> None:
    proc = subprocess.run(
        [sys.executable, *entry, str(wp), "--color", "never"],
        cwd=REPO,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "WP Security Doctor" in proc.stdout
    assert "No files were modified." in proc.stdout
