import io
import json
import urllib.error
from pathlib import Path

import pytest
from conftest import VERSION, by_rule, checksums_for, run_checks, write

from wp_security_doctor.integrations import checksums
from wp_security_doctor.models import Basis, Finding, Status


def test_no_checksum_source_is_skipped(wp: Path) -> None:
    f = by_rule(run_checks(wp, "core"))
    assert f["WPSD-CORE-001"].status is Status.PASS
    assert f"declared version: {VERSION}" in f["WPSD-CORE-001"].evidence
    for rid in ("WPSD-CORE-002", "WPSD-CORE-003", "WPSD-CORE-004"):
        assert f[rid].status is Status.SKIPPED
        assert "--core-checksums" in f[rid].remediation
    assert "WPSD-CORE-005" not in f  # WP-CLI is opt-in


def _core(wp: Path, checksum_file: Path) -> dict[str, Finding]:
    return by_rule(run_checks(wp, "core", core_checksums_file=checksum_file))


def test_pristine_core_verifies(wp: Path, checksum_file: Path) -> None:
    f = _core(wp, checksum_file)
    assert f["WPSD-CORE-002"].status is Status.PASS
    assert f["WPSD-CORE-002"].basis is Basis.VERIFIED
    assert f["WPSD-CORE-003"].status is Status.PASS
    assert f["WPSD-CORE-004"].status is Status.PASS


def test_modified_core_file_is_confirmed_failure(wp: Path, checksum_file: Path) -> None:
    write(wp / "wp-includes" / "functions.php", "<?php /* injected */ eval($_POST['x']);\n")
    f = _core(wp, checksum_file)["WPSD-CORE-002"]
    assert f.status is Status.FAIL
    assert f.basis is Basis.VERIFIED
    assert f.locations == ["wp-includes/functions.php"]


def test_unexpected_and_missing_core_files(wp: Path, checksum_file: Path) -> None:
    write(wp / "wp-includes" / "class-wp-cache-x.php", "<?php")
    write(wp / "wp-admin" / "css" / "extra.css", "x")
    write(wp / "root-tool.php", "<?php")
    write(wp / "google123.html", "x")  # non-PHP root files are not flagged
    (wp / "wp-blog-header.php").unlink()
    f = _core(wp, checksum_file)
    assert f["WPSD-CORE-003"].status is Status.WARN
    assert f["WPSD-CORE-003"].locations == [
        "root-tool.php",
        "wp-admin/css/extra.css",
        "wp-includes/class-wp-cache-x.php",
    ]
    assert f["WPSD-CORE-004"].locations == ["wp-blog-header.php"]
    # wp-config.php and wp-content are never "unexpected".
    assert all("wp-config.php" not in x and "wp-content" not in x for x in f["WPSD-CORE-003"].locations)


def test_invalid_checksum_file_is_unknown(wp: Path, tmp_path: Path) -> None:
    bad = write(tmp_path / "bad.json", "{not json")
    f = _core(wp, bad)["WPSD-CORE-002"]
    assert f.status is Status.UNKNOWN
    assert "not valid JSON" in f.evidence[0]


def test_wrong_version_in_checksum_file(wp: Path, tmp_path: Path) -> None:
    other = write(tmp_path / "c.json", json.dumps({"checksums": {"1.0": {"a.php": "0" * 32}, "2.0": {}}}))
    assert _core(wp, other)["WPSD-CORE-002"].status is Status.UNKNOWN


@pytest.mark.parametrize(
    "payload",
    [{"checksums": False}, {"checksums": {"../evil.php": "0" * 32}}, {"checksums": {"a.php": "nothex"}}, []],
)
def test_parse_checksums_rejects_bad_input(payload: object) -> None:
    with pytest.raises(checksums.ChecksumError):
        checksums.parse_checksums(payload, VERSION)


def test_parse_flat_shape() -> None:
    assert checksums.parse_checksums({"checksums": {"a.php": "A" * 32}}, VERSION) == {"a.php": "a" * 32}


def test_fetch_is_not_used_offline(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("network used in offline mode")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    f = by_rule(run_checks(wp, "core", fetch_checksums=True, offline=True))
    assert f["WPSD-CORE-002"].status is Status.SKIPPED


def test_fetch_checksums_online(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"checksums": checksums_for(wp)}).encode()
    seen = {}

    class Resp(io.BytesIO):
        def __enter__(self) -> "Resp":
            return self

        def __exit__(self, *a: object) -> None:
            pass

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        seen["url"] = req.full_url
        return Resp(body)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    f = by_rule(run_checks(wp, "core", fetch_checksums=True, offline=False))
    assert f["WPSD-CORE-002"].status is Status.PASS
    assert seen["url"].startswith("https://api.wordpress.org/core/checksums/1.0/?version=6.6.2&locale=en_US")


def test_fetch_failure_is_unknown(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*a: object, **k: object) -> None:
        raise urllib.error.URLError("no route")

    monkeypatch.setattr("urllib.request.urlopen", fail)
    f = by_rule(run_checks(wp, "core", fetch_checksums=True, offline=False))
    assert f["WPSD-CORE-002"].status is Status.UNKNOWN
