import os
from pathlib import Path

import pytest
from conftest import by_rule, run_checks

from wp_security_doctor.checks import permissions
from wp_security_doctor.models import Status

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")


@posix_only
def test_world_writable_entries_fail(wp: Path) -> None:
    os.chmod(wp / "wp-content" / "uploads", 0o777)
    os.chmod(wp / "index.php", 0o666)
    os.chmod(wp / "wp-config.php", 0o640)
    f = by_rule(run_checks(wp, "permissions"))
    ww = f["WPSD-PERM-001"]
    assert ww.status is Status.FAIL
    assert [loc.split(" ")[0] for loc in ww.locations] == ["index.php", "wp-content/uploads/"]
    assert f["WPSD-PERM-002"].status is Status.PASS


@posix_only
def test_world_readable_wp_config_warns(wp: Path) -> None:
    os.chmod(wp / "wp-config.php", 0o644)
    f = by_rule(run_checks(wp, "permissions"))["WPSD-PERM-002"]
    assert f.status is Status.WARN
    assert "readable by other" in f.evidence


@posix_only
def test_world_writable_wp_config_fails(wp: Path) -> None:
    os.chmod(wp / "wp-config.php", 0o666)
    assert by_rule(run_checks(wp, "permissions"))["WPSD-PERM-002"].status is Status.FAIL


def test_unsupported_platform_is_skipped(wp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(permissions, "SUPPORTED", False)
    findings = run_checks(wp, "permissions")
    assert {f.status for f in findings} == {Status.SKIPPED}
