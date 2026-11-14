from pathlib import Path

from conftest import DB_PASSWORD, SALTS, by_rule, config_php, make_core, run_checks, write

from wp_security_doctor.models import Basis, Status


def test_hardened_config_passes(wp: Path) -> None:
    f = by_rule(run_checks(wp, "config"))
    assert {r: x.status for r, x in f.items() if x.status is not Status.PASS} == {}
    assert f["WPSD-CONFIG-001"].basis is Basis.OBSERVED


def test_debug_settings_on_production(wp: Path) -> None:
    write(
        wp / "wp-config.php",
        config_php(
            "define('WP_DEBUG', true);\ndefine('WP_DEBUG_LOG', true);\ndefine('SCRIPT_DEBUG', true);", hardened=False
        ),
    )
    f = by_rule(run_checks(wp, "config"))
    assert f["WPSD-CONFIG-002"].status is Status.WARN
    display = f["WPSD-CONFIG-003"]
    assert display.status is Status.FAIL
    assert any("defaults to true" in e for e in display.evidence)
    assert f["WPSD-CONFIG-004"].status is Status.WARN
    assert f["WPSD-CONFIG-005"].status is Status.WARN
    assert f["WPSD-CONFIG-006"].status is Status.WARN
    assert f["WPSD-CONFIG-007"].status is Status.WARN


def test_debug_without_display_and_custom_log_path(wp: Path) -> None:
    write(
        wp / "wp-config.php",
        config_php(
            "define('WP_DEBUG', true);\ndefine('WP_DEBUG_DISPLAY', false);\n"
            "define('WP_DEBUG_LOG', '/var/log/wp/debug.log');",
            hardened=False,
        ),
    )
    f = by_rule(run_checks(wp, "config"))
    assert f["WPSD-CONFIG-003"].status is Status.PASS
    assert f["WPSD-CONFIG-004"].status is Status.PASS


def test_dynamic_values_are_unknown_not_pass(wp: Path) -> None:
    write(wp / "wp-config.php", config_php("define('WP_DEBUG', getenv('WP_DEBUG'));", hardened=False))
    f = by_rule(run_checks(wp, "config"))
    assert f["WPSD-CONFIG-002"].status is Status.UNKNOWN
    assert f["WPSD-CONFIG-003"].status is Status.UNKNOWN


def test_disallow_file_mods_satisfies_file_edit(wp: Path) -> None:
    write(wp / "wp-config.php", config_php("define('DISALLOW_FILE_MODS', true);", hardened=False))
    assert by_rule(run_checks(wp, "config"))["WPSD-CONFIG-006"].status is Status.PASS


def test_placeholder_salts_fail_and_values_are_not_reported(wp: Path) -> None:
    salts = dict(SALTS, AUTH_KEY="put your unique phrase here")
    del salts["NONCE_SALT"]
    write(wp / "wp-config.php", config_php(salts=salts))
    f = by_rule(run_checks(wp, "config"))["WPSD-CONFIG-008"]
    assert f.status is Status.FAIL
    text = " ".join(f.evidence)
    assert "AUTH_KEY" in text and "NONCE_SALT" in text
    for value in SALTS.values():
        assert value not in text


def test_duplicate_salts_warn(wp: Path) -> None:
    salts = dict(SALTS, NONCE_KEY=SALTS["AUTH_KEY"])
    write(wp / "wp-config.php", config_php(salts=salts))
    f = by_rule(run_checks(wp, "config"))["WPSD-CONFIG-008"]
    assert f.status is Status.WARN
    assert "AUTH_KEY, NONCE_KEY" in f.evidence[0]


def test_risky_constants(wp: Path) -> None:
    write(
        wp / "wp-config.php",
        config_php(
            "define('WP_ALLOW_REPAIR', true);\ndefine('ALLOW_UNFILTERED_UPLOADS', true);\n"
            "define('AUTOMATIC_UPDATER_DISABLED', true);"
        ),
    )
    f = by_rule(run_checks(wp, "config"))
    assert f["WPSD-CONFIG-009"].status is Status.WARN
    assert f["WPSD-CONFIG-010"].status is Status.WARN
    assert f["WPSD-CONFIG-011"].status is Status.FAIL


def test_core_auto_update_false(wp: Path) -> None:
    write(wp / "wp-config.php", config_php("define('WP_AUTO_UPDATE_CORE', false);"))
    assert by_rule(run_checks(wp, "config"))["WPSD-CONFIG-009"].status is Status.WARN
    write(wp / "wp-config.php", config_php("define('WP_AUTO_UPDATE_CORE', 'minor');"))
    assert by_rule(run_checks(wp, "config"))["WPSD-CONFIG-009"].status is Status.PASS


def test_missing_config_is_unknown(tmp_path: Path) -> None:
    root = make_core(tmp_path / "site")
    findings = run_checks(root, "config")
    assert len(findings) == 1
    assert findings[0].status is Status.UNKNOWN


def test_password_never_in_findings(wp: Path) -> None:
    findings = run_checks(wp, "config")
    blob = repr([f.to_dict() for f in findings])
    assert DB_PASSWORD not in blob
