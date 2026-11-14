from pathlib import Path

from conftest import by_rule, run_checks, write

from wp_security_doctor.models import Basis, Status

UPLOADS = Path("wp-content") / "uploads"


def test_clean_install_has_no_file_findings(wp: Path) -> None:
    f = by_rule(run_checks(wp, "files"))
    assert {r: x.status for r, x in f.items() if x.status is not Status.PASS} == {}


def test_php_in_uploads_is_heuristic_warning(wp: Path) -> None:
    write(wp / UPLOADS / "2024" / "05" / "shell.php", "<?php echo 1;")
    write(wp / UPLOADS / "cache" / "x.PHTML", "<?php echo 1;")
    write(wp / UPLOADS / "woocommerce_uploads" / "index.php", "<?php // Silence is golden.")
    f = by_rule(run_checks(wp, "files"))["WPSD-FILES-001"]
    assert f.status is Status.WARN
    assert f.basis is Basis.HEURISTIC
    assert f.locations == ["wp-content/uploads/2024/05/shell.php", "wp-content/uploads/cache/x.PHTML"]
    assert any("Silence is golden" in e for e in f.evidence)


def test_php_disguised_as_media(wp: Path) -> None:
    write(wp / UPLOADS / "2024" / "05" / "logo.png", b"\x89PNG\r\n<?php system($_GET['c']); ?>")
    f = by_rule(run_checks(wp, "files"))["WPSD-FILES-004"]
    assert f.status is Status.WARN
    assert f.locations == ["wp-content/uploads/2024/05/logo.png"]


def test_unusual_php_locations(wp: Path) -> None:
    write(wp / "wp-includes" / ".cache.php", "<?php")
    write(wp / "wp-content" / "plugins" / "x" / "image.jpg.php", "<?php")
    write(wp / "wp-content" / "upgrade" / "leftover.php", "<?php")
    write(wp / "wp-content" / "random.php", "<?php")
    write(wp / "wp-content" / "object-cache.php", "<?php")  # known drop-in, not flagged
    f = by_rule(run_checks(wp, "files"))["WPSD-FILES-002"]
    assert f.status is Status.WARN
    assert f.locations == [
        "wp-content/plugins/x/image.jpg.php (double extension)",
        "wp-content/random.php (unknown PHP file directly in wp-content)",
        "wp-content/upgrade/leftover.php (leftover in wp-content/upgrade)",
        "wp-includes/.cache.php (hidden file)",
    ]


def test_suspicious_code_patterns_report_line_numbers(wp: Path) -> None:
    write(wp / "wp-content" / "themes" / "t" / "functions.php", "<?php\n\n@eval(base64_decode($x));\n")
    write(wp / "wp-content" / "plugins" / "p" / "a.php", "<?php\nsystem($_GET['cmd']);\n")
    write(wp / "wp-content" / "plugins" / "p" / "b.php", "<?php\n$_POST['f']($_POST['a']);\n")
    write(wp / "wp-content" / "plugins" / "p" / "c.php", "<?php\n$x = '" + "A" * 5000 + "';\n")
    f = by_rule(run_checks(wp, "files"))["WPSD-FILES-003"]
    assert f.status is Status.WARN
    assert f.locations == [
        "wp-content/plugins/p/a.php:2 (execution of request input)",
        "wp-content/plugins/p/b.php:2 (call of function name taken from request input)",
        "wp-content/plugins/p/c.php:2 (long encoded payload)",
        "wp-content/themes/t/functions.php:3 (eval of decoded/obfuscated data)",
    ]


def test_benign_base64_usage_not_flagged(wp: Path) -> None:
    write(wp / "wp-content" / "plugins" / "p" / "ok.php", "<?php\n$img = base64_decode($data);\neval_helper();\n")
    assert by_rule(run_checks(wp, "files"))["WPSD-FILES-003"].status is Status.PASS


def test_leftover_files(wp: Path) -> None:
    write(wp / "wp-config.php.bak", "<?php")
    write(wp / "wp-config.php~", "<?php")
    write(wp / "backup.sql.gz", b"x")
    write(wp / "site.zip", b"x")
    write(wp / "wp-content" / "debug.log", "x")
    write(wp / "phpinfo.php", "<?php phpinfo();")
    write(wp / ".env", "X=1")
    write(wp / ".git" / "HEAD", "ref")
    f = by_rule(run_checks(wp, "files"))
    assert f["WPSD-FILES-005"].locations == ["wp-config.php.bak", "wp-config.php~"]
    assert f["WPSD-FILES-006"].locations == ["backup.sql.gz", "site.zip"]
    assert f["WPSD-FILES-007"].locations == ["wp-content/debug.log"]
    assert f["WPSD-FILES-008"].locations == [
        ".env",
        ".git/ (version control directory)",
        "phpinfo.php (calls phpinfo())",
    ]
    # wp-config-sample.php is part of core and must not be reported as a backup.
    assert all("sample" not in loc for loc in f["WPSD-FILES-005"].locations)


def test_plugin_inventory_and_autoloaded(wp: Path) -> None:
    write(wp / "wp-content" / "mu-plugins" / "host.php", "<?php")
    write(wp / "wp-content" / "advanced-cache.php", "<?php")
    write(wp / "wp-content" / "plugins" / "solo.php", "<?php\n/* Plugin Name: Solo\nVersion: 0.1 */")
    f = by_rule(run_checks(wp, "plugins"))
    assert f["WPSD-PLUGIN-001"].locations == ["hello-synthetic 1.2.3", "solo.php 0.1"]
    assert f["WPSD-PLUGIN-002"].status is Status.WARN
    assert f["WPSD-PLUGIN-002"].locations == [
        "wp-content/advanced-cache.php (drop-in)",
        "wp-content/mu-plugins/host.php (must-use plugin)",
    ]


def test_hex_escapes_only_flagged_when_they_decode_to_code(wp: Path) -> None:
    plugin = wp / "wp-content" / "plugins" / "p"
    # "\x65\x76\x61\x6c..." decodes to "eval(base64_decode" -> suspicious.
    hidden = "".join("\\x" + f"{b:02x}" for b in b"eval(base64_decode")
    write(plugin / "bad.php", f'<?php\n\n$f = "{hidden}";\n')
    # A long ASCII lookup table (as in Symfony polyfills) is not.
    table = "".join("\\x" + f"{b:02X}" for b in b" eiasntroludcmp'gvhfb,:=-q10C2*yx)(L9")
    write(plugin / "table.php", f'<?php\n$ASCII = "{table}";\n')
    f = by_rule(run_checks(wp, "files"))["WPSD-FILES-003"]
    assert f.locations == ["wp-content/plugins/p/bad.php:3 (hex-escaped code)"]


def test_info_php_without_phpinfo_is_not_flagged(wp: Path) -> None:
    write(wp / "wp-content" / "plugins" / "lib" / "vendor" / "Info.php", "<?php final class Info {}")
    assert by_rule(run_checks(wp, "files"))["WPSD-FILES-008"].status is Status.PASS
