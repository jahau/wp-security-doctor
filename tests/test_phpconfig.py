from wp_security_doctor.phpconfig import Dynamic, parse_config, strip_comments


def test_literals_and_comments_are_handled() -> None:
    cfg = parse_config(
        """<?php
// define('WP_DEBUG', true);
# define('SCRIPT_DEBUG', true);
/* define('DISALLOW_FILE_EDIT', false);
   spans lines */
define( 'WP_DEBUG', false );
define("DISALLOW_FILE_EDIT", TRUE);
define('WP_MEMORY_LIMIT', 256);
define('WP_HOME', "https://example.test");
"""
    )
    assert cfg.get("WP_DEBUG").value is False
    assert cfg.get("DISALLOW_FILE_EDIT").value is True
    assert cfg.get("WP_MEMORY_LIMIT").value == 256
    assert cfg.get("WP_HOME").value == "https://example.test"
    assert cfg.get("SCRIPT_DEBUG") is None
    assert cfg.get("WP_DEBUG").line == 6


def test_comment_markers_inside_strings_are_not_comments() -> None:
    src = "define('AUTH_KEY', 'a//b#c/*d*/e');\n"
    assert strip_comments(src) == src
    assert parse_config(src).get("AUTH_KEY").value == "a//b#c/*d*/e"


def test_escaped_quotes_and_braces_in_values() -> None:
    cfg = parse_config("<?php\ndefine('AUTH_KEY', 'x\\'y{z}');\ndefine('WP_DEBUG', true);\n")
    assert cfg.get("AUTH_KEY").value == "x'y{z}"
    # Braces inside the salt string must not make WP_DEBUG look conditional.
    assert cfg.get("WP_DEBUG").conditional is False


def test_runtime_expressions_are_dynamic() -> None:
    cfg = parse_config("<?php\ndefine('WP_DEBUG', getenv('WP_DEBUG') === 'true');\ndefine('X', $foo);\n")
    assert isinstance(cfg.get("WP_DEBUG").value, Dynamic)
    assert isinstance(cfg.get("X").value, Dynamic)


def test_interpolated_double_quoted_string_is_dynamic() -> None:
    assert isinstance(parse_config('define("WP_HOME", "https://$host");').get("WP_HOME").value, Dynamic)


def test_conditional_and_ambiguous_definitions() -> None:
    cfg = parse_config(
        """<?php
if ( $env === 'dev' ) {
    define( 'WP_DEBUG', true );
} else {
    define( 'WP_DEBUG', false );
}
defined('SCRIPT_DEBUG') or define('SCRIPT_DEBUG', false);
"""
    )
    assert cfg.get("WP_DEBUG").conditional
    assert cfg.is_ambiguous("WP_DEBUG")
    assert cfg.get("SCRIPT_DEBUG").conditional
    assert not cfg.is_ambiguous("SCRIPT_DEBUG")


def test_constant_names_are_case_sensitive() -> None:
    cfg = parse_config("<?php define('wp_debug', true);")
    assert cfg.get("WP_DEBUG") is None
    assert cfg.get("wp_debug") is not None


def test_bedrock_config_define_and_table_prefix() -> None:
    cfg = parse_config("<?php\nConfig::define('DISALLOW_FILE_EDIT', true);\n$table_prefix = 'abc_';\n")
    assert cfg.get("DISALLOW_FILE_EDIT").value is True
    assert cfg.table_prefix == "abc_"


def test_secret_values_only_include_passwords_and_salts() -> None:
    cfg = parse_config(
        "<?php define('DB_NAME','wordpress'); define('DB_PASSWORD','hunter22'); define('AUTH_KEY','k' );"
    )
    assert cfg.secret_values() == {"hunter22"}  # 'k' is too short to redact meaningfully


def test_includes_other_files_detected_but_wp_settings_ignored() -> None:
    assert not parse_config("<?php require_once ABSPATH . 'wp-settings.php';").includes_other_files
    assert parse_config("<?php require __DIR__ . '/secrets.php';").includes_other_files


def test_first_unconditional_define_wins() -> None:
    cfg = parse_config("<?php\ndefine('WP_DEBUG', false);\ndefine('WP_DEBUG', true);\n")
    assert not cfg.is_ambiguous("WP_DEBUG")
    assert cfg.get("WP_DEBUG").value is False
