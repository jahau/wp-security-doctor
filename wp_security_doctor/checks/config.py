"""wp-config.php security constants (static analysis, never executed)."""

from __future__ import annotations

from collections import Counter

from .. import refs
from ..context import ScanContext
from ..models import Basis, Finding, Rule, Severity, Status
from ..phpconfig import SECRET_KEYS, Definition, Dynamic, ParsedConfig

CATEGORY = "config"

CONFIG_FOUND = Rule(
    "WPSD-CONFIG-001",
    "wp-config.php located and parsed",
    CATEGORY,
    Severity.MEDIUM,
    "The configuration file was located and its define() calls were parsed statically.",
    "Make sure wp-config.php exists in the WordPress directory or its parent and is readable "
    "by the account running this audit.",
    (refs.WP_CONFIG,),
    pass_title="wp-config.php located and parsed",
)
WP_DEBUG = Rule(
    "WPSD-CONFIG-002",
    "WP_DEBUG is enabled",
    CATEGORY,
    Severity.MEDIUM,
    "WP_DEBUG turns on verbose PHP notices and debugging behaviour. On a production site it "
    "can reveal file paths, plugin internals and query details to visitors or logs.",
    "Set define( 'WP_DEBUG', false ); on production sites. Use a separate staging site for debugging.",
    (refs.DEBUGGING, refs.HARDENING),
    pass_title="WP_DEBUG is off",
)
DEBUG_DISPLAY = Rule(
    "WPSD-CONFIG-003",
    "Errors are displayed to visitors (WP_DEBUG_DISPLAY)",
    CATEGORY,
    Severity.MEDIUM,
    "When WP_DEBUG is true, WP_DEBUG_DISPLAY defaults to true, which prints PHP errors into "
    "page output. Error messages commonly disclose absolute paths and code details.",
    "Set define( 'WP_DEBUG_DISPLAY', false ); (and keep WP_DEBUG false in production).",
    (refs.DEBUGGING,),
    pass_title="PHP errors are not displayed by WordPress",
)
DEBUG_LOG = Rule(
    "WPSD-CONFIG-004",
    "Debug log written to a web-accessible default location",
    CATEGORY,
    Severity.MEDIUM,
    "WP_DEBUG_LOG = true writes wp-content/debug.log, which most web servers serve to anyone "
    "who requests it unless access is explicitly denied.",
    "Disable WP_DEBUG_LOG in production, or set it to an absolute path outside the web root, "
    "e.g. define( 'WP_DEBUG_LOG', '/var/log/wordpress/debug.log' );",
    (refs.DEBUGGING,),
    pass_title="WP_DEBUG_LOG does not target the public default path",
)
SCRIPT_DEBUG = Rule(
    "WPSD-CONFIG-005",
    "SCRIPT_DEBUG is enabled",
    CATEGORY,
    Severity.LOW,
    "SCRIPT_DEBUG loads unminified development versions of core CSS and JavaScript. It is a "
    "development setting and slightly increases information exposure and page weight.",
    "Set define( 'SCRIPT_DEBUG', false ); on production sites.",
    (refs.DEBUGGING,),
    pass_title="SCRIPT_DEBUG is off",
)
FILE_EDIT = Rule(
    "WPSD-CONFIG-006",
    "Built-in theme/plugin file editor is enabled",
    CATEGORY,
    Severity.MEDIUM,
    "Without DISALLOW_FILE_EDIT, any administrator account (including a compromised one) can "
    "edit PHP code from the dashboard, turning an account takeover into code execution.",
    "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php. DISALLOW_FILE_MODS = true "
    "also disables the editor but additionally blocks plugin/theme installs and updates.",
    (refs.HARDENING, refs.WP_CONFIG),
    pass_title="Dashboard file editor is disabled",
)
FORCE_SSL = Rule(
    "WPSD-CONFIG-007",
    "FORCE_SSL_ADMIN is not enabled",
    CATEGORY,
    Severity.LOW,
    "FORCE_SSL_ADMIN makes WordPress require HTTPS for logins and the dashboard. HTTPS may "
    "also be enforced by the web server or a proxy, which this offline audit cannot see.",
    "If the site is served over HTTPS, add define( 'FORCE_SSL_ADMIN', true ); or verify that "
    "the web server redirects all admin traffic to HTTPS.",
    (refs.HTTPS, refs.WP_CONFIG),
    pass_title="FORCE_SSL_ADMIN is enabled",
)
SALTS = Rule(
    "WPSD-CONFIG-008",
    "Authentication keys and salts",
    CATEGORY,
    Severity.HIGH,
    "The eight keys/salts sign login cookies and nonces. Missing, placeholder or short values "
    "make cookies easier to forge.",
    "Generate fresh values from the official generator and replace all eight definitions. "
    "This logs out every user, which is intended.",
    (refs.SALT_GENERATOR, refs.WP_CONFIG),
    pass_title="Authentication keys/salts are set",
)
AUTO_UPDATES = Rule(
    "WPSD-CONFIG-009",
    "Automatic core updates are disabled",
    CATEGORY,
    Severity.LOW,
    "Disabling the background updater means security releases are not applied automatically.",
    "Remove AUTOMATIC_UPDATER_DISABLED / WP_AUTO_UPDATE_CORE = false, or make sure a "
    "documented process applies WordPress security releases promptly.",
    (refs.UPGRADING,),
    pass_title="Automatic core updates are not disabled",
)
ALLOW_REPAIR = Rule(
    "WPSD-CONFIG-010",
    "Database repair page is enabled (WP_ALLOW_REPAIR)",
    CATEGORY,
    Severity.MEDIUM,
    "With WP_ALLOW_REPAIR true, /wp-admin/maint/repair.php is reachable without logging in "
    "and can be used to trigger expensive database operations.",
    "Remove define( 'WP_ALLOW_REPAIR', true ); once the repair is finished.",
    (refs.WP_CONFIG,),
    pass_title="WP_ALLOW_REPAIR is off",
)
UNFILTERED_UPLOADS = Rule(
    "WPSD-CONFIG-011",
    "Unfiltered uploads are allowed (ALLOW_UNFILTERED_UPLOADS)",
    CATEGORY,
    Severity.HIGH,
    "ALLOW_UNFILTERED_UPLOADS lets privileged users upload any file type, including "
    "executable scripts, bypassing WordPress' MIME type allow-list.",
    "Remove define( 'ALLOW_UNFILTERED_UPLOADS', true ); and allow specific extra MIME types "
    "with the upload_mimes filter instead.",
    (refs.WP_CONFIG, refs.HARDENING),
    pass_title="ALLOW_UNFILTERED_UPLOADS is off",
)

PLACEHOLDER = "put your unique phrase here"
MIN_SALT_LENGTH = 32


class _Const:
    """Effective value of a constant as far as static analysis can tell."""

    def __init__(self, cfg: ParsedConfig, name: str) -> None:
        self.name = name
        self.defn: Definition | None = cfg.get(name)
        self.ambiguous = cfg.is_ambiguous(name)

    @property
    def unknown(self) -> bool:
        return self.ambiguous or (self.defn is not None and isinstance(self.defn.value, Dynamic))

    @property
    def is_set(self) -> bool:
        return self.defn is not None

    def truthy(self) -> bool:
        return self.defn is not None and not self.unknown and bool(self.defn.value)

    def falsy_explicit(self) -> bool:
        return self.defn is not None and not self.unknown and not bool(self.defn.value)

    def describe(self) -> str:
        if self.defn is None:
            return f"{self.name} is not defined"
        if self.ambiguous:
            return f"{self.name} is defined more than once with different values (line {self.defn.line} first)"
        if isinstance(self.defn.value, Dynamic):
            return f"{self.name} is set from a runtime expression (line {self.defn.line})"
        cond = " inside a conditional block" if self.defn.conditional else ""
        return f"{self.name} = {_fmt(self.defn.value)} (line {self.defn.line}{cond})"


def _fmt(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f"'{value}'"
    return str(value)


def _unknown(rule: Rule, const: _Const, loc: str) -> Finding:
    return rule.finding(
        Status.UNKNOWN,
        Basis.OBSERVED,
        severity=Severity.INFO,
        locations=[loc],
        evidence=[const.describe()],
        explanation="The value is computed at runtime or defined in more than one place, so it "
        "cannot be determined without executing PHP. " + rule.explanation,
    )


def run(ctx: ScanContext) -> list[Finding]:
    inst = ctx.installation
    cfg = ctx.config
    if inst.config_path is None:
        return [
            CONFIG_FOUND.finding(
                Status.UNKNOWN,
                Basis.OBSERVED,
                title="wp-config.php not found",
                explanation="No wp-config.php was found in the WordPress directory or its parent, so "
                "configuration constants could not be checked.",
            )
        ]
    loc = inst.rel(inst.config_path)
    if cfg is None:
        return [
            CONFIG_FOUND.finding(
                Status.UNKNOWN,
                Basis.NONE,
                title="wp-config.php could not be read",
                locations=[loc],
                explanation="wp-config.php exists but could not be read (permissions or size limit).",
            )
        ]

    evidence = [f"location: {loc}" + (" (parent directory, outside scan root)" if inst.config_outside_root else "")]
    for extra in inst.extra_config_paths:
        evidence.append(f"also parsed: {inst.rel(extra)}")
    unparsed_note = ""
    if cfg.includes_other_files:
        unparsed_note = "wp-config.php includes other files that were not parsed; constants may be defined there"
        evidence.append(unparsed_note)
    findings = [CONFIG_FOUND.passed(evidence=evidence, locations=[loc])]

    def c(name: str) -> _Const:
        return _Const(cfg, name)

    def ev(*consts: _Const) -> list[str]:
        lines = [k.describe() for k in consts]
        if unparsed_note and any(not k.is_set for k in consts):
            lines.append(unparsed_note)
        return lines

    debug = c("WP_DEBUG")
    display = c("WP_DEBUG_DISPLAY")
    log = c("WP_DEBUG_LOG")

    # WP_DEBUG
    if debug.unknown:
        findings.append(_unknown(WP_DEBUG, debug, loc))
    elif debug.truthy():
        findings.append(WP_DEBUG.finding(Status.WARN, Basis.OBSERVED, locations=[loc], evidence=ev(debug)))
    else:
        findings.append(WP_DEBUG.passed(evidence=ev(debug), locations=[loc]))

    # WP_DEBUG_DISPLAY (only effective when WP_DEBUG is on)
    if debug.unknown or display.unknown:
        findings.append(_unknown(DEBUG_DISPLAY, display if display.unknown else debug, loc))
    elif debug.truthy() and not display.falsy_explicit():
        display_ev = ev(debug, display)
        if not display.is_set:
            display_ev.append("WP_DEBUG_DISPLAY defaults to true when not defined")
        findings.append(DEBUG_DISPLAY.finding(Status.FAIL, Basis.OBSERVED, locations=[loc], evidence=display_ev))
    else:
        findings.append(DEBUG_DISPLAY.passed(evidence=ev(debug, display), locations=[loc]))

    # WP_DEBUG_LOG
    if debug.unknown or log.unknown:
        findings.append(_unknown(DEBUG_LOG, log if log.unknown else debug, loc))
    elif debug.truthy() and log.truthy():
        value = log.defn.value if log.defn else True
        if isinstance(value, str) and value not in ("1", "true"):
            findings.append(
                DEBUG_LOG.passed(
                    evidence=[*ev(debug, log), "custom log path; make sure it is outside the web root"],
                    locations=[loc],
                )
            )
        else:
            findings.append(DEBUG_LOG.finding(Status.WARN, Basis.OBSERVED, locations=[loc], evidence=ev(debug, log)))
    else:
        findings.append(DEBUG_LOG.passed(evidence=ev(debug, log), locations=[loc]))

    # SCRIPT_DEBUG
    script = c("SCRIPT_DEBUG")
    if script.unknown:
        findings.append(_unknown(SCRIPT_DEBUG, script, loc))
    elif script.truthy():
        findings.append(SCRIPT_DEBUG.finding(Status.WARN, Basis.OBSERVED, locations=[loc], evidence=ev(script)))
    else:
        findings.append(SCRIPT_DEBUG.passed(evidence=ev(script), locations=[loc]))

    # DISALLOW_FILE_EDIT / DISALLOW_FILE_MODS
    edit, mods = c("DISALLOW_FILE_EDIT"), c("DISALLOW_FILE_MODS")
    if edit.truthy() or mods.truthy():
        findings.append(FILE_EDIT.passed(evidence=ev(edit, mods), locations=[loc]))
    elif edit.unknown or mods.unknown:
        findings.append(_unknown(FILE_EDIT, edit if edit.unknown else mods, loc))
    else:
        findings.append(FILE_EDIT.finding(Status.WARN, Basis.OBSERVED, locations=[loc], evidence=ev(edit, mods)))

    # FORCE_SSL_ADMIN
    ssl = c("FORCE_SSL_ADMIN")
    if ssl.unknown:
        findings.append(_unknown(FORCE_SSL, ssl, loc))
    elif ssl.truthy():
        findings.append(FORCE_SSL.passed(evidence=ev(ssl), locations=[loc]))
    else:
        findings.append(FORCE_SSL.finding(Status.WARN, Basis.OBSERVED, locations=[loc], evidence=ev(ssl)))

    findings.append(_check_salts(cfg, loc))

    # Automatic updates
    upd_off, core_upd = c("AUTOMATIC_UPDATER_DISABLED"), c("WP_AUTO_UPDATE_CORE")
    core_disabled = not core_upd.unknown and core_upd.defn is not None and core_upd.defn.value is False
    if upd_off.unknown or core_upd.unknown:
        findings.append(_unknown(AUTO_UPDATES, upd_off if upd_off.unknown else core_upd, loc))
    elif upd_off.truthy() or core_disabled:
        findings.append(
            AUTO_UPDATES.finding(Status.WARN, Basis.OBSERVED, locations=[loc], evidence=ev(upd_off, core_upd))
        )
    else:
        findings.append(AUTO_UPDATES.passed(evidence=ev(upd_off, core_upd), locations=[loc]))

    for rule, name in ((ALLOW_REPAIR, "WP_ALLOW_REPAIR"), (UNFILTERED_UPLOADS, "ALLOW_UNFILTERED_UPLOADS")):
        k = c(name)
        if k.unknown:
            findings.append(_unknown(rule, k, loc))
        elif k.truthy():
            status = Status.FAIL if rule is UNFILTERED_UPLOADS else Status.WARN
            findings.append(rule.finding(status, Basis.OBSERVED, locations=[loc], evidence=ev(k)))
        else:
            findings.append(rule.passed(evidence=ev(k), locations=[loc]))
    return findings


def _check_salts(cfg: ParsedConfig, loc: str) -> Finding:
    missing, weak, dynamic = [], [], []
    values: dict[str, str] = {}
    for key in SECRET_KEYS:
        const = _Const(cfg, key)
        if const.defn is None:
            missing.append(key)
        elif const.unknown:
            dynamic.append(key)
        else:
            val = const.defn.value
            if not isinstance(val, str) or val.strip().lower() == PLACEHOLDER or len(val) < MIN_SALT_LENGTH:
                weak.append(key)
            else:
                values[key] = val
    dupes = sorted(k for k, v in values.items() if Counter(values.values())[v] > 1)

    # Evidence names constants only; secret values are never included.
    evidence = []
    if missing:
        evidence.append("not defined: " + ", ".join(missing))
    if weak:
        evidence.append(f"placeholder, empty or shorter than {MIN_SALT_LENGTH} characters: " + ", ".join(weak))
    if dupes:
        evidence.append("identical values shared by: " + ", ".join(dupes))
    if dynamic:
        evidence.append("set from runtime expressions (not evaluated): " + ", ".join(dynamic))

    if missing or weak:
        return SALTS.finding(
            Status.FAIL,
            Basis.OBSERVED,
            locations=[loc],
            evidence=evidence,
            title="Authentication keys/salts are missing or weak",
        )
    if dupes:
        return SALTS.finding(
            Status.WARN,
            Basis.OBSERVED,
            severity=Severity.MEDIUM,
            locations=[loc],
            evidence=evidence,
            title="Authentication keys/salts reuse the same value",
        )
    if dynamic and len(dynamic) == len(SECRET_KEYS):
        return SALTS.finding(
            Status.UNKNOWN,
            Basis.OBSERVED,
            severity=Severity.INFO,
            locations=[loc],
            evidence=evidence,
            title="Authentication keys/salts are set at runtime",
        )
    return SALTS.passed(
        evidence=evidence or ["all 8 keys/salts defined with unique, non-placeholder values"], locations=[loc]
    )
