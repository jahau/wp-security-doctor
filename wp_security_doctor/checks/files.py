"""File-system heuristics: executable code in odd places, leftovers, known-bad patterns.

Everything here is a *heuristic*. A match means "a human should look at this",
not "this site is compromised". See README section "False positives".
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .. import refs
from ..context import ScanContext
from ..fs import Entry, read_entry
from ..models import Basis, Finding, Rule, Severity, Status

CATEGORY = "files"

UPLOADS_PHP = Rule(
    "WPSD-FILES-001",
    "PHP files in the uploads directory",
    CATEGORY,
    Severity.HIGH,
    "wp-content/uploads should only hold media and documents. Executable PHP there is a common "
    "sign of a web shell or a vulnerable upload handler, although a few plugins store PHP "
    "stubs or cache files there legitimately.",
    "Inspect each file. If it is not created by a plugin you trust, take the site offline, "
    "preserve a copy for analysis and follow the hacked-site FAQ. Prevent PHP execution in "
    "uploads at the web-server level.",
    (refs.HARDENING, refs.HACKED_FAQ),
    pass_title="No PHP files in uploads",
)
UNUSUAL_PHP = Rule(
    "WPSD-FILES-002",
    "PHP files in unusual locations or with disguised names",
    CATEGORY,
    Severity.MEDIUM,
    "Hidden PHP files, double extensions such as image.jpg.php, unknown PHP files directly in "
    "wp-content and leftovers in wp-content/upgrade are frequently used to hide malicious code.",
    "Confirm each file belongs to a plugin, theme or hosting tool you recognise; remove it "
    "otherwise (after taking a backup for forensics).",
    (refs.HARDENING, refs.HACKED_FAQ),
    pass_title="No PHP files in unusual locations",
)
SUSPICIOUS_CODE = Rule(
    "WPSD-FILES-003",
    "Code patterns associated with web shells or obfuscation",
    CATEGORY,
    Severity.HIGH,
    "These patterns (eval of decoded data, execution of request parameters, known web-shell "
    "markers, very long encoded blobs) are typical of malware, but some legitimate plugins, "
    "licensing code and libraries use them too.",
    "Review the reported lines. Compare plugin/theme files with a fresh copy from the vendor. "
    "If the code is malicious, treat the whole site as compromised.",
    (refs.HACKED_FAQ,),
    pass_title="No web-shell/obfuscation patterns matched",
)
DISGUISED_UPLOAD = Rule(
    "WPSD-FILES-004",
    "Media files in uploads that contain PHP code",
    CATEGORY,
    Severity.HIGH,
    "A file with an image or document extension whose content starts with or contains a PHP "
    "open tag is often a payload waiting to be included by another script.",
    "Open the file in a text editor (do not execute it). Remove it if it is not a genuine media "
    "file and search for the code that includes it.",
    (refs.HACKED_FAQ,),
    pass_title="No PHP code hidden in media files",
)
CONFIG_BACKUPS = Rule(
    "WPSD-FILES-005",
    "Backup copies of wp-config.php",
    CATEGORY,
    Severity.HIGH,
    "Copies such as wp-config.php.bak or wp-config.php~ are not executed by PHP, so a web "
    "server may serve them as plain text, exposing database credentials and salts.",
    "Delete the copies from the web root (keep backups elsewhere) and rotate the database "
    "password and salts if the files may have been downloaded.",
    (refs.HARDENING, refs.BACKUP),
    pass_title="No wp-config.php backup copies",
)
EXPOSED_DATA = Rule(
    "WPSD-FILES-006",
    "Database dumps or archives inside the web root",
    CATEGORY,
    Severity.HIGH,
    "SQL dumps and site archives in a web-accessible directory can be downloaded by anyone who "
    "guesses the name and usually contain password hashes and secrets.",
    "Move backups outside the web root or to off-site storage.",
    (refs.BACKUP,),
    pass_title="No database dumps or archives in the web root",
)
LOG_FILES = Rule(
    "WPSD-FILES-007",
    "Log files inside the web root",
    CATEGORY,
    Severity.MEDIUM,
    "debug.log and PHP error_log files often contain paths, queries and sometimes personal data, "
    "and are served by default by many web servers.",
    "Delete stale logs, disable debug logging in production, or write logs outside the web root.",
    (refs.DEBUGGING,),
    pass_title="No log files in the web root",
)
DEV_ARTIFACTS = Rule(
    "WPSD-FILES-008",
    "Development or administration tools left in the web root",
    CATEGORY,
    Severity.MEDIUM,
    "phpinfo() pages, database tools such as Adminer, .env files and version-control "
    "directories reveal configuration or give direct access to data.",
    "Remove these files from production or block access to them at the web-server level.",
    (refs.HARDENING,),
    pass_title="No development tools in the web root",
)

UPLOAD_STUB_RE = re.compile(rb"^\s*<\?php\s*(//|#|/\*)?\s*silence is golden\.?\s*(\*/)?\s*(\?>)?\s*$", re.I)
# Text formats (txt/css/js) are excluded: they may legitimately mention "<?php".
MEDIA_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".pdf", ".avif", ".heic")
DISGUISE_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".bmp", ".svg", ".pdf", ".zip", ".txt")
DROPINS = frozenset(
    {
        "advanced-cache.php",
        "db.php",
        "db-error.php",
        "install.php",
        "maintenance.php",
        "object-cache.php",
        "php-error.php",
        "fatal-error-handler.php",
        "sunrise.php",
        "blog-deleted.php",
        "blog-inactive.php",
        "blog-suspended.php",
        "index.php",
    }
)

# Patterns are deliberately narrow to keep false positives manageable.
CODE_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "eval of decoded/obfuscated data",
        re.compile(
            rb"\b(?:eval|assert)\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|"
            rb"rawurldecode|hex2bin|convert_uudecode)\s*\(",
            re.I,
        ),
    ),
    (
        "execution of request input",
        re.compile(
            rb"\b(?:eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?"
            rb"(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b",
            re.I,
        ),
    ),
    (
        "call of function name taken from request input",
        re.compile(rb"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", re.I),
    ),
    (
        "preg_replace with /e modifier",
        re.compile(rb"preg_replace\s*\(\s*['\"](.).{0,200}?\1[imsxADSUXu]*e[imsxADSUXu]*['\"]\s*,"),
    ),
    (
        "known web-shell marker",
        re.compile(rb"\b(?:FilesMan|WSOsetcookie|b374k|c99shell|r57shell|IndoXploit|Uname:\s*<\?)", re.I),
    ),
    ("long encoded payload", re.compile(rb"['\"][A-Za-z0-9+/]{4000,}={0,2}['\"]")),
    (
        "include of a non-PHP file",
        re.compile(rb"\b(?:include|require)(?:_once)?\s*\(?\s*['\"][^'\"]+\.(?:ico|png|jpe?g|gif|txt)['\"]", re.I),
    ),
)

# Hex-escaped strings are common in legitimate code (lookup tables, regexes), so
# they are only reported when the decoded text names an execution sink.
HEX_RUN_RE = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){6,}")
HEX_SINK_RE = re.compile(
    rb"eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|system|"
    rb"proc_open|popen|create_function|\$_(?:post|get|request|cookie)",
    re.I,
)
MAX_HEX_RUNS = 200


def hex_obfuscation(data: bytes) -> int | None:
    """Offset of the first hex-escaped run that decodes to a code sink, if any."""
    for i, m in enumerate(HEX_RUN_RE.finditer(data)):
        if i >= MAX_HEX_RUNS:
            break
        decoded = bytes.fromhex(m.group(0).replace(b"\\x", b"").decode("ascii"))
        if HEX_SINK_RE.search(decoded):
            return m.start()
    return None


def code_hits(data: bytes) -> list[tuple[int, str]]:
    """(line, label) for every pattern that matches, in pattern order."""
    hits = []
    for label, pattern in CODE_PATTERNS:
        m = pattern.search(data)
        if m:
            hits.append((data.count(b"\n", 0, m.start()) + 1, label))
    pos = hex_obfuscation(data)
    if pos is not None:
        hits.append((data.count(b"\n", 0, pos) + 1, "hex-escaped code"))
    return hits


CONFIG_BACKUP_RE = re.compile(r"^wp-config(?!-sample\.php$)[^/]*$", re.I)
DUMP_RE = re.compile(r"\.(?:sql|sql\.gz|sql\.zip|sql\.bz2|sql\.xz|mysql|dump)$", re.I)
ARCHIVE_RE = re.compile(r"\.(?:zip|tar|tar\.gz|tgz|tar\.bz2|rar|7z|wpress|bak|backup)$", re.I)
LOG_NAMES = frozenset({"debug.log", "error_log", "php_errorlog", "php_error.log", "error.log"})
DEV_NAMES = frozenset({".env", ".env.local", ".env.production", "adminer.php"})
# Common names that are only reported when the file actually calls phpinfo().
PHPINFO_NAMES = frozenset({"phpinfo.php", "info.php", "php_info.php", "pi.php", "test.php", "i.php"})
DEV_DIRS = frozenset({".git", ".svn", ".hg"})


def run(ctx: ScanContext) -> list[Finding]:
    inst = ctx.installation
    index = ctx.index
    files = index.files()
    content = ctx.root_rel(inst.content_dir) if inst.content_dir else None
    uploads = f"{content}/uploads" if content else None
    plugins_dir = f"{content}/plugins" if content else None
    limit = ctx.options.max_read_bytes

    def in_dir(e: Entry, d: str | None) -> bool:
        return d is not None and e.rel.startswith(d + "/")

    findings: list[Finding] = []

    # FILES-001 / FILES-004: uploads
    upload_php, stubs, disguised = [], 0, []
    for e in files:
        if not in_dir(e, uploads):
            continue
        if e.is_php:
            head = read_entry(ctx.root, e, 512) if e.size <= 512 else None
            if head is not None and UPLOAD_STUB_RE.match(head):
                stubs += 1
                continue
            upload_php.append(e.rel)
        elif e.name.lower().endswith(MEDIA_EXTS) and not e.is_symlink:
            head = read_entry(ctx.root, e, 8192) or b""
            if b"<?php" in head.lower() or head.lstrip().startswith(b"<?="):
                disguised.append(e.rel)
    stub_note = [f"{stubs} 'Silence is golden' index stub(s) ignored"] if stubs else []
    if uploads is None:
        findings.append(UPLOADS_PHP.skipped("no wp-content directory inside the scan root"))
    elif upload_php:
        upload_ev = [f"{len(upload_php)} PHP-like file(s) under {uploads}", *stub_note]
        findings.append(UPLOADS_PHP.finding(Status.WARN, Basis.HEURISTIC, locations=upload_php, evidence=upload_ev))
    else:
        upload_ev = [f"no PHP-like files under {uploads}", *stub_note]
        findings.append(UPLOADS_PHP.passed(evidence=upload_ev, basis=Basis.HEURISTIC))
    if uploads is not None:
        if disguised:
            findings.append(
                DISGUISED_UPLOAD.finding(
                    Status.WARN,
                    Basis.HEURISTIC,
                    locations=disguised,
                    evidence=[f"{len(disguised)} file(s) contain a PHP open tag"],
                )
            )
        else:
            findings.append(DISGUISED_UPLOAD.passed(basis=Basis.HEURISTIC))

    # FILES-002: unusual PHP locations
    unusual: list[str] = []
    for e in files:
        if not e.is_php or in_dir(e, uploads):
            continue
        name = e.name.lower()
        stem_exts = PurePosixPath(name).suffixes
        reason = None
        if name.startswith("."):
            reason = "hidden file"
        elif len(stem_exts) >= 2 and stem_exts[-2] in DISGUISE_EXTS:
            reason = "double extension"
        elif content and e.rel.startswith(f"{content}/upgrade/"):
            reason = "leftover in wp-content/upgrade"
        elif content and PurePosixPath(e.rel).parent.as_posix() == content and name not in DROPINS:
            reason = "unknown PHP file directly in wp-content"
        if reason:
            unusual.append(f"{e.rel} ({reason})")
    if unusual:
        findings.append(
            UNUSUAL_PHP.finding(
                Status.WARN, Basis.HEURISTIC, locations=unusual, evidence=[f"{len(unusual)} file(s) flagged"]
            )
        )
    else:
        findings.append(UNUSUAL_PHP.passed(basis=Basis.HEURISTIC))

    # FILES-003: code patterns in all PHP-like files
    hits: list[str] = []
    scanned = 0
    for e in files:
        if not e.is_php:
            continue
        data = read_entry(ctx.root, e, limit)
        if data is None:
            continue
        scanned += 1
        hits += [f"{e.rel}:{line} ({label})" for line, label in code_hits(data)]
    evidence = [f"{scanned} PHP-like file(s) scanned (first {limit // 1024} KiB of each)"]
    if hits:
        findings.append(
            SUSPICIOUS_CODE.finding(
                Status.WARN, Basis.HEURISTIC, locations=hits, evidence=[*evidence, f"{len(hits)} pattern match(es)"]
            )
        )
    else:
        findings.append(SUSPICIOUS_CODE.passed(evidence=evidence, basis=Basis.HEURISTIC))

    # FILES-005..008: leftovers
    backups, dumps, logs, dev = [], [], [], []
    for e in index.entries:
        name = e.name
        low = name.lower()
        in_plugins = in_dir(e, plugins_dir)
        if e.is_dir:
            if low in DEV_DIRS:
                dev.append(f"{e.rel}/ (version control directory)")
            continue
        if CONFIG_BACKUP_RE.match(name) and low != "wp-config.php" and not in_plugins:
            backups.append(e.rel)
        elif (DUMP_RE.search(low) and not in_plugins) or (
            ARCHIVE_RE.search(low) and e.rel.count("/") <= 2 and not in_plugins
        ):
            dumps.append(e.rel)
        elif low in LOG_NAMES:
            logs.append(e.rel)
        elif low in DEV_NAMES or (low.startswith("adminer") and low.endswith(".php")):
            dev.append(e.rel)
        elif low in PHPINFO_NAMES and b"phpinfo(" in (read_entry(ctx.root, e, limit) or b"").lower():
            dev.append(f"{e.rel} (calls phpinfo())")
    for rule, items in ((CONFIG_BACKUPS, backups), (EXPOSED_DATA, dumps), (LOG_FILES, logs), (DEV_ARTIFACTS, dev)):
        if items:
            findings.append(
                rule.finding(
                    Status.WARN,
                    Basis.OBSERVED,
                    locations=items,
                    evidence=[
                        f"{len(items)} file(s) found; whether they are downloadable "
                        "depends on the web-server configuration"
                    ],
                )
            )
        else:
            findings.append(rule.passed())
    return findings
