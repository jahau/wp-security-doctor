"""WordPress core detection and integrity verification."""

from __future__ import annotations

from .. import refs
from ..context import ScanContext
from ..fs import is_within
from ..integrations import checksums, wpcli
from ..models import Basis, Finding, Rule, Severity, Status

CATEGORY = "core"

DETECTED = Rule(
    "WPSD-CORE-001",
    "WordPress installation detected",
    CATEGORY,
    Severity.INFO,
    "Core version and layout as declared in wp-includes/version.php. The declared version can be "
    "edited by an attacker; only checksum verification confirms it.",
    "",
    (refs.OWN_DIRECTORY,),
    pass_title="WordPress installation detected",
)
CHECKSUM_MISMATCH = Rule(
    "WPSD-CORE-002",
    "Core files differ from official checksums",
    CATEGORY,
    Severity.HIGH,
    "These core files do not match the official WordPress.org checksums for the declared version "
    "and locale. Core files should never be edited; a mismatch is a confirmed modification "
    "(malicious or not).",
    "Compare the files with a clean copy of the same version, then reinstall core "
    "(Dashboard > Updates > Re-install, or wp core download --force --skip-content). If the "
    "changes are malicious, treat the site as compromised.",
    (refs.CLI_CORE_CHECKSUMS, refs.HACKED_FAQ),
    pass_title="Core files match official checksums",
)
UNEXPECTED_CORE = Rule(
    "WPSD-CORE-003",
    "Unexpected files inside core directories",
    CATEGORY,
    Severity.MEDIUM,
    "These files are inside wp-admin/, wp-includes/ or the core root but are not part of the "
    "official release. They can be leftovers from old versions, host tooling or injected code.",
    "Identify where each file comes from; remove it if nothing legitimate needs it.",
    (refs.CLI_CORE_CHECKSUMS, refs.HACKED_FAQ),
    pass_title="No unexpected files in core directories",
)
MISSING_CORE = Rule(
    "WPSD-CORE-004",
    "Core files are missing",
    CATEGORY,
    Severity.LOW,
    "Files listed in the official checksums are missing. This is often deliberate (e.g. "
    "readme.html removed) but can also indicate a broken update.",
    "Re-install core for the current version if functionality is affected.",
    (refs.CLI_CORE_CHECKSUMS,),
    pass_title="No core files missing",
)
WPCLI_CORE = Rule(
    "WPSD-CORE-005",
    "WP-CLI core checksum verification",
    CATEGORY,
    Severity.HIGH,
    "Result of `wp core verify-checksums` (downloads official checksums; runs before WordPress is loaded).",
    "Reinstall modified core files with wp core download --force --skip-content and review any reported extra files.",
    (refs.CLI_CORE_CHECKSUMS,),
    pass_title="WP-CLI: core verifies against checksums",
)

# Root-level files that are expected but not part of the official checksum list.
ROOT_EXPECTED = frozenset({"wp-config.php", "index.php"})


def run(ctx: ScanContext) -> list[Finding]:
    inst = ctx.installation
    opts = ctx.options
    evidence = [
        f"declared version: {inst.version or 'unknown'}",
        f"locale package: {inst.local_package or 'en_US (default)'}",
        f"layout: {inst.layout}",
        f"core directory: {inst.core_rel}",
    ]
    evidence += inst.notes
    status = Status.PASS if inst.version else Status.UNKNOWN
    findings = [DETECTED.finding(status, Basis.OBSERVED, severity=Severity.INFO, evidence=evidence, remediation="")]
    findings += _python_checksums(ctx)
    if opts.wp_cli:
        findings.append(_wpcli_core(ctx))
    return findings


def _python_checksums(ctx: ScanContext) -> list[Finding]:
    inst, opts = ctx.installation, ctx.options
    rules = (CHECKSUM_MISMATCH, UNEXPECTED_CORE, MISSING_CORE)
    hint = (
        "Pass --core-checksums FILE (offline; JSON from "
        f"{refs.CHECKSUM_API}?version=X&locale=Y), --fetch-checksums (network) or --wp-cli (network)."
    )
    if not inst.version:
        return [r.skipped("core version unknown; cannot select a checksum list", hint) for r in rules]
    locale = inst.local_package or "en_US"
    try:
        if opts.core_checksums_file is not None:
            sums = checksums.load_file(opts.core_checksums_file, inst.version)
            source = f"local file {opts.core_checksums_file.name}"
        elif opts.fetch_checksums and not opts.offline:
            sums = checksums.fetch(inst.version, locale, opts.network_timeout)
            source = f"api.wordpress.org (version {inst.version}, locale {locale})"
        else:
            return [r.skipped("no checksum source (offline mode)", hint) for r in rules]
    except checksums.ChecksumError as exc:
        return [
            r.finding(Status.UNKNOWN, Basis.NONE, severity=Severity.INFO, evidence=[str(exc)], remediation=hint)
            for r in rules
        ]

    core = inst.core_dir
    by_rel = {e.rel: e for e in ctx.index.files()}
    modified, missing, unreadable = [], [], []
    for rel, digest in sorted(sums.items()):
        if rel.startswith("wp-content/"):
            continue  # bundled themes/plugins are often updated separately
        path = core / rel
        rep = ctx.root_rel(path)
        entry = by_rel.get(rep)
        if entry is None and ctx.index.truncated:
            # Not indexed because of --max-files: fall back to a validated lookup.
            if not path.is_file():
                missing.append(rep)
                continue
            if not is_within(path.resolve(), ctx.root):
                unreadable.append(f"{rep} (resolves outside the scan root, not read)")
                continue
        elif entry is None:
            missing.append(rep)
            continue
        elif entry.is_symlink:
            unreadable.append(f"{rep} (symlink, not followed)")
            continue
        actual = checksums.md5_file(path)
        if actual is None:
            unreadable.append(rep)
        elif actual != digest:
            modified.append(rep)

    known = set(sums)
    unexpected = []
    for e in ctx.index.files():
        rel_core = ctx.rel_to_core(e.rel)
        if rel_core is None or rel_core in known:
            continue
        top = rel_core.split("/", 1)[0]
        in_core_dir = top in ("wp-admin", "wp-includes") and "/" in rel_core
        root_php = "/" not in rel_core and e.is_php and rel_core not in ROOT_EXPECTED
        if in_core_dir or root_php:
            unexpected.append(e.rel)

    source_ev = f"checksum source: {source}; {len(sums)} entries"
    out: list[Finding] = []
    if modified or unreadable:
        ev = [source_ev, f"{len(modified)} modified file(s)"]
        if unreadable:
            ev.append(f"{len(unreadable)} file(s) could not be hashed: " + ", ".join(unreadable[:10]))
        status = Status.FAIL if modified else Status.UNKNOWN
        out.append(
            CHECKSUM_MISMATCH.finding(
                status, Basis.VERIFIED, locations=modified, evidence=ev, severity=None if modified else Severity.INFO
            )
        )
    else:
        out.append(CHECKSUM_MISMATCH.passed(evidence=[source_ev, "all core files match"], basis=Basis.VERIFIED))
    if unexpected:
        out.append(
            UNEXPECTED_CORE.finding(
                Status.WARN,
                Basis.VERIFIED,
                locations=unexpected,
                evidence=[source_ev, f"{len(unexpected)} file(s) not in the official list"],
            )
        )
    else:
        out.append(UNEXPECTED_CORE.passed(evidence=[source_ev], basis=Basis.VERIFIED))
    if missing:
        out.append(
            MISSING_CORE.finding(
                Status.WARN, Basis.VERIFIED, locations=missing, evidence=[source_ev, f"{len(missing)} file(s) missing"]
            )
        )
    else:
        out.append(MISSING_CORE.passed(evidence=[source_ev], basis=Basis.VERIFIED))
    return out


def wp_cli_unavailable(rule: Rule, ctx: ScanContext) -> tuple[str | None, Finding | None]:
    wp = wpcli.find_wp(ctx.options.wp_cli_path)
    if wp is None:
        return None, rule.skipped(
            "WP-CLI not found on PATH"
            + (f" (looked for {ctx.options.wp_cli_path})" if ctx.options.wp_cli_path else ""),
            "Install WP-CLI (https://wp-cli.org/) or pass --wp-cli-path.",
        )
    return wp, None


def _wpcli_core(ctx: ScanContext) -> Finding:
    wp, skipped = wp_cli_unavailable(WPCLI_CORE, ctx)
    if skipped:
        return skipped
    assert wp is not None
    result = wpcli.run_wp(wp, wpcli.core_args(ctx.installation.core_dir), ctx.options.wp_cli_timeout)
    if not result.ok:
        return WPCLI_CORE.finding(
            Status.UNKNOWN, Basis.NONE, severity=Severity.INFO, evidence=[result.error or "WP-CLI failed"]
        )
    parsed = wpcli.parse_core(result)
    core_prefix = ctx.installation.core_rel

    def rep(p: str) -> str:
        return p if core_prefix in ("", ".") else f"{core_prefix}/{p}"

    if parsed.modified:
        ev = [
            f"{len(parsed.modified)} modified",
            f"{len(parsed.unexpected)} unexpected",
            f"{len(parsed.missing)} missing",
        ]
        return WPCLI_CORE.finding(
            Status.FAIL, Basis.VERIFIED, locations=[rep(p) for p in parsed.modified + parsed.unexpected], evidence=ev
        )
    if parsed.unexpected or parsed.missing:
        return WPCLI_CORE.finding(
            Status.WARN,
            Basis.VERIFIED,
            severity=Severity.MEDIUM,
            locations=[rep(p) for p in parsed.unexpected + parsed.missing],
            evidence=[f"{len(parsed.unexpected)} unexpected", f"{len(parsed.missing)} missing"],
        )
    if parsed.success:
        return WPCLI_CORE.passed(evidence=["WordPress installation verifies against checksums"], basis=Basis.VERIFIED)
    return WPCLI_CORE.finding(Status.UNKNOWN, Basis.NONE, severity=Severity.INFO, evidence=parsed.errors[:5])
