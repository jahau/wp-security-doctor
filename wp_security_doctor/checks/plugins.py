"""Plugin inventory (offline, header parsing) and optional WP-CLI plugin checksums."""

from __future__ import annotations

import re

from .. import refs
from ..context import ScanContext
from ..fs import read_entry
from ..integrations import wpcli
from ..models import Basis, Finding, Rule, Severity, Status
from .core import wp_cli_unavailable
from .files import DROPINS

CATEGORY = "plugins"

INVENTORY = Rule(
    "WPSD-PLUGIN-001",
    "Installed plugins",
    CATEGORY,
    Severity.INFO,
    "Plugins found in the plugins directory with the version declared in their header. Keep this "
    "list short and up to date; check versions against a vulnerability database.",
    "",
    (refs.HARDENING,),
    pass_title="Installed plugins",
)
AUTOLOADED = Rule(
    "WPSD-PLUGIN-002",
    "Must-use plugins and drop-ins (review)",
    CATEGORY,
    Severity.INFO,
    "Must-use plugins and drop-ins load automatically and are not listed on the regular Plugins "
    "screen, so they are a popular place to hide persistent malware. Many hosts and caching "
    "plugins install them legitimately.",
    "Confirm that every listed file was installed by you, your host or a plugin you trust.",
    (refs.HACKED_FAQ,),
    pass_title="No must-use plugins or drop-ins",
)
WPCLI_PLUGINS = Rule(
    "WPSD-PLUGIN-003",
    "Plugin files differ from WordPress.org checksums",
    CATEGORY,
    Severity.HIGH,
    "Result of `wp plugin verify-checksums --all`. Modified or added files in a plugin hosted on "
    "WordPress.org are a confirmed deviation from the published release.",
    "Reinstall affected plugins from a trusted source (wp plugin install <slug> --force "
    "--version=<version>) and investigate how the files were changed.",
    (refs.CLI_PLUGIN_CHECKSUMS,),
    pass_title="WP-CLI: plugins verify against checksums",
)
WPCLI_UNVERIFIABLE = Rule(
    "WPSD-PLUGIN-004",
    "Plugins that could not be verified",
    CATEGORY,
    Severity.INFO,
    "WordPress.org publishes checksums only for plugins it hosts. Premium, custom or delisted "
    "plugins cannot be verified this way.",
    "Compare these plugins against a fresh copy from their vendor.",
    (refs.CLI_PLUGIN_CHECKSUMS,),
    pass_title="Plugins that could not be verified",
)

_HEADER_RE = re.compile(rb"^[ \t/*#@]*Plugin Name\s*:\s*(.+)$", re.M | re.I)
_VERSION_RE = re.compile(rb"^[ \t/*#@]*Version\s*:\s*(\S+)", re.M | re.I)


def run(ctx: ScanContext) -> list[Finding]:
    inst = ctx.installation
    findings: list[Finding] = []
    if inst.content_dir is None:
        findings.append(INVENTORY.skipped("no wp-content directory inside the scan root"))
    else:
        findings += _inventory(ctx)
    if ctx.options.wp_cli:
        findings += _wpcli_plugins(ctx)
    return findings


def _inventory(ctx: ScanContext) -> list[Finding]:
    assert ctx.installation.content_dir is not None
    content = ctx.root_rel(ctx.installation.content_dir)
    plugins_prefix = f"{content}/plugins/"
    found: dict[str, str] = {}
    for e in ctx.index.files():
        if not e.is_php or not e.rel.startswith(plugins_prefix):
            continue
        rest = e.rel[len(plugins_prefix) :]
        depth = rest.count("/")
        if depth > 1:
            continue  # plugin headers live in top-level files only
        slug = rest.split("/", 1)[0] if depth else rest
        if slug in found:
            continue
        head = read_entry(ctx.root, e, 8192)
        if not head:
            continue
        if _HEADER_RE.search(head):
            vm = _VERSION_RE.search(head)
            found[slug] = vm.group(1).decode("utf-8", "replace") if vm else "unknown"
    plugins = [f"{slug} {ver}" for slug, ver in sorted(found.items())]
    out = [
        INVENTORY.passed(
            evidence=[f"{len(plugins)} plugin(s) found", "versions are as declared, not verified"],
            locations=plugins,
        )
    ]

    autoload = []
    mu_prefix = f"{content}/mu-plugins/"
    for e in ctx.index.files():
        if e.rel.startswith(mu_prefix) and e.is_php and e.rel[len(mu_prefix) :].count("/") == 0:
            autoload.append(f"{e.rel} (must-use plugin)")
        elif (
            e.rel.startswith(content + "/")
            and e.rel.count("/") == content.count("/") + 1
            and e.name in DROPINS
            and e.name != "index.php"
        ):
            autoload.append(f"{e.rel} (drop-in)")
    if autoload:
        out.append(
            AUTOLOADED.finding(
                Status.WARN, Basis.OBSERVED, locations=autoload, evidence=[f"{len(autoload)} auto-loaded file(s)"]
            )
        )
    else:
        out.append(AUTOLOADED.passed(evidence=["no must-use plugins or drop-ins"]))
    return out


def _wpcli_plugins(ctx: ScanContext) -> list[Finding]:
    wp, skipped = wp_cli_unavailable(WPCLI_PLUGINS, ctx)
    if skipped:
        return [skipped]
    assert wp is not None
    result = wpcli.run_wp(wp, wpcli.plugin_args(ctx.installation.core_dir), ctx.options.wp_cli_timeout)
    if not result.ok:
        return [
            WPCLI_PLUGINS.finding(
                Status.UNKNOWN, Basis.NONE, severity=Severity.INFO, evidence=[result.error or "WP-CLI failed"]
            )
        ]
    parsed = wpcli.parse_plugins(result)
    out: list[Finding] = []
    locations = []
    for label, group in (("modified", parsed.modified), ("added", parsed.added), ("missing", parsed.missing)):
        for plugin, files in sorted(group.items()):
            locations += [f"{plugin}: {f} ({label})" for f in files]
    if parsed.modified or parsed.added:
        out.append(
            WPCLI_PLUGINS.finding(
                Status.FAIL,
                Basis.VERIFIED,
                locations=locations,
                evidence=[parsed.summary or "checksum mismatches reported"],
            )
        )
    elif parsed.missing:
        out.append(
            WPCLI_PLUGINS.finding(
                Status.WARN,
                Basis.VERIFIED,
                severity=Severity.LOW,
                locations=locations,
                evidence=[parsed.summary or "missing files"],
            )
        )
    elif parsed.errors:
        out.append(
            WPCLI_PLUGINS.finding(Status.UNKNOWN, Basis.NONE, severity=Severity.INFO, evidence=parsed.errors[:5])
        )
    else:
        out.append(WPCLI_PLUGINS.passed(evidence=[parsed.summary or "no mismatches reported"], basis=Basis.VERIFIED))
    if parsed.unverifiable:
        out.append(
            WPCLI_UNVERIFIABLE.finding(
                Status.SKIPPED,
                Basis.NONE,
                locations=parsed.unverifiable,
                evidence=[f"{len(parsed.unverifiable)} plugin(s) not on WordPress.org"],
            )
        )
    return out
