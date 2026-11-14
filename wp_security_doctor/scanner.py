"""Run the selected checks and assemble a redacted, deterministic report."""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .checks import REGISTRY
from .context import ScanContext, ScanOptions
from .detect import Installation, detect
from .models import Basis, Finding, Rule, Severity, Status

COVERAGE = Rule(
    "WPSD-SCAN-001",
    "Scan coverage",
    "scan",
    Severity.INFO,
    "How much of the installation the scanner could inspect. Limits, unreadable paths and "
    "symlinks that point outside the scan root reduce coverage.",
    "Re-run with higher --max-files / --max-depth, or as a user who can read all files.",
    pass_title="Scan coverage complete",
)
CHECK_ERROR = Rule(
    "WPSD-SCAN-002",
    "A check failed to run",
    "scan",
    Severity.INFO,
    "An unexpected error stopped this check category. Other categories were not affected.",
    "Please report this with the error message (no site data needed).",
    pass_title="All checks ran",
)

DISCLAIMER = (
    "This is a read-only configuration and file-system audit. Passing every check does not mean "
    "the site is secure: it does not test the running site, the database, user accounts, server "
    "configuration or known plugin vulnerabilities, and its heuristics can miss malware or flag "
    "legitimate code."
)


@dataclass
class ScanReport:
    installation: Installation
    options: ScanOptions
    findings: list[Finding]
    network_used: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Status}
        for f in self.findings:
            out[f.status.value] += 1
        return out

    def worst(self) -> Severity | None:
        sev = [f.severity for f in self.findings if f.status in (Status.FAIL, Status.WARN)]
        return max(sev, key=lambda s: s.rank) if sev else None

    def to_dict(self) -> dict[str, Any]:
        inst = self.installation
        return {
            "schema_version": 1,
            "tool": {"name": "wp-security-doctor", "version": __version__},
            "target": {
                "scan_root": str(inst.scan_root),
                "core_dir": inst.core_rel,
                "layout": inst.layout,
                "wordpress_version": inst.version,
                "locale": inst.local_package,
                "config_file": inst.rel(inst.config_path) if inst.config_path else None,
                "content_dir": inst.rel(inst.content_dir) if inst.content_dir else None,
            },
            "scan": {
                "checks": list(self.options.checks),
                "offline": not self.network_used,
                "network_integrations": self.network_used,
                "read_only": True,
                "platform": platform.system(),
            },
            "summary": {"counts": self.counts(), "highest_open_severity": (w.value if (w := self.worst()) else None)},
            "disclaimer": DISCLAIMER,
            "findings": [f.to_dict() for f in self.findings],
        }


def scan(target: Path, options: ScanOptions) -> ScanReport:
    installation = detect(target)
    ctx = ScanContext(installation=installation, options=options)
    _ = ctx.config  # parse early so secrets are known for redaction even if "config" is not selected
    findings: list[Finding] = []
    for name in options.checks:
        try:
            findings += REGISTRY[name](ctx)
        except Exception as exc:  # noqa: BLE001 - isolate check failures
            findings.append(
                CHECK_ERROR.finding(
                    Status.UNKNOWN,
                    Basis.NONE,
                    title=f"Check '{name}' failed to run",
                    evidence=[f"{type(exc).__name__}: {exc}"],
                )
            )
    if "index" in ctx.__dict__:  # only report coverage if the file index was built
        findings.append(_coverage(ctx))
    findings.sort(key=Finding.sort_key)
    network = []
    if options.fetch_checksums and not options.offline and "core" in options.checks:
        network.append("api.wordpress.org core checksums")
    if options.wp_cli and not options.offline:
        network.append("WP-CLI checksum downloads")
    return ScanReport(installation, options, [redact(f, ctx.secrets) for f in findings], network)


def _coverage(ctx: ScanContext) -> Finding:
    idx = ctx.index
    evidence = [f"{len(idx.entries)} entries indexed under {ctx.root}"]
    locations: list[str] = []
    status = Status.PASS
    if idx.truncated:
        status = Status.UNKNOWN
        evidence.append(f"stopped after --max-files={ctx.options.max_files}; later files were not inspected")
    if idx.depth_limited:
        status = Status.UNKNOWN
        evidence.append(f"{len(idx.depth_limited)} director(y/ies) deeper than --max-depth not traversed")
        locations += [f"{p}/ (depth limit)" for p in idx.depth_limited]
    if idx.errors:
        status = Status.UNKNOWN
        evidence.append(f"{len(idx.errors)} path(s) could not be read")
        locations += [f"{p} (unreadable)" for p in idx.errors]
    if idx.external_symlinks:
        evidence.append(f"{len(idx.external_symlinks)} symlink(s) point outside the scan root and were not followed")
        locations += [f"{p} (external symlink)" for p in idx.external_symlinks]
    if idx.pruned:
        evidence.append("not descended into: " + ", ".join(idx.pruned[:10]))
    evidence += ctx.warnings
    if status is Status.PASS:
        return COVERAGE.passed(evidence=evidence, locations=locations)
    return COVERAGE.finding(status, Basis.OBSERVED, severity=Severity.INFO, evidence=evidence, locations=locations)


_REDACTED = "[REDACTED]"


def redact(finding: Finding, secrets: set[str]) -> Finding:
    """Last line of defence: scrub any known secret value from every text field."""
    if not secrets:
        return finding
    pattern = re.compile("|".join(re.escape(s) for s in sorted(secrets, key=len, reverse=True)))

    def scrub(text: str) -> str:
        return pattern.sub(_REDACTED, text)

    finding.title = scrub(finding.title)
    finding.explanation = scrub(finding.explanation)
    finding.remediation = scrub(finding.remediation)
    finding.locations = [scrub(x) for x in finding.locations]
    finding.evidence = [scrub(x) for x in finding.evidence]
    return finding
