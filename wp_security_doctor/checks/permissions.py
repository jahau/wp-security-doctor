"""POSIX permission checks. Windows ACLs are not evaluated (reported as SKIPPED)."""

from __future__ import annotations

import os
import stat
import sys

from .. import refs
from ..context import ScanContext
from ..models import Basis, Finding, Rule, Severity, Status

CATEGORY = "permissions"

WORLD_WRITABLE = Rule(
    "WPSD-PERM-001",
    "World-writable files or directories",
    CATEGORY,
    Severity.HIGH,
    "Any local account (other hosting customers, compromised services) can modify world-writable "
    "files, which allows code injection into the site.",
    "Remove the 'other' write bit, e.g. find <path> -perm -o+w -exec chmod o-w {} +. Typical "
    "modes are 755 for directories and 644 for files.",
    (refs.FILE_PERMISSIONS, refs.HARDENING),
    pass_title="No world-writable files or directories",
)
CONFIG_PERMS = Rule(
    "WPSD-PERM-002",
    "wp-config.php permissions are too open",
    CATEGORY,
    Severity.MEDIUM,
    "wp-config.php holds database credentials and salts. Read access for 'other' lets every "
    "local account read them; group write lets the group change site configuration.",
    "Restrict the file, e.g. chmod 640 wp-config.php (or 600/440/400 depending on how PHP runs).",
    (refs.FILE_PERMISSIONS, refs.HARDENING),
    pass_title="wp-config.php permissions are restrictive",
)

SUPPORTED = os.name == "posix"


def _mode(m: int) -> str:
    return stat.filemode(m) + f" ({stat.S_IMODE(m):04o})"


def run(ctx: ScanContext) -> list[Finding]:
    if not SUPPORTED:
        reason = f"permission bits are not meaningful on {sys.platform}; Windows ACLs are not evaluated by this tool"
        return [WORLD_WRITABLE.skipped(reason), CONFIG_PERMS.skipped(reason)]

    findings: list[Finding] = []
    writable = [
        f"{e.rel}{'/' if e.is_dir else ''} {_mode(e.mode)}"
        for e in ctx.index.entries
        if not e.is_symlink and e.mode & stat.S_IWOTH
    ]
    if writable:
        findings.append(
            WORLD_WRITABLE.finding(
                Status.FAIL,
                Basis.OBSERVED,
                locations=writable,
                evidence=[f"{len(writable)} entr(y/ies) writable by 'other'"],
            )
        )
    else:
        findings.append(WORLD_WRITABLE.passed(evidence=[f"{len(ctx.index.entries)} entries checked"]))

    inst = ctx.installation
    if inst.config_path is None:
        findings.append(CONFIG_PERMS.skipped("wp-config.php not found"))
        return findings
    try:
        st = inst.config_path.stat()
    except OSError as exc:
        findings.append(
            CONFIG_PERMS.finding(
                Status.UNKNOWN, Basis.NONE, severity=Severity.INFO, evidence=[f"stat failed: {exc.strerror}"]
            )
        )
        return findings
    loc = inst.rel(inst.config_path)
    problems = []
    if st.st_mode & stat.S_IWOTH:
        problems.append("writable by other")
    if st.st_mode & stat.S_IROTH:
        problems.append("readable by other")
    if st.st_mode & stat.S_IWGRP:
        problems.append("writable by group")
    evidence = [f"mode {_mode(st.st_mode)}", *problems]
    if st.st_mode & stat.S_IWOTH:
        findings.append(
            CONFIG_PERMS.finding(
                Status.FAIL, Basis.OBSERVED, severity=Severity.HIGH, locations=[loc], evidence=evidence
            )
        )
    elif problems:
        sev = Severity.MEDIUM if st.st_mode & stat.S_IROTH else Severity.LOW
        findings.append(
            CONFIG_PERMS.finding(Status.WARN, Basis.OBSERVED, severity=sev, locations=[loc], evidence=evidence)
        )
    else:
        findings.append(CONFIG_PERMS.passed(evidence=evidence, locations=[loc]))
    return findings
