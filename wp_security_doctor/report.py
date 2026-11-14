"""Terminal and JSON renderers."""

from __future__ import annotations

import json
import os
import textwrap
from collections.abc import Callable

from . import __version__
from .models import Finding, Status
from .scanner import DISCLAIMER, ScanReport

_COLORS = {
    Status.FAIL: "\033[1;31m",
    Status.WARN: "\033[33m",
    Status.UNKNOWN: "\033[35m",
    Status.SKIPPED: "\033[2m",
    Status.PASS: "\033[32m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
WIDTH = 100


def use_color(stream: object, mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_text(report: ScanReport, color: bool = False, verbose: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    inst = report.installation
    lines = [
        c(_BOLD, f"WP Security Doctor {__version__}") + " - read-only WordPress audit",
        f"Target   {inst.scan_root}",
        f"Core     {inst.core_rel} (WordPress {inst.version or 'unknown'}, layout: {inst.layout})",
        "Config   "
        + (inst.rel(inst.config_path) if inst.config_path else "not found")
        + (" (parent directory)" if inst.config_outside_root else ""),
        "Content  " + (inst.rel(inst.content_dir) if inst.content_dir else "not found"),
        "Mode     "
        + ("offline" if not report.network_used else "network: " + ", ".join(report.network_used))
        + " | checks: "
        + ",".join(report.options.checks),
        "",
    ]
    open_items = [f for f in report.findings if f.status is not Status.PASS]
    passed = [f for f in report.findings if f.status is Status.PASS]
    for f in open_items:
        lines += _finding_block(f, c, verbose)
    if passed:
        lines.append(c(_BOLD, "Passed checks"))
        for f in passed:
            lines.append(f"  {c(_COLORS[Status.PASS], 'PASS')}  {f.rule_id:<17} {f.title}")
            if verbose:
                lines += [f"{'':25}{e}" for e in f.evidence]
        lines.append("")
    counts = report.counts()
    summary = "  ".join(f"{c(_COLORS[s], s.value)} {counts[s.value]}" for s in Status if s in _COLORS)
    lines.append(c(_BOLD, "Summary  ") + summary)
    lines.append("")
    lines += textwrap.wrap("Note: " + DISCLAIMER, WIDTH)
    lines.append("No files were modified.")
    return "\n".join(lines) + "\n"


Colorize = Callable[[str, str], str]


def _finding_block(f: Finding, color: Colorize, verbose: bool) -> list[str]:
    label = f"[{f.status.value}]".ljust(9)
    head = f"{color(_COLORS[f.status], label)} {f.severity.value:<8} {f.rule_id}  {color(_BOLD, f.title)}"
    out = [head]
    ind = " " * 4

    def wrap(label: str, text: str) -> None:
        if not text:
            return
        wrapped = textwrap.wrap(text, WIDTH - len(ind) - 12) or [""]
        out.append(f"{ind}{label:<11} {wrapped[0]}")
        out.extend(f"{ind}{'':<11} {w}" for w in wrapped[1:])

    shown = f.locations if verbose else f.locations[:10]
    for i, loc in enumerate(shown):
        out.append(f"{ind}{'Location' if i == 0 else '':<11} {loc}")
    if len(f.locations) > len(shown):
        out.append(
            f"{ind}{'':<11} {color(_DIM, f'... {len(f.locations) - len(shown)} more (use --verbose or --format json)')}"
        )
    for i, ev in enumerate(f.evidence):
        out.append(f"{ind}{'Evidence' if i == 0 else '':<11} {ev}")
    out.append(f"{ind}{'Basis':<11} {f.basis.value}")
    wrap("Why", f.explanation)
    wrap("Fix", f.remediation)
    for i, ref in enumerate(f.references):
        out.append(f"{ind}{'Docs' if i == 0 else '':<11} {ref}")
    out.append("")
    return out
