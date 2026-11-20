"""SARIF 2.1.0 exporter (for GitHub code scanning and other SARIF consumers).

Mapping
-------
* Every rule (``wp-security-doctor rules``) becomes a ``reportingDescriptor`` with its
  stable ``WPSD-*`` ID, so rule IDs stay identical across runs and versions.
* Every open finding (FAIL or WARN) becomes one SARIF ``result`` per location. GitHub
  only uses the first location of a result, so one result per file keeps each file
  visible as its own alert.
* UNKNOWN and SKIPPED findings are not alerts: they become
  ``toolExecutionNotifications`` on the invocation. PASS findings are only counted.
* Severity maps to ``level`` (CRITICAL/HIGH -> error, MEDIUM -> warning,
  LOW/INFO -> note) and to GitHub's ``security-severity`` rule property.

Privacy
-------
Findings are already secret-redacted by the scanner. On top of that, the SARIF log
never contains the absolute scan root, its parent, the command line, timestamps, or any
other absolute path: artifact URIs are relative to the scan root (or to
``path_prefix``), and absolute paths inside evidence text are reduced to their last
component. Output is deterministic for the same input.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from . import __version__
from .models import Finding, Rule, Severity, Status
from .scanner import DISCLAIMER, ScanReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/jahau/wp-security-doctor"
SRCROOT = "%SRCROOT%"
FINGERPRINT_KEY = "wpsdLocationHash/v1"

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub: >9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low; INFO gets none.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
OPEN = (Status.FAIL, Status.WARN)
DESCRIPTION_LIMIT = 1024  # GitHub truncates rule descriptions at 1024 characters

# Rules whose "locations" are not file paths.
NON_PATH_RULES = frozenset({"WPSD-PLUGIN-001", "WPSD-PLUGIN-004"})
PLUGIN_FILE_RULE = "WPSD-PLUGIN-003"

_TRAILER_RE = re.compile(r"^\.\.\. and \d+ more$")
_MODE_SUFFIX_RE = re.compile(r" (?P<detail>[-bcdlps?][-rwxsStT]{9} \(\d{4}\))$")
_PAREN_SUFFIX_RE = re.compile(r" \((?P<detail>[^()]*)\)$")
_LINE_SUFFIX_RE = re.compile(r":(?P<line>[1-9]\d*)$")
_EVIDENCE_LINE_RE = re.compile(r"\(line (?P<line>[1-9]\d*)\)")
_PLUGIN_FILE_RE = re.compile(r"^(?P<plugin>[^:/\\\s]+): (?P<file>.+)$")
# Absolute paths that may appear in free-text evidence (e.g. a WP_DEBUG_LOG value).
_ABS_POSIX_RE = re.compile(r"(?<![\w.:/~\\-])/(?:[^\s/:'\"`]+/)+(?P<last>[^\s/:'\"`,;)]*)")
_ABS_WINDOWS_RE = re.compile(
    r"(?<![\w])(?:[A-Za-z]:|\\\\[^\s\\]+)[\\/](?:[^\s\\/:'\"`]+[\\/])*(?P<last>[^\s\\/:'\"`,;)]*)"
)


class SarifPathError(ValueError):
    """An invalid --sarif-path-prefix value."""


def normalise_prefix(prefix: str | None) -> str:
    """Validate a repository-relative POSIX directory prefix ("" means none)."""
    if not prefix:
        return ""
    text = prefix.replace("\\", "/").strip("/")
    if text in ("", "."):
        return ""
    if re.match(r"^[A-Za-z]:", text) or prefix.startswith(("/", "\\")):
        raise SarifPathError("--sarif-path-prefix must be a relative path inside the repository")
    norm = posixpath.normpath(text)
    if norm == ".." or norm.startswith("../"):
        raise SarifPathError("--sarif-path-prefix must not leave the repository ('..')")
    return "" if norm == "." else norm


class _Scrubber:
    """Removes absolute paths from free text so the log never reveals server layout."""

    def __init__(self, scan_root: Path) -> None:
        pairs: list[tuple[str, str]] = []
        for path, label in ((scan_root, "<scan-root>"), (scan_root.parent, "<scan-root-parent>")):
            for form in {str(path), path.as_posix()}:
                if len(form) > 1:  # never replace a bare "/" or drive root
                    pairs.append((form, label))
        self._known = sorted(pairs, key=lambda p: len(p[0]), reverse=True)

    def __call__(self, text: str) -> str:
        for form, label in self._known:
            text = text.replace(form, label)
        text = _ABS_WINDOWS_RE.sub(lambda m: "<abs-path>/" + m.group("last"), text)
        return _ABS_POSIX_RE.sub(lambda m: "<abs-path>/" + m.group("last"), text)


def _safe_relative(path: str) -> str | None:
    """Return a clean relative POSIX path, or None if it is absolute or escapes upwards."""
    if not path or "\\" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return None
    norm = posixpath.normpath(path)
    if norm in (".", "..") or norm.startswith("../"):
        return None
    return norm


class _Locator:
    """Turns the report's human-readable location strings into SARIF artifact locations."""

    def __init__(self, report: ScanReport, prefix: str) -> None:
        inst = report.installation
        self.prefix = prefix
        self.content = (
            inst.rel(inst.content_dir) if inst.content_dir and not _is_abs(inst.rel(inst.content_dir)) else None
        )
        self.core = inst.core_rel if not _is_abs(inst.core_rel) else "."
        # wp-config.php in the parent directory is reported with an absolute path.
        self.config_abs: str | None = None
        self.config_rel: str | None = None
        if inst.config_path is not None:
            rel = inst.rel(inst.config_path)
            if _is_abs(rel):
                self.config_abs = rel
                self.config_rel = Path(os.path.relpath(inst.config_path, inst.scan_root)).as_posix()
            else:
                self.config_rel = rel

    def uri(self, rel: str) -> str | None:
        """Join a scan-root-relative path with the prefix; None if the result is unsafe."""
        joined = posixpath.normpath(posixpath.join(self.prefix, rel)) if self.prefix else posixpath.normpath(rel)
        return _safe_relative(joined)

    def parse(self, rule_id: str, loc: str) -> tuple[str | None, int | None, str | None]:
        """Return (uri, line, detail) for one location string; uri None = not a file."""
        if rule_id in NON_PATH_RULES or _TRAILER_RE.match(loc):
            return None, None, None
        if self.config_abs is not None and loc == self.config_abs and self.config_rel:
            return self.uri(self.config_rel), None, "parent directory of the scan root"
        detail = None
        path = loc
        if rule_id == PLUGIN_FILE_RULE:
            m = _PLUGIN_FILE_RE.match(loc)
            if not m or self.content is None:
                return None, None, None
            path = f"{self.content}/plugins/{m['plugin']}/{m['file']}"
        if m2 := _MODE_SUFFIX_RE.search(path):
            detail, path = m2["detail"], path[: m2.start()]
        elif m3 := _PAREN_SUFFIX_RE.search(path):
            detail, path = m3["detail"], path[: m3.start()]
        line = None
        if m4 := _LINE_SUFFIX_RE.search(path):
            line, path = int(m4["line"]), path[: m4.start()]
        path = path.rstrip("/")
        if _safe_relative(path) is None:
            return None, None, detail
        return self.uri(path), line, detail

    def fallback(self, finding: Finding) -> str | None:
        """Anchor for findings without a file location (GitHub needs one per result)."""
        candidates = []
        if finding.category == "config" and self.config_rel:
            candidates.append(self.config_rel)
        candidates.append(posixpath.join(self.core, "wp-includes/version.php"))
        for c in candidates:
            if (u := self.uri(c)) is not None:
                return u
        return None


def _is_abs(path: str) -> bool:
    return path.startswith("/") or bool(re.match(r"^[A-Za-z]:", path))


def _rule_descriptor(rule: Rule) -> dict[str, Any]:
    refs = "\n".join(f"- <{r}>" for r in rule.references)
    markdown = f"{rule.explanation}\n\n**Remediation:** {rule.remediation}"
    if refs:
        markdown += f"\n\n**References:**\n{refs}"
    props: dict[str, Any] = {
        "tags": ["security", "wordpress", rule.category],
        "category": rule.category,
        "severity": rule.severity.value,
    }
    if rule.severity in SECURITY_SEVERITY:
        props["security-severity"] = SECURITY_SEVERITY[rule.severity]
    out: dict[str, Any] = {
        "id": rule.rule_id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": _limit(rule.explanation)},
        "defaultConfiguration": {"level": LEVELS[rule.severity]},
        "help": {"text": rule.remediation or rule.explanation, "markdown": markdown},
        "properties": props,
    }
    if rule.references:
        out["helpUri"] = rule.references[0]
    return out


def _limit(text: str, limit: int = DESCRIPTION_LIMIT) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _fingerprint(rule_id: str, uri: str | None, line: int | None, detail: str | None) -> str:
    raw = "\0".join((rule_id, uri or "", str(line or ""), detail or ""))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def build_sarif(report: ScanReport, rules: list[Rule], path_prefix: str | None = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (as a dict) from a finished scan report."""
    prefix = normalise_prefix(path_prefix)
    scrub = _Scrubber(report.installation.scan_root)
    locator = _Locator(report, prefix)
    rule_ids = [r.rule_id for r in rules]
    index = {rid: i for i, rid in enumerate(rule_ids)}
    descriptors = [_rule_descriptor(r) for r in rules]
    for f in report.findings:  # a finding whose rule is not registered still gets a descriptor
        if f.rule_id not in index:
            index[f.rule_id] = len(descriptors)
            descriptors.append(
                {"id": f.rule_id, "shortDescription": {"text": f.title}, "fullDescription": {"text": f.explanation}}
            )

    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    for f in report.findings:
        if f.status in OPEN:
            results += _results(f, index[f.rule_id], locator, scrub)
        elif f.status in (Status.UNKNOWN, Status.SKIPPED):
            notifications.append(_notification(f, index[f.rule_id], scrub))

    check_failed = any(f.rule_id == "WPSD-SCAN-002" and f.status is not Status.PASS for f in report.findings)
    inst = report.installation
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wp-security-doctor",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": descriptors,
                    }
                },
                "originalUriBaseIds": {
                    SRCROOT: {
                        "description": {
                            "text": "Repository root. Artifact URIs are relative to the scanned WordPress directory"
                            + (f" joined with the prefix '{prefix}'." if prefix else ".")
                        }
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not check_failed,
                        "toolExecutionNotifications": notifications,
                        "properties": {
                            "readOnly": True,
                            "offline": not report.network_used,
                            "networkIntegrations": list(report.network_used),
                            "checks": list(report.options.checks),
                        },
                    }
                ],
                "results": results,
                "columnKind": "unicodeCodePoints",
                "properties": {
                    "wordpressVersion": inst.version,
                    "layout": inst.layout,
                    "summary": report.counts(),
                    "highestOpenSeverity": (w.value if (w := report.worst()) else None),
                    "disclaimer": DISCLAIMER,
                },
            }
        ],
    }


def _results(f: Finding, rule_index: int, locator: _Locator, scrub: _Scrubber) -> list[dict[str, Any]]:
    evidence = [scrub(e) for e in f.evidence]
    trailer = next((loc for loc in f.locations if _TRAILER_RE.match(loc)), None)
    parsed = [(loc, *locator.parse(f.rule_id, loc)) for loc in f.locations if not _TRAILER_RE.match(loc)]
    file_locs = [(loc, uri, line, detail) for loc, uri, line, detail in parsed if uri is not None]
    other_locs = [scrub(loc) for loc, uri, _line, _detail in parsed if uri is None]
    extra = [*(["other locations: " + "; ".join(other_locs)] if other_locs else [])]
    if trailer:
        extra.append(f"more locations were not listed ({trailer.removeprefix('... ')}); see the JSON report")

    props = {
        "severity": f.severity.value,
        "status": f.status.value,
        "basis": f.basis.value,
        "category": f.category,
    }
    tail = f" Severity {f.severity.value}, status {f.status.value}, basis {f.basis.value}."
    if evidence or extra:
        tail += " Evidence: " + "; ".join([*evidence, *extra]) + "."

    out: list[dict[str, Any]] = []
    if not file_locs:
        anchor = locator.fallback(f)
        text = scrub(f.title) + "." + tail
        result = _result(f, rule_index, text, anchor, None, None, {**props, "locationKind": "fallback"})
        out.append(result)
        return out
    config_uri = locator.uri(locator.config_rel) if locator.config_rel else None
    for _loc, uri, line, detail in file_locs:
        if line is None and uri == config_uri:  # config evidence carries "(line N)" of the definition
            m = next((m for e in f.evidence if (m := _EVIDENCE_LINE_RE.search(e))), None)
            line = int(m["line"]) if m else None
        where = f"{uri}" + (f":{line}" if line else "") + (f" ({scrub(detail)})" if detail else "")
        text = f"{scrub(f.title)}: {where}.{tail}"
        out.append(_result(f, rule_index, text, uri, line, detail, props))
    return out


def _result(
    f: Finding,
    rule_index: int,
    text: str,
    uri: str | None,
    line: int | None,
    detail: str | None,
    props: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "kind": "fail",
        "level": LEVELS[f.severity],
        "message": {"text": text},
    }
    if uri is not None:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(uri, safe="/"), "uriBaseId": SRCROOT},
                    # GitHub requires a region; 1 marks a file-level finding.
                    "region": {"startLine": line or 1},
                }
            }
        ]
    result["partialFingerprints"] = {FINGERPRINT_KEY: _fingerprint(f.rule_id, uri, line, detail)}
    result["properties"] = props
    return result


def _notification(f: Finding, rule_index: int, scrub: _Scrubber) -> dict[str, Any]:
    if f.rule_id == "WPSD-SCAN-002":
        level = "error"
    elif f.status is Status.UNKNOWN:
        level = "warning"
    else:
        level = "note"
    parts = [scrub(e) for e in f.evidence]
    text = f"{f.status.value}: {scrub(f.title)}" + (f" ({'; '.join(parts)})" if parts else "") + "."
    return {
        "level": level,
        "message": {"text": text},
        "associatedRule": {"id": f.rule_id, "index": rule_index},
        "properties": {"status": f.status.value, "category": f.category},
    }


def render_sarif(report: ScanReport, rules: list[Rule], path_prefix: str | None = None) -> str:
    return json.dumps(build_sarif(report, rules, path_prefix), indent=2, ensure_ascii=False) + "\n"
