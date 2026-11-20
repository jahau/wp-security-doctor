"""Command-line interface.

Exit codes:
  0  scan completed, no open finding at or above --fail-on
  1  scan completed, at least one FAIL/WARN finding at or above --fail-on
  2  usage error, target is not WordPress, or the scan could not run
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .context import ALL_CHECKS, ScanOptions
from .detect import DetectionError
from .fs import is_within
from .models import Finding, Rule, Severity, Status

COMMANDS = ("scan", "rules")
FAIL_ON = ("info", "low", "medium", "high", "critical", "never")


def _checks(value: str) -> tuple[str, ...]:
    items = tuple(dict.fromkeys(v.strip().lower() for v in value.split(",") if v.strip()))
    unknown = [i for i in items if i not in ALL_CHECKS]
    if unknown or not items:
        raise argparse.ArgumentTypeError(
            f"unknown check(s): {', '.join(unknown) or '(none)'}; choose from {', '.join(ALL_CHECKS)}"
        )
    return items


def _positive(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp-security-doctor",
        description="Read-only, offline-by-default WordPress security audit.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="audit a WordPress installation (read-only)")
    s.add_argument("path", type=Path, help="WordPress directory (or a directory containing it)")
    s.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument(
        "--sarif-path-prefix",
        metavar="DIR",
        help="with --format sarif: repository-relative directory of the scanned path, prepended to "
        "artifact URIs (e.g. 'web' when scanning ./web in a GitHub checkout)",
    )
    s.add_argument("--output", "-o", type=Path, help="write the report to a file (must be outside the scan root)")
    s.add_argument(
        "--checks",
        type=_checks,
        default=ALL_CHECKS,
        help=f"comma-separated categories (default: all): {','.join(ALL_CHECKS)}",
    )
    s.add_argument(
        "--fail-on",
        choices=FAIL_ON,
        default="high",
        help="exit 1 if a FAIL/WARN finding has at least this severity (default: high)",
    )
    s.add_argument("--verbose", "-v", action="store_true", help="list every location and PASS evidence")
    s.add_argument("--color", choices=("auto", "always", "never"), default="auto")

    net = s.add_argument_group("integrity sources (default: none, fully offline)")
    net.add_argument(
        "--offline",
        action="store_true",
        help="guarantee no network access; rejects --fetch-checksums/--wp-cli (this is the default)",
    )
    net.add_argument(
        "--core-checksums",
        type=Path,
        metavar="FILE",
        help="official checksum JSON for the installed version (offline verification)",
    )
    net.add_argument(
        "--fetch-checksums", action="store_true", help="NETWORK: download core checksums from api.wordpress.org"
    )
    net.add_argument(
        "--wp-cli",
        action="store_true",
        help="NETWORK: run `wp core/plugin verify-checksums`; plugin verification bootstraps "
        "WordPress (executes wp-config.php) with plugins and themes skipped",
    )
    net.add_argument("--wp-cli-path", metavar="PATH", help="WP-CLI executable or wp-cli.phar (implies --wp-cli)")

    lim = s.add_argument_group("limits")
    lim.add_argument("--max-files", type=_positive, default=ScanOptions.max_files)
    lim.add_argument("--max-depth", type=_positive, default=ScanOptions.max_depth)
    lim.add_argument(
        "--max-read-bytes",
        type=_positive,
        default=ScanOptions.max_read_bytes,
        help="bytes read per file for content heuristics",
    )

    sub.add_parser("rules", help="list all rules")
    return p


def _normalise_argv(argv: list[str]) -> list[str]:
    """Keep `wp-security-doctor <path>` and `python wp_doctor.py <path>` working."""
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        return ["scan", *argv]
    return argv


def main(argv: Sequence[str] | None = None) -> int:
    args_list = _normalise_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(args_list)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    if args.command == "rules":
        return _list_rules()
    return _scan(args, parser)


def _scan(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    # Imported lazily so `--help` stays fast and import errors surface as messages.
    from .report import render_json, render_text, use_color
    from .scanner import scan

    wp_cli = bool(args.wp_cli or args.wp_cli_path)
    if args.sarif_path_prefix is not None:
        from .sarif import SarifPathError, normalise_prefix

        if args.format != "sarif":
            parser.error("--sarif-path-prefix requires --format sarif")
        try:
            normalise_prefix(args.sarif_path_prefix)
        except SarifPathError as exc:
            parser.error(str(exc))
    if args.offline and (args.fetch_checksums or wp_cli):
        parser.error("--offline cannot be combined with --fetch-checksums or --wp-cli")
    options = ScanOptions(
        checks=args.checks,
        offline=not (args.fetch_checksums or wp_cli),
        core_checksums_file=args.core_checksums,
        fetch_checksums=args.fetch_checksums,
        wp_cli=wp_cli,
        wp_cli_path=args.wp_cli_path,
        max_files=args.max_files,
        max_depth=args.max_depth,
        max_read_bytes=args.max_read_bytes,
    )
    target: Path = args.path
    if args.output is not None and target.exists():
        out_parent = args.output.resolve().parent
        if is_within(out_parent, target.resolve()):
            print(
                "error: --output must be outside the scanned WordPress directory "
                "(the scanner never writes into the installation).",
                file=sys.stderr,
            )
            return 2
    try:
        report = scan(target, options)
    except DetectionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not scan {target}: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        text = render_json(report)
    elif args.format == "sarif":
        from .sarif import render_sarif

        text = render_sarif(report, all_rules(), args.sarif_path_prefix)
    else:
        stream = sys.stdout if args.output is None else None
        text = render_text(report, color=use_color(stream, args.color), verbose=args.verbose)
    if args.output is not None:
        try:
            args.output.write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        _write_stdout(text)
    return _exit_code(report.findings, args.fail_on)


def _write_stdout(text: str) -> None:
    try:
        sys.stdout.write(text)
    except UnicodeEncodeError:  # legacy Windows consoles
        sys.stdout.write(text.encode("ascii", "replace").decode("ascii"))
    sys.stdout.flush()


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = Severity(fail_on.upper()).rank
    for f in findings:
        if f.status in (Status.FAIL, Status.WARN) and f.severity.rank >= threshold:
            return 1
    return 0


def all_rules() -> list[Rule]:
    from . import scanner
    from .checks import config, core, files, permissions, plugins

    rules: dict[str, Rule] = {}
    for mod in (core, config, files, permissions, plugins, scanner):
        for value in vars(mod).values():
            if isinstance(value, Rule):
                rules[value.rule_id] = value
    return [rules[k] for k in sorted(rules)]


def _list_rules() -> int:
    for r in all_rules():
        _write_stdout(f"{r.rule_id:<17} {r.severity.value:<8} {r.category:<12} {r.title}\n")
    return 0
