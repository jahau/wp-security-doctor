"""Static (non-executing) parsing of ``define()`` calls in wp-config.php.

The parser never runs PHP. It strips comments, then looks for
``define('NAME', value)`` and Bedrock-style ``Config::define('NAME', value)``
calls. Literal values (booleans, integers, quoted strings) are decoded; any
other expression (``getenv()``, ``env()``, ``$var``...) is reported as dynamic
because its runtime value cannot be known without executing code.

Secret values are kept only in memory so they can be redacted from reports;
they are never emitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SECRET_KEYS = (
    "AUTH_KEY",
    "SECURE_AUTH_KEY",
    "LOGGED_IN_KEY",
    "NONCE_KEY",
    "AUTH_SALT",
    "SECURE_AUTH_SALT",
    "LOGGED_IN_SALT",
    "NONCE_SALT",
)
# Values of these constants are redacted from all output.
PASSWORD_KEYS = ("DB_PASSWORD", "FTP_PASS")


class Dynamic:
    """Marker for a value that is computed at runtime."""

    def __init__(self, expression: str) -> None:
        self.expression = expression

    def __repr__(self) -> str:
        return "<dynamic>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Dynamic) and other.expression == self.expression

    def __hash__(self) -> int:
        return hash(self.expression)


Value = bool | int | str | Dynamic


@dataclass
class Definition:
    name: str
    value: Value
    line: int
    conditional: bool  # inside if(...) / defined(...) or ... guards


@dataclass
class ParsedConfig:
    definitions: dict[str, list[Definition]] = field(default_factory=dict)
    table_prefix: str | Dynamic | None = None
    includes_other_files: bool = False

    def get(self, name: str) -> Definition | None:
        """Return the effective definition (PHP keeps the first ``define``)."""
        defs = self.definitions.get(name)
        return defs[0] if defs else None

    def is_ambiguous(self, name: str) -> bool:
        """True when the effective value depends on runtime control flow.

        PHP keeps the first ``define()`` that executes, so an unconditional first
        definition wins regardless of later ones.
        """
        defs = self.definitions.get(name, [])
        if not defs or not defs[0].conditional:
            return False
        return len({_hashable(d.value) for d in defs}) > 1

    def secret_values(self) -> set[str]:
        out: set[str] = set()
        for key in (*SECRET_KEYS, *PASSWORD_KEYS):
            for d in self.definitions.get(key, []):
                if isinstance(d.value, str) and len(d.value) >= 4:
                    out.add(d.value)
        return out


def _hashable(v: Value) -> object:
    return ("dyn", v.expression) if isinstance(v, Dynamic) else (type(v).__name__, v)


def strip_comments(src: str) -> str:
    """Remove PHP comments while keeping string literals and line numbers intact."""
    out: list[str] = []
    i, n = 0, len(src)
    quote: str | None = None
    while i < n:
        c = src[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            out.append(c)
            i += 1
        elif c == "#" or (c == "/" and src.startswith("//", i)):
            if src.startswith("#[", i):  # PHP 8 attribute, not a comment
                out.append(c)
                i += 1
                continue
            end = src.find("\n", i)
            if end == -1:
                break
            # ``?>`` ends a single-line comment too, but that edge case is irrelevant here.
            i = end
        elif c == "/" and src.startswith("/*", i):
            end = src.find("*/", i + 2)
            chunk = src[i : (n if end == -1 else end + 2)]
            out.append("\n" * chunk.count("\n"))
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


_DEFINE_RE = re.compile(
    r"""(?P<prefix>(?:Config::)?)\bdefine\s*\(\s*(?P<q>['"])(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P=q)\s*,\s*""",
    re.IGNORECASE,
)
_PREFIX_RE = re.compile(r"""\$table_prefix\s*=\s*""")
_INCLUDE_RE = re.compile(r"""\b(?:require|include)(?:_once)?\b(?!\s*\(?\s*ABSPATH\s*\.\s*['"]wp-settings\.php)""")


def _read_expression(src: str, start: int) -> tuple[str, int]:
    """Read a PHP expression up to the closing ``)`` / ``;`` at depth 0."""
    depth = 0
    i = start
    quote: str | None = None
    while i < len(src):
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c in "([":
            depth += 1
        elif c in ")]":
            if depth == 0:
                break
            depth -= 1
        elif c in ",;" and depth == 0:
            break
        i += 1
    return src[start:i].strip(), i


def _decode_literal(expr: str) -> Value:
    low = expr.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", expr):
        return int(expr)
    m = re.fullmatch(r"'((?:[^'\\]|\\.)*)'", expr, re.DOTALL)
    if m:
        return re.sub(r"\\([\\'])", r"\1", m.group(1))
    m = re.fullmatch(r'"((?:[^"\\$]|\\.)*)"', expr, re.DOTALL)
    if m:  # double-quoted without interpolation
        return re.sub(r"\\(.)", r"\1", m.group(1))
    return Dynamic(expr)


def mask_strings(src: str) -> str:
    """Replace the contents of string literals with spaces (newlines kept)."""
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(src):
        c = src[i]
        if quote:
            if c == "\\" and i + 1 < len(src):
                out.append(" ")
                out.append("\n" if src[i + 1] == "\n" else " ")
                i += 2
                continue
            if c == quote:
                quote = None
                out.append(c)
            else:
                out.append("\n" if c == "\n" else " ")
        else:
            if c in ("'", '"'):
                quote = c
            out.append(c)
        i += 1
    return "".join(out)


_GUARD_RE = re.compile(r"\bdefined\s*\(|\bif\s*\(|\?|\|\||\bor\b|&&|\band\b", re.IGNORECASE)


def _is_conditional(masked: str, pos: int) -> bool:
    line_start = masked.rfind("\n", 0, pos) + 1
    if _GUARD_RE.search(masked[line_start:pos]):
        return True
    # Inside a block (if/else/function): unclosed braces before this point.
    depth = 0
    for ch in masked[:pos]:
        if ch == "{":
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
    return depth > 0


def parse_config(src: str) -> ParsedConfig:
    clean = strip_comments(src)
    masked = mask_strings(clean)
    parsed = ParsedConfig()
    for m in _DEFINE_RE.finditer(clean):
        expr, _ = _read_expression(clean, m.end())
        value = _decode_literal(expr)
        line = clean.count("\n", 0, m.start()) + 1
        name = m.group("name")  # PHP constant names are case-sensitive
        parsed.definitions.setdefault(name, []).append(
            Definition(name, value, line, _is_conditional(masked, m.start()))
        )
    pm = _PREFIX_RE.search(clean)
    if pm:
        expr, _ = _read_expression(clean, pm.end())
        val = _decode_literal(expr)
        parsed.table_prefix = val if isinstance(val, (str, Dynamic)) else Dynamic(expr)
    parsed.includes_other_files = bool(_INCLUDE_RE.search(clean))
    return parsed
