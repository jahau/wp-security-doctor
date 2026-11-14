"""Scan options and shared, lazily computed scan state."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from .detect import Installation
from .fs import FileIndex, build_index, read_text
from .phpconfig import ParsedConfig, parse_config

ALL_CHECKS = ("core", "config", "files", "permissions", "plugins")

CONFIG_READ_LIMIT = 1024 * 1024


@dataclass
class ScanOptions:
    checks: tuple[str, ...] = ALL_CHECKS
    # Network-capable integrations: all disabled unless explicitly requested.
    offline: bool = True
    core_checksums_file: Path | None = None
    fetch_checksums: bool = False
    wp_cli: bool = False
    wp_cli_path: str | None = None
    wp_cli_timeout: float = 300.0
    network_timeout: float = 30.0
    # Traversal bounds.
    max_files: int = 200_000
    max_depth: int = 40
    max_read_bytes: int = 2 * 1024 * 1024


@dataclass
class ScanContext:
    installation: Installation
    options: ScanOptions
    # Values that must never appear in output (filled from wp-config parsing).
    secrets: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)

    @property
    def root(self) -> Path:
        return self.installation.scan_root

    @cached_property
    def index(self) -> FileIndex:
        return build_index(self.root, self.options.max_files, self.options.max_depth)

    @cached_property
    def config(self) -> ParsedConfig | None:
        """Merged definitions from wp-config.php (+ Bedrock application.php)."""
        inst = self.installation
        if inst.config_path is None:
            return None
        # The parent-directory wp-config.php may legitimately sit outside the scan
        # root (WordPress itself loads it from there); it is read as a single file.
        boundary = None if inst.config_outside_root else self.root
        text = read_text(inst.config_path, boundary, CONFIG_READ_LIMIT)
        if text is None:
            self.warnings.append(f"Could not read {inst.rel(inst.config_path)}.")
            return None
        merged = parse_config(text)
        for extra in inst.extra_config_paths:
            extra_text = read_text(extra, self.root, CONFIG_READ_LIMIT)
            if extra_text is None:
                continue
            extra_parsed = parse_config(extra_text)
            for name, defs in extra_parsed.definitions.items():
                merged.definitions.setdefault(name, []).extend(defs)
        self.secrets |= merged.secret_values()
        return merged

    def rel_to_core(self, rel_from_root: str) -> str | None:
        """Translate a scan-root-relative path into a core-relative one."""
        core = self.installation.core_rel
        if core in ("", "."):
            return rel_from_root
        prefix = core + "/"
        return rel_from_root[len(prefix) :] if rel_from_root.startswith(prefix) else None

    def root_rel(self, path: Path) -> str:
        return self.installation.rel(path)
