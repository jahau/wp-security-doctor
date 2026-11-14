"""Locate WordPress core, wp-config.php and the content directory.

Supported layouts:

* standard        core, wp-config.php and wp-content in one directory
* parent-config   wp-config.php one level above core (WordPress loads it from
                  there when the parent is not itself a WordPress install)
* subdirectory    the scan target contains core in ``wordpress/``, ``wp/``,
                  ``public_html/`` ... ("Giving WordPress its own directory")
* bedrock         Roots Bedrock: ``web/wp`` core, ``web/app`` content,
                  ``web/wp-config.php`` and ``config/application.php``
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .fs import is_within, read_text

CORE_SUBDIRS = ("", "wordpress", "wp", "web/wp", "public_html", "htdocs", "public", "www", "web", "html")


class DetectionError(Exception):
    """The target is not a recognisable WordPress installation."""


@dataclass
class Installation:
    scan_root: Path
    core_dir: Path
    layout: str
    version: str | None = None
    local_package: str | None = None
    config_path: Path | None = None
    config_outside_root: bool = False
    extra_config_paths: list[Path] = field(default_factory=list)
    content_dir: Path | None = None
    notes: list[str] = field(default_factory=list)

    def rel(self, path: Path) -> str:
        """Report-friendly path: relative to the scan root when possible."""
        try:
            return path.relative_to(self.scan_root).as_posix() or "."
        except ValueError:
            return path.as_posix()

    @property
    def core_rel(self) -> str:
        return self.rel(self.core_dir)


def _is_core(path: Path) -> bool:
    return (path / "wp-includes" / "version.php").is_file() and (
        (path / "wp-settings.php").is_file() or (path / "wp-load.php").is_file()
    )


_VERSION_RE = re.compile(r"""\$wp_version\s*=\s*['"]([^'"]+)['"]""")
_LOCAL_RE = re.compile(r"""\$wp_local_package\s*=\s*['"]([^'"]+)['"]""")


def read_version(core_dir: Path) -> tuple[str | None, str | None]:
    text = read_text(core_dir / "wp-includes" / "version.php", core_dir, 256 * 1024)
    if text is None:
        return None, None
    v = _VERSION_RE.search(text)
    loc = _LOCAL_RE.search(text)
    return (v.group(1) if v else None), (loc.group(1) if loc else None)


def detect(target: Path) -> Installation:
    if not target.exists():
        raise DetectionError(f"Path does not exist: {target}")
    if not target.is_dir():
        raise DetectionError(f"Not a directory: {target}")
    scan_root = target.resolve()

    core_dir: Path | None = None
    for sub in CORE_SUBDIRS:
        candidate = (scan_root / sub) if sub else scan_root
        # Do not follow a symlinked candidate out of the scan root.
        if candidate.is_dir() and is_within(candidate.resolve(), scan_root) and _is_core(candidate):
            core_dir = candidate.resolve()
            break
    if core_dir is None:
        raise DetectionError(
            f"No WordPress core found in {scan_root} (looked for wp-includes/version.php "
            f"in: {', '.join(s or '.' for s in CORE_SUBDIRS)})."
        )

    bedrock = core_dir == scan_root / "web" / "wp"
    layout = "bedrock" if bedrock else ("standard" if core_dir == scan_root else "subdirectory")
    inst = Installation(scan_root=scan_root, core_dir=core_dir, layout=layout)
    inst.version, inst.local_package = read_version(core_dir)

    # wp-config.php: WordPress checks ABSPATH first, then one directory up as
    # long as that directory does not contain its own wp-settings.php.
    config_candidates = [core_dir / "wp-config.php"]
    parent = core_dir.parent
    if not (parent / "wp-settings.php").exists():
        config_candidates.append(parent / "wp-config.php")
    for cand in config_candidates:
        if cand.is_file():
            inst.config_path = cand
            break
    if inst.config_path is not None:
        inst.config_outside_root = not is_within(inst.config_path.resolve(), scan_root)
        if inst.config_path.parent != core_dir and layout == "standard":
            inst.layout = "parent-config"
        if inst.config_outside_root:
            inst.notes.append(
                "wp-config.php is outside the scan root (parent directory); it was read "
                "as a single file but the parent directory was not traversed."
            )
    if bedrock and (scan_root / "config" / "application.php").is_file():
        inst.extra_config_paths.append(scan_root / "config" / "application.php")

    for cand in (core_dir / "wp-content", scan_root / "wp-content", scan_root / "web" / "app"):
        if cand.is_dir() and is_within(cand.resolve(), scan_root):
            inst.content_dir = cand.resolve()
            break
    if inst.content_dir is None:
        inst.notes.append(
            "No wp-content directory found inside the scan root; a custom WP_CONTENT_DIR "
            "outside the scan root is not inspected."
        )
    return inst
