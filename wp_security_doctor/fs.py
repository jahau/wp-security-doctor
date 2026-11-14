"""Bounded, read-only, symlink-safe filesystem access.

Everything the scanner reads from inside the scan root goes through this module:

* directories are walked with ``os.scandir`` and symlinked directories are never
  followed;
* symlinked files are only read when their target resolves inside the scan root;
* traversal stops after ``max_files`` entries or ``max_depth`` levels and the
  truncation is reported instead of silently ignored;
* file reads are capped at ``max_read_bytes``.

Nothing in this module opens a file for writing.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

# Directories that are never descended into. Their presence is still recorded.
PRUNED_DIRS = frozenset({".git", ".svn", ".hg", "node_modules"})

PHP_SUFFIXES = (".php", ".phtml", ".phar", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht", ".phps")


@dataclass(frozen=True)
class Entry:
    rel: str  # POSIX-style path relative to the scan root
    mode: int  # lstat() mode bits
    size: int
    is_dir: bool
    is_symlink: bool

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @property
    def is_php(self) -> bool:
        return not self.is_dir and is_php_name(self.name)


def is_php_name(name: str) -> bool:
    return name.lower().endswith(PHP_SUFFIXES)


@dataclass
class FileIndex:
    root: Path
    entries: list[Entry] = field(default_factory=list)
    truncated: bool = False
    depth_limited: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    external_symlinks: list[str] = field(default_factory=list)
    pruned: list[str] = field(default_factory=list)

    def files(self) -> list[Entry]:
        return [e for e in self.entries if not e.is_dir]

    def under(self, rel_dir: str) -> list[Entry]:
        prefix = rel_dir.rstrip("/") + "/"
        if rel_dir in ("", "."):
            return list(self.entries)
        return [e for e in self.entries if e.rel.startswith(prefix)]


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def build_index(root: Path, max_files: int, max_depth: int) -> FileIndex:
    """Walk ``root`` (already resolved) without following directory symlinks."""
    index = FileIndex(root=root)
    stack: list[tuple[Path, int]] = [(root, 0)]
    count = 0
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as it:
                children = sorted(it, key=lambda d: d.name)
        except OSError as exc:
            index.errors.append(f"{_rel(directory, root) or '.'}: {exc.strerror or exc}")
            continue
        subdirs: list[Path] = []
        for child in children:
            if count >= max_files:
                index.truncated = True
                return _finish(index)
            child_path = Path(child.path)
            rel = _rel(child_path, root)
            try:
                st = child.stat(follow_symlinks=False)
            except OSError as exc:
                index.errors.append(f"{rel}: {exc.strerror or exc}")
                continue
            is_link = stat.S_ISLNK(st.st_mode)
            if is_link:
                target_ok = _symlink_target_inside(child_path, root)
                if not target_ok:
                    index.external_symlinks.append(rel)
                    continue
                # Internal symlink: record it as a file-like entry but never descend.
                try:
                    target_st = child_path.stat()
                except OSError:
                    continue
                index.entries.append(Entry(rel, st.st_mode, target_st.st_size, stat.S_ISDIR(target_st.st_mode), True))
                count += 1
                continue
            is_dir = stat.S_ISDIR(st.st_mode)
            if not is_dir and not stat.S_ISREG(st.st_mode):
                continue  # sockets, fifos, devices
            index.entries.append(Entry(rel, st.st_mode, st.st_size, is_dir, False))
            count += 1
            if is_dir:
                if child.name in PRUNED_DIRS:
                    index.pruned.append(rel)
                elif depth + 1 >= max_depth:
                    index.depth_limited.append(rel)
                else:
                    subdirs.append(child_path)
        # Reverse so that sorted order is preserved when popping from the stack.
        stack.extend((d, depth + 1) for d in reversed(subdirs))
    return _finish(index)


def _finish(index: FileIndex) -> FileIndex:
    index.entries.sort(key=lambda e: e.rel)
    index.errors.sort()
    index.external_symlinks.sort()
    index.depth_limited.sort()
    index.pruned.sort()
    return index


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _symlink_target_inside(path: Path, root: Path) -> bool:
    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    return is_within(target, root)


def read_bytes(path: Path, root: Path | None, limit: int) -> bytes | None:
    """Read at most ``limit`` bytes from a regular file.

    When ``root`` is given the resolved path must be inside it; this blocks
    symlink escapes. Returns ``None`` if the file cannot be read safely.
    """
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if root is not None and not is_within(resolved, root):
        return None
    if not resolved.is_file():
        return None
    try:
        with open(resolved, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


def read_entry(root: Path, entry: Entry, limit: int) -> bytes | None:
    """Read an indexed entry. Symlinks are re-validated; plain files are opened
    without following a final-component symlink where the OS supports it, which
    closes the window between indexing and reading."""
    path = root / entry.rel
    if entry.is_symlink:
        return read_bytes(path, root, limit)
    if entry.is_dir:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def read_text(path: Path, root: Path | None, limit: int) -> str | None:
    data = read_bytes(path, root, limit)
    if data is None:
        return None
    return data.decode("utf-8", errors="replace")
