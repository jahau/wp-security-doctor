from pathlib import Path

import pytest
from conftest import can_symlink, write

from wp_security_doctor.fs import build_index, read_bytes, read_entry


def test_index_is_sorted_and_relative(tmp_path: Path) -> None:
    for rel in ("b/2.txt", "a/1.txt", "c.txt"):
        write(tmp_path / rel, "x")
    idx = build_index(tmp_path, 1000, 10)
    assert [e.rel for e in idx.entries] == ["a", "a/1.txt", "b", "b/2.txt", "c.txt"]
    assert not idx.truncated


def test_max_files_truncates(tmp_path: Path) -> None:
    for i in range(20):
        write(tmp_path / f"f{i:02}.txt", "x")
    idx = build_index(tmp_path, 5, 10)
    assert idx.truncated
    assert len(idx.entries) == 5


def test_max_depth_limits_traversal(tmp_path: Path) -> None:
    write(tmp_path / "a" / "b" / "c" / "deep.txt", "x")
    idx = build_index(tmp_path, 1000, 2)
    assert "a/b" in idx.depth_limited
    assert all("deep.txt" not in e.rel for e in idx.entries)


def test_vcs_directories_are_pruned(tmp_path: Path) -> None:
    write(tmp_path / ".git" / "config", "x")
    idx = build_index(tmp_path, 1000, 10)
    assert idx.pruned == [".git"]
    assert [e.rel for e in idx.entries] == [".git"]


def test_symlinks_outside_root_are_not_followed(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symlinks not permitted on this system")
    outside = tmp_path / "outside"
    write(outside / "secret.php", "<?php eval(base64_decode('x'));")
    root = tmp_path / "root"
    write(root / "keep.txt", "x")
    (root / "linkdir").symlink_to(outside, target_is_directory=True)
    (root / "linkfile.php").symlink_to(outside / "secret.php")
    idx = build_index(root.resolve(), 1000, 10)
    assert idx.external_symlinks == ["linkdir", "linkfile.php"]
    assert all("secret" not in e.rel for e in idx.entries)
    assert read_bytes(root / "linkfile.php", root.resolve(), 100) is None


def test_internal_symlinks_are_recorded_but_not_descended(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("symlinks not permitted on this system")
    root = tmp_path / "root"
    write(root / "real" / "a.txt", "hello")
    (root / "alias").symlink_to(root / "real", target_is_directory=True)
    (root / "a-link.txt").symlink_to(root / "real" / "a.txt")
    idx = build_index(root.resolve(), 1000, 10)
    rels = {e.rel: e for e in idx.entries}
    assert rels["alias"].is_symlink and "alias/a.txt" not in rels
    assert read_entry(root.resolve(), rels["a-link.txt"], 100) == b"hello"


def test_read_limits(tmp_path: Path) -> None:
    f = write(tmp_path / "big.bin", b"x" * 1000)
    assert read_bytes(f, tmp_path.resolve(), 10) == b"x" * 10
    assert read_bytes(tmp_path / "missing", tmp_path.resolve(), 10) is None
    assert read_bytes(tmp_path, tmp_path.resolve(), 10) is None  # directory
