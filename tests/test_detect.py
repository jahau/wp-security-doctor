import shutil
from pathlib import Path

import pytest
from conftest import VERSION, config_php, make_core, write

from wp_security_doctor.detect import DetectionError, detect


def test_standard_layout(wp: Path) -> None:
    inst = detect(wp)
    assert inst.layout == "standard"
    assert inst.version == VERSION
    assert inst.config_path == wp / "wp-config.php"
    assert inst.content_dir == wp / "wp-content"
    assert not inst.config_outside_root


def test_config_in_parent_directory_outside_scan_root(tmp_path: Path) -> None:
    core = make_core(tmp_path / "public_html")
    write(tmp_path / "wp-config.php", config_php())
    inst = detect(core)
    assert inst.config_path == (tmp_path / "wp-config.php").resolve()
    assert inst.config_outside_root
    assert inst.layout == "parent-config"
    assert any("outside the scan root" in n for n in inst.notes)


def test_parent_config_ignored_when_parent_is_another_wordpress(tmp_path: Path) -> None:
    make_core(tmp_path)  # parent has its own wp-settings.php
    write(tmp_path / "wp-config.php", config_php())
    core = make_core(tmp_path / "blog")
    assert detect(core).config_path is None


def test_wordpress_in_subdirectory(tmp_path: Path) -> None:
    make_core(tmp_path / "wordpress")
    write(tmp_path / "wordpress" / "wp-config.php", config_php())
    inst = detect(tmp_path)
    assert inst.layout == "subdirectory"
    assert inst.core_rel == "wordpress"
    assert inst.rel(inst.config_path) == "wordpress/wp-config.php"


def test_bedrock_layout(tmp_path: Path) -> None:
    core = tmp_path / "web" / "wp"
    make_core(core)
    (tmp_path / "web" / "app" / "plugins").mkdir(parents=True)
    write(tmp_path / "web" / "wp-config.php", "<?php require_once dirname(__DIR__) . '/config/application.php';\n")
    write(tmp_path / "config" / "application.php", "<?php Config::define('DISALLOW_FILE_EDIT', true);\n")
    # Bedrock has no wp-content inside core.
    shutil.rmtree(core / "wp-content")
    inst = detect(tmp_path)
    assert inst.layout == "bedrock"
    assert inst.config_path == (tmp_path / "web" / "wp-config.php").resolve()
    assert inst.content_dir == (tmp_path / "web" / "app").resolve()
    assert inst.extra_config_paths == [tmp_path.resolve() / "config" / "application.php"]


def test_not_wordpress(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="No WordPress core"):
        detect(tmp_path)


def test_missing_and_file_targets(tmp_path: Path) -> None:
    with pytest.raises(DetectionError, match="does not exist"):
        detect(tmp_path / "nope")
    f = write(tmp_path / "file.txt", "x")
    with pytest.raises(DetectionError, match="Not a directory"):
        detect(f)


def test_missing_wp_config(tmp_path: Path) -> None:
    inst = detect(make_core(tmp_path / "site"))
    assert inst.config_path is None
