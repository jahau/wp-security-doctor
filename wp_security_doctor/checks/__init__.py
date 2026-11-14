"""Check registry. Each module exposes ``run(ctx) -> list[Finding]``."""

from __future__ import annotations

from collections.abc import Callable

from ..context import ScanContext
from ..models import Finding
from . import config, core, files, permissions, plugins

REGISTRY: dict[str, Callable[[ScanContext], list[Finding]]] = {
    "core": core.run,
    "config": config.run,
    "files": files.run,
    "permissions": permissions.run,
    "plugins": plugins.run,
}
