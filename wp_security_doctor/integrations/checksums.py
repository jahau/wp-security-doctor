"""Official WordPress core checksums: load from a local file or (opt-in) fetch them.

The checksum list is the JSON served by
``https://api.wordpress.org/core/checksums/1.0/?version=X&locale=Y``. Users who
want a fully offline scan can download that file on another machine and pass it
with ``--core-checksums``.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .. import __version__
from ..refs import CHECKSUM_API

MAX_RESPONSE = 8 * 1024 * 1024
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


class ChecksumError(Exception):
    pass


def parse_checksums(data: object, version: str | None) -> dict[str, str]:
    """Accept both the flat and the version-keyed API response shapes."""
    if not isinstance(data, dict):
        raise ChecksumError("checksum JSON must be an object")
    sums = data.get("checksums", data)
    if sums is False or sums is None:
        raise ChecksumError("checksum source has no entry for this version/locale")
    if not isinstance(sums, dict):
        raise ChecksumError("unexpected checksum JSON structure")
    if sums and all(isinstance(v, dict) for v in sums.values()):
        if version and version in sums:
            sums = sums[version]
        elif len(sums) == 1:
            sums = next(iter(sums.values()))
        else:
            raise ChecksumError(f"checksum file does not contain version {version}")
    out: dict[str, str] = {}
    for path, digest in sums.items():
        if not isinstance(path, str) or not isinstance(digest, str) or not _MD5_RE.match(digest.lower()):
            raise ChecksumError(f"invalid checksum entry for {path!r}")
        if ".." in path.split("/") or path.startswith("/"):
            raise ChecksumError(f"refusing unsafe path in checksum file: {path!r}")
        out[path] = digest.lower()
    if not out:
        raise ChecksumError("checksum list is empty")
    return out


def load_file(path: Path, version: str | None) -> dict[str, str]:
    try:
        raw = path.read_bytes()[: MAX_RESPONSE + 1]
    except OSError as exc:
        raise ChecksumError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if len(raw) > MAX_RESPONSE:
        raise ChecksumError("checksum file is unreasonably large")
    try:
        return parse_checksums(json.loads(raw), version)
    except json.JSONDecodeError as exc:
        raise ChecksumError(f"{path} is not valid JSON: {exc}") from exc


def fetch(version: str, locale: str, timeout: float) -> dict[str, str]:
    """Download checksums from api.wordpress.org (network access, opt-in only)."""
    query = urllib.parse.urlencode({"version": version, "locale": locale})
    url = f"{CHECKSUM_API}?{query}"
    # Fixed https:// base URL, so no file:// or custom schemes are possible.
    req = urllib.request.Request(url, headers={"User-Agent": f"wp-security-doctor/{__version__}"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
            raw = resp.read(MAX_RESPONSE + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ChecksumError(f"could not download checksums: {exc}") from exc
    if len(raw) > MAX_RESPONSE:
        raise ChecksumError("checksum response is unreasonably large")
    try:
        return parse_checksums(json.loads(raw), version)
    except json.JSONDecodeError as exc:
        raise ChecksumError(f"checksum API returned invalid JSON: {exc}") from exc


def md5_file(path: Path, limit: int = 64 * 1024 * 1024) -> str | None:
    h = hashlib.md5(usedforsecurity=False)
    read = 0
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                read += len(chunk)
                if read > limit:
                    return None
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()
