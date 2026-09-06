"""Deterministic artifact writing, checksums and build metadata.

Determinism is a security property here, not tidiness: if the same upstream
input and generator version can be shown to produce the same bytes, a reviewer
can reproduce any published list and tell whether it came from the sources it
claims. So the writers below control encoding, line endings and ordering
explicitly, and no timestamp is ever written into a .txt artifact.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

#: Files that are part of the GL.iNet-consumable subscription surface. Their
#: checksums are published together, in this order.
ARTIFACT_ORDER = ("cn-ipv4.txt", "cn-domains.txt", "cn-direct.txt")


def render_lines(lines: list[str]) -> bytes:
    """Render rule lines as the exact bytes that get published.

    UTF-8, LF endings, no BOM, one rule per line, final newline, nothing else.
    """
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_artifact(path: Path, lines: list[str]) -> bytes:
    """Write a rule file deterministically and return the bytes written."""
    data = render_lines(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(directory: Path, filenames: list[str]) -> bytes:
    """Write checksums.txt in the conventional `<hex>  <filename>` format."""
    lines = [f"{sha256_file(directory / name)}  {name}" for name in sorted(filenames)]
    return write_artifact(directory / "checksums.txt", lines)


def write_json(path: Path, document: dict) -> bytes:
    """Write pretty JSON with stable key order and a final newline."""
    data = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_report(directory: Path, filenames: list[str]) -> dict:
    """Line count and byte size per artifact, for router-practicality review."""
    report: dict[str, dict] = {}
    for name in sorted(filenames):
        path = directory / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        report[name] = {
            "lines": data.count(b"\n"),
            "bytes": len(data),
            "sha256": sha256_bytes(data),
        }
    return report


def release_version(today: str, existing_tags: list[str]) -> str:
    """Date-based version, suffixed when the same day already has releases.

    `today` is an ISO date; the result is v2026.09.06, then v2026.09.06.1, .2, ...
    """
    base = "v" + today.replace("-", ".")
    if base not in existing_tags:
        return base
    counter = 1
    while f"{base}.{counter}" in existing_tags:
        counter += 1
    return f"{base}.{counter}"
