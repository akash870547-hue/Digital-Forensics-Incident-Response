#!/usr/bin/env python3
"""Produce SHA-256 hashes for an evidence directory."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python evidence_hash.py EVIDENCE_DIR")
        return 2

    root = Path(sys.argv[1])
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        return 1

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        print(f"{sha256(path)}  {path.as_posix()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
