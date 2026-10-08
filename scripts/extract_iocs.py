#!/usr/bin/env python3
"""Extract obvious IPs, Windows paths, hashes and domains from text artifacts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\r\n,]+)")


def scan(folder: Path) -> dict[str, set[str]]:
    found = {"ipv4": set(), "sha256": set(), "domains": set(), "windows_paths": set()}
    for path in folder.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found["ipv4"].update(IP_RE.findall(text))
        found["sha256"].update(HASH_RE.findall(text))
        found["domains"].update(DOMAIN_RE.findall(text))
        found["windows_paths"].update(WIN_PATH_RE.findall(text))
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python extract_iocs.py EVIDENCE_DIR")
        return 2

    for category, values in scan(Path(sys.argv[1])).items():
        print(f"\n[{category}]")
        for value in sorted(values):
            print(value)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
