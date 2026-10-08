#!/usr/bin/env python3
"""Validate the structure and basic integrity of the synthetic DFIR case."""

from __future__ import annotations

import csv
import json
from pathlib import Path


REQUIRED = (
    "case-notes.md",
    "evidence/windows-events.csv",
    "evidence/sysmon-events.csv",
    "timeline/incident-timeline.csv",
    "ioc/indicators.json",
    "report/final-report.md",
    "attack-to-evidence.md",
)


def check_csv(path: Path, required_columns: set[str]) -> None:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = required_columns - columns
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        if not list(reader):
            raise ValueError(f"{path}: no data rows")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    case = root / "case-studies" / "windows-ransomware"

    for relative in REQUIRED:
        if not (case / relative).is_file():
            raise FileNotFoundError(f"Missing required artifact: {relative}")

    with (case / "ioc/indicators.json").open(encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("synthetic") is not True:
        raise ValueError("IOC inventory must explicitly declare synthetic=true")

    check_csv(
        case / "evidence/windows-events.csv",
        {"timestamp", "event_id", "host", "user", "process", "action"},
    )
    check_csv(
        case / "evidence/sysmon-events.csv",
        {"timestamp", "event_id", "host", "user", "image", "parent_image"},
    )
    check_csv(
        case / "timeline/incident-timeline.csv",
        {"timestamp", "source", "event", "actor", "assessment"},
    )

    print("DFIR case validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
