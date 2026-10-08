#!/usr/bin/env python3
"""Validate the structure and basic integrity of the synthetic DFIR case."""

from __future__ import annotations

import csv
import ipaddress
import json
from datetime import datetime
from pathlib import Path


REQUIRED = (
    "README.md",
    "case-notes.md",
    "attack-to-evidence.md",
    "lessons-learned.md",
    "evidence/README.md",
    "evidence/collection-manifest.csv",
    "evidence/windows-events.csv",
    "evidence/sysmon-events.csv",
    "timeline/incident-timeline.csv",
    "ioc/indicators.json",
    "report/final-report.md",
    "detections/office-spawns-powershell.yml",
)


def read_csv(path: Path, required_columns: set[str]) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
        missing = required_columns - columns
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        rows = list(reader)
        if not rows:
            raise ValueError(f"{path}: no data rows")
        return rows


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    case = root / "case-studies" / "windows-ransomware"

    for relative in REQUIRED:
        if not (case / relative).is_file():
            raise FileNotFoundError(f"Missing required artifact: {relative}")

    windows = read_csv(
        case / "evidence/windows-events.csv",
        {"timestamp", "event_id", "host", "user", "process", "action"},
    )
    sysmon = read_csv(
        case / "evidence/sysmon-events.csv",
        {"timestamp", "event_id", "host", "user", "image", "parent_image"},
    )
    timeline = read_csv(
        case / "timeline/incident-timeline.csv",
        {"timestamp", "source", "event", "actor", "assessment"},
    )
    manifest = read_csv(
        case / "evidence/collection-manifest.csv",
        {"evidence_id", "source", "artifact", "format", "synthetic"},
    )

    for rows, name in ((windows, "Windows events"), (sysmon, "Sysmon events"), (timeline, "Timeline")):
        timestamps = [parse_timestamp(row["timestamp"]) for row in rows]
        if timestamps != sorted(timestamps):
            raise ValueError(f"{name}: timestamps are not sorted")

    if any(row["synthetic"].lower() != "true" for row in manifest):
        raise ValueError("Evidence manifest contains a non-synthetic artifact")

    with (case / "ioc/indicators.json").open(encoding="utf-8") as handle:
        data = json.load(handle)

    if data.get("synthetic") is not True:
        raise ValueError("IOC inventory must explicitly declare synthetic=true")

    for indicator in data.get("indicators", {}).get("ipv4", []):
        try:
            ipaddress.ip_address(indicator["value"])
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 IOC: {indicator['value']}") from exc

    expected_ioc_ip = "203.0.113.77"
    observed_ips = {row.get("destination_ip", "") for row in sysmon}
    if expected_ioc_ip not in observed_ips:
        raise ValueError("Expected synthetic IOC is missing from Sysmon evidence")

    if len(timeline) < len(windows):
        raise ValueError("Normalized timeline unexpectedly contains fewer events than Windows evidence")

    print(
        "DFIR case validation: PASS "
        f"(windows={len(windows)}, sysmon={len(sysmon)}, timeline={len(timeline)}, manifest={len(manifest)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
