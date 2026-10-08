#!/usr/bin/env python3
"""Merge synthetic Windows/Sysmon CSV events into a normalized timeline."""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from datetime import datetime


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def normalize_windows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out = []
    for row in rows:
        out.append(
            {
                "timestamp": row["timestamp"],
                "source": f"WindowsEvent:{row['event_id']}",
                "event": row["action"],
                "actor": row["user"],
                "details": row["details"],
            }
        )
    return out


def normalize_sysmon(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out = []
    for row in rows:
        detail = row["command_line"] or row["destination_ip"] or row["image"]
        if row["event_id"] == "3":
            detail = f"{row['destination_ip']}:{row['destination_port']}"
        out.append(
            {
                "timestamp": row["timestamp"],
                "source": f"Sysmon:{row['event_id']}",
                "event": "network_connection" if row["event_id"] == "3" else "telemetry",
                "actor": row["user"],
                "details": detail,
            }
        )
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python build_timeline.py WINDOWS.csv SYSMON.csv")
        return 2

    windows_path = Path(sys.argv[1])
    sysmon_path = Path(sys.argv[2])
    output = windows_path.parent.parent / "timeline" / "generated-timeline.csv"
    output.parent.mkdir(parents=True, exist_ok=True)

    events = normalize_windows(read_csv(windows_path)) + normalize_sysmon(read_csv(sysmon_path))
    events.sort(key=lambda item: datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")))

    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "source", "event", "actor", "details"])
        writer.writeheader()
        writer.writerows(events)

    print(f"Wrote {len(events)} events to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
