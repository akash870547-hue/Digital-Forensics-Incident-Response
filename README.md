# Digital Forensics & Incident Response

[![DFIR Case Validation](https://github.com/akash870547-hue/Digital-Forensics-Incident-Response/actions/workflows/dfir-validation.yml/badge.svg)](https://github.com/akash870547-hue/Digital-Forensics-Incident-Response/actions/workflows/dfir-validation.yml)

A hands-on DFIR casebook focused on **evidence-driven investigation, timeline reconstruction, IOC extraction, MITRE ATT&CK mapping, and incident reporting**.

> **Training-only:** all evidence is synthetic and intentionally fabricated. Indicators in this repository must not be treated as real-world threat intelligence.

## Why This Repository Exists

The goal is to demonstrate an investigation workflow rather than simply collect security notes:

**Evidence → Artifact Analysis → Timeline → IOCs → ATT&CK Mapping → Findings → Response**

Each case is designed to show both the technical evidence and the reasoning that connects the evidence to an incident finding.

## Featured Case: Windows Ransomware Investigation

A simulated Windows 11 endpoint incident in which a user opens a phishing attachment, triggers PowerShell execution, launches follow-on activity, creates simulated persistence, stages a file, and reaches a ransomware-style impact phase.

### Investigation Coverage

| Area | Included |
|---|---|
| Windows-style telemetry | ✅ |
| Sysmon-style telemetry | ✅ |
| Process lineage | ✅ |
| PowerShell analysis | ✅ |
| Network telemetry | ✅ |
| Timeline reconstruction | ✅ |
| IOC inventory | ✅ |
| Evidence hashing | ✅ |
| Evidence provenance | ✅ |
| MITRE ATT&CK mapping | ✅ |
| DFIR final report | ✅ |
| Analyst checklist | ✅ |
| Lessons learned | ✅ |
| CI validation | ✅ |

## Repository Layout

```
.
├── case-studies/
│   └── windows-ransomware/
│       ├── README.md
│       ├── case-notes.md
│       ├── attack-to-evidence.md
│       ├── lessons-learned.md
│       ├── detections/
│       │   └── office-spawns-powershell.yml
│       ├── evidence/
│       │   ├── README.md
│       │   ├── collection-manifest.csv
│       │   ├── windows-events.csv
│       │   └── sysmon-events.csv
│       ├── timeline/
│       │   └── incident-timeline.csv
│       ├── ioc/
│       │   └── indicators.json
│       └── report/
│           └── final-report.md
├── docs/
│   ├── methodology.md
│   ├── evidence-handling.md
│   ├── analyst-checklist.md
│   └── detection-engineering.md
├── scripts/
│   ├── build_timeline.py
│   ├── extract_iocs.py
│   ├── evidence_hash.py
│   └── validate_case.py
├── .github/workflows/
│   └── dfir-validation.yml
├── SECURITY.md
└── LICENSE
```

## Quick Start

### Rebuild the normalized timeline

```bash
python scripts/build_timeline.py \
  case-studies/windows-ransomware/evidence/windows-events.csv \
  case-studies/windows-ransomware/evidence/sysmon-events.csv
```

Creates:

`case-studies/windows-ransomware/timeline/generated-timeline.csv`

### Extract IOCs

```bash
python scripts/extract_iocs.py case-studies/windows-ransomware/evidence/
```

### Hash the evidence package

```bash
python scripts/evidence_hash.py case-studies/windows-ransomware/evidence/
```

### Validate the case

```bash
python scripts/validate_case.py
```

The same validation is executed automatically by GitHub Actions on pushes and pull requests.

## Investigation Design

The case deliberately separates **facts, assessments, and gaps**.

Example:

- **Observed:** a PowerShell process was created by WINWORD.
- **Assessment:** this is a high-value suspicious process lineage.
- **Gap:** the synthetic dataset does not contain the original email headers.

This makes the case closer to a real analyst workflow and avoids presenting unsupported assumptions as facts.

## Evidence Integrity

Every case includes an evidence manifest and an explicit synthetic-data declaration.

Recommended lifecycle:

`Acquire → Hash → Preserve → Analyze → Correlate → Report`

See [docs/evidence-handling.md](docs/evidence-handling.md) for the handling model.

## Current Case Limitations

The ransomware case is intentionally small so the entire investigation can be understood from the repository. It does **not** currently include full disk images, memory captures, registry hives, packet captures, EDR exports, or live malware.

Those gaps are documented rather than hidden.

## Roadmap

- Add phishing → credential-theft case
- Add browser and Windows Registry artifacts
- Add richer Windows Event/Sysmon parsers
- Add network/PCAP-based investigation
- Expand detection coverage with additional Sigma rules
- Add cross-case IOC and ATT&CK reporting

## Safety

This repository contains synthetic data and defensive analysis tooling. Do not upload real forensic evidence, credentials, customer information, or active-incident data. See [SECURITY.md](SECURITY.md).

## License

MIT
