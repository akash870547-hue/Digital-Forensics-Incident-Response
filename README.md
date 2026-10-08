# Digital Forensics & Incident Response

A hands-on DFIR casebook focused on evidence-driven investigation, timeline reconstruction, IOC extraction, and incident reporting.

> All evidence in this repository is **synthetic** and intentionally fabricated for training, portfolio demonstration, and lab use. Do not treat the indicators as real-world threat intelligence.

## Featured Case

### Windows Ransomware Investigation
A simulated endpoint incident in which a user receives a phishing attachment, executes a malicious PowerShell command, establishes persistence, stages files, and triggers ransomware-like activity.

The case demonstrates:

- Evidence triage and artifact preservation
- Windows/Sysmon event analysis
- PowerShell execution analysis
- Incident timeline reconstruction
- IOC extraction and categorization
- MITRE ATT&CK mapping
- Containment and recovery decisions
- Professional DFIR reporting

## Repository Layout

```
case-studies/
  windows-ransomware/
    case-notes.md
    evidence/
      README.md
      windows-events.csv
      sysmon-events.csv
    timeline/
      incident-timeline.csv
    ioc/
      indicators.json
    report/
      final-report.md

scripts/
  build_timeline.py
  extract_iocs.py
  evidence_hash.py

docs/
  methodology.md
```

## Quick Start

### 1. Rebuild the incident timeline

```bash
python scripts/build_timeline.py case-studies/windows-ransomware/evidence/windows-events.csv case-studies/windows-ransomware/evidence/sysmon-events.csv
```

Output:

`case-studies/windows-ransomware/timeline/generated-timeline.csv`

### 2. Extract IOCs from the case artifacts

```bash
python scripts/extract_iocs.py case-studies/windows-ransomware/evidence/
```

### 3. Generate evidence hashes

```bash
python scripts/evidence_hash.py case-studies/windows-ransomware/evidence/
```

## Investigation Philosophy

The repository follows a simple DFIR chain:

`Evidence → Artifact Analysis → Timeline → IOCs → Findings → Response`

The objective is not just to identify suspicious activity, but to show **how the conclusion was reached and how evidence supports it**.

## Disclaimer

This project contains synthetic data and safe analysis tooling. It does not contain live malware, stolen data, credentials, or real victims.
