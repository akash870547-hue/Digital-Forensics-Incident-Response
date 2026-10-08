# Detection Engineering

DFIR findings should feed back into detections.

## Detection 1: Office Application Spawns PowerShell

### Logic

Flag when a Microsoft Office process launches PowerShell.

**High-value parent processes:**
- WINWORD.EXE
- EXCEL.EXE
- POWERPNT.EXE
- MSACCESS.EXE

**Child process:**
- powershell.exe / pwsh.exe

This should be enriched with command-line context, user identity, signer information, and network telemetry.

## Recommended Triage Context

When the detection fires, collect:

1. Parent/child process tree
2. Full command line
3. PowerShell Script Block logs
4. User and host identity
5. Destination network connections
6. Recent file creation
7. Persistence events

## Detection-to-DFIR Loop

`Alert → Triage → Evidence Collection → Timeline → Finding → Detection Tuning`

The repository intentionally keeps detection logic close to the corresponding forensic evidence so that detections remain grounded in observable behavior.
