# Case Study: Windows Ransomware Investigation

**Case ID:** DFIR-2026-001  
**Severity:** High  
**Environment:** Simulated Windows 11 workstation  
**Evidence:** Synthetic Windows and Sysmon-style event data

## Scenario

At 10:02 UTC, a finance employee opens an unexpected invoice attachment. Within minutes, a PowerShell process executes a suspicious encoded command, creates a staging directory, and connects to an external command-and-control endpoint.

Shortly afterward, multiple documents are renamed with a simulated ransom-note extension.

## Investigation Questions

1. What was the initial execution point?
2. Which process chain led to the suspicious activity?
3. What artifacts prove persistence or follow-on execution?
4. What destination infrastructure was contacted?
5. Which files and accounts were affected?
6. What containment action should occur first?

## Key Findings

- User-launched office activity preceded PowerShell execution.
- PowerShell was followed by a network connection to a synthetic external IP.
- A staging directory was created under the user profile.
- A simulated persistence action was observed.
- File-renaming activity occurred after the suspicious execution chain.

## Confidence

**High** for the event sequence represented by the supplied synthetic logs.  
**Not applicable** to real-world attribution or threat intelligence.
