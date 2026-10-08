# Lessons Learned

## What Made the Investigation Strong

### 1. Process lineage
The correlation between WINWORD → PowerShell → rundll32 provides stronger evidence than any isolated process event.

### 2. Independent telemetry
Windows-style events and Sysmon-style telemetry reinforce the same activity sequence.

### 3. Timeline correlation
The event order supports a single coherent intrusion story rather than disconnected alerts.

### 4. Explicit uncertainty
The report does not treat TCP/443 as proof of HTTP/S. Confidence is tied to the available evidence.

## Detection Opportunities

- Alert when Office applications spawn PowerShell.
- Investigate encoded PowerShell command lines.
- Alert on unexpected rundll32 execution from user-writable directories.
- Correlate new service creation with suspicious preceding process activity.
- Detect rapid multi-file modification/renaming activity.

## Missing Telemetry

A production investigation would benefit from:

- Email headers and mail gateway telemetry
- EDR process trees
- Full PowerShell operational logs
- Registry hives
- Memory capture
- DNS telemetry
- Proxy/firewall logs
- Identity-provider authentication logs

## Improvement Loop

Every completed case should produce at least one improvement to:

`Detection → Triage → Collection → Analysis → Response`

This turns an incident report into an operational learning artifact.
