# DFIR Final Report

## Executive Summary

A synthetic Windows 11 endpoint, **FIN-WS01**, was used to model a ransomware-style intrusion. The evidence shows a coherent sequence from user document execution to PowerShell activity, follow-on process creation, outbound network communication, simulated persistence, staging, and file-impact activity.

The available telemetry supports a **high-confidence reconstruction of the simulated event sequence**. Because all artifacts are fabricated, no conclusion should be applied to a real organization or threat actor.

## Scope

**Host:** FIN-WS01  
**User:** ACME\\jsmith  
**Case ID:** DFIR-2026-001

## Evidence Reviewed

- Windows-style security/process events
- PowerShell script-block telemetry
- Sysmon process/network/file events
- Analyst-generated incident timeline
- IOC inventory

## Timeline

| Time (UTC) | Event | Significance |
|---|---|---|
| 10:02:11 | Invoice document opened | Initial execution opportunity |
| 10:02:19 | WINWORD spawned PowerShell | Suspicious process chain begins |
| 10:03:07 | Outbound TCP/443 connection | Synthetic C2-like activity |
| 10:04:17 | Persistence service created | Simulated persistence |
| 10:06:03 | Staging archive created | Potential data staging |
| 10:11:40 | Documents modified | Simulated impact |
| 10:13:05 | Ransom note opened | Simulated ransomware completion |

## ATT&CK Mapping

| Technique | Evidence | Assessment |
|---|---|---|
| T1059.001 PowerShell | PowerShell script block | Observed |
| T1218.011 Rundll32 | rundll32 child process | Observed |
| T1543.003 Windows Service | Service creation event | Simulated persistence |
| T1071.001 Web Protocols | TCP/443 destination | Possible, not proven |
| T1486 Data Encrypted for Impact | Document modification sequence | Simulated impact |

## Containment Recommendation

For a real incident, isolate the affected endpoint from the network while preserving volatile evidence when operationally safe. Block confirmed malicious infrastructure only after validating scope and ownership.

## Eradication

- Identify and remove persistence.
- Remove malicious tooling after acquisition and analysis.
- Reset potentially exposed credentials.
- Search enterprise telemetry for matching indicators.

## Recovery

- Restore from known-good backups.
- Validate endpoint integrity.
- Monitor for recurrence.
- Close the case only after post-recovery verification.

## Gaps

The simulation intentionally omits memory captures, packet captures, full registry hives, EDR telemetry, email headers, and cloud identity logs. These missing sources would normally be important for a production investigation.

## Conclusion

The evidence forms a consistent simulated intrusion chain. The strongest analytical value of this case is the correlation between independent artifact types rather than any single log entry.
