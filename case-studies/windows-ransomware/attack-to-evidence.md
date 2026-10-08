# ATT&CK to Evidence Mapping

This mapping connects observed synthetic artifacts to MITRE ATT&CK techniques.

| Technique | Evidence | Confidence |
|---|---|---|
| T1059.001 PowerShell | Windows Event 4104 + Sysmon Event 1 | High |
| T1218.011 Rundll32 | Sysmon Event 1 | High |
| T1543.003 Windows Service | Windows Event 7045 | High |
| T1071.001 Web Protocols | Sysmon Event 3 to TCP/443 | Medium |
| T1486 Data Encrypted for Impact | File modification sequence | Medium / simulated |

## Evidence Chain

```text
Invoice document -> WINWORD.EXE -> PowerShell -> rundll32.exe
-> outbound connection -> simulated persistence -> staging archive -> document modification
```

The T1071.001 mapping remains medium confidence because TCP/443 alone does not prove the application-layer protocol.
