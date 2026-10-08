# Evidence Handling Guide

## Evidence Lifecycle

```
Identify → Acquire → Verify → Preserve → Analyze → Report → Retain/Dispose
```

## Acquisition Record

For every artifact, record:

| Field | Example |
|---|---|
| Case ID | DFIR-2026-001 |
| Evidence ID | E-001 |
| Source | FIN-WS01 |
| Artifact | Sysmon export |
| Collector | Analyst name/tool |
| Collection time | UTC timestamp |
| Original location | Source path |
| SHA-256 | Evidence hash |
| Notes | Any transformation or filtering |

## Integrity

Hash evidence immediately after acquisition and whenever a transformed copy is created.

A derived artifact should never replace the original. Keep the relationship explicit:

`Original Evidence → Working Copy → Parsed Output → Analyst Finding`

## Time Normalization

Store timestamps in UTC when possible. Preserve the original timezone/offset in acquisition notes so a timeline can be reconstructed accurately.

## Chain of Custody

A minimal chain-of-custody record should capture:

1. Who collected the artifact
2. When it was collected
3. Where it was stored
4. Who accessed/transferred it
5. Why it was accessed
6. Hash before/after transfer when applicable
