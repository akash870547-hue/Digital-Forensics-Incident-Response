# DFIR Methodology

## 1. Preserve

Work from copies whenever possible. Record:

- Evidence source
- Collection date/time
- Examiner
- File name
- SHA-256
- Chain-of-custody notes

## 2. Triage

Prioritize artifacts that answer:

1. What happened?
2. When did it happen?
3. Which account or process was involved?
4. What systems or files were affected?
5. What indicators can be searched elsewhere?

## 3. Correlate

Correlate multiple artifacts rather than relying on a single log source.

Example:

`Email delivery → Process creation → PowerShell → Network connection → File staging`

## 4. Timeline

Normalize timestamps to a single timezone and sort chronologically. Record both the source artifact and an analyst interpretation.

## 5. IOC Extraction

Capture observables such as:

- IP addresses
- Domains
- File paths
- File hashes
- Registry paths
- Process names
- Suspicious command fragments

Every IOC should retain provenance: where it came from and which event supports it.

## 6. Findings

Separate:

- Observed facts
- Analyst assessment
- Confidence
- Remaining gaps

Avoid presenting assumptions as facts.

## 7. Response

A response plan should cover:

`Contain → Eradicate → Recover → Validate`

Document why an action was chosen and what evidence could be lost by taking it.

## 8. Reporting

A professional report should be understandable to both technical responders and management. The final report in this repository intentionally includes an executive summary followed by technical evidence.
