# Certutil decode verification

This verification exercised **Deobfuscate/Decode Files or Information
(T1140)** with the Microsoft-signed `certutil.exe`. A 114-byte PEM-style
base64 fixture decoded into a 42-byte inert text marker. Certutil explicitly
reported successful completion, and the output SHA-256
`86A73E8A9B12F966B4D79FE8FF62D62034E0BCB97C4D06613AF18E08DCEA74F1`
matched the expected plaintext bytes.

Sysmon recorded the process lifetime as
`2026-08-10T01:42:11.656Z`–`2026-08-10T01:42:11.706Z` under
`NT AUTHORITY\SYSTEM`. The numeric exit property was not retained after a
post-run reporting-wrapper error, so `verification.json` records it as null
rather than guessing; certutil's success text, the output file, and its matching
hash establish the result.

## Five-dimension result

| Dimension | Result |
|---|---|
| Network | None: no Sysmon EID 3 or EID 22. This was a local-only flow, so no packet capture was required. |
| Files | Observed: certutil-attributed EID 11 for the decoded 42-byte output. |
| Registry | Observed: three EID 12 and three EID 13 cryptography OID initialization records; legitimate and not decode-specific enough for a rule. |
| Process | Observed: EID 1 captured certutil, `-decode`, both paths, hashes, user, and integrity. |
| Parent-child | Observed: controlled PowerShell→certutil ancestry; only normal `conhost.exe` below certutil, and no decoded content execution. |

## Sigma coverage

| Tier | Logsource | Rule |
|---|---|---|
| 1 | `windows/process_creation` | `win_process_creation_certutil_decode.yml` |
| 1 | `windows/sysmon/file_event` | `win_file_event_certutil_suspicious_output.yml` |

The process rule is the primary technique signal. The file rule is deliberately
low severity because file-event telemetry cannot see `-decode`; it should be
correlated with the process event. No Tier 2 registry rule was emitted because
the observed OID writes were generic certutil initialization rather than a
decode invariant. Both rules parsed successfully with pySigma 1.5.0.

Raw EVTX and combined events remain outside the repository. VM 104 was rolled
back to `win_verify_baseline`; the input, output, and telemetry directory were
absent, and final batch validation found Sysmon running with the expected
configuration and Defender real-time protection off.
