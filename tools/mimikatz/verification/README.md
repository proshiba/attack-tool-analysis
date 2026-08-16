# mimikatz multi-signal verification

Official mimikatz `2.2.0-20220919` was measured on VM 104
(`WIN10-ANALYSIS`, Windows 10 Enterprise LTSC build 19044) from the
`win_verify_baseline` snapshot. Sysmon 15.21 was running the verification-grade
configuration that collects unfiltered process, network, DNS, file, and
registry telemetry plus focused LSASS ProcessAccess events. The configuration
SHA-256 was
`5435642464A05B06B0AAD58C04E682336D0FBAA05786179FCA9292EAEA4F6D71`.
Defender real-time and behavior monitoring were off.

## Historical disk observation

The x64 binary reported `OriginalFileName=mimikatz.exe`, version `2.2.0.0`, and
SHA-256
`61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1`.
It was executed from `C:\lab` as `NT AUTHORITY\SYSTEM` at System integrity:

```text
mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
```

The bounded invocation ran from `2026-08-09T06:47:26.1701945Z` through
`2026-08-09T06:47:26.2598068Z` and exited with code 0. The telemetry collection
window was `2026-08-09T06:47:25.170Z` through
`2026-08-09T06:47:28.259Z`.

This run predates the mandatory post-run `check-lab-scope.py` artifact. Its
sanitized telemetry is retained as historical context, but it is withdrawn as
current execution/safety proof. Current verification rests on the two
2026-08-16 in-memory runs, both of which have attributed full-pcap PASS reports.

## Historical five observation dimensions

| Dimension | Result | Verified telemetry |
| --- | --- | --- |
| Network / DNS | None observed | No Sysmon EID 3 or EID 22 occurred in the window. |
| Files | Observed, indirect | Windows replaced `C:\Windows\Prefetch\MIMIKATZ.EXE-A381AD0F.pf`: EID 23 then EID 11 from `svchost.exe`. No direct mimikatz file write was observed. |
| Registry | None observed | EID 12/13 background activity existed, but none was attributed to the mimikatz ProcessGuid or image; EID 14 count was zero. |
| Process identity / command | Observed | EID 1 recorded the image, path, `OriginalFileName`, hashes, and the `privilege::debug sekurlsa::logonpasswords exit` command. |
| Parent-child | Observed | EID 1 recorded PowerShell (PID 1224) launching mimikatz (PID 4452), both as SYSTEM. |

Separately, the Tier 2 sensor recorded Sysmon EID 10 when mimikatz opened
`lsass.exe` with `GrantedAccess=0x1010`, which includes `PROCESS_VM_READ`.

## Detection model

Tier 1 favors fields normalized by many endpoint products:

- `proc_creation_mimikatz_cmdline.yml` is the primary rule. It detects
  characteristic `module::command` tokens such as `sekurlsa::`, `lsadump::`,
  and `privilege::debug` in any process command line. It does not use the image
  or original filename, so executable renaming does not bypass it. Parent
  process context remains useful triage enrichment but is not required.

Tier 2 complements those portable rules with the deeper Sysmon-native
`process_access_lsass_read.yml`, which detects the measured `0x1010`/`4112`
memory-read access from a user-writable staging root without depending on a
mimikatz name, command line, or hash. The rule accepts both sensor value
representations and has no `service: sysmon` mapping defect.

The former Prefetch rule was removed because the `MIMIKATZ.EXE-*.pf` artifact
changes when the attacker renames the executable and is therefore not a robust
detection signal.

No registry, file, or network rule is retained because the canonical run did
not produce a rename-resilient, distinctive signal in those dimensions. This
avoids rules based on unobserved behavior or attacker-controlled filenames.

## In-memory closure (2026-08-16)

The same approved binary hash was converted to Donut shellcode and executed
inside a lab-authored ProgramData host, with no Mimikatz executable on VM 104.
The host exited 0 and produced one LSASS EID 10 with access `0x1010`.

This measured the known structural blind spot: `proc_creation_mimikatz_cmdline.yml`
stayed silent because no EID 1 contained `sekurlsa::`, `privilege::debug`, or
another module token. `process_access_lsass_read.yml` replaced it for this run
and matched the unusual source opening LSASS. `mscoree.dll` loaded, but
`clr.dll`, `amsi.dll`, EID 8, EID 25, attributed pipes, and attributed network
did not. The absence of those optional signals is part of the result.

The repaired ProcessAccess rule measured 0 / 1,619,360 clean process-access
events and hit the public positive corpus. It remains medium-likelihood,
hunt/medium because legitimate security tools can also run from writable roots.

## In-memory SAM and LSA Secrets expansion

A second bounded run changed only Donut's clear argument field and executed
`lsadump::sam` plus `lsadump::secrets` in `CredentialManager.exe` under
ProgramData. Target-side reduction recorded three SAM success markers, five
Secrets success markers, and zero module errors. The transient output was
deleted before evidence packaging and was never pulled or human-viewed.

This run also left the command-line rule silent when evaluated with its actual
module tokens. It produced no host-to-LSASS EID 10, an expected distinction for
the registry-backed stores. Its post-run scope check returned PASS after reading
41 EID 3 and 19 EID 22 events, with zero attack-attributed violations. VM 104
was rolled back before and after the run.

## Evidence and sanitization

`evidence/multidimensional-signals.json` and
`evidence/sysmon-eid10-lsass-process-access.json` are historical telemetry from
the ungated 2026-08-09 run and are not current safety proof. No credential
material, hashes harvested from LSASS, or raw security log is committed.

`evidence/in-memory-donut-execution.json` contains the sanitized in-memory
closure measurement. The raw pcap, EVTX, opaque shellcode, loader, and any
native output remain outside the repository.

`evidence/in-memory-sam-secrets.json` and its linked safety report contain only
derived counts. Donut's PoC-review and Run C scope proof are cross-linked from
the Mimikatz evidence so the third-party and post-run gates are discoverable
from this verification directory.
