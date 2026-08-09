# Sliver multi-signal verification

Official Sliver `v1.7.3` was verified end to end in the contained vmbr1 lab.
Kali VM 100 (`192.168.1.50`) hosted the Sliver server; Windows 10 VM 104
(`192.168.1.52`) ran a generated amd64 beacon from the clean
`win_verify_baseline` snapshot. The only implant C2 endpoint was the Kali
listener on TCP/18080.

The generated beacon SHA-256 was
`DEC80089EF9183F7E741E129D5744E7733BEE72C92E44F087C1A87F98883B622`.
It used Sliver's HTTP(S) transport with a five-second interval, zero jitter,
and the default HTTP C2 profile. Packet capture showed cleartext HTTP framing
with Sliver-encrypted application payloads; no public or external C2 endpoint
was configured.

## Feasibility and canonical flow

Before touching VM 104, Sliver's native `--rc` script mechanism successfully
started the listener and generated the Windows beacon non-interactively. The
server reported `v1.7.3`, commit
`3bbaf805104dcc4a75414ee0084e8de50702cad4`. Sliver state was isolated under
`/tmp/sliver-verification/state`; pre-existing Kali `/root/.sliver` data was
not used or removed.

After rollback, the beacon was delivered into `C:\lab` from a temporary HTTP
server bound only to Kali's lab address. This fallback was necessary because
the installed `lab-push` helper invokes `bash` in the guest, and VM 104 has no
`bash.exe`; a target hash check proved the transferred file was exact. The
temporary staging server was stopped immediately.

The beacon first contacted the listener at `2026-08-09T08:57:17Z` as
`NT AUTHORITY\SYSTEM`. The bounded operator flow then completed `whoami`,
`info`, `pwd`, `ls`, `ps`, a parser-safe `cmd.exe /c whoami`, marker creation,
and download of the fixed 28-byte marker. Several earlier `execute` attempts
used paths that Sliver's client parser normalized incorrectly; those attempts
failed harmlessly and are retained in the action record because three still
created useful implant-to-`cmd.exe` telemetry.

## Five observation dimensions

| Dimension | Result | Verified telemetry |
| --- | --- | --- |
| Network / DNS | Observed network; no implant DNS | Sysmon EID 3 recorded 213 initiated TCP connections from the implant to Kali TCP/18080. The literal-IP C2 produced zero implant EID 22 queries. Pktmon captured 1,931 filtered C2 packets over 596 seconds. |
| Files | Observed | EID 11 recorded PowerShell writing the implant, Windows creating its Prefetch file, and implant-spawned `cmd.exe` creating the marker. No related EID 23/26 was observed. |
| Registry | Observed, nonspecific | The implant emitted ten EID 12 CreateKey events under Internet Settings/Connections and TenantRestrictions/Payload. No attributed EID 13/14 occurred; the paths are too common for a useful standalone rule. |
| Process identity / command | Observed | EID 1 recorded the generated implant with absent PE identity metadata, its SHA-256, SYSTEM context, and PowerShell parent. |
| Parent-child | Observed | EID 1 recorded five direct `sliver-verify.exe` → `cmd.exe` children, including successful `whoami` and marker creation. No EID 17/18 named pipes occurred in this HTTP-beacon flow. |

The endpoint collection window was `2026-08-09T08:56:50.000Z` through
`2026-08-09T09:07:15.709Z`. Pktmon covered the C2 window from
`08:57:17.360Z` through `09:07:15.709Z`.

## Detection tiers

Tier 1 uses fields commonly normalized by endpoint products:

- `proc_creation_unversioned_executable_from_script_host.yml` detects an
  unversioned executable launched by a script/command host without relying on
  the Sliver name, path, or hash.
- `proc_creation_untrusted_parent_spawns_shell_or_lolbin.yml` detects a generic
  executable parent spawning a shell or LOLBin while filtering common
  interactive and management parents.
- `file_event_script_host_writes_executable.yml` detects script-oriented tools
  writing Windows executable payloads.
- `network_connection_non_browser_web_egress.yml` detects a non-browser
  executable initiating connections to web or alternate-web ports. It does
  not contain the lab C2 IP and should be correlated for repeated connections.

Tier 2 adds `pipe_created_executable_from_user_writable_path.yml`, a
Sysmon-native rule for a named-pipe server created by an executable in a
writable staging location. Sliver supports operator-selected named-pipe pivot
C2, so the rule does not hardcode a pipe name. It was not exercised in this
HTTP-beacon run and is a future-scenario detection.

All five rules are `experimental`, include ATT&CK tags and realistic false
positives, and parsed successfully with pySigma.

## Network visibility limitation

Endpoint EID 3 establishes which process connected where, but a single-event
Sigma rule cannot robustly model beacon periodicity or encrypted C2 semantics.
This lab should add Suricata or Zeek flow/HTTP/TLS telemetry for beacon timing,
HTTP-profile analysis, and JA3/JARM when HTTPS or mTLS is exercised. This run
used cleartext HTTP framing, so no JA3/JARM fingerprint existed; Sliver still
encrypted its application payload.

The raw pcap is deliberately not committed because it contained ephemeral C2
cookie material. `evidence/pcap-summary.json` retains only the capture hash,
5-tuple, timing, packet/request counts, and a non-secret user-agent field.
`evidence/multidimensional-signals.json` contains only sanitized Sysmon fields
used to support the findings and rules. No host file contents, tokens,
credentials, or C2 secrets are present.
