# Sliver verification scenarios

Sliver is a multi-protocol command-and-control framework, so a useful
verification follows an operator workflow rather than treating successful
startup as sufficient evidence. All scenarios below assume an authorized,
isolated lab and a C2 endpoint controlled by the analyst.

## Verified flow: bounded HTTP C2 foothold and host survey

This run uses Kali VM 100 (`192.168.1.50`) as the Sliver server and Windows 10
VM 104 (`192.168.1.52`) as the implant host. The generated Windows amd64
implant is configured with the sole C2 endpoint
`http://192.168.1.50:18080`. No redirector, public listener, DNS C2, or other
external endpoint is configured.

The bounded flow is:

1. Start an HTTP listener on Kali, generate a beacon-mode Windows implant,
   transfer it from the contained Kali host into `C:\lab`, and execute it on the target
   (**T1071.001 — Application Layer Protocol: Web Protocols**, **T1105 —
   Ingress Tool Transfer**).
2. Confirm the target's C2 session on the Sliver server
   (**T1071.001**, **T1573.002 — Encrypted Channel: Asymmetric Cryptography**).
3. Run `whoami`, `info`, `pwd`, `ls`, and `ps` to exercise account, system,
   file/directory, and process discovery (**T1033**, **T1082**, **T1083**,
   **T1057**).
4. Run one benign `cmd.exe /c` command which writes a marker containing no
   host data (**T1059.003 — Windows Command Shell**).
5. Download that small marker through the established C2 channel
   (**T1041 — Exfiltration Over C2 Channel**). The marker is used only to
   prove file transfer and contains no secret or host-derived content.

This flow deliberately excludes credential access, persistence, process
injection, lateral movement, pivoting, and execution of third-party payloads.

## Additional realistic scenarios (not executed)

- **Initial foothold and alternate transports:** exercise HTTPS, mTLS, or DNS
  implants and staged delivery; map to T1071.001/T1071.004, T1573.002, and
  T1105. Each transport needs its own network baseline and capture.
- **Host and Active Directory reconnaissance:** enumerate users, groups,
  domain trusts, network configuration, services, shares, and sessions; map to
  T1087.001/T1087.002, T1069.001/T1069.002, T1482, T1016, T1007, T1135,
  and T1049.
- **Credential and loot collection:** validate approved credential-access
  extensions and collection of test-only files; map to T1003, T1555, T1005,
  T1074.001, and T1041. Never retain harvested secrets in evidence.
- **Lateral movement and pivoting:** test SOCKS, TCP pivots, named-pipe pivots,
  remote-service execution, and tool transfer between disposable targets; map
  to T1572, T1090, T1021, and T1570.
- **In-memory execution:** exercise `execute-assembly`, BOF/COFF execution, and
  sacrificial-process behavior with inert test assemblies; map observed
  injection and interpreter behavior to T1055 and T1059 only when telemetry
  proves those techniques.
- **File transfer:** test upload and download size ranges and server-to-host
  staging across each transport; map to T1105, T1570, and T1041 as applicable.
- **Persistence:** in an isolated rollback-only run, exercise one persistence
  mechanism at a time (for example a scheduled task, service, or Run key) and
  map to T1053.005, T1543.003, or T1547.001 based on the mechanism.

Each future scenario should start from `win_verify_baseline`, use a narrow UTC
window, collect all five endpoint dimensions plus packet data, and commit only
sanitized detection-relevant telemetry.
