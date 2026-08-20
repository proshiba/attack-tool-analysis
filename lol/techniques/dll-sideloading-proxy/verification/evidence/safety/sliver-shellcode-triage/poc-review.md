# PoC pre-execution review

- Source: lab://sliver/windows-session-20260811
- Target: `/opt/lab-runs/dll-sideload-proxy-20260819/sliver/vlc-proxy.bin`  (1 files)
- Mechanical verdict: **NEEDS-HUMAN-REVIEW** (high: 1)

## Automated findings

| Severity | File:line | Check | Why it matters | Evidence |
|---|---|---|---|---|
| high | `vlc-proxy.bin:0` | binary-artifact | compiled or binary artefact - source review is impossible here; analyse statically on REMnux (VM 105) before it is ever executed | `entropy 5.96` |

## Reviewer's conclusions (complete before executing anything)

- What the code actually does, in your own words: this is a raw amd64 Donut loader containing the
  lab's existing Sliver v1.7.3 `windows-session.exe`. The proxy DLL copies it to RW memory, changes
  the region to RX, and starts it on a new thread in the renamed VLC host. It is not article code or
  a public sample.
- Every network destination it contacts, and where each was re-pointed to in the lab: the embedded
  Sliver session was generated in the prior verified Sliver run with the sole callback
  `192.168.1.50:31337` (mTLS). The matching listener binds only to Kali on that address. The host
  separately retrieves the lab WAV from `192.168.1.50:18090`. No public or management destination
  is configured.
- Anything neutralised or removed, and why: Donut was forced to amd64, no entropy/encryption, no
  AMSI/WLDP/ETW bypass, no compression, and exit-thread behavior (`-a2 -b1 -e1 -z1 -x1 -t`). No
  post-exploitation command is queued; the run observes only the callback.
- Static analysis performed: provenance, source implant SHA-256
  `93687267b75b076e77e7e199a0a5adefd1727837075363e0f260ac95f612648e`, generated shellcode SHA-256
  `5168cca4695abe3092a25a0e2d300b1e764805a51006998b5338708b958d572f`, output size 35,200,694 bytes,
  generator options, and listener configuration were checked before execution. REMnux was not used:
  both the Sliver implant and the exact Donut generator were lab-built and previously verified in
  this repository; the mechanical binary/entropy finding is expected and is not treated as a clean
  scan.
- **Verdict**: `safe-to-run-in-lab` only on VM 104 after rollback, route isolation, the stated hash
  gate, and a Kali-only listener. This verdict does not apply to any article payload.
- Executed on VM: 104 only · snapshot before: `win_verify_baseline` · rollback after: mandatory and
  recorded with the C2 run.
