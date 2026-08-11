# Sliver v1.7.3 expanded Windows-flow pre-execution review

- Source repository: `https://github.com/BishopFox/sliver`
- Release: `https://github.com/BishopFox/sliver/releases/tag/v1.7.3`
- Release tag object: `62619754081c1d2a199ac7f935ef30f1d48fb742`
- Source commit: `3bbaf805104dcc4a75414ee0084e8de50702cad4`
- GitHub API tag archive SHA-256 reviewed on 2026-08-11:
  `16d0c289049969d8e1a2331111b6fa1825a54cf57db6f18ec80819a2ae452954`
- Server asset SHA-256:
  `e3216ecd12f6e7e97cb4588bb6d85c70eca3bdfad8b0818ffd53ccb2e357ccc8`
- Client asset SHA-256:
  `b0e328a131e4d679e9b268552db99ca2d46051b9205a67f9b7f7c1628983daae`

## Mechanical triage and provenance

The acquired server and client hashes exactly match the official GitHub
release digests and the already committed `poc-review.json` and
`client-triage/poc-review.json` mechanical reports. Those `poc-triage.py`
reports were completed before the same bytes were first executed and remain
applicable by exact content hash. Both reports require human review because
the stripped Go binaries contain offensive capabilities and many embedded
strings. This expanded review does not treat a hash match or scanner result as
clearance.

The source archive was acquired without running build/test/install code. The
tag resolves through the annotated tag above to the recorded source commit.
The run does not execute source or install third-party dependencies. A newly
generated implant remains separately blocked: it must receive a fresh
`poc-triage.py` report and static PE/source-correspondence review on VM 110
before it can execute on VM 104.

## Source review for newly invoked capabilities

The earlier review excluded pivoting and injection, so the following v1.7.3
paths were read specifically for this expansion:

- `client/command/socks/commands.go`, `socks-start.go`,
  `server/rpc/rpc-socks.go`, and
  `implant/sliver/handlers/tunnel_handlers/socks_handler.go`: the client binds
  the operator-selected SOCKS listener, transports requests through the
  selected session, and the implant's embedded SOCKS server resolves/dials the
  requested destination. The run binds only `127.0.0.1:1081` and requests only
  the fixed Kali service `192.168.1.50:18084`; authentication and random
  credentials are not used.
- `client/command/exec/execute-assembly.go`,
  `server/rpc/rpc-tasks.go`, `implant/sliver/handlers/handlers_windows.go`, and
  `implant/sliver/taskrunner/task_windows.go`: the server converts an uploaded
  .NET assembly to Donut shellcode, the implant starts the selected sacrificial
  process suspended, injects the shellcode, waits for completion, collects
  stdout/stderr, and kills the sacrificial process. The run supplies the
  lab-authored stdout-only assembly, explicitly selects system `notepad.exe`,
  and does not request in-process execution, PPID spoofing, AMSI bypass, ETW
  bypass, keep-alive, or shellcode encoding.
- `client/command/jobs/commands.go`, `server/c2/http.go`, and
  `server/c2/jobs.go`: the HTTPS listener accepts operator-supplied PEM
  certificate/key bytes. ACME is reached only when `--lets-encrypt` is set;
  that flag is forbidden. The run supplies a lab root/intermediate/leaf chain
  for `c2.sliver.lab` and binds only `192.168.1.50:18443`.
- `client/command/generate/generate.go` and
  `implant/sliver/transports/httpclient/*`: the generated HTTPS URL retains the
  operator hostname and advanced options. Windows WinINet is selected
  explicitly, with `no-fallback=true`, so the run creates SNI/DNS/certificate
  telemetry and cannot fall back to clear HTTP or an alternate endpoint.

The source also confirms broader features that remain forbidden: credential
access, persistence, privilege escalation, migration into existing processes,
MSF payload generation/injection, arbitrary shellcode, reverse forwarding,
WireGuard, DNS C2, Armory/update downloads, ACME, canaries, and destructive or
self-propagating actions.

## Lab-authored artifacts

`evidence/in-memory/inert-assembly.cs` only writes the fixed string
`SLIVER_IN_MEMORY_INERT_MARKER` to captured stdout. The sideload source in
`evidence/sideload/` only creates one fixed marker from `DllMain` and returns
`E_NOTIMPL` from the single export required by baseline `WerFault.exe`.
Neither artifact contains networking, credential access, collection,
persistence, process creation, injection, or a second-stage loader. They are
reviewed source authored in this repository, not third-party PoC code.

## Network destinations and preventive controls

- Sliver server/client RPC: Kali loopback only.
- Raw mTLS C2: `192.168.1.50:31337`.
- Client-side SOCKS5: Kali loopback `127.0.0.1:1081`.
- Pivoted fixed marker service: `192.168.1.50:18084`.
- Lab DNS: `192.168.1.50:53`, authoritative/local-only for
  `c2.sliver.lab`; no forwarding.
- Named HTTPS C2: `c2.sliver.lab` resolving only to
  `192.168.1.50:18443`.
- No public update, ACME, Armory, resolver, proxy, payload, alternate C2, or
  fallback destination is configured or permitted.

Before any implant starts, VM 104's outbound firewall allows only loopback and
`192.168.1.0/24`, and Kali receives an equivalent output guard after release
acquisition. Full-packet capture plus Sysmon EID 3 is checked after the run
with `check-lab-scope.py`; any non-lab responder makes the run a failure.

## Verdict

**`safe-to-run-in-lab` for server/client setup and implant generation only**, on
Kali VM 100 with the exact reviewed hashes, isolated state, update checking
disabled, fixed endpoints, and the stated egress controls. Generated implants
are **not yet cleared to execute**: execution on VM 104 is conditional on a
new mechanical triage report, static analysis on VM 110 without execution,
hash verification after transfer, the pre-run scenario-scope gate, and VM 104
rollback to `win_verify_baseline`. Nothing may execute on VM 102, VM 108, VM
109, or VM 110. VM 104 must be rolled back again immediately after evidence
collection.
