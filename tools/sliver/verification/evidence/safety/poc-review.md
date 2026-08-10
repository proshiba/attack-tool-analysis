# Sliver v1.7.3 pre-execution review

- Source repository: `https://github.com/BishopFox/sliver`
- Release: `https://github.com/BishopFox/sliver/releases/tag/v1.7.3`
- Release tag: `v1.7.3`
- Annotated tag object: `62619754081c1d2a199ac7f935ef30f1d48fb742`
- Source commit: `3bbaf805104dcc4a75414ee0084e8de50702cad4`
- Source archive SHA-256: `c1ea9f8b6327e2994d3cc77dc601aa0b6860c1ab492b8e024943efac594a784f`
- Server asset SHA-256: `e3216ecd12f6e7e97cb4588bb6d85c70eca3bdfad8b0818ffd53ccb2e357ccc8`
- Client asset SHA-256: `b0e328a131e4d679e9b268552db99ca2d46051b9205a67f9b7f7c1628983daae`

## Mechanical triage

`safety/poc-triage.py` was run separately against both official release
assets before either was executed. The server report is `poc-review.json`; the
client report is `client-triage/poc-review.json`. Both returned
`NEEDS-HUMAN-REVIEW`, as expected for stripped offensive-tool ELF binaries.
The scanner treated printable Go binary regions as text and reported apparent
credential, persistence, anti-analysis, encoded-data, and external-endpoint
strings. These findings are not treated as clearance and prompted the source
and static review below.

## Static and source review

On REMnux VM 105, `file`, `readelf`, `sha256sum`, and printable-string/module
inspection identified both assets as stripped, statically linked x86-64 ELF
executables. Their hashes exactly matched the copies acquired independently on
Kali and the AI VM. Embedded package strings identify the expected
`github.com/bishopfox/sliver` server/client packages; no mismatched wrapper or
second artifact was found.

The v1.7.3 source archive was read without executing its build or test code.
The review covered the generation flags, HTTP/HTTPS and mTLS listener code,
implant HTTP and mTLS transports, beacon interval/jitter loop, HTTP C2 profile,
task handlers used in the bounded flow, client update behavior, and daemon
startup. The server generates an implant containing only operator-supplied C2
URLs. HTTP requests use randomized profile paths and nonce parameters, an
embedded generated browser User-Agent, GET long polls, POST session/task
messages, and a session cookie. mTLS connects directly to the supplied host and
port and adds the `MUX/1` yamux preface after TLS establishment.

Sliver contains capabilities that are deliberately not invoked here,
including credential access, persistence, canaries, Armory/update downloads,
ACME/Let's Encrypt, pivots, injection, and destructive or lateral-movement
tasks. The client has a public GitHub release-check URL; the run sets
`SLIVER_NO_UPDATE_CHECK=1`. HTTPS starts with locally generated Sliver
certificate material and never requests ACME. Kali egress is constrained for
the execution window to loopback and `192.168.1.0/24`, providing a mechanical
backstop against an overlooked public destination.

## Network destinations and controls

- Server/client control: `127.0.0.1` on Kali only.
- Payload staging: `192.168.1.50:18080` from VM 103.
- HTTP C2: `192.168.1.50:8080` from VM 103.
- HTTPS C2: `192.168.1.50:8443` from VM 103.
- Raw mTLS C2: `192.168.1.50:31337` from VM 103.
- DNS C2: the lab-only parent `c2.sliver.lab.` was sent through VM 103's
  temporary exclusive resolver `192.168.1.50:53`; no public resolver or
  fallback was permitted.
- No public update, ACME, Armory, proxy, or alternate C2 was configured or
  permitted during execution.

## Verdict

**`safe-to-run-in-lab`**, only with the documented literal lab endpoints,
isolated state directories, update checking disabled, Kali egress restriction,
VM 103 restored to `linux_verify_baseline` before execution, and VM 103 rolled
back after collection. Execution is permitted only on Kali VM 100 and Ubuntu
VM 103; nothing runs on VM 102 or VM 108. Generated implants must be hashed,
mechanically triaged, and statically checked before VM 103 executes them.
