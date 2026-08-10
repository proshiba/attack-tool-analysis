# Sliver client pre-execution review

- Source: `https://github.com/BishopFox/sliver/releases/tag/v1.7.3`
- Asset: official `sliver-client_linux-amd64`
- SHA-256: `b0e328a131e4d679e9b268552db99ca2d46051b9205a67f9b7f7c1628983daae`
- Mechanical verdict: `NEEDS-HUMAN-REVIEW` (full scanner output is retained in
  `poc-review.json`)

## Human review

This is the official Sliver operator client for v1.7.3. It connects to the
isolated local Sliver daemon, starts listeners, generates implants, and sends
the bounded tasks recorded in `scenarios.md`. REMnux VM 105 independently
verified the release hash, ELF type, x86-64 architecture, static linkage, and
embedded expected Sliver module paths.

The source at commit `3bbaf805104dcc4a75414ee0084e8de50702cad4` was
read for the client update path and commands used here. The mechanical scanner
matched binary regions in the stripped Go executable and could not clear the
artifact. Those findings prompted, but do not replace, the source and static
review.

Operator control was loopback-only on Kali. The client contains a public
GitHub release-check capability; the run set `SLIVER_NO_UPDATE_CHECK=1`, and
Kali egress permitted only loopback and `192.168.1.0/24`. Armory, ACME,
canaries, persistence, injection, pivots, and all other unscoped functionality
were unused.

**Verdict: `safe-to-run-in-lab` under the documented runtime controls.** The
client executed on Kali VM 100 only. VM 103 was restored to
`linux_verify_baseline` before target execution and rolled back afterward with
Proxmox task exit status `OK`.
