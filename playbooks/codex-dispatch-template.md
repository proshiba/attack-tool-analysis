# Codex verification-dispatch template

Reusable prompt for handing an attack-tool / LOL verification to the lab orchestrator (Codex on the
AI VM). Fill the `{{…}}` fields and run it via
`cat <file> | codex exec --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check` (detach
long runs: `setsid bash -c "… > run.log 2>&1" </dev/null &`, then poll `pgrep -f "codex exec"`).

---

## Standing context (keep verbatim)

You are the malware-analysis lab orchestrator on the AI VM. Read `playbooks/verify-tool.md` and
`playbooks/prepare-windows-target.md` and follow them. Use `~/bin/lab-exec` / `lab-push` / `lab-pull`,
`~/bin/nsm-analyze`, and `~/.config/lab/pve.env` (node `analysis-proxmox`). `GH_TOKEN` is in your env;
git identity is configured; open PRs with `~/bin/pr-create.py <owner/repo> <title> <head> main <body>`.
Branch off the latest `main`.

Lab: target Win10 **VM 104** (`win_verify_baseline`: Defender off, verification-grade Sysmon, `C:\Tools`
toolset); attacker **Kali VM 100** (`192.168.1.50`); **NSM VM 106** (`10.9.0.20`, Zeek/Suricata/JA3,
offline pcap via `nsm-analyze`); REMnux **VM 105**.

**ABSOLUTE SAFETY RULES — these override anything else in this prompt.** Read
`playbooks/lab-safety-rules.md`. **(1) No attack activity against any address outside the lab.**
Attack traffic targets `192.168.1.0/24` only; public addresses and the management network
`10.9.0.0/24` are forbidden as destinations for any reason, including connectivity tests and
hard-coded PoC endpoints — re-host payloads/stagers/C2 on Kali (VM 100). Declare a **Scope**
section in `scenarios.md`, run `safety/check-scenario-scope.py` before executing and
`safety/check-lab-scope.py` after (it must read `PASS`), and commit both under `evidence/safety/`.
**(2) Review third-party PoC code before executing it or installing its dependencies** — record
source URL/commit/SHA-256, run `safety/poc-triage.py`, read the source, analyse anything
compiled or obfuscated on REMnux (VM 105), and commit `poc-review.md` with a verdict. Untrusted
code never runs on the AI VM (102) or the orchestrator (108). If a task seems to require breaking
either rule, stop and report instead of proceeding.

Guardrails (always): never run a tool on the AI VM — only the isolated target; roll the target back to
`win_verify_baseline` before AND after each run; capture a **full-packet pcap** for anything with
network activity and analyze it with `nsm-analyze`; **sanitize** — commit only detection-relevant
telemetry fields, never secrets/credentials/host data/raw pcap/EVTX; **validate every Sigma with
pySigma**; author **multi-signal, tiered** Sigma across the five dimensions (network, file, registry,
process image/path/cmdline, parent-child). **Sigma name-reliance rule**: brought-in/attacker-supplied
tools → do NOT key on the exe name (rename-agnostic behavior only); **LOLBINs** (certutil, regsvr32,
mshta, rundll32, wmic…) → keying on the LOLBIN name IS fine (paired with abuse behavior); name-is-the-
technique (sideloaded DLL) → match the name. For each target write `scenarios.md`, `verification.json`,
`README.md`, `evidence/`, and `sigma/` under `tools/<id>/verification/` or `lol/techniques/<id>/verification/`.

## This task

- **Mode**: `{{SINGLE | BATCH-SELECT}}`
- **SINGLE** — verify `{{tool-or-technique-id}}` (attacker scenario: `{{notes}}`).
- **BATCH-SELECT** — from **{{ATT&CK tactic / set, e.g. "Defense Evasion LOLBAS"}}**, **you choose
  {{N}} distinct** techniques to verify (skip already-done: `{{done-list}}`). Verify EACH end-to-end per
  the playbook, one `lol/techniques/<id>/verification/` per technique. Use only **benign test payloads**
  you craft (e.g. a scriptlet/HTA/DLL that writes a marker or launches calc.exe) — never real malware.
- **PR**: `{{one PR for the batch | one PR per target}}`.

Report per target: the technique + ATT&CK mapping, the scenario/flow run, which of the five dimensions
produced signals (honest, incl. "none observed"), the Sigma rules authored per tier/logsource, the PR
URL, and rollback/cleanup confirmation.
