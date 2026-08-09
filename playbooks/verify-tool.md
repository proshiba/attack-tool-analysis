# Playbook: Verify an attack tool → Sigma

Audience: the lab orchestrator (Codex on the AI VM). Trigger: **"verify tool `<id>`"**.
Goal — run `<id>` in an instrumented, isolated target, capture its characteristic
telemetry, and produce detection artifacts under `tools/<id>/verification/`.

## 0. Read context
- `tools/<id>/metadata.json` — `categories`, `attack_techniques`, `usage`, `detection`, `os`.
- Choose target + scenario:
  - Windows / local tools → target **VM 104** (Windows).
  - Linux tools → **VM 103** (Ubuntu) or **VM 100** (Kali).
  - Remote C2 / attacker→target → attacker = **Kali 100**, target = 104/103.
  - Dangerous / destructive / live-C2 → prefer the **airgapped vmbr2 detonation VM**
    (once it exists); until then use an existing VM you can snapshot + roll back.

## 1. Provision (instrumented, clean baseline)
- Windows: follow `playbooks/prepare-windows-target.md` — Sysmon (+ **lsass EID 10**),
  AV handling, and a `sysmon_baseline` snapshot. If the baseline already exists, **roll
  back to it** first so the run starts clean.

## 2. Acquire + deploy the tool
- Fetch from `metadata.repository` (release/binary). Treat as untrusted.
- `lab-push` to the target's `C:\lab`. Record exact **version/commit**.

## 3. Run representative behavior
- Execute the characteristic commands (from `usage`) that exercise the in-scope ATT&CK
  techniques. Record **exact command lines, the UTC time window, and account/privilege**.
- Keep the run bounded and reproducible.

## 4. Collect telemetry
- `lab-pull` the events for the run window:
  - Sysmon `Microsoft-Windows-Sysmon/Operational` — export EVTX and/or filtered JSON;
    focus on events the tool actually produced (process create 1, image load 7,
    **process access 10**, network 3, registry, file, pipe, …).
  - Security / PowerShell-Operational logs as relevant; pcap only for network/C2 tools.
- Save **sanitized** characteristic excerpts under `tools/<id>/verification/evidence/`.

## 5. Analyze → Sigma
- Identify robust, characteristic signals (behavior over brittle IOCs like paths/hashes).
- Author Sigma rule(s) under `tools/<id>/verification/sigma/` — valid schema: `title`,
  `status: experimental`, `logsource`, `detection`, `level`, `tags` (= ATT&CK technique
  IDs), `falsepositives`. Cross-check against metadata `detection`.

## 6. Record `verification.json`
`tools/<id>/verification/verification.json`, one entry per run:
- `environment` (target VM/OS, sensors, config notes)
- `tool` (version/source, exact commands)
- `observed_techniques` (ATT&CK IDs actually exercised)
- `evidence` (file refs + what each shows)
- `sigma` (rule refs + status)
- `verified_at` (UTC), `verifier`

## 7. Commit + PR + roll back
- Commit `tools/<id>/verification/**` on branch `feat/verify-<id>`; open a PR to `main`.
- **Roll the target back to `sysmon_baseline`** (removes the tool + its traces).

## Guardrails
- Never run the live tool on the AI VM itself — only on the isolated target.
- Snapshot before, roll back after. Document any Defender/AV changes as env setup.
- Sanitize committed evidence — no real user secrets, tokens, or unrelated host data.
