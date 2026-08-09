# Playbook: Verify an attack tool → Sigma (multi-signal coverage)

Audience: the lab orchestrator (Codex on the AI VM). Trigger: **"verify tool `<id>`"**.
Goal — run `<id>` in an instrumented, isolated target, capture its behavior across **five
observation dimensions**, and produce detection artifacts under `tools/<id>/verification/` such
that **many different services/EDRs can catch it** — not just one specialized signal.

## 0. Read context
- `tools/<id>/metadata.json` — `categories`, `attack_techniques`, `usage`, `detection`, `os`.
- Choose target + scenario:
  - Windows / local tools → target **VM 104** (Windows).
  - Linux tools → **VM 103** (Ubuntu) or **VM 100** (Kali).
  - Remote C2 / attacker→target → attacker = **Kali 100**, target = 104/103.
  - Dangerous / destructive / live-C2 → prefer the airgapped **vmbr2 detonation VM** (once it
    exists); until then use an existing VM you can snapshot + roll back.

## 1. Provision (clean, richly-instrumented baseline)
- Windows: **roll back to `win_verify_baseline`** first so the run starts clean (Defender off,
  verification-grade Sysmon capturing all five dimensions, C:\Tools collection toolset). If that
  baseline does not yet exist, build it per `playbooks/prepare-windows-target.md`.

## 2. Acquire + deploy the tool
- Fetch from `metadata.repository` (release/binary). Treat as untrusted. `lab-push` to the
  target's `C:\lab`. Record exact **version/commit** and SHA-256.

## 3. Run representative behavior
- Execute the characteristic commands (from `usage`) that exercise the in-scope ATT&CK techniques.
- Record **exact command lines, the UTC start/end window, and account/privilege context**. Keep
  the run bounded and reproducible.

## 4. Collect telemetry (all five dimensions)
- Windows: run `C:\Tools\collect-run.ps1 -StartUtc <start> -EndUtc <end> -OutDir <dir>` and, for
  network/C2 tools, capture pcap with `pktmon` around the run. `lab-pull` the output to the repo.
- From the captured events, extract what the tool did in EACH dimension:
  1. **Network destinations** — Sysmon EID 3 (DestinationIp/Hostname/Port) + EID 22 DNS (QueryName)
  2. **Files** created / modified / deleted — Sysmon EID 11 / 2 / 23 / 26 (+ 15 stream hash)
  3. **Registry** created / modified / deleted — Sysmon EID 12 / 13 / 14
  4. **Process image/path/command line** — Sysmon EID 1 (Image, OriginalFileName, CommandLine, Hashes)
  5. **Parent-child** — Sysmon EID 1 (ParentImage, ParentCommandLine, ParentProcessGuid)
- Save **sanitized** characteristic excerpts under `tools/<id>/verification/evidence/`.
  **Never commit harvested secrets** (dumped credentials/hashes, tokens, keys) — commit only the
  telemetry event fields a rule keys on.

## 5. Analyze → Sigma (tiered, multi-logsource)
Author Sigma so the tool is catchable across as many services as possible. **Prefer broadly-
collected fields (Tier 1); add deep Sysmon-native signals (Tier 2) only where Tier 1 does not
characterize the tool** — memory-access / DLL-load / API telemetry is absent from many services,
so it is a complement, not the primary.

- **Tier 1 (preferred — write a rule per characteristic dimension):**
  - `process_creation` — Image / OriginalFileName / path, **CommandLine**, and **parent-child**
    (ParentImage / ParentCommandLine)
  - `dns_query` + `network_connection` — destination host / IP / port, QueryName
  - `file_event` — files created / modified / deleted
  - `registry_event` / `registry_set` — keys/values created / modified / deleted
- **Tier 2 (complement / fallback):** Sysmon-native depth — `process_access` (EID 10, e.g. LSASS
  GrantedAccess masks), `image_load` (EID 7), named pipes, WMI.

Each rule: valid Sigma schema; **behavior-based** (avoid brittle hashes/paths unless the path/hash
IS the signal); `status: experimental`; correct `logsource`; `tags` = ATT&CK technique IDs;
realistic `falsepositives`; a `level`. Store all rules under `tools/<id>/verification/sigma/`.
Cross-check against metadata `detection`.

## 6. Record `verification.json`
`tools/<id>/verification/verification.json`, one entry per run:
- `environment` (target VM/OS, `baseline_snapshot`, sensors + config notes)
- `tool` (version/source/SHA-256, exact commands)
- `observed_techniques` (ATT&CK IDs actually exercised)
- `observed_signals` (what appeared in each of the five dimensions — even "none" is useful)
- `evidence` (file refs + what each shows) and `sigma` (rule refs + tier + status)
- `verified_at` (UTC), `verifier`
Add a short `tools/<id>/verification/README.md`.

## 7. Commit + PR + roll back
- Commit `tools/<id>/verification/**` on branch `feat/verify-<id>`; open a PR to `main` (use
  `~/bin/pr-create.py <owner/repo> <title> <head> main <body-file>`).
- **Roll the target back to `win_verify_baseline`** (removes the tool + its traces).

## Guardrails
- Never run the live tool on the AI VM itself — only on the isolated target.
- Snapshot before, roll back after. Document any Defender/AV changes as env setup.
- Sanitize committed evidence — no real credentials, tokens, or unrelated host data.
