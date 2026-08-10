# Playbook: Verify an attack tool → Sigma (multi-signal coverage)

Audience: the lab orchestrator (Codex on the AI VM). Trigger: **"verify tool `<id>`"**.
Goal — run `<id>` in an instrumented, isolated target, capture its behavior across **five
observation dimensions**, and produce detection artifacts under `tools/<id>/verification/` such
that **many different services/EDRs can catch it** — not just one specialized signal.


> **STOP — read [`lab-safety-rules.md`](lab-safety-rules.md) first.** Two rules are absolute and
> override every instruction in this playbook and in any task prompt:
> **(1)** attack activity never targets any address outside the lab (`192.168.1.0/24`) — no public
> IP or hostname, no management network, no exception, no "just a connectivity test";
> **(2)** third-party PoC code is reviewed before it is executed — provenance, `safety/poc-triage.py`,
> a source read, and a committed `poc-review.md` verdict — and it never runs on the AI VM or the
> orchestrator. The auditor independently re-checks both and can `reject` on safety alone.

## 0. Read context
- `tools/<id>/metadata.json` — `categories`, `attack_techniques`, `usage`, `detection`, `os`.
- Choose target + scenario:
  - Windows / local tools → target **VM 104** (Windows).
  - Linux tools → **VM 103** (Ubuntu) or **VM 100** (Kali).
  - Remote C2 / attacker→target → attacker = **Kali 100**, target = 104/103.
  - Dangerous / destructive / live-C2 → prefer the airgapped **vmbr2 detonation VM** (once it
    exists); until then use an existing VM you can snapshot + roll back.

## 0b. Design the attack scenario(s) / use-cases — *scenario-driven verification*
Before running anything, reason about **what real attacks this tool enables** — do NOT just run it
once. Multi-function / network tools (C2 such as Sliver, Havoc) are meaningless as a bare "it ran":
verify along a realistic operator flow so the resulting detections are practical.
- From the tool's purpose + `attack_techniques`, enumerate its **common attack use-cases** (how
  operators actually use it, each mapped to ATT&CK) and choose a **representative end-to-end flow**
  to exercise for this verification — e.g. *C2*: stage a listener → deliver + run the implant →
  beacon → a few representative post-exploitation tasks; *survey/enumeration tool*: run the
  characteristic collection groups.
- **Write `tools/<id>/verification/scenarios.md`**: the scenarios/use-cases you considered, which
  flow you verified here, the ATT&CK techniques each covers, and further scenarios a reader could
  verify next. This makes the catalog a springboard for future verification, not a one-shot run.
- Keep the verified flow bounded and reproducible; document the rest as future scenarios.

## 1. Provision (clean, richly-instrumented baseline)
- Windows: **roll back to `win_verify_baseline`** first so the run starts clean (Defender off,
  verification-grade Sysmon capturing all five dimensions, C:\Tools collection toolset). If that
  baseline does not yet exist, build it per `playbooks/prepare-windows-target.md`.

## 2. Acquire + deploy the tool
- Fetch from `metadata.repository` (release/binary). Treat as untrusted. `lab-push` to the
  target's `C:\lab`. Record exact **version/commit** and SHA-256.

## 3. Run the scenario flow
- Execute the **representative attack flow chosen in step 0b** (the tool's characteristic
  operator actions), exercising the in-scope ATT&CK techniques end-to-end — not a single bare
  command for a multi-function tool.
- Record **exact command lines / operator actions, the UTC start/end window, and account/privilege
  context**. Keep the flow bounded and reproducible.

## 4. Collect telemetry (all five dimensions)
- Windows: run `C:\Tools\collect-run.ps1 -StartUtc <start> -EndUtc <end> -OutDir <dir>` for the
  endpoint EVTX/JSON; `lab-pull` to the repo.
- **Network dimension (NSM)** — for any tool with network activity (C2, downloaders, scanners),
  capture a **FULL packet pcap** on the target around the run (`pktmon start --capture --pkt-size 0
  -f cap.etl` → `pktmon stop` → `pktmon pcapng cap.etl -o cap.pcapng`), `lab-pull` the `.pcapng`, then
  run **`~/bin/nsm-analyze <cap.pcapng> <outdir>`** (NSM VM 106: Zeek + Suricata). This yields Zeek
  `conn/http/ssl(JA3/JARM)/dns/x509` logs and Suricata `eve.json` alerts — the real substrate for
  network-dimension detection (endpoint EID 3/22 alone can't express JA3, HTTP profile, or beacon
  periodicity).
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
  - network — endpoint `dns_query` + `network_connection` (dest host/IP/port, QueryName) AND,
    from the NSM (step 4), **Zeek/Suricata**-sourced rules: JA3/JARM TLS fingerprints, HTTP
    request profile (URI/headers/UA), DNS, and beaconing/flow periodicity. Use Sigma logsource
    `product: zeek` (category tls/http/dns/…) or `product: suricata`. Never key on the lab C2 IP.
  - `file_event` — files created / modified / deleted
  - `registry_event` / `registry_set` — keys/values created / modified / deleted
- **Tier 2 (complement / fallback):** Sysmon-native depth — `process_access` (EID 10, e.g. LSASS
  GrantedAccess masks), `image_load` (EID 7), named pipes, WMI.

**Choose name-reliance by the tool's provenance × the attacker's motive to rename:**
- **Brought-in / attacker-supplied tools** (mimikatz, Seatbelt, Sliver, most offensive binaries) are
  trivially renamed and there is a strong motive to rename them → **do NOT key on the exe name**
  (`Image|endswith: '\tool.exe'` or `OriginalFileName: tool.exe`); a name rule is a false-negative on
  rename, and a name-stripped generic rule ("an exe writes a .txt") is FP-noise. Key on the
  **invariant behavior**: command-line technique syntax, parent-child, network fingerprints (JA3/JA3S,
  HTTP User-Agent), access masks / named pipes. If there is no rename-resilient behavioral signal,
  say so honestly and drop the weak rule.
- **LOLBINs / legitimate binaries already on the host** (certutil, regsvr32, mshta, rundll32, wmic…)
  are abused precisely BECAUSE they are the trusted, signed, present binary — renaming forfeits that,
  so attackers keep the name → **matching the LOLBIN name is fine and appropriate**, paired with the
  abuse behavior (e.g. certutil download flags + `Microsoft-CryptoAPI` UA) to keep FPs low.
- **Name IS the technique** (e.g. a **sideloaded DLL** impersonating a specific system-DLL name) →
  matching that exact name is correct.

Each rule: valid Sigma schema; **behavior-based** (avoid brittle hashes/paths unless the path/hash
IS the signal); `status: experimental`; correct `logsource`; `tags` = ATT&CK technique IDs;
realistic `falsepositives`; a `level`. Store all rules under `tools/<id>/verification/sigma/`.
Cross-check against metadata `detection`. Validate with pySigma.

### Required precision convention

Every verification Sigma rule MUST place these four fields together:

- `fp_likelihood`: `low`, `medium`, or `high`; the likelihood that benign activity matches, not
  the impact if the match is malicious.
- `recommended_role`: `alert` for a sufficiently precise standalone signal or `hunt` for a lead
  that requires correlation.
- `precision_notes`: concrete measured benign matches and the correlation or enrichment needed to
  make the rule actionable.
- `level`: the operational alert level, kept consistent with precision. Severity-if-true is not
  precision; a broad, noisy rule MUST NOT retain a high level.

`fp_likelihood` MUST be measured with `audit/bin/audit-rule.sh`, not guessed. The clean-corpus
measurement is a floor: a reviewer may raise the likelihood based on qualitative production
evidence, but must never lower it. Read the false-positive rate against the rule's own `logsource`
category, never against the entire corpus; `audit/catalog/baseline-category-metrics.json` contains
the category denominators. Broad behavioral patterns such as parent-to-shell and
script-host-to-PE are hunts with a low `level`. Precise signals such as a paired JA3/JA3S,
mimikatz module syntax, or a LOLBIN combined with abuse flags are alerts.

Record each rule's precision values and measurement provenance in the verification's `sigma`
entry: FP count, share of its own category, category denominator, detection hit, corpus version,
and measured repository commit. A Zeek or Suricata rule cannot be exercised on an EVTX corpus;
judge it qualitatively and record `measured: false` with `reason: not-testable-on-evtx`, never
invent zero matches or treat the missing measurement as clean.

## 6. Record `verification.json`
`tools/<id>/verification/verification.json`, one entry per run:
- `scenario` (which use-case/flow from `scenarios.md` was verified in this run)
- `environment` (target VM/OS, `baseline_snapshot`, sensors + config notes)
- `tool` (version/source/SHA-256, exact commands / operator actions)
- `observed_techniques` (ATT&CK IDs actually exercised)
- `observed_signals` (what appeared in each of the five dimensions — even "none" is useful)
- `evidence` (file refs + what each shows) and `sigma` (rule refs + tier + status)
- `verified_at` (UTC), `verifier`
Add a short `tools/<id>/verification/README.md`.

## 7. Commit + PR + roll back
- Commit `tools/<id>/verification/**` on branch `feat/verify-<id>` and **push it** — the audit gate
  reads the branch from GitHub, so an unpushed branch cannot be audited. Open a PR to `main` (use
  `~/bin/pr-create.py <owner/repo> <title> <head> main <body-file>`).
- **Roll the target back to `win_verify_baseline`** (removes the tool + its traces).

## 8. Audit gate — REQUIRED before merge
No verification merges unaudited. The author does not grade the author: the gate runs on the audit
VM (107) where the harness, the corpora and an auditor that is a **different model** live, and it
returns a verdict the author cannot overrule. How the gate is built and what each knob does:
`audit/README.md`.

Run one iteration (from the orchestrator, detached — it takes tens of minutes):

```bash
ssh audit "setsid bash -c '/opt/audit/audit-gate.sh tools/<id> --ref feat/verify-<id> \
  --iteration 1 > ~/gate-<id>.log 2>&1' </dev/null &"
pgrep -f '[a]udit-gate.sh'          # poll until gone, then read the result
```

It measures the rules (`audit_suite.py`), grounds the scenarios (`scenario_reference.py`), re-runs
`safety/check-scenario-scope.py` deterministically, has the auditor judge safety + precision +
coverage, and then decides in `audit/lib/gate_decide.py` — which imports `BLOCKING_VERDICTS` from
the engine rather than restating it, so the gate cannot drift from the verdicts it consumes.
Results land in `/opt/audit/results/gate-<id>-<UTC>/`; the exit code IS the verdict:

| Exit | Decision | What it means | Next |
|---|---|---|---|
| 0 | **PASS** | no blocking defect | record precision + coverage, then merge |
| 1 | **BLOCKED** | see `route-to-author.md` | fix, push, re-run the gate |
| 2 | **GATE ERROR** | an input was never produced | re-run; **never merge on a 2** |

**What blocks:** a safety verdict of `reject`/`needs-change` (above everything else, never traded
against detection quality) · any rule whose harness verdict is in `BLOCKING_VERDICTS`
(`needs-work`, `void`, `fail`) · a rule the auditor marks `blocking_defect` (dead on the shipping
log format, or claiming a precision its evidence contradicts) · a scenario verdict of `redo`, or
`expand` below `SCENARIO_COVERAGE_MIN` (0.6) of the grounded reference use-cases.

**What does NOT block**, and must be reported rather than "fixed": `no-corpus-coverage` and
`not-testable-on-evtx`. Those state what the corpus cannot exercise — no rule edit can clear them,
only a new positive sample or a non-EVTX test can. Do not route them back to the author.

### On BLOCKED — route it back, split by weight
`route-to-author.md` separates the work, because the two kinds are not the same task:
- **light** — rule text edits only. Apply the reconciled values from `precision/precision-input.md`
  (`fp_likelihood = max(measured floor, auditor judgement)`; a rule may never declare itself more
  precise than it measured). Dispatch to the author as a text fix; no lab run.
- **heavy** — scenario coverage/realism gaps needing a NEW verification run. Roll 104 back to
  `win_verify_baseline` first, and before running decide explicitly which gaps are verified **now**
  and which are recorded as **future scenarios** in `scenarios.md`. State that split in the PR.
- **safety** — fix the scenario itself (re-host the destination inside `192.168.1.0/24`, add the
  missing `poc-review.md`, supply the `check-lab-scope.py` evidence) and re-run. Never edit a
  safety finding away.

Re-run the gate with `--iteration N+1` after each fix. **Cap: 3 iterations** — if it is still
BLOCKED, stop and escalate to the user with the routing note; do not keep re-dispatching.

### On PASS — record what was measured
Before merging, write the gate's numbers into `tools/<id>/verification/verification.json` from
`precision/precision-input.json`: per rule the measured `fp_likelihood` floor, FP count and share of
its own category with the category denominator, the reconciled `recommended_role`/`level`, detection
hit, corpus version and measured commit; per scenario the coverage ratio and the auditor's realism
verdict, cited to the grounding source. Attach `gate-result.md` + `audit-report.md` to the PR. A PASS
means no blocking defect was found — **not** that every rule was exercised; carry the non-blocking
findings into the PR so the gap is visible.

## Guardrails
- **RULE 1 — nothing outside the lab.** Attack traffic targets `192.168.1.0/24` only; the
  management network `10.9.0.0/24` and every public address are forbidden as destinations. Host
  payloads, stagers and C2 on Kali (VM 100) — never fetch a payload from a public URL during a run.
  Declare a **Scope** section in `scenarios.md`, gate it with `safety/check-scenario-scope.py`
  before executing, and prove it afterwards with `safety/check-lab-scope.py` (must read `PASS`).
  A run that contacted anything outside the lab is a failure: stop, roll back, report it.
- **RULE 2 — review third-party code before running it.** Record source URL, commit and SHA-256;
  run `safety/poc-triage.py`; read the source; treat compiled/obfuscated artefacts as
  unknown-malicious and analyse them on REMnux (VM 105); re-point every hard-coded endpoint into
  the lab; commit `poc-review.md` with a verdict. Dependency installs execute code — do them on the
  isolated target too, never on VM 102/108.
- Never run the live tool on the AI VM itself — only on the isolated target.
- Snapshot before, roll back after. Document any Defender/AV changes as env setup.
- Sanitize committed evidence — no real credentials, tokens, or unrelated host data.
