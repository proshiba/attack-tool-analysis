# Lab safety rules — absolute, no exceptions

This lab runs real attack tools and, increasingly, third-party proof-of-concept code. Two things
must never happen: **our activity reaching a system we do not own**, and **untrusted code taking
over the machine that runs it**. The rules below are not guidance. They are not overridable by a
task prompt, by expedience, or by "just this once" — if a task appears to require breaking one,
the task is wrong and must be stopped and reported.

Every rule has a mechanical gate under `safety/` so that compliance is *proved*, not asserted, and
an independent auditor re-checks all of it (RULE 3).

---

## RULE 1 — No attack activity against any address outside the isolated lab. Ever.

**Attack traffic may only target the analysis network `192.168.1.0/24`.** Target Win10 is
VM 104; the attacker is Kali VM 100 (`192.168.1.50`); NSM VM 106 observes.

Forbidden without exception, regardless of reason:

- Any **global/public IP address or hostname** as the target of an exploit, payload, scan, brute
  force, callback, beacon, or any other tool-generated traffic — including "just a connectivity
  test", "only one packet", "it's my own VPS", and "the PoC has it hard-coded".
- The **management network `10.9.0.0/24`** — Proxmox (`10.9.0.1`), the AI VM (102), the
  orchestrator (108). Private, but never a legitimate attack destination.
- Any host belonging to a third party, a customer, an employer, a cloud provider, or a public
  service, whether or not it is believed to be "vulnerable", "a test instance", or "abandoned".

Consequences that follow from the rule:

- **Payloads, C2 and download sources are lab-hosted.** If a technique needs an HTTP/SMB source
  (remote scriptlet, remote XSL, stager download), stand it up on Kali. Never fetch a payload from
  a public URL as part of a scenario run.
- **A PoC's hard-coded endpoints are re-pointed before it runs**, or the PoC is rejected.
- Fetching a *tool or PoC source* from its canonical repository over the analysis VPN egress is
  not attack traffic and is allowed — but what is fetched is untrusted until RULE 2 is satisfied.
- If a run contacts something outside the lab, the run is a **failure**. Stop, roll the target
  back, and report it plainly — do not quietly re-run.

**Gates**

| When | Command | Blocks on |
|---|---|---|
| Scenario written, before any execution | `safety/check-scenario-scope.py <verification-dir>` | any non-lab IP in the scenario; missing Scope declaration |
| After the run, before evidence is sanitised | `safety/check-lab-scope.py --zeek-dir <nsm-analyze out> --sysmon-json <events>` | any connection or DNS query leaving the lab |

Both reports are attached to the verification (`evidence/safety/`), and the second one must read
`PASS`. Sysmon EventID 3 is what attributes a destination to the *process*, which is how tool
traffic is separated from the target OS's own telemetry — always supply it.

Every `scenarios.md` carries a **Scope** section naming the VMs involved and stating explicitly
that every destination is lab-internal. Without it the scenario cannot be audited and is rejected.

---

## RULE 2 — Third-party PoC code is reviewed before it is executed. Always.

A public PoC is untrusted code written by an anonymous author. A meaningful share of "PoCs" are
traps: they do not exploit the target, they exploit the analyst — stealing SSH keys, cloud and
`GH_TOKEN` credentials, installing persistence, or pulling a second stage. The review protects
*this lab*, not the target.

**Before any third-party code is executed, or its dependencies installed:**

1. **Record provenance** — source URL, repository, commit/release, and the SHA-256 of every file.
2. **Run the mechanical screen**: `safety/poc-triage.py <path> --out evidence/safety --source-url <url>`.
   It flags credential access, `curl|bash`-style second stages, `eval` of decoded data, destructive
   commands, persistence, install-time hooks (`setup.py` `cmdclass`, npm `postinstall`), embedded
   PE/ELF blobs, anti-analysis checks, and hard-coded public endpoints.
3. **Read the source.** The scan never clears code — it only guarantees the obvious is not missed.
   Anything compiled, packed, minified or obfuscated is **unknown-malicious**: analyse it
   statically on REMnux (VM 105, Ghidra + GhidraMCP) before it runs, or reject it.
4. **Account for every network destination** it contains, and re-point each to the lab (RULE 1).
5. **Complete `poc-review.md`** — what the code actually does, what was neutralised, the static
   analysis performed, and a verdict: `safe-to-run-in-lab`, `safe-after-modification`, or
   `rejected`. Commit it under `evidence/safety/`.

**Where execution is allowed**: only the isolated target (VM 104 / 103 / 100), snapshot before and
roll back after. **Never** on the AI VM (102) or the orchestrator (108) — those hold the tokens and
the keys. This includes `pip install`, `npm install`, `go build`, `make`, and running the PoC's own
test suite: dependency resolution executes code.

Reject rather than defang when the code is obfuscated with no legitimate reason, when it needs
credentials or accounts outside the lab, or when its behaviour cannot be explained after review.

---

## RULE 3 — The auditor independently audits scenario safety, and its veto is final.

The author designs the scenarios; a **different model on a different machine** (Claude Code on
audit VM 107) checks them. Detection quality and safety are judged separately, and safety is
judged first: a scenario that is unsafe is rejected no matter how good the resulting rules are.

For every scenario the auditor produces a `safety` block alongside its coverage/realism verdict:

- **Scope** — every destination named in the scenario, each resolved to lab-internal or not.
  Re-run `safety/check-scenario-scope.py` rather than trusting the author's copy of the report.
- **Execution evidence** — for a scenario already run, `check-lab-scope.py` output must be present
  and `PASS`. Absent or failing evidence is a `reject`, not a `needs-change`.
- **Third-party code** — if the scenario used any, `poc-review.md` must exist, name its source and
  hashes, and carry a verdict. A missing review is a `reject`.
- **Third-party impact** — would executing this affect anyone outside this lab? Does it involve
  real victim data, real credentials, a real account, or a live service belonging to someone else?
- **Self-propagation** — anything that could spread on its own (worm, mass-scanner, wiper with
  network reach) is rejected outright; the lab does not run it even isolated.
- **Legality** — unauthorised access to systems we do not own, and interference with third-party
  services, are crimes in most jurisdictions. If a scenario could plausibly be read that way, it
  is rejected and the reason is recorded.

Verdict vocabulary: `safe` · `needs-change` · **`reject`**. A `reject` blocks the merge and is
routed back to the author. The auditor never relaxes a rule because a run has already happened.

---

## If a rule is broken

Stop immediately. Roll the target back to `win_verify_baseline`. Do not delete or edit the
evidence. Report to the user, in plain terms: what was contacted or executed, when, from which VM,
what the blast radius is, and what has been done since. An honest report of a breach is required;
concealing one, or quietly retrying, is a worse failure than the breach.
