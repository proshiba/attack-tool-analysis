# `safety/` — mechanical gates for the absolute lab rules

The rules themselves are in [`playbooks/lab-safety-rules.md`](../playbooks/lab-safety-rules.md).
These scripts exist so that compliance is *proved* rather than asserted, and so the proof is an
artefact an independent auditor can re-run instead of trusting a claim.

| Script | Rule | When | Blocks on |
|---|---|---|---|
| `check-scenario-scope.py` | 1 | scenario written, before any execution | non-lab IP named in the scenario; missing Scope declaration |
| `poc-triage.py` | 2 | before any third-party code or its dependencies are run | credential access, second-stage download, install hooks, embedded executables, hard-coded public endpoints |
| `check-lab-scope.py` | 1 | after the run, before evidence is sanitised | any connection or DNS query that left the lab |

All three exit non-zero when they block, so they can be used directly as gates.

```bash
# design time
safety/check-scenario-scope.py lol/techniques/<id>/verification --out evidence/safety/scenario-scope.json

# before running third-party code
safety/poc-triage.py ~/poc/CVE-2026-XXXX --out evidence/safety --source-url https://github.com/…

# after the run (Sysmon EID 3 is what attributes a destination to a process - always supply it)
safety/check-lab-scope.py --zeek-dir ~/nsm-out --sysmon-json ~/events.json --out evidence/safety/lab-scope.json
```

## What these scripts are not

`poc-triage.py` does not clear code. A pattern scanner cannot decide that unfamiliar code is
benign — it can only guarantee that the obvious traps are never missed. Read the source; treat
compiled, packed or obfuscated artefacts as unknown-malicious and analyse them on REMnux (VM 105).

`check-lab-scope.py` is evidence of what *did* happen, not a preventive control. The preventive
control is the scenario design plus the network layout; this proves the design held.

`check-scenario-scope.py` reads the written scenario, so it catches an intent to touch an outside
host — not an accident at runtime. That is what the post-run check is for.

## Allowed ranges

Attack traffic: `192.168.1.0/24` only. The management network `10.9.0.0/24` (Proxmox `10.9.0.1`,
AI VM 102, orchestrator 108) is never a legitimate attack destination and is treated as a
violation despite being private. Override with `--allow` only to *narrow*, never to add a
public range.
