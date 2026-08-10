#!/usr/bin/env python3
"""Decide one audit-gate iteration: does this verification merge, or go back to the author?

The gate has two inputs that are deliberately produced by different things:

* `suite-summary.json` - what the harness MEASURED. Deterministic, reproducible, and the
  authority on whether a rule is broken. `audit_engine.BLOCKING_VERDICTS` is imported here
  rather than restated, so the gate can never drift from the engine that assigns verdicts.
* `audit-report.json` - what the independent auditor (a different model, on this VM) JUDGED:
  scenario safety, coverage against real-world grounding, and precision in production.

This script only combines them. It makes no judgement of its own and asks no model anything;
given the same two files it always returns the same verdict. What it adds is the routing:
a blocked gate is split into work that is a text edit to a rule (light) and work that needs a
new lab run (heavy), because those go back to the author as very different tasks.

    gate_decide.py <gate-outdir> [--verification tools/sliver] [--iteration 1]

Reads `<gate-outdir>/harness/suite-summary.json`, `<gate-outdir>/auditor/audit-report.json`
and `<gate-outdir>/safety/scope-check.json`; writes `gate-result.json`, `gate-result.md` and,
when blocked, `route-to-author.md`. Exit code 0 = PASS, 1 = BLOCKED, 2 = gate error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

AUDIT_HOME = Path(os.getenv("AUDIT_HOME", "/opt/audit"))
sys.path.insert(0, str(AUDIT_HOME / "lib"))

try:
    from audit_engine import BLOCKING_VERDICTS  # the single definition of "this blocks a merge"
except ImportError:  # pragma: no cover - the gate must not silently invent its own policy
    print("FATAL: cannot import BLOCKING_VERDICTS from audit_engine; is AUDIT_HOME correct?",
          file=sys.stderr)
    raise SystemExit(2)

SCHEMA_VERSION = 1

# A scenario the auditor marked `expand` blocks only below this coverage of the grounded
# reference use-cases; above it, the gap is recorded as future scenarios instead of holding
# the merge. `redo` always blocks, at any coverage.
SCENARIO_COVERAGE_MIN = float(os.getenv("SCENARIO_COVERAGE_MIN", "0.6"))

LIGHT = "light"   # a text edit to a rule or to scenarios.md - no lab run
HEAVY = "heavy"   # needs the target rolled back and a new verification run
SAFETY = "safety"  # blocks regardless of detection quality, and is never traded away


def read_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"WARNING: {path} is not valid JSON ({exc})", file=sys.stderr)
        return None


def coverage_fraction(value) -> float | None:
    """Accept 0.43, "3/7", "43%", "43" - or the prose an auditor actually writes.

    Real reports read like `"1/8 ATT&CK techniques verified (12.5%); 6/8 counting future
    scenarios"`. Only the LEADING figure is taken: it is what this verification covers today,
    and a coverage number that counts work not yet done is not coverage. Unparseable returns
    None, and the caller treats that as blocking - a gate may not fail open on a number it
    could not read.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) / 100.0 if float(value) > 1.0 else float(value)
    text = str(value).strip()
    ratio = re.search(r"(\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)", text)
    if ratio:
        denominator = float(ratio.group(2))
        return float(ratio.group(1)) / denominator if denominator else None
    percent = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
    if percent:
        return float(percent.group(1)) / 100.0
    try:
        number = float(text)
    except ValueError:
        return None
    return number / 100.0 if number > 1.0 else number


def blocker(kind: str, weight: str, subject: str, detail: str) -> dict:
    return {"kind": kind, "weight": weight, "subject": subject, "detail": detail}


def collect(gate_dir: Path, verification: str | None) -> dict:
    suite = read_json(gate_dir / "harness" / "suite-summary.json")
    report = read_json(gate_dir / "auditor" / "audit-report.json")
    scope = read_json(gate_dir / "safety" / "scope-check.json")

    errors, blockers, findings = [], [], []

    if suite is None:
        errors.append("harness/suite-summary.json is missing or unreadable - the rules were "
                      "never measured, so nothing can be concluded about them")
    if report is None:
        errors.append("auditor/audit-report.json is missing or unreadable - the auditor did not "
                      "produce a verdict; re-run the gate rather than merging unaudited")

    # --- safety, first and vetoing -------------------------------------------------
    if scope is not None and scope.get("exit_code") not in (0, None):
        blockers.append(blocker(
            "safety-scope-check", SAFETY, scope.get("target", verification or "?"),
            f"safety/check-scenario-scope.py exited {scope['exit_code']}: the scenario names a "
            f"destination outside the lab, or carries no Scope declaration. "
            f"See safety/scope-check.txt."))

    if report is not None and not report.get("safety"):
        blockers.append(blocker(
            "safety-not-audited", SAFETY, verification or "?",
            "the audit report carries no `safety` section, so the scenario's safety was never "
            "judged. An unaudited scenario is blocked - absence of a finding is not a pass."))

    for entry in (report or {}).get("safety", []):
        verdict = str(entry.get("verdict", "")).lower()
        if verdict in {"reject", "needs-change"}:
            blockers.append(blocker(
                f"safety-{verdict}", SAFETY, entry.get("id", verification or "?"),
                json.dumps({k: v for k, v in entry.items() if k != "id"}, ensure_ascii=False)))
        elif verdict != "safe":
            blockers.append(blocker(
                "safety-verdict-unreadable", SAFETY, entry.get("id", verification or "?"),
                f"safety verdict `{entry.get('verdict')}` is not one of safe|needs-change|reject"))

    # --- rules: measured defects, then judged ones ---------------------------------
    for rule in (suite or {}).get("rules", []):
        if rule.get("blocking"):
            blockers.append(blocker(
                "rule-verdict", LIGHT, rule.get("rule", "?"),
                f"harness verdict `{rule.get('verdict')}` "
                f"({', '.join(rule.get('verdict_codes') or []) or 'no codes'}); "
                f"FP {rule.get('fp_count')} = {rule.get('fp_share_of_category_percent')}% of "
                f"{rule.get('category')}; measured floor "
                f"{rule.get('measured_fp_likelihood_floor')} vs declared "
                f"{rule.get('declared_fp_likelihood')}"))

    for rule in (report or {}).get("rules", []):
        if rule.get("blocking_defect"):
            blockers.append(blocker(
                "auditor-rule-defect", LIGHT, Path(str(rule.get("path", "?"))).name,
                str(rule.get("rationale") or rule.get("blocking_defect"))))

    # --- scenarios: `redo` always blocks, `expand` only below the coverage floor ----
    for scenario in (report or {}).get("scenarios", []):
        verdict = str(scenario.get("verdict", "")).lower()
        coverage = coverage_fraction(scenario.get("coverage_ratio"))
        shown = "unstated" if coverage is None else f"{coverage:.0%}"
        missing = ", ".join(str(m) for m in (scenario.get("missing_use_cases") or [])[:6]) or "none listed"
        subject = scenario.get("id", verification or "?")
        if verdict == "redo":
            blockers.append(blocker(
                "scenario-redo", HEAVY, subject,
                f"coverage {shown}; the verified flow is not representative. "
                f"Missing: {missing}. Realism flags: "
                f"{', '.join(str(f) for f in (scenario.get('realism_flags') or [])) or 'none'}"))
        elif verdict == "expand":
            detail = (f"coverage {shown} against the grounded reference "
                      f"(floor {SCENARIO_COVERAGE_MIN:.0%}). Missing: {missing}")
            if coverage is None:
                blockers.append(blocker(
                    "scenario-coverage-unreadable", HEAVY, subject,
                    f"`coverage_ratio` = {json.dumps(scenario.get('coverage_ratio'), ensure_ascii=False)} "
                    f"carries no leading fraction or percentage, so the gate cannot check it "
                    f"against the {SCENARIO_COVERAGE_MIN:.0%} floor. Restate it as `covered/total` "
                    f"for what is verified TODAY. Missing: {missing}"))
            elif coverage < SCENARIO_COVERAGE_MIN:
                blockers.append(blocker("scenario-coverage", HEAVY, subject, detail))
            else:
                findings.append(blocker("scenario-expand", HEAVY, subject, detail +
                                        " - above the floor: record as future scenarios, "
                                        "do not hold the merge"))
        elif verdict and verdict != "pass":
            findings.append(blocker("scenario-unknown-verdict", HEAVY, subject,
                                    f"auditor verdict `{verdict}` is not one of pass|expand|redo"))

    # Non-blocking, but the report must state them so a merge is not mistaken for coverage.
    for rule in (suite or {}).get("rules", []):
        if rule.get("verdict") in {"no-corpus-coverage", "not-testable-on-evtx"}:
            findings.append(blocker(
                f"unmeasurable-{rule['verdict']}", LIGHT, rule.get("rule", "?"),
                "the corpus cannot exercise this rule; recall is unproven and must be judged "
                "against the verification's own evidence/, not assumed"))

    return {"suite": suite, "report": report, "scope": scope,
            "errors": errors, "blockers": blockers, "findings": findings}


def route_markdown(verification: str, iteration: int, blockers: list[dict], findings: list[dict],
                   gate_dir: Path) -> str:
    light = [b for b in blockers if b["weight"] == LIGHT]
    heavy = [b for b in blockers if b["weight"] == HEAVY]
    safety = [b for b in blockers if b["weight"] == SAFETY]

    lines = [
        f"# Audit gate FAILED - `{verification}` (iteration {iteration})",
        "",
        "This is the routing note for the author (Codex on the AI VM). Every item below is "
        "either a MEASUREMENT from the harness or a JUDGEMENT from the independent auditor - "
        "the gate itself decided nothing. Fix the blockers, then the gate re-runs.",
        "",
        f"Evidence: `{gate_dir}/scorecard.md`, `{gate_dir}/auditor/audit-report.md`, "
        f"`{gate_dir}/precision/precision-input.md`.",
        "",
    ]

    if safety:
        lines += ["## SAFETY - fix first, nothing else matters until this clears", ""]
        for item in safety:
            lines.append(f"- **{item['subject']}** ({item['kind']}): {item['detail']}")
        lines += ["", "A safety blocker is never traded against detection quality. If a scenario "
                      "names a destination outside `192.168.1.0/24`, re-host it inside the lab and "
                      "re-run; do not edit the finding away.", ""]

    if light:
        lines += ["## Rule fixes - text edits, no lab run", ""]
        for item in light:
            lines.append(f"- `{item['subject']}`: {item['detail']}")
        lines += ["", "Apply the reconciled values from `precision/precision-input.md` "
                      "(`fp_likelihood = max(measured floor, auditor)`); a rule may not declare "
                      "itself more precise than it measured.", ""]

    if heavy:
        lines += ["## Scenario gaps - needs a new lab run", ""]
        for item in heavy:
            lines.append(f"- **{item['subject']}**: {item['detail']}")
        lines += ["", "Split these before running anything: which gaps are verified NOW (add to "
                      "the flow, roll 104 back to `win_verify_baseline` first) and which are "
                      "recorded as future scenarios in `scenarios.md`. State the split in the PR.", ""]

    if findings:
        lines += ["## Non-blocking - record, do not fix", ""]
        for item in findings:
            lines.append(f"- `{item['subject']}` ({item['kind']}): {item['detail']}")
        lines.append("")

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("gate_dir", type=Path)
    parser.add_argument("--verification", default=None)
    parser.add_argument("--iteration", type=int, default=1)
    parser.add_argument("--commit", default=None)
    args = parser.parse_args()

    gate_dir = args.gate_dir.resolve()
    data = collect(gate_dir, args.verification)
    suite, report = data["suite"], data["report"]
    blockers, findings, errors = data["blockers"], data["findings"], data["errors"]

    if errors:
        decision, exit_code = "gate-error", 2
    elif blockers:
        decision, exit_code = "BLOCKED", 1
    else:
        decision, exit_code = "PASS", 0

    result = {
        "schema_version": SCHEMA_VERSION,
        "verification": args.verification,
        "iteration": args.iteration,
        "decision": decision,
        "repo_commit": args.commit or (suite or {}).get("commit"),
        "blocking_verdicts": sorted(BLOCKING_VERDICTS),
        "scenario_coverage_min": SCENARIO_COVERAGE_MIN,
        "harness": {
            "rule_count": (suite or {}).get("rule_count"),
            "blocking_count": (suite or {}).get("blocking_count"),
            "verdict_counts": (suite or {}).get("verdict_counts"),
        },
        "auditor": {
            "safety_verdicts": [
                {"id": e.get("id"), "verdict": e.get("verdict")} for e in (report or {}).get("safety", [])
            ],
            "scenario_verdicts": [
                {"id": s.get("id"), "verdict": s.get("verdict"),
                 "coverage_ratio": s.get("coverage_ratio")} for s in (report or {}).get("scenarios", [])
            ],
            "summary": (report or {}).get("summary"),
        },
        "blockers": blockers,
        "non_blocking_findings": findings,
        "errors": errors,
        "records_on_pass": (
            "precision/precision-input.json -> verification.json `sigma[].precision` and "
            "`audit` (measured fp_likelihood, role, level, corpus + commit, scenario coverage)"
            if decision == "PASS" else None),
    }
    (gate_dir / "gate-result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    headline = {"PASS": "PASS - may merge", "BLOCKED": "BLOCKED - back to the author",
                "gate-error": "GATE ERROR - inconclusive, re-run"}[decision]
    verdict_counts = result["harness"]["verdict_counts"] or {}
    verdict_line = ", ".join(f"{k} {v}" for k, v in sorted(verdict_counts.items()) if v)
    safety_line = ", ".join(
        "{}={}".format(s["id"], s["verdict"]) for s in result["auditor"]["safety_verdicts"])
    scenario_line = ", ".join(
        "{}={} ({})".format(s["id"], s["verdict"], s["coverage_ratio"])
        for s in result["auditor"]["scenario_verdicts"])
    md = [
        f"# Audit gate: {headline}",
        "",
        f"`{args.verification or 'all'}` at commit `{result['repo_commit']}`, iteration {args.iteration}.",
        "",
        f"- harness: {result['harness']['rule_count']} rules, "
        f"**{result['harness']['blocking_count']} blocking** ({verdict_line})",
        f"- auditor safety: {safety_line or 'not reported'}",
        f"- auditor scenarios: {scenario_line or 'not reported'}",
        f"- blockers: {len(blockers)} | non-blocking findings: {len(findings)}",
        "",
    ]
    if errors:
        md += ["## Gate errors", ""] + [f"- {e}" for e in errors] + [""]
    if decision == "PASS":
        md += ["Record the measured precision and the scenario coverage in `verification.json` "
               "from `precision/precision-input.json` before merging. A PASS means no blocking "
               "defect was found - not that every rule was exercised: see the non-blocking "
               "findings for what the corpus could not prove.", ""]
        if findings:
            md += ["## Non-blocking findings", ""] + \
                  [f"- `{f['subject']}` ({f['kind']}): {f['detail']}" for f in findings] + [""]
    else:
        md += ["See `route-to-author.md` for the routed work.", ""]
    (gate_dir / "gate-result.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    route_path = gate_dir / "route-to-author.md"
    if decision == "BLOCKED":
        route_path.write_text(
            route_markdown(args.verification or "the verification", args.iteration,
                           blockers, findings, gate_dir), encoding="utf-8")
    elif route_path.exists():
        route_path.unlink()  # a stale note from a previous iteration must not be re-dispatched

    print(json.dumps({"decision": decision, "blockers": len(blockers),
                      "non_blocking": len(findings), "gate_dir": str(gate_dir)}, indent=2))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
