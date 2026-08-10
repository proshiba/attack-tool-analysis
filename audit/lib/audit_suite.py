#!/usr/bin/env python3
"""Run the rule harness over every verification in a repo and merge the results.

Discovers `**/verification/sigma/` directories, grades each with audit_engine.py,
and merges the per-directory summaries into one machine-readable suite summary plus
a Markdown scorecard table. Rules are graded per directory so that a syntax error or
a checker abort can never reach beyond its own verification - and the syntax gate in
audit_engine.py means it no longer reaches even that far.

    audit_suite.py <repo-root> <outdir> [--only <substring>]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

AUDIT_HOME = Path(os.getenv("AUDIT_HOME", "/opt/audit"))
ENGINE = AUDIT_HOME / "lib" / "audit_engine.py"


def discover(repo: Path) -> list[Path]:
    return sorted(
        p for p in repo.glob("**/verification/sigma")
        if p.is_dir() and any(p.glob("*.yml"))
    )


def verification_id(repo: Path, sigma_dir: Path) -> str:
    """tools/sliver/verification/sigma -> tools/sliver"""
    return str(sigma_dir.relative_to(repo).parent.parent)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path)
    parser.add_argument("outdir", type=Path)
    parser.add_argument("--only", default=None, help="grade only verifications whose id contains this")
    args = parser.parse_args()

    repo = args.repo.resolve()
    outdir = args.outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    targets = discover(repo)
    if args.only:
        targets = [t for t in targets if args.only in verification_id(repo, t)]
    if not targets:
        print(f"No */verification/sigma directories under {repo}", file=sys.stderr)
        raise SystemExit(2)

    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
        text=True, capture_output=True, check=False).stdout.strip() or "unknown"

    started = time.time()
    runs, rules = [], []
    for target in targets:
        identifier = verification_id(repo, target)
        run_out = outdir / "per-verification" / identifier.replace("/", "__")
        run_out.mkdir(parents=True, exist_ok=True)
        print(f"==> {identifier}", file=sys.stderr, flush=True)
        begin = time.time()
        result = subprocess.run(
            [sys.executable, str(ENGINE), str(target), str(run_out)],
            text=True, capture_output=True, check=False)
        (run_out / "engine.stderr.txt").write_text(result.stderr, encoding="utf-8")
        summary_path = run_out / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None
        runs.append({
            "verification": identifier,
            "sigma_dir": str(target),
            "returncode": result.returncode,
            "seconds": round(time.time() - begin, 1),
            "summary": str(summary_path) if summary else None,
            "harness_notes": (summary or {}).get("harness_notes", []),
        })
        for rule in (summary or {}).get("rules", []):
            rules.append({"verification": identifier, **rule})

    verdicts: dict[str, int] = {}
    for rule in rules:
        verdicts[rule["verdict"]] = verdicts.get(rule["verdict"], 0) + 1
    blocking = sum(1 for rule in rules if rule.get("blocking"))

    suite = {
        "schema_version": 1,
        "repo": str(repo),
        "commit": commit,
        "verification_count": len(runs),
        "rule_count": len(rules),
        "verdict_counts": verdicts,
        "blocking_count": blocking,
        "seconds": round(time.time() - started, 1),
        "runs": runs,
        "rules": rules,
    }
    (outdir / "suite-summary.json").write_text(json.dumps(suite, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def cell(value) -> str:
        return "-" if value is None else str(value)

    lines = [
        f"# Rule scorecard - `{commit}`",
        "",
        f"{len(rules)} rules across {len(runs)} verifications. "
        f"Verdicts: " + ", ".join(f"**{k}** {v}" for k, v in sorted(verdicts.items())),
        "",
        f"**{blocking} of {len(rules)} rules are blocking** (`needs-work`, `void`, `fail`). "
        "`no-corpus-coverage` and `not-testable-on-evtx` describe what the corpus cannot "
        "exercise, not a defect in the rule: they never block a merge and are judged "
        "qualitatively.",
        "",
        "FP share is a percentage of the events in the rule's OWN logsource category, "
        "measured on a clean corpus. `floor` is the lowest defensible `fp_likelihood`: "
        "an auditor may raise it, never lower it.",
        "",
        "| Verification | Rule | Category | FP hits | FP share % | floor | declared | role | level | detection | verdict |",
        "|---|---|---|---|---:|---|---|---|---|---|---|",
    ]
    order = {"fail": 0, "void": 1, "needs-work": 2, "not-testable-on-evtx": 3,
             "no-corpus-coverage": 4, "pass": 5}
    for rule in sorted(rules, key=lambda r: (order.get(r["verdict"], 9), -(r["fp_share_of_category_percent"] or 0))):
        detection = "-" if rule["detection_hit"] is None else ("hit" if rule["detection_hit"] else "no-hit")
        lines.append(
            f"| {rule['verification']} | `{rule['rule']}` | {cell(rule['category'])} | "
            f"{cell(rule['fp_count'])} | {cell(rule['fp_share_of_category_percent'])} | "
            f"{cell(rule['measured_fp_likelihood_floor'])} | {cell(rule['declared_fp_likelihood'])} | "
            f"{cell(rule['declared_role'])} | {cell(rule['level'])} | {detection} | **{rule['verdict']}** |"
        )
    lines += ["", "## Harness notes", ""]
    any_note = False
    for run in runs:
        for note in run["harness_notes"]:
            any_note = True
            lines.append(f"- `{run['verification']}` - {json.dumps(note, ensure_ascii=False)}")
    if not any_note:
        lines.append("- none")
    (outdir / "scorecard.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({"verdict_counts": verdicts, "rule_count": len(rules),
                      "blocking_count": blocking,
                      "outdir": str(outdir), "seconds": suite["seconds"]}, indent=2))


if __name__ == "__main__":
    main()
