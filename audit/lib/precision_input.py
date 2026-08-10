#!/usr/bin/env python3
"""Join harness measurements with the auditor's judgement into one authoring input.

The precision pass has two independent sources of truth and they must not be merged
by hand:

* `audit_suite.py` output - what the rule *measured* on a clean corpus (the floor).
* the auditor's `audit-report.json` - what a reviewer concluded qualitatively, e.g.
  "0 measured FPs, but `Microsoft-CryptoAPI/` is the user agent Windows uses for all
  CRL/OCSP traffic, so this is high-FP in production".

Reconciliation is deterministic: `fp_likelihood = max(measured floor, auditor)`. The
measurement is a floor a reviewer may raise, never lower; and a reviewer's qualitative
raise is never overridden by a quiet lab corpus. Disagreements are reported, not smoothed.

    precision_input.py <suite-summary.json> <auditor-report.json> <outdir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

LIKELIHOOD = {"low": 0, "medium": 1, "high": 2}
LEVELS = ["informational", "low", "medium", "high", "critical"]


def stronger(a: str | None, b: str | None) -> str | None:
    candidates = [x for x in (a, b) if x in LIKELIHOOD]
    return max(candidates, key=lambda x: LIKELIHOOD[x]) if candidates else None


def main() -> None:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    suite = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    report = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    outdir = Path(sys.argv[3])
    outdir.mkdir(parents=True, exist_ok=True)

    auditor_by_name = {Path(r["path"]).name: r for r in report.get("rules", [])}
    scenarios = report.get("scenarios", [])

    rows = []
    for rule in suite["rules"]:
        name = rule["rule"]
        auditor = auditor_by_name.get(name, {})
        scorecard_path = Path(rule["scorecard"])
        scorecard = json.loads(scorecard_path.read_text(encoding="utf-8")) if scorecard_path.exists() else {}

        floor = rule["measured_fp_likelihood_floor"]
        judged = (auditor.get("fp_likelihood") or "").lower() or None
        final = stronger(floor, judged)

        role = (auditor.get("recommended_role") or "").lower() or None
        if final == "high":
            role = "hunt"
        elif role is None:
            role = "alert"

        current_level = (rule["level"] or "").lower() or None
        level = (auditor.get("recommended_level") or "").lower() or current_level
        if final == "high" and level in {"high", "critical"}:
            level = "low"

        disagreement = None
        if floor and judged and floor != judged:
            direction = "auditor raised" if LIKELIHOOD.get(judged, 0) > LIKELIHOOD.get(floor, 0) else "auditor below measurement"
            disagreement = f"{direction}: measured floor {floor}, auditor {judged} -> using {final}"

        rows.append({
            "rule_file": name,
            "repo_path": auditor.get("path") or rule["path"],
            "verification": rule["verification"],
            "logsource": {"category": rule["category"], "product": rule["product"]},
            "current_level": current_level,
            "harness": {
                "verdict": rule["verdict"],
                "verdict_codes": rule["verdict_codes"],
                "measured": rule["measured"],
                "fp_count": rule["fp_count"],
                "fp_share_of_category_percent": rule["fp_share_of_category_percent"],
                "category_denominator": (scorecard.get("fp") or {}).get("category_denominator"),
                "measured_fp_likelihood_floor": floor,
                "detection_hit": rule["detection_hit"],
                "top_matching_images": (scorecard.get("fp") or {}).get("top_matching_images", []),
            },
            "auditor": {
                "fp_likelihood": judged,
                "recommended_role": (auditor.get("recommended_role") or None),
                "recommended_level": (auditor.get("recommended_level") or None),
                "blocking_defect": auditor.get("blocking_defect"),
                "rationale": auditor.get("rationale"),
                "recommendations": auditor.get("recommendations"),
            },
            "apply": {
                "fp_likelihood": final,
                "recommended_role": role,
                "level": level,
                "level_change": None if level == current_level else f"{current_level} -> {level}",
            },
            "disagreement": disagreement,
        })

    payload = {
        "schema_version": 1,
        "repo_commit_measured": suite["commit"],
        "auditor_report_commit": report.get("repo_commit"),
        "reconciliation_rule": "fp_likelihood = max(measured floor, auditor judgement); "
                               "high fp_likelihood forces recommended_role=hunt and level<=low",
        "rule_count": len(rows),
        "rules": rows,
        "scenarios": scenarios,
    }
    (outdir / "precision-input.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Precision pass - per-rule input",
        "",
        f"Measured at `{suite['commit']}`; auditor report at `{report.get('repo_commit')}`.",
        "`apply` is the deterministic reconciliation of measurement and judgement - "
        "author these values, and write `precision_notes` from the evidence columns.",
        "",
        "| Rule | category | FP hits | share % | floor | auditor | **apply** | role | level | detection |",
        "|---|---|---:|---:|---|---|---|---|---|---|",
    ]
    for row in rows:
        h, a, ap = row["harness"], row["auditor"], row["apply"]
        lines.append(
            f"| `{row['rule_file']}` | {row['logsource']['category']} | "
            f"{'-' if h['fp_count'] is None else h['fp_count']} | "
            f"{'-' if h['fp_share_of_category_percent'] is None else h['fp_share_of_category_percent']} | "
            f"{h['measured_fp_likelihood_floor'] or '-'} | {a['fp_likelihood'] or '-'} | "
            f"**{ap['fp_likelihood'] or '?'}** | {ap['recommended_role']} | "
            f"{ap['level_change'] or ap['level']} | "
            f"{'-' if h['detection_hit'] is None else ('hit' if h['detection_hit'] else 'no-hit')} |"
        )
    lines += ["", "## Evidence for precision_notes", ""]
    for row in rows:
        h = row["harness"]
        if not h["top_matching_images"] and not row["auditor"]["rationale"]:
            continue
        lines.append(f"### `{row['rule_file']}`")
        if h["top_matching_images"]:
            benign = ", ".join(f"{i['image']} x{i['count']}" for i in h["top_matching_images"][:8])
            lines.append(f"- benign processes matched on the clean corpus: {benign}")
        if row["auditor"]["rationale"]:
            lines.append(f"- auditor: {row['auditor']['rationale']}")
        if row["disagreement"]:
            lines.append(f"- reconciliation: {row['disagreement']}")
        lines.append("")
    (outdir / "precision-input.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "rules": len(rows),
        "disagreements": sum(1 for r in rows if r["disagreement"]),
        "level_changes": sum(1 for r in rows if r["apply"]["level_change"]),
        "hunt": sum(1 for r in rows if r["apply"]["recommended_role"] == "hunt"),
        "outdir": str(outdir),
    }, indent=2))


if __name__ == "__main__":
    main()
