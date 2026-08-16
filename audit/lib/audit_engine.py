#!/usr/bin/env python3
"""Deterministic Sigma rule syntax, false-positive, precision, and detection scoring.

What changed in schema_version 2 (2026-08-10), and why
-----------------------------------------------------
1. SYNTAX GATE BEFORE MEASUREMENT. `sigma check` now runs on every rule *before*
   anything is staged, and only compiling rules reach the checker. Previously one
   uncompilable rule (`2 of selection_check_*`, unsupported by sigma-cli 3.1.0)
   aborted the single directory-wide checker invocation, and every rule in that
   directory was then reported as `fp_per_million: 0.0, detection_hit: false` -
   indistinguishable from a genuinely clean result.
2. NO FABRICATED ZEROS. If the checker still exits non-zero, the offending rules
   are isolated by bisection and quarantined, the rest are re-measured, and
   anything that could not be measured reports `null` with `measured: false` and
   verdict `void` - never `0.0`.
3. CATEGORY-NORMALISED FP RATE. `fp_per_million` against all 6.9M baseline events
   understated process-rule noise by ~279x (only 23,695 events are
   process_creation). Every rule is now also scored as a share of the events its
   own logsource category can match, from the measured catalog built by
   baseline_metrics.py.
4. EVTX-TESTABILITY. Zeek/Suricata rules cannot be exercised against an EVTX
   corpus at all. They are marked `not-testable-on-evtx` instead of being failed
   for "no detection hit".
5. PRECISION CONVENTION ENFORCEMENT. The engine reads each rule's declared
   `fp_likelihood` / `recommended_role` / `precision_notes` / `level` and compares
   them with the measured floor. Declaring a rule more precise than it measures is
   a `precision-mismatch`. A detection miss is `needs-work`, not `fail`: SigmaHQ's
   own mimikatz rule also misses here, because the positive corpus has no mimikatz
   command line - that is a corpus limit, not a rule defect.

What changed in schema_version 3 (2026-08-10)
---------------------------------------------
7. A DETECTION MISS IS NO LONGER `needs-work`. Every one of the 10 `needs-work`
   rules in the first full suite run carried exactly one reason code,
   `no-positive-corpus-sample`, with 0.0 FP and every other threshold satisfied -
   so `needs-work` was routing clean rules back to the author for a defect that
   does not exist and that no rule edit could clear. The miss now gets its own
   verdict `no-corpus-coverage`, ranked below `not-testable-on-evtx` in
   SEVERITY_ORDER so any real defect still wins through worst(), and excluded from
   `BLOCKING_VERDICTS` - the set the Phase-2 merge gate consumes. Recall for a tool
   the corpus does not carry is judged qualitatively against the verification's own
   `evidence/`, with the upstream SigmaHQ rule as a control.
6. STRUCTURAL SCHEMA GATE (added 2026-08-10 after it caught a live regression).
   `sigma check` validates the pySigma model and is relaxed about the metadata
   around it, so a YAML slip outside `detection` passes it and only breaks
   downstream. A `falsepositives:` entry ending in `kerberos::` at end-of-line is
   read by YAML as a mapping key, so the list item becomes a dict: sigma-cli
   accepted it, the Go checker refused the whole rule with "cannot unmarshal !!map
   into string", and the rule silently stopped being measurable. That class is now
   `fail` / `rule-schema-invalid` at the gate, and a rule the checker refuses even
   in isolation is `fail` / `rule-unparseable-by-checker` carrying the checker's own
   error - not the generic `void`.

What changed in schema_version 4 (2026-08-16)
---------------------------------------------
8. DEAD LOGSOURCE MAPPINGS FAIL BEFORE MEASUREMENT. The THOR mapping selects generic
   rules by category+product, adds the category EventID, and rewrites service. A rule
   that also pins service can compile and report zero matches while never being
   eligible for the mapped event stream. The structural gate now derives every
   service-rewriting category+product pair from THOR and rejects that redundant,
   measurement-voiding service qualifier with a clear repair message.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

SCHEMA_VERSION = 4

BASELINE = Path(os.getenv("AUDIT_BASELINE", "/data/datasets/evtx-baseline"))
ATTACK = Path(os.getenv("AUDIT_ATTACK", "/data/datasets/EVTX-ATTACK-SAMPLES"))
REGRESSION = Path(os.getenv("AUDIT_REGRESSION", "/data/datasets/regression_data"))
THOR = Path(os.getenv("AUDIT_THOR", "/data/datasets/sigma/tests/thor.yml"))
CHECKER = Path(os.getenv("AUDIT_CHECKER", "/opt/audit/bin/evtx-sigma-checker"))
METRICS = Path(os.getenv("AUDIT_METRICS", "/opt/audit/catalog/dataset-metrics.json"))
CATEGORY_METRICS = Path(os.getenv("AUDIT_CATEGORY_METRICS", "/opt/audit/catalog/baseline-category-metrics.json"))

# Share of the rule's own logsource category, in percent, measured on a CLEAN corpus.
FP_CATEGORY_HIGH_PERCENT = float(os.getenv("FP_CATEGORY_HIGH_PERCENT", "0.1"))
FP_CATEGORY_MEDIUM_PERCENT = float(os.getenv("FP_CATEGORY_MEDIUM_PERCENT", "0.001"))
FP_CATEGORY_FAIL_PERCENT = float(os.getenv("FP_CATEGORY_FAIL_PERCENT", "5.0"))
MAX_SAMPLES = int(os.getenv("MAX_SAMPLE_MATCHES", "20"))
TIMEOUT = int(os.getenv("CHECKER_TIMEOUT_SECONDS", "1800"))
REQUIRE_PRECISION_FIELDS = os.getenv("REQUIRE_PRECISION_FIELDS", "true").lower() == "true"

# EVTX corpora only carry Windows event logs; anything else cannot be exercised here.
EVTX_PRODUCTS = {"windows", None, ""}

LIKELIHOOD_ORDER = {"low": 0, "medium": 1, "high": 2}
# `no-corpus-coverage` sits below `not-testable-on-evtx`: both describe a limit of the
# corpus, not of the rule, so any genuine defect still wins through worst().
SEVERITY_ORDER = {"pass": 0, "no-corpus-coverage": 1, "not-testable-on-evtx": 2,
                  "needs-work": 3, "void": 4, "fail": 5}

# The authoritative definition consumed by the Phase-2 merge gate. Everything else is
# informational: it reports a property of the corpus that no rule edit can change.
BLOCKING_VERDICTS = {"needs-work", "void", "fail"}


def fail(message: str, code: int = 2) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def yaml_files(source: Path) -> list[Path]:
    if source.is_file():
        return [source] if source.suffix.lower() in {".yml", ".yaml"} else []
    if source.is_dir():
        return sorted(p for p in source.rglob("*") if p.is_file() and p.suffix.lower() in {".yml", ".yaml"})
    return []


def run(command: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
            except json.JSONDecodeError as exc:
                fail(f"Invalid checker JSON on line {number} of {path}: {exc}")
    return rows


def checker(rules_dir: Path, evtx_paths: list[Path], raw_out: Path, err_out: Path) -> tuple[int, list[dict]]:
    command = [str(CHECKER), "--log-source", str(THOR), "--rule-level", "informational"]
    for evtx in evtx_paths:
        command += ["--evtx-path", str(evtx)]
    command += ["--rule-path", str(rules_dir)]
    try:
        result = run(command, TIMEOUT)
        raw_out.write_text(result.stdout, encoding="utf-8")
        err_out.write_text(result.stderr, encoding="utf-8")
        return result.returncode, load_jsonl(raw_out)
    except subprocess.TimeoutExpired as exc:
        raw_out.write_text(exc.stdout or "", encoding="utf-8")
        err_out.write_text((exc.stderr or "") + f"\nTIMEOUT after {TIMEOUT}s\n", encoding="utf-8")
        return 124, load_jsonl(raw_out)


def stage(records: list[dict], directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for record in records:
        shutil.copy2(record["source"], directory / record["staged_name"])
    return directory


def measure(records: list[dict], evtx_paths: list[Path], outdir: Path, tag: str,
            workspace: Path, quarantine_reasons: dict[str, str]) -> tuple[list[dict], list[dict], list[str]]:
    """Measure `records` against `evtx_paths`.

    Returns (findings, notes, quarantined_staged_names). A checker abort never
    yields zeros: the offenders are bisected out and reported, and the survivors
    are re-measured on their own. `quarantine_reasons` is filled in with the
    checker's own error message per offending rule, so the scorecard can say WHY
    the rule could not be loaded instead of only that it could not.
    """
    notes: list[dict] = []
    quarantined: list[str] = []

    def attempt(subset: list[dict], label: str) -> tuple[int, list[dict], Path]:
        if not subset:
            return 0, [], workspace / "empty.stderr.txt"
        directory = workspace / f"{tag}-{label}"
        stage(subset, directory)
        err_out = (outdir / f"{tag}-checker.stderr.txt" if label == "all"
                   else workspace / f"{tag}-{label}.stderr.txt")
        code, rows = checker(
            directory, evtx_paths,
            outdir / f"{tag}-findings.raw.jsonl" if label == "all" else workspace / f"{tag}-{label}.jsonl",
            err_out,
        )
        return code, rows, err_out

    code, rows, _ = attempt(records, "all")
    if code == 0:
        return rows, notes, quarantined

    notes.append({
        "event": "checker-aborted",
        "corpus": tag,
        "returncode": code,
        "action": "bisecting to isolate the offending rule(s); no zeros are reported for unmeasured rules",
    })

    def bisect(subset: list[dict], depth: int) -> list[dict]:
        """Return the subset that measured cleanly; append offenders to `quarantined`."""
        if not subset:
            return []
        code, _, err_out = attempt(subset, f"b{depth}-{len(subset)}-{subset[0]['index']}")
        if code == 0:
            return subset
        if len(subset) == 1:
            message = ""
            if err_out.exists():
                message = " ".join(err_out.read_text(encoding="utf-8", errors="replace").split())[:600]
            quarantined.append(subset[0]["staged_name"])
            quarantine_reasons[subset[0]["staged_name"]] = (
                f"evtx-sigma-checker exits {code} when this rule is loaded alone"
                + (f": {message}" if message else "")
            )
            notes.append({
                "event": "rule-quarantined",
                "corpus": tag,
                "rule": str(subset[0]["source"]),
                "reason": quarantine_reasons[subset[0]["staged_name"]],
            })
            return []
        middle = len(subset) // 2
        return bisect(subset[:middle], depth + 1) + bisect(subset[middle:], depth + 1)

    survivors = bisect(records, 0)
    if not survivors:
        return [], notes, quarantined
    code, rows, _ = attempt(survivors, "survivors")
    if code != 0:
        notes.append({"event": "checker-aborted-after-quarantine", "corpus": tag, "returncode": code})
        return [], notes, [record["staged_name"] for record in records]
    (outdir / f"{tag}-findings.raw.jsonl").write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    return rows, notes, quarantined


def event_value(event: str, field: str) -> str | None:
    match = re.search(rf"(?:^|  ){re.escape(field)}: (.*?)(?=  [A-Za-z][A-Za-z0-9_]*: |\s*$)", event)
    return match.group(1).strip() if match else None


def infer_os(file_name: str) -> str:
    lower = file_name.lower()
    for token, label in (
        ("win11", "Windows 11"), ("win10", "Windows 10"),
        ("win2022", "Windows Server 2022"), ("win7", "Windows 7"),
        ("logs_client", "Windows 10"),
    ):
        if token in lower:
            return label
    return "Windows (version unknown)" if lower.endswith(".evtx") else "unknown"


def sample_fields(finding: dict) -> dict:
    event = str(finding.get("Event", ""))
    match_strings = finding.get("MatchStrings") or []
    return {
        "os": infer_os(str(finding.get("File", ""))),
        "event_id": event_value(event, "EventID"),
        "channel": finding.get("Channel") or event_value(event, "Channel"),
        "image": event_value(event, "Image"),
        "command_line": event_value(event, "CommandLine"),
        "triggering_selection": sorted({str(m.get("SearchIdentifier")) for m in match_strings if m.get("SearchIdentifier")}),
        "matched_fields": [
            {"selection": m.get("SearchIdentifier"), "field": m.get("Field"), "value": m.get("Data")}
            for m in match_strings
        ],
        "sample_file": finding.get("File"),
    }


def top_offenders(findings: list[dict], limit: int = 10) -> list[dict]:
    """Which benign processes actually trip the rule - the evidence an auditor needs."""
    counts: dict[tuple[str, str], int] = {}
    for row in findings:
        fields = sample_fields(row)
        key = (fields.get("image") or "?", fields.get("channel") or "?")
        counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:limit]
    return [{"image": image, "channel": channel, "count": count} for (image, channel), count in ranked]


def safe_stem(path: Path, used: set[str]) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem)
    candidate = base
    index = 2
    while candidate in used:
        candidate = f"{base}-{index}"
        index += 1
    used.add(candidate)
    return candidate


def measured_likelihood(share_percent: float | None) -> str | None:
    if share_percent is None:
        return None
    if share_percent >= FP_CATEGORY_HIGH_PERCENT:
        return "high"
    if share_percent >= FP_CATEGORY_MEDIUM_PERCENT:
        return "medium"
    return "low"


def service_rewrite_keys(mapping: dict) -> dict[tuple[str, str], set[str]]:
    """Return category+product keys whose mapping chooses the concrete service."""
    keys: dict[tuple[str, str], set[str]] = {}
    logsources = mapping.get("logsources") if isinstance(mapping, dict) else None
    if not isinstance(logsources, dict):
        return keys
    for entry in logsources.values():
        if not isinstance(entry, dict):
            continue
        category = entry.get("category")
        product = entry.get("product")
        rewrite = entry.get("rewrite")
        rewritten_service = rewrite.get("service") if isinstance(rewrite, dict) else None
        if not all(isinstance(value, str) and value for value in
                   (category, product, rewritten_service)):
            continue
        key = (category.lower(), product.lower())
        keys.setdefault(key, set()).add(rewritten_service.lower())
    return keys


def schema_errors(metadata: dict,
                  mapped_service_rewrites: dict[tuple[str, str], set[str]] | None = None) -> list[str]:
    """Structural checks `sigma check` does not make.

    pySigma parses a rule into its own model and is relaxed about the surrounding
    metadata, so a YAML slip outside `detection` sails through it and only surfaces
    downstream. The one that actually happened: a `falsepositives` entry ending in
    `kerberos::` at end-of-line, which YAML reads as a mapping key, turning the list
    item into a dict. sigma-cli accepted it; the Go checker refused to load the rule
    ("cannot unmarshal !!map into string") and every consumer expecting a list of
    strings would too. Catch that class here, at the gate, with a clear reason.
    """
    problems: list[str] = []
    for key in ("falsepositives", "tags", "references"):
        value = metadata.get(key)
        if value is None:
            continue
        if not isinstance(value, list):
            problems.append(f"{key} must be a list of strings, got {type(value).__name__}")
            continue
        for index, item in enumerate(value):
            if not isinstance(item, str):
                hint = ""
                if isinstance(item, dict) and len(item) == 1:
                    hint = (" - a list entry ending in ':' or '::' is read by YAML as a mapping key; "
                            "quote the string")
                problems.append(f"{key}[{index}] must be a string, got {type(item).__name__}{hint}")
    for key in ("logsource", "detection"):
        if key in metadata and not isinstance(metadata[key], dict):
            problems.append(f"{key} must be a mapping, got {type(metadata[key]).__name__}")
    logsource = metadata.get("logsource")
    if isinstance(logsource, dict) and mapped_service_rewrites:
        category = logsource.get("category")
        product = logsource.get("product")
        service = logsource.get("service")
        if all(isinstance(value, str) and value for value in (category, product, service)):
            key = (category.lower(), product.lower())
            if key in mapped_service_rewrites:
                rewritten = ", ".join(sorted(mapped_service_rewrites[key]))
                problems.append(
                    "logsource must not declare service when its category+product mapping "
                    f"rewrites service: category={category!r}, product={product!r}, "
                    f"declared service={service!r}, mapped service(s)={rewritten!r}; "
                    "remove service so the category mapping can select its event stream "
                    "(otherwise a compiling rule can become a dead zero-match query)"
                )
    for key in ("title", "id", "level", "description"):
        if key in metadata and metadata[key] is not None and not isinstance(metadata[key], str):
            problems.append(f"{key} must be a string, got {type(metadata[key]).__name__}")
    return problems


def worst(verdicts: list[str]) -> str:
    return max(verdicts, key=lambda v: SEVERITY_ORDER.get(v, 0)) if verdicts else "pass"


def main() -> None:
    if len(sys.argv) != 3:
        fail("Usage: audit_engine.py <rule-file-or-dir> <outdir>")
    source = Path(sys.argv[1]).resolve()
    outdir = Path(sys.argv[2]).resolve()
    rules = yaml_files(source)
    if not rules:
        fail(f"No Sigma YAML rules found at {source}")
    for required in (BASELINE, ATTACK, REGRESSION, THOR, CHECKER, METRICS):
        if not required.exists():
            fail(f"Required audit dependency missing: {required}")
    outdir.mkdir(parents=True, exist_ok=True)

    metrics = json.loads(METRICS.read_text(encoding="utf-8"))
    catalog_events = int(metrics["evtx_baseline"]["event_count"])
    category_catalog: dict = {}
    if CATEGORY_METRICS.exists():
        category_catalog = json.loads(CATEGORY_METRICS.read_text(encoding="utf-8"))
    else:
        print(f"WARNING: {CATEGORY_METRICS} missing - category-normalised rates unavailable. "
              f"Run baseline_metrics.py.", file=sys.stderr)
    categories = (category_catalog.get("categories") or {})
    try:
        mapping_document = yaml.safe_load(THOR.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - a broken mapping voids the schema check
        fail(f"Unable to read logsource mapping {THOR}: {exc}")
    mapped_service_rewrites = service_rewrite_keys(mapping_document)
    # The per-file measurement is authoritative: it is the same pass that produced
    # the category denominators, so corpus and category rates stay consistent.
    measured_events = ((category_catalog.get("dataset") or {}).get("total_events"))
    baseline_events = int(measured_events or catalog_events)
    denominator_note = None
    if measured_events and measured_events != catalog_events:
        denominator_note = (
            f"corpus denominator {measured_events} (measured per file by baseline_metrics.py) "
            f"disagrees with {METRICS} ({catalog_events}); using the measured value"
        )
        print(f"WARNING: {denominator_note}", file=sys.stderr)

    records: list[dict] = []
    used: set[str] = set()
    for index, rule in enumerate(rules):
        try:
            metadata = yaml.safe_load(rule.read_text(encoding="utf-8")) or {}
            parse_error = None
        except Exception as exc:  # noqa: BLE001 - the parse error itself is the finding
            metadata, parse_error = {}, str(exc)
        logsource = metadata.get("logsource") if isinstance(metadata.get("logsource"), dict) else {}
        records.append({
            "index": index,
            "source": rule,
            "metadata": metadata,
            "staged_name": f"{index:04d}__{rule.name}",
            "id": metadata.get("id"),
            "title": metadata.get("title", rule.stem),
            "slug": safe_stem(rule, used),
            "parse_error": parse_error,
            "category": logsource.get("category"),
            "product": logsource.get("product"),
            "service": logsource.get("service"),
            "level": metadata.get("level"),
            "declared_fp_likelihood": metadata.get("fp_likelihood"),
            "declared_role": metadata.get("recommended_role"),
            "declared_precision_notes": metadata.get("precision_notes"),
            "falsepositives": metadata.get("falsepositives"),
        })

    # ---- 1. Syntax gate: never let one uncompilable rule void its neighbours ----
    for record in records:
        syntax = run(["sigma", "check", str(record["source"])], 300)
        record["syntax_text"] = syntax.stdout + syntax.stderr
        record["syntax_exit_code"] = syntax.returncode
        record["schema_errors"] = schema_errors(record["metadata"], mapped_service_rewrites)
        record["syntax_ok"] = (syntax.returncode == 0 and record["parse_error"] is None
                               and not record["schema_errors"])
    compiling = [r for r in records if r["syntax_ok"]]
    rejected = [r for r in records if not r["syntax_ok"]]

    # ---- 2. Testability gate: EVTX corpora are Windows-only ----
    for record in compiling:
        product = (record["product"] or "").lower() or None
        known_category = record["category"] in categories if categories else True
        record["testable_on_evtx"] = product in EVTX_PRODUCTS and known_category
    testable = [r for r in compiling if r["testable_on_evtx"]]

    notes: list[dict] = []
    if denominator_note:
        notes.append({"event": "denominator-disagreement", "detail": denominator_note})
    if rejected:
        notes.append({
            "event": "rules-excluded-before-measurement",
            "count": len(rejected),
            "rules": [str(r["source"]) for r in rejected],
            "reason": "sigma check or the structural schema check failed; excluded so their "
                      "neighbours still get real numbers",
        })

    fp_all: list[dict] = []
    detection_all: list[dict] = []
    quarantined_fp: list[str] = []
    quarantined_detection: list[str] = []
    quarantine_reasons: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="sigma-audit-") as temporary:
        workspace = Path(temporary)
        if testable:
            fp_all, fp_notes, quarantined_fp = measure(
                testable, [BASELINE], outdir, "fp", workspace, quarantine_reasons)
            detection_all, detection_notes, quarantined_detection = measure(
                testable, [ATTACK, REGRESSION], outdir, "detection", workspace, quarantine_reasons)
            notes += fp_notes + detection_notes

    summaries = []
    single = source.is_file() and len(records) == 1
    for record in records:
        rule_out = outdir if single else outdir / record["slug"]
        rule_out.mkdir(parents=True, exist_ok=True)
        (rule_out / "sigma-check.txt").write_text(record["syntax_text"], encoding="utf-8")

        staged_name = record["staged_name"]
        measured = (
            record["syntax_ok"]
            and record.get("testable_on_evtx")
            and staged_name not in quarantined_fp
            and staged_name not in quarantined_detection
        )

        def belongs(row: dict) -> bool:
            return Path(str(row.get("RulePath", ""))).name == staged_name

        fps = [row for row in fp_all if belongs(row)] if measured else []
        detections = [row for row in detection_all if belongs(row)] if measured else []
        (rule_out / "findings.json").write_text(json.dumps(fps, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (rule_out / "detection-findings.json").write_text(
            json.dumps(detections, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        category_info = categories.get(record["category"] or "", {})
        category_denominator = category_info.get("event_count")
        fp_count = len(fps) if measured else None
        fp_rate = round(fp_count * 1_000_000 / baseline_events, 6) if measured else None
        if measured and category_denominator:
            fp_category_rate = round(fp_count * 1_000_000 / category_denominator, 3)
            fp_share = round(fp_count * 100 / category_denominator, 6)
        else:
            fp_category_rate = fp_share = None

        floor = measured_likelihood(fp_share) if measured else None
        declared = (record["declared_fp_likelihood"] or "").lower() or None
        declared_role = (record["declared_role"] or "").lower() or None
        level = (record["level"] or "").lower() or None

        reasons: list[dict] = []
        verdicts: list[str] = []

        if record["schema_errors"]:
            verdicts.append("fail")
            reasons.append({
                "code": "rule-schema-invalid",
                "detail": "; ".join(record["schema_errors"]),
            })
        elif not record["syntax_ok"]:
            verdicts.append("fail")
            reasons.append({
                "code": "sigma-syntax-error",
                "detail": record["parse_error"] or record["syntax_text"].strip().splitlines()[-1:] or "sigma check failed",
            })
        elif not record.get("testable_on_evtx"):
            verdicts.append("not-testable-on-evtx")
            reasons.append({
                "code": "not-testable-on-evtx",
                "detail": f"logsource product={record['product']!r} category={record['category']!r} "
                          f"cannot be exercised against a Windows EVTX corpus; judge qualitatively",
            })
        elif staged_name in quarantine_reasons:
            verdicts.append("fail")
            reasons.append({
                "code": "rule-unparseable-by-checker",
                "detail": quarantine_reasons[staged_name],
            })
        elif not measured:
            verdicts.append("void")
            reasons.append({
                "code": "measurement-void",
                "detail": "the checker aborted with this rule loaded; no FP/detection numbers exist for it",
            })
        else:
            if fp_share is not None and fp_share > FP_CATEGORY_FAIL_PERCENT:
                verdicts.append("fail")
                reasons.append({
                    "code": "fp-share-excessive",
                    "detail": f"{fp_share}% of all {record['category']} events in a CLEAN corpus "
                              f"(> {FP_CATEGORY_FAIL_PERCENT}%)",
                })
            if not detections:
                verdicts.append("no-corpus-coverage")
                reasons.append({
                    "code": "no-positive-corpus-sample",
                    "detail": "no hit in EVTX-ATTACK-SAMPLES/regression_data. The positive corpus does not "
                              "cover this tool - SigmaHQ's own mimikatz rule misses here too - so this is a "
                              "property of the corpus, not evidence of a rule defect. NON-BLOCKING: no rule "
                              "edit can clear it, only adding a positive sample can. Judge recall "
                              "qualitatively against the verification's own evidence/ instead",
                })
            if REQUIRE_PRECISION_FIELDS and (declared is None or declared_role is None
                                             or not record["declared_precision_notes"]):
                verdicts.append("needs-work")
                reasons.append({
                    "code": "precision-fields-missing",
                    "detail": "every verification rule must carry fp_likelihood, precision_notes and "
                              "recommended_role (see playbooks/verify-tool.md)",
                })
            if declared and floor and LIKELIHOOD_ORDER.get(declared, 0) < LIKELIHOOD_ORDER[floor]:
                verdicts.append("needs-work")
                reasons.append({
                    "code": "precision-mismatch",
                    "detail": f"declared fp_likelihood={declared} but measured floor is {floor} "
                              f"({fp_count} hits = {fp_share}% of {record['category']} events)",
                })
            if floor == "high" and declared_role == "alert":
                verdicts.append("needs-work")
                reasons.append({
                    "code": "role-mismatch",
                    "detail": "measured high-FP rules are hunt leads, not standalone alerts",
                })
            if floor == "high" and level in {"high", "critical"}:
                verdicts.append("needs-work")
                reasons.append({
                    "code": "level-mismatch",
                    "detail": f"level={level} contradicts a measured high FP likelihood; "
                              f"severity-if-true is not precision",
                })
            if not any(v in BLOCKING_VERDICTS for v in verdicts):
                reasons.append({"code": "ok", "detail": "all deterministic thresholds satisfied"})

        detection_samples = []
        for row in detections[:MAX_SAMPLES]:
            file_name = str(row.get("File", ""))
            regression_prefixes = (str(REGRESSION), str(REGRESSION.resolve()))
            corpus = "regression_data" if file_name.startswith(regression_prefixes) else "EVTX-ATTACK-SAMPLES"
            detection_samples.append({"corpus": corpus, **sample_fields(row)})

        card = {
            "schema_version": SCHEMA_VERSION,
            "rule": {
                "path": str(record["source"]), "id": record["id"], "title": record["title"],
                "logsource": {"category": record["category"], "product": record["product"],
                              "service": record["service"]},
                "level": record["level"],
            },
            "syntax_ok": record["syntax_ok"],
            "syntax_exit_code": record["syntax_exit_code"],
            "schema_errors": record["schema_errors"],
            "testable_on_evtx": record.get("testable_on_evtx", False),
            "measured": measured,
            "fp": {
                "count": fp_count,
                "corpus_denominator": baseline_events,
                "per_million_corpus": fp_rate,
                "category": record["category"],
                "category_denominator": category_denominator,
                "per_million_category": fp_category_rate,
                "share_of_category_percent": fp_share,
                "top_matching_images": top_offenders(fps) if measured else [],
            },
            "sample_matched_fields": [sample_fields(row) for row in fps[:MAX_SAMPLES]],
            "detection": {
                "hit": bool(detections) if measured else None,
                "count": len(detections) if measured else None,
                "samples": detection_samples,
            },
            "precision": {
                "declared_fp_likelihood": record["declared_fp_likelihood"],
                "declared_recommended_role": record["declared_role"],
                "declared_precision_notes": record["declared_precision_notes"],
                "measured_fp_likelihood_floor": floor,
                "note": "the measured value is a FLOOR from a clean corpus. An auditor may raise it "
                        "(production noise exceeds a lab baseline) but must not lower it.",
            },
            "thresholds": {
                "fp_category_high_percent": FP_CATEGORY_HIGH_PERCENT,
                "fp_category_medium_percent": FP_CATEGORY_MEDIUM_PERCENT,
                "fp_category_fail_percent": FP_CATEGORY_FAIL_PERCENT,
                "require_precision_fields": REQUIRE_PRECISION_FIELDS,
            },
            "verdict": worst(verdicts),
            "blocking": worst(verdicts) in BLOCKING_VERDICTS,
            "verdict_reasons": reasons,
        }
        (rule_out / "scorecard.json").write_text(json.dumps(card, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        summaries.append({
            "rule": record["source"].name, "id": record["id"], "path": str(record["source"]),
            "category": record["category"], "product": record["product"],
            "syntax_ok": record["syntax_ok"], "measured": measured,
            "fp_count": fp_count, "fp_per_million_category": fp_category_rate,
            "fp_share_of_category_percent": fp_share,
            "declared_fp_likelihood": record["declared_fp_likelihood"],
            "measured_fp_likelihood_floor": floor,
            "declared_role": record["declared_role"], "level": record["level"],
            "detection_hit": bool(detections) if measured else None,
            "verdict": worst(verdicts),
            "blocking": worst(verdicts) in BLOCKING_VERDICTS,
            "verdict_codes": [r["code"] for r in reasons],
            "scorecard": str(rule_out / "scorecard.json"),
        })

    summary = {
        "schema_version": SCHEMA_VERSION,
        "source": str(source),
        "rule_count": len(records),
        "measured_count": sum(1 for s in summaries if s["measured"]),
        "verdict_counts": {v: sum(1 for s in summaries if s["verdict"] == v) for v in sorted(SEVERITY_ORDER)},
        "blocking_count": sum(1 for s in summaries if s["blocking"]),
        "blocking_verdicts": sorted(BLOCKING_VERDICTS),
        "dataset_metrics": metrics,
        "corpus_denominator": {
            "events": baseline_events,
            "source": "baseline_metrics.py per-file measurement" if measured_events else str(METRICS),
            "dataset_metrics_json_value": catalog_events,
        },
        "category_metrics": {
            "path": str(CATEGORY_METRICS),
            "present": bool(categories),
            "denominators": {name: info.get("event_count") for name, info in sorted(categories.items())},
        },
        "thresholds": {
            "fp_category_high_percent": FP_CATEGORY_HIGH_PERCENT,
            "fp_category_medium_percent": FP_CATEGORY_MEDIUM_PERCENT,
            "fp_category_fail_percent": FP_CATEGORY_FAIL_PERCENT,
            "require_precision_fields": REQUIRE_PRECISION_FIELDS,
        },
        "harness_notes": notes,
        "rules": summaries,
    }
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
