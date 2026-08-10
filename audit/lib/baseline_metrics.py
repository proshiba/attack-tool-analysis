#!/usr/bin/env python3
"""Measure per-Sigma-category event denominators for an EVTX corpus.

Why this exists
---------------
`fp_per_million` was computed against every event in the corpus (6,923,967 on
evtx-baseline v0.8.4), but a `process_creation` rule can only ever match the
process-creation events - about 26k of them. Scoring a process rule against the
6.9M denominator understates its noise by roughly 260-340x. Every rule must be
measured against the number of events its own logsource category can match.

Method (fully scripted - nothing is counted by hand)
---------------------------------------------------
1. `hayabusa eid-metrics` is run **per file**, not per directory. Directory mode
   silently truncates `Logs_Win11_2023/Security.evtx` at record 2783 and loses
   312,784 records (2,592 of them EventID 4688), which is exactly the corpus-wide
   discrepancy the old catalog patched up with a manual chainsaw correction.
2. Per-(channel, EventID) counts are summed across all files.
3. `thor.yml` - the same log-source mapping `evtx-sigma-checker` is invoked with -
   is parsed to map Sigma category -> {(service, EventID)}, and each service is
   resolved to hayabusa's channel abbreviation. Anything that cannot be resolved
   is reported in `unresolved` instead of being silently dropped.

Output: a JSON catalog consumed by audit_engine.py.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml

# hayabusa abbreviates Windows channel names. Map the Sigma/thor `service:`
# token to the abbreviation(s) hayabusa prints in the `Channel` column.
SERVICE_CHANNELS: dict[str, list[str]] = {
    "sysmon": ["Sysmon"],
    "security": ["Sec"],
    "system": ["Sys"],
    "application": ["App"],
    "powershell": ["PwSh"],
    "powershell-classic": ["PwShClassic"],
    "applocker": ["AppLocker"],
    "windefend": ["Defender"],
    "firewall-as": ["Firewall"],
    "security-mitigations": ["SecMitig"],
    "codeintegrity-operational": ["CodeInteg"],
    "bits-client": ["BitsCli"],
    "dns-client": ["DNS-Cli"],
    "dns-server": ["DNS-Svr"],
    "ntlm": ["NTLM"],
    "taskscheduler": ["TaskSch"],
    "wmi": ["WMI-Act"],
}


def die(message: str, code: int = 2) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def evtx_files(dataset: Path) -> list[Path]:
    return sorted(p for p in dataset.rglob("*") if p.is_file() and p.suffix.lower() == ".evtx")


def cache_path(cache_dir: Path, dataset: Path, evtx: Path) -> Path:
    relative = evtx.relative_to(dataset)
    flat = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(relative))
    return cache_dir / f"{flat}.csv"


def measure_file(hayabusa: Path, evtx: Path, out_csv: Path, reuse: bool) -> tuple[Path, int, str]:
    """Run hayabusa eid-metrics on one file. Returns (csv, returncode, stderr)."""
    if reuse and out_csv.exists() and out_csv.stat().st_mtime >= evtx.stat().st_mtime:
        return out_csv, 0, "cached"
    command = [
        str(hayabusa), "eid-metrics", "-f", str(evtx),
        "-o", str(out_csv), "-C", "-q", "-K", "-U", "-Q",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    return out_csv, result.returncode, (result.stderr or "")[-2000:]


def parse_metrics_csv(path: Path) -> list[tuple[str, str, int]]:
    """Return [(channel, event_id, count)] from a hayabusa eid-metrics CSV."""
    rows: list[tuple[str, str, int]] = []
    if not path.exists() or path.stat().st_size == 0:
        return rows
    with path.open(encoding="utf-8", errors="replace", newline="") as handle:
        for record in csv.DictReader(handle):
            total = (record.get("Total") or "").replace(",", "").strip()
            channel = (record.get("Channel") or "").strip()
            event_id = (record.get("ID") or "").strip()
            if not total.isdigit() or not channel or not event_id:
                continue
            rows.append((channel, event_id, int(total)))
    return rows


def thor_category_map(thor: Path) -> tuple[dict[str, list[dict]], list[str]]:
    """category -> [{service, event_id}]; plus the services we could not resolve."""
    document = yaml.safe_load(thor.read_text(encoding="utf-8")) or {}
    categories: dict[str, list[dict]] = defaultdict(list)
    unresolved: set[str] = set()
    for entry in (document.get("logsources") or {}).values():
        category = entry.get("category")
        if not category:
            continue
        conditions = entry.get("conditions") or {}
        event_ids = conditions.get("EventID")
        if event_ids is None:
            continue
        if not isinstance(event_ids, list):
            event_ids = [event_ids]
        service = ((entry.get("rewrite") or {}).get("service") or entry.get("service") or "").lower()
        if service and service not in SERVICE_CHANNELS:
            unresolved.add(service)
        for event_id in event_ids:
            source = {"service": service, "event_id": str(event_id)}
            if source not in categories[category]:
                categories[category].append(source)
    return dict(categories), sorted(unresolved)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", default="/data/datasets/evtx-baseline", type=Path)
    parser.add_argument("--dataset-name", default="evtx-baseline")
    parser.add_argument("--out", default="/opt/audit/catalog/baseline-category-metrics.json", type=Path)
    parser.add_argument("--hayabusa", default="/opt/audit/bin/hayabusa", type=Path)
    parser.add_argument("--thor", default="/data/datasets/sigma/tests/thor.yml", type=Path)
    parser.add_argument("--cache-dir", default="/opt/audit/scratch/eid-metrics", type=Path)
    parser.add_argument("--jobs", type=int, default=max(2, (os.cpu_count() or 4) // 2))
    parser.add_argument("--no-reuse", action="store_true", help="ignore cached per-file CSVs")
    args = parser.parse_args()

    for required in (args.dataset, args.hayabusa, args.thor):
        if not required.exists():
            die(f"Missing dependency: {required}")

    files = evtx_files(args.dataset)
    if not files:
        die(f"No .evtx files under {args.dataset}")
    args.cache_dir.mkdir(parents=True, exist_ok=True)

    channel_counts: dict[str, int] = defaultdict(int)
    per_file_totals: dict[str, int] = {}
    failures: list[dict] = []
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {
            pool.submit(
                measure_file, args.hayabusa, evtx,
                cache_path(args.cache_dir, args.dataset, evtx), not args.no_reuse,
            ): evtx
            for evtx in files
        }
        for future in concurrent.futures.as_completed(futures):
            evtx = futures[future]
            out_csv, code, stderr = future.result()
            done += 1
            if done % 200 == 0 or done == len(files):
                print(f"[{done}/{len(files)}] scanned", file=sys.stderr, flush=True)
            rows = parse_metrics_csv(out_csv)
            if code != 0 and not rows:
                failures.append({"file": str(evtx), "returncode": code, "stderr": stderr})
                continue
            total = 0
            for channel, event_id, count in rows:
                channel_counts[f"{channel}|{event_id}"] += count
                total += count
            per_file_totals[str(evtx.relative_to(args.dataset))] = total

    total_events = sum(channel_counts.values())
    categories_map, unresolved_services = thor_category_map(args.thor)

    categories: dict[str, dict] = {}
    for category, sources in sorted(categories_map.items()):
        resolved_sources = []
        resolvable = True
        for source in sources:
            channels = SERVICE_CHANNELS.get(source["service"])
            if channels is None:
                resolvable = False
                resolved_sources.append({**source, "channel": None, "count": None})
                continue
            count = sum(channel_counts.get(f"{channel}|{source['event_id']}", 0) for channel in channels)
            resolved_sources.append({**source, "channel": channels[0], "count": count})
        counted = [s["count"] for s in resolved_sources if s["count"] is not None]
        categories[category] = {
            "event_count": sum(counted) if counted else None,
            "fully_resolved": resolvable,
            "sources": resolved_sources,
        }

    catalog = {
        "schema_version": 1,
        "dataset": {
            "name": args.dataset_name,
            "path": str(args.dataset),
            "evtx_file_count": len(files),
            "total_events": total_events,
        },
        "method": {
            "tool": "hayabusa eid-metrics",
            "invocation": "per file (-f), never per directory",
            "why_per_file": (
                "directory mode truncates Logs_Win11_2023/Security.evtx at record 2783 "
                "and loses 312,784 records, including 2,592 EventID 4688"
            ),
            "category_mapping_source": str(args.thor),
            "jobs": args.jobs,
        },
        "channel_event_id_counts": dict(sorted(channel_counts.items(), key=lambda kv: -kv[1])),
        "categories": categories,
        "unresolved": {
            "services_without_channel_mapping": unresolved_services,
            "files_that_failed_to_scan": failures,
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"total_events={total_events} files={len(files)} failures={len(failures)}")
    for category in ("process_creation", "file_event", "registry_set", "process_access", "network_connection", "image_load", "dns_query"):
        info = categories.get(category)
        if info:
            print(f"  {category:<20} {info['event_count']}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
