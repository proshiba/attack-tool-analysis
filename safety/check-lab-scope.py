#!/usr/bin/env python3
"""SAFETY RULE 1 gate: prove that no attack traffic left the isolated lab.

Attack execution is confined to the analysis network. This script is the mechanical
proof of that, run against the artifacts of every verification that produces network
activity, BEFORE the evidence is sanitised and committed. It is a gate, not a report:
a violation exits non-zero and the run must be treated as failed and disclosed.

    check-lab-scope.py --zeek-dir <nsm-analyze output> [--sysmon-json <events.json>]
                       [--allow 192.168.1.0/24] [--out report.json]

What it checks
--------------
1. `conn.log` - every responder address must be inside an allowed lab CIDR. Anything
   else is a potential attack against a host we do not own.
2. Management network - 10.9.0.0/24 carries the orchestrator (108), the AI VM (102)
   and Proxmox (10.9.0.1). It is never a legitimate destination for attack traffic,
   so it is a violation even though it is private.
3. `dns.log` - a query for a name outside the lab is how a fake PoC or a real implant
   reaches its own infrastructure. Reported as a violation unless explicitly allowed.
4. `--sysmon-json` (Sysmon EventID 3, optional but strongly preferred) - attributes
   each destination to the process that opened it, which separates "the target OS did
   its usual telemetry/CRL traffic" from "the tool we ran called out". Only the second
   is a rule-1 breach; the first is noted so the run report can account for it.

Benign link-local, multicast, broadcast and unspecified addresses are ignored.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_ALLOW = ["192.168.1.0/24"]
# Private, but never a legitimate attack destination: the management plane.
MANAGEMENT = ["10.9.0.0/24"]
# Addresses that are noise rather than a destination host.
IGNORED = ["0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
           "255.255.255.255/32", "::1/128", "fe80::/10", "ff00::/8"]

# Images that legitimately talk to Microsoft infrastructure from the target itself.
# Traffic from these is reported as `os_background`, not as a rule-1 violation - but it
# is still listed, because the run report has to account for every external destination.
OS_BACKGROUND = re.compile(
    r"\\(svchost|SearchApp|MoUsoCoreWorker|OneDrive|MicrosoftEdgeUpdate|msedge|"
    r"backgroundTaskHost|CompatTelRunner|WaaSMedicAgent|dllhost|SIHClient|"
    r"MpCmdRun|SecurityHealthService|wermgr|smartscreen)\.exe$", re.IGNORECASE)


def networks(values: list[str]) -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(value, strict=False) for value in values]


def contained(address: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in nets)


def read_zeek_tsv(path: Path) -> list[dict]:
    """Zeek TSV or JSON-lines - nsm-analyze emits TSV, but accept both."""
    rows: list[dict] = []
    if not path.exists():
        return rows
    fields: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                continue
            if not fields:
                continue
            values = line.split("\t")
            rows.append(dict(zip(fields, values)))
    return rows


def load_sysmon(path: Path) -> list[dict]:
    """Accept a JSON array, JSON lines, or {"events": [...]}."""
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            for key in ("events", "records", "Events"):
                if isinstance(value.get(key), list):
                    return value[key]
            return []
        return value if isinstance(value, list) else []
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return rows


def field(event: dict, *names: str):
    for name in names:
        if name in event and event[name] not in (None, ""):
            return event[name]
    data = event.get("EventData") or event.get("event_data") or {}
    if isinstance(data, dict):
        for name in names:
            if data.get(name) not in (None, ""):
                return data[name]
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zeek-dir", type=Path, required=True, help="nsm-analyze output directory")
    parser.add_argument("--sysmon-json", type=Path, default=None, help="Sysmon events (EventID 3) export")
    parser.add_argument("--allow", action="append", default=None, help="allowed lab CIDR (repeatable)")
    parser.add_argument("--allow-domain", action="append", default=[], help="DNS suffix allowed to be queried")
    parser.add_argument("--out", type=Path, default=None, help="write the JSON report here")
    args = parser.parse_args()

    allow = networks(args.allow or DEFAULT_ALLOW)
    management = networks(MANAGEMENT)
    ignored = networks(IGNORED)

    violations: list[dict] = []
    background: list[dict] = []

    # 1 + 2. Connections
    flows: dict[tuple, dict] = {}
    for row in read_zeek_tsv(args.zeek_dir / "conn.log"):
        dst = str(row.get("id.resp_h") or row.get("id_resp_h") or "")
        if not dst or contained(dst, ignored) or contained(dst, allow):
            continue
        key = (str(row.get("id.orig_h") or row.get("id_orig_h") or ""), dst,
               str(row.get("id.resp_p") or row.get("id_resp_p") or ""),
               str(row.get("proto") or ""), str(row.get("service") or ""))
        entry = flows.setdefault(key, {"source": key[0], "destination": dst, "port": key[2],
                                       "proto": key[3], "service": key[4], "connections": 0,
                                       "bytes_sent": 0})
        entry["connections"] += 1
        try:
            entry["bytes_sent"] += int(row.get("orig_bytes") or 0)
        except ValueError:
            pass

    for entry in flows.values():
        scope = "management-plane" if contained(entry["destination"], management) else "outside-lab"
        violations.append({
            "check": "conn.log",
            "severity": "critical",
            "scope": scope,
            "detail": f"{entry['source']} -> {entry['destination']}:{entry['port']}/{entry['proto']}"
                      f" ({entry['connections']} connections, {entry['bytes_sent']} bytes sent)",
            **entry,
        })

    # 3. DNS
    queries: dict[str, int] = defaultdict(int)
    for row in read_zeek_tsv(args.zeek_dir / "dns.log"):
        query = str(row.get("query") or "").strip().lower()
        if not query or query in ("-", "(empty)"):
            continue
        if query.endswith(".local") or query.endswith(".lab") or query.endswith(".arpa"):
            continue
        if any(query.endswith(suffix.lower().lstrip(".")) for suffix in args.allow_domain):
            continue
        queries[query] += 1
    for query, count in sorted(queries.items(), key=lambda kv: -kv[1]):
        violations.append({
            "check": "dns.log", "severity": "high", "scope": "outside-lab",
            "detail": f"resolved external name {query!r} ({count} queries)", "query": query,
        })

    # 4. Process attribution
    attributed = 0
    if args.sysmon_json:
        for event in load_sysmon(args.sysmon_json):
            event_id = str(field(event, "EventId", "EventID", "event_id") or "")
            if event_id != "3":
                continue
            dst = str(field(event, "DestinationIp", "destination_ip") or "")
            if not dst or contained(dst, ignored) or contained(dst, allow):
                continue
            attributed += 1
            image = str(field(event, "Image", "image") or "?")
            record = {
                "check": "sysmon-eid3",
                "detail": f"{image} -> {dst}:{field(event, 'DestinationPort', 'destination_port')}",
                "image": image, "destination": dst,
                "destination_hostname": field(event, "DestinationHostname"),
            }
            if OS_BACKGROUND.search(image):
                background.append({**record, "severity": "info", "scope": "os-background"})
            else:
                violations.append({**record, "severity": "critical", "scope": "outside-lab",
                                   "note": "a non-OS process contacted a host outside the lab"})

    report = {
        "schema_version": 1,
        "rule": "SAFETY RULE 1 - attack traffic never leaves the isolated lab",
        "allowed_networks": [str(net) for net in allow],
        "management_networks": [str(net) for net in management],
        "inputs": {"zeek_dir": str(args.zeek_dir),
                   "sysmon_json": str(args.sysmon_json) if args.sysmon_json else None,
                   "sysmon_attribution_available": bool(args.sysmon_json)},
        "violation_count": len(violations),
        "violations": violations,
        "os_background_destinations": background,
        "verdict": "PASS" if not violations else "VIOLATION",
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"verdict: {report['verdict']}  ({len(violations)} violations, "
          f"{len(background)} OS-background destinations)")
    for violation in violations[:40]:
        print(f"  [{violation['severity']}] {violation['check']}: {violation['detail']}")
    if not args.sysmon_json:
        print("  note: no Sysmon EID 3 supplied - destinations could not be attributed to a process")
    raise SystemExit(0 if not violations else 1)


if __name__ == "__main__":
    main()
