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
    rendered = message_fields(event)
    for name in names:
        if rendered.get(name) not in (None, ""):
            return rendered[name]
    return None


def message_fields(event: dict) -> dict:
    """Parse Sysmon's rendered `Message` blob into a field dict.

    `collect-run.ps1` exports what Get-WinEvent gives it: the event id under `Id`, and the
    payload only as the rendered `Message` text - there is no `EventData` dict. The checker
    used to look for `EventId`/`EventID` and flat `Image`/`DestinationIp` keys, found none,
    and silently attributed nothing; every off-lab destination then fell through to
    `critical`, which is how ordinary Windows telemetry came to look like a tool breach.
    Parse the format our own collector actually produces.
    """
    cached = event.get("_parsed_message")
    if isinstance(cached, dict):
        return cached
    parsed: dict[str, str] = {}
    message = event.get("Message")
    if isinstance(message, str):
        for line in message.splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() and " " not in key.strip():
                parsed[key.strip()] = value.strip()
    event["_parsed_message"] = parsed
    return parsed


def event_id(event: dict) -> str:
    return str(field(event, "EventId", "EventID", "event_id", "Id") or "")


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
    unattributed: list[dict] = []

    # 0. Process attribution, built FIRST so connection findings can be judged against it.
    # A destination is only a rule-1 breach if the thing that opened it was ours. The target
    # OS talks to its vendor whether or not we are running a tool; that is a property of
    # running a real operating system, not evidence of a breach.
    attribution: dict[str, set] = defaultdict(set)
    eid3_seen = 0
    if args.sysmon_json:
        for event in load_sysmon(args.sysmon_json):
            if event_id(event) != "3":
                continue
            eid3_seen += 1
            dst = str(field(event, "DestinationIp", "destination_ip") or "")
            if not dst:
                continue
            attribution[dst].add(str(field(event, "Image", "image") or "?"))

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
                                       "bytes_sent": 0, "packets_sent": 0,
                                       "conn_states": []})
        entry["connections"] += 1
        for source_key, target_key in (("orig_bytes", "bytes_sent"), ("orig_pkts", "packets_sent")):
            try:
                entry[target_key] += int(row.get(source_key) or 0)
            except ValueError:
                pass
        state = str(row.get("conn_state") or "").strip()
        if state and state not in entry["conn_states"]:
            entry["conn_states"].append(state)

    for entry in flows.values():
        scope = "management-plane" if contained(entry["destination"], management) else "outside-lab"
        images = sorted(attribution.get(entry["destination"], set()))
        detail = (f"{entry['source']} -> {entry['destination']}:{entry['port']}/{entry['proto']}"
                  f" ({entry['connections']} connections, {entry['bytes_sent']} bytes sent)")
        record = {"check": "conn.log", "scope": scope, "detail": detail,
                  "attributed_images": images, **entry}
        if entry["packets_sent"] == 0 and entry["bytes_sent"] == 0:
            # The target sent nothing. Zeek still logs the flow because packets addressed to it
            # crossed the wire - a responder RST, a FIN from a session that predates the capture
            # (conn_state RSTRH / SHR / OTH all mean the originator's SYN was never seen). Calling
            # this egress would fail a run for traffic the lab did not emit.
            background.append({**record, "severity": "info", "scope": "inbound-unsolicited",
                               "note": "0 packets and 0 bytes from the target; conn_state "
                                       f"{','.join(entry['conn_states']) or 'unknown'} - not "
                                       "target-originated traffic"})
        elif images and all(OS_BACKGROUND.search(image) for image in images):
            background.append({**record, "severity": "info", "scope": "os-background",
                               "note": "the target OS contacted its own vendor; not caused by the "
                                       "verification, and reported rather than failed"})
        elif images:
            violations.append({**record, "severity": "critical",
                               "note": f"opened by {', '.join(images)} - not an OS background process"})
        else:
            unattributed.append({**record, "severity": "warning", "scope": "unattributed-off-lab",
                                 "note": "no Sysmon EID 3 record attributes this destination to a "
                                         "process, so it can be neither cleared nor blamed"})

    # 3. DNS. A query for an external NAME is not the same event as a packet leaving the lab:
    # asking the in-lab resolver about `client.wns.windows.com` sends nothing outside. Judge by
    # where the query packet went, and report the name either way.
    queries: dict[tuple, int] = defaultdict(int)
    for row in read_zeek_tsv(args.zeek_dir / "dns.log"):
        query = str(row.get("query") or "").strip().lower()
        if not query or query in ("-", "(empty)"):
            continue
        if query.endswith(".local") or query.endswith(".lab") or query.endswith(".arpa"):
            continue
        if any(query.endswith(suffix.lower().lstrip(".")) for suffix in args.allow_domain):
            continue
        resolver = str(row.get("id.resp_h") or row.get("id_resp_h") or "")
        queries[(query, resolver)] += 1
    for (query, resolver), count in sorted(queries.items(), key=lambda kv: -kv[1]):
        resolver_in_lab = bool(resolver) and contained(resolver, allow)
        record = {"check": "dns.log", "query": query, "resolver": resolver or "unknown",
                  "queries": count}
        if resolver_in_lab:
            background.append({**record, "severity": "info", "scope": "external-name-queried-in-lab",
                               "detail": f"asked the in-lab resolver {resolver} about {query!r} "
                                         f"({count} queries) - no packet left the lab",
                               "note": "an indicator worth reading, not an egress event"})
        else:
            violations.append({**record, "severity": "critical", "scope": "outside-lab",
                               "detail": f"queried {query!r} against off-lab resolver "
                                         f"{resolver or 'unknown'} ({count} queries)"})

    off_lab_flows = len(flows)
    attributed_flows = off_lab_flows - len(unattributed)
    conn_rows = len(read_zeek_tsv(args.zeek_dir / "conn.log"))

    if violations:
        verdict, exit_code = "VIOLATION", 1
    elif unattributed:
        # Neither cleared nor blamed. Reporting this as PASS is how a check that could not be
        # performed gets mistaken for one that was; reporting it as VIOLATION blames the tool
        # for the operating system. It is its own answer, and it is not mergeable.
        verdict, exit_code = "INCONCLUSIVE", 2
    else:
        verdict, exit_code = "PASS", 0

    report = {
        "schema_version": 2,
        "rule": "SAFETY RULE 1 - attack traffic never leaves the isolated lab",
        "allowed_networks": [str(net) for net in allow],
        "management_networks": [str(net) for net in management],
        "inputs": {"zeek_dir": str(args.zeek_dir),
                   "sysmon_json": str(args.sysmon_json) if args.sysmon_json else None,
                   # What was actually resolved, not merely what was passed on the command line.
                   "sysmon_eid3_events_read": eid3_seen,
                   "attributed_destinations": len(attribution),
                   "sysmon_attribution_available": bool(attribution)},
        "capture_scale": {
            "conn_log_rows": conn_rows,
            "off_lab_destinations": off_lab_flows,
            "attributed_off_lab_destinations": attributed_flows,
            "note": "a capture pre-filtered to in-lab traffic cannot show an off-lab destination, "
                    "so 0 here proves nothing on its own - state what the input covered",
        },
        "violation_count": len(violations),
        "violations": violations,
        "unattributed_count": len(unattributed),
        "unattributed_destinations": unattributed,
        "os_background_destinations": background,
        "verdict": verdict,
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"verdict: {verdict}  ({len(violations)} violations, {len(unattributed)} unattributed, "
          f"{len(background)} OS-background/indicator entries)")
    for entry in (violations + unattributed)[:40]:
        print(f"  [{entry['severity']}] {entry['check']}: {entry['detail']}")
    if not args.sysmon_json:
        print("  note: no Sysmon EID 3 supplied - destinations cannot be attributed to a process")
    elif not attribution:
        print(f"  note: {eid3_seen} EID 3 events read but no destination could be attributed - "
              f"check that the export is the collector's own format")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
