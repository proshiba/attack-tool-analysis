#!/usr/bin/env python3
"""SAFETY RULE 1 gate: did our ATTACK ACTIVITY leave the isolated lab?

    check-lab-scope.py --zeek-dir <nsm-analyze output> --tool-image <name> [...]
                       [--sysmon-json <events.json>] [--operator-log <file>]
                       [--allow 192.168.1.0/24] [--out report.json]

What this judges, and what it deliberately does not
---------------------------------------------------
This used to fail a run on ANY packet to an off-lab address. That was never the rule -
the rule is that *what we run* must not reach anything we do not own - and on a real
operating system the packet-level version is unachievable: Windows talks to Microsoft
whether or not we are running a tool. The consequences were concrete. Ordinary Defender
and telemetry traffic was reported as a tool breach, and the way to make a run pass
became to pre-filter the capture to lab-only traffic first, which is a tautology: three
verifications carried a PASS computed that way, proving nothing.

So the subject of the judgement is the attack, established from two kinds of evidence:

1. **The operator record** (`--operator-log`, repeatable) - the C2 framework's own logs
   and config, the listener definitions, the operator command transcripts. A listener
   whose callback address is lab-internal is stronger evidence than any packet capture:
   the implant could not have been pointed outside by design. An off-lab address or host
   named in these files is a violation.
2. **Traffic attributed to the tools we planted** (`--tool-image`, repeatable) - the
   binaries the scenario installed, including the names they were renamed to, and any
   process the scenario injected into. Off-lab traffic from those is a violation.

Everything else off-lab - OS telemetry, Defender, update and notification traffic,
packets arriving from sessions that predate the capture - is RECORDED IN THE MANIFEST
AND NOT JUDGED. Recorded, not deleted: filtering it out of the input is what hid the
problem last time. An allowlist of benign process names was tried and does not hold;
Windows ships new ones (`MpDefenderCoreService.exe` was the one that broke it).

What we can therefore claim is not "nothing left the lab" - that was never true - but
"no traffic attributable to the attack left the lab, and here is everything else that
did". The first is unprovable on a real OS. The second is true and checkable.

A violation exits non-zero: stop the run, preserve the evidence, roll the target back,
and disclose it. Concealing one is a worse failure than the breach.
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

# Addresses and hosts an operator record may legitimately mention without it meaning the
# run contacted them: documentation and provenance citations.
CITATION_HOSTS = re.compile(
    r"(attack\.mitre\.org|lolbas-project\.github\.io|gtfobins\.github\.io|github\.com|"
    r"raw\.githubusercontent\.com|sigmahq\.io|learn\.microsoft\.com|docs\.microsoft\.com)$",
    re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_HOST = re.compile(r"\bhttps?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?::\d+)?", re.IGNORECASE)


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


def matches_tool(image: str, tools: list[str]) -> bool:
    """A declared tool matches on basename or on any path fragment.

    The scenario declares what it planted, including the name it renamed the implant to
    and any process it injected into - `telemetry-service.exe`, `C:\\lab\\stage.exe`,
    `notepad.exe` when an assembly was executed inside it.
    """
    lowered = image.lower().replace("/", "\\")
    base = lowered.rsplit("\\", 1)[-1]
    for tool in tools:
        needle = tool.lower().replace("/", "\\").strip()
        if not needle:
            continue
        if needle == base or needle in lowered:
            return True
    return False


def scan_operator_record(path: Path, allow, ignored) -> list[dict]:
    """Read what the operator actually configured and ran.

    A C2 listener definition carries its own callback address; if that address is
    lab-internal the implant could not have been aimed outside by design. This is
    stronger evidence than a packet capture, and it is available before anything runs.
    """
    findings: list[dict] = []
    if not path.exists():
        return [{"check": "operator-record", "severity": "warning", "file": str(path),
                 "detail": f"declared operator record {path} does not exist"}]
    text = path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), start=1):
        for match in IPV4.finditer(line):
            address = match.group(0)
            if contained(address, ignored) or contained(address, allow):
                continue
            findings.append({
                "check": "operator-record", "severity": "critical", "file": path.name,
                "line": number, "address": address,
                "detail": f"{path.name}:{number} names off-lab address {address}",
                "evidence": line.strip()[:200],
            })
        for match in URL_HOST.finditer(line):
            host = match.group(1)
            if CITATION_HOSTS.search(host):
                continue
            findings.append({
                "check": "operator-record", "severity": "critical", "file": path.name,
                "line": number, "host": host,
                "detail": f"{path.name}:{number} names off-lab host {host}",
                "evidence": line.strip()[:200],
            })
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zeek-dir", type=Path, required=True, help="nsm-analyze output directory")
    parser.add_argument("--sysmon-json", type=Path, default=None, help="Sysmon export (EID 3 network, EID 22 DNS)")
    parser.add_argument("--tool-image", action="append", default=[],
                        help="a binary the scenario planted, the name it was renamed to, or a process "
                             "it injected into (repeatable). Traffic from these is the thing judged.")
    parser.add_argument("--operator-log", action="append", default=[], type=Path,
                        help="C2 server log/config or operator command transcript (repeatable)")
    parser.add_argument("--allow", action="append", default=None, help="allowed lab CIDR (repeatable)")
    parser.add_argument("--allow-domain", action="append", default=[], help="DNS suffix allowed to be queried")
    parser.add_argument("--out", type=Path, default=None, help="write the JSON report here")
    args = parser.parse_args()

    allow = networks(args.allow or DEFAULT_ALLOW)
    management = networks(MANAGEMENT)
    ignored = networks(IGNORED)
    tools = [t for t in args.tool_image if t.strip()]

    violations: list[dict] = []
    manifest: list[dict] = []

    # 1. What the operator configured and ran. Checked first: it decides whether the attack
    #    could ever have been aimed outside, independently of what any capture caught.
    for path in args.operator_log:
        for finding in scan_operator_record(path, allow, ignored):
            (violations if finding["severity"] == "critical" else manifest).append(finding)

    # 2. Attribution: which process opened which destination, and which process asked for
    #    which name. Without this, tool traffic cannot be told from the OS talking to its vendor.
    attribution: dict[str, set] = defaultdict(set)
    dns_by_image: list[tuple] = []
    eid3_seen = eid22_seen = 0
    if args.sysmon_json:
        for event in load_sysmon(args.sysmon_json):
            identifier = event_id(event)
            if identifier == "3":
                eid3_seen += 1
                dst = str(field(event, "DestinationIp", "destination_ip") or "")
                if dst:
                    attribution[dst].add(str(field(event, "Image", "image") or "?"))
            elif identifier == "22":
                eid22_seen += 1
                dns_by_image.append((str(field(event, "Image", "image") or "?"),
                                     str(field(event, "QueryName", "query_name") or "").lower()))

    # 3. Connections, judged only where they are attributable to a declared tool.
    flows: dict[tuple, dict] = {}
    for row in read_zeek_tsv(args.zeek_dir / "conn.log"):
        dst = str(row.get("id.resp_h") or row.get("id_resp_h") or "")
        if not dst or contained(dst, ignored) or contained(dst, allow):
            continue
        key = (str(row.get("id.orig_h") or row.get("id_orig_h") or ""), dst,
               str(row.get("id.resp_p") or row.get("id_resp_p") or ""),
               str(row.get("proto") or ""))
        entry = flows.setdefault(key, {"source": key[0], "destination": dst, "port": key[2],
                                       "proto": key[3], "connections": 0, "bytes_sent": 0,
                                       "packets_sent": 0, "conn_states": []})
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
        images = sorted(attribution.get(entry["destination"], set()))
        scope = "management-plane" if contained(entry["destination"], management) else "outside-lab"
        detail = (f"{entry['source']} -> {entry['destination']}:{entry['port']}/{entry['proto']} "
                  f"({entry['connections']} connections, {entry['bytes_sent']} bytes, "
                  f"{entry['packets_sent']} packets sent)")
        record = {"check": "conn.log", "scope": scope, "detail": detail,
                  "attributed_images": images, **entry}
        attack = [image for image in images if matches_tool(image, tools)]
        if attack:
            violations.append({**record, "severity": "critical", "attack_images": attack,
                               "note": f"attack traffic: {', '.join(attack)} reached an off-lab host"})
        else:
            record["severity"] = "info"
            record["note"] = ("not attributed to a declared tool - recorded, not judged"
                              if images else
                              "no process attribution available - recorded, not judged")
            manifest.append(record)

    # 4. DNS. A name asked of the in-lab resolver sends nothing outside, so what matters is
    #    whether a DECLARED TOOL asked for an off-lab name - which EID 22 attributes directly.
    for image, query in dns_by_image:
        if not query or query.endswith((".local", ".lab", ".arpa")):
            continue
        if any(query.endswith(suffix.lower().lstrip(".")) for suffix in args.allow_domain):
            continue
        if matches_tool(image, tools):
            violations.append({"check": "sysmon-eid22", "severity": "critical", "scope": "outside-lab",
                               "image": image, "query": query,
                               "detail": f"attack tool {image} resolved off-lab name {query!r}"})

    queries: dict[tuple, int] = defaultdict(int)
    for row in read_zeek_tsv(args.zeek_dir / "dns.log"):
        query = str(row.get("query") or "").strip().lower()
        if not query or query in ("-", "(empty)") or query.endswith((".local", ".lab", ".arpa")):
            continue
        if any(query.endswith(suffix.lower().lstrip(".")) for suffix in args.allow_domain):
            continue
        resolver = str(row.get("id.resp_h") or row.get("id_resp_h") or "")
        queries[(query, resolver)] += 1
    for (query, resolver), count in sorted(queries.items(), key=lambda kv: -kv[1]):
        in_lab = bool(resolver) and contained(resolver, allow)
        manifest.append({
            "check": "dns.log", "severity": "info", "query": query, "queries": count,
            "resolver": resolver or "unknown",
            "scope": "external-name-queried-in-lab" if in_lab else "off-lab-resolver",
            "detail": f"{query!r} asked of {'in-lab' if in_lab else 'OFF-LAB'} resolver "
                      f"{resolver or 'unknown'} ({count} queries)",
        })

    attributable = bool(attribution)
    off_lab_flows = len(flows)
    if violations:
        verdict, exit_code = "VIOLATION", 1
    elif off_lab_flows and not attributable:
        # Off-lab traffic exists and nothing can say whose it was. Not a breach, and not a
        # clean bill of health either - the check simply could not be performed.
        verdict, exit_code = "INCONCLUSIVE", 2
    else:
        verdict, exit_code = "PASS", 0

    report = {
        "schema_version": 3,
        "rule": "SAFETY RULE 1 - attack activity never leaves the isolated lab",
        "claim": ("no traffic attributable to the declared attack reached an off-lab host; "
                  "all other off-lab traffic is recorded in the manifest and is not judged"),
        "allowed_networks": [str(net) for net in allow],
        "management_networks": [str(net) for net in management],
        "declared_tool_images": tools,
        "inputs": {
            "zeek_dir": str(args.zeek_dir),
            "sysmon_json": str(args.sysmon_json) if args.sysmon_json else None,
            "operator_logs": [str(p) for p in args.operator_log],
            "sysmon_eid3_events_read": eid3_seen,
            "sysmon_eid22_events_read": eid22_seen,
            "attributed_destinations": len(attribution),
            "attribution_available": attributable,
        },
        "capture_scale": {
            "conn_log_rows": len(read_zeek_tsv(args.zeek_dir / "conn.log")),
            "off_lab_destinations": off_lab_flows,
            "note": "a capture pre-filtered to in-lab traffic cannot show an off-lab destination, "
                    "so 0 here proves nothing on its own - never filter the input",
        },
        "violation_count": len(violations),
        "violations": violations,
        "manifest_count": len(manifest),
        "manifest": manifest,
        "verdict": verdict,
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"verdict: {verdict}  ({len(violations)} attack-attributed violations, "
          f"{len(manifest)} recorded and not judged)")
    for violation in violations[:40]:
        print(f"  [{violation['severity']}] {violation['check']}: {violation['detail']}")
    if not tools:
        print("  note: no --tool-image declared - nothing could be judged as attack traffic")
    if off_lab_flows and not attributable:
        print(f"  note: {off_lab_flows} off-lab destinations and no usable attribution "
              f"({eid3_seen} EID 3 events read)")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
