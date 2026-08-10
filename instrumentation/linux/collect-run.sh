#!/usr/bin/env bash
# Collect a bounded Linux verification window from Sysmon and auditd.
set -euo pipefail

usage() {
  echo "usage: collect-run.sh --start-utc <ISO-8601> --end-utc <ISO-8601> --out-dir <path>" >&2
  exit 2
}

START_UTC=""
END_UTC=""
OUT_DIR=""
while (($#)); do
  case "$1" in
    --start-utc) (($# >= 2)) || usage; START_UTC="$2"; shift 2 ;;
    --end-utc) (($# >= 2)) || usage; END_UTC="$2"; shift 2 ;;
    --out-dir) (($# >= 2)) || usage; OUT_DIR="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ -n "$START_UTC" && -n "$END_UTC" && -n "$OUT_DIR" ]] || usage
(( EUID == 0 )) || { echo "collect-run.sh must run as root" >&2; exit 1; }

START_EPOCH=$(date -u -d "$START_UTC" +%s) || usage
END_EPOCH=$(date -u -d "$END_UTC" +%s) || usage
(( START_EPOCH <= END_EPOCH )) || { echo "start must not be after end" >&2; exit 2; }
START_JOURNAL=$(date -u -d "@$START_EPOCH" '+%Y-%m-%d %H:%M:%S UTC')
END_JOURNAL=$(date -u -d "@$END_EPOCH" '+%Y-%m-%d %H:%M:%S UTC')

install -d -m 0750 "$OUT_DIR"
SYSMON_RAW="$OUT_DIR/sysmon-journal.jsonl"
AUDIT_RAW="$OUT_DIR/audit-raw.log"

# JSON Lines preserves embedded newlines in long CommandLine fields while
# retaining the complete raw journal record around each Sysmon XML message.
journalctl -u sysmon \
  --since "$START_JOURNAL" --until "$END_JOURNAL" \
  --output=json --no-pager > "$SYSMON_RAW"

# audit.log is filtered by its kernel audit timestamp so the raw supplement has
# exactly the same requested window. The parser below performs a second check.
python3 - "$START_EPOCH" "$END_EPOCH" /var/log/audit/audit.log "$AUDIT_RAW" <<'PY'
import re
import sys

start, end = map(float, sys.argv[1:3])
source, destination = sys.argv[3:5]
stamp = re.compile(r"msg=audit\(([0-9]+(?:\.[0-9]+)?):")
with open(destination, "w", encoding="utf-8") as output:
    try:
        audit_log = open(source, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        sys.exit(0)
    with audit_log:
        for line in audit_log:
            match = stamp.search(line)
            if match and start <= float(match.group(1)) <= end:
                output.write(line)
PY

python3 - "$START_EPOCH" "$END_EPOCH" "$OUT_DIR" <<'PY'
import datetime as dt
import json
import os
import pwd
import re
import shlex
import socket
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

start_epoch, end_epoch = map(float, sys.argv[1:3])
out_dir = sys.argv[3]

def parse_sysmon_time(value):
    value = value.strip().replace(" ", "T")
    if not value.endswith("Z"):
        value += "Z"
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()

def event_envelope(event_id, system, data):
    result = {
        "EventID": event_id,
        "EventRecordID": system.findtext("EventRecordID"),
        "Computer": system.findtext("Computer"),
        "SystemTime": system.find("TimeCreated").attrib.get("SystemTime"),
        "SystemUserId": system.find("Security").attrib.get("UserId"),
    }
    result.update(data)
    return result

sysmon_events = []
with open(os.path.join(out_dir, "sysmon-journal.jsonl"), encoding="utf-8") as source:
    for number, line in enumerate(source, 1):
        if not line.strip():
            continue
        try:
            journal_record = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"invalid journal JSON at raw line {number}: {error}")
        message = journal_record.get("MESSAGE", "")
        if not message.startswith("<Event>"):
            continue
        try:
            root = ET.fromstring(message)
        except ET.ParseError as error:
            raise SystemExit(f"invalid Sysmon XML in raw journal record {number}: {error}")
        system = root.find("System")
        event_id = int(system.findtext("EventID"))
        data = {
            item.attrib["Name"]: item.text or ""
            for item in root.findall("./EventData/Data")
        }
        event = event_envelope(event_id, system, data)
        # Linux Sysmon's EventData.UtcTime can lag System.TimeCreated by more
        # than a second on this kernel. TimeCreated is also what journald uses,
        # so it is the stable boundary for a requested collection window.
        event_time = parse_sysmon_time(event["SystemTime"])
        if start_epoch <= event_time <= end_epoch:
            sysmon_events.append(event)

audit_stamp = re.compile(r"msg=audit\(([0-9]+(?:\.[0-9]+)?):([0-9]+)\)")
audit_type = re.compile(r"^type=([^ ]+)")
audit_field = re.compile(r'(?:^|\s)([A-Za-z0-9_]+)=("(?:\\.|[^"])*"|\S+)')
audit_groups = defaultdict(lambda: {"records": []})
with open(os.path.join(out_dir, "audit-raw.log"), encoding="utf-8", errors="replace") as source:
    for line in source:
        stamp = audit_stamp.search(line)
        record_type = audit_type.search(line)
        if not stamp or not record_type:
            continue
        epoch, serial = stamp.groups()
        group = audit_groups[serial]
        group["epoch"] = float(epoch)
        group["records"].append((record_type.group(1), line.rstrip("\n")))

def fields(line):
    parsed = {}
    for key, raw in audit_field.findall(line):
        if len(raw) >= 2 and raw[0] == raw[-1] == '"':
            try:
                parsed[key] = shlex.split(raw)[0]
            except (ValueError, IndexError):
                parsed[key] = raw[1:-1]
        else:
            parsed[key] = raw
    return parsed

def decode_proctitle(value):
    if not value or not re.fullmatch(r"[0-9A-Fa-f]+", value):
        return None
    try:
        argv = bytes.fromhex(value).split(b"\0")
        return shlex.join(part.decode("utf-8", "replace") for part in argv if part)
    except ValueError:
        return None

audit_exec = []
audit_connect = []
audit_file_events = []
for serial, group in audit_groups.items():
    syscall = None
    proctitle = None
    sockaddr = None
    paths = []
    for record_type, line in group["records"]:
        parsed = fields(line)
        if record_type == "SYSCALL":
            syscall = parsed
        elif record_type == "PROCTITLE":
            proctitle = parsed.get("proctitle")
        elif record_type == "SOCKADDR":
            sockaddr = parsed.get("saddr")
        elif record_type == "PATH":
            paths.append(parsed)
    if syscall is None:
        continue
    command_line = decode_proctitle(proctitle)
    if syscall.get("key") == "lab_exec":
        audit_exec.append({
            "serial": serial,
            "epoch": group["epoch"],
            "pid": syscall.get("pid"),
            "ppid": syscall.get("ppid"),
            "uid": syscall.get("uid"),
            "euid": syscall.get("euid"),
            "suid": syscall.get("suid"),
            "fsuid": syscall.get("fsuid"),
            "auid": syscall.get("auid"),
            "exe": syscall.get("exe"),
            "audit_command_line": command_line,
        })
    elif syscall.get("key") == "lab_connect" and sockaddr:
        try:
            address = bytes.fromhex(sockaddr)
        except ValueError:
            address = b""
        destination_ip = None
        destination_port = None
        if address[:2] == b"\x02\x00" and len(address) >= 8:
            destination_port = str(int.from_bytes(address[2:4], "big"))
            destination_ip = socket.inet_ntop(socket.AF_INET, address[4:8])
        elif address[:2] == b"\x0a\x00" and len(address) >= 24:
            destination_port = str(int.from_bytes(address[2:4], "big"))
            destination_ip = socket.inet_ntop(socket.AF_INET6, address[8:24])
        if destination_ip:
            audit_connect.append({
                "serial": serial,
                "epoch": group["epoch"],
                "pid": syscall.get("pid"),
                "ppid": syscall.get("ppid"),
                "uid": syscall.get("uid"),
                "euid": syscall.get("euid"),
                "suid": syscall.get("suid"),
                "fsuid": syscall.get("fsuid"),
                "auid": syscall.get("auid"),
                "exe": syscall.get("exe"),
                "command_line": command_line,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "syscall_success": syscall.get("success"),
                "syscall_exit": syscall.get("exit"),
            })
    elif syscall.get("key") == "lab_file":
        syscall_names = {
            "1": "write", "2": "open", "87": "unlink", "90": "chmod",
            "257": "openat", "263": "unlinkat", "268": "fchmodat",
        }
        for path in paths:
            if path.get("nametype") == "PARENT" or not path.get("name"):
                continue
            audit_file_events.append({
                "Source": "auditd:lab_file",
                "EventID": "auditd",
                "UtcTime": dt.datetime.fromtimestamp(
                    group["epoch"], dt.timezone.utc
                ).isoformat(),
                "audit_serial": serial,
                "operation": syscall_names.get(syscall.get("syscall"), "syscall"),
                "syscall_number": syscall.get("syscall"),
                "success": syscall.get("success"),
                "ProcessId": syscall.get("pid"),
                "ParentProcessId": syscall.get("ppid"),
                "Image": syscall.get("exe"),
                "CommandLine": command_line,
                "uid": syscall.get("uid"),
                "euid": syscall.get("euid"),
                "suid": syscall.get("suid"),
                "fsuid": syscall.get("fsuid"),
                "auid": syscall.get("auid"),
                "TargetFilename": path.get("name"),
                "NameType": path.get("nametype"),
                "mode": path.get("mode"),
            })

def numeric_identity(user):
    try:
        return str(pwd.getpwnam(user).pw_uid)
    except KeyError:
        return None

def enrich_identity(event):
    pid = str(event.get("ProcessId", ""))
    event_epoch = parse_sysmon_time(event["SystemTime"])
    matches = [item for item in audit_exec
               if item["pid"] == pid and abs(item["epoch"] - event_epoch) <= 2.0]
    if matches:
        identity = min(matches, key=lambda item: abs(item["epoch"] - event_epoch))
        for field in ("uid", "euid", "suid", "fsuid", "auid"):
            event[field] = identity[field]
        event["identity_source"] = "auditd:lab_exec"
        event["audit_serial"] = identity["serial"]
        return
    resolved = numeric_identity(event.get("User", ""))
    event["uid"] = resolved
    event["euid"] = resolved
    event["suid"] = None
    event["fsuid"] = None
    event["auid"] = None
    event["identity_source"] = "sysmon_user_fallback"

process_events = [dict(event) for event in sysmon_events if event["EventID"] == 1]
for event in process_events:
    enrich_identity(event)

parent_child_events = [{
    "EventID": event["EventID"],
    "UtcTime": event.get("UtcTime"),
    "ProcessGuid": event.get("ProcessGuid"),
    "ProcessId": event.get("ProcessId"),
    "Image": event.get("Image"),
    "CommandLine": event.get("CommandLine"),
    "User": event.get("User"),
    "uid": event.get("uid"),
    "euid": event.get("euid"),
    "ParentProcessGuid": event.get("ParentProcessGuid"),
    "ParentProcessId": event.get("ParentProcessId"),
    "ParentImage": event.get("ParentImage"),
    "ParentCommandLine": event.get("ParentCommandLine"),
    "ParentUser": event.get("ParentUser"),
} for event in process_events]

network_events = [dict(event) for event in sysmon_events if event["EventID"] == 3]
for event in network_events:
    event_epoch = parse_sysmon_time(event["SystemTime"])
    matches = [item for item in audit_connect
               if item["pid"] == str(event.get("ProcessId", ""))
               and item["destination_ip"] == event.get("DestinationIp")
               and item["destination_port"] == str(event.get("DestinationPort", ""))
               and abs(item["epoch"] - event_epoch) <= 2.0]
    if matches:
        owner = min(matches, key=lambda item: abs(item["epoch"] - event_epoch))
        event["OwningProcessImage"] = owner["exe"]
        event["OwningProcessId"] = owner["pid"]
        event["uid"] = owner["uid"]
        event["euid"] = owner["euid"]
        event["attribution_source"] = "Sysmon EID 3 correlated with auditd:lab_connect"
        event["audit_serial"] = owner["serial"]
        process_matches = [item for item in process_events
                           if str(item.get("ProcessId", "")) == owner["pid"]
                           and item.get("Image") == owner["exe"]
                           and abs(parse_sysmon_time(item["SystemTime"]) - event_epoch) <= 2.0]
        if process_matches:
            process_owner = min(
                process_matches,
                key=lambda item: abs(parse_sysmon_time(item["SystemTime"]) - event_epoch),
            )
            event["OwningProcessGuid"] = process_owner.get("ProcessGuid")
            event["OwningProcessCommandLine"] = process_owner.get("CommandLine")
            event["command_line_source"] = "Sysmon EID 1 matched by PID, image, and time"
        else:
            event["OwningProcessCommandLine"] = owner["command_line"]
            event["command_line_source"] = "auditd PROCTITLE fallback"
    else:
        event["OwningProcessImage"] = event.get("Image")
        event["OwningProcessCommandLine"] = None
        event["OwningProcessId"] = event.get("ProcessId")
        event["attribution_source"] = "Sysmon EID 3 only"
sysmon_file_events = [dict(event) for event in sysmon_events if event["EventID"] in (11, 26)]
for event in sysmon_file_events:
    event["Source"] = f"Sysmon for Linux EID {event['EventID']}"
file_events = sysmon_file_events + audit_file_events

def write_dimension(filename, dimension, source, events, status="collected", note=None):
    payload = {
        "dimension": dimension,
        "status": status,
        "source": source,
        "events": events,
    }
    if note:
        payload["note"] = note
    with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2, sort_keys=True)
        output.write("\n")

write_dimension("process.json", "process image and command line",
                "Sysmon for Linux EID 1 enriched from auditd lab_exec", process_events)
write_dimension("parent-child.json", "parent-child process relationship",
                "Sysmon for Linux EID 1", parent_child_events)
write_dimension("network.json", "network connection with owning process",
                "Sysmon for Linux EID 3 enriched from auditd lab_connect", network_events)
write_dimension("file.json", "file write/create/delete under verification paths",
                "auditd lab_file watches, plus Sysmon for Linux EID 11/26 when emitted",
                file_events)
write_dimension("registry.json", "registry", "not applicable on Linux", [],
                status="not_applicable",
                note="Linux has no Windows Registry or direct registry telemetry analogue.")

manifest = {
    "collector": "/opt/lab/collect-run.sh",
    "start_utc": dt.datetime.fromtimestamp(start_epoch, dt.timezone.utc).isoformat(),
    "end_utc": dt.datetime.fromtimestamp(end_epoch, dt.timezone.utc).isoformat(),
    "raw_sources": ["sysmon-journal.jsonl", "audit-raw.log"],
    "counts": {
        "process": len(process_events),
        "parent_child": len(parent_child_events),
        "network": len(network_events),
        "file": len(file_events),
        "registry": 0,
    },
    "limitations": [
        "No Linux analogue exists for the Windows Registry dimension.",
        "On Sysmon 1.5.2/kernel 6.8, EID 11 was present at boot but did not reliably emit for post-boot test creates.",
        "The auditd file fallback covers common staging/persistence roots rather than the entire filesystem; see audit-verification.rules.",
        "Distinct uid/euid values come from correlated auditd exec records; fallback identity is Sysmon User resolution.",
        "Window selection uses Sysmon System.TimeCreated because EventData.UtcTime can lag on Linux.",
        "Sysmon EID 3 can retain a pre-exec Image; OwningProcess* fields are correlated from auditd by PID, destination, and time.",
        "Packet capture is collected separately with tcpdump and is not embedded in endpoint JSON.",
    ],
}
with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as output:
    json.dump(manifest, output, indent=2, sort_keys=True)
    output.write("\n")
PY

chmod 0640 "$OUT_DIR"/*
echo "collected $START_UTC through $END_UTC into $OUT_DIR"
