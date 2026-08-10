#!/usr/bin/env bash
# Benign baseline proof. Kali must have a listener on 192.168.1.50:18080.
set -euo pipefail

DESTINATION_IP="192.168.1.50"
DESTINATION_PORT="18080"
RUN_DIR="/opt/lab/self-test"
TELEMETRY_DIR="$RUN_DIR/telemetry"
PCAP="$RUN_DIR/linux-baseline-self-test.pcap"
MARKER="/tmp/linux-baseline-self-test.txt"

(( EUID == 0 )) || { echo "self-test.sh must run as root" >&2; exit 1; }
[[ ! -e "$TELEMETRY_DIR" && ! -e "$PCAP" && ! -e "$MARKER" ]] || {
  echo "self-test output already exists; start from linux_verify_baseline" >&2
  exit 1
}

install -d -m 0750 "$RUN_DIR"
timeout --signal=INT 10 tcpdump -i eth0 -nn -s 0 -U -c 8 \
  -w "$PCAP" "host $DESTINATION_IP and tcp port $DESTINATION_PORT" \
  >"$RUN_DIR/tcpdump.stdout" 2>"$RUN_DIR/tcpdump.stderr" &
CAPTURE_PID=$!
sleep 1

START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
/bin/bash -c '/usr/bin/printf "linux-baseline-self-test\n" > /tmp/linux-baseline-self-test.txt
/usr/bin/test -s /tmp/linux-baseline-self-test.txt
/usr/bin/python3 -c '\''import socket; s=socket.create_connection(("192.168.1.50", 18080), 5); s.sendall(b"linux-baseline-self-test\n"); s.close()'\'''
sleep 3
END_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
wait "$CAPTURE_PID" || true

/opt/lab/collect-run.sh \
  --start-utc "$START_UTC" --end-utc "$END_UTC" --out-dir "$TELEMETRY_DIR"

printf 'START_UTC=%s\nEND_UTC=%s\n' "$START_UTC" "$END_UTC"
stat -c 'PCAP_BYTES=%s' "$PCAP"
tcpdump -nn -r "$PCAP"

python3 - "$TELEMETRY_DIR" <<'PY'
import json
import os
import sys

base = sys.argv[1]
selectors = {
    "process": lambda event: event.get("Image") in ("/usr/bin/bash", "/usr/bin/printf", "/usr/bin/test", "/usr/bin/python3") and "linux-baseline-self-test" in str(event),
    "parent-child": lambda event: event.get("Image") in ("/usr/bin/printf", "/usr/bin/test", "/usr/bin/python3") and event.get("ParentImage") == "/usr/bin/bash",
    "file": lambda event: event.get("TargetFilename") == "/tmp/linux-baseline-self-test.txt",
    "network": lambda event: event.get("DestinationIp") == "192.168.1.50" and event.get("DestinationPort") == "18080" and event.get("OwningProcessImage") == "/usr/bin/python3.12",
}
for name, select in selectors.items():
    with open(os.path.join(base, f"{name}.json"), encoding="utf-8") as source:
        events = json.load(source)["events"]
    selected = [event for event in events if select(event)]
    print(f"{name.upper()}={json.dumps(selected, sort_keys=True)}")
    if not selected:
        raise SystemExit(f"missing {name} self-test telemetry")
PY
