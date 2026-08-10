# Playbook: Prepare a Linux target for attack-tool verification

Audience: the lab orchestrator (Codex on the AI VM). Goal: bring the Linux
analysis VM to a clean, rollback-capable, verification-grade baseline whose
telemetry can support Linux Sigma rules and process-attributed network claims.

This playbook provisions instrumentation only. It does not install or run an
attack tool. The absolute rules in `playbooks/lab-safety-rules.md` apply: any
future tool-generated traffic may target only `192.168.1.0/24`.

## Inputs and final state

- **Target VM**: `103` = `ubuntu`, Ubuntu 24.04.4 LTS,
  `192.168.1.51/24` on `vmbr1`, kernel `6.8.0-136-generic` x86-64.
- **Kali self-test peer**: VM `100`, `192.168.1.50`; the only self-test
  destination is TCP `192.168.1.50:18080`.
- **Helpers**: `~/bin/lab-exec`, `~/bin/lab-push`, `~/bin/lab-pull`.
- **Proxmox credentials**: `~/.config/lab/pve.env`, node
  `analysis-proxmox`.
- **Canonical snapshot**: **`linux_verify_baseline`**.
- **Primary endpoint sensor**: Sysmon for Linux for process creation and
  network connections.
- **Required supplement**: auditd for numeric identity, correct post-`exec`
  network ownership, and file writes in the watched verification paths.

## What is installed

Observed package versions on 2026-08-10:

| Package | Version | Purpose |
|---|---|---|
| `sysmonforlinux` | `1.5.2` | EID 1 process and EID 3 network telemetry; EID 11 is configured but not reliable after boot on this VM |
| `sysinternalsebpf` | `1.6.0` | Sysmon's eBPF dependency |
| `auditd` | `1:3.1.2-2.1build1.1` | exec identity, connect attribution, and verification-path file writes |
| `audispd-plugins` | `1:3.1.2-2.1build1.1` | auditd support package |
| `tcpdump` | `4.99.4-3ubuntu4.24.04.1` | full-packet capture |

Repository files and installed hashes:

| Repository file | Installed path | SHA-256 |
|---|---|---|
| `instrumentation/linux/sysmon-verification.xml` | `/opt/lab/sysmon-verification.xml` | `8846f4d95596c90cde00386fbc802194e43b7c6227f8612c457ab9c0e10f6739` |
| `instrumentation/linux/audit-verification.rules` | `/etc/audit/rules.d/lab-verification.rules` | `06448045bae2225fdf4f4bdcd17ea10e17dc254d49592bc364397d04e9882618` |
| `instrumentation/linux/collect-run.sh` | `/opt/lab/collect-run.sh` | `f8fa789660af7dc33d996092a114459fc6990dbcd7f07893f52adf36b22a4bb3` |
| `instrumentation/linux/self-test.sh` | `/opt/lab/self-test.sh` | `f96e06defd9811c4d46a1a148999383ec9f0d13ac0e321bc43d88924833845dc` |

Both `sysmon.service` and `auditd.service` are enabled and survived a reboot.
After the final rollback, both were active; `auditctl -s` reported
`enabled 1`, `failure 1`, `lost 0`.

## Provision or reproduce the baseline

Read the safety rules first, then register Microsoft's Ubuntu 24.04 package
feed and use only signed distribution/vendor packages:

```bash
~/bin/lab-exec 103 bash -lc '
  set -euxo pipefail
  export DEBIAN_FRONTEND=noninteractive
  wget -q https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb \
    -O /tmp/packages-microsoft-prod.deb
  dpkg -i /tmp/packages-microsoft-prod.deb
  apt-get update
  apt-get install -y sysmonforlinux tcpdump auditd audispd-plugins
  install -d -m 0755 /opt/lab
'
```

Push the versioned files and activate them:

```bash
~/bin/lab-push 103 instrumentation/linux/sysmon-verification.xml /opt/lab/sysmon-verification.xml
~/bin/lab-push 103 instrumentation/linux/audit-verification.rules /etc/audit/rules.d/lab-verification.rules
~/bin/lab-push 103 instrumentation/linux/collect-run.sh /opt/lab/collect-run.sh
~/bin/lab-push 103 instrumentation/linux/self-test.sh /opt/lab/self-test.sh

~/bin/lab-exec 103 bash -lc '
  chown root:root /opt/lab/sysmon-verification.xml \
    /etc/audit/rules.d/lab-verification.rules \
    /opt/lab/collect-run.sh /opt/lab/self-test.sh
  chmod 0644 /opt/lab/sysmon-verification.xml
  chmod 0640 /etc/audit/rules.d/lab-verification.rules
  chmod 0755 /opt/lab/collect-run.sh /opt/lab/self-test.sh
  sysmon -accepteula -i /opt/lab/sysmon-verification.xml
  augenrules --load
  systemctl enable auditd
'
```

The Sysmon config deliberately collects every process creation, termination,
network connection, file creation and detected file deletion. SHA-256 image
hashing is enabled. Reverse DNS lookup is deliberately disabled
(`DnsLookup=false`) so collection does not create DNS traffic or replace the
literal destination with a resolver result.

The audit rules collect both 64-bit and 32-bit `execve`/`execveat` and
`connect` syscalls. File write/attribute records are scoped to common Linux
staging and persistence roots:

```text
/tmp  /var/tmp  /dev/shm  /opt  /home  /root
/etc  /usr/local  /var/lib  /var/log
```

The audit configuration deliberately does not set immutable mode (`-e 2`):
this is a reusable lab baseline whose rules must remain updateable. It is not
a production hardening profile.

Verify configuration and reboot persistence before snapshotting:

```bash
~/bin/lab-exec 103 bash -lc '
  systemctl is-enabled sysmon auditd
  systemctl is-active sysmon auditd qemu-guest-agent
  sysmon -c
  auditctl -s
  auditctl -l
  sha256sum /opt/lab/sysmon-verification.xml \
    /etc/audit/rules.d/lab-verification.rules \
    /opt/lab/collect-run.sh /opt/lab/self-test.sh
'
```

Also reboot once and repeat those checks. A local tcpdump diagnostic can prove
the capture path without leaving the VM:

```bash
~/bin/lab-exec 103 bash -lc '
  timeout 8 tcpdump -i lo -c 2 -w /opt/lab/tcpdump-diagnostic.pcap icmp &
  capture_pid=$!
  sleep 1
  ping -c 1 127.0.0.1 >/dev/null
  wait "$capture_pid"
  tcpdump -nn -r /opt/lab/tcpdump-diagnostic.pcap
'
```

The observed diagnostic captured the ICMP request and reply in a 252-byte
pcap. Remove that named diagnostic before snapshotting.

## Collection interface

Start full-packet capture before a verification action, record its UTC
window, then collect endpoint data after the end time:

```bash
~/bin/lab-exec 103 bash -lc '
  install -d -m 0750 /opt/lab/run
  nohup tcpdump -i eth0 -nn -s 0 -U -w /opt/lab/run/capture.pcap \
    >/opt/lab/run/tcpdump.stdout 2>/opt/lab/run/tcpdump.stderr </dev/null &
  echo $! >/opt/lab/run/tcpdump.pid
'

# After the bounded action:
~/bin/lab-exec 103 bash -lc '
  kill -INT "$(cat /opt/lab/run/tcpdump.pid)"
  while kill -0 "$(cat /opt/lab/run/tcpdump.pid)" 2>/dev/null; do sleep 0.1; done
'

~/bin/lab-exec 103 /opt/lab/collect-run.sh \
  --start-utc 2026-08-10T18:00:00Z \
  --end-utc 2026-08-10T18:01:00Z \
  --out-dir /opt/lab/run/telemetry
```

`collect-run.sh` must run as root and emits:

| File | Contents |
|---|---|
| `process.json` | Sysmon EID 1: image, full command line, hashes, parent, user; correlated audit `uid`, `euid`, `suid`, `fsuid`, and `auid` |
| `parent-child.json` | Child and parent image, command line, PID and process GUID |
| `network.json` | Sysmon EID 3 destination/source plus correlated audit owner; see attribution caveat below |
| `file.json` | auditd writes/creates/deletes in watched roots plus Sysmon EID 11/26 if emitted |
| `registry.json` | `status: not_applicable` and an empty event list |
| `manifest.json` | Window, source files, counts, and known limitations |
| `sysmon-journal.jsonl` | Raw journal records containing Sysmon XML |
| `audit-raw.log` | Raw audit records for the window |

The pcap and both raw sources are working evidence, but **do not commit them**.
Commit only reviewed, sanitized telemetry fields selected from the per-
dimension JSON. Raw command lines, audit records, packet payloads, and future
tool output can contain secrets or payload material.

Window selection uses Sysmon XML `System.TimeCreated`, not
`EventData.UtcTime`: on this VM the latter lagged by about 1.2 seconds and
could cross a rounded collection boundary.

## Sigma logsource requirements

Every Linux rule must declare `product: linux`; omitting it can send the rule
to a Windows corpus and produce a meaningless clean zero.

Process rules use the actual primary source:

```yaml
logsource:
  category: process_creation
  product: linux
  service: sysmon
```

Network-connection rules based on raw EID 3 use:

```yaml
logsource:
  category: network_connection
  product: linux
  service: sysmon
```

File rules for the reliable records on this baseline must use auditd, not
claim Sysmon parity:

```yaml
logsource:
  category: file_event
  product: linux
  service: auditd
```

Rules that use collector-enriched fields such as `OwningProcessImage` require
the repository's normalization/correlation pipeline; those fields are not
native raw Sysmon fields.

## Snapshot and rollback

After configuration, reboot checks, local capture checks, and cleanup, create
an online disk snapshot with QEMU guest-agent filesystem freeze:

```bash
# Run on the Proxmox node.
qm snapshot 103 linux_verify_baseline \
  --description '<versions, hashes, limitations, deliberately disabled features>'
qm listsnapshot 103
```

The final Proxmox tasks `qmdelsnapshot` (replacement of the pre-fix snapshot)
and `qmsnapshot` both returned `OK`. The authenticated API listing after the
final test and rollback was:

```text
linux_verify_baseline  snaptime=1786385130  vmstate=0
current                parent=linux_verify_baseline  running=1
```

The AI VM's Proxmox API token can create, delete, update and roll back this
snapshot. It does not have SSH public-key access to `root@10.9.0.1`, so a
literal `qm listsnapshot 103` could not be run from the AI VM; use a Proxmox
node shell for that command. The API listing above is the confirmation that
was actually obtained, not substituted `qm` output.

Before and after every future verification:

```bash
# Run on the Proxmox node, or perform the equivalent authenticated API tasks.
qm rollback 103 linux_verify_baseline
qm start 103
```

Wait for the guest agent, then confirm the three services and four hashes.
The final post-self-test rollback returned `OK`, and the marker, pcap and
`/opt/lab/self-test` output directory were absent afterward.

## Benign self-test and observed evidence

On Kali, start a one-shot listener bound only to the analysis address:

```bash
~/bin/lab-exec 100 bash -lc '
  python3 -c '\''import socket
s=socket.socket(); s.bind(("192.168.1.50",18080)); s.listen(1)
c,a=s.accept(); print(a,c.recv(4096)); c.close(); s.close()'\''
'
```

Run `/opt/lab/self-test.sh` on VM 103. It starts tcpdump, creates a shell child
chain, writes `/tmp/linux-baseline-self-test.txt`, and makes exactly one TCP
connection to Kali. It fails unless every observable dimension has a selected
event and the network event is attributed to `/usr/bin/python3.12`.

Final successful window: `2026-08-10T18:05:45Z` through
`2026-08-10T18:05:48Z`. Sanitized telemetry fields:

```json
{
  "process": {
    "EventID": 1,
    "Image": "/usr/bin/printf",
    "CommandLine": "/usr/bin/printf linux-baseline-self-test\\n",
    "ProcessId": "1058",
    "uid": "0",
    "euid": "0"
  },
  "parent_child": {
    "Image": "/usr/bin/printf",
    "ProcessId": "1058",
    "ParentImage": "/usr/bin/bash",
    "ParentProcessId": "1057",
    "ParentCommandLine": "/bin/bash"
  },
  "file": {
    "Source": "auditd:lab_file",
    "operation": "openat",
    "NameType": "CREATE",
    "TargetFilename": "/tmp/linux-baseline-self-test.txt",
    "Image": "/usr/bin/bash",
    "uid": "0",
    "euid": "0"
  },
  "network": {
    "EventID": 3,
    "SourceIp": "192.168.1.51",
    "SourcePort": "40678",
    "DestinationIp": "192.168.1.50",
    "DestinationPort": "18080",
    "ProcessId": "1057",
    "Image": "/usr/bin/bash",
    "OwningProcessId": "1057",
    "OwningProcessImage": "/usr/bin/python3.12",
    "OwningProcessCommandLine": "/usr/bin/python3 -c import socket; s=socket.create_connection((\"192.168.1.50\", 18080), 5); s.sendall(b\"linux-baseline-self-test\\n\"); s.close()",
    "attribution_source": "Sysmon EID 3 correlated with auditd:lab_connect"
  },
  "registry": {
    "status": "not_applicable",
    "events": []
  },
  "pcap": {
    "bytes": 721,
    "packets": 8,
    "scope": "192.168.1.51:40678 <-> 192.168.1.50:18080 only"
  }
}
```

Kali received `linux-baseline-self-test` from `192.168.1.51`. The pcap showed
the SYN/SYN-ACK/ACK, 25-byte data segment, ACK and FIN exchange; it contained
only the two lab addresses.

## Honest limitations: what Linux verification cannot observe here

- **Registry: no analogue.** Linux has no Windows Registry dimension. Do not
  infer that it was checked from an absent file or an empty result.
- **Sysmon file parity is not present.** EID 11 appeared during boot but did
  not emit for two post-boot `/tmp` creates on Sysmon 1.5.2/kernel 6.8. The
  reliable file source is auditd, limited to the listed watched roots. Writes
  elsewhere are not guaranteed to be observed.
- **Raw EID 3 can carry a stale image after `exec`.** In the self-test it
  correctly recorded PID/destination but kept `/usr/bin/bash`; auditd showed
  the same PID's actual executable as `/usr/bin/python3.12`, and EID 1 supplied
  the matching command line. Raw Sysmon-only Sigma must not assume perfect
  image attribution across a rapid same-PID exec.
- **No Windows identity/integrity model.** Linux has UID/EUID/AUID rather than
  Windows SIDs, tokens and integrity levels. Sysmon's Linux `IntegrityLevel`
  is `no level`; auditd supplies the numeric Linux identities. Guest-agent
  commands have `auid=4294967295` (`unset`).
- **No Windows PE/ETW/Defender/PowerShell/LSASS equivalents.** Fields such as
  `OriginalFileName`, Company and Product are usually `-` for ELF processes;
  there is no Defender channel, Windows PowerShell Script Block channel,
  registry channel, or directly equivalent LSASS EID 10 evidence.
- **A pcap has no process identity by itself.** Tool-specific external-traffic
  claims require the endpoint EID 3/audit correlation in addition to tcpdump.
