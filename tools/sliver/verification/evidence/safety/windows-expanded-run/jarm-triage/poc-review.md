# Salesforce JARM v1.0 active-fingerprint script review

- Source: `https://github.com/salesforce/jarm`
- Commit: `2c0cf5ce8418c7a1d03edb219acea3c18e068289`
- File: `jarm.py`
- SHA-256:
  `8b44d084d8fa49307d401a9be5ec4cd2e6fde6705ee913684d08c301f14524a1`

## Mechanical triage

The adjacent fresh `poc-review.json` reports two human-review findings. The
byte strings are fixed TLS extension encodings used to construct the ten JARM
ClientHello probes, not decoded or evaluated code. `8.8.4.4` occurs only in an
argument-help example, and `opensource.org` occurs only in the license comment;
neither is a default, lookup, socket target, or second stage.

## Source review and destination accounting

The complete 518-line source was read. It uses only Python standard-library
modules unless the unused `--proxy` option is selected. The script parses a
single operator-supplied host/port, opens ten TCP sockets to exactly that
destination, sends fixed TLS ClientHello variants, reads each ServerHello, and
prints the resulting fuzzy hash. It has no update check, install hook,
credential access, persistence, subprocess, shell invocation, file download,
or embedded executable. The run does not use input files, proxying, or output
files.

## Verdict

**`safe-to-run-in-lab`** on NSM VM 106 only, with the exact reviewed hash and
the literal destination `192.168.1.50:18443`. The script must not receive a
hostname, public address, management address, alternate port, proxy, or input
list. Its ten active probes are permitted only while the Kali lab HTTPS
listener is live. It is an analysis measurement, not a payload or C2
component, and is never run on VM 102, VM 108, VM 109, or VM 110.
