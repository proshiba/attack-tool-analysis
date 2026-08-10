#!/usr/bin/env python3
"""SAFETY gate, design time: no scenario may name a target outside the lab.

`check-lab-scope.py` proves after the fact that nothing left the lab. This runs BEFORE
anything is executed, over the written scenario, so a scenario that would have attacked
somebody else's host is caught while it is still a document.

    check-scenario-scope.py <verification-dir-or-file> [--allow-domain example.internal]

Checks
------
1. Every IPv4 literal in `scenarios.md` / `verification.json` / `README.md` must be inside
   an allowed lab range. A public address in a scenario is a critical finding whether it
   is described as a target, a C2, a download source or an "example".
2. Public hostnames and URLs are reported. A scenario may legitimately *cite* a vendor
   write-up or a tool's source repository, so these are `high`, not automatically fatal -
   but each one must be accounted for in the scenario text as a citation rather than as
   something the run will contact.
3. The scenario must carry an explicit **Scope** declaration naming the lab VMs involved
   and stating that every destination is lab-internal. A scenario without one cannot be
   audited and is rejected.
4. Wording that implies acting against systems we do not own (scanning public ranges,
   "real target", "production", "customer", "internet-wide") is flagged for the reviewer.

Exit code is non-zero on any critical finding.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

LAB_IPV4 = re.compile(r"^(192\.168\.1\.|10\.9\.0\.|127\.|0\.0\.0\.0$)")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"\bhttps?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})(?::\d+)?(/[^\s)\"'>]*)?")
SCOPE_HEADING = re.compile(r"^#{1,6}\s*(scope|scope declaration|lab scope)\b", re.IGNORECASE | re.MULTILINE)

# `file version 1.0.0.0` and `mimikatz 2.2.0.0` are version quads, not destinations, and a
# verification is REQUIRED to record the binary version it ran. The window is deliberately
# small - the word must sit on the same line, within a few characters before the number -
# and a match downgrades the finding rather than dropping it.
VERSION_LOOKBEHIND = 28
VERSION_CONTEXT = re.compile(
    r"(version|assembly|build|revision|release|schema)\b[\s:=\"'`\[(]*$", re.IGNORECASE)

# Citing a write-up is fine; contacting it during a run is not. These are the hosts a
# scenario is expected to cite, so they are reported at `info` instead of `high`.
CITATION_HOSTS = re.compile(
    r"(attack\.mitre\.org|lolbas-project\.github\.io|gtfobins\.github\.io|github\.com|"
    r"sigmahq\.io|docs\.microsoft\.com|learn\.microsoft\.com|nvd\.nist\.gov|cve\.org|"
    r"cve\.mitre\.org|thedfirreport\.com|unit42\.paloaltonetworks\.com|"
    r"securelist\.com|welivesecurity\.com|research\.checkpoint\.com)$", re.IGNORECASE)

RISKY_WORDING = [
    (re.compile(r"\b(shodan|censys|internet[- ]wide|mass[- ]scan|masscan\s+0\.0\.0\.0/0)\b", re.I),
     "implies scanning hosts on the public internet"),
    (re.compile(r"\b(real|live|production|customer|client|third[- ]party)\s+(target|host|server|system|environment)\b", re.I),
     "implies acting against a system we do not own"),
    (re.compile(r"\b(exfiltrat\w+)\s+to\s+(?!.*(192\.168\.1\.|10\.9\.0\.|kali|lab))", re.I),
     "exfiltration destination is not stated as lab-internal"),
    (re.compile(r"\b(public|external)\s+(c2|command[- ]and[- ]control|teamserver|listener)\b", re.I),
     "C2 infrastructure must be lab-hosted"),
]

TEXT_FILES = ("scenarios.md", "README.md", "verification.json")


def gather(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files = [target / name for name in TEXT_FILES]
    return [p for p in files if p.exists()] or [
        p for p in sorted(target.rglob("*")) if p.suffix in {".md", ".json"} and p.is_file()
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", type=Path)
    parser.add_argument("--allow-domain", action="append", default=[])
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    files = gather(args.target.resolve())
    if not files:
        print(f"nothing to check at {args.target}", file=sys.stderr)
        raise SystemExit(2)

    findings: list[dict] = []
    scope_declared = False

    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        name = path.name
        if SCOPE_HEADING.search(text) or '"scope"' in text or '"lab_scope"' in text:
            scope_declared = True

        for match in IPV4.finditer(text):
            address = match.group(0)
            if LAB_IPV4.match(address):
                continue
            line = text.count("\n", 0, match.start()) + 1
            preceding = text[max(0, match.start() - VERSION_LOOKBEHIND):match.start()].rsplit("\n", 1)[-1]
            if VERSION_CONTEXT.search(preceding):
                findings.append({
                    "severity": "high", "check": "ipv4-like-version", "file": name, "line": line,
                    "detail": f"{address} reads as a version quad, not an address",
                    "why": "a recorded binary version is not a destination - but confirm the run "
                           "never contacts it as one.",
                    "evidence": text.splitlines()[line - 1].strip()[:200],
                })
                continue
            findings.append({
                "severity": "critical", "check": "non-lab-ipv4", "file": name, "line": line,
                "detail": f"scenario names the non-lab address {address}",
                "why": "SAFETY RULE 1: attack activity is confined to the lab. A public or "
                       "off-lab address in a scenario is a target we do not own.",
                "evidence": text.splitlines()[line - 1].strip()[:200],
            })

        for match in URL.finditer(text):
            host = match.group(1)
            if any(host.lower().endswith(d.lower().lstrip(".")) for d in args.allow_domain):
                continue
            line = text.count("\n", 0, match.start()) + 1
            citation = bool(CITATION_HOSTS.search(host))
            findings.append({
                "severity": "info" if citation else "high",
                "check": "citation-host" if citation else "external-host",
                "file": name, "line": line,
                "detail": f"{'cited' if citation else 'external'} host {host}",
                "why": "a cited write-up is fine; a host the run would CONTACT is not. "
                       "Confirm this appears only as a reference." if citation else
                       "SAFETY RULE 1: if the run contacts this host, the scenario is rejected. "
                       "Re-host the payload on Kali (VM 100).",
                "evidence": text.splitlines()[line - 1].strip()[:200],
            })

        for pattern, why in RISKY_WORDING:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append({
                    "severity": "high", "check": "risky-wording", "file": name, "line": line,
                    "detail": match.group(0), "why": why,
                    "evidence": text.splitlines()[line - 1].strip()[:200],
                })

    if not scope_declared:
        findings.append({
            "severity": "critical", "check": "scope-declaration-missing",
            "file": str(args.target), "line": 0,
            "detail": "no Scope declaration found",
            "why": "every scenario must state the lab VMs involved and that all destinations are "
                   "lab-internal, so the safety audit has something to check against.",
            "evidence": "",
        })

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

    report = {
        "schema_version": 1,
        "rule": "SAFETY RULE 1 at design time - no scenario targets anything outside the lab",
        "target": str(args.target),
        "files_checked": [str(p) for p in files],
        "scope_declaration_present": scope_declared,
        "severity_counts": counts,
        "findings": findings,
        "verdict": "REJECT" if counts.get("critical") else ("REVIEW" if counts.get("high") else "PASS"),
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"verdict: {report['verdict']}  "
          f"({', '.join(f'{k}={v}' for k, v in sorted(counts.items())) or 'no findings'})")
    for finding in findings[:40]:
        if finding["severity"] == "info":
            continue
        print(f"  [{finding['severity']:<8}] {finding['file']}:{finding['line']} "
              f"{finding['check']} - {finding['detail']}")
    raise SystemExit(1 if counts.get("critical") else 0)


if __name__ == "__main__":
    main()
