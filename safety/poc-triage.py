#!/usr/bin/env python3
"""SAFETY RULE 2 gate: mechanically screen third-party PoC code BEFORE running it.

A public "PoC" is untrusted code from an anonymous author. A fake PoC does not exploit
the target - it exploits the analyst who runs it: it steals the tokens and SSH keys on
the machine that runs it, installs persistence, or pulls a second stage. This script is
the mechanical first pass over such code.

**It does not clear code. It cannot.** Read the source yourself; treat anything
compiled, packed or obfuscated as unknown-malicious and analyse it statically on REMnux
(VM 105) first. This script exists so that the obvious red flags are never missed and so
that the review leaves a recorded artefact.

    poc-triage.py <path> [--out review-dir] [--json]

Exit code is non-zero when any high or critical finding is present: an unreviewed PoC
must not proceed to execution on that basis alone.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
import sys
from pathlib import Path

TEXT_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".pl", ".rb", ".js",
    ".mjs", ".ts", ".php", ".go", ".c", ".h", ".cpp", ".cs", ".java", ".rs", ".yml",
    ".yaml", ".json", ".toml", ".ini", ".cfg", ".txt", ".md", ".xml", ".html", ".sql",
    ".mk", ".make", "", ".conf", ".service", ".vbs", ".hta",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}

PRIVATE = re.compile(
    r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|255\.|22[4-9]\.|2[3-5]\d\.)")

# (id, severity, regex, why it matters)
RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("credential-theft", "critical", re.compile(
        r"(\.ssh/id_[a-z0-9]+|authorized_keys|\.aws/credentials|\.env\b|GH_TOKEN|GITHUB_TOKEN|"
        r"/etc/shadow|LOCAL APPDATA.{0,40}Login Data|Local State|cookies\.sqlite|"
        r"lsass|SAM\b.{0,20}SYSTEM|\.docker/config\.json|kube/config)", re.IGNORECASE),
     "reads credentials or secrets belonging to the machine that runs it"),
    ("remote-execution", "critical", re.compile(
        r"(curl|wget)\b[^\n|;]{0,200}\|\s*(ba)?sh|"
        r"(iwr|invoke-webrequest|invoke-restmethod|irm)\b[^\n|;]{0,200}\|\s*(iex|invoke-expression)|"
        r"powershell(\.exe)?\s+(-\w+\s+)*-e(nc|ncoded(command)?)?\s|"
        r"certutil\b.{0,60}-urlcache|bitsadmin\b.{0,40}/transfer", re.IGNORECASE),
     "downloads and executes a second stage - the code you reviewed is not the code that runs"),
    ("dynamic-eval", "high", re.compile(
        r"\b(eval|exec)\s*\(\s*(base64|codecs|zlib|marshal|pickle|bytes\.fromhex|__import__)|"
        r"FromBase64String|\[System\.Reflection\.Assembly\]::Load|"
        r"compile\s*\(.{0,40}(decode|decompress)", re.IGNORECASE),
     "executes decoded or decompressed data, hiding its real behaviour from review"),
    ("destructive", "critical", re.compile(
        r"(rm\s+-rf\s+(/|~|\$HOME)(\s|$)|mkfs(\.\w+)?\s|dd\s+if=.{0,40}of=/dev/|"
        r"vssadmin\b.{0,40}delete\s+shadows|wbadmin\b.{0,30}delete|cipher\s+/w|"
        r"format\s+[a-z]:|Remove-Item\s+.{0,30}-Recurse.{0,30}(C:\\|\$env:SystemDrive))", re.IGNORECASE),
     "destroys data on the machine that runs it"),
    ("persistence", "high", re.compile(
        r"(crontab\s+-|/etc/cron\.|systemctl\s+enable|\.bashrc|\.zshrc|LaunchAgents|"
        r"CurrentVersion\\\\?Run|schtasks\b.{0,20}/create|New-ScheduledTask|"
        r"HKCU:.{0,40}Run\b|HKLM:.{0,40}Run\b)", re.IGNORECASE),
     "installs persistence on the machine that runs it"),
    ("install-hook", "high", re.compile(
        r"(cmdclass\s*=|class\s+\w*(Install|Develop|Egg_info)\w*\s*\(|"
        r"\"(pre|post)install\"\s*:|setup_requires|__import__\(.{0,20}\)\s*\.system)", re.IGNORECASE),
     "runs code at dependency-install time, before you ever execute the PoC"),
    ("anti-analysis", "medium", re.compile(
        r"(IsDebuggerPresent|CheckRemoteDebuggerPresent|vmware|virtualbox|qemu|"
        r"sandboxie|wine_get_version|/sys/class/dmi/id/product_name|Win32_ComputerSystem.{0,40}Model)",
        re.IGNORECASE),
     "changes behaviour when it detects analysis - what you observe may not be what a victim gets"),
    ("obfuscation", "medium", re.compile(
        r"(chr\(\s*ord\(|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){12,}|[A-Za-z0-9+/]{300,}={0,2})"),
     "large encoded or escaped blob - review its decoded content before running"),
]


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        chunk = path.open("rb").read(2048)
    except OSError:
        return False
    return b"\x00" not in chunk


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def public_hosts(text: str) -> list[str]:
    found: set[str] = set()
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        address = match.group(0)
        if not PRIVATE.match(address) and address != "0.0.0.0":
            found.add(address)
    for match in re.finditer(r"\bhttps?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text):
        found.add(match.group(1))
    for match in re.finditer(r"\b([a-z0-9-]+\.(?:ngrok\.io|duckdns\.org|no-ip\.\w+|onion|tk|ml|ga|cf|gq|xyz|top|ru|su|zip|mov))\b",
                             text, re.IGNORECASE):
        found.add(match.group(1))
    return sorted(found)


def scan_file(path: Path, root: Path) -> dict:
    relative = str(path.relative_to(root)) if path != root else path.name
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    record = {"file": relative, "bytes": len(raw), "sha256": digest, "findings": []}

    if not is_probably_text(path):
        record["findings"].append({
            "id": "binary-artifact", "severity": "high", "line": 0,
            "why": "compiled or binary artefact - source review is impossible here; "
                   "analyse statically on REMnux (VM 105) before it is ever executed",
            "evidence": f"entropy {entropy(raw[:65536]):.2f}",
        })
        return record

    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    for identifier, severity, pattern, why in RULES:
        for match in pattern.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            evidence = lines[line_number - 1].strip() if line_number <= len(lines) else match.group(0)
            record["findings"].append({
                "id": identifier, "severity": severity, "line": line_number,
                "why": why, "evidence": evidence[:200],
            })
            break  # one finding per rule per file is enough to force a read

    hosts = public_hosts(text)
    if hosts:
        record["findings"].append({
            "id": "external-endpoint", "severity": "high", "line": 0,
            "why": "hard-coded public host. Under SAFETY RULE 1 the PoC may not contact it: "
                   "re-point it at a lab-hosted service on Kali (VM 100) or reject the PoC",
            "evidence": ", ".join(hosts[:12]),
        })

    for blob in re.finditer(r"[A-Za-z0-9+/]{200,}={0,2}", text):
        try:
            decoded = base64.b64decode(blob.group(0)[:4000] + "==", validate=False)
        except Exception:  # noqa: BLE001
            continue
        if decoded[:2] == b"MZ" or decoded[:4] == b"\x7fELF":
            record["findings"].append({
                "id": "embedded-executable", "severity": "critical", "line": 0,
                "why": "a base64 blob decodes to a PE/ELF executable",
                "evidence": blob.group(0)[:60] + "...",
            })
            break
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", type=Path)
    parser.add_argument("--out", type=Path, default=None, help="directory for poc-review.json / .md")
    parser.add_argument("--source-url", default=None, help="where the PoC was obtained from")
    args = parser.parse_args()

    root = args.path.resolve()
    targets = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
    ]
    if not targets:
        print(f"nothing to scan at {root}", file=sys.stderr)
        raise SystemExit(2)

    files = [scan_file(path, root if root.is_dir() else root.parent) for path in targets]
    findings = [{**f, "file": record["file"]} for record in files for f in record["findings"]]
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    blocking = counts.get("critical", 0) + counts.get("high", 0)

    review = {
        "schema_version": 1,
        "rule": "SAFETY RULE 2 - third-party PoC code is reviewed before it is executed",
        "target": str(root),
        "source_url": args.source_url,
        "file_count": len(files),
        "severity_counts": counts,
        "findings": findings,
        "files": files,
        "mechanical_verdict": "NEEDS-HUMAN-REVIEW" if blocking else "NO-AUTOMATED-RED-FLAGS",
        "disclaimer": "A mechanical scan never clears code. Read the source. Treat compiled or "
                      "obfuscated artefacts as unknown-malicious and analyse them on REMnux (VM 105). "
                      "Execution happens only on the isolated target, snapshot before and roll back after.",
    }

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "poc-review.json").write_text(
            json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        lines = [
            "# PoC pre-execution review",
            "",
            f"- Source: {args.source_url or '**RECORD THE URL/COMMIT**'}",
            f"- Target: `{root}`  ({len(files)} files)",
            f"- Mechanical verdict: **{review['mechanical_verdict']}** "
            f"({', '.join(f'{k}: {v}' for k, v in sorted(counts.items())) or 'no findings'})",
            "",
            "## Automated findings",
            "",
        ]
        if findings:
            lines += ["| Severity | File:line | Check | Why it matters | Evidence |", "|---|---|---|---|---|"]
            for finding in sorted(findings, key=lambda f: {"critical": 0, "high": 1, "medium": 2}.get(f["severity"], 3)):
                evidence = finding["evidence"].replace("|", "\\|")
                lines.append(f"| {finding['severity']} | `{finding['file']}:{finding['line']}` | "
                             f"{finding['id']} | {finding['why']} | `{evidence}` |")
        else:
            lines.append("None. This does **not** mean the code is safe.")
        lines += [
            "",
            "## Reviewer's conclusions (complete before executing anything)",
            "",
            "- What the code actually does, in your own words:",
            "- Every network destination it contacts, and where each was re-pointed to in the lab:",
            "- Anything neutralised or removed, and why:",
            "- Static analysis performed on REMnux for compiled/obfuscated parts:",
            "- **Verdict**: `safe-to-run-in-lab` / `safe-after-modification` / `rejected`",
            "- Executed on VM: ____  · snapshot before: ____  · rolled back after: ____",
        ]
        (args.out / "poc-review.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"{review['mechanical_verdict']}: {len(findings)} findings across {len(files)} files "
          f"({', '.join(f'{k}={v}' for k, v in sorted(counts.items())) or 'none'})")
    for finding in findings[:30]:
        print(f"  [{finding['severity']:<8}] {finding['file']}:{finding['line']} {finding['id']} - {finding['evidence'][:90]}")
    raise SystemExit(1 if blocking else 0)


if __name__ == "__main__":
    main()
