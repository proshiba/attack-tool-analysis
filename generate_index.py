#!/usr/bin/env python3
"""Generate index.json and human-readable README.md files from the catalog.

Source of truth:
  tools/<id>/metadata.json   - one per tool
  lol/sites/<id>.json        - one per living-off-the-land reference site

Outputs (all derived, safe to regenerate):
  index.json                 - aggregate catalog (tools + lol sites)
  tools/<id>/README.md       - per-tool page
  lol/README.md              - LOL sites overview
  README.md                  - project overview + full index table

Usage:
  python3 generate_index.py
"""
import glob
import json
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ROOT, "tools")
LOL_SITES_DIR = os.path.join(ROOT, "lol", "sites")

SCHEMA_VERSION = "1.0"

CATEGORY_LABELS = {
    "credential-access": "Credential Access",
    "privilege-escalation": "Privilege Escalation",
    "discovery": "Discovery / Situational Awareness",
    "lateral-movement": "Lateral Movement",
    "command-and-control": "Command & Control (Remote Ops)",
    "collection": "Collection",
    "defense-evasion": "Defense Evasion",
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def load_tools():
    tools = []
    for meta_path in sorted(glob.glob(os.path.join(TOOLS_DIR, "*", "metadata.json"))):
        tools.append(load_json(meta_path))
    tools.sort(key=lambda t: t["id"])
    return tools


def load_sites():
    sites = [load_json(p) for p in sorted(glob.glob(os.path.join(LOL_SITES_DIR, "*.json")))]
    sites.sort(key=lambda s: s["id"])
    return sites


def cat_label(c):
    return CATEGORY_LABELS.get(c, c)


def tool_readme(t):
    lines = [f"# {t['name']}", "", f"> {t['summary']}", ""]
    lines += ["| | |", "|---|---|"]
    lines.append(f"| **Categories** | {', '.join(cat_label(c) for c in t['categories'])} |")
    lines.append(f"| **Platforms** | {', '.join(t['os'])} |")
    lines.append(f"| **Language** | {t.get('language', 'N/A')} |")
    lines.append(f"| **License** | {t.get('license', 'N/A')} |")
    lines.append(f"| **Type** | {t.get('type', 'N/A')} |")
    lines.append(f"| **Repository** | {t['repository']} |")
    if t.get("homepage"):
        lines.append(f"| **Homepage** | {t['homepage']} |")
    if t.get("mitre_software_id"):
        sid = t["mitre_software_id"]
        lines.append(f"| **MITRE ATT&CK Software** | [{sid}](https://attack.mitre.org/software/{sid}/) |")
    lines.append(f"| **Status** | {t.get('status', 'unknown')} |")
    lines.append(f"| **First seen** | {t.get('first_seen', 'N/A')} |")
    lines.append(f"| **Last reviewed** | {t.get('last_reviewed', 'N/A')} |")
    lines.append("")

    lines += ["## Overview", "", t["description"], ""]

    lines += ["## Related TTPs (MITRE ATT&CK)", ""]
    if t.get("attack_techniques"):
        lines += ["| Technique | ID |", "|---|---|"]
        for tech in t["attack_techniques"]:
            base = tech["id"].split(".")[0]
            sub = tech["id"].split(".")[1] if "." in tech["id"] else None
            url = f"https://attack.mitre.org/techniques/{base}/" + (f"{sub}/" if sub else "")
            lines.append(f"| {tech['name']} | [{tech['id']}]({url}) |")
    else:
        lines.append("_None recorded._")
    lines.append("")

    lines += ["## Usage examples", "", "```text"]
    lines += t.get("usage", ["# see upstream documentation"])
    lines += ["```", ""]

    lines += ["## Detection", ""]
    for d in t.get("detection", []):
        lines.append(f"- {d}")
    lines.append("")

    lines += ["## Update / release history", ""]
    if t.get("release_history"):
        lines += ["| Version | Date | Notes |", "|---|---|---|"]
        for r in t["release_history"]:
            lines.append(f"| {r.get('version', '')} | {r.get('date', '')} | {r.get('notes', '')} |")
    else:
        lines.append("_See `CHANGELOG.md` in this folder. Structured release data lives in "
                     "`metadata.json` -> `release_history` (populated by the refresh workflow)._")
    lines.append("")

    lines += ["## References", ""]
    for r in t.get("references", []):
        lines.append(f"- [{r['title']}]({r['url']})")
    lines.append("")

    lines += ["---", "", "_This file is generated from `metadata.json` by "
              "`generate_index.py`. Edit the JSON, not this file._", ""]
    return "\n".join(lines)


def lol_readme(sites):
    lines = [
        "# Living Off The Land (LOL) reference sites",
        "",
        "Curated catalog of *methodology* references - community projects that document "
        "living-off-the-land techniques, abusable binaries/services, and related tradecraft. "
        "These are techniques and knowledge bases, not standalone tools (which live under "
        "[`../tools`](../tools)).",
        "",
        "Each entry has a machine-readable source file in [`sites/`](sites/).",
        "",
        "| Site | Platform | Focus | Link |",
        "|---|---|---|---|",
    ]
    for s in sites:
        lines.append(
            f"| **{s['name'].split('(')[0].strip()}** | {s['platform']} | "
            f"{s['focus'].split('.')[0].split(' - ')[0][:80]} | [{s['url']}]({s['url']}) |"
        )
    lines.append("")
    for s in sites:
        lines += [f"## {s['name']}", ""]
        lines.append(f"- **URL:** {s['url']}")
        if s.get("repository"):
            lines.append(f"- **Repository:** {s['repository']}")
        lines.append(f"- **Platform:** {s['platform']}")
        lines.append(f"- **Content type:** {s.get('content_type', 'N/A')}")
        lines.append(f"- **Focus:** {s['focus']}")
        lines.append(f"- **Data format:** {s.get('data_format', 'N/A')}")
        if s.get("attack_mapping"):
            lines.append(f"- **ATT&CK mapping:** {s['attack_mapping']}")
        if s.get("example_entries"):
            lines.append(f"- **Examples:** {', '.join(s['example_entries'])}")
        if s.get("notes"):
            lines.append(f"- **Notes:** {s['notes']}")
        lines.append("")
    lines += ["---", "", "_Generated from `sites/*.json` by `generate_index.py`._", ""]
    return "\n".join(lines)


def build_index(tools, sites):
    categories = {}
    for t in tools:
        for c in t["categories"]:
            categories.setdefault(c, {"key": c, "label": cat_label(c), "count": 0})
            categories[c]["count"] += 1

    index = {
        "schema_version": SCHEMA_VERSION,
        "project": "attack-tool-analysis",
        "description": "Catalog of free/OSS post-exploitation tools (privilege escalation, "
                       "credential theft, internal recon, remote operation / C2) and "
                       "living-off-the-land methodology references used in pentest / red team.",
        "generated_by": "generate_index.py",
        "counts": {"tools": len(tools), "lol_sites": len(sites)},
        "categories": sorted(categories.values(), key=lambda c: c["key"]),
        "tools": [
            {
                "id": t["id"],
                "name": t["name"],
                "categories": t["categories"],
                "summary": t["summary"],
                "os": t["os"],
                "language": t.get("language"),
                "license": t.get("license"),
                "type": t.get("type"),
                "repository": t["repository"],
                "homepage": t.get("homepage"),
                "mitre_software_id": t.get("mitre_software_id"),
                "attack_techniques": [x["id"] for x in t.get("attack_techniques", [])],
                "status": t.get("status"),
                "first_seen": t.get("first_seen"),
                "last_reviewed": t.get("last_reviewed"),
                "path": f"tools/{t['id']}/",
                "metadata": f"tools/{t['id']}/metadata.json",
            }
            for t in tools
        ],
        "lol_sites": [
            {
                "id": s["id"],
                "name": s["name"],
                "url": s["url"],
                "repository": s.get("repository"),
                "platform": s["platform"],
                "content_type": s.get("content_type"),
                "focus": s["focus"],
                "path": f"lol/sites/{s['id']}.json",
            }
            for s in sites
        ],
    }
    return index


def root_readme(tools, sites, index):
    by_cat = {}
    for t in tools:
        for c in t["categories"]:
            by_cat.setdefault(c, []).append(t)

    lines = [
        "# attack-tool-analysis",
        "",
        "A curated, structured catalog of **free / open-source post-exploitation tooling** and "
        "**living-off-the-land (LOL) methodology references** for authorized penetration testing "
        "and red team work.",
        "",
        "For each tool the catalog records **what it is, how it is used, related TTPs "
        "(MITRE ATT&CK), detection guidance, and update history**. Everything is stored as JSON "
        "so it can be queried, diffed, and kept current over time.",
        "",
        "> Intended for defensive research, detection engineering, and authorized offensive "
        "security assessments only.",
        "",
        "## Repository layout",
        "",
        "```",
        "index.json              Aggregate catalog (generated) - tools + LOL sites",
        "tools/<id>/",
        "    metadata.json       Source of truth for a tool",
        "    README.md           Human-readable page (generated)",
        "    CHANGELOG.md        Update history for the catalog entry",
        "lol/",
        "    sites/<id>.json     Source of truth for a LOL reference site",
        "    README.md           Overview (generated)",
        "schema/                 JSON Schemas for the above",
        "generate_index.py       Rebuilds index.json + README files from metadata",
        "build_seed.py           One-off seed of the initial dataset",
        "```",
        "",
        f"**Current contents:** {len(tools)} tools, {len(sites)} LOL reference sites.",
        "",
        "## Tools by category",
        "",
    ]
    for c in sorted(by_cat, key=lambda x: cat_label(x)):
        lines.append(f"### {cat_label(c)}")
        lines.append("")
        lines += ["| Tool | Platforms | Language | Summary |", "|---|---|---|---|"]
        for t in sorted(by_cat[c], key=lambda x: x["name"].lower()):
            summ = t["summary"].split(".")[0]
            summ = (summ[:110] + "...") if len(summ) > 113 else summ
            lines.append(
                f"| [{t['name']}](tools/{t['id']}/) | {', '.join(t['os'])} | "
                f"{t.get('language', '')} | {summ} |"
            )
        lines.append("")

    lines += [
        "## Living Off The Land references",
        "",
        "Technique / methodology catalogs (not standalone tools). See [`lol/`](lol/).",
        "",
        "| Site | Platform | Focus |",
        "|---|---|---|",
    ]
    for s in sites:
        lines.append(
            f"| [{s['name'].split('(')[0].strip()}]({s['url']}) | {s['platform']} | "
            f"{s['focus'].split('.')[0].split(' - ')[0][:70]} |"
        )
    lines += [
        "",
        "## Maintaining the catalog",
        "",
        "1. Add or edit a tool: create/modify `tools/<id>/metadata.json` (see "
        "`schema/tool.schema.json`).",
        "2. Add or edit a LOL site: create/modify `lol/sites/<id>.json` (see "
        "`schema/lol-site.schema.json`).",
        "3. Regenerate derived files: `python3 generate_index.py`.",
        "4. Record notable upstream changes in the tool's `CHANGELOG.md` and, when known, in "
        "`metadata.json` -> `release_history`.",
        "",
        "`index.json`, every `tools/<id>/README.md`, and `lol/README.md` are **generated** - "
        "edit the JSON, then rerun the generator.",
        "",
        "## Disclaimer",
        "",
        "This repository documents offensive security tooling for **lawful, authorized** testing "
        "and defensive research. Do not use these tools against systems you do not own or lack "
        "explicit permission to test.",
        "",
    ]
    return "\n".join(lines)


def main():
    tools = load_tools()
    sites = load_sites()

    for t in tools:
        write(os.path.join(TOOLS_DIR, t["id"], "README.md"), tool_readme(t))

    write(os.path.join(ROOT, "lol", "README.md"), lol_readme(sites))

    index = build_index(tools, sites)
    with open(os.path.join(ROOT, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
        f.write("\n")

    write(os.path.join(ROOT, "README.md"), root_readme(tools, sites, index))

    print(f"Generated index.json ({len(tools)} tools, {len(sites)} LOL sites), "
          f"per-tool READMEs, lol/README.md, and root README.md.")


if __name__ == "__main__":
    main()
