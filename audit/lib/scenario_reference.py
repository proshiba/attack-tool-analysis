#!/usr/bin/env python3
"""Build a deterministic scenario reference bundle; it makes no audit judgment."""

import csv
import json
import re
import sys
import urllib.request
from pathlib import Path

import yaml

CATALOG = Path("/opt/audit/scratch/attack-tool-analysis")
NEWS = Path("/data/tech-memo/daily-news")
CACHE = Path("/opt/audit/catalog")
LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
GTFO_TREE_URL = "https://api.github.com/repos/GTFOBins/GTFOBins.github.io/git/trees/master?recursive=1"

ALIASES = {
    "mimikatz": ["mimikatz", "sekurlsa", "lsadump", "mimilite", "getpass"],
    "certutil": ["certutil", "certutil.exe", "microsoft-cryptoapi", "certificate utility"],
    "certutil-remote-download": ["certutil", "certutil.exe", "microsoft-cryptoapi", "certificate utility"],
}


def fetch(url: str, path: Path) -> object:
    request = urllib.request.Request(url, headers={"User-Agent": "sigma-audit-reference-builder/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
    path.write_bytes(data)
    return json.loads(data)


def get_aliases(query: str) -> list[str]:
    lower = query.lower()
    values = [query]
    values.extend(ALIASES.get(lower, []))
    if "certutil" in lower:
        values.extend(ALIASES["certutil"])
    return sorted({v.lower() for v in values if v}, key=lambda x: (-len(x), x))


def matches(text: str, aliases: list[str]) -> bool:
    lower = text.lower()
    return any(alias in lower for alias in aliases)


def attack_techniques(query: str, aliases: list[str]) -> tuple[list[dict], list[str]]:
    found = {}
    sources = []
    for path in sorted(CATALOG.glob("tools/*/metadata.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if matches(" ".join([str(data.get("id", "")), str(data.get("name", "")), str(data.get("summary", ""))]), aliases) or query.upper().startswith("T"):
            for item in data.get("attack_techniques", []):
                if not query.upper().startswith("T") or item.get("id", "").upper() == query.upper():
                    found[item.get("id")] = item
                    sources.append(str(path))
    for path in sorted(CATALOG.glob("lol/techniques/*/verification/verification.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        identity = f"{path.parent.parent.name} {data.get('tool', {}).get('name', '')}"
        if matches(identity, aliases) or query.upper().startswith("T"):
            items = list(data.get("observed_techniques", []))
            for technique_id in data.get("scenario", {}).get("attack_mapping", []):
                items.append({"id": technique_id, "name": "name not present in catalog metadata"})
            for item in items:
                if not query.upper().startswith("T") or item.get("id", "").upper() == query.upper():
                    found[item.get("id")] = {"id": item.get("id"), "name": item.get("name")}
                    sources.append(str(path))
    return sorted((v for k, v in found.items() if k), key=lambda x: x["id"]), sorted(set(sources))


def lolbas_entries(aliases: list[str]) -> tuple[list[dict], str]:
    cache = CACHE / "lolbas.json"
    data = fetch(LOLBAS_URL, cache)
    found = [item for item in data if matches(json.dumps(item, ensure_ascii=False), aliases)]
    return found, LOLBAS_URL


def gtfobins_entries(aliases: list[str]) -> tuple[list[dict], str]:
    cache = CACHE / "gtfobins-tree.json"
    tree = fetch(GTFO_TREE_URL, cache)
    entries = []
    for item in tree.get("tree", []):
        path = str(item.get("path", ""))
        if not path.startswith("_gtfobins/") or "/" in path[len("_gtfobins/"):]:
            continue
        name = path.split("/", 1)[1]
        if not matches(name, aliases):
            continue
        url = f"https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/{path}"
        request = urllib.request.Request(url, headers={"User-Agent": "sigma-audit-reference-builder/1"})
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode("utf-8")
        entries.append({"name": name, "source_url": url, "entry": yaml.safe_load(raw)})
    return entries, GTFO_TREE_URL


def csv_cases(aliases: list[str]) -> list[dict]:
    cases = []
    for path in sorted(NEWS.glob("data/**/events.csv")):
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if matches(f"{row.get('title', '')} {row.get('summary', '')}", aliases):
                    cases.append({
                        "date": row.get("date"), "title": row.get("title"),
                        "summary": row.get("summary"), "source_url": row.get("source_url"),
                        "source_file": row.get("source_file"), "origin": "events.csv",
                    })
    return cases


def markdown_cases(aliases: list[str]) -> list[dict]:
    cases = []
    heading = re.compile(r"^####\s+(.+)$", re.M)
    url_re = re.compile(r"https?://[^\s)>]+")
    for path in sorted(NEWS.glob("news/**/*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        sections = list(heading.finditer(text))
        for index, match in enumerate(sections):
            end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
            block = text[match.start():end]
            if not matches(block, aliases):
                continue
            urls = url_re.findall(block)
            bullets = [line.strip()[2:].strip() for line in block.splitlines() if line.strip().startswith("- ")]
            cases.append({
                "date": path.stem, "title": match.group(1).strip(),
                "summary": " ".join(bullets[:5]), "source_url": urls[0].rstrip(".,") if urls else None,
                "source_file": str(path.relative_to(NEWS.parent)), "origin": "news_markdown",
            })
    return cases


def daily_news_cases(aliases: list[str]) -> list[dict]:
    combined = csv_cases(aliases) + markdown_cases(aliases)
    result, seen = [], set()
    for case in combined:
        key = case.get("source_url") or (case.get("source_file"), case.get("title"))
        if key in seen:
            continue
        seen.add(key)
        result.append(case)
    return result


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("Usage: scenario_reference.py <tool-or-technique-id> <outdir>")
    query = sys.argv[1]
    outdir = Path(sys.argv[2]).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    aliases = get_aliases(query)
    techniques, metadata_sources = attack_techniques(query, aliases)
    lolbas, lolbas_source = lolbas_entries(aliases)
    gtfobins, gtfobins_source = gtfobins_entries(aliases)
    cases = daily_news_cases(aliases)
    bundle = {
        "schema_version": 1, "query": query, "aliases": aliases,
        "reference_only": True, "judgment": None,
        "attack_techniques": techniques, "catalog_metadata_sources": metadata_sources,
        "lolbas": {"source_url": lolbas_source, "matches": lolbas},
        "gtfobins": {"source_url": gtfobins_source, "matches": gtfobins},
        "daily_news_cases": cases,
    }
    target = outdir / "reference.json"
    target.write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (outdir / "daily-news-cases.json").write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"reference": str(target), "attack_techniques": len(techniques), "lolbas_matches": len(lolbas), "gtfobins_matches": len(gtfobins), "daily_news_cases": len(cases)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
