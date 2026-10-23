"""Turn raw collected items into Findings.

Three paths, merged by CVE:
- KEV records are structured, so they map directly.
- Free text (advisories, blogs, Reddit) goes through the LLM when one is configured, otherwise a regex
  fallback that finds CVE IDs, ATT&CK IDs, product names from the inventory and a few URI patterns.
- Offline fixtures carry the recorded output of the LLM step so demos run without API keys.
"""
from __future__ import annotations

import re

from .inventory import Inventory
from .models import Finding, RawItem

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
URI_RE = re.compile(
    r"(?<![\w/])/(?:[\w\-.%~]+/)*[\w\-.%~]*\.(?:aspx|ashx|asmx|cgi|jsp|php|pl)\b|/api/v\d+/[\w\-./]+"
)


def from_kev(raw: RawItem) -> Finding:
    kev = raw.extra
    product = f"{kev.get('vendorProject', '')} {kev.get('product', '')}".strip()
    return Finding(
        id=raw.id,
        title=raw.title,
        summary=raw.text,
        url=raw.url,
        cves=[raw.id],
        products=[product, kev.get("product", "")],
        kev=True,
        kev_added=kev.get("dateAdded", ""),
        ransomware=kev.get("knownRansomwareCampaignUse", "") == "Known",
        references=[raw.url],
        sources=["CISA KEV"],
    )


def heuristic(raw: RawItem, inventory: Inventory) -> Finding:
    text = f"{raw.title}\n{raw.text}"
    products = [
        name for a in inventory.assets for name in [a.product, *a.aliases]
        if re.search(rf"(?<![a-z0-9]){re.escape(name.lower())}(?![a-z0-9])", text.lower())
    ]
    cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text)))
    uris = list(dict.fromkeys(URI_RE.findall(text)))
    return Finding(
        id=cves[0] if cves else raw.id,
        title=raw.title,
        summary=raw.text[:600],
        url=raw.url,
        cves=cves,
        products=list(dict.fromkeys(products)),
        iocs={"uri": uris} if uris else {},
        techniques=list(dict.fromkeys(TECH_RE.findall(text))),
        references=[raw.url],
        sources=[raw.source],
    )


def from_recorded(raw: RawItem, recorded: dict) -> Finding:
    data = {"id": raw.id, "title": raw.title, "url": raw.url, "summary": raw.text[:600],
            "references": [raw.url], "sources": [raw.source], **recorded}
    return Finding.from_dict(data)


def apply_kev(finding: Finding, kev_index: dict[str, dict]) -> Finding:
    for cve in finding.cves:
        entry = kev_index.get(cve)
        if entry:
            finding.kev = True
            finding.kev_added = entry.get("dateAdded", finding.kev_added)
            finding.ransomware = finding.ransomware or entry.get("knownRansomwareCampaignUse") == "Known"
            if "CISA KEV" not in finding.sources:
                finding.sources.append("CISA KEV")
    return finding


def merge(a: Finding, b: Finding) -> Finding:
    """Combine two findings about the same CVE. `a` wins on scalar fields it already has."""
    def union(x: list, y: list) -> list:
        return list(dict.fromkeys([*x, *y]))

    iocs = {k: union(a.iocs.get(k, []), b.iocs.get(k, [])) for k in {*a.iocs, *b.iocs}}
    conditional = a.conditional + [c for c in b.conditional if c not in a.conditional]
    return Finding(
        id=a.id, title=a.title or b.title, summary=a.summary or b.summary, url=a.url or b.url,
        cves=union(a.cves, b.cves), products=union(a.products, b.products),
        affected=a.affected + [x for x in b.affected if x not in a.affected],
        iocs=iocs, conditional=conditional, techniques=union(a.techniques, b.techniques),
        kev=a.kev or b.kev, kev_added=a.kev_added or b.kev_added, ransomware=a.ransomware or b.ransomware,
        first_exploited=a.first_exploited or b.first_exploited,
        references=union(a.references, b.references), sources=union(a.sources, b.sources),
    )
