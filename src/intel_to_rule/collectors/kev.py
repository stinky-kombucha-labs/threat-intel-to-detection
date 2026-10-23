"""CISA Known Exploited Vulnerabilities catalog (public JSON, no key)."""
from __future__ import annotations

from ..models import RawItem
from . import http_get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse(catalog: dict, since: str = "") -> list[RawItem]:
    items = []
    for v in catalog.get("vulnerabilities", []):
        if since and v.get("dateAdded", "") < since:
            continue
        items.append(RawItem(
            source="kev",
            id=v["cveID"],
            title=f"{v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}".strip(),
            url=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            published=v.get("dateAdded", ""),
            text=v.get("shortDescription", ""),
            extra=v,
        ))
    return items


def index(catalog: dict) -> dict[str, dict]:
    return {v["cveID"]: v for v in catalog.get("vulnerabilities", [])}


def fetch(since: str = "") -> tuple[list[RawItem], dict[str, dict]]:
    catalog = http_get_json(KEV_URL, timeout=60)
    return parse(catalog, since), index(catalog)
