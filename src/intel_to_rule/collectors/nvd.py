"""NVD CVE API 2.0. Without an API key NVD allows 5 requests per rolling 30 seconds, with a key 50."""
from __future__ import annotations

import time
import urllib.parse

from ..models import RawItem
from . import http_get_json

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse(payload: dict) -> list[RawItem]:
    items = []
    for entry in payload.get("vulnerabilities", []):
        cve = entry["cve"]
        description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        items.append(RawItem(
            source="nvd",
            id=cve["id"],
            title=cve["id"],
            url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            published=cve.get("published", ""),
            text=description,
            extra={"metrics": cve.get("metrics", {}), "configurations": cve.get("configurations", [])},
        ))
    return items


def fetch(keywords: list[str], since_iso: str, api_key: str = "") -> list[RawItem]:
    """One keyword search per inventory product, modified since `since_iso` (UTC, ISO-8601)."""
    headers = {"apiKey": api_key} if api_key else {}
    pause = 1 if api_key else 7  # stay under the public rate limit
    seen: dict[str, RawItem] = {}
    for keyword in keywords:
        query = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "lastModStartDate": since_iso,
            "lastModEndDate": time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime()),
        })
        try:
            for item in parse(http_get_json(f"{NVD_URL}?{query}", headers, timeout=60)):
                seen[item.id] = item
        except Exception as exc:  # NVD is slow and rate limited, one failed keyword must not stop the run
            print(f"warning: NVD search for '{keyword}' failed: {exc}")
        time.sleep(pause)
    return list(seen.values())
