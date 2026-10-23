"""GitHub repository search for public PoCs and Sigma rules that mention a CVE."""
from __future__ import annotations

import urllib.parse

from . import http_get_json


def find_repos(cve: str, token: str = "", limit: int = 5) -> list[dict]:
    query = urllib.parse.urlencode({"q": f"{cve} in:name,description", "sort": "stars", "per_page": limit})
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = http_get_json(f"https://api.github.com/search/repositories?{query}", headers)
    return [
        {"name": r["full_name"], "url": r["html_url"], "description": r.get("description") or "",
         "stars": r["stargazers_count"]}
        for r in payload.get("items", [])
    ]
