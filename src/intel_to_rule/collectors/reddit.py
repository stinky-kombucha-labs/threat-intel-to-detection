"""Reddit subreddit listings (public JSON). Search is noisy, so the pipeline reads new posts and filters by keyword."""
from __future__ import annotations

from ..models import RawItem
from . import http_get_json


def parse(payload: dict, subreddit: str, keywords: list[str]) -> list[RawItem]:
    items = []
    for child in payload.get("data", {}).get("children", []):
        d = child["data"]
        haystack = f"{d.get('title', '')} {d.get('selftext', '')}".lower()
        if keywords and not any(k.lower() in haystack for k in keywords):
            continue
        items.append(RawItem(
            source=f"reddit:r/{subreddit}",
            id=d["id"],
            title=d.get("title", ""),
            url=d.get("url_overridden_by_dest") or f"https://www.reddit.com{d.get('permalink', '')}",
            published=str(d.get("created_utc", "")),
            text=d.get("selftext", "")[:6000],
            extra={"score": d.get("score", 0), "permalink": f"https://www.reddit.com{d.get('permalink', '')}"},
        ))
    return items


def fetch(subreddits: list[str], keywords: list[str], limit: int = 50) -> list[RawItem]:
    items: list[RawItem] = []
    for sub in subreddits:
        try:
            items += parse(http_get_json(f"https://www.reddit.com/r/{sub}/new.json?limit={limit}"), sub, keywords)
        except Exception as exc:
            print(f"warning: reddit r/{sub} failed: {exc}")
    return items
