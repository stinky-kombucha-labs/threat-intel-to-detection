"""RSS and Atom feeds: vendor advisories and DFIR blogs. Keeps only posts that mention a keyword."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import RawItem
from . import http_get

_TAGS = re.compile(r"<[^>]+>")


def _text(node: ET.Element | None) -> str:
    return _TAGS.sub(" ", (node.text or "")).strip() if node is not None else ""


def parse(xml_bytes: bytes, feed_name: str, keywords: list[str]) -> list[RawItem]:
    root = ET.fromstring(xml_bytes)
    ns = {"a": "http://www.w3.org/2005/Atom", "c": "http://purl.org/rss/1.0/modules/content/"}
    entries = root.findall(".//item") or root.findall(".//a:entry", ns)
    items = []
    for e in entries:
        title = _text(e.find("title")) or _text(e.find("a:title", ns))
        link_node = e.find("link") if e.find("link") is not None else e.find("a:link", ns)
        link = (link_node.text or link_node.get("href", "")) if link_node is not None else ""
        body = (_text(e.find("c:encoded", ns)) or _text(e.find("description"))
                or _text(e.find("a:summary", ns)) or _text(e.find("a:content", ns)))
        published = _text(e.find("pubDate")) or _text(e.find("a:updated", ns)) or _text(e.find("a:published", ns))
        haystack = f"{title} {body}".lower()
        if keywords and not any(k.lower() in haystack for k in keywords):
            continue
        items.append(RawItem(source=f"feed:{feed_name}", id=link.strip(), title=title, url=link.strip(),
                             published=published, text=re.sub(r"\s+", " ", body)[:6000]))
    return items


def fetch(feeds: list[dict], keywords: list[str]) -> list[RawItem]:
    items: list[RawItem] = []
    for feed in feeds:
        try:
            items += parse(http_get(feed["url"]), feed["name"], keywords)
        except Exception as exc:  # one broken feed must not stop the run
            print(f"warning: feed {feed['name']} failed: {exc}")
    return items
