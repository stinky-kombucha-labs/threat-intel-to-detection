from __future__ import annotations

import re
from dataclasses import dataclass

from .inventory import Asset, Inventory
from .models import Finding
from .util import version_tuple


@dataclass
class Match:
    asset: Asset
    reason: str
    # affected | not_affected | unknown
    version_status: str


def _names(asset: Asset) -> list[str]:
    return [asset.product, *asset.aliases]


def _mentions(haystack: str, name: str) -> bool:
    return bool(re.search(rf"(?<![a-z0-9]){re.escape(name.lower())}(?![a-z0-9])", haystack))


def version_status(asset: Asset, finding: Finding) -> str:
    ranges = [
        r for r in finding.affected
        if any(_mentions(r.get("product", "").lower(), n) or _mentions(n.lower(), r.get("product", "").lower())
               for n in _names(asset))
    ]
    if not ranges:
        return "unknown"
    have = version_tuple(asset.version)
    for r in ranges:
        introduced = version_tuple(r.get("introduced", ""))
        fixed = version_tuple(r.get("fixed", ""))
        if have >= introduced and (not fixed or have < fixed):
            return "affected"
    return "not_affected"


def match_inventory(finding: Finding, inventory: Inventory) -> list[Match]:
    """Return inventory assets the finding applies to (not_affected versions are dropped)."""
    haystack = " ".join([finding.title, finding.summary, *finding.products]).lower()
    matches: list[Match] = []
    for asset in inventory.assets:
        hit = next((n for n in _names(asset) if _mentions(haystack, n)), None)
        if not hit:
            continue
        status = version_status(asset, finding)
        if status == "not_affected":
            continue
        matches.append(Match(asset, f"'{hit}' is named in the finding", status))
    return matches
