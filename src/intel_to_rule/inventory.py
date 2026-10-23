from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Asset:
    id: str
    vendor: str
    product: str
    version: str
    aliases: list[str] = field(default_factory=list)
    exposure: str = "internal"  # internet | partner | internal
    criticality: str = "medium"
    hosts: list[str] = field(default_factory=list)
    # Log source categories actually collected for this asset (webserver, proxy, file_event, ...)
    log_sources: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    company: str
    assets: list[Asset]

    def by_id(self, asset_id: str) -> Asset | None:
        return next((a for a in self.assets if a.id == asset_id), None)


def load_inventory(path: str | Path) -> Inventory:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Inventory(
        company=data.get("company", "unknown"),
        assets=[Asset(**item) for item in data["assets"]],
    )
