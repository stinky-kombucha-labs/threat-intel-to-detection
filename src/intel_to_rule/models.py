from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

# IOC kinds a Finding can carry. Each maps to a log source category and a field in every rule format.
IOC_KINDS = ("uri", "dir", "filename", "cmdline")

# Log source categories that can evidence each IOC kind.
LOGSOURCE_FOR_KIND = {
    "uri": ("webserver", "proxy"),
    "uri_long_host": ("proxy", "webserver"),
    "dir": ("file_event",),
    "filename": ("file_event",),
    "cmdline": ("process_creation",),
}


@dataclass
class RawItem:
    """One item as collected from a source, before any interpretation."""

    source: str
    id: str
    title: str
    url: str
    published: str
    text: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """Normalised intelligence about one vulnerability or attack."""

    id: str
    title: str
    summary: str = ""
    url: str = ""
    cves: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    # {"product": str, "introduced": str, "fixed": str}; empty "fixed" means no fix at disclosure
    affected: list[dict] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    # IOCs that only mean something with an extra condition, e.g. {"kind": "uri_long_host", ...}
    conditional: list[dict] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    kev: bool = False
    kev_added: str = ""
    ransomware: bool = False
    first_exploited: str = ""
    references: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def key(self) -> str:
        return self.cves[0] if self.cves else self.id

    @property
    def has_iocs(self) -> bool:
        return any(self.iocs.values()) or bool(self.conditional)
