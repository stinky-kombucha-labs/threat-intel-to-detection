from __future__ import annotations

import datetime as dt
import os
import re
import uuid

_NS = uuid.UUID("6f1f7d0e-3b7a-4a55-9c1e-1d2f3c4b5a60")


def stable_uuid(*parts: str) -> str:
    """Deterministic rule IDs so reruns produce identical diffs."""
    return str(uuid.uuid5(_NS, "|".join(parts)))


def slug(value: str, sep: str = "_") -> str:
    return re.sub(r"[^a-z0-9]+", sep, value.lower()).strip(sep)


def today() -> str:
    # Overridable so tests and demo output are reproducible.
    return os.environ.get("INTEL_TO_RULE_TODAY") or dt.date.today().isoformat()


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", value or ""))


def norm_ioc(value: str) -> str:
    """Normalise an indicator for comparison: case, slashes, spaces, wildcards."""
    value = value.lower().replace("\\\\", "\\").replace("\\", "/").replace("*", "")
    return re.sub(r"\s+", "", value)
