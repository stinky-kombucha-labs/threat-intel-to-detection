from __future__ import annotations

from pathlib import Path

from .base import Rule, RuleFormat
from .elastic import ElasticFormat
from .sigma import SigmaFormat
from .splunk import SplunkFormat

FORMATS: dict[str, RuleFormat] = {
    "sigma": SigmaFormat(),
    "splunk": SplunkFormat(),
    "elastic": ElasticFormat(),
}


def load_rules(dirs: dict[str, str], root: Path) -> list[Rule]:
    """Load every rule from the per-format directories (generated output is never scanned)."""
    rules: list[Rule] = []
    for fmt_name, rel_dir in dirs.items():
        fmt = FORMATS[fmt_name]
        base = root / rel_dir
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in fmt.extensions:
                rules.append(fmt.load(path.relative_to(root).as_posix(), path.read_text(encoding="utf-8")))
    return rules


__all__ = ["FORMATS", "Rule", "RuleFormat", "load_rules"]
