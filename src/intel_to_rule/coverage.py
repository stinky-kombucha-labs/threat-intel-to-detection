from __future__ import annotations

from dataclasses import dataclass, field

from .inventory import Asset
from .models import LOGSOURCE_FOR_KIND, Finding
from .relevance import Match
from .rule_formats import Rule
from .util import norm_ioc, slug

# An indicator covers an IOC when it is at least this large a share of it. Stops a generic
# ".aspx" from "covering" a specific webshell name.
MIN_SHARE = 0.7


def indicator_covers(indicator: str, ioc: str) -> bool:
    if len(indicator) < 4:
        return False
    if ioc in indicator:
        return True
    return indicator in ioc and len(indicator) / len(ioc) >= MIN_SHARE


@dataclass
class Coverage:
    # verdict: covered | partial | none | no_iocs
    verdict: str
    covered: dict[str, list[str]] = field(default_factory=dict)
    missing: dict[str, list[str]] = field(default_factory=dict)
    # ioc -> ids of rules that already cover it
    covered_by: dict[str, list[str]] = field(default_factory=dict)
    related_rules: list[Rule] = field(default_factory=list)
    log_gaps: list[str] = field(default_factory=list)


def _related(finding: Finding, matches: list[Match], rules: list[Rule]) -> list[Rule]:
    """Rules about the same CVE, the same product, or the same ATT&CK technique."""
    keys = {slug(m.asset.product) for m in matches} | {m.asset.id for m in matches}
    return [
        r for r in rules
        if set(finding.cves) & set(r.cves)
        or keys & {slug(p) for p in r.products}
        or set(finding.techniques) & set(r.techniques)
    ]


def analyse(finding: Finding, matches: list[Match], rules: list[Rule]) -> Coverage:
    cov = Coverage(verdict="none", related_rules=_related(finding, matches, rules))

    for kind, values in finding.iocs.items():
        for value in values:
            target = norm_ioc(value)
            hits = [r.id for r in rules if any(indicator_covers(i, target) for i in r.indicators)]
            bucket = cov.covered if hits else cov.missing
            bucket.setdefault(kind, []).append(value)
            if hits:
                cov.covered_by[value] = hits

    # A conditional IOC is covered only by a rule already tagged with the CVE.
    for cond in finding.conditional:
        label = cond["uri"]
        tagged = [r.id for r in rules if set(finding.cves) & set(r.cves)]
        bucket = cov.covered if tagged else cov.missing
        bucket.setdefault(cond["kind"], []).append(label)
        if tagged:
            cov.covered_by[label] = tagged

    if not finding.has_iocs:
        cov.verdict = "no_iocs"
    elif not cov.missing:
        cov.verdict = "covered"
    elif cov.covered:
        cov.verdict = "partial"

    cov.log_gaps = log_source_gaps(finding, [m.asset for m in matches])
    return cov


def log_source_gaps(finding: Finding, assets: list[Asset]) -> list[str]:
    """Report assets for which no log source able to evidence the IOCs is collected."""
    kinds = [k for k, v in finding.iocs.items() if v] + [c["kind"] for c in finding.conditional]
    gaps = []
    for asset in assets:
        for kind in dict.fromkeys(kinds):
            needed = LOGSOURCE_FOR_KIND.get(kind, ())
            if needed and not set(needed) & set(asset.log_sources):
                gaps.append(
                    f"{asset.product} ({', '.join(asset.hosts) or asset.id}) has no "
                    f"{' or '.join(needed)} logs in the SIEM, so a rule on '{kind}' indicators cannot fire"
                )
    return gaps
