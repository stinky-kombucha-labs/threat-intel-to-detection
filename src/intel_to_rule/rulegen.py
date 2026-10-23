"""Decide how to change the rule set for a finding and produce the new rule text.

Preference order for every uncovered IOC kind:
1. Add the values to the list in an existing, related rule (smallest possible diff, same format).
2. Otherwise write a new rule in the configured primary format.
Conditional indicators (for example a Host header length) cannot be merged into a list, so they always
become a new rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from . import sigma_eval
from .coverage import Coverage
from .models import LOGSOURCE_FOR_KIND, Finding
from .relevance import Match
from .rule_formats import FORMATS, Rule
from .rule_formats.base import Draft, UpdateMeta
from .util import slug, stable_uuid

LABELS = {
    "uri": "Web Requests",
    "dir": "Script Files in Web Root",
    "filename": "Dropped Files",
    "cmdline": "Command Lines",
    "uri_long_host": "Oversized Host Header",
}
FALSE_POSITIVES = {
    "uri": ["Vulnerability scanners and authorised penetration tests requesting the same paths"],
    "dir": [
        "Product upgrades and hotfixes that write script files into the web root",
        "Administrators deploying legitimate pages (check the change calendar)",
    ],
    "filename": ["Administrators copying files with the same name during maintenance"],
    "cmdline": ["Administration scripts that use the same command line"],
    "uri_long_host": [
        "Exposure-management scanners that send oversized Host headers",
        "Normal OpenID discovery requests carry a short Host header, so only long values are suspicious",
    ],
}


@dataclass
class Change:
    path: str
    action: str  # update | new | generated
    format: str
    old: str
    new: str
    kinds: list[str] = field(default_factory=list)


@dataclass
class Proposal:
    changes: list[Change] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    replay: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _pick_rule(kind: str, related: list[Rule], finding: Finding, matches: list[Match]) -> Rule | None:
    """Best existing rule to extend: same CVE first, then same product, then same technique."""
    wanted = set(LOGSOURCE_FOR_KIND.get(kind, ()))
    candidates = [r for r in related if r.logsource in wanted]
    if not candidates:
        return None
    products = {slug(m.asset.product) for m in matches} | {m.asset.id for m in matches}
    return max(candidates, key=lambda r: (
        len(set(r.cves) & set(finding.cves)),
        len(products & {slug(p) for p in r.products}),
        len(set(r.techniques) & set(finding.techniques)),
        len(r.indicators),
    ))


def _draft(finding: Finding, matches: list[Match], kind: str, values: list[str], condition: dict, date: str,
           fmt: str) -> Draft:
    cve = finding.cves[0] if finding.cves else finding.id
    product = matches[0].asset.product if matches else (finding.products[0] if finding.products else "Unknown")
    label = LABELS[kind]
    return Draft(
        title=f"{cve} {product} - {label}",
        rule_id=stable_uuid(finding.key, kind, fmt),
        description=(
            f"Detects {label.lower()} linked to {', '.join(finding.cves) or finding.id}. "
            "Draft built from public reporting, requires analyst review before use."
        ),
        references=list(dict.fromkeys([*finding.references, finding.url]))[:6],
        false_positives=FALSE_POSITIVES[kind],
        level="high" if finding.kev else "medium",
        cves=finding.cves,
        techniques=finding.techniques,
        products=sorted({slug(m.asset.product) for m in matches}),
        date=date,
        kind=kind,
        values=values,
        condition=condition,
        hosts=sorted({h for m in matches for h in m.asset.hosts}),
    )


def _replay_events(kind: str, values: list[str], condition: dict) -> tuple[list[dict], list[dict]]:
    if kind == "uri":
        return ([{"cs-uri-stem": values[0], "cs-method": "POST"}],
                [{"cs-uri-stem": "/index.html", "cs-method": "GET"}])
    if kind == "dir":
        return ([{"TargetFilename": values[0] + "update.aspx"}],
                [{"TargetFilename": "C:\\Windows\\Temp\\notes.txt"}, {"TargetFilename": values[0] + "readme.txt"}])
    if kind == "filename":
        return ([{"TargetFilename": "C:\\inetpub\\wwwroot\\" + values[0]}],
                [{"TargetFilename": "C:\\inetpub\\wwwroot\\index.html"}])
    if kind == "cmdline":
        return [{"CommandLine": values[0]}], [{"CommandLine": "ipconfig /all"}]
    n = condition["host_min_length"]
    return ([{"c-uri": condition["uri"], "cs-host": "A" * (n + 10)}],
            [{"c-uri": condition["uri"], "cs-host": "vpn.example.com"}])


def _replay(change: Change, kind: str, values: list[str], condition: dict) -> list[dict]:
    """Run the old and new Sigma text against a synthetic attack event and a benign one."""
    if change.format != "sigma":
        return []
    positive, negative = _replay_events(kind, values, condition)
    out = []
    for label, events in (("attack event", positive), ("benign event", negative)):
        for event in events:
            out.append({
                "rule": change.path,
                "case": label,
                "event": event,
                "old": sigma_eval.matches(change.old, event) if change.old else None,
                "new": sigma_eval.matches(change.new, event),
            })
    return out


def propose(finding: Finding, matches: list[Match], cov: Coverage, rules: list[Rule],
            primary_format: str, date: str) -> Proposal | None:
    if cov.verdict in ("covered", "no_iocs"):
        return None
    proposal = Proposal()
    meta = UpdateMeta(date=date, cves=finding.cves, references=list(dict.fromkeys(
        [*finding.references, finding.url]))[:5], techniques=finding.techniques)
    working: dict[str, str] = {}

    work_items = [(k, v, {}) for k, v in cov.missing.items() if k != "uri_long_host"]
    work_items += [("uri_long_host", [c["uri"]], c) for c in finding.conditional if c["uri"] in cov.missing.get(
        c["kind"], [])]

    for kind, values, condition in work_items:
        fp = FALSE_POSITIVES[kind]
        proposal.false_positives += [f for f in fp if f not in proposal.false_positives]
        target = None if condition else _pick_rule(kind, cov.related_rules, finding, matches)
        change = None
        if target:
            current = replace(target, text=working.get(target.path, target.text))
            new_text = FORMATS[target.format].add_values(current, kind, values, meta)
            if new_text is not None:
                working[target.path] = new_text
                existing = next((c for c in proposal.changes if c.path == target.path), None)
                if existing:
                    existing.new = new_text
                    existing.kinds.append(kind)
                else:
                    change = Change(target.path, "update", target.format, target.text, new_text, [kind])
            else:
                proposal.notes.append(
                    f"Rule '{target.title}' has no editable list for '{kind}' indicators, wrote a new rule instead.")
                target = None
        if not target:
            fmt = FORMATS[primary_format]
            draft = _draft(finding, matches, kind, values, condition, date, primary_format)
            text = fmt.render(draft)
            path = f"rules/{primary_format}/{slug(finding.key)}_{kind}{fmt.extensions[0]}"
            change = Change(path, "new", primary_format, "", text, [kind])
            if condition:
                proposal.notes.append(
                    "The Host header length condition cannot be added to an existing list rule, so it is a new rule.")
        if change:
            proposal.changes.append(change)
        applied = next(c for c in proposal.changes if kind in c.kinds)
        proposal.replay += _replay(applied, kind, values, condition)

    for change in proposal.changes:
        proposal.problems += [f"{change.path}: {p}" for p in FORMATS[change.format].validate(change.new)]
    for r in proposal.replay:
        if r["case"] == "attack event" and not r["new"]:
            proposal.problems.append(f"{r['rule']}: new rule does not match the replayed attack event")
        if r["case"] == "benign event" and r["new"]:
            proposal.problems.append(f"{r['rule']}: new rule matches a benign event")
    return proposal if proposal.changes else None
