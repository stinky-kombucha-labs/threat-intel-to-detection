"""Render the analyst email, the pull request body and diffs from one Report."""
from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field

from .coverage import Coverage
from .models import Finding
from .relevance import Match
from .rulegen import Change, Proposal

VERDICT_TEXT = {
    "covered": "Already covered by existing rules",
    "partial": "Partly covered, rule update proposed",
    "none": "Not covered, rule change proposed",
    "no_iocs": "No usable indicators yet, analyst action needed",
    "not_relevant": "Not relevant to our inventory",
}


@dataclass
class Report:
    finding: Finding
    matches: list[Match]
    coverage: Coverage | None
    proposal: Proposal | None
    date: str
    to: str = ""
    pr_url: str = ""
    extras: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        if not self.matches:
            return "not_relevant"
        return self.coverage.verdict if self.coverage else "not_relevant"


def unified_diff(change: Change) -> str:
    old = change.old.splitlines(keepends=True)
    new = change.new.splitlines(keepends=True)
    return "".join(difflib.unified_diff(old, new, f"a/{change.path}", f"b/{change.path}", n=2)) \
        if change.old else "".join(difflib.unified_diff([], new, "/dev/null", f"b/{change.path}"))


def subject(r: Report) -> str:
    names = ", ".join(sorted({m.asset.product for m in r.matches}))
    label = ", ".join(r.finding.cves) or r.finding.title
    return f"[Detection] {label} | {VERDICT_TEXT[r.verdict]} | {names}"


def _asset_lines(r: Report) -> list[str]:
    out = []
    for m in r.matches:
        a = m.asset
        status = {"affected": "version is in the affected range",
                  "unknown": "affected versions not stated in the source, check manually"}[m.version_status]
        out.append(f"- {a.product} {a.version} on {', '.join(a.hosts) or a.id} "
                   f"({a.exposure}, {a.criticality} criticality). {status[0].upper() + status[1:]}.")
    return out


def _what_lines(f: Finding) -> list[str]:
    out = [f"- {f.title}", f"- Source: {f.url}"]
    if f.kev:
        out.append(f"- Listed in CISA KEV since {f.kev_added}"
                   + (", used in ransomware campaigns" if f.ransomware else ""))
    if f.first_exploited:
        out.append(f"- Earliest known exploitation: {f.first_exploited}")
    if f.summary:
        out.append(f"- {f.summary}")
    return out


def _coverage_lines(r: Report) -> list[str]:
    c = r.coverage
    out = [f"Verdict: {VERDICT_TEXT[r.verdict]}."]
    for kind, values in c.covered.items():
        for v in values:
            out.append(f"- Covered ({kind}): {v} by rule {', '.join(c.covered_by.get(v, []))}")
    for kind, values in c.missing.items():
        for v in values:
            out.append(f"- Not covered ({kind}): {v}")
    if c.related_rules:
        shown = c.related_rules[:5]
        more = f" and {len(c.related_rules) - 5} more" if len(c.related_rules) > 5 else ""
        out.append("Related rules reviewed: " + "; ".join(x.title for x in shown) + more)
    if r.verdict == "no_iocs":
        out.append("The sources name no URL, file or command indicators. Wait for a technical write-up or "
                   "write a behavioural rule by hand.")
    return out


def _replay_lines(p: Proposal) -> list[str]:
    if not p.replay:
        return ["Replay was not run (it needs a Sigma rule). Test the Splunk or Elastic change on sample data."]
    out = ["| Rule | Test event | Old rule | New rule |", "|---|---|---|---|"]
    for r in p.replay:
        old = "n/a (new rule)" if r["old"] is None else ("match" if r["old"] else "no match")
        event = ", ".join(f"{k}={v}" for k, v in r["event"].items())
        out.append(f"| {r['rule']} | {r['case']} ({event}) | {old} | {'match' if r['new'] else 'no match'} |")
    return out


def email(r: Report) -> str:
    f = r.finding
    lines = [f"Subject: {subject(r)}", f"To: {r.to}", "", "## What was found", *_what_lines(f), "",
             "## Why it matters to us", *_asset_lines(r), ""]
    if r.coverage:
        lines += ["## Current coverage", *_coverage_lines(r), ""]
        if r.coverage.log_gaps:
            lines += ["## Log source gaps", *[f"- {g}" for g in r.coverage.log_gaps], ""]
    p = r.proposal
    if p:
        pr = r.pr_url or "not opened yet"
        lines += [f"## Proposed change (pull request: {pr})",
                  "Nothing is applied to the SIEM. Review the diff and merge the pull request if it looks right.", ""]
        for change in p.changes:
            if change.action == "generated":
                continue
            lines += [f"### {change.action.upper()}: {change.path}", "```diff", unified_diff(change).rstrip(), "```", ""]
        lines += ["## Replay check", *_replay_lines(p), "",
                  "## Possible false positives", *[f"- {x}" for x in p.false_positives], ""]
        if p.notes:
            lines += ["## Notes", *[f"- {n}" for n in p.notes], ""]
        if p.problems:
            lines += ["## Validation problems (do not merge)", *[f"- {x}" for x in p.problems], ""]
    lines += ["## Sources", *[f"- {s}" for s in dict.fromkeys([f.url, *f.references])]]
    return "\n".join(lines) + "\n"


def pr_body(r: Report) -> str:
    p = r.proposal
    f = r.finding
    lines = [f"## {', '.join(f.cves) or f.title}", "", *_what_lines(f), "", "### Affected inventory", *_asset_lines(r), ""]
    lines += ["### Coverage", *_coverage_lines(r), ""]
    if p:
        lines += ["### Files", *[f"- `{c.path}` ({c.action})" for c in p.changes], "",
                  "### Replay check", *_replay_lines(p), "",
                  "### Possible false positives", *[f"- {x}" for x in p.false_positives], ""]
        if p.problems:
            lines += ["### Validation problems", *[f"- {x}" for x in p.problems], ""]
    lines += ["### Review checklist",
              "- [ ] Indicators match the cited sources",
              "- [ ] False positives acceptable for the listed hosts",
              "- [ ] Log source is collected for the listed hosts",
              "- [ ] Tested on sample data in a non-production SIEM", "",
              "Generated by intel-to-rule. The SIEM is not changed until this pull request is merged and deployed."]
    return "\n".join(lines) + "\n"


def finding_json(r: Report) -> str:
    return json.dumps({"finding": r.finding.to_dict(), "verdict": r.verdict,
                       "assets": [m.asset.id for m in r.matches]}, indent=2) + "\n"
