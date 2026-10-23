from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import collectors, convert, extract, report as rpt
from .collectors import feeds, github, kev, nvd, reddit
from .coverage import analyse
from .inventory import Inventory, load_inventory
from .models import Finding, RawItem
from .relevance import match_inventory
from .rule_formats import load_rules
from .rulegen import Change, propose
from .store import Store
from .util import today


def load_config(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


@dataclass
class Context:
    root: Path
    config: dict
    inventory: Inventory
    store: Store
    kev_index: dict[str, dict] = field(default_factory=dict)
    recorded: dict[str, dict] = field(default_factory=dict)
    llm: object | None = None
    force: bool = False


def build_context(root: Path, config_path: Path, state_path: str | None = None, **kw) -> Context:
    config = load_config(config_path)
    return Context(
        root=root,
        config=config,
        inventory=load_inventory(root / config["inventory"]),
        store=Store(state_path or root / config["state_db"]),
        **kw,
    )


# ------------------------------------------------------------------ collection

def collect_fixtures(ctx: Context) -> list[RawItem]:
    base = ctx.root / ctx.config["fixtures_dir"]
    catalog = json.loads((base / "kev_sample.json").read_text(encoding="utf-8"))
    ctx.kev_index = kev.index(catalog)
    items = []
    for path in sorted((base / "items").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        raw = RawItem(**data["raw"])
        ctx.recorded[raw.id] = data.get("recorded_extraction", {})
        items.append(raw)
    return items + kev.parse(catalog)


def collect_live(ctx: Context, since_days: int) -> list[RawItem]:
    import datetime as dt
    import os

    src = ctx.config["sources"]
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=since_days))
    keywords = sorted({n for a in ctx.inventory.assets for n in [a.product, *a.aliases]})
    items, index = kev.fetch(since.date().isoformat())
    ctx.kev_index = index
    if src.get("nvd", {}).get("enabled"):
        items += nvd.fetch(keywords, since.strftime("%Y-%m-%dT%H:%M:%S.000"), os.environ.get("NVD_API_KEY", ""))
    items += feeds.fetch(src.get("feeds", []), keywords)
    if src.get("reddit", {}).get("enabled"):
        items += reddit.fetch(src["reddit"]["subreddits"], keywords)
    return items


def fetch_url(url: str) -> RawItem:
    """Read one web page for the `analyze` command."""
    html = collectors.http_get(url).decode("utf-8", "replace")
    title = (re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I) or [None, url])[1].strip()
    text = re.sub(r"\s+", " ", re.sub(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", " ", html, flags=re.S | re.I))
    return RawItem(source="url", id=url, title=title, url=url, published="", text=text[:12000])


# ------------------------------------------------------------------ processing

def to_finding(ctx: Context, raw: RawItem) -> Finding:
    if raw.source == "kev":
        return extract.from_kev(raw)
    if ctx.recorded.get(raw.id):
        return extract.from_recorded(raw, ctx.recorded[raw.id])
    if ctx.llm:
        from . import llm as llm_mod
        return extract.from_recorded(raw, llm_mod.extract(ctx.llm, raw, ctx.inventory))
    return extract.heuristic(raw, ctx.inventory)


def build_findings(ctx: Context, items: list[RawItem]) -> list[Finding]:
    """Convert raw items, merge by CVE, add KEV data. Bare KEV records never stand alone when a write-up exists."""
    findings: dict[str, Finding] = {}
    bare_kev: list[Finding] = []
    for raw in items:
        f = to_finding(ctx, raw)
        if raw.source == "kev":
            bare_kev.append(f)
            continue
        findings[f.key] = extract.merge(findings[f.key], f) if f.key in findings else f
    claimed = {c for f in findings.values() for c in f.cves}
    for f in bare_kev:
        if f.key not in claimed:
            findings[f.key] = f
    out = []
    for f in findings.values():
        previous = ctx.store.get(f.key)
        out.append(extract.apply_kev(extract.merge(previous, f) if previous else f, ctx.kev_index))
    return out


def _generated_changes(ctx: Context, changes: list[Change]) -> tuple[list[Change], list[str]]:
    gen_dir = ctx.config["rules"]["generated_dir"]
    extra, notes = [], []
    sigma = [c for c in changes if c.format == "sigma"]
    if not sigma:
        return extra, notes
    if not convert.available():
        return extra, ["pySigma is not installed, so Splunk and Elastic queries were not generated "
                       "(pip install -e .[sigma])."]
    for c in sigma:
        stem = Path(c.path).stem
        try:
            converted = convert.convert(c.new)
        except Exception as exc:
            notes.append(f"Conversion of {c.path} failed: {exc}")
            continue
        for target, suffix in (("splunk", ".spl"), ("elastic", ".lucene")):
            rel = f"{gen_dir}/{target}/{stem}{suffix}"
            existing = ctx.root / rel
            old = existing.read_text(encoding="utf-8") if existing.exists() else ""
            extra.append(Change(rel, "generated", target, old, converted[target] + "\n", c.kinds))
    return extra, notes


def process(ctx: Context, finding: Finding) -> rpt.Report:
    cfg = ctx.config
    matches = match_inventory(finding, ctx.inventory)
    base = rpt.Report(finding, matches, None, None, today(), to=cfg["email"]["to"])
    if not matches:
        return base
    rules = load_rules(cfg["rules"]["dirs"], ctx.root)
    cov = analyse(finding, matches, rules)
    proposal = propose(finding, matches, cov, rules, cfg["rules"]["primary_format"], today())
    if proposal:
        extra, notes = _generated_changes(ctx, proposal.changes)
        proposal.changes += extra
        proposal.notes += notes
    base.coverage, base.proposal = cov, proposal
    return base


def write_outputs(ctx: Context, r: rpt.Report, out_dir: Path) -> Path:
    folder = out_dir / r.finding.key
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "finding.json").write_text(rpt.finding_json(r), encoding="utf-8")
    if r.proposal:
        (folder / "email.md").write_text(rpt.email(r), encoding="utf-8")
        (folder / "pr_body.md").write_text(rpt.pr_body(r), encoding="utf-8")
        for c in r.proposal.changes:
            (folder / (Path(c.path).name + ".diff")).write_text(rpt.unified_diff(c), encoding="utf-8")
    elif r.matches:
        (folder / "email.md").write_text(rpt.email(r), encoding="utf-8")
    return folder


def apply_changes(ctx: Context, r: rpt.Report) -> list[str]:
    """Write the proposed files into the working tree. Used before opening a pull request."""
    paths = []
    for c in (r.proposal.changes if r.proposal else []):
        target = ctx.root / c.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(c.new, encoding="utf-8", newline="\n")
        paths.append(c.path)
    return paths


def run(ctx: Context, items: list[RawItem], out_dir: Path) -> list[rpt.Report]:
    reports = []
    for finding in build_findings(ctx, items):
        if not ctx.force and ctx.store.is_processed(finding):
            continue
        r = process(ctx, finding)
        write_outputs(ctx, r, out_dir)
        ctx.store.save(finding)
        reports.append(r)
    write_summary(reports, out_dir)
    return reports


def write_summary(reports: list[rpt.Report], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = ["# Run summary", "", "| Finding | Verdict | Assets | Files changed |", "|---|---|---|---|"]
    for r in reports:
        files = ", ".join(c.path for c in r.proposal.changes if c.action != "generated") if r.proposal else "-"
        assets = ", ".join(m.asset.product for m in r.matches) or "-"
        lines.append(f"| {r.finding.key} | {rpt.VERDICT_TEXT[r.verdict]} | {assets} | {files} |")
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
