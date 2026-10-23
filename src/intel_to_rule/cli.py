from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from . import convert as convert_mod
from . import notify, pipeline, pr, report as rpt
from .rule_formats import FORMATS, load_rules


def _root(args) -> Path:
    return Path(args.root).resolve()


def _context(args, fixtures: bool):
    root = _root(args)
    state = None
    if fixtures and not args.keep_state:
        state = str(Path(tempfile.mkdtemp()) / "state.sqlite")  # demos always start clean
    ctx = pipeline.build_context(root, root / args.config, state, force=args.force)
    if args.llm:
        from .llm import LLM
        ctx.llm = LLM()
    return ctx


def _finish(ctx, reports, args, out_dir: Path) -> int:
    for r in reports:
        label = rpt.VERDICT_TEXT[r.verdict]
        print(f"{r.finding.key:<22} {label}")
        if not r.proposal:
            continue
        for c in r.proposal.changes:
            print(f"    {c.action:<9} {c.path}")
        for problem in r.proposal.problems:
            print(f"    PROBLEM {problem}")
        if args.apply or args.open_pr:
            paths = pipeline.apply_changes(ctx, r)
            if args.open_pr:
                cfg = ctx.config["pr"]
                body = out_dir / r.finding.key / "pr_body.md"
                r.pr_url = pr.open_pr(r, ctx.root, paths, cfg["base"], cfg["labels"], body, cfg["branch_prefix"])
                print(f"    PR {r.pr_url}")
                (out_dir / r.finding.key / "email.md").write_text(rpt.email(r), encoding="utf-8")
        if args.send_email:
            notify.send(rpt.subject(r), rpt.email(r), r.to, ctx.config["email"]["from"])
    print(f"\nOutput written to {out_dir}")
    return 1 if any(r.proposal and r.proposal.problems for r in reports) else 0


def cmd_run(args) -> int:
    ctx = _context(args, args.fixtures)
    out_dir = _root(args) / args.out
    items = pipeline.collect_fixtures(ctx) if args.fixtures else pipeline.collect_live(ctx, args.since)
    return _finish(ctx, pipeline.run(ctx, items, out_dir), args, out_dir)


def cmd_analyze(args) -> int:
    ctx = _context(args, False)
    out_dir = _root(args) / args.out
    from .collectors import kev
    _, ctx.kev_index = kev.fetch("9999")
    items = [pipeline.fetch_url(u) for u in args.url]
    return _finish(ctx, pipeline.run(ctx, items, out_dir), args, out_dir)


def cmd_validate(args) -> int:
    root = _root(args)
    cfg = pipeline.load_config(root / args.config)
    rules = load_rules(cfg["rules"]["dirs"], root)
    bad = 0
    for rule in rules:
        problems = FORMATS[rule.format].validate(rule.text)
        print(f"{'FAIL' if problems else 'ok  '} {rule.format:<8} {rule.path}")
        for p in problems:
            print(f"       {p}")
        bad += bool(problems)
    return 1 if bad else 0


def cmd_convert(args) -> int:
    if not convert_mod.available():
        print("pySigma is not installed. Run: pip install -e .[sigma]", file=sys.stderr)
        return 2
    root = _root(args)
    cfg = pipeline.load_config(root / args.config)
    gen = root / cfg["rules"]["generated_dir"]
    for rule in (r for r in load_rules(cfg["rules"]["dirs"], root) if r.format == "sigma"):
        for target, suffix in (("splunk", ".spl"), ("elastic", ".lucene")):
            out = gen / target / (Path(rule.path).stem + suffix)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(convert_mod.convert(rule.text)[target] + "\n", encoding="utf-8")
        print(f"converted {rule.path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=".", help="repository root")
    common.add_argument("--config", default="config/pipeline.yaml")
    common.add_argument("--out", default="out")
    common.add_argument("--force", action="store_true", help="reprocess findings already seen")
    common.add_argument("--keep-state", action="store_true", help="use the real state DB even with --fixtures")
    common.add_argument("--llm", action="store_true", help="use the LLM for extraction (needs ANTHROPIC_API_KEY)")
    common.add_argument("--apply", action="store_true", help="write proposed files into the working tree")
    common.add_argument("--open-pr", action="store_true", help="commit, push and open a pull request (implies --apply)")
    common.add_argument("--send-email", action="store_true", help="send the analyst email over SMTP")

    parser = argparse.ArgumentParser(prog="intel-to-rule", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", parents=[common], help="collect, analyse and propose rule changes")
    run.add_argument("--fixtures", action="store_true", help="offline demo data, no network")
    run.add_argument("--since", type=int, default=7, help="days of history to read in live mode")
    run.set_defaults(func=cmd_run)

    analyze = sub.add_parser("analyze", parents=[common], help="analyse specific URLs")
    analyze.add_argument("url", nargs="+")
    analyze.set_defaults(func=cmd_analyze)

    sub.add_parser("validate", parents=[common], help="check every rule file").set_defaults(func=cmd_validate)
    sub.add_parser("convert", parents=[common], help="Sigma -> SPL/Elastic").set_defaults(func=cmd_convert)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
