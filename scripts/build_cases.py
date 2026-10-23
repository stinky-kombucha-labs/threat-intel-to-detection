"""Rebuild the generated parts of cases/ (rules before and after, diffs, example emails) from the offline fixtures.

Run from the repository root:  py scripts/build_cases.py
The narrative README.md in each case folder is written by hand and never touched here.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("INTEL_TO_RULE_TODAY", "2026-10-23")

from intel_to_rule import pipeline, report as rpt  # noqa: E402

CASES = {
    "CVE-2023-34362": "01-moveit-transfer",
    "CVE-2023-46805": "02-ivanti-connect-secure",
    "CVE-2023-4966": "03-citrix-bleed",
}


def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    ctx = pipeline.build_context(ROOT, ROOT / "config/pipeline.yaml", str(tmp / "state.sqlite"))
    reports = {r.finding.key: r for r in pipeline.run(ctx, pipeline.collect_fixtures(ctx), tmp / "out")}
    for key, folder in CASES.items():
        r = reports[key]
        case = ROOT / "cases" / folder
        for sub in ("before", "after", "generated"):
            shutil.rmtree(case / sub, ignore_errors=True)
        (case / "before").mkdir(parents=True, exist_ok=True)
        (case / "after").mkdir(exist_ok=True)
        diffs = []
        for change in r.proposal.changes:
            name = Path(change.path).name
            if change.action == "generated":
                (case / "generated").mkdir(exist_ok=True)
                (case / "generated" / name).write_text(change.new, encoding="utf-8")
                continue
            if change.old:
                (case / "before" / name).write_text(change.old, encoding="utf-8", newline="\n")
            (case / "after" / name).write_text(change.new, encoding="utf-8", newline="\n")
            diffs.append(rpt.unified_diff(change))
        (case / "rule.diff").write_text("\n".join(diffs), encoding="utf-8")
        (case / "example_email.md").write_text(rpt.email(r), encoding="utf-8")
        print(f"built {folder}")


if __name__ == "__main__":
    main()
