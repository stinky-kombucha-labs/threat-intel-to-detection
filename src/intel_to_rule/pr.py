"""Open a pull request with the proposed rule change. Never touches the SIEM.

Uses the local `git` and the GitHub `gh` CLI, so it works with whatever the analyst is already logged in to.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import report as rpt
from .util import slug


def _run(args: list[str], cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def plan(r: rpt.Report, prefix: str = "intel-to-rule") -> dict:
    branch = f"{prefix}/{slug(r.finding.key, '-')}"
    return {
        "branch": branch,
        "title": f"{', '.join(r.finding.cves) or r.finding.title}: {rpt.VERDICT_TEXT[r.verdict].lower()}",
        "files": [c.path for c in r.proposal.changes] if r.proposal else [],
    }


def open_pr(r: rpt.Report, root: Path, paths: list[str], base: str, labels: list[str],
            body_file: Path, prefix: str = "intel-to-rule") -> str:
    """Create a branch, commit the already-written files and open the pull request. Returns its URL."""
    p = plan(r, prefix)
    _run(["git", "checkout", "-b", p["branch"]], root)
    _run(["git", "add", *paths], root)
    _run(["git", "commit", "-m", p["title"]], root)
    _run(["git", "push", "-u", "origin", p["branch"]], root)
    args = ["gh", "pr", "create", "--base", base, "--head", p["branch"], "--title", p["title"],
            "--body-file", str(body_file)]
    for label in labels:
        args += ["--label", label]
    url = _run(args, root)
    _run(["git", "checkout", base], root)  # next finding starts from the base branch again
    return url
