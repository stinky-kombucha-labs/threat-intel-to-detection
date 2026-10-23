from __future__ import annotations

import re

import yaml

from ..util import norm_ioc
from .base import (
    Draft, Rule, RuleFormat, UpdateMeta, add_to_yaml_field_list, append_top_level_list, yaml_quote,
)

# IOC kind -> (Sigma field, logsource block)
FIELDS = {
    "uri": ("cs-uri-stem|contains", "category: webserver"),
    "dir": ("TargetFilename|contains", "category: file_event\n  product: windows"),
    "filename": ("TargetFilename|endswith", "category: file_event\n  product: windows"),
    "cmdline": ("CommandLine|contains", "category: process_creation"),
}
SCRIPT_EXTENSIONS = (".aspx", ".ashx", ".asmx", ".jsp", ".php")
TACTICS = {
    "T1190": "initial-access",
    "T1505.003": "persistence",
    "T1059": "execution",
    "T1078": "defense-evasion",
}


def _strings(node):
    if isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


class SigmaFormat(RuleFormat):
    name = "sigma"
    extensions = (".yml", ".yaml")

    def load(self, path: str, text: str) -> Rule:
        data = yaml.safe_load(text)
        tags = [str(t) for t in data.get("tags", [])]
        detection = {k: v for k, v in data.get("detection", {}).items() if k != "condition"}
        return Rule(
            id=str(data.get("id", "")),
            title=data.get("title", ""),
            format=self.name,
            path=path,
            text=text,
            products=[t.split(".", 1)[1] for t in tags if t.startswith("product.")],
            cves=[t.split(".", 1)[1].upper() for t in tags if t.startswith("cve.")],
            techniques=[t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d", t)],
            logsource=str(data.get("logsource", {}).get("category", "")),
            level=str(data.get("level", "")),
            indicators={n for s in _strings(detection) if len(n := norm_ioc(s)) >= 4},
        )

    def render(self, d: Draft) -> str:
        tags = []
        for t in d.techniques:
            if t in TACTICS:
                tag = f"attack.{TACTICS[t]}"
                if tag not in tags:
                    tags.append(tag)
        tags += [f"attack.{t.lower()}" for t in d.techniques]
        tags += [f"cve.{c.lower().removeprefix('cve-')}" for c in d.cves]
        tags += [f"product.{p}" for p in d.products]
        refs = "\n".join(f"  - {r}" for r in d.references)
        fps = "\n".join(f"  - {f}" for f in d.false_positives)
        tag_block = "\n".join(f"  - {t}" for t in tags)

        if d.kind == "uri_long_host":
            logsource = "category: proxy"
            detection = (
                "  selection:\n"
                f"    c-uri|contains: {yaml_quote(d.condition['uri'])}\n"
                f"    cs-host|re: {yaml_quote('.{' + str(d.condition['host_min_length']) + '}')}\n"
                "  condition: selection"
            )
        else:
            field_name, logsource = FIELDS[d.kind]
            items = "\n".join(f"      - {yaml_quote(v)}" for v in d.values)
            if d.kind == "dir":
                exts = "\n".join(f"      - {yaml_quote(e)}" for e in SCRIPT_EXTENSIONS)
                detection = (
                    f"  selection_path:\n    {field_name}:\n{items}\n"
                    f"  selection_extension:\n    TargetFilename|endswith:\n{exts}\n"
                    "  condition: selection_path and selection_extension"
                )
            else:
                detection = f"  selection:\n    {field_name}:\n{items}\n  condition: selection"

        return (
            f"title: {d.title}\n"
            f"id: {d.rule_id}\n"
            "status: experimental\n"
            f"description: {d.description}\n"
            f"references:\n{refs}\n"
            "author: intel-to-rule (draft, requires analyst review)\n"
            f"date: {d.date}\n"
            f"tags:\n{tag_block}\n"
            f"logsource:\n  {logsource}\n"
            f"detection:\n{detection}\n"
            f"falsepositives:\n{fps}\n"
            f"level: {d.level}\n"
        )

    def add_values(self, rule: Rule, kind: str, values: list[str], meta: UpdateMeta) -> str | None:
        if kind not in FIELDS:
            return None
        field_name, _ = FIELDS[kind]
        text = add_to_yaml_field_list(rule.text, field_name, values)
        if text is None:
            return None
        if re.search(r"^modified:", text, re.MULTILINE):
            text = re.sub(r"^modified:.*$", f"modified: {meta.date}", text, flags=re.MULTILINE)
        else:
            text = re.sub(r"^(date:.*)$", rf"\1\nmodified: {meta.date}", text, count=1, flags=re.MULTILINE)
        text = append_top_level_list(text, "references", meta.references)
        tags = [f"cve.{c.lower().removeprefix('cve-')}" for c in meta.cves]
        return append_top_level_list(text, "tags", tags)

    def validate(self, text: str) -> list[str]:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            return [f"invalid YAML: {exc}"]
        if not isinstance(data, dict):
            return ["rule is not a mapping"]
        problems = [f"missing key '{k}'" for k in ("title", "id", "logsource", "detection", "level") if k not in data]
        detection = data.get("detection") or {}
        if "condition" not in detection:
            problems.append("detection has no condition")
        if data.get("level") not in {"informational", "low", "medium", "high", "critical", None}:
            problems.append(f"bad level '{data.get('level')}'")
        return problems
