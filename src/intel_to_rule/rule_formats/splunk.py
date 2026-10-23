"""Native Splunk detections in the Splunk Security Content YAML layout (name, search, cve, ...)."""
from __future__ import annotations

import re

import yaml

from ..util import norm_ioc
from .base import (
    Draft, Rule, RuleFormat, UpdateMeta, add_to_query_list, append_top_level_list, bump_version, set_top_scalar,
)

FIELD_RE = {
    "uri": r"(?:\w+\.)?url",
    "dir": r"(?:\w+\.)?(?:TargetFilename|file_path)",
    "filename": r"(?:\w+\.)?(?:TargetFilename|file_path)",
    "cmdline": r"(?:\w+\.)?(?:CommandLine|process)",
}
WILDCARD = {"uri": "*{}*", "dir": "*{}*", "filename": "*{}", "cmdline": "*{}*"}
LOGSOURCE = {"uri": "webserver", "dir": "file_event", "filename": "file_event",
             "cmdline": "process_creation", "uri_long_host": "proxy"}
SCRIPT_REGEX = r'(?i)\.(aspx|ashx|asmx|jsp|php)$'

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def spl_quote(value: str, kind: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + WILDCARD[kind].format(escaped) + '"'


class SplunkFormat(RuleFormat):
    name = "splunk"
    extensions = (".yml", ".yaml")

    def load(self, path: str, text: str) -> Rule:
        data = yaml.safe_load(text)
        search = str(data.get("search", ""))
        literals = (m.replace("\\\\", "\\") for m in _QUOTED.findall(search))
        return Rule(
            id=str(data.get("id", "")),
            title=data.get("name", ""),
            format=self.name,
            path=path,
            text=text,
            products=list(data.get("inventory_products", [])),
            cves=[str(c).upper() for c in data.get("cve", [])],
            techniques=[str(t).upper() for t in data.get("mitre_attack_id", [])],
            logsource=str(data.get("logsource", "")),
            level=str(data.get("level", "")),
            indicators={n for s in literals if len(n := norm_ioc(s)) >= 4},
        )

    def _search(self, d: Draft) -> str:
        if d.kind == "uri_long_host":
            return (
                f'index=proxy url="*{d.condition["uri"]}*"\n'
                "| eval host_length=len(http_host)\n"
                f'| where host_length>={d.condition["host_min_length"]}\n'
                "| stats count min(_time) as firstTime max(_time) as lastTime by src dest url host_length"
            )
        vals = ", ".join(spl_quote(v, d.kind) for v in d.values)
        if d.kind == "uri":
            return (
                "| tstats count min(_time) as firstTime max(_time) as lastTime from datamodel=Web "
                f"where Web.url IN ({vals}) "
                "by Web.src Web.dest Web.http_method Web.url Web.status\n"
                '| `drop_dm_object_name("Web")`'
            )
        if d.kind == "dir":
            return (
                f"index=sysmon EventCode=11 TargetFilename IN ({vals})\n"
                f'| regex TargetFilename="{SCRIPT_REGEX}"\n'
                "| stats count min(_time) as firstTime max(_time) as lastTime by host Image TargetFilename"
            )
        if d.kind == "filename":
            return (
                f"index=sysmon EventCode=11 TargetFilename IN ({vals})\n"
                "| stats count min(_time) as firstTime max(_time) as lastTime by host Image TargetFilename"
            )
        return (
            f"index=sysmon EventCode=1 CommandLine IN ({vals})\n"
            "| stats count min(_time) as firstTime max(_time) as lastTime by host ParentImage Image CommandLine"
        )

    def render(self, d: Draft) -> str:
        def block(key: str, items: list[str]) -> str:
            return f"{key}:\n" + "".join(f"  - {i}\n" for i in items)

        search = "\n".join("  " + line for line in self._search(d).splitlines())
        fps = "; ".join(d.false_positives)
        scope = f" Scope the saved search to {', '.join(d.hosts)}." if d.hosts else ""
        return (
            f"name: {d.title}\n"
            f"id: {d.rule_id}\n"
            "version: 1\n"
            f"date: '{d.date}'\n"
            "author: intel-to-rule (draft, requires analyst review)\n"
            "status: experimental\n"
            "type: TTP\n"
            f"description: {d.description}\n"
            f"logsource: {LOGSOURCE[d.kind]}\n"
            f"search: |-\n{search}\n"
            f"how_to_implement: Needs the {LOGSOURCE[d.kind]} log source in Splunk.{scope}\n"
            f"known_false_positives: {fps}\n"
            + block("references", d.references)
            + block("cve", d.cves)
            + block("mitre_attack_id", d.techniques)
            + block("inventory_products", d.products)
            + f"level: {d.level}\n"
        )

    def add_values(self, rule: Rule, kind: str, values: list[str], meta: UpdateMeta) -> str | None:
        if kind not in FIELD_RE:
            return None
        items = [spl_quote(v, kind) for v in values]
        text = add_to_query_list(rule.text, FIELD_RE[kind], items)
        if text is None:
            return None
        text = bump_version(text)
        if re.search(r"^modification_date:", text, re.MULTILINE):
            text = set_top_scalar(text, "modification_date", meta.date)
        else:
            text = re.sub(r"^(date:.*)$", rf"\1\nmodification_date: '{meta.date}'", text, count=1, flags=re.MULTILINE)
        text = append_top_level_list(text, "cve", meta.cves)
        return append_top_level_list(text, "references", meta.references)

    def validate(self, text: str) -> list[str]:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            return [f"invalid YAML: {exc}"]
        if not isinstance(data, dict):
            return ["rule is not a mapping"]
        problems = [f"missing key '{k}'" for k in ("name", "id", "description", "search") if k not in data]
        search = str(data.get("search", ""))
        bare = _QUOTED.sub('""', search)
        if bare.count('"') % 2:
            problems.append("unbalanced double quotes in search")
        if bare.count("(") != bare.count(")"):
            problems.append("unbalanced parentheses in search")
        return problems
