"""Native Elastic Security detection rules (JSON, as exported from Kibana)."""
from __future__ import annotations

import json
import re

from ..util import norm_ioc
from .base import Draft, Rule, RuleFormat, UpdateMeta, add_to_query_list

FIELD_RE = {
    "uri": r"url\.(?:original|path|full)",
    "dir": r"file\.path",
    "filename": r"file\.path",
    "cmdline": r"process\.command_line",
}
WILDCARD = {"uri": "*{}*", "dir": "*{}*", "filename": "*{}", "cmdline": "*{}*"}
LOGSOURCE = {"uri": "webserver", "dir": "file_event", "filename": "file_event",
             "cmdline": "process_creation", "uri_long_host": "proxy"}
SCRIPT_EXTENSIONS = ("aspx", "ashx", "asmx", "jsp", "php")

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
SEVERITY = {"low": (21, "low"), "medium": (47, "medium"), "high": (73, "high"), "critical": (99, "critical")}


def eql_quote(value: str, kind: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + WILDCARD[kind].format(escaped) + '"'


class ElasticFormat(RuleFormat):
    name = "elastic"
    extensions = (".json",)

    def load(self, path: str, text: str) -> Rule:
        data = json.loads(text)
        tags = data.get("tags", [])

        def tagged(prefix: str) -> list[str]:
            return [t.split(":", 1)[1].strip() for t in tags if t.startswith(prefix)]

        literals = (m.replace("\\\\", "\\") for m in _QUOTED.findall(data.get("query", "")))
        return Rule(
            id=str(data.get("rule_id", "")),
            title=data.get("name", ""),
            format=self.name,
            path=path,
            text=text,
            products=tagged("Product:"),
            cves=[c.upper() for c in tagged("CVE:")],
            techniques=[t["technique"][0]["id"].upper() for t in data.get("threat", []) if t.get("technique")],
            logsource=(tagged("Logsource:") or [""])[0],
            level=data.get("severity", ""),
            indicators={n for s in literals if len(n := norm_ioc(s)) >= 4},
        )

    def _query(self, d: Draft) -> str:
        if d.kind == "uri_long_host":
            return (
                f'any where url.path : "*{d.condition["uri"]}*" '
                f'and length(url.domain) >= {d.condition["host_min_length"]}'
            )
        vals = ", ".join(eql_quote(v, d.kind) for v in d.values)
        if d.kind == "uri":
            return f"any where url.original : ({vals})"
        if d.kind == "dir":
            exts = ", ".join(f'"{e}"' for e in SCRIPT_EXTENSIONS)
            return (
                'file where event.action in ("creation", "overwrite") '
                f"and file.path : ({vals}) and file.extension : ({exts})"
            )
        if d.kind == "filename":
            return f'file where event.action in ("creation", "overwrite") and file.path : ({vals})'
        return f'process where event.type == "start" and process.command_line : ({vals})'

    def render(self, d: Draft) -> str:
        risk, severity = SEVERITY.get(d.level, SEVERITY["medium"])
        tags = ["Use Case: Threat Detection", "Source: intel-to-rule", f"Logsource: {LOGSOURCE[d.kind]}"]
        tags += [f"CVE: {c}" for c in d.cves] + [f"Product: {p}" for p in d.products]
        rule = {
            "name": d.title,
            "rule_id": d.rule_id,
            "description": d.description,
            "type": "eql",
            "language": "eql",
            "index": ["logs-*", "winlogbeat-*", "filebeat-*"],
            "query": self._query(d),
            "risk_score": risk,
            "severity": severity,
            "tags": tags,
            "threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "technique": [{"id": t, "reference": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}],
                }
                for t in d.techniques
            ],
            "false_positives": d.false_positives,
            "references": d.references,
            "author": ["intel-to-rule (draft, requires analyst review)"],
            "version": 1,
        }
        return json.dumps(rule, indent=2) + "\n"

    def add_values(self, rule: Rule, kind: str, values: list[str], meta: UpdateMeta) -> str | None:
        if kind not in FIELD_RE:
            return None
        data = json.loads(rule.text)
        items = [eql_quote(v, kind) for v in values]
        query = add_to_query_list(data.get("query", ""), FIELD_RE[kind], items)
        if query is None:
            return None
        data["query"] = query
        data["version"] = int(data.get("version", 1)) + 1
        data["references"] = list(dict.fromkeys([*data.get("references", []), *meta.references]))
        tags = data.get("tags", [])
        data["tags"] = list(dict.fromkeys([*tags, *[f"CVE: {c}" for c in meta.cves]]))
        return json.dumps(data, indent=2) + "\n"

    def validate(self, text: str) -> list[str]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return [f"invalid JSON: {exc}"]
        problems = [f"missing key '{k}'" for k in ("name", "rule_id", "query", "type", "severity") if k not in data]
        query = data.get("query", "")
        bare = _QUOTED.sub('""', query)
        if bare.count('"') % 2:
            problems.append("unbalanced double quotes in query")
        if bare.count("(") != bare.count(")"):
            problems.append("unbalanced parentheses in query")
        return problems
