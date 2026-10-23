"""Shared types and text-editing helpers for the rule format adapters.

Rules are edited as text, not re-serialised, so the pull request diff shows only
the lines that really changed (comments and ordering stay intact).
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..util import norm_ioc


@dataclass
class Rule:
    id: str
    title: str
    format: str  # sigma | splunk | elastic
    path: str
    text: str
    products: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    logsource: str = ""
    level: str = ""
    # Normalised literal strings the rule looks for (see util.norm_ioc)
    indicators: set[str] = field(default_factory=set)


@dataclass
class Draft:
    """Format-neutral description of a rule to create."""

    title: str
    rule_id: str
    description: str
    references: list[str]
    false_positives: list[str]
    level: str
    cves: list[str]
    techniques: list[str]
    products: list[str]
    date: str
    kind: str  # an IOC kind, or "uri_long_host"
    values: list[str] = field(default_factory=list)
    condition: dict = field(default_factory=dict)
    hosts: list[str] = field(default_factory=list)


class RuleFormat(ABC):
    name: str
    extensions: tuple[str, ...]

    @abstractmethod
    def load(self, path: str, text: str) -> Rule: ...

    @abstractmethod
    def render(self, draft: Draft) -> str: ...

    @abstractmethod
    def add_values(self, rule: Rule, kind: str, values: list[str], meta: "UpdateMeta") -> str | None:
        """Return the rule text with `values` added to the matching list, or None if it cannot be done safely."""

    @abstractmethod
    def validate(self, text: str) -> list[str]:
        """Return a list of problems; empty means the rule is structurally valid."""

    def filename(self, draft: Draft) -> str:
        return f"{draft.kind}_{draft.rule_id[:8]}{self.extensions[0]}"


@dataclass
class UpdateMeta:
    """Extra data written into an updated rule alongside the new values."""

    date: str
    cves: list[str]
    references: list[str]
    techniques: list[str]


# ---------------------------------------------------------------- query lists

def _unquote(item: str) -> str:
    return item.strip().strip("'\"")


def add_to_query_list(query: str, field_re: str, items: list[str]) -> str | None:
    """Append already-quoted `items` to the first `field IN (...)` / `field : (...)` list.

    Works for SPL (`Web.url IN ("a", "b")`) and Elastic (`url.original : ("a", "b")`).
    """
    pattern = re.compile(
        rf"(?P<head>(?<![\w.]){field_re}\s*(?:\bIN\b|\bin\b|:)\s*\()(?P<body>[^)]*)(?P<tail>\))"
    )
    match = pattern.search(query)
    if not match:
        return None
    body = match.group("body")
    existing = {_unquote(x).lower() for x in re.split(r"\s+or\s+|,", body) if x.strip()}
    fresh = [i for i in items if _unquote(i).lower() not in existing]
    if not fresh:
        return query
    sep = " or " if re.search(r"\sor\s", body) else ", "
    stripped = body.rstrip()
    new_body = stripped + sep + sep.join(fresh) + body[len(stripped):]
    return query[: match.start("body")] + new_body + query[match.end("body"):]


# ---------------------------------------------------------------- YAML text edits

def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def add_to_yaml_field_list(text: str, field_key: str, values: list[str]) -> str | None:
    """Add values to a `field_key:` list inside a Sigma selection (never inside a filter)."""
    lines = text.splitlines()
    key_re = re.compile(rf"^(\s*){re.escape(field_key)}:\s*$")
    for i, line in enumerate(lines):
        m = key_re.match(line)
        if not m:
            continue
        if _in_filter(lines, i):
            continue
        last = i
        j = i + 1
        while j < len(lines) and re.match(r"^\s*-\s", lines[j]) and _indent_of(lines[j]) > _indent_of(line):
            last = j
            j += 1
        if last == i:
            return None
        item_indent = " " * _indent_of(lines[last])
        existing = {norm_ioc(_unquote(re.sub(r"^\s*-\s*", "", lines[k]))) for k in range(i + 1, last + 1)}
        fresh = [v for v in values if norm_ioc(v) not in existing]
        lines[last + 1: last + 1] = [f"{item_indent}- {yaml_quote(v)}" for v in fresh]
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return None


def _in_filter(lines: list[str], idx: int) -> bool:
    indent = _indent_of(lines[idx])
    for k in range(idx - 1, -1, -1):
        if lines[k].strip() and _indent_of(lines[k]) < indent and lines[k].rstrip().endswith(":"):
            return lines[k].strip().startswith("filter")
    return False


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def append_top_level_list(text: str, key: str, items: list[str], quote: bool = False) -> str:
    """Append items to a top-level list, creating the key at the end if it does not exist."""
    lines = text.rstrip("\n").splitlines()
    # `key: []` is an empty list written inline, turn it into a block list first
    lines = [f"{key}:" if re.match(rf"^{re.escape(key)}:\s*\[\]\s*$", ln) else ln for ln in lines]
    key_re = re.compile(rf"^{re.escape(key)}:\s*$")
    for i, line in enumerate(lines):
        if not key_re.match(line):
            continue
        last = i
        j = i + 1
        while j < len(lines) and re.match(r"^\s*-\s", lines[j]):
            last = j
            j += 1
        indent = " " * (_indent_of(lines[last]) if last > i else 2)
        existing = {_unquote(re.sub(r"^\s*-\s*", "", lines[k])) for k in range(i + 1, last + 1)}
        fresh = [x for x in items if x not in existing]
        lines[last + 1: last + 1] = [f"{indent}- {yaml_quote(x) if quote else x}" for x in fresh]
        return "\n".join(lines) + "\n"
    block = [f"{key}:"] + [f"  - {yaml_quote(x) if quote else x}" for x in items]
    return "\n".join(lines + block) + "\n"


def set_top_scalar(text: str, key: str, value: str) -> str:
    """Replace `key: value` keeping its quote style; insert it at the end if missing."""
    pattern = re.compile(rf"^({re.escape(key)}:\s*)(['\"]?)(.*?)(['\"]?)\s*$", re.MULTILINE)
    m = pattern.search(text)
    if m:
        q = m.group(2)
        return text[: m.start()] + f"{m.group(1)}{q}{value}{q}" + text[m.end():]
    return text.rstrip("\n") + f"\n{key}: {value}\n"


def bump_version(text: str) -> str:
    m = re.search(r"^version:\s*(\d+)\s*$", text, re.MULTILINE)
    if not m:
        return text
    return text[: m.start()] + f"version: {int(m.group(1)) + 1}" + text[m.end():]
