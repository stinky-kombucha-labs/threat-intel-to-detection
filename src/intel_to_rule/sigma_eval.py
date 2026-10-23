"""Tiny Sigma evaluator used for replay checks ("does the old rule see this event, does the new one?").

Supports the subset the pipeline itself generates: field modifiers contains/startswith/endswith/re/all,
OR over value lists, AND over fields, and conditions with and/or/not, parentheses and `1 of` / `all of`.
It is not a replacement for a real backend, it only proves the draft matches the attack event.
"""
from __future__ import annotations

import fnmatch
import re

import yaml


def _field_match(event: dict, key: str, expected) -> bool:
    name, *mods = key.split("|")
    actual = event.get(name)
    if actual is None:
        return expected is None
    actual = str(actual)
    values = expected if isinstance(expected, list) else [expected]

    def one(value) -> bool:
        a, v = actual.lower(), str(value).lower()
        if "contains" in mods:
            return v in a
        if "startswith" in mods:
            return a.startswith(v)
        if "endswith" in mods:
            return a.endswith(v)
        if "re" in mods:
            return re.search(str(value), actual) is not None
        return fnmatch.fnmatchcase(a, v)

    results = [one(v) for v in values]
    return all(results) if "all" in mods else any(results)


def _selection_match(event: dict, selection) -> bool:
    if isinstance(selection, dict):
        return all(_field_match(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):  # list of maps = OR
        return any(_selection_match(event, s) for s in selection)
    return False


_TOKEN = re.compile(r"\(|\)|[^\s()]+")


def _eval_condition(cond: str, results: dict[str, bool]) -> bool:
    tokens = _TOKEN.findall(cond)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def quantifier(word: str) -> bool:
        nonlocal pos
        take()  # "of"
        target = take()
        names = list(results) if target == "them" else [n for n in results if fnmatch.fnmatchcase(n, target)]
        vals = [results[n] for n in names]
        return all(vals) if word == "all" and vals else any(vals)

    def atom() -> bool:
        tok = take()
        if tok == "(":
            val = expr()
            take()  # ")"
            return val
        if tok == "not":
            return not atom()
        if tok in ("1", "all") and peek() == "of":
            return quantifier(tok)
        return results[tok]

    def conj() -> bool:
        val = atom()
        while peek() == "and":
            take()
            val = atom() and val
        return val

    def expr() -> bool:
        val = conj()
        while peek() == "or":
            take()
            val = conj() or val
        return val

    return expr()


def matches(rule_text: str, event: dict) -> bool:
    detection = yaml.safe_load(rule_text)["detection"]
    results = {k: _selection_match(event, v) for k, v in detection.items() if k != "condition"}
    return _eval_condition(str(detection["condition"]), results)
