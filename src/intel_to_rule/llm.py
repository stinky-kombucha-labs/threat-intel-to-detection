"""Optional LLM steps. The pipeline works without them, using regex extraction and templated rules.

The LLM never writes to the SIEM or the repository. Its output is parsed as JSON and passes through the same
validation and replay checks as everything else.
"""
from __future__ import annotations

import json
import os
import re

from .inventory import Inventory
from .models import RawItem

DEFAULT_MODEL = "claude-sonnet-5-5"

EXTRACT_SYSTEM = """You extract structured detection intelligence from a security advisory or blog post.
Reply with one JSON object and nothing else. Use only facts stated in the text. Leave a field empty when the
text does not state it. Keys:
cves (list of CVE IDs), products (list of product names), affected (list of {product, introduced, fixed}),
iocs ({uri: [...], dir: [...], filename: [...], cmdline: [...]}), conditional (list of
{kind: "uri_long_host", uri, host_min_length}), techniques (MITRE ATT&CK IDs), first_exploited (YYYY-MM-DD or
YYYY-MM), summary (max 2 sentences).
iocs.uri holds URL paths seen in attacker requests. iocs.dir holds directories where attackers drop files."""


class LLM:
    def __init__(self, model: str | None = None):
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Install the 'llm' extra: pip install -e .[llm]") from exc
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic()
        self.model = model or os.environ.get("INTEL_TO_RULE_MODEL", DEFAULT_MODEL)

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        response = self._client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def _json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    return json.loads(match.group(0)) if match else {}


def extract(llm: LLM, raw: RawItem, inventory: Inventory) -> dict:
    products = ", ".join(a.product for a in inventory.assets)
    user = f"Products the reader cares about: {products}\n\nTitle: {raw.title}\nURL: {raw.url}\n\n{raw.text[:12000]}"
    return _json(llm.complete(EXTRACT_SYSTEM, user))
