from __future__ import annotations

import json
import urllib.request
from typing import Any

USER_AGENT = "intel-to-rule/0.1 (+https://github.com/; detection engineering research)"


def http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (https URLs from config)
        return response.read()


def http_get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> Any:
    return json.loads(http_get(url, headers, timeout))
