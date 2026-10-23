"""SQLite state so each finding is processed again only when its indicators change."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from .models import Finding


class Store:
    def __init__(self, path: str | Path):
        path = Path(path)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS findings (key TEXT PRIMARY KEY, data TEXT, fingerprint TEXT)")

    @staticmethod
    def fingerprint(f: Finding) -> str:
        payload = json.dumps([f.iocs, f.conditional, f.cves, f.kev], sort_keys=True)
        return hashlib.sha1(payload.encode()).hexdigest()  # noqa: S324 (change detection, not security)

    def get(self, key: str) -> Finding | None:
        row = self.db.execute("SELECT data FROM findings WHERE key=?", (key,)).fetchone()
        return Finding.from_dict(json.loads(row[0])) if row else None

    def is_processed(self, f: Finding) -> bool:
        row = self.db.execute("SELECT fingerprint FROM findings WHERE key=?", (f.key,)).fetchone()
        return bool(row) and row[0] == self.fingerprint(f)

    def save(self, f: Finding) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO findings VALUES (?, ?, ?)",
            (f.key, json.dumps(f.to_dict()), self.fingerprint(f)),
        )
        self.db.commit()
