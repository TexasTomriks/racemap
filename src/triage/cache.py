"""SQLite triage response cache (Part 6 — demo mode).

Caches LLM triage verdicts so a live demo is reliable and fast. In ``--demo-mode``
results are always served from the cache (never calling an LLM API); otherwise the
cache is checked first and a miss is computed and stored. Entries older than the
TTL (7 days) are ignored.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

from src.models import Candidate, TriageResult, Verdict

DEFAULT_DB = Path.home() / ".racemap" / "cache.db"
TTL_SECONDS = 7 * 24 * 3600


class TriageCache:
    def __init__(self, db_path: Optional[Path] = None, ttl: int = TTL_SECONDS) -> None:
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.ttl = ttl
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS triage_cache ("
            "key TEXT PRIMARY KEY, verdict TEXT, confidence REAL, "
            "confidence_low REAL, confidence_high REAL, reasoning TEXT, "
            "reasoning_steps TEXT, lock_held INTEGER, snapshot_taken INTEGER, "
            "token_count INTEGER, backend TEXT, ts REAL)"
        )
        self._conn.commit()

    @staticmethod
    def key(candidate: Candidate) -> str:
        raw = (f"{candidate.file}|{candidate.line}|{candidate.zero_copy_primitive}|"
               f"{(candidate.snippet or '')[:200]}")
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[dict]:
        cur = self._conn.execute("SELECT * FROM triage_cache WHERE key=?", (key,))
        row = cur.fetchone()
        if not row:
            return None
        cols = [d[0] for d in cur.description]
        rec = dict(zip(cols, row))
        if time.time() - rec.get("ts", 0) > self.ttl:
            return None  # expired
        return rec

    def put(self, key: str, result: TriageResult) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO triage_cache VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                key, result.verdict.value, result.confidence,
                result.confidence_low, result.confidence_high, result.reasoning,
                json.dumps(result.reasoning_steps),
                _b2i(result.lock_held), _b2i(result.snapshot_taken),
                result.token_count, result.model, time.time(),
            ),
        )
        self._conn.commit()

    def to_result(self, candidate: Candidate, rec: dict) -> TriageResult:
        try:
            verdict = Verdict(rec["verdict"])
        except (ValueError, KeyError):
            verdict = Verdict.NEEDS_REVIEW
        return TriageResult(
            candidate=candidate,
            verdict=verdict,
            confidence=rec.get("confidence", 0.5) or 0.5,
            confidence_low=rec.get("confidence_low", 0.0) or 0.0,
            confidence_high=rec.get("confidence_high", 0.0) or 0.0,
            reasoning=rec.get("reasoning", "") or "",
            reasoning_steps=json.loads(rec.get("reasoning_steps") or "[]"),
            lock_held=_i2b(rec.get("lock_held")),
            snapshot_taken=_i2b(rec.get("snapshot_taken")),
            token_count=rec.get("token_count", 0) or 0,
            model=f"{rec.get('backend', 'cache')} [CACHED]",
        )

    def clear(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM triage_cache")
        n = cur.fetchone()[0]
        self._conn.execute("DELETE FROM triage_cache")
        self._conn.commit()
        return n

    def close(self) -> None:
        self._conn.close()


def _b2i(v: Optional[bool]) -> Optional[int]:
    return None if v is None else int(v)


def _i2b(v) -> Optional[bool]:
    return None if v is None else bool(v)
