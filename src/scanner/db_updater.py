"""Patch-signature DB updater.

Refreshes the patch-gap signature database by querying the GitHub commits API for
the torvalds/linux tree and looking for commits that mention each tracked CVE.
Falls back silently to the built-in signatures whenever the network or API is
unavailable. The local DB lives at ~/.racemap/patch_db.json and is considered
fresh for 7 days.
"""

from __future__ import annotations

import datetime
import json
import re
from pathlib import Path
from typing import Optional

DB_PATH = Path.home() / ".racemap" / "patch_db.json"
TTL_DAYS = 7
GITHUB_COMMITS = "https://api.github.com/repos/torvalds/linux/commits"

# Canonical built-in signatures (single source of truth; patch_gap imports these).
BUILTIN_SIGNATURES: dict[str, str] = {
    "CVE-2022-0847": r"buf->flags\s*=\s*0",          # Dirty Pipe: flags zero-init
    "CVE-2022-2590": r"\bvma_lookup\b",              # mmap race: VMA re-validate
    "ctx->iv": r"memcpy\s*\([^;]*ctx->iv",           # algif: per-request IV snapshot
    "ctx->info": r"memcpy\s*\([^;]*ctx->info",
    "pipe->bufs[].page": r"\bpipe_buf_get\b",        # splice: take a page ref
    "req->imu": r"\bunpin_user_page\b",              # io_uring: unpin after copy
    "gup pages": r"\bset_page_dirty\b",              # vmsplice: dirty + put
    "skb_shared_info": r"\bskb_unshare\b",           # zerocopy: unshare before write
}

# CVEs we try to refresh from upstream.
CVES = [k for k in BUILTIN_SIGNATURES if k.startswith("CVE-")]


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_days(ts: str) -> Optional[float]:
    try:
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
        return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 86400
    except Exception:
        return None


def _signature_from_commit(commit: dict, cve: str) -> Optional[str]:
    """Derive a signature from a commit's added lines, else keep the built-in."""
    for f in commit.get("files", []) or []:
        for line in (f.get("patch", "") or "").splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                m = re.search(r"[A-Za-z_][A-Za-z0-9_]{3,}", line[1:])
                if m:
                    return re.escape(m.group(0))
    return BUILTIN_SIGNATURES.get(cve)


def fetch_latest_signatures() -> dict:
    """Query GitHub for each tracked CVE and refresh its signature.

    Returns ``{"updated": N, "new": M, "errors": [...], "timestamp": ISO,
    "signatures": {...}}``. Always returns a valid structure; on any failure the
    built-in signatures are preserved and the error is recorded.
    """
    result = {"updated": 0, "new": 0, "errors": [], "timestamp": _now_iso(),
              "signatures": dict(BUILTIN_SIGNATURES)}
    try:
        import requests
    except Exception as exc:
        result["errors"].append(f"requests unavailable: {exc}")
        return result

    for cve in CVES:
        try:
            resp = requests.get(
                GITHUB_COMMITS, params={"per_page": 50},
                headers={"Accept": "application/vnd.github+json"}, timeout=10)
            resp.raise_for_status()
            commits = resp.json()
            matched = None
            for commit in commits or []:
                msg = (commit.get("commit") or {}).get("message", "")
                if cve in msg:
                    matched = commit
                    break
            if matched:
                sig = _signature_from_commit(matched, cve)
                if sig:
                    if cve in BUILTIN_SIGNATURES:
                        result["updated"] += 1
                    else:
                        result["new"] += 1
                    result["signatures"][cve] = sig
        except Exception as exc:
            result["errors"].append(f"{cve}: {exc}")
    return result


def update_local_db(result: dict) -> Path:
    """Persist refreshed signatures to ~/.racemap/patch_db.json."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": result.get("timestamp", _now_iso()),
        "signatures": result.get("signatures", dict(BUILTIN_SIGNATURES)),
    }
    DB_PATH.write_text(json.dumps(payload, indent=2))
    return DB_PATH


def get_db() -> dict:
    """Return the local DB if present and fresh (<7 days); else the built-in DB."""
    try:
        if DB_PATH.exists():
            data = json.loads(DB_PATH.read_text())
            ts = data.get("timestamp")
            age = _age_days(ts) if ts else None
            sigs = data.get("signatures")
            if age is not None and age < TTL_DAYS and isinstance(sigs, dict) and sigs:
                return sigs
    except Exception:
        pass
    return dict(BUILTIN_SIGNATURES)


def last_update_info() -> dict:
    """Metadata for the UI: timestamp + age in days (or None / 'Never')."""
    try:
        if DB_PATH.exists():
            data = json.loads(DB_PATH.read_text())
            ts = data.get("timestamp")
            return {"timestamp": ts, "age_days": _age_days(ts) if ts else None}
    except Exception:
        pass
    return {"timestamp": None, "age_days": None}
