"""Patch-DB updater tests (GitHub API mocked)."""

import json
from unittest import mock

import pytest

from src.scanner import db_updater


def _fake_commits(messages_with_files):
    """Build a fake GitHub commits-list response."""
    commits = []
    for msg, patch in messages_with_files:
        c = {"commit": {"message": msg}}
        if patch is not None:
            c["files"] = [{"patch": patch}]
        commits.append(c)
    return commits


def _resp(json_data):
    r = mock.MagicMock()
    r.raise_for_status.return_value = None
    r.json.return_value = json_data
    return r


@mock.patch("src.scanner.db_updater.DB_PATH")
def test_fetch_structure_and_updated(mock_db, tmp_path, monkeypatch):
    # All CVEs found in commit messages -> updated count == number of CVEs.
    commits = _fake_commits([(f"net: fix {c}", None) for c in db_updater.CVES])
    fake_requests = mock.MagicMock()
    fake_requests.get.return_value = _resp(commits)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)

    result = db_updater.fetch_latest_signatures()
    assert set(result.keys()) >= {"updated", "new", "errors", "timestamp", "signatures"}
    assert result["updated"] == len(db_updater.CVES)
    assert result["errors"] == []
    assert "CVE-2022-0847" in result["signatures"]
    assert result["timestamp"].endswith("Z")


def test_fetch_derives_signature_from_added_lines(monkeypatch):
    commits = _fake_commits([("fix CVE-2022-0847 dirty pipe",
                              "@@\n-old\n+\tbuf->flags = 0;\n")])
    fake_requests = mock.MagicMock()
    fake_requests.get.return_value = _resp(commits)
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    result = db_updater.fetch_latest_signatures()
    # Signature for CVE-2022-0847 derived from an added-line token.
    assert result["signatures"]["CVE-2022-0847"]
    assert result["updated"] >= 1


def test_fetch_graceful_on_network_error(monkeypatch):
    fake_requests = mock.MagicMock()
    fake_requests.get.side_effect = Exception("no network")
    monkeypatch.setitem(__import__("sys").modules, "requests", fake_requests)
    result = db_updater.fetch_latest_signatures()
    assert result["updated"] == 0
    assert result["errors"]                       # error recorded, no crash
    assert result["signatures"] == db_updater.BUILTIN_SIGNATURES


def test_update_local_db_writes_json(tmp_path, monkeypatch):
    db = tmp_path / "patch_db.json"
    monkeypatch.setattr(db_updater, "DB_PATH", db)
    result = {"timestamp": db_updater._now_iso(),
              "signatures": {"CVE-2022-0847": r"buf->flags\s*=\s*0"}}
    db_updater.update_local_db(result)
    data = json.loads(db.read_text())
    assert data["signatures"]["CVE-2022-0847"] == r"buf->flags\s*=\s*0"
    assert "timestamp" in data


def test_get_db_returns_local_when_fresh(tmp_path, monkeypatch):
    db = tmp_path / "patch_db.json"
    monkeypatch.setattr(db_updater, "DB_PATH", db)
    db.write_text(json.dumps({"timestamp": db_updater._now_iso(),
                              "signatures": {"X": "sig"}}))
    assert db_updater.get_db() == {"X": "sig"}


def test_get_db_falls_back_when_stale(tmp_path, monkeypatch):
    db = tmp_path / "patch_db.json"
    monkeypatch.setattr(db_updater, "DB_PATH", db)
    db.write_text(json.dumps({"timestamp": "2000-01-01T00:00:00Z",
                              "signatures": {"X": "sig"}}))
    assert db_updater.get_db() == db_updater.BUILTIN_SIGNATURES


def test_get_db_falls_back_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(db_updater, "DB_PATH", tmp_path / "nope.json")
    assert db_updater.get_db() == db_updater.BUILTIN_SIGNATURES
