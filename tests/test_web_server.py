"""Smoke tests for web/server.py and the (unused-in-the-demo) Streamlit
dashboard. Neither had any test coverage before this: a change here could
break silently and no CI run would notice. This isn't a full endpoint
suite -- see the project's own manual endpoint pass for that -- just enough
to catch an import-time crash or a wired-wrong route.
"""
from __future__ import annotations

import importlib

import pytest

import web.server as server


@pytest.fixture()
def client():
    server.app.config["TESTING"] = True
    return server.app.test_client()


def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"RACEMAP" in resp.data


def test_scan_requires_kernel_version(client):
    resp = client.post("/api/scan", json={"path": "tests/sample_kernel"})
    assert resp.status_code == 400
    assert "Kernel version" in resp.get_json()["error"]


def test_scan_sample_kernel(client):
    resp = client.post("/api/scan", json={
        "path": "tests/sample_kernel", "llm": "heuristic", "kernel_version": "6.9",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["summary"]["candidates"] == 23
    assert body["summary"]["races"] == 12


def test_cache_status(client):
    resp = client.get("/api/cache-status")
    assert resp.status_code == 200
    assert "count" in resp.get_json()


def test_resolve_allows_absolute_path_by_default(monkeypatch):
    # Pin explicitly rather than asserting the ambient state: a RACEMAP_ROOT
    # set in the environment running pytest would otherwise make this test
    # fail for a reason that has nothing to do with the behavior it checks.
    monkeypatch.setattr(server, "_ALLOWED_ROOT", None)
    resolved = server._resolve(str(server.ROOT / "tests" / "sample_kernel"))
    assert resolved.exists()


def test_resolve_enforces_racemap_root(monkeypatch):
    monkeypatch.setattr(server, "_ALLOWED_ROOT", (server.ROOT / "tests").resolve())
    server._resolve(str(server.ROOT / "tests" / "sample_kernel"))  # inside: fine
    with pytest.raises(PermissionError):
        server._resolve(str(server.ROOT))  # outside: rejected


def test_streamlit_dashboard_imports():
    """Not exercised by the demo video or CI otherwise -- just confirm it
    still imports cleanly so it doesn't silently bit-rot. streamlit is a
    real requirements.txt dependency, but skip (not fail) if it's somehow
    missing -- same "optional toolchain" convention as the spatch-only
    rules in test_coccinelle_only_rules.py."""
    pytest.importorskip("streamlit")
    importlib.import_module("src.ui.app")
