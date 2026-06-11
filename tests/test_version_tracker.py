"""Kernel version-tracking tests."""

from src.models import Candidate, Engine
from src.scanner import version_tracker
from src.scanner.version_tracker import VERSION_DB, is_affected, kernel_is_affected


def _cand(**kw) -> Candidate:
    base = dict(rule_id="r", engine=Engine.COCCINELLE, file="f.c", line=1)
    base.update(kw)
    return Candidate(**base)


def test_cve_2022_0847_ranges():
    entry = VERSION_DB["CVE-2022-0847"]
    assert entry["affected"] == ["5.8", "5.16"]
    assert entry["fixed_in"] == "5.16.11"


def test_cve_2022_2590_ranges():
    entry = VERSION_DB["CVE-2022-2590"]
    assert entry["affected"] == ["5.16", "6.0"]
    assert entry["fixed_in"] == "6.0.8"


def test_is_affected_closed_range():
    assert is_affected("5.10", ["5.8", "5.16"]) is True
    assert is_affected("6.8", ["5.8", "5.16"]) is False   # past the fixed range
    assert is_affected("5.4", ["5.8", "5.16"]) is False   # before the range


def test_is_affected_open_ended():
    assert is_affected("6.8", ["6.1", "6.8+"]) is True
    assert is_affected("7.0", ["6.1", "6.8+"]) is True
    assert is_affected("6.0", ["6.1", "6.8+"]) is False


def test_annotate_sets_fields_for_cve():
    c = _cand(cve_id="CVE-2022-0847", shared_field="buf->flags CAN_MERGE")
    version_tracker.annotate(c)
    assert c.affected_versions == ["5.8", "5.16"]
    assert c.fixed_in == "5.16.11"


def test_annotate_sets_fields_for_pattern():
    c = _cand(shared_field="req->imu")
    version_tracker.annotate(c)
    assert c.affected_versions == ["5.1", "6.8+"]
    assert c.fixed_in is None


def test_kernel_is_affected_respects_fix():
    c = _cand(cve_id="CVE-2022-0847", shared_field="buf->flags CAN_MERGE")
    version_tracker.annotate(c)
    assert kernel_is_affected(c, "5.10") is True      # within range, before fix
    assert kernel_is_affected(c, "5.16.11") is False  # at the fix version
    assert kernel_is_affected(c, "6.8") is False      # past the range


def test_kernel_is_affected_open_pattern():
    c = _cand(shared_field="ctx->iv")
    version_tracker.annotate(c)
    assert kernel_is_affected(c, "6.8") is True       # open-ended, no fix yet
