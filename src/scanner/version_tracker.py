"""Kernel version tracking.

Maps each detected pattern / CVE to a known affected kernel version range and the
version it was fixed in (if any). A range is encoded as ``[low, high]`` where a
trailing ``+`` on the high bound means "and later" (open-ended, still affected at
HEAD). ``is_affected("6.8", ...)`` answers whether a given kernel falls in range.
"""

from __future__ import annotations

from typing import Optional

from src.models import Candidate

# Each entry: {"affected": [low, high], "fixed_in": <str|None>}.
VERSION_DB: dict[str, dict] = {
    # Known CVEs (keyed by cve_id).
    "CVE-2022-0847": {"affected": ["5.8", "5.16"], "fixed_in": "5.16.11"},
    "CVE-2022-2590": {"affected": ["5.16", "6.0"], "fixed_in": "6.0.8"},
    # racemap-detected patterns (keyed by Candidate.shared_field primitive).
    "ctx->iv": {"affected": ["6.1", "6.8+"], "fixed_in": None},          # algif_skcipher (our finding)
    "ctx->info": {"affected": ["6.1", "6.8+"], "fixed_in": None},
    "pipe->bufs[].page": {"affected": ["4.9", "6.8+"], "fixed_in": None},  # splice/pipe
    "gup pages": {"affected": ["4.0", "6.8+"], "fixed_in": None},          # vmsplice
    "req->imu": {"affected": ["5.1", "6.8+"], "fixed_in": None},           # io_uring fixed buffers
    "io_mapped_ubuf": {"affected": ["5.1", "6.8+"], "fixed_in": None},     # io_uring registered buffers
    "skb_shared_info": {"affected": ["4.14", "6.8+"], "fixed_in": None},   # MSG_ZEROCOPY
    "skb(shared_frag)": {"affected": ["5.10", "6.8+"], "fixed_in": None},  # tipc in-place AEAD
}


def _ver(s: str) -> tuple[int, int, int]:
    s = s.strip().rstrip("+")
    parts = s.split(".")
    nums = []
    for p in parts[:3]:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)  # type: ignore[return-value]


def lookup(candidate: Candidate) -> Optional[dict]:
    """Return the VERSION_DB entry for a candidate (CVE id takes precedence)."""
    if candidate.cve_id and candidate.cve_id in VERSION_DB:
        return VERSION_DB[candidate.cve_id]
    if candidate.shared_field and candidate.shared_field in VERSION_DB:
        return VERSION_DB[candidate.shared_field]
    return None


def is_affected(version: str, affected: list[str]) -> bool:
    """Whether ``version`` falls within the ``[low, high]`` affected range."""
    if not version or not affected:
        return False
    low = _ver(affected[0])
    high_raw = affected[-1]
    v = _ver(version)
    if high_raw.endswith("+"):
        return v >= low
    return low <= v <= _ver(high_raw)


def annotate(candidate: Candidate) -> Candidate:
    """Set ``affected_versions`` / ``fixed_in`` on ``candidate`` in place."""
    entry = lookup(candidate)
    if entry:
        candidate.affected_versions = list(entry["affected"])
        candidate.fixed_in = entry["fixed_in"]
    return candidate


def kernel_is_affected(candidate: Candidate, kernel_version: Optional[str]) -> bool:
    """Whether a specific kernel version is affected by this candidate, taking the
    fix version into account (a kernel >= fixed_in is not affected)."""
    if not kernel_version or not candidate.affected_versions:
        return False
    if not is_affected(kernel_version, candidate.affected_versions):
        return False
    if candidate.fixed_in and _ver(kernel_version) >= _ver(candidate.fixed_in):
        return False
    return True
