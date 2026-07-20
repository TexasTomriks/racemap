"""Shared Pydantic data models used across scanner, triage and reporter layers."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Engine(str, Enum):
    """Which static-analysis engine produced a candidate."""

    COCCINELLE = "coccinelle"
    SEMGREP = "semgrep"


class Verdict(str, Enum):
    """LLM triage verdict for a candidate."""

    LIKELY_RACE = "likely_race"          # locking looks insufficient
    LIKELY_SAFE = "likely_safe"          # protected by lock / snapshot
    NEEDS_REVIEW = "needs_review"        # ambiguous, escalate to human
    TRIAGE_ERROR = "triage_error"        # LLM unavailable / parse failure


class Candidate(BaseModel):
    """A raw race-condition candidate emitted by a static analysis engine."""

    rule_id: str = Field(..., description="Identifier of the rule that fired")
    engine: Engine
    file: str = Field(..., description="Path to the source file, relative to kernel tree")
    line: int = Field(..., ge=1)
    function: Optional[str] = Field(None, description="Enclosing function name if known")
    subsystem: Optional[str] = Field(None, description="net / crypto / fs / io_uring etc.")
    snippet: str = Field("", description="Source excerpt around the match")
    message: str = Field("", description="Human-readable rule description")
    shared_field: Optional[str] = Field(
        None, description="The shared field / zero-copy primitive, e.g. ctx->iv, req->imu"
    )
    zero_copy_primitive: str = Field(
        "unknown",
        description="Classified zero-copy primitive: splice / vmsplice / io_uring "
        "/ zerocopy / aead / unknown (set from a ±15 line window).",
    )
    pattern_name: str = Field(
        "", description="Human-readable pattern name, e.g. aead_inplace_write."
    )
    mitigation_present: Optional[bool] = Field(
        None,
        description="Did the scanner see a copy/ownership/unshare mitigation near "
        "the sink? True ⇒ probably the fixed variant.",
    )
    cve_id: Optional[str] = Field(
        None, description="Associated CVE identifier, if this is a known-CVE pattern"
    )
    also_matched_by: list[str] = Field(
        default_factory=list,
        description="Rule ids of other findings collapsed into this one by "
        "Scanner._dedupe(). Structured rather than a note in `message`, so SARIF "
        "/ CSV / code-scanning consumers that group by rule id can still see "
        "that a line matched more than one rule.",
    )
    also_cve_ids: list[str] = Field(
        default_factory=list,
        description="CVE ids carried over from collapsed findings whose CVE "
        "differs from this candidate's own.",
    )
    # -- container escape assessment (src/scanner/container_escape.py) --------
    container_escape_potential: bool = Field(
        False,
        description="Whether this race is a plausible container-escape primitive.",
    )
    container_escape_reason: str = Field(
        "", description="Why the candidate is (or is not) a container-escape primitive."
    )
    # -- kernel version tracking (src/scanner/version_tracker.py) -------------
    affected_versions: list[str] = Field(
        default_factory=list,
        description="Known affected kernel version range, e.g. ['5.8', '5.16'].",
    )
    fixed_in: Optional[str] = Field(
        None, description="Kernel version the issue was fixed in, or None if open."
    )
    # -- taint tracking lite (src/scanner/taint.py) ---------------------------
    taint_propagated: bool = Field(
        False,
        description="Shared buffer/variable is passed to a callee that lacks a "
        "covering lock within 1 hop (risk escalation).",
    )
    taint_callee: Optional[str] = Field(
        None, description="The callee the flagged variable propagates into, if any."
    )
    # -- patch gap analysis (src/scanner/patch_gap.py) ------------------------
    patch_missing: bool = Field(
        False,
        description="A known patch signature for this pattern/subsystem is absent.",
    )
    # -- caller lock traversal (src/scanner/caller_lock.py) -------------------
    caller_lock_held: bool = Field(
        False,
        description="All callers (up to 3 hops) hold a covering lock before the "
        "candidate function — strong false-positive signal (-0.3).",
    )
    caller_lock_name: Optional[str] = Field(
        None, description="The lock held by callers, if any."
    )
    # -- sparse annotations (src/scanner/sparse_annotations.py) ---------------
    annotation_protected: bool = Field(
        False,
        description="A sparse annotation (__must_hold / __acquires) shows the "
        "access is lock-protected (-0.2).",
    )
    annotation_detail: Optional[str] = Field(
        None, description="The sparse annotation found, e.g. __must_hold(&ctx->lock)."
    )
    # -- memory barrier awareness (Part 3) ------------------------------------
    barrier_protected: bool = Field(
        False,
        description="A memory barrier (READ_ONCE/smp_mb/rcu_dereference/...) sits "
        "between the shared access and the async call (-0.15).",
    )
    # -- interrupt context (Part 4) -------------------------------------------
    interrupt_context_note: Optional[str] = Field(
        None,
        description="If set, the function/callers run in interrupt/atomic context "
        "(+0.1 escalation).",
    )
    # -- workqueue async path (Part 5) ----------------------------------------
    workqueue_async: bool = Field(
        False,
        description="A deferred execution path (INIT_WORK/queue_work/...) is near "
        "the shared access (+0.1 if no lock).",
    )
    # -- git log cross-reference (src/scanner/git_log.py) ---------------------
    recently_modified: bool = Field(
        False, description="The file has a commit in the last 90 days."
    )
    last_commit_date: Optional[str] = Field(None, description="Last commit date (ISO).")
    last_author_email: Optional[str] = Field(None, description="Last commit author email.")
    commit_count_90d: int = Field(0, description="Commits in the last 90 days.")
    git_age_note: Optional[str] = Field(
        None, description="Human-readable age, e.g. '2 weeks ago by foo@kernel.org'."
    )

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


class TriageResult(BaseModel):
    """Output of the LLM triage filter for a single candidate."""

    candidate: Candidate
    verdict: Verdict
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    reasoning_steps: list[str] = Field(
        default_factory=list,
        description="Forced chain-of-thought steps the triage model followed.",
    )
    lock_held: Optional[bool] = Field(
        None, description="Did the LLM find a lock covering the shared access?"
    )
    snapshot_taken: Optional[bool] = Field(
        None, description="Did the LLM find a per-request snapshot/copy?"
    )
    token_count: int = Field(
        0, description="Approximate token count of the context sent to the LLM."
    )
    confidence_low: float = Field(
        0.0, ge=0.0, le=1.0, description="Lower bound of the confidence band."
    )
    confidence_high: float = Field(
        0.0, ge=0.0, le=1.0, description="Upper bound of the confidence band."
    )
    model: str = Field("", description="Backend model that produced this result")

    @property
    def score(self) -> float:
        """Ranking score: race-likelihood weighted by confidence, with risk
        escalation for taint propagation (+0.2) and missing patches (+0.15)."""
        base = {
            Verdict.LIKELY_RACE: 1.0,
            Verdict.NEEDS_REVIEW: 0.5,
            Verdict.TRIAGE_ERROR: 0.4,
            Verdict.LIKELY_SAFE: 0.0,
        }[self.verdict]
        raw = base * (0.5 + 0.5 * self.confidence)
        if base > 0:  # only adjust a live (non-exonerated) candidate
            c = self.candidate
            # escalations
            if c.taint_propagated:
                raw += 0.2
            if c.patch_missing:
                raw += 0.15
            if c.interrupt_context_note:
                raw += 0.1
            if c.workqueue_async and not c.caller_lock_held:
                raw += 0.1
            # false-positive demotions
            if c.caller_lock_held:
                raw -= 0.3
            if c.annotation_protected:
                raw -= 0.2
            if c.barrier_protected:
                raw -= 0.15
        return round(min(max(raw, 0.0), 1.0), 4)


class ScanReport(BaseModel):
    """Top-level scan result, serialised to ranked JSON."""

    target: str
    kernel_version: Optional[str] = None
    subsystems: list[str] = Field(default_factory=list)
    candidates_found: int = 0
    results: list[TriageResult] = Field(default_factory=list)

    def ranked(self) -> list[TriageResult]:
        return sorted(self.results, key=lambda r: r.score, reverse=True)
