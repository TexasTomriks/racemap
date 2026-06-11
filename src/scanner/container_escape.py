"""Container-escape potential assessment.

A shared page-cache / zero-copy race becomes a *container-escape primitive* when
the aliased buffer crosses an isolation boundary (user namespace, network
namespace, or the container/host page cache). This module applies a conservative
heuristic over the classified primitive and the candidate's file path. It never
asserts an exploit — only that the primitive is escape-relevant and warrants
priority review.
"""

from __future__ import annotations

from src.models import Candidate

# Per-primitive escape rationale (Bug 2: primitive-driven, always-on for these).
_PRIMITIVE_REASON = {
    "aead": "algif_skcipher/AEAD shared-IV crypto over the shared page cache — "
            "confirmed escape-relevant primitive (our finding)",
    "splice": "splice pipe pages cross user namespace boundary — container "
              "escape primitive",
    "vmsplice": "vmsplice user pages aliased into the kernel across the user-ns "
                "boundary — container escape primitive",
    "io_uring": "io_uring registered buffers shared with the container host — "
                "escape primitive",
    "zerocopy": "zerocopy skb shared across netns — potential host memory read",
}

# File-path segments reachable from inside a container.
_ESCAPE_PATH_SEGMENTS = ("net/", "crypto/", "io_uring/", "drivers/", "mystery/")


def assess(candidate: Candidate) -> tuple[bool, str]:
    """Return ``(container_escape_potential, reason)`` for a candidate."""
    # A mitigated (fixed) site is not a live primitive.
    if candidate.mitigation_present is True:
        return False, "mitigated (copy/ownership transfer present) — not a live primitive"

    prim = candidate.zero_copy_primitive or "unknown"
    path = (candidate.file or "").replace("\\", "/")

    # Primitive-driven escape classes (always escape-relevant).
    if prim in _PRIMITIVE_REASON:
        return True, _PRIMITIVE_REASON[prim]

    # Path-driven: a reachable subsystem with any known (non-unknown) primitive.
    if prim != "unknown" and any(seg in f"/{path}" or path.startswith(seg)
                                 for seg in _ESCAPE_PATH_SEGMENTS):
        return True, (f"race in {path.split('/')[0]}/ with zero-copy primitive "
                      f"'{prim}' — namespace isolation does not cover this path")

    return False, "primitive does not cross a namespace/page-cache boundary"


def annotate(candidate: Candidate) -> Candidate:
    """Set the container-escape fields on ``candidate`` in place and return it."""
    potential, reason = assess(candidate)
    candidate.container_escape_potential = potential
    candidate.container_escape_reason = reason
    return candidate
