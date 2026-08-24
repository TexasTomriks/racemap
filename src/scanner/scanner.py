"""Scanner: runs Coccinelle + Semgrep rules over a kernel tree and normalises
their output into :class:`Candidate` objects.

Design notes
------------
* The default engine is the built-in matcher (`_regex_scan`), driven by a table
  of :class:`_Detector` specs (one per zero-copy attack surface) plus two
  bespoke patterns kept for backward compatibility. It needs no external
  toolchain, so a scan is hermetic and reproduces identically everywhere, and it
  reports both the vulnerable and the guarded shape of each pattern so the
  triage layer has something to exonerate.
* ``external_tools=True`` (``--external-tools``) shells out to ``spatch``
  (Coccinelle) and ``semgrep`` against ``rules/`` instead, parsing their output
  into the same :class:`Candidate` shape. If a binary is missing it degrades
  gracefully with a warning and the built-in matcher takes over. That path finds
  fewer sites, because the rule files encode only the vulnerable shapes.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Pattern

from src.models import Candidate, Engine
from src.scanner import (
    container_escape, version_tracker, taint, caller_lock,
    sparse_annotations, barrier, interrupt_ctx, workqueue, git_log,
)

# Map top-level kernel dirs to the subsystem labels we care about.
_SUBSYSTEM_MAP = {
    "net": "net",
    "crypto": "crypto",
    "drivers/char": "drivers/char",
    "io_uring": "io_uring",
    "fs": "fs",
    "mystery": "mystery",
}

# Crypto/async request setters that take an IV / state pointer as their last arg.
_SINK_FUNCS = (
    "skcipher_request_set_crypt",
    "aead_request_set_crypt",
    "ablkcipher_request_set_crypt",
    "akcipher_request_set_crypt",
)

# Shared fields that must be snapshotted under lock before being handed to a sink.
_SHARED_FIELD_RE = re.compile(r"\bctx->(iv|key|info|state)\b")

# In-place AEAD decrypt: src and dst are the same scatterlist (backreference).
_INPLACE_RE = re.compile(
    r"aead_request_set_crypt\(\s*\w+\s*,\s*(\w+)\s*,\s*\1\s*,"
)

# Preprocessor branch directives. Detector windows are clipped at these so a
# #ifndef FIXED (vulnerable) branch never reads a mitigation that lives in the
# paired #else (fixed) branch of the same fixture.
_CPP_BRANCH_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b")

# Mitigation check per rule family, for candidates an external engine reported
# without a verdict. Coccinelle and Semgrep report a match without saying whether
# the site is already guarded; without this every external finding would come
# back "likely race" and the exonerated variants would disappear. Each entry mirrors the matching built-in detector's own
# `mitigation` regex, so the question asked is always "is *this* pattern's
# mitigation present?".
#
# A flat union of every token was tried first and was wrong twice over. It
# exonerated `net/tipc/crypto.c` because `skb_cow_data()` was in the union,
# although copying the data does not make the fragments unshared — precisely the
# site the Dirty Frag fixture exists to catch. More generally it would exonerate
# any candidate that merely sits near *some* known mitigation call: a shared-IV
# hit next to an unrelated put_page(), say. Rule families not listed here get no
# verdict at all (None) rather than a guess, and the triage layer falls back to
# its own lock/annotation/barrier signals.
_MITIGATION_BY_RULE: tuple[tuple[str, Pattern], ...] = (
    # Order matters: check the narrower in-place rule before the shared-IV one,
    # since a Semgrep in-place hit can also mention ctx-> fields.
    ("inplace",   re.compile(r"\bskb_has_shared_frag\b")),
    ("sharediv",  re.compile(r"\bmemcpy\b")),
    ("sharedstate", re.compile(r"\bmemcpy\b")),
    # Two distinct io_uring detectors normalise to "iouring", and their
    # mitigations are not interchangeable: Pattern A is about unpinning a
    # registered buffer, A2 about copying before a network send. Merging them
    # both missed a real `skb_copy` mitigation on A2 and exonerated A next to an
    # unrelated `sk_msg_memcopy`. Match the specific fragments first; a rule that
    # covers both (io_uring_race.cocci) is genuinely ambiguous and falls through
    # to no verdict rather than a guess.
    ("fixedbuffer", re.compile(r"\b(memcpy|copy_page|copy_from_user|"
                               r"unpin_user_page|io_buffer_unmap|"
                               r"kmap_local_page)\b")),
    ("netsend",     re.compile(r"\b(memcpy|copy_from_user|skb_copy|"
                               r"kmap_local_page|sk_msg_memcopy)\b")),
    # vmsplice before splice: "splice" is a substring of "vmsplice".
    ("vmsplice",  re.compile(r"\b(set_page_dirty|put_page|copy_page|memcpy)\b")),
    ("splice",    re.compile(r"\b(pipe_buf_get|copy_page|get_page)\b")),
    ("zerocopy",  re.compile(r"\b(skb_unshare|skb_copy|pskb_copy|pskb_expand_head)\b")),
    ("dirtypipe", re.compile(r"(buf->flags\s*=\s*0|\bPageAnon\b|\.flags\s*=\s*0)")),
    ("canmerge",  re.compile(r"(buf->flags\s*=\s*0|\bPageAnon\b|\.flags\s*=\s*0)")),
    ("mmap",      re.compile(r"\b(vma_lookup|vma_is_stable|VM_FAULT_RETRY|"
                     r"FAULT_FLAG_ALLOW_RETRY)\b")),
    # Bluetooth hci_cmd_sync_queue(): a bare struct hci_conn* handed to a
    # deferred-work wrapper without hci_conn_get() bracketing its lifetime
    # (the exact shape of the confirmed, real, fixed 2026-08-06 UAF in
    # hci_enhanced_setup_sync(), commit 42de40abe25d). Mitigation is the
    # reference-hold call itself.
    ("btdeferredqueue", re.compile(r"\bhci_conn_get\s*\(")),
    # Double-fetch TOCTOU (CVE-2026-64034 shape): a shared/DMA-visible field
    # is checked once then reused; mitigation is snapshotting it into a
    # local via READ_ONCE() before the check, so a nearby READ_ONCE( is the
    # signal the value was actually snapshotted rather than re-read raw.
    ("toctoudoublefetch", re.compile(r"\bREAD_ONCE\s*\(")),
    # Raw pointer into shared/mmap'd memory passed straight to
    # virtio_net_hdr_to_skb() (CVE-2026-31700 shape); mitigation is a
    # memcpy() snapshot into a stack-local before use. Named "vnethdr", not
    # "mmap...", to avoid colliding with the existing "mmap" fragment
    # (CVE-2022-2590's VMA-stability check) via a substring match.
    ("vnethdr", re.compile(r"\bmemcpy\b")),
)


def _mitigation_re_for_rule(rule_id: Optional[str]) -> Optional[Pattern]:
    """Pick the mitigation check matching a rule id, or None if unrecognised.

    Ids are normalised to letters only so both engines' conventions collapse to
    the same key: ``coccinelle.shared_iv_no_snapshot`` and
    ``src.rules.semgrep.racemap-shared-iv-no-snapshot`` both contain ``sharediv``.
    """
    key = re.sub(r"[^a-z]", "", (rule_id or "").lower())
    for fragment, pattern in _MITIGATION_BY_RULE:
        if fragment in key:
            return pattern
    return None


def _clip_window(
    lines: list[str], center0: int, before: int, after: int,
    strip_comments: bool = False,
) -> str:
    """Return the text window around 0-based line index ``center0``, expanding up
    to ``before`` lines back and ``after`` lines forward but stopping at any
    preprocessor branch directive. When ``strip_comments`` is set, comment-only
    lines are dropped so a token mentioned in prose (e.g. "no put_page") is not
    mistaken for an actual mitigation call."""
    lo = center0
    for j in range(center0 - 1, max(-1, center0 - before - 1), -1):
        if _CPP_BRANCH_RE.match(lines[j]):
            break
        lo = j
    hi = center0
    for j in range(center0 + 1, min(len(lines), center0 + after + 1)):
        if _CPP_BRANCH_RE.match(lines[j]):
            break
        hi = j
    window = lines[lo:hi + 1]
    if strip_comments:
        window = [
            ln for ln in window
            if not ln.lstrip().startswith(("*", "//", "/*"))
        ]
    return "\n".join(window)


@dataclass
class _Detector:
    """A regex-driven zero-copy attack-surface detector.

    A candidate fires when ``trigger`` matches a source line and (optionally)
    ``confirm`` matches the surrounding window. ``mitigation`` matching the
    window marks the candidate as the *fixed* variant (mitigation_present=True),
    which the triage layer uses to exonerate it.
    """

    rule_id: str
    trigger: Pattern
    mitigation: Pattern
    shared_field: str
    message: str
    confirm: Optional[Pattern] = None
    require_window: Optional[Pattern] = None   # extra token that must be in window
    cve_id: Optional[str] = None
    engine: Engine = Engine.COCCINELLE


def _c(pat: str) -> Pattern:
    return re.compile(pat)


# Order matters only for readability; dedupe handles overlaps.
_DETECTORS: list[_Detector] = [
    # Pattern A — io_uring fixed buffers: registered buffer (req->imu) fed to a
    # kernel crypto/network op without a copy or unpin before reuse.
    _Detector(
        rule_id="racemap.io-uring-fixed-buffer-no-copy",
        trigger=_c(r"\bimu->bvec\b"),
        mitigation=_c(r"\b(memcpy|copy_page|copy_from_user|unpin_user_page|"
                      r"io_buffer_unmap|kmap_local_page)\b"),
        shared_field="req->imu",
        message=("io_uring registered buffer (req->imu) passed to a kernel "
                 "operation without copy/unpin; imported user mapping reused "
                 "after submission."),
    ),
    # Pattern A2 — io_uring registered buffer (io_mapped_ubuf) sent over the
    # network without a copy (fs/io_uring/ advanced pattern).
    _Detector(
        rule_id="racemap.io-uring-net-send-no-copy",
        trigger=_c(r"\b(kernel_sendmsg|sock_sendmsg|tcp_sendmsg_locked)\b"),
        mitigation=_c(r"\b(memcpy|copy_from_user|skb_copy|kmap_local_page|"
                      r"sk_msg_memcopy)\b"),
        shared_field="io_mapped_ubuf",
        message=("io_uring registered buffer (io_mapped_ubuf) sent over the "
                 "network without a copy; buffer shared with the submitter."),
        require_window=_c(r"\b(io_mapped_ubuf|req->imu|imu->bvec|imu->folio)\b"),
    ),
    # Pattern B — splice(): pipe_inode_info page handed to a sink without a
    # .get callback or copy_page after the pipe lock is dropped.
    _Detector(
        rule_id="racemap.splice-pipe-page-no-get",
        trigger=_c(r"\bpipe->bufs\[\w+\]\.page\b"),
        mitigation=_c(r"\b(pipe_buf_get|copy_page|get_page|\.get\s*=)\b"),
        shared_field="pipe->bufs[].page",
        message=("splice path uses a pipe_inode_info page without "
                 "pipe_buf_get()/.get callback or copy_page after the pipe "
                 "lock is released."),
    ),
    # Pattern C — vmsplice(): get_user_pages() result fed to a crypto request
    # without set_page_dirty/put_page (user page aliased into kernel, no COW).
    _Detector(
        rule_id="racemap.vmsplice-gup-no-cow",
        trigger=_c(r"\bget_user_pages(_fast)?\b"),
        mitigation=_c(r"\b(set_page_dirty|put_page|copy_page|memcpy)\b"),
        shared_field="gup pages",
        message=("get_user_pages() result fed to a crypto request without "
                 "set_page_dirty/put_page; user page aliased into the kernel "
                 "with no copy-on-write enforcement."),
    ),
    # Pattern D — MSG_ZEROCOPY: skb modified after skb_zerocopy()/zerocopy_clone
    # without skb_unshare() (shared skb data written while refcount > 1).
    _Detector(
        rule_id="racemap.zerocopy-skb-shared-write",
        trigger=_c(r"\bskb_zerocopy\b"),
        mitigation=_c(r"\b(skb_unshare|skb_copy|pskb_copy|pskb_expand_head)\b"),
        shared_field="skb_shared_info",
        message=("skb modified after skb_zerocopy()/zerocopy_clone without "
                 "skb_unshare(); shared skb data written while refcount > 1."),
    ),
    # CVE-2022-0847 (Dirty Pipe): PIPE_BUF_FLAG_CAN_MERGE set on a pipe buffer
    # whose flags were never initialised / page ownership never checked.
    _Detector(
        rule_id="racemap.dirtypipe-can-merge-no-init",
        trigger=_c(r"\bPIPE_BUF_FLAG_CAN_MERGE\b"),
        mitigation=_c(r"(buf->flags\s*=\s*0|\bPageAnon\b|\.flags\s*=\s*0)"),
        shared_field="buf->flags CAN_MERGE",
        message=("PIPE_BUF_FLAG_CAN_MERGE set on a pipe buffer without flag "
                 "initialisation or page-ownership check (Dirty Pipe)."),
        cve_id="CVE-2022-0847",
        confirm=_c(r"\|=\s*PIPE_BUF_FLAG_CAN_MERGE"),
    ),
    # CVE-2022-2590: copy_{from,to}_user inside an mmap_read_lock section with no
    # VMA stability re-check after the lock is taken.
    _Detector(
        rule_id="racemap.mmap-copy-user-vma-race",
        trigger=_c(r"\bcopy_(from|to)_user\b"),
        mitigation=_c(r"\b(vma_lookup|vma_is_stable|VM_FAULT_RETRY|"
                      r"FAULT_FLAG_ALLOW_RETRY)\b"),
        shared_field="copy_user under mmap_read_lock",
        message=("copy_{from,to}_user inside an mmap_read_lock section without "
                 "a VMA stability re-check (mmap_lock race)."),
        cve_id="CVE-2022-2590",
        require_window=_c(r"\bmmap_read_lock\b"),
    ),
]



# Bug-1/6 fix: classify the zero-copy primitive from a code window, independent
# of which engine produced the candidate. Checked in this precedence order.
_PRIMITIVE_KEYWORDS = [
    # vmsplice before splice: "splice" is a substring of "vmsplice".
    ("vmsplice", ("vmsplice", "get_user_pages")),
    ("splice",   ("splice", "pipe_buf", "pipe_inode")),
    ("io_uring", ("io_uring", "io_buffer", "req->imu", "imu->bvec", "IORING")),
    ("zerocopy", ("skb_zerocopy", "MSG_ZEROCOPY", "skb_shared")),
    ("aead",     ("skcipher_request", "aead_request", "crypto_aead",
                  "ctx->iv", "tipc_aead")),
]

# Human-readable pattern name per primitive (Bug 6).
_PATTERN_NAME = {
    "aead": "aead_inplace_write",
    "splice": "splice_pipe_race",
    "vmsplice": "vmsplice_gup_race",
    "io_uring": "io_uring_shared_buffer",
    "zerocopy": "zerocopy_skb_race",
    "unknown": "",
}


def classify_primitive(window_text: str) -> str:
    """Return the zero-copy primitive class for a ±15 line code window."""
    text = window_text or ""
    for label, keywords in _PRIMITIVE_KEYWORDS:
        if any(kw in text for kw in keywords):
            return label
    return "unknown"


def pattern_name_for(primitive: str) -> str:
    return _PATTERN_NAME.get(primitive, "")


class Scanner:
    def __init__(
        self,
        rules_dir: Path,
        subsystems: Optional[list[str]] = None,
        use_regex_fallback: bool = True,
        external_tools: bool = False,
        git_cross_ref: bool = False,
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.subsystems = subsystems or list(_SUBSYSTEM_MAP.values())
        self.use_regex_fallback = use_regex_fallback
        # Bug-5 fix: spatch/semgrep are opt-in. By default racemap uses its own
        # (fully enriched, well-tested) regex engine, so behaviour is identical
        # in Docker and locally and the benchmark never spawns subprocesses.
        self.external_tools = external_tools
        # git cross-reference is opt-in (subprocess per file) so the
        # benchmark / repeated scans stay fast.
        self.git_cross_ref = git_cross_ref
        self.warnings: list[str] = []

    # -- public API ---------------------------------------------------------

    def scan(self, target: Path) -> list[Candidate]:
        """Scan ``target`` (a kernel source tree or single file) for candidates."""
        target = Path(target)
        candidates: list[Candidate] = []

        if self.external_tools:
            candidates.extend(self._run_coccinelle(target))
            candidates.extend(self._run_semgrep(target))

        if not candidates and self.use_regex_fallback:
            candidates.extend(self._regex_scan(target))

        deduped = self._dedupe(candidates)
        self._enrich_all(deduped, target)
        return deduped

    def _enrich_all(self, candidates: list[Candidate], target: Path) -> None:
        self._git_cache: dict = {}
        """Enrich every candidate (any engine) from its source file: classify the
        zero-copy primitive over a +/-15 line window, then container-escape,
        version tracking and 1-hop taint."""
        base = target if target.is_dir() else target.parent
        cache: dict[str, list[str]] = {}
        for c in candidates:
            path = base / c.file
            key = str(path)
            if key not in cache:
                try:
                    cache[key] = path.read_text(errors="ignore").splitlines()
                except OSError:
                    cache[key] = []
            lines = cache[key]

            # Bug 1 + 6: primitive + pattern name from a +/-15 line window.
            idx = c.line - 1
            window = "\n".join(lines[max(0, idx - 15): idx + 15]) if lines else (c.snippet or "")
            c.zero_copy_primitive = classify_primitive(window)
            c.pattern_name = pattern_name_for(c.zero_copy_primitive)

            # Coccinelle / Semgrep report a match without a mitigation verdict.
            # Annotate those the same way the built-in detectors do, so the
            # triage layer can still exonerate an already-guarded site. Built-in
            # candidates always arrive with a bool here and are left alone.
            if c.mitigation_present is None and lines:
                mit_re = _mitigation_re_for_rule(c.rule_id)
                if mit_re is not None:
                    c.mitigation_present = bool(mit_re.search(
                        _clip_window(lines, idx, 10, 10, strip_comments=True)
                    ))

            # Bug 2: container-escape now uses primitive + file path.
            container_escape.annotate(c)
            version_tracker.annotate(c)
            if lines:
                taint.analyze(c, lines)
                # Part 1: caller lock traversal (false-positive filter).
                caller_lock.analyze(c, lines)
                # Part 2: sparse annotations (__must_hold / __acquires).
                sparse_annotations.analyze(c, lines)
                # Part 3: memory barrier in the +/-20 window.
                win20 = "\n".join(lines[max(0, idx - 20): idx + 20])
                c.barrier_protected = barrier.detect(win20)
                # Part 4: interrupt/atomic context in the +/-25 window.
                win25 = "\n".join(lines[max(0, idx - 25): idx + 25])
                c.interrupt_context_note = interrupt_ctx.detect(win25)
                # Part 5: workqueue / deferred path within +/-30 lines.
                win30 = "\n".join(lines[max(0, idx - 30): idx + 30])
                c.workqueue_async = workqueue.detect(win30)
            # Part 8: git cross-reference (opt-in).
            if self.git_cross_ref:
                git_log.annotate(c, base, self._git_cache)

    # -- engine wrappers ----------------------------------------------------

    def _run_coccinelle(self, target: Path) -> list[Candidate]:
        if not shutil.which("spatch"):
            self.warnings.append("spatch (Coccinelle) not found on PATH; skipping.")
            return []
        results: list[Candidate] = []
        for cocci in sorted((self.rules_dir / "coccinelle").glob("*.cocci")):
            try:
                proc = subprocess.run(
                    # -D report activates the `virtual report` rule the .cocci
                    # files declare; without it their @script:python blocks are
                    # inert and spatch prints nothing at all.
                    ["spatch", "--sp-file", str(cocci), "--dir", str(target),
                     "--no-includes", "--very-quiet", "-D", "report"],
                    capture_output=True, text=True, timeout=1800,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                self.warnings.append(f"spatch failed on {cocci.name}: {exc}")
                continue
            # A .cocci that fails to parse exits non-zero and prints nothing on
            # stdout. Without this check that is indistinguishable from "rule
            # matched nothing", which is how a broken rule set stayed invisible.
            if proc.returncode != 0:
                first = (proc.stderr or "").strip().splitlines()
                self.warnings.append(
                    f"spatch rejected {cocci.name} (exit {proc.returncode}): "
                    f"{first[0] if first else 'no stderr'}"
                )
                continue
            results.extend(self._parse_cocci_output(proc.stdout, cocci.stem, target))
        return results

    def _run_semgrep(self, target: Path) -> list[Candidate]:
        if not shutil.which("semgrep"):
            self.warnings.append("semgrep not found on PATH; skipping.")
            return []
        results: list[Candidate] = []
        rule_path = self.rules_dir / "semgrep"
        try:
            proc = subprocess.run(
                ["semgrep", "--config", str(rule_path), "--json", str(target)],
                capture_output=True, text=True, timeout=1800,
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
            self.warnings.append(f"semgrep failed: {exc}")
            return []
        for hit in data.get("results", []):
            start = hit.get("start", {})
            path = hit.get("path", "")
            # Normalise to the same target-relative form the Coccinelle and
            # built-in paths use, so _dedupe() can merge a site both engines
            # found and _enrich_all() can locate the source file.
            rel = self._rel(Path(path), target) if path else path
            results.append(
                Candidate(
                    rule_id=hit.get("check_id", "semgrep.unknown"),
                    engine=Engine.SEMGREP,
                    file=rel,
                    line=start.get("line", 1),
                    subsystem=self._subsystem_for(path),
                    snippet=hit.get("extra", {}).get("lines", ""),
                    message=hit.get("extra", {}).get("message", ""),
                    shared_field=self._shared_field(
                        hit.get("extra", {}).get("lines", "")
                    ),
                )
            )
        return results

    # -- regex fallback -----------------------------------------------------

    def _regex_scan(self, target: Path) -> list[Candidate]:
        results: list[Candidate] = []
        for path in self._iter_sources(target):
            try:
                lines = path.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            results.extend(self._scan_legacy(path, target, lines))
            results.extend(self._scan_detectors(path, target, lines))
        return results

    def _scan_legacy(self, path, target, lines) -> list[Candidate]:
        """The two original crypto patterns (shared ctx->field; in-place AEAD)."""
        results: list[Candidate] = []
        for i, line in enumerate(lines, start=1):
            if line.lstrip().startswith(("*", "//", "/*")):
                continue  # never trigger inside a comment
            if not any(fn in line for fn in _SINK_FUNCS):
                continue
            window = "\n".join(lines[max(0, i - 3): i + 4])
            snippet = "\n".join(lines[max(0, i - 3): i + 3])

            m = _SHARED_FIELD_RE.search(window)
            if m:
                field_name = m.group(1)
                snap = bool(re.search(rf"memcpy\s*\([^;]*{field_name}", snippet))
                results.append(
                    Candidate(
                        rule_id="racemap.shared-state-no-snapshot",
                        engine=Engine.COCCINELLE,
                        file=self._rel(path, target),
                        line=i,
                        function=self._enclosing_function(lines, i),
                        subsystem=self._subsystem_for(str(path)),
                        snippet=snippet,
                        message=(
                            "Shared crypto state passed to async request setter "
                            "without a per-request snapshot taken under lock."
                        ),
                        shared_field=f"ctx->{field_name}",
                        mitigation_present=snap,
                    )
                )
                continue

            call_window = " ".join(lines[max(0, i - 1): i + 3])
            if _INPLACE_RE.search(call_window):
                # An skb_has_shared_frag() guard in the same preprocessor branch
                # is the ESP-style mitigation. Emit the candidate either way and
                # let triage exonerate the guarded one, which is what every
                # other detector does; dropping it outright hid the *fixed*
                # variant of the pattern from the ground-truth pair. Uses the
                # preprocessor-aware window so a #ifndef FIXED branch cannot
                # read the guard out of its paired #else branch.
                guarded = "skb_has_shared_frag" in _clip_window(
                    lines, i - 1, 30, 5, strip_comments=True
                )
                results.append(
                    Candidate(
                        rule_id="racemap.inplace-decrypt-no-cow",
                        engine=Engine.COCCINELLE,
                        file=self._rel(path, target),
                        line=i,
                        function=self._enclosing_function(lines, i),
                        subsystem=self._subsystem_for(str(path)),
                        snippet=snippet,
                        message=(
                            "In-place AEAD decrypt (src == dst) over a "
                            "possibly-shared skb with no "
                            "skb_has_shared_frag()/COW guard (cf. ESP "
                            "CVE-2026-43284)."
                        ),
                        shared_field="skb(shared_frag)",
                        mitigation_present=guarded,
                    )
                )
        return results

    def _scan_detectors(self, path, target, lines) -> list[Candidate]:
        """Run the table-driven zero-copy / known-CVE detectors."""
        results: list[Candidate] = []
        for i, line in enumerate(lines, start=1):
            stripped = line.lstrip()
            if stripped.startswith(("*", "//", "/*")):
                continue  # never trigger inside a comment
            for det in _DETECTORS:
                if not det.trigger.search(line):
                    continue
                c0 = i - 1
                if det.confirm and not det.confirm.search(
                    _clip_window(lines, c0, 4, 5, strip_comments=True)
                ):
                    continue
                if det.require_window:
                    req_win = "\n".join(
                        ln for ln in lines[max(0, c0 - 15): c0 + 15]
                        if not ln.lstrip().startswith(("*", "//", "/*"))
                    )
                    if not det.require_window.search(req_win):
                        continue
                mit_window = _clip_window(lines, c0, 10, 10, strip_comments=True)
                mitigated = bool(det.mitigation.search(mit_window))
                snippet = _clip_window(lines, c0, 3, 4)
                results.append(
                    Candidate(
                        rule_id=det.rule_id,
                        engine=det.engine,
                        file=self._rel(path, target),
                        line=i,
                        function=self._enclosing_function(lines, i),
                        subsystem=self._subsystem_for(str(path)),
                        snippet=snippet,
                        message=det.message,
                        shared_field=det.shared_field,
                        mitigation_present=mitigated,
                        cve_id=det.cve_id,
                    )
                )
        return results

    # -- helpers ------------------------------------------------------------

    def _iter_sources(self, target: Path) -> Iterable[Path]:
        if target.is_file():
            yield target
            return
        for path in target.rglob("*.c"):
            if self.subsystems and not self._in_scope(str(path)):
                continue
            yield path

    def _in_scope(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        return any(f"/{s}/" in f"/{norm}" or f"{s}/" in norm for s in self.subsystems)

    def _subsystem_for(self, path: str) -> Optional[str]:
        norm = path.replace("\\", "/")
        for key, label in _SUBSYSTEM_MAP.items():
            if f"/{key}/" in norm or norm.startswith(f"{key}/") or f"{key}/" in norm:
                return label
        return None

    @staticmethod
    def _shared_field(text: str) -> Optional[str]:
        m = _SHARED_FIELD_RE.search(text or "")
        return f"ctx->{m.group(1)}" if m else None

    @staticmethod
    def _enclosing_function(lines: list[str], idx: int) -> Optional[str]:
        func_re = re.compile(r"^\w[\w\s\*]*\b(\w+)\s*\([^;]*$")
        for j in range(idx - 1, max(0, idx - 80), -1):
            m = func_re.match(lines[j])
            if m and "=" not in lines[j]:
                return m.group(1)
        return None

    @staticmethod
    def _rel(path: Path, target: Path) -> str:
        try:
            base = target if target.is_dir() else target.parent
            return str(path.relative_to(base)).replace("\\", "/")
        except ValueError:
            return str(path).replace("\\", "/")

    @staticmethod
    def _parse_cocci_output(stdout: str, rule_id: str,
                            target: Optional[Path] = None) -> list[Candidate]:
        """Parse our cocci rules' ``RACEMAP:file:line:field`` print lines.

        spatch emits ``<file>:<line>:<cols>: RACEMAP:<file>:<line>:<field>``, so
        the payload after the marker has exactly three colon-separated parts.
        """
        results: list[Candidate] = []
        base = None
        if target is not None:
            base = target if target.is_dir() else target.parent
        for line in stdout.splitlines():
            if "RACEMAP:" not in line:
                continue
            try:
                file, lineno, field_name = (
                    line.split("RACEMAP:", 1)[1].split(":", 2)
                )
            except ValueError:
                continue
            file = file.strip()
            if base is not None:
                try:
                    file = str(Path(file).relative_to(base)).replace("\\", "/")
                except ValueError:
                    pass
            results.append(
                Candidate(
                    rule_id=f"coccinelle.{rule_id}",
                    engine=Engine.COCCINELLE,
                    file=file,
                    line=int(lineno.strip() or 1),
                    snippet="",
                    message="Coccinelle matched a zero-copy anti-pattern.",
                    shared_field=field_name.strip() or None,
                )
            )
        return results

    @staticmethod
    def _dedupe(candidates: list[Candidate]) -> list[Candidate]:
        """Collapse candidates describing the same source line, richest wins.

        Engines overlap: Semgrep can match several of its rules on one line, and
        Coccinelle reports sites the built-in matcher also finds. Keying on
        (file, line, shared_field) let those through as separate rows, so an
        --external-tools run listed the same site two or three times.
        """
        def _rank(c: Candidate) -> tuple:
            return (
                c.mitigation_present is not None,
                bool(c.shared_field),
                bool(c.snippet),
                bool(c.cve_id),
            )

        seen: dict[tuple, Candidate] = {}
        for c in candidates:
            key = (c.file, c.line)
            cur = seen.get(key)
            if cur is None:
                seen[key] = c
                continue
            keep, drop = (c, cur) if _rank(c) > _rank(cur) else (cur, c)
            # Merging on (file, line) can also collapse two genuinely different
            # rules that happen to land on one line — likelier on a real kernel
            # tree than on the single-pattern fixtures. Carry the dropped row's
            # identity across in *structured* fields, not just prose: SARIF, CSV
            # and code-scanning views group by rule id and CVE, and would
            # otherwise never learn the second rule fired at all.
            if drop.rule_id and drop.rule_id != keep.rule_id:
                if drop.rule_id not in keep.also_matched_by:
                    keep.also_matched_by.append(drop.rule_id)
            for rid in drop.also_matched_by:
                if rid != keep.rule_id and rid not in keep.also_matched_by:
                    keep.also_matched_by.append(rid)
            if drop.cve_id:
                if not keep.cve_id:
                    keep.cve_id = drop.cve_id
                elif (drop.cve_id != keep.cve_id
                      and drop.cve_id not in keep.also_cve_ids):
                    keep.also_cve_ids.append(drop.cve_id)
            for cid in drop.also_cve_ids:
                if cid != keep.cve_id and cid not in keep.also_cve_ids:
                    keep.also_cve_ids.append(cid)
            seen[key] = keep
        return list(seen.values())
