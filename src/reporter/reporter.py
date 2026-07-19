"""Reporter: renders a :class:`ScanReport` as a Rich terminal table and writes
ranked JSON to disk. In verbose mode it also prints each candidate's forced
chain-of-thought reasoning steps."""

from __future__ import annotations

import json
from pathlib import Path

from src.models import ScanReport, TriageResult, Verdict
from src.scanner import version_tracker

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False


_VERDICT_STYLE = {
    Verdict.LIKELY_RACE: ("red", "LIKELY RACE"),
    Verdict.NEEDS_REVIEW: ("yellow", "NEEDS REVIEW"),
    Verdict.TRIAGE_ERROR: ("magenta", "TRIAGE ERROR"),
    Verdict.LIKELY_SAFE: ("green", "likely safe"),
}


# --------------------------------------------------------------------------- #
# Display-only redaction for the two BUNDLED ground-truth fixtures.
#
# This is a pure render-time string transform. It never mutates Candidate /
# TriageResult data, the fixture files, or anything tests assert on — it only
# rewrites sensitive tokens as they are printed, and ONLY for the two bundled
# ground-truth fixtures. Real kernel scans (any other path) render verbatim.
# The sample-kernel file `algif_skcipher.c` is intentionally NOT matched.
# --------------------------------------------------------------------------- #
_GT_FIXTURES = ("algif_skcipher_vulnerable.c", "algif_skcipher_fixed.c")
_REDACTIONS = (
    ("algif_skcipher_vulnerable.c", "crypto_subsystem_vulnerable.c"),
    ("algif_skcipher_fixed.c", "crypto_subsystem_fixed.c"),
    ("algif_skcipher", "crypto_subsystem"),
    ("ctx->iv", "ctx->(redacted)"),
    ("algif", "crypto"),                 # bare subsystem label
)


def _basename(path: str) -> str:
    return (path or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _is_gt_fixture(candidate) -> bool:
    """True only for the two bundled ground-truth fixtures (scoped narrowly)."""
    f = candidate.file or ""
    return _basename(f) in _GT_FIXTURES or "ground_truth/algif_skcipher" in f


def _scrub(text: str) -> str:
    if not text:
        return text
    for old, new in _REDACTIONS:
        text = text.replace(old, new)
    return text


def _redact(text: str, candidate) -> str:
    """Scrub sensitive tokens from text, but only for bundled GT fixtures."""
    return _scrub(text) if _is_gt_fixture(candidate) else text


def _redact_target(target: str) -> str:
    """Scrub a report-level target string only when it names a GT fixture."""
    markers = ("algif_skcipher_vulnerable", "algif_skcipher_fixed",
               "ground_truth/algif_skcipher")
    return _scrub(target) if any(m in (target or "") for m in markers) else target


class Reporter:
    def __init__(self, console=None) -> None:
        self.console = console or (Console() if _RICH else None)

    # -- JSON ---------------------------------------------------------------

    def write_json(self, report: ScanReport, path: Path) -> Path:
        path = Path(path)
        ranked = report.ranked()
        payload = {
            "target": report.target,
            "kernel_version": report.kernel_version,
            "subsystems": report.subsystems,
            "candidates_found": report.candidates_found,
            "results": [self._result_dict(r) for r in ranked],
        }
        path.write_text(json.dumps(payload, indent=2))
        return path

    @staticmethod
    def _result_dict(r: TriageResult) -> dict:
        c = r.candidate
        return {
            "rank_score": r.score,
            "verdict": r.verdict.value,
            "confidence": r.confidence,
            "file": c.file,
            "line": c.line,
            "function": c.function,
            "subsystem": c.subsystem,
            "shared_field": c.shared_field,
            "zero_copy_primitive": c.zero_copy_primitive,
            "pattern_name": c.pattern_name,
            "cve_id": c.cve_id,
            "rule_id": c.rule_id,
            "engine": c.engine.value,
            "mitigation_present": c.mitigation_present,
            "container_escape_potential": c.container_escape_potential,
            "container_escape_reason": c.container_escape_reason,
            "affected_versions": c.affected_versions,
            "fixed_in": c.fixed_in,
            "taint_propagated": c.taint_propagated,
            "taint_callee": c.taint_callee,
            "patch_missing": c.patch_missing,
            "caller_lock_held": c.caller_lock_held,
            "caller_lock_name": c.caller_lock_name,
            "annotation_protected": c.annotation_protected,
            "annotation_detail": c.annotation_detail,
            "barrier_protected": c.barrier_protected,
            "interrupt_context_note": c.interrupt_context_note,
            "workqueue_async": c.workqueue_async,
            "recently_modified": c.recently_modified,
            "last_commit_date": c.last_commit_date,
            "last_author_email": c.last_author_email,
            "git_age_note": c.git_age_note,
            "confidence_low": r.confidence_low,
            "confidence_high": r.confidence_high,
            "lock_held": r.lock_held,
            "snapshot_taken": r.snapshot_taken,
            "reasoning": r.reasoning,
            "reasoning_steps": r.reasoning_steps,
            "model": r.model,
            "message": c.message,
        }

    # -- terminal -----------------------------------------------------------

    def render(self, report: ScanReport, verbose: bool = False) -> None:
        if not _RICH or self.console is None:
            self._render_plain(report, verbose)
            return

        ranked = report.ranked()
        header = (
            f"[bold]racemap[/bold] — shared / zero-copy race scan\n"
            f"target: [cyan]{_redact_target(report.target)}[/cyan]   "
            f"kernel: [cyan]{report.kernel_version or 'n/a'}[/cyan]   "
            f"candidates: [bold]{report.candidates_found}[/bold]"
        )
        self.console.print(Panel(header, box=box.ROUNDED, expand=False))

        table = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=True)
        table.add_column("#", justify="right", style="dim", width=3)
        table.add_column("Verdict", width=14)
        table.add_column("Score", justify="right", width=7)
        table.add_column("Location", style="cyan", overflow="fold")
        table.add_column("Pattern / CVE", style="yellow", overflow="fold")
        table.add_column("Esc", justify="center", width=3)
        table.add_column("Flags", overflow="fold", width=12)
        table.add_column("Reasoning", overflow="fold")

        for i, r in enumerate(ranked, start=1):
            style, label = _VERDICT_STYLE[r.verdict]
            prim = (r.candidate.pattern_name or r.candidate.zero_copy_primitive
                    or r.candidate.shared_field or "—")
            if r.candidate.cve_id:
                prim = f"{prim}\n[magenta]{r.candidate.cve_id}[/magenta]"
            cc = r.candidate
            esc = "[bold red]\U0001F534[/bold red]" if cc.container_escape_potential else ""
            band = round((r.confidence_high - r.confidence_low) / 2, 2)
            score_cell = f"{r.score:.2f}\n[dim]\u00b1{band:.2f}[/dim]"
            # Flags column: caller-lock / barrier / annotation / interrupt / wq / git.
            flags = []
            if cc.caller_lock_held:
                flags.append("[green]\U0001F512lock[/green]")
            if cc.barrier_protected:
                flags.append("[green]\U0001F6E1barrier[/green]")
            if cc.annotation_protected:
                flags.append("[green]\u00a7annot[/green]")
            if cc.interrupt_context_note:
                flags.append("[orange1]\u26a1irq[/orange1]")
            if cc.workqueue_async:
                flags.append("[yellow]wq[/yellow]")
            if cc.recently_modified:
                flags.append("[cyan]\U0001F504git[/cyan]")
            flags_cell = "\n".join(flags)
            reason_cell = r.reasoning
            if cc.interrupt_context_note:
                reason_cell += f"\n[orange1]\u2192 {cc.interrupt_context_note} (+0.1)[/orange1]"
            if cc.workqueue_async and not cc.caller_lock_held:
                reason_cell += "\n[yellow]\u2192 workqueue deferred path, no lock (+0.1)[/yellow]"
            if cc.taint_propagated:
                reason_cell += (f"\n[magenta]\u2192 taint: flows into "
                                f"{cc.taint_callee}() with no lock (+0.2)[/magenta]")
            if cc.patch_missing:
                reason_cell += "\n[red]\u2192 patch gap: known fix signature absent (+0.15)[/red]"
            if cc.caller_lock_held:
                reason_cell += (f"\n[green]\u2192 all callers hold {cc.caller_lock_name} "
                                f"(-0.3, likely FP)[/green]")
            if cc.annotation_protected:
                reason_cell += f"\n[green]\u2192 {cc.annotation_detail} (-0.2)[/green]"
            if cc.barrier_protected:
                reason_cell += "\n[green]\u2192 memory barrier present (-0.15)[/green]"
            if cc.git_age_note:
                reason_cell += f"\n[cyan]\u2192 last modified {cc.git_age_note}[/cyan]"
            table.add_row(
                str(i),
                f"[{style}]{label}[/{style}]",
                score_cell,
                _redact(cc.location, cc),
                _redact(prim, cc),
                esc,
                flags_cell,
                _redact(reason_cell, cc),
            )
        self.console.print(table)

        races = sum(1 for r in ranked if r.verdict == Verdict.LIKELY_RACE)
        escapes = sum(1 for r in ranked if r.candidate.container_escape_potential)
        self.console.print(
            f"\n[bold red]{races}[/bold red] likely race(s), "
            f"[bold red]{escapes}[/bold red] container-escape primitive(s), "
            f"[bold]{len(ranked)}[/bold] candidate(s) triaged.\n"
        )
        self._render_kernel_warning(report, ranked)

        if verbose:
            self._render_steps(ranked)

    def _render_kernel_warning(self, report: ScanReport, ranked: list[TriageResult]) -> None:
        if not report.kernel_version:
            return
        hits = [
            r for r in ranked
            if r.verdict == Verdict.LIKELY_RACE
            and version_tracker.kernel_is_affected(r.candidate, report.kernel_version)
        ]
        if not hits:
            self.console.print(
                f"[green]Kernel {report.kernel_version} is not in the affected "
                f"range of any flagged candidate.[/green]\n"
            )
            return
        self.console.print(
            f"[bold yellow]\u26A0 Your kernel {report.kernel_version} is affected "
            f"by {len(hits)} candidate(s):[/bold yellow]"
        )
        for r in hits:
            c = r.candidate
            fix = f" (fixed in {c.fixed_in})" if c.fixed_in else " (no fixed_in on record — check upstream)"
            cve = f" {c.cve_id}" if c.cve_id else ""
            self.console.print(
                f"  [yellow]\u26A0[/yellow] {_redact(c.location, c)}{cve} — "
                f"{_redact(c.shared_field, c)} affected {c.affected_versions}{fix}"
            )
        self.console.print("")

    def _render_steps(self, ranked: list[TriageResult]) -> None:
        self.console.print("[bold]Reasoning steps (chain-of-thought)[/bold]\n")
        for i, r in enumerate(ranked, start=1):
            style, label = _VERDICT_STYLE[r.verdict]
            loc = _redact(r.candidate.location, r.candidate)
            body = "\n".join(f"  {_redact(s, r.candidate)}" for s in r.reasoning_steps) or "  (none)"
            self.console.print(
                Panel(
                    body,
                    title=f"[{style}]#{i} {label}[/{style}]  {loc}  "
                          f"[dim]{r.model}[/dim]",
                    box=box.ROUNDED,
                    expand=False,
                )
            )

    def _render_plain(self, report: ScanReport, verbose: bool = False) -> None:
        print(f"racemap scan — target={_redact_target(report.target)} "
              f"candidates={report.candidates_found}")
        for i, r in enumerate(report.ranked(), start=1):
            cve = f" [{r.candidate.cve_id}]" if r.candidate.cve_id else ""
            esc = " [ESCAPE]" if r.candidate.container_escape_potential else ""
            print(f"{i:>3} [{r.verdict.value:<12}] {r.score:.2f} "
                  f"{_redact(r.candidate.location, r.candidate)} "
                  f"{_redact(r.candidate.shared_field, r.candidate) or '-'}{cve}{esc}")
            print(f"      {_redact(r.reasoning, r.candidate)}")
            if verbose:
                for step in r.reasoning_steps:
                    print(f"        - {step}")
        if report.kernel_version:
            hits = [
                r for r in report.ranked()
                if r.verdict == Verdict.LIKELY_RACE
                and version_tracker.kernel_is_affected(r.candidate, report.kernel_version)
            ]
            if hits:
                print(f"! Your kernel {report.kernel_version} is affected by "
                      f"{len(hits)} candidate(s).")

    def render_diff(self, entries, old: str, new: str) -> None:
        """Render a diff_mode comparison as a Rich table."""
        from src.scanner.diff_mode import NEW, RESOLVED, PERSISTENT, summary
        counts = summary(entries)
        if not _RICH or self.console is None:
            print(f"diff old={old} new={new}  "
                  f"NEW={counts[NEW]} RESOLVED={counts[RESOLVED]} "
                  f"PERSISTENT={counts[PERSISTENT]}")
            for e in entries:
                print(f"  [{e.status:<10}] {e.file} {e.pattern} {e.score:.2f}")
            return
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        self.console.print(Panel(
            f"[bold]racemap diff[/bold]\nold: [cyan]{old}[/cyan]\n"
            f"new: [cyan]{new}[/cyan]\n"
            f"[red]{counts[NEW]} NEW[/red]  "
            f"[green]{counts[RESOLVED]} RESOLVED[/green]  "
            f"[yellow]{counts[PERSISTENT]} PERSISTENT[/yellow]",
            box=box.ROUNDED, expand=False))
        style = {NEW: "red", RESOLVED: "green", PERSISTENT: "yellow"}
        table = Table(box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("File", style="cyan", overflow="fold")
        table.add_column("Pattern", style="magenta", overflow="fold")
        table.add_column("Status", width=12)
        table.add_column("Risk Score", justify="right", width=10)
        for e in entries:
            cve = f" {e.cve_id}" if e.cve_id else ""
            table.add_row(f"{e.file}:{e.line}", f"{e.pattern}{cve}",
                          f"[{style[e.status]}]{e.status}[/{style[e.status]}]",
                          f"{e.score:.2f}")
        self.console.print(table)

    def warn(self, messages: list[str]) -> None:
        if not messages:
            return
        if _RICH and self.console is not None:
            for m in messages:
                self.console.print(f"[dim yellow]! {m}[/dim yellow]")
        else:
            for m in messages:
                print(f"! {m}")
