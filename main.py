#!/usr/bin/env python3
"""racemap — Linux kernel shared page-cache race condition scanner with LLM triage.

CLI entry point. Pipeline: static scan (Coccinelle + Semgrep) -> LLM triage
(Ollama / Anthropic / OpenAI / Gemini, with an offline heuristic fallback) ->
ranked JSON + Rich report.

The LLM is a triage filter for false-positive reduction only. It never
generates exploits.

Examples
--------
  # Scan a kernel tree (net/, crypto/, drivers/char/, io_uring/, fs/, and the
  # bundled "mystery" driver fixture, by default)
  python main.py scan /path/to/linux

  # Validate against the bundled crypto-subsystem ground truth (self-contained, offline)
  python main.py validate

  # Scan a directory, force the offline heuristic backend, write JSON
  python main.py scan tests/ground_truth/ --llm heuristic --json out.json
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

# Allow running as `python main.py` without installation.
sys.path.insert(0, str(Path(__file__).parent))

from src import __version__
from src.models import ScanReport, Verdict
from src.reporter import Reporter
from src.scanner import Scanner
from src.triage import LLM_CHOICES, TriagePipeline

ROOT = Path(__file__).parent
RULES_DIR = ROOT / "rules"
DEFAULT_SUBSYSTEMS = ["net", "crypto", "drivers/char", "io_uring", "fs", "mystery"]


def _run_pipeline(
    target: Path,
    subsystems: list[str],
    llm: str,
    ollama_model: str,
    kernel_version: str | None,
    json_out: Path | None,
    quiet: bool,
    verbose: bool = False,
    output: str = "terminal",
    patch_gap: bool = False,
    demo_mode: bool = False,
) -> ScanReport:
    reporter = Reporter()
    scanner = Scanner(rules_dir=RULES_DIR, subsystems=subsystems, git_cross_ref=True)
    triage = TriagePipeline(backend=llm, ollama_model=ollama_model,
                            demo_mode=demo_mode, cache_enabled=True)

    if not quiet and reporter.console:
        reporter.console.print(f"[dim]scanning {target} ...[/dim]")
    elif not quiet:
        print(f"scanning {target} ...")

    candidates = scanner.scan(target)
    if patch_gap:
        from src.scanner import patch_gap as _pg
        _pg.apply_all(candidates, target)
    if not quiet:
        reporter.warn(scanner.warnings)

    results = triage.triage(candidates)
    if not quiet:
        reporter.warn(triage.warnings)

    report = ScanReport(
        target=str(target),
        kernel_version=kernel_version,
        subsystems=subsystems,
        candidates_found=len(candidates),
        results=results,
    )

    if not quiet:
        reporter.render(report, verbose=verbose)
    if json_out:
        path = reporter.write_json(report, json_out)
        if not quiet:
            print(f"ranked JSON written to {path}")
    if output == "sarif":
        from src.reporter.sarif import write_sarif
        sarif_path = write_sarif(report, ROOT / "results" / "scan.sarif")
        if not quiet:
            print(f"SARIF written to {sarif_path}")
    return report


@click.group(context_settings={"help_option_names": ["-h", "--help"]},
             invoke_without_command=True)
@click.version_option(__version__, prog_name="racemap")
@click.option("--update-db", is_flag=True,
              help="Refresh the patch-gap signature DB from the kernel git history.")
@click.pass_context
def cli(ctx, update_db) -> None:
    """racemap — shared page-cache race scanner with LLM triage."""
    if update_db:
        from src.scanner import db_updater
        result = db_updater.fetch_latest_signatures()
        db_updater.update_local_db(result)
        click.secho(
            f"DB updated: {result['updated']} signatures refreshed, "
            f"last update: {result['timestamp']}", fg="green")
        ctx.exit(0)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--subsystem", "subsystems", multiple=True,
              help="Subsystem to scope (repeatable). Default: net, crypto, drivers/char, io_uring, fs, mystery.")
@click.option("--llm", type=click.Choice(LLM_CHOICES),
              default="heuristic", show_default=True,
              help="Triage backend. Defaults to the offline heuristic so a bare "
                   "'scan' is deterministic and reproducible with no API key or "
                   "local server required. 'auto' tries ollama -> anthropic -> "
                   "openai -> gemini -> heuristic. Selected backend always falls "
                   "back to the offline heuristic if unavailable.")
@click.option("--ollama-model", default="llama3.2", show_default=True)
@click.option("--kernel-version", default=None, help="Recorded in the report metadata.")
@click.option("--json", "json_out", type=click.Path(path_type=Path), default=None,
              help="Write ranked JSON to this path.")
@click.option("--quiet", is_flag=True, help="Suppress the terminal report.")
@click.option("--verbose", is_flag=True, help="Show per-candidate chain-of-thought reasoning steps.")
@click.option("--output", type=click.Choice(["terminal", "sarif"]), default="terminal",
              show_default=True, help="terminal report, or SARIF 2.1.0 to results/scan.sarif.")
@click.option("--patch-gap", is_flag=True,
              help="Flag candidates whose known upstream patch signature is absent (+0.15 risk).")
@click.option("--demo-mode", is_flag=True,
              help="Serve triage verdicts from the SQLite cache; never call an LLM API.")
def scan(target, subsystems, llm, ollama_model, kernel_version, json_out, quiet, verbose, output, patch_gap, demo_mode):
    """Scan a kernel TREE or single FILE for shared-state race candidates."""
    subs = list(subsystems) or DEFAULT_SUBSYSTEMS
    _run_pipeline(target, subs, llm, ollama_model, kernel_version, json_out, quiet,
                  verbose, output=output, patch_gap=patch_gap, demo_mode=demo_mode)


@cli.command()
@click.option("--llm", type=click.Choice(LLM_CHOICES),
              default="heuristic", show_default=True,
              help="Triage backend (default heuristic so validation is offline).")
@click.option("--json", "json_out", type=click.Path(path_type=Path), default=None)
def validate(llm, json_out):
    """Validate against the bundled crypto-subsystem ground truth (offline, deterministic).

    Exits non-zero if the vulnerable fixture is not surfaced as a likely race or
    the fixed fixture is not exonerated.
    """
    gt = ROOT / "tests" / "ground_truth"
    reporter = Reporter()
    scanner = Scanner(rules_dir=RULES_DIR, subsystems=[])
    triage = TriagePipeline(backend=llm)

    vuln = triage.triage(scanner.scan(gt / "algif_skcipher_vulnerable.c"))
    fixed = triage.triage(scanner.scan(gt / "algif_skcipher_fixed.c"))

    report = ScanReport(
        target="ground_truth/algif_skcipher",
        kernel_version="6.8.0-124-generic",
        subsystems=["crypto"],
        candidates_found=len(vuln) + len(fixed),
        results=vuln + fixed,
    )
    reporter.render(report)
    if json_out:
        reporter.write_json(report, json_out)

    vuln_ok = any(r.verdict == Verdict.LIKELY_RACE for r in vuln)
    fixed_ok = all(r.verdict == Verdict.LIKELY_SAFE for r in fixed) if fixed else True

    if vuln_ok and fixed_ok:
        click.secho("GROUND TRUTH PASS: crypto-subsystem race surfaced; fix exonerated.",
                    fg="green", bold=True)
        sys.exit(0)
    click.secho(
        f"GROUND TRUTH FAIL: vuln_flagged={vuln_ok} fix_exonerated={fixed_ok}",
        fg="red", bold=True,
    )
    sys.exit(1)

@cli.command()
@click.option("--old", "old_dir", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to the OLD kernel source tree.")
@click.option("--new", "new_dir", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to the NEW kernel source tree.")
@click.option("--subsystem", "subsystems", multiple=True,
              help="Subsystem to scope (repeatable).")
@click.option("--llm", type=click.Choice(LLM_CHOICES), default="heuristic", show_default=True)
@click.option("--json", "json_out", type=click.Path(path_type=Path), default=None,
              help="Write the diff as JSON to this path.")
def diff(old_dir, new_dir, subsystems, llm, json_out):
    """Compare racemap findings between two kernel trees (NEW / RESOLVED / PERSISTENT)."""
    from src.scanner import diff_mode
    subs = list(subsystems) or None
    entries = diff_mode.compare(old_dir, new_dir, RULES_DIR, subsystems=subs, backend=llm)
    Reporter().render_diff(entries, str(old_dir), str(new_dir))
    if json_out:
        import json as _json
        Path(json_out).write_text(_json.dumps([e.__dict__ for e in entries], indent=2))
        print(f"diff JSON written to {json_out}")


@cli.command(name="clear-cache")
def clear_cache():
    """Delete all cached triage responses (~/.racemap/cache.db)."""
    from src.triage.cache import TriageCache
    n = TriageCache().clear()
    click.secho(f"cleared {n} cached triage response(s).", fg="green")


if __name__ == "__main__":
    cli()
