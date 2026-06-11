#!/usr/bin/env python3
"""Playwright self-verification for the racemap web UI.

Run where a Chromium browser is available (the build sandbox blocks the
Playwright browser download, so this could not be executed there):

    pip install playwright && playwright install chromium
    python web/verify.py

Captures every tab in BOTH light and dark to web/screenshots/, and asserts:
  * bar chart renders visible bars in dark mode (the regression we fixed)
  * no emoji/box glyphs survive in the rendered DOM (icons are inline SVG)
  * call-graph labels are truncated/readable, nodes drawn
  * header fixed on scroll, sidebar not stretched, export + diff aligned
"""
from __future__ import annotations
import re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "web" / "screenshots"; SHOTS.mkdir(exist_ok=True)
BASE = "http://127.0.0.1:5005"
TABS = ["scan", "diff", "live", "patch", "cache"]
EMOJI = re.compile(
    "[\U0001F300-\U0001FAFF☀-➿⬀-⯿■-◿✀-➿]")


def main() -> int:
    from playwright.sync_api import sync_playwright
    srv = subprocess.Popen([sys.executable, str(ROOT / "web" / "server.py")])
    time.sleep(4)
    issues: list[str] = []
    try:
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1440, "height": 900})
            pg.goto(BASE, wait_until="networkidle")

            # run a scan so the scan tab has content
            pg.fill("#kpath", "tests/sample_kernel")
            pg.click("#runScan")
            pg.wait_for_selector("#scanMetrics .metric", timeout=60000)
            pg.wait_for_timeout(400)

            # Fix (session log): run two more scans, assert capped dimmed history
            for _ in range(2):
                pg.click("#runScan")
                pg.wait_for_timeout(800)
            entries = pg.eval_on_selector_all("#scanTerminal .log-entry", "els => els.length")
            tops = pg.eval_on_selector_all("#scanTerminal .log-entry.top", "els => els.length")
            if entries < 3 or entries > 5:
                issues.append(f"session log entry count out of range: {entries}")
            if tops != 1:
                issues.append(f"expected exactly 1 highlighted (top) log entry, got {tops}")
            pg.screenshot(path=str(SHOTS / "session_log.png"))

            for theme in ("light", "dark"):
                want_dark = theme == "dark"
                is_dark = pg.get_attribute("html", "data-theme") == "dark"
                if want_dark != is_dark:
                    pg.click("#themeToggle"); pg.wait_for_timeout(300)

                # bar chart must have visible bars (esp. in dark)
                pg.click("#nav a[data-tab='scan']"); pg.wait_for_timeout(200)
                bars = pg.eval_on_selector_all(
                    "#chartWrap rect",
                    "els => els.filter(e => e.getBBox().height > 1).length")
                if bars == 0:
                    issues.append(f"[{theme}] bar chart has no visible bars")

                # no box-glyph emoji anywhere in rendered text
                txt = pg.inner_text("body")
                bad = set(EMOJI.findall(txt))
                if bad:
                    issues.append(f"[{theme}] emoji/box glyphs in DOM: {bad}")

                for tab in TABS:
                    pg.click(f"#nav a[data-tab='{tab}']"); pg.wait_for_timeout(200)
                    pg.screenshot(path=str(SHOTS / f"{theme}_{tab}.png"), full_page=True)

                # analysis + call graph
                pg.click("#nav a[data-tab='scan']")
                pg.click("#scanTabs a[data-sub='analysis']"); pg.wait_for_timeout(200)
                pg.click(".acard .head"); pg.wait_for_timeout(1300)
                nodes = pg.eval_on_selector_all("#graph circle", "els => els.length")
                labels = pg.eval_on_selector_all("#graph text", "els => els.map(e=>e.textContent)")
                if not nodes:
                    issues.append(f"[{theme}] call graph drew 0 nodes")
                if any(len(l) > 16 for l in labels):
                    issues.append(f"[{theme}] call-graph label not truncated: {labels}")
                pg.screenshot(path=str(SHOTS / f"{theme}_call_graph.png"))

                # export alignment
                pg.click("#scanTabs a[data-sub='export']"); pg.wait_for_timeout(200)
                ys = pg.eval_on_selector_all(".export-row a",
                     "els => els.map(e => Math.round(e.getBoundingClientRect().top))")
                if len(set(ys)) > 1:
                    issues.append(f"[{theme}] export buttons misaligned: {ys}")
                pg.click("#scanTabs a[data-sub='results']")

            # header fixed on scroll
            top0 = pg.eval_on_selector("#topbar", "e=>e.getBoundingClientRect().top")
            pg.evaluate("window.scrollTo(0,600)"); pg.wait_for_timeout(150)
            top1 = pg.eval_on_selector("#topbar", "e=>e.getBoundingClientRect().top")
            if abs(top1 - top0) > 1:
                issues.append(f"header not fixed on scroll ({top0}->{top1})")
            # sidebar not stretched
            sb = pg.eval_on_selector("#sidebar", "e=>e.getBoundingClientRect().height")
            if sb >= 900 - 56 - 2:
                issues.append(f"sidebar stretches to bottom (h={sb})")
            # diff inputs aligned
            pg.click("#nav a[data-tab='diff']"); pg.wait_for_timeout(150)
            dys = pg.eval_on_selector_all("#diffOld,#diffNew",
                  "els=>els.map(e=>Math.round(e.getBoundingClientRect().top))")
            if len(set(dys)) > 1:
                issues.append(f"diff inputs misaligned: {dys}")
            b.close()
    finally:
        srv.terminate()

    print("\n=== racemap UI verification ===")
    if issues:
        print("ISSUES:"); [print("  -", i) for i in issues]; return 1
    print(f"PASS — screenshots in {SHOTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
