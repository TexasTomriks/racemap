"""racemap — Streamlit dashboard (modern, light/dark themes).

Clean, professional, minimal. Light mode by default; a top-right toggle switches
to dark. No neon colours anywhere — a mat, professional palette throughout. The
triage layer is a false-positive filter only; it never generates exploits.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
import time
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import streamlit as st

from src import __version__
from src.models import ScanReport, Verdict
from src.scanner import Scanner, version_tracker, patch_gap as _patch_gap, diff_mode
from src.triage import LLM_CHOICES, TriagePipeline
from src.reporter import Reporter
from src.reporter.semgrep_exporter import export_yaml, filename_for
from src.ui import live_scan

RULES_DIR = ROOT / "rules"
SUBSYSTEMS = ["net", "crypto", "drivers/char", "io_uring", "fs", "mystery"]
ENV_KEY = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
           "gemini": "GEMINI_API_KEY"}

# ---- theme palettes ------------------------------------------------------- #
THEMES = {
    "light": {
        "bg": "#F9FAFB", "surface": "#FFFFFF", "border": "#E5E7EB",
        "text": "#111827", "text2": "#6B7280", "muted": "#9CA3AF",
        "accent": "#059669", "danger": "#DC2626", "warn": "#D97706",
        "sidebar": "#F9FAFB", "row": "#FFFFFF", "row_hover": "#F9FAFB",
        "header_bg": "#FFFFFF", "nav_active_bg": "#ECFDF5",
        "term_bg": "#F3F4F6", "term_text": "#374151", "term_border": "#D1D5DB",
        "race_bg": "#FEE2E2", "race_fg": "#DC2626",
        "safe_bg": "#D1FAE5", "safe_fg": "#059669",
        "review_bg": "#FEF3C7", "review_fg": "#D97706",
        "card_shadow": "0 1px 3px rgba(0,0,0,0.08)", "graph_bg": "#FFFFFF",
        "tab_inactive": "#6B7280", "uploader_bg": "#F9FAFB",
        "chart_race": "#DC2626", "chart_safe": "#059669",
        "score_high": "#DC2626", "score_med": "#D97706", "score_low": "#059669",
    },
    "dark": {
        "bg": "#0F1117", "surface": "#1C1E26", "border": "#2D3748",
        "text": "#F1F5F9", "text2": "#94A3B8", "muted": "#64748B",
        "accent": "#10B981", "danger": "#EF4444", "warn": "#F59E0B",
        "sidebar": "#161820", "row": "#1C1E26", "row_hover": "#252836",
        "header_bg": "#161820", "nav_active_bg": "#0D2D1F",
        "term_bg": "#0D1117", "term_text": "#D1D5DB", "term_border": "#374151",
        "race_bg": "rgba(220,38,38,0.15)", "race_fg": "#F87171",
        "safe_bg": "rgba(5,150,105,0.15)", "safe_fg": "#34D399",
        "review_bg": "#3A2A07", "review_fg": "#FBBF24",
        "card_shadow": "none", "graph_bg": "#1C1E26",
        "tab_inactive": "#64748B", "uploader_bg": "#1C1E26",
        "chart_race": "#B91C1C", "chart_safe": "#047857",
        "score_high": "#EF4444", "score_med": "#F59E0B", "score_low": "#10B981",
    },
}
# Pattern → mat chip hue (works on both themes).
PATTERN_HUE = {
    "aead_inplace_write": "#2563EB", "zerocopy_skb_race": "#D97706",
    "splice_pipe_race": "#7C3AED", "io_uring_shared_buffer": "#0D9488",
    "vmsplice_gup_race": "#CA8A04",
}
METRIC_HELP = {
    "candidates": "Total race candidates surfaced by static analysis.",
    "likely race": "Candidates the triage filter rates as genuine races.",
    "exonerated": "Candidates triaged as safe (snapshot/copy/lock found).",
    "escape": "ESCAPE = candidates that can cross a container boundary via shared memory.",
    "fp-filtered": "Candidates demoted by caller-lock / annotation / barrier analysis.",
}
SANS = ('-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, '
        'Arial, sans-serif')
MONO = '"SF Mono", "JetBrains Mono", Menlo, Consolas, monospace'

LOGO_SVG = (
    '<svg width="22" height="22" viewBox="0 0 48 48" fill="none" '
    'xmlns="http://www.w3.org/2000/svg">'
    '<path d="M6 14 H20 L34 34 H42" stroke="{a}" stroke-width="2.5"/>'
    '<path d="M6 34 H20 L34 14 H42" stroke="{a}" stroke-width="2.5" opacity="0.55"/>'
    '<circle cx="6" cy="14" r="3" fill="{a}"/><circle cx="6" cy="34" r="3" fill="{a}"/>'
    '<circle cx="42" cy="34" r="3" fill="{a}"/><circle cx="42" cy="14" r="3" fill="{a}"/>'
    '<circle cx="27" cy="24" r="2.4" fill="{d}"/></svg>'
)

st.set_page_config(layout="wide", page_title="RACEMAP // Kernel Race Scanner",
                   page_icon="⚡")

# Module-level active palette (set per rerun in main()).
T = THEMES["light"]


def active_theme() -> dict:
    return THEMES.get(st.session_state.get("theme", "light"), THEMES["light"])


def inject_css(t: dict) -> None:
    st.markdown(f"""
<style>
#MainMenu, header, footer, [data-testid="stToolbar"], [data-testid="stDecoration"],
[data-testid="stStatusWidget"], .stDeployButton, [data-testid="stHeader"] {{
  display:none !important; visibility:hidden !important; }}
html, body, .stApp, [class*="css"] {{ font-family:{SANS} !important; }}
.stApp, body {{ background:{t['bg']} !important; color:{t['text2']} !important; }}
.block-container {{ padding-top:0.5rem !important; max-width:1600px; }}
h1,h2,h3,h4 {{ color:{t['text']}; }}
p,span,label,div {{ color:{t['text2']}; }}
* {{ transition: background-color 0.15s ease, border-color 0.15s ease, color 0.15s ease; }}

.rm-mono {{ font-family:{MONO}; }}
.rm-logo {{ font-family:{MONO}; color:{t['accent']}; font-weight:bold; font-size:18px;
  display:flex; align-items:center; gap:8px; }}
.rm-h {{ color:{t['text2']}; font-size:13px; text-transform:uppercase; letter-spacing:0.05em; margin:0.2rem 0; }}
.rm-railh {{ color:{t['muted']}; font-size:11px; text-transform:uppercase; letter-spacing:0.04em;
  margin:0.9rem 0 0.25rem 2px; }}

/* header bar */
.rm-topbar {{ display:flex; justify-content:space-between; align-items:center;
  background:{t['header_bg']}; border-bottom:1px solid {t['border']}; padding:0.5rem 0.9rem;
  border-radius:8px; margin-bottom:0.6rem; position:sticky; top:0; z-index:50; }}
.rm-pill {{ font-size:10px; padding:2px 8px; border-radius:10px; font-weight:600; letter-spacing:0.02em; }}
.rm-status {{ background:{t['review_bg']}; color:{t['review_fg']}; }}

/* left rail = first column */
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-of-type,
[data-testid="stHorizontalBlock"] > [data-testid="column"]:first-of-type {{
  background:{t['sidebar']}; border-right:1px solid {t['border']}; border-radius:8px;
  padding:0.8rem 0.7rem 2rem 0.7rem !important; align-items:flex-start; }}

/* metric cards */
.rm-cards {{ display:flex; gap:0.8rem; flex-wrap:wrap; margin:0.3rem 0 1rem 0; }}
.rm-card {{ flex:1; min-width:130px; background:{t['surface']}; border:1px solid {t['border']};
  border-radius:8px; padding:20px; box-shadow:{t['card_shadow']}; }}
.rm-card .num {{ font-size:28px; font-weight:600; line-height:1.1; }}
.rm-card .lbl {{ font-size:12px; text-transform:uppercase; letter-spacing:0.04em; color:{t['muted']}; margin-top:0.35rem; }}

/* table */
.rm-tablewrap {{ overflow-x:auto; width:100%; }}
table.rm-table {{ width:100%; border-collapse:collapse; font-size:13px; table-layout:auto; }}
table.rm-table th {{ background:{t['bg']}; color:{t['muted']}; text-transform:uppercase;
  letter-spacing:0.04em; text-align:left; padding:9px 10px; border-bottom:1px solid {t['border']};
  font-size:11px; }}
table.rm-table td {{ padding:9px 10px; border-bottom:1px solid {t['border']}; vertical-align:top;
  overflow:hidden; text-overflow:ellipsis; background:{t['row']}; color:{t['text2']}; }}
table.rm-table tr:hover td {{ background:{t['row_hover']}; }}
table.rm-table th.icol, table.rm-table td.icol {{ max-width:50px; width:50px; text-align:center; }}
.rm-badge {{ font-size:10px; padding:2px 8px; border-radius:6px; font-weight:600; }}
.rm-chip {{ font-size:10px; padding:1px 6px; border-radius:10px; white-space:nowrap; display:inline-block; }}
table.rm-table td.pat {{ white-space:nowrap; }}
table.rm-table td.loc {{ max-width:220px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.rm-path {{ font-family:{MONO}; font-size:12px; color:{t['text']}; }}
[data-testid="stDownloadButton"] button {{ width:100% !important; height:42px !important; margin:0 !important; }}

/* buttons: primary = solid accent; others = surface */
.stButton > button[kind="primary"] {{ background:{t['accent']} !important;
  border:1px solid {t['accent']} !important; font-weight:600 !important; }}
.stButton > button[kind="primary"], .stButton > button[kind="primary"] * {{
  color:#FFFFFF !important; font-weight:600 !important; }}
.stButton > button[kind="primary"]:hover {{ filter:brightness(0.94); }}
.stButton > button, [data-testid="stDownloadButton"] > button {{
  font-family:{SANS} !important; background:{t['surface']} !important; color:{t['accent']} !important;
  border:1px solid {t['border']} !important; border-radius:6px !important; font-weight:600 !important; width:100%; }}
.stButton > button:hover, [data-testid="stDownloadButton"] > button:hover {{ border-color:{t['accent']} !important; }}

/* inputs + selects + popover (Part 2) */
input, textarea {{ background:{t['surface']} !important; color:{t['text']} !important;
  border-color:{t['border']} !important; font-family:{SANS} !important; }}
input:focus, textarea:focus {{ border-color:{t['accent']} !important; }}
[data-baseweb="select"] > div {{ background:{t['surface']} !important; color:{t['text']} !important;
  border-color:{t['border']} !important; }}
[data-baseweb="select"] * {{ color:{t['text']} !important; }}
[data-baseweb="popover"], [data-baseweb="popover"] [role="listbox"],
[data-baseweb="menu"], ul[role="listbox"] {{ background:{t['surface']} !important;
  border:1px solid {t['border']} !important; }}
[data-baseweb="popover"] li, ul[role="listbox"] li {{ background:{t['surface']} !important;
  color:{t['text']} !important; }}
[data-baseweb="popover"] li:hover, ul[role="listbox"] li:hover {{ background:{t['row_hover']} !important; }}

.rm-term {{ background:{t['term_bg']}; border:1px solid {t['term_border']}; border-radius:6px;
  padding:0.6rem 0.8rem; color:{t['term_text']}; font-family:{MONO}; font-size:12px;
  white-space:pre-wrap; line-height:1.5; max-height:150px; overflow-y:auto;
  display:flex; flex-direction:column-reverse; }}
.rm-code {{ background:{t['term_bg']}; border-left:3px solid {t['accent']}; border-radius:4px;
  padding:0.5rem 0.8rem; color:{t['term_text']}; font-family:{MONO}; font-size:12px; white-space:pre-wrap; }}
.rm-empty {{ border:1px dashed {t['border']}; background:{t['surface']}; border-radius:8px;
  padding:2rem; text-align:center; color:{t['muted']}; }}
.critical-card {{ border:1px solid {t['danger']}; background:{t['surface']}; border-left:3px solid {t['danger']};
  border-radius:8px; padding:16px; margin:0.4rem 0; }}
.safe-card {{ border:1px solid {t['accent']}; background:{t['surface']}; border-left:3px solid {t['accent']};
  border-radius:8px; padding:16px; margin:0.4rem 0; }}
.warning-card {{ border:1px solid {t['warn']}; background:{t['surface']}; border-left:3px solid {t['warn']};
  border-radius:8px; padding:16px; margin:0.4rem 0; }}
.rm-demo {{ background:{t['review_bg']}; border:1px solid {t['warn']}; color:{t['review_fg']};
  border-radius:6px; padding:0.5rem 0.9rem; font-weight:600; margin-bottom:0.6rem; }}
[data-testid="stProgress"] > div > div > div > div {{ background:{t['accent']} !important; }}

/* Fix 3 — tab text colours */
[data-baseweb="tab"] {{ font-family:{SANS} !important; color:{t['tab_inactive']} !important; }}
[data-baseweb="tab"] * {{ color:{t['tab_inactive']} !important; }}
[aria-selected="true"][data-baseweb="tab"] {{ color:{t['text']} !important;
  border-bottom:2px solid {t['accent']} !important; }}
[aria-selected="true"][data-baseweb="tab"] * {{ color:{t['text']} !important; }}

/* Fix 5 — left rail background on every possible column selector + sidebar */
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-child,
[data-testid="stHorizontalBlock"] > [data-testid="column"]:first-child,
section[data-testid="stSidebar"] {{ background:{t['sidebar']} !important;
  border-right:1px solid {t['border']}; }}

/* Fix 2 — st.radio styled as a navigation menu (theme-aware, no white bleed) */
div[data-testid="stRadio"] [role="radiogroup"] {{ gap:3px; }}
div[data-testid="stRadio"] label {{ display:flex; align-items:center; width:100%;
  padding:7px 10px; border-radius:6px; border-left:3px solid transparent;
  background:{t['sidebar']}; color:{t['text2']}; cursor:pointer; }}
div[data-testid="stRadio"] label:hover {{ background:{t['row_hover']}; }}
div[data-testid="stRadio"] label,
div[data-testid="stRadio"] label *,
div[data-testid="stRadio"] [data-testid="stMarkdownContainer"] p {{ color:{t['text2']} !important; }}
div[data-testid="stRadio"] label > div:first-child {{ display:none !important; }}
div[data-testid="stRadio"] label:has(input:checked) {{ border-left:3px solid {t['accent']};
  background:{t['nav_active_bg']}; font-weight:600; }}
div[data-testid="stRadio"] label:has(input:checked),
div[data-testid="stRadio"] label:has(input:checked) * {{ color:{t['accent']} !important; }}

/* Fix 4 — file uploader theme (aggressive, all nested elements) */
[data-testid="stFileUploader"],
[data-testid="stFileUploader"] > div,
[data-testid="stFileUploader"] section,
[data-testid="stFileUploaderDropzone"],
[data-testid="stFileUploaderDropzone"] > div,
section[data-testid="stFileUploaderDropzone"] {{
  background-color:{t['uploader_bg']} !important; border-color:{t['border']} !important; }}
[data-testid="stFileUploader"] * {{ color:{t['text2']} !important; }}
[data-testid="stFileUploader"] button {{ background:{t['surface']} !important;
  color:{t['text2']} !important; border:1px solid {t['border']} !important; }}

/* Fix 6 — hide the radio widget's own (collapsed) label entirely */
div[data-testid="stRadio"] > label,
div[data-testid="stRadio"] [data-testid="stWidgetLabel"] {{
  display:none !important; height:0; margin:0; padding:0; }}

/* Fix 2 — rail must not stretch to viewport bottom; scroll with the page */
[data-testid="stHorizontalBlock"] > [data-testid="stColumn"]:first-of-type,
[data-testid="stHorizontalBlock"] > [data-testid="column"]:first-of-type {{
  align-self:flex-start !important; height:auto !important; }}

/* Fix 6 — expander header AND expanded content match the theme (no white) */
[data-testid="stExpander"], [data-testid="stExpander"] details,
[data-testid="stExpander"] details > div, [data-testid="stExpander"] summary,
[data-testid="stExpanderDetails"], .streamlit-expanderContent,
.streamlit-expanderHeader {{
  background-color:{t['surface']} !important; border-color:{t['border']} !important;
  color:{t['text2']} !important; }}

/* Fix 1 — compact pagination row (no bordered boxes, small controls) */
.rm-pager [data-testid="stButton"] button,
.rm-pager [data-testid="baseButton-secondary"] {{ height:32px !important; min-height:32px !important;
  padding:0 8px !important; }}
.rm-pager [data-testid="stSelectbox"] {{ max-width:90px; }}
.rm-pager [data-testid="stSelectbox"] label {{ display:none !important; }}
.rm-pager [data-baseweb="select"] > div {{ min-height:32px !important; }}

/* Fix 3/4 — input + uploader spacing/borders consistent */
[data-testid="stTextInput"] {{ margin-top:0 !important; }}
[data-testid="stFileUploader"] > label, [data-testid="stFileUploader"] [data-testid="stWidgetLabel"] {{
  margin-bottom:8px !important; display:block !important; }}
</style>
""", unsafe_allow_html=True)


# ---- cached compute ------------------------------------------------------- #
@st.cache_data(show_spinner=False)
def cached_scan(target: str, subs: tuple, backend: str, kver: str,
                patch_gap: bool, demo: bool) -> ScanReport:
    scanner = Scanner(rules_dir=RULES_DIR, subsystems=list(subs) or None, git_cross_ref=True)
    cands = scanner.scan(Path(target))
    if patch_gap:
        _patch_gap.apply_all(cands, Path(target))
    triage = TriagePipeline(backend=backend, demo_mode=demo, cache_enabled=True)
    return ScanReport(target=target, kernel_version=kver or None, subsystems=list(subs),
                      candidates_found=len(cands), results=triage.triage(cands))


@st.cache_data(show_spinner=False)
def cached_diff(old: str, new: str) -> list:
    return diff_mode.compare(Path(old), Path(new), RULES_DIR)


# ---- helpers -------------------------------------------------------------- #
def _score_color(s: float) -> str:
    return T["danger"] if s >= 0.9 else (T["warn"] if s >= 0.7 else T["accent"])


def _risk_word(s: float) -> str:
    return "high risk" if s >= 0.85 else ("medium risk" if s >= 0.5 else "low risk")


def _verdict_badge(v: str) -> str:
    bg, fg = {"likely_race": (T["race_bg"], T["race_fg"]),
              "likely_safe": (T["safe_bg"], T["safe_fg"]),
              "needs_review": (T["review_bg"], T["review_fg"])}.get(
        v, (T["surface"], T["muted"]))
    return f"<span class='rm-badge' style='background:{bg};color:{fg}'>{v.upper()}</span>"


def _chip(pattern: str) -> str:
    col = PATTERN_HUE.get(pattern, T["muted"])
    return (f"<span class='rm-chip' style='background:{col}1A;color:{col};"
            f"border:1px solid {col}55'>{escape(pattern or '—')}</span>")


def _metric_cards(cards) -> None:
    html = '<div class="rm-cards">'
    for value, label, color in cards:
        help_t = METRIC_HELP.get(label, label)
        html += (f'<div class="rm-card" title="{escape(help_t)}">'
                 f'<div class="num" style="color:{color}">{value}</div>'
                 f'<div class="lbl">{label}</div></div>')
    st.markdown(html + "</div>", unsafe_allow_html=True)


def _verdict_chart(ranked) -> None:
    rows = [{"subsystem": r.candidate.subsystem or "other", "verdict": r.verdict.value}
            for r in ranked]
    cmap = {"likely_race": T["chart_race"], "likely_safe": T["chart_safe"],
            "needs_review": T["warn"], "triage_error": "#9b59b6"}
    try:
        import pandas as pd, plotly.express as px
        df = pd.DataFrame(rows).groupby(["subsystem", "verdict"]).size().reset_index(name="count")
        is_dark = st.session_state.get("theme", "light") == "dark"
        fig = px.bar(df, x="subsystem", y="count", color="verdict",
                     color_discrete_map=cmap, barmode="stack",
                     template="plotly_dark" if is_dark else "plotly_white")
        fig.update_layout(paper_bgcolor=T["bg"], plot_bgcolor=T["surface"], height=280,
                          font=dict(family=SANS, color=T["text2"]),
                          margin=dict(l=12, r=12, t=24, b=12),
                          legend=dict(bgcolor=T["surface"], font=dict(color=T["text"])),
                          hoverlabel=dict(bgcolor=T["surface"], font_size=12, font_family=SANS))
        fig.update_xaxes(gridcolor=T["border"], tickfont=dict(color=T["text2"]),
                         title_font=dict(color=T["text2"]))
        fig.update_yaxes(gridcolor=T["border"], tickfont=dict(color=T["text2"]),
                         title_font=dict(color=T["text2"]))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    except Exception:
        st.write("(chart unavailable)")


def _results_table(results, start: int = 0) -> None:
    head = ("<div class='rm-tablewrap'><table class='rm-table'><tr><th>#</th><th>Verdict</th><th>Score</th>"
            "<th>Location</th><th>Pattern</th><th>CVE</th><th class='icol'>Esc</th>"
            "<th class='icol'>Lock</th><th class='icol'>Barr</th><th class='icol'>Ann</th>"
            "<th class='icol'>Irq</th><th class='icol'>WQ</th><th>Git Age</th></tr>")
    rows = ""
    for i, r in enumerate(results, start=start + 1):
        c = r.candidate
        rowcol = (T["race_fg"] if r.verdict == Verdict.LIKELY_RACE else
                  T["safe_fg"] if r.verdict == Verdict.LIKELY_SAFE else "transparent")
        sc = _score_color(r.score)
        aria = f"Risk score {r.score:.2f} out of 1.0, {_risk_word(r.score)}"
        cells = [
            f"<td style='border-left:2px solid {rowcol};color:{T['muted']}'>{i}</td>",
            f"<td>{_verdict_badge(r.verdict.value)}</td>",
            f"<td><span aria-label='{aria}' title='{aria}' style='color:{sc};font-weight:600'>{r.score:.2f}</span></td>",
            f"<td class='rm-path loc' title='{escape(c.location)}'>{escape(c.location)}</td>",
            f"<td class='pat'>{_chip(c.pattern_name or c.zero_copy_primitive)}</td>",
            f"<td style='color:{T['text2']}'>{escape(c.cve_id or '')}</td>",
            f"<td class='icol' title='container escape via shared memory'>{'●' if c.container_escape_potential else ''}</td>",
            f"<td class='icol' title='all callers hold {escape(c.caller_lock_name or '')}'>{'🔒' if c.caller_lock_held else ''}</td>",
            f"<td class='icol' title='memory barrier present'>{'🛡' if c.barrier_protected else ''}</td>",
            f"<td class='icol' title='{escape(c.annotation_detail or 'sparse annotation')}'>{'§' if c.annotation_protected else ''}</td>",
            f"<td class='icol' title='{escape(c.interrupt_context_note or 'interrupt context')}'>{'⚡' if c.interrupt_context_note else ''}</td>",
            f"<td class='icol' title='workqueue deferred path'>{'⚙' if c.workqueue_async else ''}</td>",
            f"<td class='rm-path' style='color:{T['text2']}'>"
            f"{('↻ ' + escape(c.git_age_note)) if c.git_age_note else ''}</td>",
        ]
        rows += "<tr>" + "".join(cells) + "</tr>"
    st.markdown(head + rows + "</table></div>", unsafe_allow_html=True)


def _paginate(items, key: str):
    """Compact one-row pager above the table: [‹][›] [centered info] [rows select]."""
    total = len(items)
    c_prev, c_next, c_info, c_sp, c_sz = st.columns([1, 1, 5, 1, 2])
    size = c_sz.selectbox("rows", [10, 20, 50, "All"], index=0, key=key + "_size",
                          label_visibility="collapsed")
    per = total if size == "All" else int(size)
    per = max(per, 1)
    pages = max(1, (total + per - 1) // per)
    page = min(max(st.session_state.get(key + "_page", 1), 1), pages)
    st.session_state[key + "_page"] = page
    start = (page - 1) * per
    endi = min(start + per, total)
    if c_prev.button("\u2039", key=key + "_prev", disabled=page <= 1,
                     use_container_width=True):
        st.session_state[key + "_page"] = page - 1
        st.rerun()
    if c_next.button("\u203a", key=key + "_next", disabled=page >= pages,
                     use_container_width=True):
        st.session_state[key + "_page"] = page + 1
        st.rerun()
    c_info.markdown(
        f"<div style='text-align:center;color:{T['muted']};font-size:12px;padding-top:7px'>"
        f"Showing {start + 1 if total else 0}-{endi} of {total} \u00b7 Page {page}/{pages}</div>",
        unsafe_allow_html=True)
    return items[start:endi], start


def _call_graph_html(candidate) -> str:
    """Deterministic static SVG call graph — always centred, always readable.

    No pyvis, no physics, no JS. candidate (red) -> async_op (gray), plus taint
    (green), lock (amber) and caller (amber) nodes when present.
    """
    surf = T["surface"]; border = T["border"]; muted = T["muted"]

    def _trunc(label: str) -> str:
        return label if len(label) <= 12 else label[:11] + "\u2026"

    def node(cx, cy, r, fill, label, full):
        return (f'<g><title>{escape(full)}</title>'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}"/>'
                f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" '
                f'fill="#FFFFFF" font-size="10" font-family="sans-serif">{escape(_trunc(label))}</text>'
                f'</g>')

    def edge(x1, y1, x2, y2, label, dashed=False):
        dash = ' stroke-dasharray="5,4"' if dashed else ''
        e = (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{muted}" '
             f'stroke-width="1.5" marker-end="url(#ah)"{dash}/>')
        mx, my = (x1 + x2) // 2, (y1 + y2) // 2 - 6
        e += (f'<text x="{mx}" y="{my}" text-anchor="middle" fill="{muted}" '
              f'font-size="10" font-family="sans-serif">{escape(label)}</text>')
        return e

    fn = candidate.function or "candidate"
    parts = [
        f'<svg viewBox="0 0 600 240" width="100%" height="240" '
        f'xmlns="http://www.w3.org/2000/svg" '
        f'style="background:{surf};border:1px solid {border};border-radius:8px">',
        f'<defs><marker id="ah" markerWidth="9" markerHeight="9" refX="8" refY="3" '
        f'orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="{muted}"/></marker></defs>',
    ]
    # edges first (so nodes draw on top)
    parts.append(edge(338, 70, 450, 70, "async handoff"))
    if candidate.taint_callee:
        parts.append(edge(322, 102, 460, 158, "taint"))
    if candidate.caller_lock_held:
        parts.append(edge(148, 158, 268, 92, "holds", dashed=True))
        parts.append(edge(150, 70, 262, 70, "calls"))
    # nodes
    parts.append(node(300, 70, 38, "#DC2626", fn, fn))
    parts.append(node(480, 70, 30, "#6B7280", "async_op", "async_op"))
    if candidate.taint_callee:
        parts.append(node(480, 180, 28, "#059669", candidate.taint_callee,
                          candidate.taint_callee))
    if candidate.caller_lock_held:
        parts.append(node(120, 180, 28, "#D97706",
                          candidate.caller_lock_name or "lock",
                          candidate.caller_lock_name or "lock"))
        parts.append(node(120, 70, 30, "#D97706", "caller", "caller"))
    parts.append("</svg>")
    return "".join(parts)


def _analysis(report: ScanReport) -> None:
    for idx, r in enumerate(report.ranked()):
        c = r.candidate
        cls = ("critical-card" if r.verdict == Verdict.LIKELY_RACE else
               "safe-card" if r.verdict == Verdict.LIKELY_SAFE else "warning-card")
        title = (f"{r.verdict.value.upper()} · {c.location} · "
                 f"{c.pattern_name or c.zero_copy_primitive} · {r.score:.2f}")
        with st.expander(title):
            steps = "\n".join(r.reasoning_steps)
            band = round((r.confidence_high - r.confidence_low) / 2, 2)
            fg = {"likely_race": T["race_fg"], "likely_safe": T["safe_fg"]}.get(
                r.verdict.value, T["review_fg"])
            st.markdown(
                f'<div class="{cls}"><div style="color:{fg};font-weight:600">'
                f'{r.verdict.value} · conf {r.confidence:.2f} (±{band}) · ~{r.token_count} tok · '
                f'{escape(r.model)}</div><div style="margin:0.3rem 0">{escape(r.reasoning)}</div>'
                f'<div class="rm-code">{escape(steps)}</div></div>', unsafe_allow_html=True)
            st.caption("Call graph — red=candidate, gray=async handoff, green=taint/lock, amber=caller")
            st.markdown(_call_graph_html(c), unsafe_allow_html=True)
            st.download_button("Export as Semgrep Rule", export_yaml(c),
                               file_name=filename_for(c), mime="text/yaml", key=f"sg_{idx}")


def _export_tab(report: ScanReport) -> None:
    ranked = report.ranked()
    payload = {"target": report.target, "kernel_version": report.kernel_version,
               "results": [Reporter._result_dict(r) for r in ranked]}
    rows = [{"file": r.candidate.file, "line": r.candidate.line,
             "pattern": r.candidate.pattern_name, "verdict": r.verdict.value,
             "score": r.score, "cve": r.candidate.cve_id or "",
             "escape": r.candidate.container_escape_potential} for r in ranked]
    csv_buf = io.StringIO()
    if rows:
        w = csv.DictWriter(csv_buf, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    from src.reporter.sarif import to_sarif
    races = sum(1 for r in ranked if r.verdict == Verdict.LIKELY_RACE)
    escapes = sum(1 for r in ranked if r.candidate.container_escape_potential)
    clean = sum(1 for r in ranked if r.candidate.mitigation_present is True)
    fp = sum(1 for r in ranked if r.candidate.mitigation_present is True
             and r.verdict == Verdict.LIKELY_RACE)
    fp_rate = (fp / clean * 100) if clean else 0.0
    arsenal = (f"Raw candidates: {len(ranked)} -> Triaged (likely races): {races} "
               f"-> FP rate: {fp_rate:.1f}% ({escapes} container-escape primitive(s))")
    c1, c2, c3 = st.columns(3)
    c1.download_button("JSON", json.dumps(payload, indent=2).encode(),
                       "racemap_report.json", "application/json", use_container_width=True)
    c2.download_button("CSV", csv_buf.getvalue().encode(),
                       "racemap_report.csv", "text/csv", use_container_width=True)
    c3.download_button("SARIF", json.dumps(to_sarif(report), indent=2).encode(),
                       "scan.sarif", "application/json", use_container_width=True)
    st.markdown('<div class="rm-railh">Arsenal summary</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="rm-code" style="font-weight:600;color:{T["text"]}">'
                f'{escape(arsenal)}</div>', unsafe_allow_html=True)


# ---- pages ---------------------------------------------------------------- #
def page_scan(cfg: dict) -> None:
    if cfg.get("run"):
        target = Path(cfg["kpath"])
        if not target.exists():
            st.markdown(f'<div class="critical-card">Path not found: {escape(cfg["kpath"])}</div>',
                        unsafe_allow_html=True)
            return
        if cfg["backend"] in ENV_KEY and cfg.get("api_key"):
            os.environ[ENV_KEY[cfg["backend"]]] = cfg["api_key"]
        holder = st.empty()
        bar = st.progress(0.0)
        log = ["> initializing scanner...", f"> backend: {cfg['backend']}",
               f"> target: {cfg['kpath']}"]
        holder.markdown(f'<div class="rm-term">{escape(chr(10).join(reversed(log)))}</div>',
                        unsafe_allow_html=True)
        time.sleep(0.05)
        report = cached_scan(cfg["kpath"], tuple(cfg["subs"]), cfg["backend"],
                             cfg["kver"], cfg["patch_gap"], False)
        for i, r in enumerate(report.ranked(), start=1):
            log.append(f"> candidate {r.candidate.location} :: triage={r.verdict.value}")
            holder.markdown(f'<div class="rm-term">{escape(chr(10).join(reversed(log[-30:])))}</div>',
                            unsafe_allow_html=True)
            bar.progress(min(i / max(len(report.results), 1), 1.0))
            time.sleep(0.03)
        log.append(f"[ ok ] {len(report.results)} candidate(s)")
        holder.markdown(f'<div class="rm-term">{escape(chr(10).join(reversed(log[-30:])))}</div>',
                        unsafe_allow_html=True)
        bar.progress(1.0)
        st.session_state["last_report"] = report

    report = st.session_state.get("last_report")
    if not report:
        st.markdown('<div class="rm-empty">Enter a kernel path in the rail and press '
                    'Run Scan to begin</div>', unsafe_allow_html=True)
        return

    ranked = report.ranked()
    races = sum(1 for r in ranked if r.verdict == Verdict.LIKELY_RACE)
    exo = sum(1 for r in ranked if r.verdict == Verdict.LIKELY_SAFE)
    esc = sum(1 for r in ranked if r.candidate.container_escape_potential)
    fp = sum(1 for r in ranked if r.candidate.caller_lock_held
             or r.candidate.annotation_protected or r.candidate.barrier_protected)
    _metric_cards([(str(len(ranked)), "candidates", T["text"]),
                   (str(races), "likely race", T["danger"]),
                   (str(exo), "exonerated", T["accent"]),
                   (str(esc), "escape", T["danger"]),
                   (str(fp), "fp-filtered", T["accent"])])
    t_res, t_ana, t_exp = st.tabs(["📊 Results", "🔍 Analysis", "📤 Export"])
    with t_res:
        _verdict_chart(ranked)
        page, start = _paginate(ranked, "results")
        _results_table(page, start)
    with t_ana:
        _analysis(report)
    with t_exp:
        _export_tab(report)


def page_diff() -> None:
    st.markdown('<div class="rm-h">Diff — compare two kernel trees</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    old = c1.text_input("Old tree", value=str(ROOT / "tests" / "sample_kernel_old"))
    new = c2.text_input("New tree", value=str(ROOT / "tests" / "sample_kernel_new"))
    if st.button("Run Diff", type="primary"):
        if not Path(old).exists() or not Path(new).exists():
            st.markdown('<div class="critical-card">Both paths must exist</div>',
                        unsafe_allow_html=True)
            return
        st.session_state["diff_entries"] = cached_diff(old, new)
        st.session_state["diff_page"] = 1
    entries = st.session_state.get("diff_entries")
    if not entries:
        return
    counts = diff_mode.summary(entries)
    _metric_cards([(str(counts[diff_mode.NEW]), "new", T["danger"]),
                   (str(counts[diff_mode.RESOLVED]), "resolved", T["accent"]),
                   (str(counts[diff_mode.PERSISTENT]), "persistent", T["warn"])])
    badge = {diff_mode.NEW: (T["race_bg"], T["race_fg"]),
             diff_mode.RESOLVED: (T["safe_bg"], T["safe_fg"]),
             diff_mode.PERSISTENT: (T["review_bg"], T["review_fg"])}
    page, _start = _paginate(entries, "diff")
    head = ("<div class='rm-tablewrap'><table class='rm-table'><tr><th>File</th>"
            "<th>Pattern</th><th>Status</th><th>Risk</th></tr>")
    body = "".join(
        f"<tr><td class='rm-path loc' title='{escape(e.file)}:{e.line}'>{escape(e.file)}:{e.line}</td>"
        f"<td class='pat'>{_chip(e.pattern)}</td>"
        f"<td><span class='rm-badge' style='background:{badge[e.status][0]};color:{badge[e.status][1]}'>"
        f"{e.status}</span></td>"
        f"<td style='color:{_score_color(e.score)};font-weight:600'>{e.score:.2f}</td></tr>"
        for e in page)
    st.markdown(head + body + "</table></div>", unsafe_allow_html=True)


def page_live() -> None:
    st.markdown('<div class="rm-h">Bring your own driver</div>', unsafe_allow_html=True)
    preset = st.selectbox("Demo preset", ["(none)"] + list(live_scan.PRESETS.keys()))
    up = st.file_uploader("Upload a .c file", type=["c"])
    src, name = None, "upload.c"
    if up is not None:
        src = up.getvalue().decode("utf-8", errors="ignore"); name = up.name
    elif preset != "(none)":
        src = live_scan.preset_source(preset); name = Path(live_scan.PRESETS[preset]).name
    if src is not None:
        with st.expander("Source"):
            st.code(src, language="c")
    if st.button("Initialize Scan", type="primary"):
        if src is None:
            st.markdown('<div class="warning-card">Choose a preset or upload a file</div>',
                        unsafe_allow_html=True)
            return
        with st.spinner(f"scanning {name} …"):
            report, secs = live_scan.scan_source(src, name, patch_gap=True)
        st.session_state["live_report"] = report
        st.session_state["live_meta"] = (name, secs)
        st.session_state["live_results_page"] = 1
    report = st.session_state.get("live_report")
    if report is None:
        return
    name, secs = st.session_state.get("live_meta", (name, 0.0))
    st.markdown(f'<div class="rm-term">[ ok ] {escape(name)} in {secs*1000:.1f}ms — '
                f'{report.candidates_found} candidate(s)</div>', unsafe_allow_html=True)
    if not report.results:
        st.markdown('<div class="safe-card">No race candidates — looks clean</div>', unsafe_allow_html=True)
        return
    t_res, t_ana = st.tabs(["📊 Results", "🔍 Analysis"])
    with t_res:
        page, start = _paginate(report.ranked(), "live_results")
        _results_table(page, start)
    with t_ana:
        _analysis(report)


def page_patch() -> None:
    st.markdown('<div class="rm-h">Patch gap analysis</div>', unsafe_allow_html=True)
    report = st.session_state.get("last_report")
    if not report:
        st.markdown('<div class="rm-empty">Run a scan first — patch-gap results appear here</div>',
                    unsafe_allow_html=True)
        return
    cands = [r.candidate.model_copy(deep=True) for r in report.results]
    try:
        _patch_gap.apply_all(cands, Path(report.target))
    except Exception:
        pass
    missing = _patch_gap.missing_patches(cands)
    if not missing:
        st.markdown('<div class="safe-card">No missing patches in the last scan</div>', unsafe_allow_html=True)
        return
    for e in missing:
        st.markdown(f'<div class="critical-card"><b style="color:{T["danger"]}">Missing patch: '
                    f'{escape(str(e["signature_for"]))}</b><br><span style="color:{T["muted"]}">'
                    f'candidates: {e["count"]} · subsystems: {escape(", ".join(e["subsystems"]) or "—")}'
                    f'</span></div>', unsafe_allow_html=True)


def page_cache() -> None:
    st.markdown('<div class="rm-h">Response cache</div>', unsafe_allow_html=True)
    from src.triage.cache import TriageCache, DEFAULT_DB
    st.markdown(f'<div class="rm-railh">SQLite cache at {escape(str(DEFAULT_DB))} · TTL 7 days</div>',
                unsafe_allow_html=True)
    cache = TriageCache()
    n = cache._conn.execute("SELECT COUNT(*) FROM triage_cache").fetchone()[0]
    _metric_cards([(str(n), "cached responses", T["accent"])])
    if st.button("Clear cache", type="primary"):
        cleared = cache.clear()
        st.markdown(f'<div class="rm-term">cleared {cleared} cached response(s)</div>',
                    unsafe_allow_html=True)


# ---- rail + main ---------------------------------------------------------- #
def render_rail() -> dict:
    st.markdown('<div class="rm-railh">Run</div>', unsafe_allow_html=True)
    run = st.button("Run Scan", type="primary")
    st.markdown('<div class="rm-railh">Configuration</div>', unsafe_allow_html=True)
    kpath = st.text_input("Kernel path", value=str(ROOT / "tests" / "sample_kernel"))
    backend = st.selectbox("LLM backend", LLM_CHOICES, index=LLM_CHOICES.index("heuristic"))
    api_key = ""
    if backend in ENV_KEY:
        api_key = st.text_input(ENV_KEY[backend], type="password")
    kver = st.selectbox("Kernel version",
                        ["", "4.9", "5.4", "5.10", "5.15", "5.16", "6.0", "6.1",
                         "6.6", "6.8", "6.9", "6.10", "6.12"], index=0)
    patch_gap = st.toggle("Patch gap", value=True)

    st.markdown('<div class="rm-railh">Navigation</div>', unsafe_allow_html=True)
    items = ["Scan", "Diff", "Live Scan", "Patch Gap", "Cache"]
    nav = st.radio("Section navigation", items, label_visibility="collapsed", key="rm_nav")

    # Patch-signature database section.
    from src.scanner import db_updater
    st.markdown('<div class="rm-railh">Database</div>', unsafe_allow_html=True)
    info = db_updater.last_update_info()
    if info["age_days"] is None:
        last = "Never"
    else:
        d = int(info["age_days"])
        last = "today" if d < 1 else f"{d} day{'s' if d != 1 else ''} ago"
    st.markdown(f'<div style="color:{T["muted"]};font-size:11px;margin:0 0 4px 2px">'
                f'Last updated: {last}</div>', unsafe_allow_html=True)
    if st.button("🔄 Update Patch DB", key="update_db", use_container_width=True):
        with st.spinner("Fetching from kernel.org..."):
            res = db_updater.fetch_latest_signatures()
            db_updater.update_local_db(res)
        if res["errors"] and res["updated"] == 0:
            st.warning("Update failed — using built-in DB")
        else:
            st.success(f"DB updated: {res['updated']} signatures refreshed")

    # Theme toggle at the very bottom of the rail (Fix 4).
    st.markdown('<div class="rm-railh">Theme</div>', unsafe_allow_html=True)
    tlabel = ("🌙 Switch to Dark" if st.session_state.get("theme", "light") == "light"
              else "☀️ Switch to Light")
    if st.button(tlabel, key="theme_toggle", use_container_width=True):
        st.session_state["theme"] = ("dark" if st.session_state.get("theme", "light") == "light"
                                     else "light")
        st.rerun()

    return {"run": run, "kpath": kpath, "backend": backend, "api_key": api_key,
            "kver": kver, "patch_gap": patch_gap, "subs": SUBSYSTEMS, "nav": nav}


def main() -> None:
    global T
    if "theme" not in st.session_state:
        st.session_state["theme"] = "light"
    T = active_theme()
    inject_css(T)

    # Zone A — full-width header bar (theme toggle now lives at the rail bottom).
    st.markdown(
        f'<div class="rm-topbar"><div class="rm-logo">'
        f'{LOGO_SVG.format(a=T["accent"], d=T["danger"])} RACEMAP '
        f'<span style="color:{T["muted"]};font-size:11px">v{__version__}</span></div>'
        f'</div>',
        unsafe_allow_html=True)

    rail_col, content = st.columns([1, 4], gap="medium")
    with rail_col:
        cfg = render_rail()
    with content:
        nav = cfg["nav"]
        if nav == "Scan":
            page_scan(cfg)
        elif nav == "Diff":
            page_diff()
        elif nav == "Live Scan":
            page_live()
        elif nav == "Patch Gap":
            page_patch()
        elif nav == "Cache":
            page_cache()


if __name__ == "__main__":
    main()
