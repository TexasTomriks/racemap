"""Export a racemap Candidate as a starter Semgrep rule (YAML).

Given a detected candidate, produce a valid Semgrep YAML rule a user can drop
into their own ruleset. The pattern is seeded from the candidate's code snippet;
it is a starting point intended for human refinement, not a finished rule.
"""

from __future__ import annotations

import datetime
import re

from src import __version__
from src.models import Candidate

# Sink / primitive tokens we prefer as the pattern line.
_SINK_TOKENS = (
    "skcipher_request_set_crypt", "aead_request_set_crypt", "request_set_crypt",
    "skb_zerocopy", "get_user_pages", "PIPE_BUF_FLAG_CAN_MERGE",
    "copy_from_user", "copy_to_user", "pipe_buf", "->bvec", "->page",
)


def _yaml_dq(text: str) -> str:
    """Double-quote a scalar for YAML, escaping backslashes and quotes."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _pattern_line(candidate: Candidate) -> str:
    snippet = candidate.snippet or ""
    lines = [ln.strip() for ln in snippet.splitlines()
             if ln.strip() and not ln.lstrip().startswith(("*", "//", "/*"))]
    for ln in lines:
        if any(tok in ln for tok in _SINK_TOKENS):
            return ln
    field = candidate.shared_field or ""
    key = field.split("->")[-1] if "->" in field else field
    if key:
        for ln in lines:
            if key and key in ln:
                return ln
    return lines[-1] if lines else "..."


def export_yaml(candidate: Candidate) -> str:
    """Return a Semgrep rule (YAML text) for a single candidate."""
    rule_id = f"racemap-export-{_slug(candidate.rule_id)}-l{candidate.line}"
    severity = "ERROR" if candidate.cve_id else "WARNING"
    pattern = _pattern_line(candidate)
    message = (
        f"{candidate.message or 'racemap-detected race candidate'} "
        f"(auto-exported by racemap {__version__} from {candidate.file}:{candidate.line})"
    )
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        "rules:",
        f"  - id: {rule_id}",
        f"    message: {_yaml_dq(message)}",
        f"    severity: {severity}",
        "    languages: [c]",
        "    patterns:",
        f"      - pattern: {_yaml_dq(pattern)}",
        "    metadata:",
        f"      racemap_version: {_yaml_dq(__version__)}",
        f"      export_timestamp: {_yaml_dq(ts)}",
        f"      shared_field: {_yaml_dq(candidate.shared_field or '')}",
        f"      source_rule: {_yaml_dq(candidate.rule_id)}",
        f"      container_escape: {str(candidate.container_escape_potential).lower()}",
    ]
    if candidate.cve_id:
        lines.append(f"      cve_id: {_yaml_dq(candidate.cve_id)}")
    if candidate.affected_versions:
        av = ", ".join(_yaml_dq(v) for v in candidate.affected_versions)
        lines.append(f"      affected_versions: [{av}]")
    return "\n".join(lines) + "\n"


def filename_for(candidate: Candidate) -> str:
    return f"racemap-export-{_slug(candidate.rule_id)}-l{candidate.line}.yaml"
