"""Minimal ``.env`` loader.

The README and the web UI both tell the user an API key can live in a ``.env``
file in the project root. Nothing read it: every backend goes straight to
``os.environ`` and ``python-dotenv`` is not a dependency, so a key placed in
``.env`` was silently ignored and the run fell back to the offline heuristic.
This is the smallest thing that makes that instruction true, without pulling in
another package.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


def load_dotenv(path: Path | None = None) -> int:
    """Populate ``os.environ`` from a ``.env`` file; existing variables win.

    Returns the number of variables set. A missing or unreadable file is the
    normal case and is silently ignored.
    """
    path = Path(path) if path is not None else DEFAULT_ENV_PATH
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return 0

    count = 0
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        # An explicitly exported variable always beats the file.
        if key and key not in os.environ:
            os.environ[key] = value
            count += 1
    return count
