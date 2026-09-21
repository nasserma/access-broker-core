"""Dev-machine resolution of the groupware sibling checkout (the
verification-by-porting parity imports). Publishable form of the
previously hard-coded absolute path: the env var GROUPWARE_PATH names
the sibling checkout on dev machines; when absent or unusable, the
parity tests that need the real groupware semantics SKIP rather than
fail (the wall mechanics are still exhaustively tested against the
in-file table)."""

# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
from pathlib import Path


def groupware_path() -> str | None:
    """Resolve the sibling groupware checkout, env var first, then the
    conventional suite layout. Returns the directory that actually
    contains groupware_broker, or None."""
    candidates: list[str] = []
    env = os.environ.get("GROUPWARE_PATH")
    if env:
        candidates.append(env)
    here = Path(__file__).resolve().parent.parent
    candidates.append(str(here.parent / "groupwareAccessBroker"))
    for cand in candidates:
        if (Path(cand) / "groupware_broker").is_dir():
            return cand
    return None


def insert_groupware_path() -> str | None:
    """Add the resolved sibling to sys.path (idempotent); returns the
    path or None when unavailable."""
    path = groupware_path()
    if path is not None and path not in sys.path:
        sys.path.insert(0, path)
    return path
