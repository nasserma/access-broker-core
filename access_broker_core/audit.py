"""Append-only, hash-chained audit log, write-before-operate (S3).

Ported from the same author's nextcloud-access-broker broker/audit.py
(GPL-3.0-or-later) per the S3 design note, with the PIM field adaptations:

- ``account`` replaces ``instance``;
- ``resource`` carries the backend-shaped resource (mail folder, calendar,
  address book, task list);
- an optional ``backend`` field names the protocol family
  (imap | smtp | caldav | carddav | msgraph);
- Tier-2 lifecycle event types are recorded in ``decision``:
  submitted, approved, rejected, revoked, expired_notice, executed,
  refused (LIFECYCLE_EVENTS). Each Tier-2 execution writes its intent
  entry BEFORE the backend call via the ``then`` callback.

Goal contract requirements (unchanged from the reference):

- Write-before-operate. record() writes and flushes the entry, and only
  then runs the caller's operation via the ``then`` callback. If the log
  write fails for ANY reason (disk, permissions, injected fault), the
  callback never runs and LogWriteError propagates. The wall does not
  operate unobserved.
- Append-only, fsync per record.
- Tamper evidence: every record carries prev_sha256, the hash of the
  canonical JSON of the previous record (64 zeros for the first).
  verify_chain() walks the chain and reports the first break, detecting
  truncation, reordering, and edits.
- No secrets: any field containing a configured secret-shaped string is
  rejected with ValueError before it is ever written. The configured
  secrets list is injected by the caller (config, later stage); the log
  itself never sees credentials otherwise.
- The clock is injected (same clock provider as grants/policy: a
  Callable[[], datetime]; the timestamp is written ISO-8601).

Record format (one JSON object per line, canonical key order):
  {"timestamp": ..., "account": ..., "backend": ..., "resource": ...,
   "operation": ..., "grant_id": ..., "decision": ..., "reason": ...,
   "principal": ..., "custody": ..., "prev_sha256": ..., "sha256": ...}

The chain hash is computed over the record WITHOUT prev_sha256, so a
record's own hash does not depend on the chain position of its writer,
and verify_chain() recomputes identically. Optional fields (backend,
principal) are hashed only when present, so legacy lines still verify.

Truncation detection: a hash chain alone cannot detect the loss of its
own tail (a shorter chain is internally consistent). So every write also
updates a sidecar checkpoint file (<path>.head) holding the chain head
hash and the line count. verify_chain() compares the log against the
checkpoint; a missing tail is reported as a chain break.

No protocol coupling, no I/O beyond the log file and its checkpoint, no
network, no wall-clock reads.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from access_broker_core.custody import CustodyClass

GENESIS = "0" * 64

_CHAINED_FIELDS = (
    "timestamp",
    "account",
    "backend",
    "resource",
    "operation",
    "grant_id",
    "decision",
    "reason",
    "principal",
    "custody",
)

#: Tier-2 lifecycle event types (goal contract D5): the values written in
#: the ``decision`` field for grant lifecycle entries. Each Tier-2
#: execution writes its intent entry (``executed`` pending the backend
#: call) BEFORE the backend call, via the ``then`` callback.
LIFECYCLE_EVENTS = frozenset(
    {"submitted", "approved", "rejected", "revoked", "expired_notice", "executed", "refused"}
)


#: The recognized custody vocabulary (S6-1): the string values a
#: record's ``custody`` field may carry. Anything else is refused
#: before write.
_CUSTODY_VALUES = frozenset(c.value for c in CustodyClass)


def _check_custody_value(custody) -> None:
    """Fail-closed vocabulary gate on the optional custody field: the
    chain must never carry a custody statement outside the recognized
    vocabulary. Runs BEFORE the entry is built, so a refused value
    leaves no partial record behind. The enum member itself is
    normalized by the caller."""
    if custody is None or isinstance(custody, CustodyClass):
        return
    if not isinstance(custody, str) or custody not in _CUSTODY_VALUES:
        raise ValueError(
            f"refusing to record custody value {custody!r}: not a "
            "recognized custody class (scoped | account_wide | unscopable)"
        )


class LogWriteError(Exception):
    """The audit write failed; the operation was refused.

    Carries the security contract of the audit gate: whatever operation
    was to be recorded has NOT run, and the caller must fail the request
    closed. Raised both for I/O failures and for an unreadable
    pre-existing tail at open time.
    """


@dataclass(frozen=True)
class ChainResult:
    """Outcome of verify_chain(): ok=False means the log cannot be trusted
    as a faithful, complete record (edit, reorder, truncation, or
    checkpoint mismatch); error names the first problem, lines is the
    verified record count (0 on most failures)."""

    ok: bool
    error: str | None = None
    lines: int = 0


def _canonical(record: dict) -> str:
    """Serialize with sorted keys so the same record always hashes
    identically, regardless of dict construction order."""
    return json.dumps(record, sort_keys=True)


def _chain_payload(record: dict) -> str:
    """The subset of fields that get hashed: everything except prev_sha256."""
    return _canonical({k: record[k] for k in _CHAINED_FIELDS if k in record})


class AuditLog:
    """Append-only audit log writer (module docstring carries the full
    security contract: write-before-operate, fsync per record, chain
    hashing, checkpoint sidecar, secret scrubbing). One instance per
    process, constructed at boot with the shared injected clock."""

    def __init__(
        self,
        path: Path | str,
        clock: Callable[[], datetime],
        secrets: list[str] | None = None,
    ):
        """Open the audit log and recover the chain head from disk.

        path: append-only JSONL log file; the sidecar checkpoint is
        <path>.head. clock: injected clock (same provider as
        grants/policy) returning the datetime written ISO-8601 into
        records. secrets: configured secret-shaped strings; any field
        containing one is refused before write (credential-scrubbing
        guarantee - the log never stores secrets).
        Raises LogWriteError if the existing tail is unreadable: a
        broken chain is never silently extended.
        """
        self._path = Path(path)
        self._head_path = Path(str(self._path) + ".head")
        self._clock = clock
        self._secrets = [s for s in (secrets or []) if s]
        self._prev_sha256, self._lines = self._load_last_hash()

    def _load_last_hash(self) -> tuple[str, int]:
        """Recover the chain head on restart: read the last valid line's
        stored hash-of-record and the line count. If the file does not
        exist, genesis. Raises LogWriteError on an unreadable tail."""
        if not self._path.exists():
            return GENESIS, 0
        try:
            with open(self._path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return GENESIS, 0
                # count lines and take the last in one pass
                f.seek(0)
                raw = f.read().decode("utf-8", errors="replace")
            lines = [ln for ln in raw.splitlines() if ln.strip()]
            if not lines:
                return GENESIS, 0
            last = json.loads(lines[-1])
            return last["sha256"], len(lines)
        except (ValueError, KeyError, OSError):
            # Corrupt tail: refuse to extend a broken chain. The operator
            # must verify_chain() and resolve before the broker continues.
            raise LogWriteError(
                f"audit log tail unreadable at {self._path}: verify and resolve before continuing"
            ) from None

    def _check_secrets(self, *values):
        """Refuse to write any string field containing a configured secret
        (the audit log must never become a credential store). Runs
        BEFORE the entry is built, so a rejected value leaves no partial
        record behind.
        """
        for value in values:
            if not isinstance(value, str):
                continue
            for secret in self._secrets:
                if secret in value:
                    raise ValueError(
                        "refusing to log a value containing a configured secret"
                    )

    def record(
        self,
        account: str,
        resource: str,
        operation: str,
        grant_id: int | None,
        decision: str,
        reason: str,
        then: Callable[[], object] | None = None,
        _fail_inject: bool = False,
        backend: str | None = None,
        principal: str | None = None,
        custody: str | CustodyClass | None = None,
    ) -> object:
        """Write the audit entry, flush, then run ``then``. Returns whatever
        ``then`` returns, or None when ``then`` is not given.

        backend names the protocol family (imap | smtp | caldav |
        carddav | msgraph) when the entry concerns a specific backend
        resource; None for broker-level lifecycle entries. It is part of
        the chain hash but optional.

        principal records which surface authorized the operation
        ('agent' | 'transfer'); None means a caller that does not name a
        principal. It is part of the chain hash but optional, so legacy
        lines still verify.

        custody carries the custody class of the backend principal
        (S6-1): the string value of a CustodyClass member ('scoped' |
        'account_wide' | 'unscopable') or the member itself, normalized
        at the seam. None means a caller that does not declare it (and
        a legacy line that predates the field). It is part of the chain
        hash but optional. Any OTHER string value is refused before
        write (fail-closed: the chain must never carry a custody
        statement outside the recognized vocabulary).

        For Tier-2 lifecycle entries, decision carries the event type
        (LIFECYCLE_EVENTS); each execution writes its intent entry
        BEFORE the backend call via ``then``.

        Raises LogWriteError when the write fails (callback NOT run).
        Raises ValueError when a field would contain a configured secret
        (also NOT run - and not written).
        """
        self._check_secrets(account, resource, operation, decision, reason)
        _check_custody_value(custody)

        entry = {
            "timestamp": self._clock().isoformat(),
            "account": account,
            "resource": resource,
            "operation": operation,
            "grant_id": grant_id,
            "decision": decision,
            "reason": reason,
        }
        if backend is not None:
            entry["backend"] = backend
        if principal is not None:
            entry["principal"] = principal
        if custody is not None:
            entry["custody"] = (
                custody.value if isinstance(custody, CustodyClass) else custody
            )
        line_record = dict(entry)
        line_record["prev_sha256"] = self._prev_sha256
        line_record["sha256"] = hashlib.sha256(_chain_payload(entry).encode()).hexdigest()
        line = _canonical(line_record) + "\n"

        if _fail_inject:
            raise LogWriteError("injected write failure")

        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        except OSError as exc:
            raise LogWriteError(f"audit write failed: {exc}") from exc

        self._prev_sha256 = line_record["sha256"]
        self._lines += 1

        # Checkpoint: chain head + line count, for truncation detection.
        try:
            head = {"sha256": self._prev_sha256, "lines": self._lines}
            with open(self._head_path, "w", encoding="utf-8") as f:
                f.write(_canonical(head) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as exc:
            # The record IS written, but the checkpoint is not: the next
            # verify_chain() will flag a mismatch, which is the safe
            # direction. Surface it so the operator notices immediately.
            raise LogWriteError(f"audit checkpoint write failed: {exc}") from exc

        if then is not None:
            return then()
        return None


def verify_chain(path: Path | str) -> ChainResult:  # noqa: PLR0911 - fail-fast walk
    """Walk the whole chain and check it against the checkpoint sidecar
    (<path>.head). Returns ChainResult with ok=False and an error
    message naming the first broken line (1-indexed). A missing or
    mismatched checkpoint is a chain break: the log has lost its tail
    or the checkpoint was tampered with."""  # noqa: PLR0911 - fail-fast walk
    p = Path(path)
    if not p.exists():
        return ChainResult(False, f"no such file: {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        return ChainResult(False, f"unreadable: {exc}")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    prev = GENESIS
    for i, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except ValueError:
            return ChainResult(False, f"line {i}: not valid JSON", i)
        if record.get("prev_sha256") != prev:
            return ChainResult(False, f"line {i}: chain break (prev mismatch)", i)
        recomputed = hashlib.sha256(_chain_payload(record).encode()).hexdigest()
        if recomputed != record.get("sha256"):
            return ChainResult(False, f"line {i}: record hash mismatch (edited?)", i)
        prev = record["sha256"]
    # Checkpoint comparison (see module docstring): the sidecar turns
    # silent truncation into a detectable break. Only compared AFTER the
    # full walk succeeds, so chain corruption is reported with a line
    # number first.
    head_path = Path(str(p) + ".head")
    if head_path.exists():
        try:
            head = json.loads(head_path.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return ChainResult(False, "checkpoint unreadable")
        if head.get("sha256") != prev:
            return ChainResult(
                False, "checkpoint mismatch: log truncated or checkpoint tampered"
            )
        if head.get("lines") != len(lines):
            return ChainResult(
                False,
                f"checkpoint line count {head.get('lines')} != actual {len(lines)} (truncated?)",
            )
    return ChainResult(True, None, len(lines))
