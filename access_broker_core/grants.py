"""Grants: the Tier 2 grant state machine (generalized from nextcloud-access-broker).

State machine (D5 item schema, conditional-SQL transitions from day one):

    pending --approve--> active --expiry--> expired
    pending --reject----> rejected        active --revoke--> revoked
    pending --12h silence--> expired      pending --revoke--> rejected
    pending --restart--> rejected (restart_discard)

Rules ported verbatim in behavior from the same author's
nextcloud-access-broker broker/grants.py (GPL-3.0-or-later):

- Request numbers are one-time and monotonic; a decided number never
  changes state again except the single expiry/revocation transition
  from active.
- Active grants persist across restart; pending requests are discarded
  at open (state rejected, state_source='restart_discard'): a stale
  pending request grants nothing and is worthless after a restart.
- No auto-renewal: expiry timestamps are written once at approval and
  never touched again.
- The clock is injected; nothing in this module reads wall-clock time.
- GrantRecord is frozen; items are deep-copied out so callers cannot
  mutate the stored authorization payload through a returned record.
- Effective-state-on-read: a pending row past the pending timeout and an
  active row past its expires_at both read as expired, with a
  synthesized state_source ('pending_timeout' / 'grant_expiry') so audit
  trails always name why a grant died.

Rework per the groupware-access-broker goal contract (D5; the project was
formerly named pimAccessBroker) and S2 design note:

- Item schema {backend, account, resource, ops, expires_at} replaces
  {path, mode}. The store does NOT interpret resource semantics: it
  validates structure (backend in the allowed set via the registered PolicyRegistry,
  ops a nonempty subset of the known operation table, account/resource
  nonempty, expires_at parseable ISO-8601) and delegates all matching
  semantics (resource normalization, scope containment, write-implies-
  read) to the policy wall in active_for().
- Every transition is a compare-and-set UPDATE ... WHERE state=expected,
  so double-decision of one request number is impossible even under
  concurrent callers (the rowcount of the guarded UPDATE is the arbiter).
- Approval decisions arrive as (request_number, decision, optional
  duration override); duration overrides arrive as normalized timedeltas
  (the 'approve 47 8h' grammar lives in the gateway, not here).
- An item-level expires_at, when present, caps the approval expiry: the
  effective expiry is min(now + duration, item expiries).
- SQLite WAL journal mode + busy_timeout (5s). Single connection owned
  by the event loop in v1 (single-process architecture), but the
  transitions stay CAS-safe regardless.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import copy
import enum
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from access_broker_core import policy as _policy
from access_broker_core.policy import GrantItem, PolicyRegistry, Request

PENDING = "pending"
ACTIVE = "active"
EXPIRED = "expired"
REVOKED = "revoked"
REJECTED = "rejected"

DEFAULT_PENDING_TIMEOUT = timedelta(hours=12)
DEFAULT_ACTIVE_TTL = timedelta(hours=24)

_ZERO = timedelta(0)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    request_number INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id_hint TEXT NOT NULL,
    justification TEXT NOT NULL,
    items TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    expires_at TEXT,
    state TEXT NOT NULL,
    state_source TEXT
);
"""


class RequestState(enum.Enum):
    """Effective state of one request number (time transitions applied)."""

    PENDING = PENDING
    ACTIVE = ACTIVE
    EXPIRED = EXPIRED
    REVOKED = REVOKED
    REJECTED = REJECTED
    UNKNOWN = "unknown"


class RejectReason(enum.Enum):
    """Why an approve() call did not produce a GrantRecord (never silent)."""

    UNKNOWN_REQUEST = "unknown_request"
    ALREADY_DECIDED = "already_decided"


@dataclass(frozen=True)
class GrantRecord:
    """Immutable view of one grant row for callers outside this module.

    state is the EFFECTIVE state (time-based transitions applied on read),
    not the raw stored state. items is deep-copied so callers cannot
    mutate the store's authorization payload through a returned record.
    """

    request_number: int
    request_id_hint: str
    justification: str
    items: list[dict[str, Any]]
    state: str
    created_at: datetime
    decided_at: datetime | None
    expires_at: datetime | None
    state_source: str | None


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _validate_item(item: Any, registry: PolicyRegistry) -> dict[str, Any]:
    """Validate one D5 grant item; return the cleaned, normalized copy.

    Store-level validation only (S2 design note section 2): backend in the
    allowed set, ops a nonempty subset of the known operation table,
    account/resource nonempty, expires_at parseable ISO-8601. Resource
    semantics are NOT interpreted here - the policy wall owns that.
    Raises ValueError on anything else.
    """
    if not isinstance(item, dict):
        raise ValueError(f"item must be a dict: {item!r}")
    backend = item.get("backend")
    if not isinstance(backend, str) or backend not in registry.backends:
        raise ValueError(f"invalid backend: {backend!r}")
    account = item.get("account")
    if not isinstance(account, str) or not account:
        raise ValueError(f"invalid account: {account!r}")
    resource = item.get("resource")
    if not isinstance(resource, str) or not resource:
        raise ValueError(f"invalid resource: {resource!r}")
    ops = item.get("ops")
    if not isinstance(ops, (list, tuple, set, frozenset)) or not ops:
        raise ValueError(f"ops must be a nonempty sequence: {ops!r}")
    if not all(isinstance(op, str) and op in registry.operation_class for op in ops):
        raise ValueError(f"ops must be known operations: {ops!r}")
    raw_expires = item.get("expires_at")
    if raw_expires is None:
        expires_iso = None
    elif isinstance(raw_expires, datetime):
        expires_iso = _iso(raw_expires)
    elif isinstance(raw_expires, str):
        try:
            expires_iso = _iso(datetime.fromisoformat(raw_expires))
        except ValueError as exc:
            raise ValueError(f"unparseable expires_at: {raw_expires!r}") from exc
    else:
        raise ValueError(f"expires_at must be ISO-8601 str or datetime: {raw_expires!r}")
    return {
        "backend": backend,
        "account": account,
        "resource": resource,
        "ops": sorted(set(ops)),
        "expires_at": expires_iso,
        # Display-only human label (e.g. Matrix room name); the policy
        # wall never reads it and matching is by `resource` alone.
        **(
            {"label": item["label"]}
            if isinstance(item.get("label"), str) and item["label"]
            else {}
        ),
    }


class GrantStore:
    """SQLite-backed grant lifecycle store.

    Open one per process; reopening the same file is the restart path
    (pending -> rejected on open). The clock is injected and shared with
    policy.py per the configuration; no wall-clock reads happen here.
    """

    def __init__(
        self,
        db_path: str,
        clock: Callable[[], datetime],
        registry: PolicyRegistry,
        pending_timeout: timedelta = DEFAULT_PENDING_TIMEOUT,
        active_ttl: timedelta = DEFAULT_ACTIVE_TTL,
    ) -> None:
        """Open (creating if needed) the grant database and apply the
        restart-discard rule.

        registry: the broker's PolicyRegistry (operation table, backend
        set, normalizer). The store validates items and judges scope
        through it - the store never duplicates wall semantics.

        MUST be constructed before the transport starts serving requests:
        the restart-discard pass on open is what guarantees a stale pending
        request from a previous process lifetime can never be approved.
        """
        self._clock = clock
        self._registry = registry
        self._pending_timeout = pending_timeout
        self._active_ttl = active_ttl
        # check_same_thread=False: the connection is owned by the event loop
        # in production (single-process architecture), but the CAS guard and
        # SQLite's serialized mode keep transitions safe even if tooling
        # drives the store from another thread (tests exercise this).
        db_parent = Path(db_path).resolve().parent
        if not db_parent.is_dir():
            raise ValueError(
                f"grants_db parent directory does not exist: {db_parent} "
                f"(create it before boot, or set storage.data_dir to an "
                f"existing directory)"
            )
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        # WAL: allows a reader (inspection tooling) while the server loop
        # holds its connection. The right mode for a long-running process.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)
        self._db.commit()
        self._discard_pending_at_open()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._db.close()

    # ------------------------------------------------------------ restart rule

    def _discard_pending_at_open(self) -> None:
        """Restart-discard rule: pending requests never survive a restart.

        Called ONLY from __init__, before anything else can observe the
        store. A pending request that outlived its process is stale: the
        gateway message may already have been reacted to, duplicated, or
        lost, so human intent can no longer be established - every such
        row is moved to rejected with state_source='restart_discard'.
        Rows older than the pending timeout would already read as expired
        via the effective-state-on-read rule, so discarding all pending
        rows subsumes the 'older than pending TTL' case.
        """
        cur = self._db.execute(
            "UPDATE grants SET state=?, state_source=? WHERE state=?",
            (REJECTED, "restart_discard", PENDING),
        )
        if cur.rowcount:
            self._db.commit()

    # ------------------------------------------------------------- transitions

    def submit(self, request_id_hint: str, items: Any, justification: str) -> int:
        """Record a new pending request; returns its one-time request number.

        This grants NOTHING - only approve() can create an active grant.
        request_id_hint: opaque gateway correlation hint (e.g. the posted
        message id), stored for audit. items: nonempty sequence of D5
        items; justification: nonempty human explanation shown to the
        approver. Raises ValueError on any invalid input.
        """
        if not isinstance(justification, str) or not justification.strip():
            raise ValueError("justification must be a non-empty string")
        if not isinstance(items, (list, tuple)) or not items:
            raise ValueError("items must be a non-empty sequence")
        clean_items = [_validate_item(item, self._registry) for item in items]
        cur = self._db.execute(
            "INSERT INTO grants (request_id_hint, justification, items,"
            " created_at, state, state_source) VALUES (?,?,?,?,?,NULL)",
            (
                str(request_id_hint),
                justification.strip(),
                json.dumps(clean_items),
                _iso(self._clock()),
                PENDING,
            ),
        )
        lastrowid = cur.lastrowid
        assert lastrowid is not None  # INSERT into an AUTOINCREMENT table
        self._db.commit()
        return int(lastrowid)

    def approve(
        self, request_number: int, duration: timedelta | None = None
    ) -> GrantRecord | RejectReason:
        """The human yes: pending -> active, the ONLY transition that can
        create an active grant.

        duration: normalized duration override (the gateway parses the
        '8h'-style grammar) or None for the default active TTL. The expiry
        timestamp is computed once here and written immediately - no
        auto-renewal ever touches it again. Item-level expires_at values
        cap the computed expiry. Returns RejectReason instead of raising
        for unknown request numbers and already-decided (or
        effectively-expired) requests: silence never approves.
        Raises ValueError for a malformed duration override.
        """
        if duration is not None and (not isinstance(duration, timedelta) or duration <= _ZERO):
            raise ValueError(f"invalid duration override: {duration!r}")
        row = self._row(request_number)
        if row is None:
            return RejectReason.UNKNOWN_REQUEST
        if self._effective_state(row) != PENDING:
            return RejectReason.ALREADY_DECIDED
        now = self._clock()
        base = now + (duration if duration is not None else self._active_ttl)
        expiry = self._capped_expiry(base, json.loads(row["items"]))
        # Compare-and-set: the WHERE guard is the arbiter. If a concurrent
        # caller decided this request between our read and this UPDATE,
        # rowcount is 0 and we report ALREADY_DECIDED instead of double-
        # approving a one-time request number.
        cur = self._db.execute(
            "UPDATE grants SET state=?, decided_at=?, expires_at=?, state_source=?"
            " WHERE request_number=? AND state=?",
            (ACTIVE, _iso(now), _iso(expiry), "approval", request_number, PENDING),
        )
        if cur.rowcount != 1:
            return RejectReason.ALREADY_DECIDED
        self._db.commit()
        return self.get_record(request_number)

    def _capped_expiry(self, base: datetime, items: list[dict[str, Any]]) -> datetime:
        """Fold item-level expires_at caps into the approval expiry."""
        for item in items:
            raw = item.get("expires_at")
            if raw is None:
                continue
            cap = datetime.fromisoformat(raw)
            try:
                base = min(base, cap)
            except TypeError:
                # Incomparable (naive vs aware): the policy wall fails
                # closed on incomparable expiry at check time; the cap is
                # best-effort here, so skip it.
                continue
        return base

    def reject(self, request_number: int) -> bool:
        """The human no: pending -> rejected (state_source='rejection').

        Returns False when the request number is unknown or already
        decided: a decided number can never be re-decided.
        """
        cur = self._db.execute(
            "UPDATE grants SET state=?, decided_at=?, state_source=?"
            " WHERE request_number=? AND state=?",
            (REJECTED, _iso(self._clock()), "rejection", request_number, PENDING),
        )
        if cur.rowcount:
            self._db.commit()
        return bool(cur.rowcount)

    def revoke(self, request_number: int) -> bool:
        """Withdraw a grant early, at any point before its natural end.

        active -> revoked (state_source='revocation') and
        pending -> rejected (state_source='pending_revoke'). Unlike
        approve/reject this does not require the pending state: revoking a
        live grant is the operator kill switch and must always work.
        Effective state is honored: an already-expired grant is dead and
        revoking it is a no-op (False). Returns False for unknown or
        otherwise-terminal numbers. The CAS WHERE guard still arbitrates
        concurrent revocations of the same number.
        """
        row = self._row(request_number)
        if row is None:
            return False
        effective = self._effective_state(row)
        if effective == ACTIVE:
            cur = self._db.execute(
                "UPDATE grants SET state=?, state_source=?"
                " WHERE request_number=? AND state=?",
                (REVOKED, "revocation", request_number, ACTIVE),
            )
        elif effective == PENDING:
            cur = self._db.execute(
                "UPDATE grants SET state=?, decided_at=?, state_source=?"
                " WHERE request_number=? AND state=?",
                (REJECTED, _iso(self._clock()), "pending_revoke", request_number, PENDING),
            )
        else:
            return False
        if cur.rowcount:
            self._db.commit()
        return bool(cur.rowcount)

    def revoke_all(self) -> int:
        """Operator kill switch for every effective-ACTIVE grant at once.

        Returns the number of grants transitioned active -> revoked.
        Effectively-expired rows stored as active are skipped (they are
        dead already); pending requests are untouched (use reject()).
        """
        cur = self._db.execute(
            "SELECT * FROM grants WHERE state=? ORDER BY request_number", (ACTIVE,)
        )
        count = 0
        for row in cur.fetchall():
            if self._effective_state(row) != ACTIVE:
                continue
            upd = self._db.execute(
                "UPDATE grants SET state=?, state_source=?"
                " WHERE request_number=? AND state=?",
                (REVOKED, "revocation", row["request_number"], ACTIVE),
            )
            count += upd.rowcount
        if count:
            self._db.commit()
        return count

    # ---------------------------------------------------------------- reading

    def _row(self, request_number: int) -> sqlite3.Row | None:
        cur = self._db.execute(
            "SELECT * FROM grants WHERE request_number=?", (request_number,)
        )
        return cur.fetchone()

    def _effective_state(self, row: sqlite3.Row) -> str:
        """Effective state: applies time-based transitions on read.

        Pending rows expire after pending_timeout; active rows expire at
        expires_at. Nothing is written here - expiry is a read-time view,
        so an expired grant is denied even though the stored state column
        still says pending/active.
        """
        state = row["state"]
        if state == PENDING:
            if self._clock() - datetime.fromisoformat(row["created_at"]) >= (
                self._pending_timeout
            ):
                return EXPIRED
            return PENDING
        if state == ACTIVE:
            if self._clock() >= datetime.fromisoformat(row["expires_at"]):
                return EXPIRED
            return ACTIVE
        return state

    def _record(self, row: sqlite3.Row) -> GrantRecord:
        """Load one row as an effective-state GrantRecord.

        When the effective state is expired but the stored state is not,
        the state_source is synthesized ('pending_timeout' or
        'grant_expiry') so audit trails always name why a grant died.
        """
        effective = self._effective_state(row)
        source = row["state_source"]
        if effective == EXPIRED and row["state"] == PENDING:
            source = "pending_timeout"
        elif effective == EXPIRED and row["state"] == ACTIVE:
            source = "grant_expiry"
        return GrantRecord(
            request_number=row["request_number"],
            request_id_hint=row["request_id_hint"],
            justification=row["justification"],
            items=copy.deepcopy(json.loads(row["items"])),
            state=effective,
            created_at=datetime.fromisoformat(row["created_at"]),
            decided_at=(
                datetime.fromisoformat(row["decided_at"]) if row["decided_at"] else None
            ),
            expires_at=(
                datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
            ),
            state_source=source,
        )

    def get(self, request_number: int) -> RequestState:
        """Effective state of one request number (UNKNOWN if never seen)."""
        row = self._row(request_number)
        if row is None:
            return RequestState.UNKNOWN
        return RequestState(self._effective_state(row))

    def get_record(self, request_number: int) -> GrantRecord:
        """Fetch one grant by request number, effective state applied.

        Raises LookupError for unknown request numbers (never returns
        None); the gateway distinguishes 'unknown request' from
        'already decided' via approve()'s RejectReason instead.
        """
        row = self._row(request_number)
        if row is None:
            raise LookupError(f"no grant with request number {request_number}")
        return self._record(row)

    def all_records(self) -> list[GrantRecord]:
        """Every grant row as an effective-state GrantRecord, ordered by
        request number (the store is the source of truth; the gateway
        renders from this)."""
        cur = self._db.execute(
            "SELECT * FROM grants ORDER BY request_number"
        )
        return [self._record(row) for row in cur.fetchall()]

    def active_for(self, backend: str, account: str, resource: str, op: str) -> list[GrantRecord]:
        """All grants that authorize (backend, account, resource, op) right now.

        Every candidate is re-checked for effective state (a grant that
        expired between the SQL query and this read is dropped) and then
        judged by the policy wall - the store never duplicates scope
        semantics, so normalization, folder recursion, and
        write-implies-read behave exactly as check() defines them.
        """
        cur = self._db.execute(
            "SELECT * FROM grants WHERE state=? ORDER BY request_number", (ACTIVE,)
        )
        out: list[GrantRecord] = []
        for row in cur.fetchall():
            if self._effective_state(row) != ACTIVE:
                continue
            record = self._record(row)
            if self._authorizes(record, backend, account, resource, op):
                out.append(record)
        return out

    def _authorizes(
        self, record: GrantRecord, backend: str, account: str, resource: str, op: str
    ) -> bool:
        """One grant authorizes the request if ANY of its items does."""
        request = Request(backend=backend, account=account, resource=resource, op=op)
        for item in record.items:
            grant_item = GrantItem(
                backend=item["backend"],
                account=item["account"],
                resource=item["resource"],
                ops=item["ops"],
                expires_at=record.expires_at,
            )
            if _policy.check(self._registry, grant_item, request, self._clock).allowed:
                return True
        return False
