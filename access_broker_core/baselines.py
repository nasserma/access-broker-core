"""Baseline permissions engine: standing T0/T1 permissions, reassessed.

The design note rev 2 (2026-09-15, findings F-A..F-L applied; see
nextcloudAccessBroker/review/baselinePermissionsDesignNote-2026-09-15.md)
is the specification; this module is its implementation, landed in the
core during Stage 4 because the data broker is its natural consumer
(the December 2026 generalization window's vehicle, pulled forward on
the owner's instruction).

Rulings implemented (design note, verbatim intent):

1. A baseline permission is TEMPORARILY SUSPENDED - not revoked - when
   its reconfirmation request goes unanswered.
2. Config changes to baselines are themselves gated (T2-class).
3. A supervisory AI is an available option, explicitly NOT recommended
   (the principal type is designable but no constructor is provided
   here; nothing in this module resolves approvals on a human's
   behalf).
4. T0/T1 may be baselined; T2/T3 never (the registered operation table
   is the validation set: a definition whose ops carry a GATED
   operation is refused at creation - tier classification wins over
   scope matching, F-C).
5. The reassessment loop is the primary mechanism; baseline
   accumulation is a cost to be managed (the budget report), not a
   feature to be celebrated.

State machine (design note section 3):

    baseline states:  ACTIVE --reconfirm-due--> PENDING_RECONFIRM
                        ^                          | grace elapses
                        | re-approval              v
                        +--------- re-approval -- SUSPENDED
                        +--owner-revokes---------> REVOKED

Findings applied (each maps to a battery section in
tests/test_baselines.py):

- F-A: suspension indefinite by default; the zombie countermeasure is
  the budget report, not a timer. NOTE: no max_suspension mechanism is
  implemented in this version — the design note's optional owner-set
  timer (default OFF) was deliberately not built (an unimplemented
  knob would be worse than none); the budget report is the SOLE zombie
  countermeasure. last_used_at is likewise absent from the schema by
  design: usage lives in the baseline_usage table (F-B's stance).
- F-B: NO usage-based auto-renewal. At interval end the baseline
  converts to a reconfirmation request regardless of usage; usage data
  populates the request so the owner decides informed. The human is
  the only renewal source.
- F-C (normative): tier classification first; T2/T3 always gate; a
  definition carrying a GATED op is invalid, full stop; suspended
  baselines match nothing.
- F-D: definitions live in the grant-store database, never in config;
  creation and modification run exclusively through the gated request
  path with config_change_request_id provenance on every state
  transition.
- F-E: ACTIVE/SUSPENDED/REVOKED are restart-persistent DB states;
  restart never promotes suspended or pending to ACTIVE (restoration
  requires an approval event, which restarts cannot fabricate);
  PENDING_RECONFIRM re-issues idempotently.
- F-F: grant/baseline orthogonality (grants already approved under a
  baseline survive its suspension); restoration pinned to the exact
  definition_hash at suspension time.
- F-G: principal-scoped, never inherited by children/peers/supervisors.
- F-H: PENDING_RECONFIRM -> SUSPENDED after reconfirm_grace (default
  72h), not instantaneously.
- F-I: a suspended baseline falls back to the operation's default tier
  treatment (a suspended baseline matches nothing and the caller's
  normal grant path applies).
- F-J: discovery migration is owner-visible and NOT behavior-neutral;
  it is deliberately NOT implemented here (belongs to the supersession
  rollout).
- F-L: budget report: per-baseline age, last-confirmed, window usage,
  distinct principals, state, against the owner-set standing budget,
  with roll-up and headroom.

Implementation shape (section 4): one SQLite table in the grant
store's database, transitions as conditional SQL, clock injected (no
wall-clock reads). The engine has NO write path to definitions except
the gated request/approval methods; the reassessment cycle reads
definitions and only transitions states per the state machine.

This module never performs I/O beyond the injected store's database
and never reads wall-clock time.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from access_broker_core.grants import GrantStore
from access_broker_core.policy import OperationClass, PolicyRegistry

ACTIVE = "ACTIVE"
PENDING_RECONFIRM = "PENDING_RECONFIRM"
SUSPENDED = "SUSPENDED"
REVOKED = "REVOKED"

#: Default grace: silence after this interval suspends (F-H, default 72h).
DEFAULT_RECONFIRM_GRACE = timedelta(hours=72)

DEFAULT_REASSESS_INTERVAL = timedelta(days=7)

#: Duration strings parse to these; unknown suffixes are refused (fail closed).
_INTERVAL_UNITS = {
    "d": "days",
    "h": "hours",
    "m": "minutes",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    baseline_id INTEGER PRIMARY KEY AUTOINCREMENT,
    definition_hash TEXT NOT NULL,
    definition TEXT NOT NULL,
    state TEXT NOT NULL,
    reassess_interval TEXT NOT NULL,
    reconfirm_grace TEXT NOT NULL,
    last_confirmed_at TEXT NOT NULL,
    suspended_at TEXT,
    config_change_request_id TEXT NOT NULL,
    last_reconfirm_request_id INTEGER
);
CREATE TABLE IF NOT EXISTS baseline_usage (
    baseline_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    principal TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_baseline_usage ON baseline_usage(baseline_id);
"""

_STATES = (ACTIVE, PENDING_RECONFIRM, SUSPENDED, REVOKED)


_MIN_DURATION_LEN = 2  # '<n><unit>': one digit plus one unit character


def _parse_duration(text: Any, where: str) -> timedelta:
    """Parse '<n><d|h|m>' durations; fail closed on anything else."""
    if not isinstance(text, str):
        raise ValueError(f"{where}: must be a string like '7d' or '72h'")
    text = text.strip()
    if len(text) < _MIN_DURATION_LEN:
        raise ValueError(f"{where}: unparseable duration {text!r}")
    unit = text[-1]
    if unit not in _INTERVAL_UNITS:
        raise ValueError(f"{where}: unknown duration unit {unit!r}")
    try:
        amount = int(text[:-1])
    except ValueError:
        raise ValueError(f"{where}: unparseable duration {text!r}") from None
    if amount <= 0:
        raise ValueError(f"{where}: duration must be positive: {text!r}")
    return timedelta(**{_INTERVAL_UNITS[unit]: amount})


def _format_duration(td: timedelta) -> str:
    seconds = int(td.total_seconds())
    if seconds % 86400 == 0:
        return f"{seconds // 86400}d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


def definition_hash(definition: dict[str, Any]) -> str:
    """Deterministic hash over the definition's policy-relevant content."""
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _resource_within(resource: str, base: str) -> bool:
    """Exact component-prefix containment on path-like resources.

    Reuses the suite's covers() rule at the component level:
    'Knowledge' covers 'Knowledge' and 'Knowledge/2026' but never
    'Knowledgeable'. Component boundaries are the only legal prefix
    ends; a longer bare prefix is refused (fail closed).
    """
    if resource == base:
        return True
    return resource.startswith(base + "/")


@dataclass(frozen=True)
class CreateOutcome:
    """The result of a gated creation request (nothing exists yet)."""

    request_id: int
    definition_hash: str


class BaselineError(Exception):
    """Raised for invalid baseline operations (never silent)."""


class BaselineEngine:
    """The baseline-permissions engine over the grant store's database.

    One instance per broker process, constructed at boot with the same
    injected clock as the grant store and audit log. All state lives in
    the store's SQLite database (F-D: definitions DB-only); the engine
    itself holds no mutable state beyond the connection, so reopening
    the database is the restart path.
    """

    def __init__(
        self,
        store: GrantStore,
        clock: Any,
        default_reassess_interval: timedelta = DEFAULT_REASSESS_INTERVAL,
        default_reconfirm_grace: timedelta = DEFAULT_RECONFIRM_GRACE,
    ) -> None:
        self._store = store
        self._clock = clock
        self._default_interval = default_reassess_interval
        self._default_grace = default_reconfirm_grace
        self._db: sqlite3.Connection = store._db  # noqa: SLF001 - one database, one custody
        self._registry: PolicyRegistry = store._registry  # noqa: SLF001
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ---------------------------------------------------------------- gated
    # F-D: these are the ONLY paths that create or modify definitions.

    def create_request(
        self, definition: dict[str, Any], config_change_request_id: str
    ) -> CreateOutcome:
        """Submit a gated creation request (T2-class; F-D).

        Nothing exists until approve_creation() is called: the engine
        has no write path of its own. Raises ValueError for any invalid
        definition (T2 ops refused at creation, F-C; unknown backends
        refused; reassess/grace unparseable refused).
        """
        if not config_change_request_id:
            raise ValueError("config_change_request_id is required (gated mutation, F-D)")
        clean = self._validate_definition(definition)
        h = definition_hash(clean)
        cur = self._db.execute(
            "INSERT INTO baselines (definition_hash, definition, state,"
            " reassess_interval, reconfirm_grace, last_confirmed_at,"
            " config_change_request_id, last_reconfirm_request_id)"
            " VALUES (?,?,?,?,?,?,?,NULL)",
            (
                h,
                json.dumps(clean, sort_keys=True),
                "PENDING_CREATION",
                clean["reassess_interval"],
                clean["reconfirm_grace"],
                _iso(self._clock()),
                config_change_request_id,
            ),
        )
        lastrowid = cur.lastrowid
        assert lastrowid is not None  # INSERT into an AUTOINCREMENT table
        self._db.commit()
        return CreateOutcome(request_id=int(lastrowid), definition_hash=h)

    def approve_creation(self, request_id: int) -> None:
        """The owner yes: PENDING_CREATION -> ACTIVE (the ONLY transition
        that creates a standing definition)."""
        cur = self._db.execute(
            "UPDATE baselines SET state=?, last_confirmed_at=?"
            " WHERE baseline_id=? AND state=?",
            (ACTIVE, _iso(self._clock()), request_id, "PENDING_CREATION"),
        )
        if cur.rowcount != 1:
            raise BaselineError(f"creation request {request_id} not pending")
        self._db.commit()

    def modify_request(
        self, baseline_id: int, new_definition: dict[str, Any], config_change_request_id: str
    ) -> int:
        """Submit a gated mutation request (a change is NOT a restoration)."""
        if not config_change_request_id:
            raise ValueError("config_change_request_id is required (gated mutation, F-D)")
        clean = self._validate_definition(new_definition)
        row = self._row(baseline_id)
        if row is None:
            raise BaselineError(f"unknown baseline {baseline_id}")
        payload = (
            json.dumps(clean, sort_keys=True),
            definition_hash(clean),
            baseline_id,
            ACTIVE,
            SUSPENDED,
        )
        cur = self._db.execute(
            "UPDATE baselines SET definition=?, definition_hash=?"
            " WHERE baseline_id=? AND state IN (?,?)",
            payload,
        )
        if cur.rowcount != 1:
            raise BaselineError(f"baseline {baseline_id} not modifiable in current state")
        self._db.commit()
        return baseline_id

    # ------------------------------------------------------------ usage data

    def record_use(self, baseline_id: int, principal: str) -> None:
        """Record one audited use (populates reconfirmation requests; F-B:
        usage informs, it never renews)."""
        if not principal:
            raise ValueError("principal required")
        self._db.execute(
            "INSERT INTO baseline_usage (baseline_id, timestamp, principal) VALUES (?,?,?)",
            (baseline_id, _iso(self._clock()), principal),
        )
        self._db.commit()

    # ------------------------------------------------------- reassessment

    def reassess(self) -> list[dict[str, Any]]:
        """The reassessment cycle.

        For every ACTIVE baseline past its interval end: convert to a
        reconfirmation request REGARDLESS of usage (F-B), recording the
        window usage stats on the request. The request's logical issue
        time is the interval end, not the moment this cycle notices
        (catch-up semantics: a broker restarted after an outage
        suspends due baselines on its first pass, never late). Then
        every PENDING_RECONFIRM baseline past its grace converts to
        SUSPENDED (F-H). SUSPENDED and REVOKED baselines are untouched
        (F-A: indefinite by default).

        Returns the events produced (new reconfirmation requests).
        """
        now = self._clock()
        events: list[dict[str, Any]] = []
        for row in self._all_rows():
            if row["state"] == ACTIVE:
                interval = _parse_duration(row["reassess_interval"], "reassess_interval")
                due = datetime.fromisoformat(row["last_confirmed_at"]) + interval
                if now >= due:
                    events.append(self._issue_reconfirm(row, due))
        # Second pass on FRESH rows: baselines converted above are now
        # subject to the grace clock in this same pass.
        for row in self._all_rows():
            if row["state"] != PENDING_RECONFIRM:
                continue
            grace = _parse_duration(row["reconfirm_grace"], "reconfirm_grace")
            requested = self._last_reconfirm_at(row)
            if requested is not None and now >= requested + grace:
                self._db.execute(
                    "UPDATE baselines SET state=?, suspended_at=? WHERE baseline_id=?",
                    (SUSPENDED, _iso(now), row["baseline_id"]),
                )
        self._db.commit()
        return events

    def _issue_reconfirm(self, row: sqlite3.Row, due: datetime) -> dict[str, Any]:
        """Create one reconfirmation request carrying the window usage
        stats (F-B: the owner decides informed).

        The request timestamp is written as a '_reconfirm' usage mark
        at the LOGICAL issue time (the interval end, `due`): that row
        is what starts the grace clock (F-H), so a restart re-derives
        it identically from the database (F-E).
        """
        since = datetime.fromisoformat(row["last_confirmed_at"])
        usage = [
            u
            for u in self._usage(row["baseline_id"])
            if datetime.fromisoformat(u["timestamp"]) >= since
            and u["principal"] != "_reconfirm"
        ]
        principals = sorted({u["principal"] for u in usage})
        event = {
            "baseline_id": row["baseline_id"],
            "usage_count": len(usage),
            "distinct_principals": principals,
            "reconfirm_request_id": row["baseline_id"],
        }
        self._db.execute(
            "INSERT INTO baseline_usage (baseline_id, timestamp, principal)"
            " VALUES (?,?,?)",
            (row["baseline_id"], _iso(due), "_reconfirm"),
        )
        self._db.execute(
            "UPDATE baselines SET state=?, last_reconfirm_request_id=?"
            " WHERE baseline_id=? AND state=?",
            (PENDING_RECONFIRM, row["baseline_id"], row["baseline_id"], ACTIVE),
        )
        return event

    # -------------------------------------------------------- restoration

    def approve_restoration(self, baseline_id: int, definition_hash_hex: str) -> None:
        """Re-approval restores the EXACT definition identified by
        definition_hash (F-F). A mismatch is refused: a changed
        definition is a new gated mutation, never a restoration."""
        row = self._row(baseline_id)
        if row is None:
            raise BaselineError(f"unknown baseline {baseline_id}")
        if row["definition_hash"] != definition_hash_hex:
            raise ValueError(
                "restoration hash mismatch: a changed definition is a"
                " new gated mutation, not a restoration"
            )
        cur = self._db.execute(
            "UPDATE baselines SET state=?, last_confirmed_at=?, suspended_at=NULL"
            " WHERE baseline_id=? AND state IN (?,?)",
            (ACTIVE, _iso(self._clock()), baseline_id, PENDING_RECONFIRM, SUSPENDED),
        )
        if cur.rowcount != 1:
            raise BaselineError(f"baseline {baseline_id} not restorable from {row['state']}")
        self._db.commit()

    def revoke(self, baseline_id: int) -> bool:
        """The owner kill switch, from any state."""
        cur = self._db.execute(
            "UPDATE baselines SET state=? WHERE baseline_id=? AND state IN (?,?,?)",
            (REVOKED, baseline_id, ACTIVE, PENDING_RECONFIRM, SUSPENDED),
        )
        if cur.rowcount:
            self._db.commit()
        return bool(cur.rowcount)

    # ------------------------------------------------------------ matching

    def baseline_for(
        self, principal: str, backend: str, account: str, resource: str, op: str
    ) -> dict[str, Any] | None:
        """The ACTIVE baseline of this principal covering the operation.

        F-C normative order: tier classification FIRST. The operation's
        tier is decided by the registered operation table; a GATED
        (T2/T3) operation never matches any baseline. Suspended
        baselines match nothing. Principal scoping is exact (F-G).
        """
        op_class = self._registry.classify(op)
        if op_class is not OperationClass.READ:
            return None  # T2/T3 always gate; baseline never matches
        if not backend or not account or not resource or not principal:
            return None
        for row in self._all_rows():
            if row["state"] != ACTIVE:
                continue
            definition = json.loads(row["definition"])
            if definition.get("principal") != principal:
                continue
            if definition.get("backend") != backend:
                continue
            if definition.get("account") != account:
                continue
            base = definition.get("resource") or ""
            if base and not _resource_within(resource, base):
                continue  # exact component-prefix containment (covers())
            if op in (definition.get("ops") or []):
                return {
                    "baseline_id": row["baseline_id"],
                    "definition_hash": row["definition_hash"],
                }
        return None

    # ------------------------------------------------------------- reading

    def list_definitions(self) -> list[dict[str, Any]]:
        """Every definition row (DB is the source of truth).

        PENDING_CREATION rows are excluded: a definition exists only
        once the owner has approved it (F-D: the gated request path
        creates nothing until the human yes).
        """
        cur = self._db.execute(
            "SELECT * FROM baselines WHERE state != 'PENDING_CREATION'"
            " ORDER BY baseline_id"
        )
        return [dict(row) for row in cur.fetchall()]

    def get_definition(self, baseline_id: int) -> dict[str, Any] | None:
        row = self._row(baseline_id)
        return dict(row) if row is not None else None

    def budget_report(self, standing_budget: int) -> dict[str, Any]:
        """F-L: per-baseline age, last-confirmed, window usage, distinct
        principals, state, against the standing budget; roll-up with
        headroom.

        Only standing definitions are listed: REVOKED rows are skipped
        (dead) and PENDING_CREATION rows are skipped (an unapproved
        request is not a standing permission and must not consume
        budget).
        """
        entries = []
        active = suspended = 0
        for row in self._all_rows():
            if row["state"] in (REVOKED, "PENDING_CREATION"):
                continue
            since = datetime.fromisoformat(row["last_confirmed_at"])
            usage = [
                u
                for u in self._usage(row["baseline_id"])
                if datetime.fromisoformat(u["timestamp"]) >= since
            ]
            principals = sorted({u["principal"] for u in usage})
            state = row["state"]
            if state == ACTIVE:
                active += 1
            elif state == SUSPENDED:
                suspended += 1
            entries.append(
                {
                    "baseline_id": row["baseline_id"],
                    "state": state,
                    "age_days": (self._clock() - since).days,
                    "last_confirmed_at": row["last_confirmed_at"],
                    "window_usage": len(usage),
                    "distinct_principals": principals,
                }
            )
        return {
            "baselines": entries,
            "active_count": active,
            "suspended_count": suspended,
            "standing_budget": standing_budget,
            # Every listed baseline consumes budget, whatever its
            # mid-cycle state (a PENDING_RECONFIRM baseline is still
            # standing - the report's discouragement counts it).
            "budget_headroom": standing_budget - len(entries),
        }

    # -------------------------------------------------------------- private

    def _validate_definition(self, definition: dict[str, Any]) -> dict[str, Any]:
        """Creation-time validation (tier-first, F-C): T2/T3 ops refused;
        the registered operation table is the validation set."""
        if not isinstance(definition, dict):
            raise ValueError("definition must be a mapping")
        backend = definition.get("backend")
        if backend not in self._registry.backends:
            raise ValueError(f"invalid backend: {backend!r}")
        for key in ("account", "resource", "principal"):
            if not isinstance(definition.get(key), str) or not definition.get(key):
                raise ValueError(f"definition.{key} must be a nonempty string")
        ops = definition.get("ops")
        if not isinstance(ops, (list, tuple)) or not ops:
            raise ValueError("definition.ops must be a nonempty list")
        if not all(isinstance(op, str) and op in self._registry.operation_class for op in ops):
            raise ValueError(f"ops must be declared operations: {ops!r}")
        if any(self._registry.classify(op) is not OperationClass.READ for op in ops):
            raise ValueError("T2/T3 operations are never baselinable (ruling 4, F-C)")
        interval = definition.get("reassess_interval", "7d")
        _parse_duration(interval, "reassess_interval")
        grace = definition.get("reconfirm_grace", "72h")
        _parse_duration(grace, "reconfirm_grace")
        return {
            "backend": definition["backend"],
            "account": definition["account"],
            "resource": definition["resource"],
            "ops": sorted(set(ops)),
            "principal": definition["principal"],
            "reassess_interval": interval,
            "reconfirm_grace": definition.get("reconfirm_grace", "72h"),
        }

    def _row(self, baseline_id: int) -> sqlite3.Row | None:
        cur = self._db.execute(
            "SELECT * FROM baselines WHERE baseline_id=?", (baseline_id,)
        )
        return cur.fetchone()

    def _all_rows(self) -> list[sqlite3.Row]:
        cur = self._db.execute("SELECT * FROM baselines ORDER BY baseline_id")
        return cur.fetchall()

    def _usage(self, baseline_id: int) -> list[dict[str, Any]]:
        cur = self._db.execute(
            "SELECT * FROM baseline_usage WHERE baseline_id=? ORDER BY timestamp",
            (baseline_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    def _last_reconfirm_at(self, row: sqlite3.Row) -> datetime | None:
        """When the last reconfirmation request was issued.

        The usage table records the request timestamp (the reassess()
        entry writes a usage row with principal='_reconfirm'); fall back
        to the last usage row, then to the interval end.
        """
        rows = self._usage(row["baseline_id"])
        marks = [r for r in rows if r["principal"] == "_reconfirm"]
        if marks:
            return datetime.fromisoformat(marks[-1]["timestamp"])
        return None


def _iso(dt: datetime) -> str:
    return dt.isoformat()
