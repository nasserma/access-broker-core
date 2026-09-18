"""Exhaustive test battery for the grant store (groupware_broker.grants).

Ported semantic coverage from the same author's nextcloud-access-broker
tests/test_grants.py (GPL-3.0-or-later), adapted to the D5 item schema:

- States: pending -> active -> (expired | revoked | rejected).
- Pending requests die at 12h silence (configurable); silence grants nothing.
- Active grants default to 24h; per-approval duration override arrives as a
  normalized timedelta.
- No auto-renewal, ever.
- Grants survive process restart (SQLite); pending requests are DISCARDED
  on open (a stale pending request is worthless).
- Request numbers are one-time: CAS transitions make double-decision
  impossible, including under concurrent callers (asyncio.gather, exactly
  one approve() succeeds).
- Revocation is immediate and recorded; revoke_all is the operator kill
  switch.
- active_for() delegates ALL matching semantics to the policy wall.
- The clock is injected everywhere; no test depends on real time passing.

Contract under test (goal contract D5 + S2 design note):

    GrantStore(db_path, clock, pending_timeout=12h, active_ttl=24h)
    submit(request_id_hint, items, justification) -> request_number
    approve(request_number, duration=None) -> GrantRecord | RejectReason
    reject(request_number) -> bool
    revoke(request_number) -> bool
    revoke_all() -> int
    active_for(backend, account, resource, op) -> list[GrantRecord]
    get(request_number) -> RequestState
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from access_broker_core.grants import (
    ACTIVE,
    DEFAULT_ACTIVE_TTL,
    DEFAULT_PENDING_TIMEOUT,
    EXPIRED,
    PENDING,
    REJECTED,
    REVOKED,
    GrantRecord,
    GrantStore,
    RejectReason,
    RequestState,
)

T0 = datetime(2026, 9, 13, 12, 0, 0)  # injected clock, never real time

# --- S1 seam: the store judges through a PolicyRegistry; this battery uses
# the groupware semantics (same tables the groupware broker registers at
# boot) so the ported battery runs verbatim against the seam.
_STORE_REGISTRY = None


def _store_registry():
    global _STORE_REGISTRY
    if _STORE_REGISTRY is None:
        import sys

        sys.path.insert(
            0, "HOME/GW"
        )
        from groupware_broker.policy import normalize_resource as gw_normalize

        from access_broker_core import policy as _cp

        _read = {"list", "read", "search", "free_busy", "attachment_fetch", "folder_tree", "availability"}
        _gated = {"send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"}
        table = dict.fromkeys(sorted(_read), _cp.OperationClass.READ) | dict.fromkeys(sorted(_gated), _cp.OperationClass.GATED)
        _STORE_REGISTRY = _cp.PolicyRegistry(
            operation_class=table,
            backends=frozenset({"imap", "smtp", "caldav", "carddav", "msgraph"}),
            normalize_resource=gw_normalize,
        )
    return _STORE_REGISTRY


ITEM = {
    "backend": "imap",
    "account": "personal",
    "resource": "Work",
    "ops": ["send"],
}


def make_store(tmp_path: Path, **kwargs: Any) -> GrantStore:
    return GrantStore(db_path=tmp_path / "grants.sqlite3", clock=lambda: T0, registry=_store_registry(), **kwargs)


def item(**overrides: Any) -> dict[str, Any]:
    merged = dict(ITEM)
    merged.update(overrides)
    return merged


def submit(store: GrantStore, **item_overrides: Any) -> int:
    return store.submit("hint-1", [item(**item_overrides)], "justification")


# --------------------------------------------------------------- lifecycle


def test_submit_creates_pending_request(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit("evt-42", [item()], "send the CHT paper")
    assert req == 1
    assert store.get(req) is RequestState.PENDING
    record = store.get_record(req)
    assert record.state == PENDING
    assert record.request_id_hint == "evt-42"
    assert record.justification == "send the CHT paper"
    assert record.items == [
        {**ITEM, "expires_at": None}
    ]  # stored items are normalized copies (expires_at -> ISO or None)


def test_request_numbers_monotonic_never_reused(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    r1 = store.submit("h", [item()], "j")
    store.reject(r1)
    r2 = store.submit("h", [item()], "j")
    assert r2 == r1 + 1


def test_approve_activates_with_default_ttl(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    outcome = store.approve(req)
    assert isinstance(outcome, GrantRecord)
    assert outcome.state == ACTIVE
    assert outcome.state_source == "approval"
    assert outcome.decided_at == T0
    assert outcome.expires_at == T0 + DEFAULT_ACTIVE_TTL
    assert store.get(req) is RequestState.ACTIVE


def test_approve_with_duration_override(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    outcome = store.approve(req, timedelta(hours=8))
    assert isinstance(outcome, GrantRecord)
    assert outcome.expires_at == T0 + timedelta(hours=8)


def test_reject(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    assert store.reject(req) is True
    assert store.get(req) is RequestState.REJECTED
    assert store.get_record(req).state_source == "rejection"
    assert store.get_record(req).decided_at == T0


def test_reject_twice_second_is_false(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    assert store.reject(req) is True
    assert store.reject(req) is False


def test_reject_unknown_request_false(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.reject(4242) is False


def test_approve_unknown_request_returns_reject_reason(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.approve(31337) is RejectReason.UNKNOWN_REQUEST


def test_decided_number_never_reusable(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    assert isinstance(store.approve(req), GrantRecord)
    assert store.approve(req) is RejectReason.ALREADY_DECIDED


def test_rejected_number_never_approvable(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    assert store.reject(req) is True
    assert store.approve(req) is RejectReason.ALREADY_DECIDED


def test_silence_never_approves_pending_expires_after_12h(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store._clock = lambda: T0 + timedelta(hours=11, minutes=59)
    assert store.get(req) is RequestState.PENDING
    store._clock = lambda: T0 + timedelta(hours=12)
    assert store.get(req) is RequestState.EXPIRED
    record = store.get_record(req)
    assert record.state == EXPIRED
    assert record.state_source == "pending_timeout"
    # Approving after the silence: decided, refused.
    assert store.approve(req) is RejectReason.ALREADY_DECIDED


def test_pending_timeout_configurable(tmp_path: Path) -> None:
    store = make_store(tmp_path, pending_timeout=timedelta(hours=1))
    req = submit(store)
    store._clock = lambda: T0 + timedelta(minutes=61)
    assert store.get(req) is RequestState.EXPIRED
    assert timedelta(hours=12) == DEFAULT_PENDING_TIMEOUT


def test_active_ttl_configurable(tmp_path: Path) -> None:
    store = make_store(tmp_path, active_ttl=timedelta(hours=2))
    req = submit(store)
    outcome = store.approve(req)
    assert isinstance(outcome, GrantRecord)
    assert outcome.expires_at == T0 + timedelta(hours=2)


# ------------------------------------------------------- item expires_at cap


def test_item_expires_at_caps_approval_expiry(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit(
        "h", [item(expires_at=(T0 + timedelta(hours=3)).isoformat())], "j"
    )
    outcome = store.approve(req)  # default 24h, item caps at 3h
    assert isinstance(outcome, GrantRecord)
    assert outcome.expires_at == T0 + timedelta(hours=3)


def test_item_expires_at_later_than_ttl_does_not_extend(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit(
        "h", [item(expires_at=(T0 + timedelta(days=30)).isoformat())], "j"
    )
    outcome = store.approve(req)
    assert isinstance(outcome, GrantRecord)
    assert outcome.expires_at == T0 + DEFAULT_ACTIVE_TTL


def test_item_expires_at_datetime_object_accepted(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit("h", [item(expires_at=T0 + timedelta(hours=5))], "j")
    outcome = store.approve(req)
    assert isinstance(outcome, GrantRecord)
    assert outcome.expires_at == T0 + timedelta(hours=5)


def test_items_without_expires_at_use_full_ttl(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit("h", [item(), item(backend="caldav", resource="Cal", ops=["create"])], "j")
    outcome = store.approve(req)
    assert isinstance(outcome, GrantRecord)
    assert outcome.expires_at == T0 + DEFAULT_ACTIVE_TTL


# ------------------------------------------------------------------- expiry


def test_active_grant_expires_at_its_expiry_time(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store.approve(req, timedelta(hours=2))
    store._clock = lambda: T0 + timedelta(hours=1, minutes=59)
    assert store.get(req) is RequestState.ACTIVE
    store._clock = lambda: T0 + timedelta(hours=2)
    assert store.get(req) is RequestState.EXPIRED
    assert store.get_record(req).state_source == "grant_expiry"


def test_no_auto_renewal_expired_stays_expired(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store.approve(req, timedelta(hours=1))
    store._clock = lambda: T0 + timedelta(hours=5)
    record = store.get_record(req)
    assert record.state == EXPIRED
    assert record.expires_at == T0 + timedelta(hours=1)  # unchanged


# ------------------------------------------------------------------ revoke


def test_revoke_active_grant(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store.approve(req)
    assert store.revoke(req) is True
    record = store.get_record(req)
    assert record.state == REVOKED
    assert record.state_source == "revocation"
    assert store.revoke(req) is False  # terminal


def test_revoke_pending_request_rejects_it(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    assert store.revoke(req) is True
    record = store.get_record(req)
    assert record.state == REJECTED
    assert record.state_source == "pending_revoke"


def test_revoke_unknown_request_false(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.revoke(999) is False


def test_revoke_expired_active_grant_false(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store.approve(req, timedelta(hours=1))
    store._clock = lambda: T0 + timedelta(hours=2)
    assert store.revoke(req) is False


def test_revoke_expired_pending_false(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store._clock = lambda: T0 + timedelta(hours=13)
    assert store.revoke(req) is False


def test_revoke_all(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    r1 = submit(store)
    store.approve(r1, timedelta(hours=48))
    r2 = submit(store, backend="caldav")
    store.approve(r2, timedelta(hours=1))
    r3 = submit(store)  # stays pending
    store._clock = lambda: T0 + timedelta(hours=30)  # r2 expired; r3 pending timed out
    assert store.revoke_all() == 1  # only r1
    assert store.get(r1) is RequestState.REVOKED
    assert store.get(r2) is RequestState.EXPIRED
    assert store.get(r3) is RequestState.EXPIRED  # 12h pending silence elapsed


def test_revoke_all_empty_store_zero(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.revoke_all() == 0


def test_item_expires_at_incomparable_cap_skipped(tmp_path: Path) -> None:
    """A naive-vs-aware incomparable item cap is skipped (best-effort) at
    approval; the policy wall still fails the grant closed at check time."""
    store = make_store(tmp_path)
    req = store.submit(
        "h",
        [item(expires_at=datetime(2026, 1, 1).isoformat())],  # naive datetime
        "j",
    )
    outcome = store.approve(req, timedelta(hours=24))
    assert isinstance(outcome, GrantRecord)
    # Clock is naive too -> comparable; force incomparability via a direct
    # call to the private helper instead.
    capped = store._capped_expiry(
        T0 + timedelta(hours=24),
        [{"expires_at": datetime.now(tz=UTC).isoformat()}],  # aware
    )
    assert capped == T0 + timedelta(hours=24)


# ------------------------------------------------------------- CAS concurrency


async def _tagged(i: int, store: GrantStore, request_number: int):
    # Tagged result: asyncio.gather dedups awaitables by hash, and
    # GrantRecord (with list fields) is unhashable - tags keep the two
    # concurrent calls distinct and their results attributable.
    return (i, store.approve(request_number))


async def _gather_approve(store: GrantStore, request_number: int):
    return await asyncio.gather(
        _tagged(0, store, request_number), _tagged(1, store, request_number)
    )


def test_double_approve_exactly_one_succeeds_concurrent(tmp_path: Path) -> None:
    """CAS requirement (05_concurrency): two concurrent transitions on one
    request - exactly one approve succeeds even under asyncio.gather. The
    concurrent callers race as coroutines; the WHERE state='pending' guard
    is the arbiter, so one wins and one reports ALREADY_DECIDED."""
    store = make_store(tmp_path)
    req = submit(store)
    results = asyncio.run(_gather_approve(store, req))
    records = [r for _, r in results if isinstance(r, GrantRecord)]
    refused = [r for _, r in results if r is RejectReason.ALREADY_DECIDED]
    assert len(records) == 1
    assert len(refused) == 1
    assert store.get(req) is RequestState.ACTIVE


async def _tagged_reject(i: int, store: GrantStore, request_number: int):
    return (i, store.reject(request_number))


async def _gather_reject(store: GrantStore, request_number: int):
    return await asyncio.gather(
        _tagged_reject(0, store, request_number), _tagged_reject(1, store, request_number)
    )


def test_double_reject_exactly_one_succeeds_concurrent(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    results = asyncio.run(_gather_reject(store, req))
    assert sorted((r for _, r in results), reverse=True) == [True, False]
    assert store.get(req) is RequestState.REJECTED


class _Intercept:
    """Proxy over sqlite3.Connection with an execute() hook.

    sqlite3.Connection.execute is read-only, so tests wrap the connection
    to force race conditions underneath guarded UPDATEs.
    """

    def __init__(self, conn: sqlite3.Connection, hook: Any) -> None:
        self._conn = conn
        self._hook = hook

    def execute(self, sql: str, *args: Any) -> Any:
        return self._hook(sql, args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def test_cas_lost_race_reports_already_decided(tmp_path: Path) -> None:
    """Force the CAS guard's lost-update path: the stored row flips from
    pending between approve()'s read and its guarded UPDATE, so the UPDATE
    matches 0 rows and the caller gets ALREADY_DECIDED, never a double
    decision."""
    store = make_store(tmp_path)
    req = submit(store)
    raw_conn = sqlite3.connect(str(tmp_path / "grants.sqlite3"))
    flipped = False

    def stealing_execute(sql: str, args: Any) -> Any:
        nonlocal flipped
        if sql.startswith("UPDATE grants SET state=?") and not flipped:
            # First matching call is the CAS UPDATE; flip the state
            # underneath it via a second connection so the guarded UPDATE
            # matches 0 rows.
            flipped = True
            raw_conn.execute(
                "UPDATE grants SET state='rejected', state_source='rejection'"
                " WHERE request_number=?",
                (req,),
            )
            raw_conn.commit()
        return store._db._conn.execute(sql, *args)

    store._db = _Intercept(store._db, stealing_execute)  # type: ignore[assignment]
    assert store.approve(req) is RejectReason.ALREADY_DECIDED
    assert store.get(req) is RequestState.REJECTED
    raw_conn.close()


def test_revoke_rowcount_zero_race_returns_false(tmp_path: Path) -> None:
    """Force revoke()'s commit-guard branch: the effective state says the
    grant is live, but the CAS UPDATE loses the race (rowcount 0) - the
    result is False, no exception."""
    store = make_store(tmp_path)
    req = submit(store)
    raw_conn = sqlite3.connect(str(tmp_path / "grants.sqlite3"))
    flipped = False

    def counting_execute(sql: str, args: Any) -> Any:
        nonlocal flipped
        if sql.startswith("UPDATE grants SET state=?, decided_at=?") and not flipped:
            # Make the guarded UPDATE match nothing: pre-decide the row on
            # a second connection before the UPDATE statement runs.
            flipped = True
            raw_conn.execute(
                "UPDATE grants SET state='rejected' WHERE request_number=?", (req,)
            )
            raw_conn.commit()
        return store._db._conn.execute(sql, *args)

    store._db = _Intercept(store._db, counting_execute)  # type: ignore[assignment]
    assert store.revoke(req) is False
    raw_conn.close()


# ------------------------------------------------------------------ restart


def test_active_grant_survives_restart_pending_discarded(tmp_path: Path) -> None:
    """The core persistence contract. Write with one store, reopen a new
    store on the same file: active grants intact, pending gone."""
    db = tmp_path / "restart.sqlite3"
    s1 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    r_active = s1.submit("h1", [item()], "keep")
    s1.approve(r_active, timedelta(hours=24))
    r_pending = s1.submit("h2", [item(backend="caldav")], "drop")

    s2 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())  # "restart"
    assert s2.get(r_active) is RequestState.ACTIVE
    assert s2.get_record(r_active).expires_at == T0 + timedelta(hours=24)
    record = s2.get_record(r_pending)
    assert record.state == REJECTED
    assert record.state_source == "restart_discard"


def test_pending_discarded_even_within_timeout(tmp_path: Path) -> None:
    """Pending discard at open is unconditional - restart TTL subsumes the
    pending-timeout rule; a minutes-old pending request is still dropped."""
    db = tmp_path / "fresh.sqlite3"
    s1 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    req = s1.submit("h", [item()], "j")
    s2 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    assert s2.get(req) is RequestState.REJECTED


def test_decided_numbers_still_one_time_after_restart(tmp_path: Path) -> None:
    db = tmp_path / "onetime.sqlite3"
    s1 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    r = s1.submit("h", [item()], "j")
    s1.reject(r)
    s2 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    assert s2.approve(r) is RejectReason.ALREADY_DECIDED


def test_numbers_keep_increasing_after_restart(tmp_path: Path) -> None:
    db = tmp_path / "seq.sqlite3"
    s1 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    r1 = s1.submit("h", [item()], "j")
    s2 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    assert s2.submit("h", [item()], "j") == r1 + 1


# ------------------------------------------------------------ active_for / wall


def test_active_for_matching_grant(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)  # imap/personal/Work/[send]
    store.approve(req)
    hits = store.active_for("imap", "personal", "Work", "send")
    assert [h.request_number for h in hits] == [req]


def test_active_for_folder_recursion_via_wall(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit("h", [item(resource="Work")], "j")
    store.approve(req)
    # Descendant folder covered (exact component prefix, wall semantics).
    assert [h.request_number for h in store.active_for("imap", "personal", "Work/2026", "send")]
    # Sibling prefix is NOT covered.
    assert store.active_for("imap", "personal", "Workers", "send") == []


def test_active_for_write_implies_read_via_wall(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)  # ops [send]
    store.approve(req)
    assert [h.request_number for h in store.active_for("imap", "personal", "Work", "read")]


def test_active_for_ignores_ungranted_op(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store.approve(req)
    assert store.active_for("imap", "personal", "Work", "delete") == []


def test_active_for_ignores_other_account_and_backend(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    store.approve(req)
    assert store.active_for("imap", "other", "Work", "send") == []
    assert store.active_for("caldav", "personal", "Work", "send") == []


def test_active_for_excludes_expired_pending_and_revoked(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    r_ok = submit(store)
    store.approve(r_ok, timedelta(hours=48))
    r_pending = submit(store)
    r_expired = submit(store)
    store.approve(r_expired, timedelta(hours=1))
    r_revoked = submit(store)
    store.approve(r_revoked)
    store.revoke(r_revoked)
    store._clock = lambda: T0 + timedelta(hours=2)  # r_expired dies
    hits = store.active_for("imap", "personal", "Work", "send")
    assert [h.request_number for h in hits] == [r_ok]
    assert store.get(r_expired) is RequestState.EXPIRED
    assert store.get(r_pending) is RequestState.PENDING
    assert store.get(r_revoked) is RequestState.REVOKED


def test_active_for_multi_item_grant_any_item_authorizes(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit(
        "h",
        [
            item(resource="Work"),
            item(backend="caldav", account="work", resource="Calendar", ops=["create"]),
        ],
        "j",
    )
    store.approve(req)
    assert [h.request_number for h in store.active_for("imap", "personal", "Work", "send")]
    assert [
        h.request_number for h in store.active_for("caldav", "work", "Calendar", "create")
    ]
    assert store.active_for("carddav", "personal", "Contacts", "read") == []


def test_active_for_empty_store(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.active_for("imap", "personal", "Work", "send") == []


# --------------------------------------------------------- validation rejections


def test_submit_rejects_empty_items(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="items"):
        store.submit("h", [], "j")


def test_submit_rejects_non_sequence_items(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="items"):
        store.submit("h", "not-a-list", "j")


def test_submit_rejects_blank_justification(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="justification"):
        store.submit("h", [item()], "   ")


def test_submit_rejects_non_string_justification(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="justification"):
        store.submit("h", [item()], 7)


def test_submit_rejects_non_dict_item(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="item must be a dict"):
        store.submit("h", ["nope"], "j")


def test_submit_rejects_unknown_backend(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="backend"):
        store.submit("h", [item(backend="gopher")], "j")


def test_submit_rejects_non_string_backend(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="backend"):
        store.submit("h", [item(backend=42)], "j")


def test_submit_rejects_missing_backend(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    bad = {"account": "personal", "resource": "Work", "ops": ["send"]}
    with pytest.raises(ValueError, match="backend"):
        store.submit("h", [bad], "j")


def test_submit_rejects_empty_account(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="account"):
        store.submit("h", [item(account="")], "j")


def test_submit_rejects_non_string_account(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="account"):
        store.submit("h", [item(account=None)], "j")


def test_submit_rejects_empty_resource(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="resource"):
        store.submit("h", [item(resource="")], "j")


def test_submit_rejects_non_string_resource(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="resource"):
        store.submit("h", [item(resource=[])], "j")


def test_submit_rejects_empty_ops(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="ops"):
        store.submit("h", [item(ops=[])], "j")


def test_submit_rejects_non_sequence_ops(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="ops"):
        store.submit("h", [item(ops="send")], "j")


def test_submit_rejects_unknown_op(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="known operations"):
        store.submit("h", [item(ops=["format_disk"])], "j")


def test_submit_rejects_non_string_op(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="known operations"):
        store.submit("h", [item(ops=[1])], "j")


def test_submit_rejects_unparseable_expires_at(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="expires_at"):
        store.submit("h", [item(expires_at="not-a-date")], "j")


def test_submit_rejects_non_string_non_datetime_expires_at(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(ValueError, match="expires_at"):
        store.submit("h", [item(expires_at=12345)], "j")


def test_submit_ops_deduplicated_and_sorted(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit("h", [item(ops=["send", "delete", "send"])], "j")
    store.approve(req)
    record = store.get_record(req)
    assert record.items[0]["ops"] == ["delete", "send"]


def test_read_class_ops_are_grantable(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = store.submit("h", [item(ops=["read"])], "j")
    store.approve(req)
    assert [h.request_number for h in store.active_for("imap", "personal", "Work", "read")]


def test_approve_rejects_non_timedelta_duration(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    with pytest.raises(ValueError, match="duration"):
        store.approve(req, "8h")  # the gateway parses the grammar, not the store


def test_approve_rejects_zero_duration(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    with pytest.raises(ValueError, match="duration"):
        store.approve(req, timedelta(0))
    assert store.get(req) is RequestState.PENDING


def test_approve_rejects_negative_duration(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    with pytest.raises(ValueError, match="duration"):
        store.approve(req, timedelta(hours=-1))


# ------------------------------------------------------------------- reading


def test_get_unknown_request_state(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.get(4242) is RequestState.UNKNOWN


def test_get_record_unknown_raises(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    with pytest.raises(LookupError):
        store.get_record(4242)


def test_record_items_are_deep_copied(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    record = store.get_record(req)
    record.items[0]["ops"].append("delete")
    record.items[0]["resource"] = "Hacked"
    fresh = store.get_record(req)
    assert fresh.items[0]["ops"] == ["send"]
    assert fresh.items[0]["resource"] == "Work"


def test_record_is_frozen(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    record = store.get_record(req)
    with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError is stdlib-private-ish
        record.state = "active"  # type: ignore[misc]


def test_close_is_clean(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.close()  # no error


def test_pending_discard_uses_state_source_not_synthesis(tmp_path: Path) -> None:
    """A restart-discarded record reads as REJECTED (stored state), never as
    pending_timeout - the two expiry paths are distinguishable in audit."""
    db = tmp_path / "audit.sqlite3"
    s1 = GrantStore(db_path=db, clock=lambda: T0, registry=_store_registry())
    req = s1.submit("h", [item()], "j")
    s2 = GrantStore(db_path=db, clock=lambda: T0 + timedelta(hours=48), registry=_store_registry())
    record = s2.get_record(req)
    assert record.state_source == "restart_discard"
    assert record.state == REJECTED


def test_store_rejects_duration_override_type_confusion(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    req = submit(store)
    for bad in (None, 0, 8, "8h"):
        if bad is None:
            continue  # None is the legitimate default
        with pytest.raises(ValueError, match="duration"):
            store.approve(req, bad)  # type: ignore[arg-type]
    assert store.get(req) is RequestState.PENDING
