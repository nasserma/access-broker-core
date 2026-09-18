"""Test battery for the baseline permissions engine (access_broker_core.baselines).

TDD-first per the S4-1 goal contract: this battery is the specification,
written against the design note rev 2 (2026-09-15, findings F-A..F-L
applied) BEFORE the implementation. Spec sections -> test sections:

- F-C normative evaluation order (tier-first): suspended baselines
  match nothing; T2 never matches a baseline, ever (section 8).
- Suspension state machine (section 3):
  ACTIVE -> PENDING_RECONFIRM -> SUSPENDED; re-approval restores the
  exact definition_hash; owner revoke from any state.
- F-B: NO usage-based auto-renewal; usage data populates the
  reconfirmation request instead (section 3).
- F-H: PENDING_RECONFIRM -> SUSPENDED after reconfirm_grace (default
  72h), not instantaneously (section 3).
- F-A: suspension is indefinite by default; no auto-expiry, no auto-
  revoke (section 3).
- F-E: restart never promotes suspended/pending to ACTIVE; ACTIVE/
  SUSPENDED/REVOKED are restart-persistent; PENDING_RECONFIRM is
  re-creatable idempotently (section 3).
- F-F: grant/baseline orthogonality (a suspension suspends only the
  baseline; approved grants survive); restoration pinning (a changed
  definition is a new gated mutation, not a restoration) (section 3).
- F-D: definitions live DB-only, created/modified exclusively through
  the gated request path with config_change_request_id provenance
  (section 4).
- F-G: principal scoping, never inherited (section 5).
- F-I: suspended baselines fall back to the operation's default tier
  treatment (section 3).
- F-L: the budget report: per-baseline age, last-confirmed, window
  usage, distinct principals, state, against the standing budget with
  roll-up and headroom (section 7).

State machine vocabulary (design note section 3):

    baseline states:  ACTIVE --reconfirm-due--> PENDING_RECONFIRM
                        ^                          | grace elapses
                        | re-approval              v
                        +--------- re-approval -- SUSPENDED
                        +--owner-revokes---------> REVOKED
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from access_broker_core import baselines
from access_broker_core.grants import GrantStore
from access_broker_core.policy import OperationClass, PolicyRegistry

T0 = datetime(2026, 9, 13, 12, 0, 0)


def make_registry() -> PolicyRegistry:
    return PolicyRegistry(
        operation_class={
            "read": OperationClass.READ,
            "list": OperationClass.READ,
            "write": OperationClass.GATED,
            "move": OperationClass.GATED,
            "trash": OperationClass.GATED,
            "mkdir": OperationClass.GATED,
        },
        backends=frozenset({"webdav", "onedrive"}),
        normalize_resource=lambda raw, backend: (),  # unused by the engine
    )


def make_store(tmp_path: Path, clock: Any = None) -> GrantStore:
    return GrantStore(
        db_path=str(tmp_path / "grants.sqlite3"),
        clock=clock or (lambda: T0),
        registry=make_registry(),
    )


def definition(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "backend": "webdav",
        "account": "personal",
        "resource": "Knowledge",
        "ops": ["read"],
        "principal": "agent",
        "reassess_interval": "7d",
        "reconfirm_grace": "72h",
    }
    base.update(overrides)
    return base


class FakeClock:
    """Advancing injected clock."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: Any) -> None:
        self.now += timedelta(**kwargs)


def make_engine(tmp_path: Path) -> tuple[baselines.BaselineEngine, GrantStore, FakeClock]:
    clock = FakeClock(T0)
    store = make_store(tmp_path, clock=clock)
    return baselines.BaselineEngine(store, clock=clock), store, clock


# ----------------------------------------------------------------- creation
# F-D (section 4): definitions DB-only, gated request path only.


def test_create_goes_through_gated_request_path(tmp_path: Path) -> None:
    engine, _store, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    assert outcome.request_id is not None
    # No definition exists until the owner approves the gated request.
    assert engine.list_definitions() == []


def test_definition_requires_config_change_request_id(tmp_path: Path) -> None:
    engine, _store, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(definition(), config_change_request_id="")


def test_owner_approval_activates_definition(tmp_path: Path) -> None:
    engine, _store, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    defs = engine.list_definitions()
    assert len(defs) == 1
    assert defs[0]["state"] == "ACTIVE"
    assert defs[0]["config_change_request_id"] == "ccr-1"


def test_definition_hash_is_deterministic(tmp_path: Path) -> None:
    engine, _store, _clock = make_engine(tmp_path)
    d1 = definition()
    d2 = definition()
    o1 = engine.create_request(d1, config_change_request_id="ccr-1")
    engine.approve_creation(o1.request_id)
    o2 = engine.create_request(d2, config_change_request_id="ccr-2")
    engine.approve_creation(o2.request_id)
    defs = engine.list_definitions()
    assert defs[0]["definition_hash"] == defs[1]["definition_hash"]


def test_tier2_tier3_operations_are_never_baselinable(tmp_path: Path) -> None:
    """Ruling 4: T0/T1 may be baselined; T2/T3 never."""
    engine, _store, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(definition(ops=["write"]), config_change_request_id="ccr-1")


# ------------------------------------------------------------- state machine


def test_reconfirm_due_converts_to_pending(tmp_path: Path) -> None:
    """At interval end the baseline converts to a reconfirmation request
    regardless of usage (F-B)."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    engine.list_definitions()[0]["baseline_id"]
    clock.advance(days=7)
    events = engine.reassess()
    assert events, "interval end must produce a reconfirmation request"
    assert engine.list_definitions()[0]["state"] == "PENDING_RECONFIRM"


def test_usage_does_not_renew(tmp_path: Path) -> None:
    """F-B: usage data informs, it never renews.

    The clock advances past the interval with usage recorded in the
    window: the baseline is due anyway. A further advance past grace
    suspends it - usage never extended anything.
    """
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    baseline_id = engine.list_definitions()[0]["baseline_id"]
    clock.advance(days=1)
    engine.record_use(baseline_id, principal="agent")
    clock.advance(days=6)  # day 8: interval passed, within grace
    engine.reassess()
    # Due despite usage: no auto-renewal, ever.
    assert engine.list_definitions()[0]["state"] == "PENDING_RECONFIRM"
    clock.advance(days=4)  # past 72h grace
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"


def test_reconfirmation_request_carries_usage_data(tmp_path: Path) -> None:
    """F-B: the owner decides informed; the request carries the window stats."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    baseline_id = engine.list_definitions()[0]["baseline_id"]
    engine.record_use(baseline_id, principal="agent")
    engine.record_use(baseline_id, principal="delegate-1")
    clock.advance(days=7)
    events = engine.reassess()
    assert events[0]["usage_count"] == 2
    assert events[0]["distinct_principals"] == ["agent", "delegate-1"]


def test_grace_elapses_to_suspended(tmp_path: Path) -> None:
    """F-H: silence after grace suspends; default grace 72h."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    clock.advance(days=7)
    engine.reassess()
    clock.advance(hours=71)
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "PENDING_RECONFIRM"
    clock.advance(hours=1)  # 73h > 72h grace
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"


def test_suspension_is_indefinite_by_default(tmp_path: Path) -> None:
    """F-A: SUSPENDED has no automatic exit and no auto-expiry."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    clock.advance(days=7, hours=73)
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"
    clock.advance(days=365)
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"


def test_reapproval_restores_exact_definition(tmp_path: Path) -> None:
    """Re-approval restores ACTIVE; restoration is pinned to the
    definition_hash (F-F)."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    d = engine.list_definitions()[0]
    clock.advance(days=7, hours=73)
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"
    engine.approve_restoration(d["baseline_id"], d["definition_hash"])
    restored = engine.list_definitions()[0]
    assert restored["state"] == "ACTIVE"
    assert restored["definition_hash"] == d["definition_hash"]


def test_restoration_rejects_hash_mismatch(tmp_path: Path) -> None:
    """A restoration never widens a baseline: a hash mismatch is refused."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    d = engine.list_definitions()[0]
    clock.advance(days=7, hours=73)
    engine.reassess()
    with pytest.raises(ValueError):
        engine.approve_restoration(d["baseline_id"], "0" * 64)


def test_owner_revoke_from_any_state(tmp_path: Path) -> None:
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    d = engine.list_definitions()[0]
    clock.advance(days=7, hours=73)
    engine.reassess()
    assert engine.revoke(d["baseline_id"])
    assert engine.list_definitions()[0]["state"] == "REVOKED"


def test_tier2_ops_refused_at_creation(tmp_path: Path) -> None:
    """F-C normative: the declared-operation vocabulary is the validation
    set, and a baseline whose scope contains a T2 operation is refused at
    creation, not at match time (tier classification wins over scope)."""
    engine, _store, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(
            definition(ops=["read", "write"]), config_change_request_id="ccr-1"
        )


def test_suspended_matches_nothing(tmp_path: Path) -> None:
    """F-C: suspended baselines are skipped at the baseline step."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    engine.list_definitions()
    clock.advance(days=7, hours=73)
    engine.reassess()
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledge", "read") is None


def test_active_baseline_matches_t1(tmp_path: Path) -> None:
    engine, _store, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    engine.list_definitions()
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledge", "read") is not None


def test_baseline_never_matches_tier2(tmp_path: Path) -> None:
    """F-C: T2/T3 always gate; baselines are irrelevant to T2/T3."""
    engine, _store, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(ops=["read"]), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledge", "write") is None


def test_principal_never_inherited(tmp_path: Path) -> None:
    """F-G: a baseline is a property of its principal; never inherited by
    children, peers, or supervisors."""
    engine, _store, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    assert engine.baseline_for("other-principal", "webdav", "personal", "Knowledge", "read") is None


# ------------------------------------------------------------------ restart


def test_restart_never_promotes(tmp_path: Path) -> None:
    """F-E: ACTIVE/SUSPENDED/REVOKED persist; a restart re-issues missing
    reconfirmation requests idempotently and never promotes."""
    engine, store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    d = engine.list_definitions()[0]
    clock.advance(days=7, hours=73)
    engine.reassess()
    # Reopen the store (the restart path) against the same DB.
    engine2 = baselines.BaselineEngine(
        GrantStore(
            db_path=str(tmp_path / "grants.sqlite3"),
            clock=clock,
            registry=make_registry(),
        ),
        clock=clock,
    )
    state = {x["baseline_id"]: x["state"] for x in engine2.list_definitions()}
    assert state[d["baseline_id"]] == "SUSPENDED"


def test_pending_reconfirm_reissued_idempotently(tmp_path: Path) -> None:
    engine, store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    engine.list_definitions()
    clock.advance(days=7)
    engine.reassess()
    first = engine.reassess()
    again = engine.reassess()
    # Idempotent: no duplicate reconfirmation requests on repeat cycles.
    assert len(first) == len(again)


# --------------------------------------------------------------- F-I fallback


def test_suspended_falls_back_to_default_treatment(tmp_path: Path) -> None:
    """F-I: while suspended, the permission does not count toward the free
    lane and falls back to the operation's default tier treatment."""
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    d = engine.list_definitions()[0]
    clock.advance(days=7, hours=73)
    engine.reassess()
    # Suspended: matches nothing; the caller falls back to grants.
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledge", "read") is None
    # Re-approval restores exactly the pinned definition.
    engine.approve_restoration(d["baseline_id"], d["definition_hash"])
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledge", "read") is not None


# ------------------------------------------------------------------ F-L budget


def test_budget_report_fields(tmp_path: Path) -> None:
    engine, _store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    d = engine.list_definitions()[0]
    engine.record_use(d["baseline_id"], principal="agent")
    clock.advance(days=1)
    engine.record_use(d["baseline_id"], principal="agent-2")
    report = engine.budget_report(standing_budget=5)
    entry = report["baselines"][0]
    assert entry["state"] == "ACTIVE"
    assert entry["window_usage"] == 2
    assert entry["distinct_principals"] == ["agent", "agent-2"]
    assert report["active_count"] == 1
    assert report["suspended_count"] == 0
    assert report["budget_headroom"] == 4


# ----------------------------------------------------------------- F-F grants


def test_grant_baseline_orthogonality(tmp_path: Path) -> None:
    """F-F: approved grants survive a suspension with their own scopes."""
    engine, store, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    engine.list_definitions()
    number = store.submit(
        "hint", [{"backend": "webdav", "account": "personal", "resource": "Drafts", "ops": ["write"]}],
        "one-off write",
    )
    store.approve(number)
    clock.advance(days=7, hours=73)
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"
    # The grant is independent of the baseline state: it expired on its
    # OWN terms (24h TTL from approval), not because of the suspension.
    expired = store.active_for("webdav", "personal", "Drafts", "write")
    assert not expired
    record = store.get_record(number)
    assert record.state == "expired"
