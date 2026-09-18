"""Coverage battery for the baseline engine (S4-1 suite bar: 100%).

Every refusal path, malformed input, and fallback branch the main
battery reaches only on its happy path. Grouped by the finding each
branch implements.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from access_broker_core import baselines
from access_broker_core.baselines import BaselineError, definition_hash
from access_broker_core.grants import GrantStore
from access_broker_core.policy import OperationClass, PolicyRegistry

T0 = datetime(2026, 9, 13, 12, 0, 0)


def make_registry() -> PolicyRegistry:
    return PolicyRegistry(
        operation_class={
            "read": OperationClass.READ,
            "list": OperationClass.READ,
            "write": OperationClass.GATED,
        },
        backends=frozenset({"webdav", "onedrive"}),
        normalize_resource=lambda raw, backend: (),
    )


class FakeClock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: Any) -> None:
        self.now += timedelta(**kwargs)


def make_engine(tmp_path: Path) -> tuple[baselines.BaselineEngine, FakeClock]:
    clock = FakeClock()
    store = GrantStore(
        db_path=str(tmp_path / "g.sqlite3"),
        clock=clock,
        registry=make_registry(),
    )
    return baselines.BaselineEngine(store, clock=clock), clock


def definition(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "backend": "webdav",
        "account": "personal",
        "resource": "Knowledge",
        "ops": ["read"],
        "principal": "agent",
    }
    base.update(overrides)
    return base


def activate(engine: baselines.BaselineEngine, **overrides: Any) -> int:
    outcome = engine.create_request(definition(**overrides), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    return engine.list_definitions()[0]["baseline_id"]


# ------------------------------------------------------------- duration parsing


@pytest.mark.parametrize(
    "bad",
    [7, None, "", "d", "xd", "7x", "-7d", "0d"],
)
def test_unparseable_durations_refused(tmp_path: Path, bad: Any) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        baselines._parse_duration(bad, "test")  # noqa: SLF001 - battery seam


def test_duration_minutes_roundtrip(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    td = baselines._parse_duration("90m", "test")  # noqa: SLF001
    assert td == timedelta(minutes=90)
    assert baselines._format_duration(td) == "90m"  # noqa: SLF001
    # The day and hour branches of the formatter.
    assert baselines._format_duration(timedelta(days=7)) == "7d"  # noqa: SLF001
    assert baselines._format_duration(timedelta(hours=36)) == "36h"  # noqa: SLF001


def test_modify_revoked_baseline_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    baseline_id = engine.list_definitions()[0]["baseline_id"]
    engine.revoke(baseline_id)
    with pytest.raises(BaselineError):
        engine.modify_request(baseline_id, definition(), "ccr-2")


def test_match_skips_non_active_rows(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    engine.create_request(definition(), config_change_request_id="ccr-1")
    # Row exists in PENDING_CREATION: the match loop skips it (not ACTIVE).
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledge", "read") is None


def test_match_wrong_principal_is_not_a_hit(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    activate_and_hash(engine)
    # The principal arm matches the definition, the scope arms do not:
    # a second baseline for a different principal exercises the
    # backend/account continue arms from an ACTIVE row.
    assert engine.baseline_for("agent", "onedrive", "personal", "Knowledge", "read") is None
    assert engine.baseline_for("agent", "webdav", "other", "Knowledge", "read") is None


def test_match_op_not_in_scope_falls_through(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    activate_and_hash(engine, resource="A/B")
    outcome = engine.create_request(
        definition(ops=["list"], principal="agent2", resource="A/B"),
        config_change_request_id="ccr-2",
    )
    engine.approve_creation(outcome.request_id)
    # First principal matches on ops; second principal's op is missing.
    assert engine.baseline_for("agent2", "webdav", "personal", "A/B", "read") is None


def test_budget_report_ignores_other_states(tmp_path: Path) -> None:
    """PENDING_CREATION rows never appear in the report (F-L lists
    standing permissions, not requests)."""
    engine, _clock = make_engine(tmp_path)
    engine.create_request(definition(), config_change_request_id="ccr-1")
    report = engine.budget_report(standing_budget=5)
    assert report["baselines"] == []
    assert report["active_count"] == 0
    assert report["suspended_count"] == 0
    assert report["budget_headroom"] == 5


def test_reassess_leaves_undue_baselines_alone(tmp_path: Path) -> None:
    """An ACTIVE baseline inside its interval produces no events and
    stays ACTIVE."""
    engine, clock = make_engine(tmp_path)
    activate_and_hash(engine)
    clock.advance(days=2)
    assert engine.reassess() == []
    assert engine.list_definitions()[0]["state"] == "ACTIVE"


def test_budget_report_lists_pending_reconfirm(tmp_path: Path) -> None:
    """PENDING_RECONFIRM is a standing definition mid-cycle: it appears
    in the report with its state, consuming budget."""
    engine, clock = make_engine(tmp_path)
    activate_and_hash(engine)
    clock.advance(days=7)
    engine.reassess()
    report = engine.budget_report(standing_budget=5)
    assert report["baselines"][0]["state"] == "PENDING_RECONFIRM"
    assert report["active_count"] == 0
    assert report["suspended_count"] == 0
    assert report["budget_headroom"] == 4


def test_definition_hash_changes_with_content() -> None:
    a = definition()
    b = definition(reassess_interval="30d")
    assert definition_hash(a) != definition_hash(b)


def test_definition_hash_is_canonical() -> None:
    a = {"backend": "webdav", "account": "a", "resource": "r", "ops": ["read"], "principal": "p"}
    b = {"principal": "p", "ops": ["read"], "resource": "r", "account": "a", "backend": "webdav"}
    assert definition_hash(a) == definition_hash(b)


# ------------------------------------------------------- gated mutation paths


def test_approve_creation_twice_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    with pytest.raises(BaselineError):
        engine.approve_creation(outcome.request_id)


def test_approve_unknown_creation_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(BaselineError):
        engine.approve_creation(999)


def test_modify_requires_request_id(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    baseline_id = activate_and_hash(engine)[0]
    with pytest.raises(ValueError):
        engine.modify_request(baseline_id, definition(), config_change_request_id="")


def test_modify_unknown_baseline_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(BaselineError):
        engine.modify_request(999, definition(), "ccr-2")


def test_modify_suspended_baseline_allowed(tmp_path: Path) -> None:
    engine, clock = make_engine(tmp_path)
    baseline_id, original_hash = activate_and_hash(engine)
    clock.advance(days=7, hours=73)
    engine.reassess()
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"
    engine.modify_request(baseline_id, definition(resource="Archive"), "ccr-2")
    row = engine.get_definition(baseline_id)
    assert row is not None and row["definition_hash"] != original_hash


def test_modify_active_baseline_allowed(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    baseline_id, _ = activate_and_hash(engine)
    engine.modify_request(baseline_id, definition(resource="Projects"), "ccr-2")
    row = engine.get_definition(baseline_id)
    assert row is not None and json.loads(row["definition"])["resource"] == "Projects"


def activate_and_hash(engine: baselines.BaselineEngine, **overrides: Any) -> tuple[int, str]:
    outcome = engine.create_request(definition(**overrides), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    row = engine.list_definitions()[0]
    return row["baseline_id"], row["definition_hash"]


def test_record_use_requires_principal(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    baseline_id = activate_and_hash(engine)[0]
    with pytest.raises(ValueError):
        engine.record_use(baseline_id, principal="")


# ------------------------------------------------------------- restore/revoke


def test_restore_unknown_baseline_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(BaselineError):
        engine.approve_restoration(999, "0" * 64)


def test_restore_active_baseline_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    baseline_id, h = activate_and_hash(engine)
    with pytest.raises(BaselineError):
        engine.approve_restoration(baseline_id, h)


def test_revoke_unknown_baseline_is_false(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    assert not engine.revoke(999)


def test_revoke_pending_creation_is_false(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    assert not engine.revoke(outcome.request_id)  # PENDING_CREATION is not revocable


# ------------------------------------------------------------- matching arms


def test_match_unknown_backend_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    activate_and_hash(engine)
    assert engine.baseline_for("agent", "gdrive", "personal", "Knowledge", "read") is None


def test_match_empty_fields_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    activate_and_hash(engine)
    assert engine.baseline_for("", "webdav", "personal", "Knowledge", "read") is None
    assert engine.baseline_for("agent", "webdav", "", "Knowledge", "read") is None


def test_match_resource_prefix_containment(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    activate_and_hash(engine)
    hit = engine.baseline_for("agent", "webdav", "personal", "Knowledge/2026", "read")
    assert hit is not None
    assert engine.baseline_for("agent", "webdav", "personal", "Knowledgeable", "read") is None


def test_get_definition_unknown_is_none(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    activate_and_hash(engine)
    assert engine.get_definition(999) is None


# ------------------------------------------------------------- budget report


def test_budget_report_counts_suspended(tmp_path: Path) -> None:
    engine, clock = make_engine(tmp_path)
    activate_and_hash(engine)
    clock.advance(days=7, hours=73)
    engine.reassess()
    report = engine.budget_report(standing_budget=5)
    assert report["suspended_count"] == 1
    assert report["active_count"] == 0
    assert report["budget_headroom"] == 4


def test_budget_report_excludes_revoked(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    baseline_id, _h = activate_and_hash(engine)
    engine.revoke(baseline_id)
    report = engine.budget_report(standing_budget=5)
    assert report["baselines"] == []
    assert report["active_count"] == 0


# ------------------------------------------------------- definition validation


def test_non_mapping_definition_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request("nope", config_change_request_id="ccr-1")  # type: ignore[arg-type]


def test_invalid_backend_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(definition(backend="gdrive"), config_change_request_id="ccr-1")


@pytest.mark.parametrize("key", ["account", "resource", "principal"])
def test_empty_fields_refused(tmp_path: Path, key: str) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(definition(**{key: ""}), config_change_request_id="ccr-1")


def test_empty_ops_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(definition(ops=[]), config_change_request_id="ccr-1")


def test_bad_interval_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(
            definition(reassess_interval="5x"), config_change_request_id="ccr-1"
        )


def test_bad_grace_refused(tmp_path: Path) -> None:
    engine, _clock = make_engine(tmp_path)
    with pytest.raises(ValueError):
        engine.create_request(
            definition(reconfirm_grace="now"), config_change_request_id="ccr-1"
        )


# --------------------------------------------------------------- catch-up


def test_catchup_suspends_on_first_pass_after_outage(tmp_path: Path) -> None:
    """The logical issue time is the interval end: a broker restarted
    after an outage suspends a due baseline on its first pass."""
    engine, clock = make_engine(tmp_path)
    activate_and_hash(engine)
    clock.advance(days=30)  # way past interval AND grace
    events = engine.reassess()
    assert events  # the reconfirmation request was still produced
    assert engine.list_definitions()[0]["state"] == "SUSPENDED"


def test_grace_never_starts_without_a_request(tmp_path: Path) -> None:
    """A PENDING_RECONFIRM baseline with no '_reconfirm' mark (impossible
    through the engine, but defensive) is never suspended by the clock."""
    engine, clock = make_engine(tmp_path)
    outcome = engine.create_request(definition(), config_change_request_id="ccr-1")
    engine.approve_creation(outcome.request_id)
    baseline_id = engine.list_definitions()[0]["baseline_id"]
    row = engine.get_definition(baseline_id)
    assert row is not None
    # Simulate a row whose mark is missing: force state without a mark.
    engine._db.execute(  # noqa: SLF001 - defensive-state battery
        "UPDATE baselines SET state=? WHERE baseline_id=?",
        (baselines.PENDING_RECONFIRM, baseline_id),
    )
    engine._db.commit()  # noqa: SLF001
    clock.advance(days=400)
    engine.reassess()
    after = engine.get_definition(baseline_id)
    assert after is not None
    assert after["state"] == baselines.PENDING_RECONFIRM


import json  # noqa: E402
