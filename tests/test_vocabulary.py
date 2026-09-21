"""S4-1: the declared-operation vocabulary registration seam.

The grant-store generalization (goal contract section 6): the grant
item schema's operation vocabulary is the broker's REGISTERED
operation table. A broker that registers a one-op vocabulary is the
current shape (backward compatibility by construction); the data
broker registers the full declared set (read, write, list, move,
trash, mkdir). Tests:

- the registry exposes the declared vocabulary;
- grant items validate against it (existing behavior, pinned);
- baseline definitions validate against it (new, via the engine);
- the vocabulary is the validation set for BOTH consumers - one
  table, one custody.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from access_broker_core import baselines
from access_broker_core.grants import GrantStore
from access_broker_core.policy import OperationClass, PolicyRegistry

T0 = datetime(2026, 9, 13, 12, 0, 0)


def _table() -> dict[str, OperationClass]:
    return {
        "read": OperationClass.READ,
        "list": OperationClass.READ,
        "write": OperationClass.GATED,
        "move": OperationClass.GATED,
        "trash": OperationClass.GATED,
        "mkdir": OperationClass.GATED,
    }


def make_registry() -> PolicyRegistry:
    return PolicyRegistry(
        operation_class=_table(),
        backends=frozenset({"webdav", "onedrive"}),
        normalize_resource=lambda raw, backend: (),
    )


def test_registry_exposes_declared_vocabulary() -> None:
    registry = make_registry()
    assert registry.declared_operations() == sorted(_table())


def test_store_judges_through_the_vocabulary(tmp_path: Path) -> None:
    """Existing behavior, pinned: an undeclared op is refused at submit."""
    store = GrantStore(
        db_path=str(tmp_path / "g.sqlite3"), clock=lambda: T0, registry=make_registry()
    )
    with pytest.raises(ValueError):
        store.submit(
            "hint",
            [{"backend": "webdav", "account": "a", "resource": "r", "ops": ["undeclared"]}],
            "j",
        )


def test_baseline_validates_against_same_vocabulary(tmp_path: Path) -> None:
    """One table, one custody: the engine uses the grant store's registry."""
    store = GrantStore(
        db_path=str(tmp_path / "g.sqlite3"), clock=lambda: T0, registry=make_registry()
    )
    engine = baselines.BaselineEngine(store, clock=lambda: T0)
    with pytest.raises(ValueError):
        engine.create_request(
            {
                "backend": "webdav",
                "account": "a",
                "resource": "r",
                "ops": ["undeclared"],
                "principal": "p",
            },
            config_change_request_id="ccr-1",
        )


def test_one_op_vocabulary_is_the_current_shape(tmp_path: Path) -> None:
    """Backward compatibility by construction: a one-op registry is a
    valid registry (the groupware/automation shape)."""
    registry = PolicyRegistry(
        operation_class={"send": OperationClass.GATED},
        backends=frozenset({"imap"}),
        normalize_resource=lambda raw, backend: (),
    )
    registry.validate()
    assert registry.declared_operations() == ["send"]
