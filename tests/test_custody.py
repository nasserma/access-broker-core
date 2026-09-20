"""Test battery for the core custody module (S6-1).

Goal contract requirements covered:

- CustodyClass enum: SCOPED | ACCOUNT_WIDE | UNSCOPABLE, the three
  custody classes the suite recognizes.
- CustodyRegistry: the broker populates it at boot with its backends'
  custody classes. An EMPTY registry refuses to start (the
  policy-registry mechanism, already the suite's pattern); a backend
  registered with an invalid class also refuses to start.
- Fail-closed default: an unregistered backend's custody class reads
  ACCOUNT_WIDE (the most conservative statement). The registry
  declares() an unregistered backend rather than raising, so
  audit-chain writers can always obtain an answer.
- Audit chain carries the custody class: record(custody=...) writes
  the field into the entry, hashes it into the chain, and
  verify_chain() still verifies; the field is optional, so legacy
  lines without it still verify (backward compatibility).
"""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from datetime import UTC, datetime

import pytest

from access_broker_core.audit import AuditLog, verify_chain
from access_broker_core.custody import CustodyClass, CustodyRegistry

NOW = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)


# ------------------------------------------- CustodyClass enum


def test_custody_class_values():
    """Exactly three custody classes with the contract vocabulary."""
    assert CustodyClass.SCOPED.value == "scoped"
    assert CustodyClass.ACCOUNT_WIDE.value == "account_wide"
    assert CustodyClass.UNSCOPABLE.value == "unscopable"
    assert len(CustodyClass) == 3


# ------------------------------------------- registry mechanics


def test_registry_round_trip():
    """Register backends with classes, read them back exactly."""
    reg = CustodyRegistry()
    reg.register("imap", CustodyClass.SCOPED)
    reg.register("ha", CustodyClass.ACCOUNT_WIDE)
    assert reg.declared("imap") is CustodyClass.SCOPED
    assert reg.declared("ha") is CustodyClass.ACCOUNT_WIDE


def test_empty_registry_refuses_to_start():
    """Refuse-to-start: an empty custody registry must stop the boot."""
    with pytest.raises(ValueError, match="custody registry: no backend declares"):
        CustodyRegistry().validate()


def test_registry_with_backends_validates():
    reg = CustodyRegistry()
    reg.register("imap", CustodyClass.SCOPED)
    reg.validate()


def test_reregister_same_class_is_idempotent():
    """Re-registering the same backend with the SAME class is a no-op;
    changing a declared custody class at runtime is refused (the
    declaration is load-bearing and must not shift under a live boot)."""
    reg = CustodyRegistry()
    reg.register("imap", CustodyClass.SCOPED)
    reg.register("imap", CustodyClass.SCOPED)
    assert reg.declared("imap") is CustodyClass.SCOPED
    with pytest.raises(ValueError, match="custody class.*already declared"):
        reg.register("imap", CustodyClass.ACCOUNT_WIDE)


def test_register_rejects_non_enum_class():
    """A class that is not a CustodyClass member refuses at registration
    (the seam normalizes nothing silently)."""
    reg = CustodyRegistry()
    with pytest.raises(ValueError, match="custody class"):
        reg.register("imap", "scoped")


# ------------------------------------------- fail-closed default


def test_unregistered_backend_defaults_account_wide():
    """Fail-closed: an unregistered backend declares the most
    conservative class, ACCOUNT_WIDE."""
    reg = CustodyRegistry()
    reg.register("imap", CustodyClass.SCOPED)
    assert reg.declared("websocket") is CustodyClass.ACCOUNT_WIDE
    assert reg.declared("anything-unheard-of") is CustodyClass.ACCOUNT_WIDE


def test_declared_returns_enum_identity_not_string():
    reg = CustodyRegistry()
    reg.register("imap", CustodyClass.SCOPED)
    got = reg.declared("imap")
    assert got is CustodyClass.SCOPED and isinstance(got, CustodyClass)


def test_declared_backends_sorted():
    reg = CustodyRegistry()
    reg.register("caldav", CustodyClass.SCOPED)
    reg.register("imap", CustodyClass.SCOPED)
    reg.register("msgraph", CustodyClass.SCOPED)
    assert reg.declared_backends() == ["caldav", "imap", "msgraph"]


def test_declared_backends_empty_registry():
    assert CustodyRegistry().declared_backends() == []


# ------------------------------------------- audit-chain integration


def make_log(tmp_path):
    return AuditLog(path=tmp_path / "audit.log", clock=lambda: NOW)


def test_record_accepts_custody_field(tmp_path):
    """record(custody=...) writes the field and verify_chain confirms."""
    log = make_log(tmp_path)
    log.record(
        account="a",
        resource="r",
        operation="op",
        grant_id=None,
        decision="allowed",
        reason="ok",
        custody="scoped",
    )
    (entry,) = [
        json.loads(ln)
        for ln in (tmp_path / "audit.log").read_text().splitlines()
    ]
    assert entry["custody"] == "scoped"
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok and result.lines == 1


def test_record_omits_custody_when_absent(tmp_path):
    """Legacy shape: no custody argument means no custody key (optional
    field, hashed only when present)."""
    log = make_log(tmp_path)
    log.record(
        account="a",
        resource="r",
        operation="op",
        grant_id=None,
        decision="allowed",
        reason="ok",
    )
    (entry,) = [
        json.loads(ln)
        for ln in (tmp_path / "audit.log").read_text().splitlines()
    ]
    assert "custody" not in entry
    assert verify_chain(tmp_path / "audit.log").ok


def test_record_rejects_invalid_custody_value(tmp_path):
    """A custody value outside the class vocabulary refuses before write
    (fail-closed; no partial record)."""
    log = make_log(tmp_path)
    with pytest.raises(ValueError, match="custody"):
        log.record(
            account="a",
            resource="r",
            operation="op",
            grant_id=None,
            decision="allowed",
            reason="ok",
            custody="whatever-i-feel-like",
        )
    assert not (tmp_path / "audit.log").exists()


def test_record_accepts_custody_enum_instance(tmp_path):
    """Callers holding the enum itself (registry output) pass unchanged;
    the value is normalized at the seam."""
    log = make_log(tmp_path)
    log.record(
        account="a",
        resource="r",
        operation="op",
        grant_id=None,
        decision="allowed",
        reason="ok",
        custody=CustodyClass.SCOPED,
    )
    (entry,) = [
        json.loads(ln)
        for ln in (tmp_path / "audit.log").read_text().splitlines()
    ]
    assert entry["custody"] == "scoped"
    assert verify_chain(tmp_path / "audit.log").ok


def test_mixed_legacy_and_custody_lines_verify(tmp_path):
    """Backward compatibility: a chain mixing legacy lines (no custody)
    with custody-carrying lines verifies as a whole."""
    log = make_log(tmp_path)
    log.record(
        account="a",
        resource="r",
        operation="op1",
        grant_id=None,
        decision="allowed",
        reason="ok",
    )
    log.record(
        account="a",
        resource="r",
        operation="op2",
        grant_id=None,
        decision="allowed",
        reason="ok",
        custody="account_wide",
    )
    result = verify_chain(tmp_path / "audit.log")
    assert result.ok and result.lines == 2
