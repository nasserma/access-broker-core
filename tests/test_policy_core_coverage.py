"""Coverage completion for the core policy mechanics: the registry seams
the ported groupware battery does not reach (custom classifier, validate
guards, custom-classify construction, the reason-value fallback in
check(), and classify_tier on the default classifier)."""

# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from access_broker_core import policy as core_policy
from access_broker_core.policy import (
    OperationClass,
    PolicyError,
    PolicyRegistry,
)


def _noop_normalizer(raw, backend):
    if not isinstance(raw, str):
        raise PolicyError(core_policy.Reason.MALFORMED_RESOURCE)
    return (raw,)


def _registry(**kwargs):
    table = {"read": OperationClass.READ, "send": OperationClass.GATED}
    defaults = {
        "operation_class": table,
        "backends": frozenset({"imap"}),
        "normalize_resource": lambda raw, backend: (
            (raw,) if isinstance(raw, str) else (_ for _ in ()).throw(PolicyError(core_policy.Reason.MALFORMED_RESOURCE))
        ),
    }
    defaults.update(kwargs)
    return PolicyRegistry(**defaults)


def test_registry_validate_refuses_empty_table():
    r = _registry(operation_class={})
    with pytest.raises(ValueError, match="operation table is empty"):
        r.validate()


def test_registry_validate_refuses_empty_backends():
    r = _registry(backends=frozenset())
    with pytest.raises(ValueError, match="backend set is empty"):
        r.validate()


def test_registry_validate_passes_when_populated():
    _registry().validate()


def test_registry_custom_classify_agreeing_with_table_is_used():
    """P14: a custom classifier is only accepted when it AGREES with the
    declared table for every declared operation. (The old test pinned the
    fail-open mapping: a classifier that called a GATED op READ was
    accepted, and the wall obeyed it.)"""
    calls = []

    def custom(op):
        calls.append(op)
        return {"read": OperationClass.READ, "send": OperationClass.GATED}.get(
            op, OperationClass.GATED
        )

    r = _registry(classify=custom)
    # construction probed the declared set once
    assert sorted(calls) == ["read", "send"]
    calls.clear()
    assert r.classify("anything") is OperationClass.GATED
    assert calls == ["anything"]
    assert r.classify_tier("read") == 1
    assert r.classify_tier("send") == 2


def test_registry_custom_classify_contradicting_table_refuses_start():
    def custom(op):
        return OperationClass.READ  # claims EVERY op is a read, including "send"

    with pytest.raises(ValueError, match="disagrees"):
        _registry(classify=custom)


def test_registry_custom_classify_raising_on_a_declared_op_refuses_start():
    def custom(op):
        raise KeyError(op)

    with pytest.raises(ValueError, match="classifier raised"):
        _registry(classify=custom)


def test_registry_refuses_string_valued_operation_table():
    """P18: a bare string never identity-compares to OperationClass.READ,
    so it would silently classify as GATED while the broker believed it
    declared a read. Refuse at construction instead."""
    with pytest.raises(ValueError, match="bare strings are refused"):
        _registry(operation_class={"read": "read", "send": "gated"})
    with pytest.raises(ValueError, match="non-empty string"):
        _registry(operation_class={"": OperationClass.READ})


def test_default_classify_tier_read_and_gated():
    r = _registry()
    assert r.classify_tier("read") == 1
    assert r.classify_tier("send") == 2


def test_check_falls_back_to_registry_reason_value():
    """A normalizer raising a foreign PolicyError subclass is matched by
    reason VALUE (the seam contract), not exception identity."""
    class ForeignReason:
        MALFORMED = type("F", (), {"value": "malformed_resource"})()

    class ForeignPolicyError(Exception):
        def __init__(self):
            self.reason = core_policy.Reason.MALFORMED_RESOURCE

    def foreign_normalizer(raw, backend):
        raise ForeignPolicyError()

    r = _registry(normalize_resource=foreign_normalizer)
    grant = {"backend": "imap", "account": "a", "resource": "W", "ops": ["read"], "expires_at": None}
    request = {"backend": "imap", "account": "a", "resource": "W", "op": "read"}
    d = core_policy.check(r, grant, request, lambda: None)
    assert d.allowed is False
    assert d.reason is core_policy.Reason.MALFORMED_RESOURCE


def test_check_unknown_exception_denies_normalization_failure():
    """A normalizer raising an alien exception denies fail-closed with the
    normalization-failure reason (never propagates)."""

    def exploding_normalizer(raw, backend):
        raise RuntimeError("boom")

    r = _registry(normalize_resource=exploding_normalizer)
    grant = {"backend": "imap", "account": "a", "resource": "W", "ops": ["read"], "expires_at": None}
    request = {"backend": "imap", "account": "a", "resource": "W", "op": "read"}
    d = core_policy.check(r, grant, request, lambda: None)
    assert d.allowed is False
    assert d.reason is core_policy.Reason.NORMALIZATION_FAILURE


def test_policy_error_carries_reason_value():
    err = PolicyError(core_policy.Reason.ESCAPES_NAMESPACE)
    assert str(err) == "escapes_namespace"
    assert err.reason is core_policy.Reason.ESCAPES_NAMESPACE

def test_check_line_248_unreachable_only_when_policy_error_matches():
    """Branch completion: PolicyError raised by a registered normalizer
    whose Reason is this module's enum hits the FIRST handler; the
    fallback must still deny correctly when the reason is a foreign enum
    whose value is NOT a valid core Reason (unknown value -> fall through
    to NORMALIZATION_FAILURE)."""

    class AlienPolicyError(Exception):
        def __init__(self):
            self.reason = type("R", (), {"value": "not_a_core_reason"})()

    def alien_normalizer(raw, backend):
        raise AlienPolicyError()

    r = _registry(normalize_resource=alien_normalizer)
    grant = {"backend": "imap", "account": "a", "resource": "W", "ops": ["read"], "expires_at": None}
    request = {"backend": "imap", "account": "a", "resource": "W", "op": "read"}
    d = core_policy.check(r, grant, request, lambda: None)
    assert d.allowed is False
    assert d.reason is core_policy.Reason.NORMALIZATION_FAILURE


def test_check_policy_error_identity_path_line248():
    """Line 248 completion: a normalizer raising THIS module's PolicyError
    (identity match) takes the first handler with its exact reason."""
    def core_error_normalizer(raw, backend):
        raise core_policy.PolicyError(core_policy.Reason.ESCAPES_NAMESPACE)

    r = _registry(normalize_resource=core_error_normalizer)
    grant = {"backend": "imap", "account": "a", "resource": "W", "ops": ["read"], "expires_at": None}
    request = {"backend": "imap", "account": "a", "resource": "W", "op": "read"}
    d = core_policy.check(r, grant, request, lambda: None)
    assert d.allowed is False
    assert d.reason is core_policy.Reason.ESCAPES_NAMESPACE
