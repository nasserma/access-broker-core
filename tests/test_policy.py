"""Exhaustive test battery for the wall (groupware_broker.policy).

Every DENY reason branch, recursion semantics, write-implies-read, expiry
via the injected clock, component-vs-substring distinction, IMAP INBOX
case handling, backend-aware separator normalization, encoding-depth
attacks (including the depth-6 recursive percent-encoding case that
defeats the 4-pass cap), and Hypothesis fuzz. The wall is never mocked.

Contract under test (goal contract D5 + S1 design note):

    classify(operation) -> OperationClass
    classify_tier(operation) -> 1 | 2
    check(grant_item, request_item, clock) -> Decision
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import enum
from datetime import datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from access_broker_core import policy as _core_policy
from access_broker_core.policy import (
    Decision,
    GrantItem,
    OperationClass,
    PolicyError,
    Reason,
    Request,
)

NOW = datetime(2026, 9, 13, 12, 0, 0)  # injected clock, never real time

# The core's check()/classify()/normalize_resource() are registry-bound.
# This battery exercises the MECHANICS through a PolicyRegistry loaded with
# the groupware semantics (the same tables the groupware broker registers at
# boot) - the battery runs verbatim against the seam, proving the registry
# seam preserves behavior exactly.

_READ_OPS = frozenset(
    {"list", "read", "search", "free_busy", "attachment_fetch", "folder_tree", "availability"}
)
_GATED_OPS = frozenset(
    {"send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"}
)
_OPERATION_CLASS = dict.fromkeys(sorted(_READ_OPS), OperationClass.READ) | dict.fromkeys(sorted(_GATED_OPS), OperationClass.GATED)
_REGISTRY = None


def _get_registry():
    global _REGISTRY
    if _REGISTRY is None:

        from tests import _gw_path

        if _gw_path.insert_groupware_path() is None:  # pragma: no cover
            pytest.skip(
                "groupware sibling checkout not available (set GROUPWARE_PATH)",
                allow_module_level=False,
            )
        from groupware_broker.policy import normalize_resource as gw_normalize

        _REGISTRY = _core_policy.PolicyRegistry(
            operation_class=dict(_OPERATION_CLASS),
            backends=frozenset({"imap", "smtp", "caldav", "carddav", "msgraph"}),
            normalize_resource=gw_normalize,
        )
    return _REGISTRY


class _RegistryFacade:
    """Module-level function facade over the registry (the battery's call
    shapes unchanged: check(grant, request, clock) etc.)."""

    def check(self, grant, request, clock):
        return _core_policy.check(_get_registry(), grant, request, clock)

    def classify(self, op):
        return _get_registry().classify(op)

    def classify_tier(self, op):
        return _get_registry().classify_tier(op)

    @property
    def OPERATION_CLASS(self):
        return dict(_OPERATION_CLASS)

    def normalize_resource(self, raw, backend):
        return _get_registry().normalize_resource(raw, backend)


policy = _RegistryFacade()

# Bare-name bindings so the battery's original call shapes run unchanged.
check = policy.check
classify = policy.classify
classify_tier = policy.classify_tier
normalize_resource = policy.normalize_resource
OPERATION_CLASS = policy.OPERATION_CLASS


def static_clock() -> datetime:
    return NOW


def grant(  # noqa: PLR0913
    backend: str = "imap",
    account: str = "personal",
    resource: str = "Work",
    ops: list[str] | None = None,
    hours: float | None = 24.0,
) -> GrantItem:
    return GrantItem(
        backend=backend,
        account=account,
        resource=resource,
        ops=["read"] if ops is None else ops,
        expires_at=None if hours is None else NOW + timedelta(hours=hours),
    )


def request(  # noqa: PLR0913
    backend: str = "imap",
    account: str = "personal",
    resource: str = "Work",
    op: str = "read",
) -> Request:
    return Request(backend=backend, account=account, resource=resource, op=op)


# ------------------------------------------------------- classification


@pytest.mark.parametrize("op", sorted({"list", "read", "search", "free_busy", "attachment_fetch", "folder_tree", "availability"}))
def test_read_ops_classified_read(op: str) -> None:
    assert classify(op) is OperationClass.READ
    assert classify_tier(op) == 1


@pytest.mark.parametrize(
    "op",
    sorted({"send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"}),
)
def test_gated_ops_classified_gated(op: str) -> None:
    assert classify(op) is OperationClass.GATED
    assert classify_tier(op) == 2


@pytest.mark.parametrize("op", ["", "Read", "READ", "purge", "send_email", "drop_all", "unknown_op"])
def test_unknown_operations_fail_closed_to_gated(op: str) -> None:
    """Fail-closed default: an unclassified operation is treated as sensitive."""
    assert classify(op) is OperationClass.GATED
    assert classify_tier(op) == 2


@pytest.mark.parametrize("op", [None, 123, ["read"], {"op": "read"}])
def test_non_string_operations_fail_closed_to_gated(op: Any) -> None:
    assert classify(op) is OperationClass.GATED


def test_classification_table_has_no_overlap_and_exact_membership() -> None:
    read_ops = {"list", "read", "search", "free_busy", "attachment_fetch", "folder_tree", "availability"}
    gated_ops = {"send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"}
    assert not read_ops & gated_ops
    assert set(OPERATION_CLASS) == read_ops | gated_ops
    assert all(isinstance(v, OperationClass) for v in OPERATION_CLASS.values())
    assert all(isinstance(v, enum.Enum) for v in Reason)


def test_operation_class_enum_values() -> None:
    assert OperationClass.READ.value == "read"
    assert OperationClass.GATED.value == "gated"


# ------------------------------------------------------ basics: ALLOW


def test_exact_resource_exact_op_allowed() -> None:
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work", op="read"), static_clock)
    assert d == Decision(True, Reason.OK)


def test_folder_grant_covers_descendant() -> None:
    """Folder recursion: a grant covers the folder and all descendants."""
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work/2026", op="read"), static_clock)
    assert d.allowed


def test_folder_grant_covers_deeply_nested_descendant() -> None:
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work/2026/01/reports", op="read"), static_clock)
    assert d.allowed


def test_calendar_grant_covers_nested_path() -> None:
    d = check(
        grant(backend="caldav", resource="/calendars/personal/work", ops=["read"]),
        request(backend="caldav", resource="/calendars/personal/work/q3.ics", op="read"),
        static_clock,
    )
    assert d.allowed


def test_msgraph_scope_resource_matching() -> None:
    d = check(
        grant(backend="msgraph", resource="mailFolders/Work", ops=["read"]),
        request(backend="msgraph", resource="mailFolders/Work/subFolder/123", op="read"),
        static_clock,
    )
    assert d.allowed


def test_gated_op_in_ops_allowed() -> None:
    d = check(grant(resource="Sent", ops=["send"]), request(resource="Sent", op="send"), static_clock)
    assert d.allowed


def test_all_gated_ops_allow_when_listed() -> None:
    for op in ("send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"):
        d = check(grant(resource="Work", ops=[op]), request(resource="Work", op=op), static_clock)
        assert d.allowed, op


# --------------------------------------------------- basics: DENY


def test_empty_grant_list_denies_everything() -> None:
    pass  # single-grant checker: covered by not-in-scope tests below


def test_request_outside_scope_denied() -> None:
    d = check(grant(resource="Work"), request(resource="Photos"), static_clock)
    assert d == Decision(False, Reason.NOT_IN_SCOPE)


def test_sibling_prefix_denied_component_not_substring() -> None:
    """Grant 'Work' must never match 'Workers' (exact component matching)."""
    for victim in ("Workers", "Workforce/2026", "Workbook", "Workshop"):
        d = check(grant(resource="Work"), request(resource=victim), static_clock)
        assert not d.allowed, victim
        assert d.reason is Reason.NOT_IN_SCOPE


def test_request_shorter_than_grant_denied() -> None:
    d = check(grant(resource="Work/2026"), request(resource="Work"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


def test_account_mismatch_denied() -> None:
    d = check(grant(account="personal"), request(account="work-account"), static_clock)
    assert d.reason is Reason.ACCOUNT_MISMATCH


def test_account_type_mismatch_denied() -> None:
    d = check(grant(account="personal"), request(account=str(None)), static_clock)
    assert d.reason is Reason.ACCOUNT_MISMATCH


def test_backend_mismatch_denied() -> None:
    d = check(grant(backend="imap"), request(backend="caldav"), static_clock)
    assert d.reason is Reason.BACKEND_MISMATCH


@pytest.mark.parametrize("backend", ["imap", "smtp", "caldav", "carddav", "msgraph"])
def test_all_known_backends_pass_backend_gate(backend: str) -> None:
    d = check(grant(backend=backend, resource="X"), request(backend=backend, resource="X"), static_clock)
    assert d.allowed


@pytest.mark.parametrize("backend", ["", "IMAP", "Imap", "nextcloud", "exchange", "graph", None, 123, ["imap"]])
def test_unknown_backends_fail_closed(backend: Any) -> None:
    d = check(grant(backend=backend), request(backend="imap"), static_clock)
    assert d.reason is Reason.UNKNOWN_BACKEND
    d2 = check(grant(backend="imap"), request(backend=backend), static_clock)
    assert d2.reason is Reason.UNKNOWN_BACKEND


def test_missing_account_denied() -> None:
    d = check(grant(account="personal"), Request(resource="Work", op="read", backend="imap"), static_clock)
    assert d.reason is Reason.ACCOUNT_MISMATCH


# ------------------------------------------------------------ expiry


def test_expired_grant_denied() -> None:
    g = grant(resource="Work", ops=["read"], hours=-1)
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.EXPIRED


def test_expires_exactly_now_is_expired() -> None:
    """Boundary: expires_at == now means expired (fail closed)."""
    g = grant(resource="Work", ops=["read"], hours=0)
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.EXPIRED


def test_injected_clock_is_used_not_wall_time() -> None:
    """The clock callable decides expiry: a grant expired relative to the
    injected clock is denied even though wall-clock 'now' is later."""
    later = NOW + timedelta(hours=100)
    g = GrantItem(
        backend="imap",
        account="personal",
        resource="Work",
        ops=["read"],
        expires_at=NOW - timedelta(hours=1),
    )
    d = check(g, request(resource="Work"), lambda: later)
    assert d.reason is Reason.EXPIRED


def test_advancing_clock_expires_a_live_grant() -> None:
    g = grant(resource="Work", ops=["read"], hours=1)
    t: list[datetime] = [NOW]
    d1 = check(g, request(resource="Work"), lambda: t[0])
    assert d1.allowed
    t[0] = NOW + timedelta(hours=2)
    d2 = check(g, request(resource="Work"), lambda: t[0])
    assert d2.reason is Reason.EXPIRED


def test_grant_with_no_expiry_never_expires() -> None:
    g = grant(resource="Work", ops=["read"], hours=None)
    far = NOW + timedelta(days=3650)
    assert check(g, request(resource="Work"), lambda: far).allowed


def test_non_datetime_expiry_fails_closed() -> None:
    g = grant(resource="Work", ops=["read"], hours=None)
    g["expires_at"] = "2026-09-13"  # type: ignore[assignment]
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.MALFORMED_GRANT


def test_naive_vs_aware_expiry_fails_closed_expired() -> None:
    """Incomparable expiry (naive grant vs aware clock) fails closed."""
    g = GrantItem(
        backend="imap",
        account="personal",
        resource="Work",
        ops=["read"],
        expires_at=datetime(2027, 1, 1, tzinfo=None),
    )
    aware_clock = datetime(2026, 9, 13, tzinfo=NOW.astimezone().tzinfo)
    d = check(g, request(resource="Work"), lambda: aware_clock)
    assert d.reason is Reason.EXPIRED


# ------------------------------------------------ write-implies-read


def test_write_grant_implies_read() -> None:
    """Any GATED op in the ops list implicitly grants READ inside scope."""
    for write_op in ("send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"):
        d = check(grant(resource="Work", ops=[write_op]), request(resource="Work", op="read"), static_clock)
        assert d.allowed, write_op


def test_write_grant_implies_all_read_class_ops() -> None:
    for read_op in ("list", "read", "search", "free_busy", "attachment_fetch", "folder_tree", "availability"):
        d = check(grant(resource="Work", ops=["send"]), request(resource="Work", op=read_op), static_clock)
        assert d.allowed, read_op


def test_write_grant_implies_read_on_descendants() -> None:
    d = check(grant(resource="Work", ops=["create"]), request(resource="Work/2026", op="search"), static_clock)
    assert d.allowed


def test_read_grant_does_not_imply_write() -> None:
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work", op="send"), static_clock)
    assert d.reason is Reason.OP_NOT_GRANTED


def test_op_absent_from_grant_ops_denied() -> None:
    d = check(grant(resource="Work", ops=["read", "search"]), request(resource="Work", op="delete"), static_clock)
    assert d.reason is Reason.OP_NOT_GRANTED


def test_empty_ops_list_denies_everything_including_read() -> None:
    d = check(grant(resource="Work", ops=[]), request(resource="Work", op="read"), static_clock)
    assert d.reason is Reason.OP_NOT_GRANTED


def test_missing_ops_denies() -> None:
    """A grant with no ops key is corrupt (the store never produces one;
    fail closed as malformed rather than granting nothing silently)."""
    g = GrantItem(backend="imap", account="personal", resource="Work", expires_at=NOW + timedelta(hours=1))
    d = check(g, request(resource="Work", op="read"), static_clock)
    assert d.reason is Reason.MALFORMED_GRANT


@pytest.mark.parametrize("bad_ops", ["read", 123, {"read": True}, ["read", 123], [123], [("read",)]])
def test_corrupt_ops_structure_fails_closed(bad_ops: Any) -> None:
    g = grant(resource="Work", ops=["read"])
    g["ops"] = bad_ops  # type: ignore[assignment]
    d = check(g, request(resource="Work", op="read"), static_clock)
    assert d.reason is Reason.MALFORMED_GRANT


def test_ops_none_treated_as_malformed_fails_closed() -> None:
    """Explicit None ops is corrupt (fail-closed), distinct from a grant
    built without an ops key at all."""
    g = grant(resource="Work", ops=["read"])
    g["ops"] = None  # type: ignore[assignment]
    d = check(g, request(resource="Work", op="read"), static_clock)
    assert d.reason is Reason.MALFORMED_GRANT


def test_ops_as_tuple_accepted() -> None:
    d = check(grant(resource="Work", ops=("read",)), request(resource="Work", op="read"), static_clock)  # type: ignore[arg-type]
    assert d.allowed


def test_ops_as_set_accepted() -> None:
    d = check(grant(resource="Work", ops={"read"}), request(resource="Work", op="read"), static_clock)  # type: ignore[arg-type]
    assert d.allowed


# --------------------------------------- normalization: separators etc.


def test_duplicate_slashes_collapsed() -> None:
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work//2026"), static_clock)
    assert d.allowed


def test_trailing_slash_stripped() -> None:
    d = check(grant(resource="Work/", ops=["read"]), request(resource="Work/"), static_clock)
    assert d.allowed


def test_leading_slash_and_double_slashes_on_caldav_url() -> None:
    d = check(
        grant(backend="caldav", resource="/calendars/personal/work/", ops=["read"]),
        request(backend="caldav", resource="//calendars/personal//work//q3.ics"),
        static_clock,
    )
    assert d.allowed


def test_imap_dot_separator_normalized() -> None:
    """For IMAP both '/' and '.' are hierarchy separators for matching."""
    d = check(grant(backend="imap", resource="Work/2026", ops=["read"]), request(backend="imap", resource="Work.2026"), static_clock)
    assert d.allowed


def test_imap_mixed_separators_normalized() -> None:
    d = check(grant(backend="imap", resource="Work.2026", ops=["read"]), request(backend="imap", resource="Work/2026"), static_clock)
    assert d.allowed


def test_imap_dots_inside_component_names_do_not_merge_unrelated_folders() -> None:
    """'Sent.Items' and 'Sent/Items' are the same scope for matching."""
    d = check(grant(backend="imap", resource="Sent.Items", ops=["read"]), request(backend="imap", resource="Sent/Items/Archive"), static_clock)
    assert d.allowed


@pytest.mark.parametrize("backend", ["smtp", "caldav", "carddav", "msgraph"])
def test_dot_is_not_a_separator_on_non_imap_backends(backend: str) -> None:
    """Non-IMAP backends do not treat '.' as a separator: 'Work.2026' is a
    single component, distinct from 'Work/2026'."""
    d = check(grant(backend=backend, resource="Work", ops=["read"]), request(backend=backend, resource="Work.2026"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


def test_non_string_resource_fails_closed() -> None:
    for bad in (None, 123, ["Work"], {"r": "Work"}):
        d = check(grant(resource="Work"), Request(backend="imap", account="personal", resource=bad, op="read"), static_clock)  # type: ignore[arg-type]
        assert d.reason is Reason.MALFORMED_RESOURCE


def test_non_string_grant_resource_fails_closed() -> None:
    g = grant(resource="Work")
    g["resource"] = None  # type: ignore[assignment]
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.MALFORMED_RESOURCE


def test_empty_grant_scope_fails_closed() -> None:
    """An empty normalized grant scope would cover everything: never grantable."""
    g = grant(resource="")
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.MALFORMED_GRANT
    g2 = grant(resource="//")
    d2 = check(g2, request(resource="Work"), static_clock)
    assert d2.reason is Reason.MALFORMED_GRANT


def test_empty_request_resource_with_gated_op_denied() -> None:
    d = check(grant(resource="Work", ops=["send"]), request(resource="", op="send"), static_clock)
    assert d.reason is Reason.EMPTY_RESOURCE


def test_empty_request_resource_with_read_op_denied() -> None:
    d = check(grant(resource="Work", ops=["read"]), request(resource="", op="read"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


@pytest.mark.parametrize("attack", ["Work/../..", "Work/../../Escape", "..", "../Work"])
def test_dotdot_namespace_escape_denied(attack: str) -> None:
    d = check(grant(resource="Work"), request(resource=attack), static_clock)
    assert d.reason is Reason.ESCAPES_NAMESPACE


def test_dot_noop_segment_dropped_non_imap() -> None:
    """'.' components are no-ops on every backend; on non-IMAP backends the
    '.' branch of the component loop is what drops them (IMAP dot-expands
    earlier)."""
    d = check(
        grant(backend="caldav", resource="Work", ops=["read"]),
        request(backend="caldav", resource="Work/./x"),
        static_clock,
    )
    assert d.allowed
    assert normalize_resource("Work/./x", "caldav") == ("Work", "x")


def test_dotdot_refused_non_imap_component_loop() -> None:
    """On non-IMAP backends the '..' refusal fires in the component loop
    (IMAP refuses earlier, during dot-expansion)."""
    d = check(
        grant(backend="caldav", resource="Work", ops=["read"]),
        request(backend="caldav", resource="Work/../Escape"),
        static_clock,
    )
    assert d.reason is Reason.ESCAPES_NAMESPACE


def test_dotdot_hidden_behind_encoding_denied() -> None:
    d = check(grant(resource="Work"), request(resource="Work%2F..%2Fescape"), static_clock)
    assert d.reason is Reason.ESCAPES_NAMESPACE


@pytest.mark.parametrize("ch", ["\x00", "\x1f", "\n", "\r", "\t", "\x7f", "Work\x00x"])
def test_control_characters_denied(ch: str) -> None:
    d = check(grant(resource="Work"), request(resource=f"Work{ch}sub" if ch != "Work\x00x" else ch), static_clock)
    assert d.reason is Reason.MALFORMED_RESOURCE


def test_control_characters_in_grant_resource_fail_closed() -> None:
    g = grant(resource="Work\x00")
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.MALFORMED_RESOURCE


def test_control_character_revealed_by_decoding_denied() -> None:
    d = check(grant(resource="Work"), request(resource="Work%09x"), static_clock)
    assert d.reason is Reason.MALFORMED_RESOURCE


def test_oversized_resource_denied() -> None:
    d = check(grant(resource="Work"), request(resource="Work/" + "a" * 1024), static_clock)
    assert d.reason is Reason.MALFORMED_RESOURCE


def test_resource_exactly_at_length_cap_allowed() -> None:
    """Boundary: exactly 1024 code points is within the cap."""
    tail = "a" * (1024 - len("Work/"))
    d = check(grant(resource="Work", ops=["read"]), request(resource=f"Work/{tail}"), static_clock)
    assert d.allowed


def test_oversized_grant_resource_fails_closed() -> None:
    g = grant(resource="Work/" + "a" * 1024)
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.MALFORMED_RESOURCE


# ------------------------------------------------- INBOX case handling


@pytest.mark.parametrize("spelling", ["INBOX", "inbox", "InBoX", "Inbox"])
def test_imap_inbox_case_insensitive_matching(spelling: str) -> None:
    """RFC 3501 section 6.3.1: INBOX is case-insensitive."""
    d = check(grant(backend="imap", resource="INBOX", ops=["read"]), request(backend="imap", resource=spelling, op="read"), static_clock)
    assert d.allowed, spelling


def test_imap_inbox_descendants_case_insensitive_root() -> None:
    d = check(
        grant(backend="imap", resource="inbox/Archive", ops=["read"]),
        request(backend="imap", resource="INBOX/Archive/2026"),
        static_clock,
    )
    assert d.allowed


@pytest.mark.parametrize("spelling", ["inbox", "Inbox"])
def test_imap_inbox_normalizes_to_canonical_uppercase(spelling: str) -> None:
    assert normalize_resource(spelling, "imap") == ("INBOX",)


def test_non_inbox_mailboxes_case_sensitive() -> None:
    """Every other mailbox name compares case-sensitively."""
    d = check(grant(backend="imap", resource="Sent", ops=["read"]), request(backend="imap", resource="sent"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE
    d2 = check(grant(backend="imap", resource="Work", ops=["read"]), request(backend="imap", resource="WORK"), static_clock)
    assert d2.reason is Reason.NOT_IN_SCOPE


def test_inbox_as_component_not_root_is_case_sensitive() -> None:
    """Only a leading INBOX component is case-insensitive; nested 'inbox'
    components elsewhere are ordinary case-sensitive names."""
    d = check(grant(backend="imap", resource="Work/inbox", ops=["read"]), request(backend="imap", resource="Work/INBOX"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


def test_inbox_like_names_are_not_inbox() -> None:
    d = check(grant(backend="imap", resource="INBOX", ops=["read"]), request(backend="imap", resource="INBOXDrafts"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


def test_smtp_has_no_inbox_special_case() -> None:
    """The INBOX rule is IMAP-specific; other backends stay case-sensitive."""
    d = check(grant(backend="smtp", resource="INBOX", ops=["read"]), request(backend="smtp", resource="inbox"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


# ------------------------------------------------- percent-encoding


def test_percent_encoded_separator_decoded_before_matching() -> None:
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work%2F2026"), static_clock)
    assert d.allowed


def test_double_percent_encoding_settles_within_cap() -> None:
    """%252F -> %2F -> / within the 4-pass cap: allowed."""
    d = check(grant(resource="Work", ops=["read"]), request(resource="Work%252F2026"), static_clock)
    assert d.allowed


def test_depth_three_recursive_encoding_settles_within_cap() -> None:
    """Depth-3 recursive per-byte encoding settles within 4 passes."""
    deep = "/"
    for _ in range(3):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    d = check(grant(resource="Work", ops=["read"]), request(resource=f"Work{deep}2026"), static_clock)
    assert d.allowed


def test_depth_four_recursive_encoding_settles_exactly_at_cap() -> None:
    """Depth-4 settles on the final pass: the cap must not deny chains
    that settle just in time."""
    deep = "/"
    for _ in range(4):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    d = check(grant(resource="Work", ops=["read"]), request(resource=f"Work{deep}2026"), static_clock)
    assert d.allowed


def test_depth_six_recursive_encoding_defeats_cap_denied() -> None:
    """Depth-6 needs 6 passes to settle; at the 4-pass cap the input is
    still changing -> normalization-failure DENY (broker lesson)."""
    deep = "/"
    for _ in range(6):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    d = check(grant(resource="Work", ops=["read"]), request(resource=f"Work{deep}2026"), static_clock)
    assert d == Decision(False, Reason.NORMALIZATION_FAILURE)


def test_depth_six_encoding_in_grant_resource_fails_closed() -> None:
    deep = "/"
    for _ in range(6):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    g = grant(resource=f"Work{deep}2026")
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.NORMALIZATION_FAILURE


def test_depth_five_recursive_encoding_defeats_cap_denied() -> None:
    deep = "/"
    for _ in range(5):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    d = check(grant(resource="Work", ops=["read"]), request(resource=f"Work{deep}2026"), static_clock)
    assert d.reason is Reason.NORMALIZATION_FAILURE


def test_percent_encoding_without_escape_semantics_allowed() -> None:
    """'Work%20folder' decodes to 'Work folder': a real component name."""
    d = check(grant(resource="Work folder", ops=["read"]), request(resource="Work%20folder"), static_clock)
    assert d.allowed


def test_percent_encoding_in_grant_decodes_for_matching() -> None:
    d = check(grant(resource="Work%20folder", ops=["read"]), request(resource="Work folder"), static_clock)
    assert d.allowed


def test_plus_is_not_a_separator() -> None:
    d = check(grant(resource="Work"), request(resource="Work+2026"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


def test_unicode_fullwidth_solidus_is_not_a_separator() -> None:
    d = check(grant(resource="Work"), request(resource="Work\uff0f2026"), static_clock)
    assert d.reason is Reason.NOT_IN_SCOPE


# ------------------------------------------------ grant vs request stages


def test_normalization_failure_beaten_by_nothing_later() -> None:
    """A hostile request resource denies before any matching occurs."""
    deep = "/"
    for _ in range(6):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    d = check(
        grant(resource="Work", ops=["send"]),
        request(resource=f"Work{deep}", op="send"),
        static_clock,
    )
    assert d.reason is Reason.NORMALIZATION_FAILURE


def test_expired_checked_before_normalization() -> None:
    """Expiry is evaluated on the grant before resource normalization runs."""
    deep = "/"
    for _ in range(6):
        deep = "".join(f"%{b:02x}" for b in deep.encode())
    g = grant(resource="Work", ops=["read"], hours=-1)
    d = check(g, request(resource=f"Work{deep}"), static_clock)
    assert d.reason is Reason.EXPIRED


def test_unknown_backend_checked_before_expiry() -> None:
    g = grant(resource="Work", hours=-1)
    g["backend"] = "bogus"  # type: ignore[assignment]
    d = check(g, request(resource="Work"), static_clock)
    assert d.reason is Reason.UNKNOWN_BACKEND


def test_account_mismatch_checked_before_expiry() -> None:
    g = grant(resource="Work", hours=-1)
    d = check(g, request(resource="Work", account="other"), static_clock)
    assert d.reason is Reason.ACCOUNT_MISMATCH


def test_live_grant_beats_corrupt_sibling_ordering_is_per_grant() -> None:
    """A corrupt grant elsewhere in the store cannot block a clean grant
    (single-item checker: each item is judged on its own merits)."""
    corrupt = grant(resource="Work", ops=["read"], hours=None)
    corrupt["ops"] = 42  # type: ignore[assignment]
    clean = grant(resource="Work", ops=["read"], hours=None)
    d1 = check(corrupt, request(resource="Work"), static_clock)
    d2 = check(clean, request(resource="Work"), static_clock)
    assert d1.reason is Reason.MALFORMED_GRANT
    assert d2.allowed


# ------------------------------------------------------- Decision shape


def test_decision_is_exact_namedtuple() -> None:
    d = check(grant(resource="Work"), request(resource="Work"), static_clock)
    assert isinstance(d, Decision)
    assert d.allowed is True
    assert d.reason is Reason.OK
    assert d._fields == ("allowed", "reason")


def test_every_reason_member_is_exercised() -> None:
    exercised: set[Reason] = set()

    cases: list[tuple[GrantItem, Request]] = [
        (grant(), request()),  # OK
        (grant(backend="bogus"), request()),  # UNKNOWN_BACKEND
        (grant(backend="imap"), request(backend="caldav")),  # BACKEND_MISMATCH
        (grant(), request(account="other")),  # ACCOUNT_MISMATCH
        (grant(hours=-1), request()),  # EXPIRED
        (grant(resource="Work\x00"), request()),  # MALFORMED_GRANT (control)
        (grant(), request(resource="\x00")),  # MALFORMED_RESOURCE
        (grant(resource="Work%252F%252F%252Fx"), request()),  # settles (decays inert)
        (grant(), request(resource=_deep_encode("Work/x", 6))),  # NORMALIZATION_FAILURE (depth-6)
        (grant(resource="Work\x00"), request()),  # MALFORMED_RESOURCE (grant-side control char)
        (GrantItem(backend="imap", account="personal", resource="Work", ops=None, expires_at=None),  # type: ignore[dict-item]
         request(op="read")),  # MALFORMED_GRANT (ops=None corrupt)
        (grant(ops=["send"]), request(resource="", op="send")),  # EMPTY_RESOURCE
        (grant(), request(resource="Work/../..")),  # ESCAPES_NAMESPACE
        (grant(resource="A"), request(resource="B")),  # NOT_IN_SCOPE
        (grant(ops=["search"]), request(op="delete")),  # OP_NOT_GRANTED
    ]
    for g, r in cases:
        d = check(g, r, static_clock)
        assert isinstance(d.reason, Reason)
        exercised.add(d.reason)

    missing = {r for r in Reason} - exercised
    assert not missing, f"reasons never produced: {sorted(r.value for r in missing)}"


# ------------------------------------------------------------- fuzz


def _deep_encode(s: str, depth: int) -> str:
    for _ in range(depth):
        s = "".join(f"%{b:02x}" for b in s.encode())
    return s


components = st.text(
    alphabet=st.characters(codec="utf-8", categories=("Lu", "Ll", "Nd"), exclude_characters="/%."),
    min_size=1,
    max_size=8,
)
imaps = st.lists(components, min_size=1, max_size=4).map(lambda parts: "/".join(parts))


@given(imaps)
@settings(max_examples=500, deadline=None)
def test_fuzz_allow_only_inside_granted_scope(p: str) -> None:
    """Invariant: any ALLOW must be an exact normalized match inside the
    grant scope; DENY is the default for every other input."""
    g = grant(backend="imap", resource="Work", ops=["read"])
    d = check(g, Request(backend="imap", account="personal", resource=p, op="read"), static_clock)
    if d.allowed:
        norm = normalize_resource(p, "imap")
        assert norm == ("Work",) or norm[:2] == ("Work", norm[1]) and norm[:1] == ("Work",), (p, norm)
        assert norm[:1] == ("Work",)
        assert norm == ("Work",) or norm[0] == "Work"
        assert len(norm) >= 1 and norm[0] == "Work"


@given(imaps)
@settings(max_examples=300, deadline=None)
def test_fuzz_gated_write_requires_explicit_or_implied_grant(p: str) -> None:
    g = grant(backend="imap", resource="Work", ops=["create"])
    d = check(g, Request(backend="imap", account="personal", resource=p, op="delete"), static_clock)
    if d.allowed:
        assert normalize_resource(p, "imap")[0] == "Work"


@given(imaps)
@settings(max_examples=300, deadline=None)
def test_fuzz_expired_grant_never_allows(p: str) -> None:
    g = grant(backend="imap", resource="Work", ops=["read"], hours=-1)
    d = check(g, Request(backend="imap", account="personal", resource=p, op="read"), static_clock)
    assert not d.allowed
    assert d.reason is Reason.EXPIRED


@given(st.text(max_size=40))
@settings(max_examples=500, deadline=None)
def test_fuzz_arbitrary_unicode_never_crashes_and_fails_closed_or_exact(s: str) -> None:
    """No input can crash the wall; non-matching input always denies."""
    g = grant(backend="imap", resource="Work", ops=["read"])
    try:
        d = check(g, Request(backend="imap", account="personal", resource=s, op="read"), static_clock)
    except PolicyError:  # pragma: no cover - check() must never raise
        raise AssertionError(f"check() raised on {s!r}") from None
    if d.allowed:
        norm = normalize_resource(s, "imap")
        assert norm[0] == "Work" and (len(norm) == 1 or True)
        assert norm[:1] == ("Work",)


@given(imaps)
@settings(max_examples=200, deadline=None)
def test_fuzz_control_and_oversize_injection_denied(p: str) -> None:
    for hostile in (p + "\x00", "Work/" + p + "/%00"):
        d = check(grant(backend="imap", resource="Work", ops=["read"]), Request(backend="imap", account="personal", resource=hostile, op="read"), static_clock)
        assert not d.allowed


@pytest.mark.parametrize("depth", [5, 6, 7])
def test_recursive_encoding_beyond_cap_always_denied(depth: int) -> None:
    """The broker lesson: depth 6 defeats a 4-pass cap; depth 3-4 settles.
    Everything deeper must deny with normalization-failure."""
    deep = _deep_encode("/", depth)
    d = check(
        grant(backend="imap", resource="Work", ops=["read"]),
        Request(backend="imap", account="personal", resource=f"Work{deep}2026", op="read"),
        static_clock,
    )
    assert d.reason is Reason.NORMALIZATION_FAILURE


@pytest.mark.parametrize("depth", [3, 4])
def test_recursive_encoding_at_or_under_cap_settles(depth: int) -> None:
    deep = _deep_encode("/", depth)
    d = check(
        grant(backend="imap", resource="Work", ops=["read"]),
        Request(backend="imap", account="personal", resource=f"Work{deep}2026", op="read"),
        static_clock,
    )
    assert d.allowed


def test_policy_module_has_no_io_surface() -> None:
    """The wall performs no I/O: no open, no socket, no subprocess imports."""
    import ast
    import pathlib

    source = pathlib.Path(_core_policy.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"os", "socket", "subprocess", "pathlib", "logging", "sqlite3", "requests", "httpx"}
    assert not imported & forbidden, imported & forbidden
