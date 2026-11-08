"""Factory, config-validation and adapter-contract coverage.

The ported batteries exercise the happy paths through a registered
adapter; these tests exercise the refuse-closed wiring branches, the
2026-11 hygiene-round contracts (review P5/P15/P29/P30) and the real
adapter shape (base.py).
"""

# SPDX-License-Identifier: GPL-3.0-or-later

import asyncio

import pytest

from access_broker_core import gateways
from access_broker_core.gateways import (
    GatewayConfigError,
    _PlaceholderTransport,
    _resolve_fields,
    register_adapter,
    supported_adapters,
)
from access_broker_core.gateways.logic import GatewayTransport


class NullTransport(GatewayTransport):
    """A sendable transport: records what the core actually sent."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send_message(self, text: str) -> str:
        self.sent.append(text)
        return f"evt-{len(self.sent)}"


def _stub_builder(transport, surface: str = "surface-1"):
    """Builder that binds NOTHING: the factory must rebind from
    ``adapter.transport`` (review P15)."""

    class Adapter:
        def __init__(self) -> None:
            self.transport = transport

    def builder(core, fields, approver):
        return Adapter(), surface

    return builder


# --------------------------------------------------------------------------
# _PlaceholderTransport: the wiring-bug guard
# --------------------------------------------------------------------------


async def test_placeholder_transport_send_is_loud():
    t = _PlaceholderTransport()
    with pytest.raises(RuntimeError, match="before its adapter transport was wired"):
        await t.send_message("x")


async def test_placeholder_transport_reaction_is_loud():
    t = _PlaceholderTransport()
    with pytest.raises(RuntimeError, match="before its adapter transport was wired"):
        await t.add_reaction("evt", "emoji")


# --------------------------------------------------------------------------
# _resolve_fields env rules (P5: lists expand too)
# --------------------------------------------------------------------------


def test_resolve_fields_env_key_resolved(monkeypatch):
    monkeypatch.setenv("TOK", "resolved-value")
    fields = _resolve_fields({"access_token_env": "TOK", "chat_id": "123"})
    assert fields["access_token"] == "resolved-value"
    assert fields["chat_id"] == "123"


def test_resolve_fields_env_missing_fails_closed(monkeypatch):
    monkeypatch.delenv("TOK_MISSING", raising=False)
    with pytest.raises(GatewayConfigError, match="TOK"):
        _resolve_fields({"access_token_env": "TOK"})


def test_resolve_fields_dollar_expansion(monkeypatch):
    monkeypatch.setenv("ROOM", "!room:x")
    fields = _resolve_fields({"room_id": "${ROOM}"})
    assert fields["room_id"] == "!room:x"


def test_resolve_fields_dollar_unset_fails_closed(monkeypatch):
    monkeypatch.delenv("ROOM", raising=False)
    with pytest.raises(GatewayConfigError, match="ROOM"):
        _resolve_fields({"room_id": "${ROOM}"})


def test_resolve_fields_expands_list_values(monkeypatch):
    """P5: env indirection used to skip LIST values, so
    allowed_senders: ['${OWNER_ID}'] became the literal string."""
    monkeypatch.setenv("OWNER_ID", "@owner:example.org")
    fields = _resolve_fields({"allowed_senders": ["${OWNER_ID}"]})
    assert fields["allowed_senders"] == ["@owner:example.org"]


def test_resolve_fields_list_with_unset_var_fails_closed(monkeypatch):
    monkeypatch.delenv("OWNER_MISSING", raising=False)
    with pytest.raises(GatewayConfigError, match="OWNER_MISSING"):
        _resolve_fields({"allowed_senders": ["${OWNER_MISSING}"]})


def test_resolve_fields_non_string_passes_through():
    fields = _resolve_fields({"count": 3, "flag": True, "none_val": None})
    assert fields == {"count": 3, "flag": True, "none_val": None}


# --------------------------------------------------------------------------
# build_gateway refuse-closed branches
# --------------------------------------------------------------------------


def _register_stub(name="stub", fields=None, transport=None):
    transport = transport if transport is not None else NullTransport()
    register_adapter(name, _stub_builder(transport), fields=fields)
    return transport


def _teardown_stub(name="stub"):
    gateways._ADAPTER_BUILDERS.pop(name, None)
    gateways._ADAPTER_FIELDS.pop(name, None)


@pytest.fixture()
def stub_adapter():
    _register_stub()
    yield
    _teardown_stub()


def test_build_gateway_rejects_empty_section():
    with pytest.raises(GatewayConfigError, match="exactly one adapter key"):
        gateways.build_gateway({}, store=None, clock=lambda: None)


def test_build_gateway_rejects_non_mapping():
    with pytest.raises(GatewayConfigError, match="exactly one adapter key"):
        gateways.build_gateway("nope", store=None, clock=lambda: None)


def test_build_gateway_rejects_two_adapters(stub_adapter):
    section = {"stub": {"allowed_senders": ["@a"]}, "other": {"allowed_senders": ["@a"]}}
    with pytest.raises(GatewayConfigError, match="exactly one"):
        gateways.build_gateway(section, store=None, clock=lambda: None)


def test_build_gateway_rejects_unknown_adapter(stub_adapter):
    with pytest.raises(GatewayConfigError, match="unknown gateway adapter"):
        gateways.build_gateway(
            {"irc": {"allowed_senders": ["@a"]}}, store=None, clock=lambda: None
        )


def test_build_gateway_rejects_when_nothing_registered():
    # no stub registered: the error names the empty registry
    with pytest.raises(GatewayConfigError, match="NONE - the broker must register"):
        gateways.build_gateway(
            {"matrix": {"allowed_senders": ["@a"]}}, store=None, clock=lambda: None
        )


def test_build_gateway_rejects_non_mapping_adapter_section(stub_adapter):
    with pytest.raises(GatewayConfigError, match="section must be a mapping"):
        gateways.build_gateway({"stub": "nope"}, store=None, clock=lambda: None)


def test_build_gateway_rejects_missing_allowed_senders(stub_adapter):
    with pytest.raises(GatewayConfigError, match="allowed_senders"):
        gateways.build_gateway({"stub": {}}, store=None, clock=lambda: None)


def test_build_gateway_rejects_bad_allowed_senders_shape(stub_adapter):
    with pytest.raises(GatewayConfigError, match="allowed_senders"):
        gateways.build_gateway({"stub": {"allowed_senders": "not-a-list"}}, store=None, clock=lambda: None)


# --------------------------------------------------------------------------
# P29: the audit-less boot is a loud, explicit choice
# --------------------------------------------------------------------------


def test_build_gateway_refuses_audit_less_boot(stub_adapter):
    with pytest.raises(GatewayConfigError, match="without an audit log"):
        gateways.build_gateway(
            {"stub": {"allowed_senders": ["@a"]}},
            store=object(),
            clock=lambda: None,
            audit=None,
        )


def test_build_gateway_allows_explicit_headless_boot(stub_adapter):
    core, adapter = gateways.build_gateway(
        {
            "stub": {"allowed_senders": ["@a"]},
            "allow_without_audit": True,
        },
        store=object(),
        clock=lambda: None,
        audit=None,
    )
    assert core._audit is None  # noqa: SLF001 - the explicit headless mode
    assert adapter is not None


def test_build_gateway_audit_flag_must_be_boolean(stub_adapter):
    with pytest.raises(GatewayConfigError, match="allow_without_audit"):
        gateways.build_gateway(
            {"stub": {"allowed_senders": ["@a"]}, "allow_without_audit": "yes"},
            store=object(),
            clock=lambda: None,
        )


# --------------------------------------------------------------------------
# P15/contract: the factory guarantees a core that can actually send
# --------------------------------------------------------------------------


def test_factory_rebinds_the_adapter_transport(stub_adapter):
    core, _adapter = gateways.build_gateway(
        {"stub": {"allowed_senders": ["@a"]}, "allow_without_audit": True},
        store=object(),
        clock=lambda: None,
    )
    assert core.has_live_transport is True
    assert isinstance(core.transport, NullTransport)
    # the sendability contract, proven by sending
    assert asyncio.run(core.transport.send_message("ping")) == "evt-1"
    assert core.transport.sent == ["ping"]


def test_factory_refuses_a_builder_that_wires_no_transport():
    def blind_builder(core, fields, approver):
        class Adapter:
            pass

        return Adapter(), "surface-1"

    register_adapter("blind", blind_builder)
    try:
        with pytest.raises(GatewayConfigError, match="bound no transport"):
            gateways.build_gateway(
                {"blind": {"allowed_senders": ["@a"]}, "allow_without_audit": True},
                store=object(),
                clock=lambda: None,
            )
    finally:
        _teardown_stub("blind")


def test_public_bind_transport_is_the_construction_seam():
    from access_broker_core.gateways.logic import ApprovalGatewayCore

    assert hasattr(ApprovalGatewayCore, "bind_transport")
    with pytest.raises(ValueError, match="must not be None"):
        ApprovalGatewayCore.bind_transport(object(), None)


# --------------------------------------------------------------------------
# P30: adapter-section field validation + command_prefix conformance
# --------------------------------------------------------------------------


def test_declared_fields_accept_known_keys(monkeypatch):
    monkeypatch.setenv("TOK", "t")
    transport = _register_stub(
        "matrix", fields=("homeserver_url", "room_id", "access_token")
    )
    try:
        core, _adapter = gateways.build_gateway(
            {
                "matrix": {
                    "homeserver_url": "https://x",
                    "room_id": "!r:x",
                    "access_token_env": "TOK",
                    "allowed_senders": ["@a"],
                },
                "allow_without_audit": True,
            },
            store=object(),
            clock=lambda: None,
        )
        assert core.has_live_transport is True
        assert transport.sent == []
    finally:
        _teardown_stub("matrix")


def test_unknown_adapter_field_refuses_the_boot(monkeypatch):
    monkeypatch.setenv("TOK", "t")
    _register_stub("matrix", fields=("homeserver_url", "room_id", "access_token"))
    try:
        with pytest.raises(GatewayConfigError, match="unknown field"):
            gateways.build_gateway(
                {
                    "matrix": {
                        "homeserver_url": "https://x",
                        "room_id": "!r:x",
                        "access_token_env": "TOK",
                        "roomid": "typo",  # the P30 typo that used to boot cleanly
                        "allowed_senders": ["@a"],
                    },
                    "allow_without_audit": True,
                },
                store=object(),
                clock=lambda: None,
            )
    finally:
        _teardown_stub("matrix")


def test_undeclared_adapter_keeps_pass_through_behavior(stub_adapter):
    """An adapter that declares no field set keeps the historical
    pass-through contract (back-compat for brokers that have not
    declared their fields yet)."""
    core, _adapter = gateways.build_gateway(
        {"stub": {"allowed_senders": ["@a"], "anything_at_all": 1}, "allow_without_audit": True},
        store=object(),
        clock=lambda: None,
    )
    assert core.has_live_transport is True


def test_command_prefix_must_match_the_inbound_grammar(stub_adapter):
    with pytest.raises(GatewayConfigError, match="command_prefix"):
        gateways.build_gateway(
            {
                "stub": {
                    "allowed_senders": ["@a"],
                    "shared_room": True,
                    "command_prefix": "Comms",  # uppercase: no inbound line matches
                },
                "allow_without_audit": True,
            },
            store=object(),
            clock=lambda: None,
        )


def test_command_prefix_valid_shape_boots(stub_adapter):
    core, _adapter = gateways.build_gateway(
        {
            "stub": {
                "allowed_senders": ["@a"],
                "shared_room": True,
                "command_prefix": "comms_1",
            },
            "allow_without_audit": True,
        },
        store=object(),
        clock=lambda: None,
    )
    assert core._prefix == "comms_1"  # noqa: SLF001 - the routing tag


def test_command_prefix_without_shared_room_is_refused(stub_adapter):
    with pytest.raises(GatewayConfigError, match="only valid with"):
        gateways.build_gateway(
            {"stub": {"allowed_senders": ["@a"], "command_prefix": "comms"}, "allow_without_audit": True},
            store=object(),
            clock=lambda: None,
        )


def test_send_timeout_must_be_positive(stub_adapter):
    for bad in (0, -1, "10", True):
        with pytest.raises(GatewayConfigError, match="send_timeout_seconds"):
            gateways.build_gateway(
                {"stub": {"allowed_senders": ["@a"], "send_timeout_seconds": bad}, "allow_without_audit": True},
                store=object(),
                clock=lambda: None,
            )


def test_send_timeout_is_configurable(stub_adapter):
    core, _adapter = gateways.build_gateway(
        {"stub": {"allowed_senders": ["@a"], "send_timeout_seconds": 2.5}, "allow_without_audit": True},
        store=object(),
        clock=lambda: None,
    )
    assert core._send_timeout == 2.5  # noqa: SLF001 - the bounded-call knob


def test_approver_is_read_from_the_resolved_fields(stub_adapter, monkeypatch):
    """P5: the approver came from the RAW section, so an env-indirected
    allowed_senders produced a literal '${OWNER}' that no inbound event
    could ever match (a healthy-looking, deaf gateway)."""
    monkeypatch.setenv("OWNER_ID", "@owner:example.org")
    core, _adapter = gateways.build_gateway(
        {"stub": {"allowed_senders": ["${OWNER_ID}"]}, "allow_without_audit": True},
        store=object(),
        clock=lambda: None,
    )
    assert core._approver == "@owner:example.org"  # noqa: SLF001 - the allowlist


# --------------------------------------------------------------------------
# Registry bookkeeping
# --------------------------------------------------------------------------


def test_supported_adapters_sorted():
    _register_stub("aaa")
    try:
        assert supported_adapters() == tuple(sorted(supported_adapters()))
        assert "aaa" in supported_adapters()
    finally:
        _teardown_stub("aaa")


def test_register_adapter_replace_simple():
    def b1(core, fields, approver):
        core.bind_transport(NullTransport())
        return "one", "s1"

    def b2(core, fields, approver):
        core.bind_transport(NullTransport())
        return "two", "s2"

    register_adapter("replace_me", b1)
    register_adapter("replace_me", b2)
    _, adapter = gateways.build_gateway(
        {"replace_me": {"allowed_senders": ["@a"]}, "allow_without_audit": True},
        store=object(),
        clock=lambda: None,
    )
    assert adapter == "two"
    gateways._ADAPTER_BUILDERS.pop("replace_me", None)
    gateways._ADAPTER_FIELDS.pop("replace_me", None)


# --------------------------------------------------------------------------
# ApprovalGateway: the REAL adapter contract (base.py)
# --------------------------------------------------------------------------


class _RealShapeAdapter:
    """What an adapter actually is: lifecycle + the transport the core
    sends through. No notify_request, no decision semantics."""

    def __init__(self) -> None:
        self._transport = NullTransport()

    @property
    def transport(self) -> GatewayTransport:
        return self._transport

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None


def test_approval_gateway_protocol_matches_reality():
    from access_broker_core.gateways.base import ApprovalGateway

    adapter = _RealShapeAdapter()
    assert isinstance(adapter, ApprovalGateway)  # runtime_checkable
    assert not isinstance(object(), ApprovalGateway)
    # the fictional members are gone (P15)
    assert not hasattr(ApprovalGateway, "notify_request")
    assert asyncio.run(adapter.start()) is None
    assert asyncio.run(adapter.stop()) is None
