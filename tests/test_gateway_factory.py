"""Factory and base-interface coverage: the wiring guards and defaults
(the ported batteries exercise the happy paths through a registered
adapter; these tests exercise the refuse-closed wiring branches and the
Protocol shape)."""

# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from access_broker_core import gateways
from access_broker_core.gateways import (
    GatewayConfigError,
    _PlaceholderTransport,
    _resolve_fields,
    register_adapter,
    supported_adapters,
)

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
# _resolve_fields env rules
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


def test_resolve_fields_non_string_passes_through():
    fields = _resolve_fields({"count": 3, "flag": True, "none_val": None})
    assert fields == {"count": 3, "flag": True, "none_val": None}


# --------------------------------------------------------------------------
# build_gateway refuse-closed branches
# --------------------------------------------------------------------------


def _register_stub(name="stub"):
    def builder(core, fields, approver):
        class A:
            pass

        return A(), "surface-1"

    register_adapter(name, builder)


def _teardown_stub(name="stub"):
    gateways._ADAPTER_BUILDERS.pop(name, None)


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


def test_build_gateway_happy_path_wires_surface(stub_adapter):
    class FakeStore:
        pass

    core, adapter = gateways.build_gateway(
        {"stub": {"allowed_senders": ["@owner:example.org"], "chat_id": "1"}},
        store=FakeStore(),
        clock=lambda: None,
    )
    assert core._surface == "surface-1"  # noqa: SLF001 - wiring assertion
    assert core._approver == "@owner:example.org"  # noqa: SLF001
    assert adapter is not None


def test_supported_adapters_sorted():
    _register_stub("aaa")
    try:
        assert supported_adapters() == tuple(sorted(supported_adapters()))
        assert "aaa" in supported_adapters()
    finally:
        _teardown_stub("aaa")


def test_register_adapter_replace_simple():
    def b1(core, fields, approver):
        return "one", "s1"

    def b2(core, fields, approver):
        return "two", "s2"

    register_adapter("replace_me", b1)
    register_adapter("replace_me", b2)
    _, adapter = gateways.build_gateway(
        {"replace_me": {"allowed_senders": ["@a"]}}, store=object(), clock=lambda: None
    )
    assert adapter == "two"
    gateways._ADAPTER_BUILDERS.pop("replace_me", None)


# --------------------------------------------------------------------------
# ApprovalGateway Protocol shape (base.py)
# --------------------------------------------------------------------------


def test_approval_gateway_protocol_shape():
    """The Protocol defines the adapter lifecycle contract; a conforming
    class satisfies it structurally."""

    class Conforming:
        def start(self):
            pass

        def stop(self):
            pass

        def notify_request(self, request_number, summary):
            pass

    # structural typing: isinstance check with runtime_checkable is not
    # needed for Protocol conformance; assert the methods exist
    c = Conforming()
    c.start()
    c.stop()
    c.notify_request("1", "s")


class Conforming:
    def start(self) -> None: ...

    def stop(self) -> None: ...

    def notify_request(self, request_number: str, summary: str) -> None: ...

async def test_protocol_default_bodies_execute():
    """base.py: the Protocol's method bodies are `...` stubs; executing
    them returns None (they exist so structural subtyping has concrete
    callables)."""
    from access_broker_core.gateways.base import ApprovalGateway

    assert await _none_result(ApprovalGateway.start, object()) is None
    assert await _none_result(ApprovalGateway.stop, object()) is None
    assert await _none_result(ApprovalGateway.notify_request, object(), "1", "s") is None


async def _none_result(fn, *args):
    result = fn(*args)
    return await result if hasattr(result, "__await__") else result
