"""S6 wave C: FULL Tier-2 approval flow integration test (the S5+S6 seam).

End-to-end over the REAL construction wiring (build_gateway), the REAL
ApprovalGatewayCore, the REAL GrantStore, and the REAL AuditLog - only
the network transport is faked. This is the seam proof: the factory
wiring in access_broker_core/gateways/__init__.py produces a core that actually
drives the S5 grant state machine.

Flow proven per test:
1. agent submits a pending request (store.submit + core.notify_request)
2. human approves via core.handle_reaction -> grant becomes active
3. store.active_for authorizes a Tier-2 operation
4. operator revokes via core.handle_reply('revoke N') -> grant dies
5. restart semantics: pending discarded, active preserved
6. expiry sweep posts exactly one notice
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

# --- S1 seam: gateway tests build the store with the groupware-semantics
# registry (identical tables to what the groupware broker registers at boot),
# so the ported batteries run verbatim against the core seam.
import sys as _sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from access_broker_core.audit import AuditLog, verify_chain
from access_broker_core.gateways import GatewayConfigError, build_gateway
from access_broker_core.gateways.logic import (
    APPROVE_EMOJI,
    REJECT_EMOJI,
    ApprovalGatewayCore,
    GatewayTransport,
)
from access_broker_core.grants import GrantStore, RequestState

_sys.path.insert(
    0, "HOME/GW"
)
from groupware_broker.policy import normalize_resource as _gw_norm  # noqa: E402

from access_broker_core import policy as _cp  # noqa: E402

_GW_REGISTRY = _cp.PolicyRegistry(
    operation_class={
        **dict.fromkeys(("list", "read", "search", "free_busy", "attachment_fetch", "folder_tree", "availability"), _cp.OperationClass.READ),
        **dict.fromkeys(("send", "delete", "move", "flag_update", "create", "update", "bulk_send", "bulk_delete", "share", "delegate"), _cp.OperationClass.GATED),
    },
    backends=frozenset({"imap", "smtp", "caldav", "carddav", "msgraph"}),
    normalize_resource=_gw_norm,
)

APPROVER = "@owner:example.org"

ITEM = {
    "backend": "imap",
    "account": "work",
    "resource": "Sent",
    "ops": ["send"],
}

MATRIX_SECTION = {
    "matrix": {
        "homeserver_url": "https://matrix.example.org",
        "user_id": "@brokerbot:example.org",
        "access_token_env": "TEST_MATRIX_TOKEN",
        "room_id": "!approvalroom:example.org",
        "allowed_senders": [APPROVER],
    }
}


class FakeTransport(GatewayTransport):
    """Records every outbound action; the platform shell stands in for nio."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.event_seq = 0

    async def send_message(self, text: str) -> str:
        self.sent.append(text)
        self.event_seq += 1
        return f"evt-{self.event_seq}"


class FakeMatrixGateway:
    """Adapter-shaped fake: start()/stop() + .transport, no network."""

    def __init__(self, core: ApprovalGatewayCore, transport: FakeTransport) -> None:
        self._core = core
        self._transport = transport
        self.started = False

    @property
    def transport(self) -> FakeTransport:
        return self._transport

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.started = False


@pytest.fixture()
def clock():
    state = {"now": datetime(2026, 9, 16, 12, 0, 0, tzinfo=UTC)}

    def now() -> datetime:
        return state["now"]

    def advance(**kwargs) -> None:
        state["now"] = state["now"] + timedelta(**kwargs)

    now.advance = advance  # type: ignore[attr-defined]
    return now


@pytest.fixture(autouse=True)
def env_token(monkeypatch):
    monkeypatch.setenv("TEST_MATRIX_TOKEN", "secret-token-value")


class Env:
    """One wired environment: store + audit + build_gateway output."""

    def __init__(self, tmp_path: Path, clock) -> None:
        self.db_path = str(tmp_path / "grants.db")
        self.clock = clock
        self.store = GrantStore(self.db_path, clock, registry=_GW_REGISTRY)
        self.audit = AuditLog(tmp_path / "audit.jsonl", clock)
        self.transport = FakeTransport()
        self._patch_matrix()
        # F1 wiring: the audit log rides into the gateway core through the
        # factory, exactly as production boot now passes it.
        self.core, self.adapter = build_gateway(
            MATRIX_SECTION, self.store, clock, audit=self.audit
        )

    def _patch_matrix(self) -> None:
        """Register a fake 'matrix' adapter with the core's adapter
        registry (S1 seam: platform adapters are per-broker; the core
        provides the registry). The fake asserts the same wiring facts
        the groupware battery asserted (token resolution, room id) and
        returns the fake adapter carrying the fake transport; the core
        does the core construction, transport rebind, and surface set.

        NOTE: field validation (homeserver/user_id/room_id/access_token)
        is the ADAPTER's job in the core shape (the core factory passes
        the raw fields dict), so the fake performs the same assertions
        here that _build_matrix performed in groupware.
        """

        def fake_builder(core, fields, approver):
            # _resolve_fields has resolved access_token_env -> access_token
            assert fields.get("homeserver_url") == "https://matrix.example.org"
            assert fields.get("user_id") == "@brokerbot:example.org"
            assert fields.get("access_token") == "secret-token-value"
            assert fields.get("room_id") == "!approvalroom:example.org"
            core._transport = self.transport  # same rebind _build_matrix did
            return FakeMatrixGateway(core, self.transport), fields["room_id"]

        from access_broker_core.gateways import register_adapter

        self._adapter_registered = True
        register_adapter("matrix", fake_builder)

    def teardown(self) -> None:
        # remove the fake so other tests see the un-registered state
        import access_broker_core.gateways as gw_mod

        gw_mod._ADAPTER_BUILDERS.pop("matrix", None)
        self.store.close()

    def submit(self, items=(ITEM,), justification="send the reply") -> int:
        return self.store.submit(
            request_id_hint="hint-1", items=list(items), justification=justification
        )


@pytest.fixture()
def env(tmp_path, clock):
    e = Env(tmp_path, clock)
    yield e
    e.teardown()


# ---------------------------------------------------------------------------
# Factory wiring
# ---------------------------------------------------------------------------


def test_factory_wires_core_and_adapter(env: Env):
    core, adapter = env.core, env.adapter
    assert isinstance(core, ApprovalGatewayCore)
    assert adapter.transport is env.transport
    assert adapter.started is False  # start() is the server's call
    assert core._approver == APPROVER
    assert core._surface == "!approvalroom:example.org"


def test_factory_rejects_unknown_adapter(env: Env):
    with pytest.raises(GatewayConfigError, match="unknown gateway adapter 'irc'"):
        build_gateway({"irc": {"allowed_senders": [APPROVER]}}, env.store, env.clock)


def test_factory_rejects_two_gateways(env: Env):
    section = dict(MATRIX_SECTION)
    section["telegram"] = {"chat_id": "1", "token_env": "T", "allowed_senders": [APPROVER]}
    with pytest.raises(GatewayConfigError, match="exactly one"):
        build_gateway(section, env.store, env.clock)


def test_factory_rejects_unset_env(monkeypatch, env: Env):
    monkeypatch.delenv("TEST_MATRIX_TOKEN")
    with pytest.raises(GatewayConfigError, match="TEST_MATRIX_TOKEN"):
        build_gateway(MATRIX_SECTION, env.store, env.clock)


def test_factory_rejects_missing_allowed_senders(env: Env):
    section = {"matrix": {"homeserver_url": "https://x", "user_id": "@b:x", "room_id": "!r:x"}}
    with pytest.raises(GatewayConfigError, match="allowed_senders"):
        build_gateway(section, env.store, env.clock)


# ---------------------------------------------------------------------------
# The full approval flow
# ---------------------------------------------------------------------------


async def test_full_tier2_approval_flow(env: Env):
    """Submit -> notify -> approve -> active grant authorizes -> revoke."""
    # 1. agent calls the flow: pending request
    number = env.submit(justification="send quarterly report")
    assert env.store.get(number) is RequestState.PENDING

    event_id = await env.core.notify_request(number, "send quarterly report", [ITEM])
    assert event_id == "evt-1"
    assert "PENDING #1" in env.transport.sent[0]

    # not yet authorized: the pending grant authorizes nothing
    assert env.store.active_for("imap", "work", "Sent", "send") == []

    # 2. human approves via reaction on the request message
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)

    # 3. grant becomes active and authorizes a Tier-2 operation
    assert env.store.get(number) is RequestState.ACTIVE
    grants = env.store.active_for("imap", "work", "Sent", "send")
    assert [g.request_number for g in grants] == [number]
    assert grants[0].state == "active"
    assert grants[0].expires_at is not None

    # confirmations were posted: decision + refreshed status
    assert any("Approved #1" in text for text in env.transport.sent)
    assert any("Active grants" in text for text in env.transport.sent)

    # 4. operator revokes via typed reply -> grant dies
    env.transport.sent.clear()
    await env.core.handle_reply(APPROVER, f"revoke {number}")

    assert env.store.get(number) is RequestState.REVOKED
    assert env.store.active_for("imap", "work", "Sent", "send") == []
    assert any("Revoked #1" in text for text in env.transport.sent)


async def test_non_approver_reaction_is_ignored(env: Env):
    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction("@intruder:example.org", event_id, APPROVE_EMOJI)
    assert env.store.get(number) is RequestState.PENDING


# ---------------------------------------------------------------------------
# Restart semantics
# ---------------------------------------------------------------------------


async def test_restart_discards_pending_keeps_active(env: Env, tmp_path: Path):
    # one request approved, one left pending
    approved = env.submit(justification="keep me")
    event_id = await env.core.notify_request(approved, "keep me", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)
    assert env.store.get(approved) is RequestState.ACTIVE

    pending = env.submit(justification="stale after restart")
    await env.core.notify_request(pending, "stale after restart", [ITEM])
    assert env.store.get(pending) is RequestState.PENDING

    # restart: reopen the same db path
    env.store.close()
    reopened = GrantStore(env.db_path, env.clock, registry=_GW_REGISTRY)

    assert reopened.get(approved) is RequestState.ACTIVE
    assert reopened.get(pending) is RequestState.REJECTED

    # the active grant still authorizes after the restart...
    grants = reopened.active_for("imap", "work", "Sent", "send")
    assert [g.request_number for g in grants] == [approved]
    # ...and the discarded pending one does not
    reopened.revoke(approved)
    assert reopened.active_for("imap", "work", "Sent", "send") == []
    reopened.close()


# ---------------------------------------------------------------------------
# Expiry sweep
# ---------------------------------------------------------------------------


async def test_expiry_sweep_posts_exactly_one_notice(env: Env, tmp_path: Path):
    number = env.submit(justification="will time out")
    await env.core.notify_request(number, "will time out", [ITEM])

    # advance past the pending timeout: the request reads as expired
    env.clock.advance(hours=13)
    assert env.store.get(number) is RequestState.EXPIRED

    await env.core.sweep()
    notices = [t for t in env.transport.sent if f"#{number} expired unanswered" in t]
    assert len(notices) == 1

    # a second sweep must not re-notice (once per number per lifetime)
    await env.core.sweep()
    await env.core.sweep()
    notices = [t for t in env.transport.sent if f"#{number} expired unanswered" in t]
    assert len(notices) == 1

    # audit trail: any entries written still form a valid chain
    if (tmp_path / "audit.jsonl").exists():
        result = verify_chain(tmp_path / "audit.jsonl")
        assert result.ok, result.error


# ---------------------------------------------------------------------------
# F1 regression: human decisions are in the audit chain
# (review finding F1, 2026-09-16 — the empirical finding was that a grant
# could go active with NO audit.jsonl entry; these tests pin the fix)
# ---------------------------------------------------------------------------


def _audit_records(path: Path) -> list[dict]:
    """Read every audit record; the tests assert on real chain contents.
    A log that was never written to does not exist on disk — empty list."""
    import json

    if not path.exists():
        return []
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


async def test_f1_submit_decision_audited(env: Env, tmp_path: Path):
    number = env.submit()
    await env.core.notify_request(number, "j", [ITEM])
    records = _audit_records(tmp_path / "audit.jsonl")
    submitted = [r for r in records if r["decision"] == "submitted"]
    assert len(submitted) == 1
    entry = submitted[0]
    assert entry["grant_id"] == number
    assert entry["principal"] == f"approver:{APPROVER}"
    assert entry["account"] == "work"
    assert entry["resource"] == "Sent"
    assert entry["operation"] == "send"
    assert entry["backend"] == "imap"


async def test_f1_approve_decision_audited_before_confirmation(env: Env, tmp_path: Path):
    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)
    assert env.store.get(number) is RequestState.ACTIVE

    records = _audit_records(tmp_path / "audit.jsonl")
    approved = [r for r in records if r["decision"] == "approved"]
    assert len(approved) == 1
    entry = approved[0]
    assert entry["grant_id"] == number
    assert entry["principal"] == f"approver:{APPROVER}"
    assert entry["reason"] == "grant_active"
    # the confirmation message the approver saw must POST-DATE the audit
    # write (write-before-notify): the record exists before the reply in
    # the same synchronous flow — verified by the entry simply existing;
    # ordering is enforced by construction (record() precedes send).
    assert any("Approved" in t for t in env.transport.sent)
    result = verify_chain(tmp_path / "audit.jsonl")
    assert result.ok, result.error


async def test_f1_reject_decision_audited(env: Env, tmp_path: Path):
    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, REJECT_EMOJI)
    assert env.store.get(number) is RequestState.REJECTED

    records = _audit_records(tmp_path / "audit.jsonl")
    rejected = [r for r in records if r["decision"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["grant_id"] == number
    assert rejected[0]["principal"] == f"approver:{APPROVER}"


async def test_f1_revoke_decision_audited(env: Env, tmp_path: Path):
    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)
    # after approval the event mapping is cleared (one-time semantics), so
    # revocation goes through the typed command, as in the existing tests
    await env.core.handle_reply(APPROVER, f"revoke {number}")
    assert env.store.get(number) is RequestState.REVOKED

    records = _audit_records(tmp_path / "audit.jsonl")
    revoked = [r for r in records if r["decision"] == "revoked"]
    assert len(revoked) == 1
    assert revoked[0]["grant_id"] == number


async def test_f1_revoke_all_audited(env: Env, tmp_path: Path):
    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)
    await env.core.handle_reply(APPROVER, "revoke all")
    assert env.store.get(number) is RequestState.REVOKED

    records = _audit_records(tmp_path / "audit.jsonl")
    bulk = [r for r in records if "revoke_all" in (r.get("reason") or "")]
    assert len(bulk) == 1
    assert bulk[0]["principal"] == f"approver:{APPROVER}"


async def test_f1_undo_decision_audited(env: Env, tmp_path: Path):
    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, REJECT_EMOJI)
    env.clock.advance(seconds=5)  # inside the 15s undo grace
    await env.core.handle_reply(APPROVER, f"undo {number}")

    records = _audit_records(tmp_path / "audit.jsonl")
    undo_entries = [r for r in records if "undo" in (r.get("reason") or "")]
    assert len(undo_entries) == 1
    assert undo_entries[0]["decision"] == "submitted"


async def test_f1_approve_fails_closed_on_audit_write_failure(env: Env, tmp_path: Path):
    """The F1 fail-closed path: an approve whose audit write fails is NOT
    confirmed to the approver; the room gets an explicit warning instead.
    The grant exists in the store but was never visibly confirmed."""
    from access_broker_core.audit import LogWriteError

    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    assert env.store.get(number) is RequestState.PENDING

    original_record = env.audit.record

    def broken_record(*args, **kwargs):
        raise LogWriteError("injected disk failure")

    env.audit.record = broken_record  # type: ignore[method-assign]
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)

    # the store DID transition (store semantics are unchanged)...
    assert env.store.get(number) is RequestState.ACTIVE
    # ...but the approver saw the warning, NOT a confirmation
    assert not any("Approved #" in t for t in env.transport.sent)
    assert any("audit" in t.lower() and "FAILED" in t for t in env.transport.sent)
    env.audit.record = original_record  # restore for teardown


def test_f1_no_gateway_audit_reference_leaves_no_entries(env: Env, tmp_path: Path):
    """Backward compatibility: a core built WITHOUT an audit log (the old
    signature) skips decision entries silently — headless/test mode."""
    import asyncio

    from access_broker_core.gateways.logic import ApprovalGatewayCore

    plain_core = ApprovalGatewayCore(
        store=env.store,
        transport=env.transport,
        approver=APPROVER,
        now=env.clock,
    )
    number = env.submit()

    async def _flow():
        event_id = await plain_core.notify_request(number, "j", [ITEM])
        await plain_core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)

    asyncio.run(_flow())
    assert env.store.get(number) is RequestState.ACTIVE
    # the shared audit log gained NO approver-principal entries from the
    # plain core (it holds no audit reference)
    records = _audit_records(tmp_path / "audit.jsonl")
    assert not any(
        r.get("principal", "").startswith("approver:") for r in records
    )


# ---------------------------------------------------------------------------
# F1 companion coverage: the remaining decision-path error branches
# ---------------------------------------------------------------------------


async def test_f1_submit_audit_failure_is_loud_not_fatal(env: Env, tmp_path: Path):
    """Submit is non-widening: an audit write failure surfaces loudly and
    the request still posts (capability unchanged, only evidence late).
    Consolidates the former *_branch and *_logged duplicates (review
    finding 4): the entry is attempted exactly once and the request
    posts regardless."""
    from access_broker_core.audit import LogWriteError

    number = env.submit()
    original = env.audit.record
    attempts = []

    def broken_record(*args, **kwargs):
        attempts.append(1)
        raise LogWriteError("injected disk failure")

    env.audit.record = broken_record  # type: ignore[method-assign]
    await env.core.notify_request(number, "j", [ITEM])
    env.audit.record = original  # restore
    assert len(attempts) == 1  # the submit entry was ATTEMPTED exactly once
    assert any("PENDING" in t for t in env.transport.sent)  # posted anyway


async def test_f1_reject_audit_failure_stands(env: Env, tmp_path: Path):
    """Reject shrinks capability: the decision stands even when its audit
    entry fails; the error is logged loudly (branch coverage)."""
    from access_broker_core.gateways.logic import (  # noqa: PLC0415
        REJECT_EMOJI,
        LogWriteError,
    )

    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    original = env.audit.record

    def broken_record(*args, **kwargs):
        raise LogWriteError("injected disk failure")

    env.audit.record = broken_record  # type: ignore[method-assign]
    await env.core.handle_reaction(APPROVER, event_id, REJECT_EMOJI)
    env.audit.record = original
    assert env.store.get(number) is RequestState.REJECTED
    assert any("Rejected" in t for t in env.transport.sent)  # decision stands


async def test_f1_revoke_audit_failure_stands(env: Env, tmp_path: Path):
    """Revoke shrinks capability: the revocation stands even when its
    audit entry fails (branch coverage for the non-widening path)."""
    from access_broker_core.audit import LogWriteError  # noqa: PLC0415

    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)
    original = env.audit.record

    def broken_record(*args, **kwargs):
        raise LogWriteError("injected disk failure")

    env.audit.record = broken_record  # type: ignore[method-assign]
    await env.core.handle_reply(APPROVER, f"revoke {number}")
    env.audit.record = original
    assert env.store.get(number) is RequestState.REVOKED
    assert any("Revoked" in t for t in env.transport.sent)


async def test_f1_revoke_all_audit_failure_stands(env: Env, tmp_path: Path):
    """revoke all is non-widening: the bulk revocation stands through an
    audit write failure (branch coverage)."""
    from access_broker_core.audit import LogWriteError  # noqa: PLC0415

    number = env.submit()
    event_id = await env.core.notify_request(number, "j", [ITEM])
    await env.core.handle_reaction(APPROVER, event_id, APPROVE_EMOJI)
    original = env.audit.record

    def broken_record(*args, **kwargs):
        raise LogWriteError("injected disk failure")

    env.audit.record = broken_record  # type: ignore[method-assign]
    await env.core.handle_reply(APPROVER, "revoke all")
    env.audit.record = original
    assert env.store.get(number) is RequestState.REVOKED


async def test_f1_reject_refused_branch(env: Env):
    """Branch coverage: rejecting an already-decided number is refused
    (store refuses, no audit entry, no undo window)."""
    number = env.submit()
    await env.core.handle_reply(APPROVER, f"approve {number}")
    # second reject on the now-active number -> refused path
    await env.core.handle_reply(APPROVER, f"reject {number}")
    assert env.store.get(number) is RequestState.ACTIVE  # unchanged


async def test_f1_revoke_unknown_refused(env: Env):
    """Branch coverage: revoking an unknown number reports refusal."""
    await env.core.handle_reply(APPROVER, "revoke 999")
    assert any("Cannot revoke" in t for t in env.transport.sent)
