"""Battery for the pulled REST approvals surface (Stage E1a).

What this file pins, contract by contract:

- ``ApprovalGatewayCore.apply_decision``: the structured outcome of the
  EXISTING decision machinery — applied/refused, effective state +
  state_source, the computed capped expiry, RejectReason value, item
  count, audit chain head — with the three stale-card refusal states
  (unknown / already decided / expired) kept distinguishable and the
  room path (``_decide``/``_revoke``) delegating to the same code.
- ``ApprovalGatewayCore.snapshot``: the bounded read model — the
  store's ACTUAL pending timeout, per-request deadlines, item identity,
  active expiries, and expired rows in a separate slice (never in
  ``pending``).
- ``access_broker_core.approvals``: the ASGI mount helper — bearer auth
  (third credential class, refuse-to-start) BEFORE any body parse, a
  decision answered as a structured 200 (a refusal is never a 4xx),
  malformed bodies refused AND audited, idempotent ``decision_id``
  replay, health, and protected-surface registration.

No network, no broker process: the ASGI app is called with hand-built
scopes, the store is real (SQLite in tmp_path), the clock is injected.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from access_broker_core import policy as _cp
from access_broker_core.approvals import (
    APPROVAL_SURFACE_ID,
    MIN_TOKEN_LENGTH,
    ApprovalSurfaceApp,
    approval_surface_ids,
    build_approval_surface_app,
    register_protected_surfaces,
)
from access_broker_core.audit import GENESIS, AuditLog, verify_chain
from access_broker_core.gateways.logic import ApprovalGatewayCore, GatewayTransport
from access_broker_core.grants import GrantStore

APPROVER = "@owner:example.org"
TOKEN_ENV = "APPROVAL_SURFACE_TEST_TOKEN"
TOKEN = "s" * 40  # synthetic fixed-length value, never a real credential

REGISTRY = _cp.PolicyRegistry(
    operation_class={
        "list": _cp.OperationClass.READ,
        "read": _cp.OperationClass.READ,
        "send": _cp.OperationClass.GATED,
        "delete": _cp.OperationClass.GATED,
    },
    backends=frozenset({"imap", "smtp"}),
    normalize_resource=lambda raw, backend: (str(raw),),
)

ITEM = {
    "backend": "imap",
    "account": "work",
    "resource": "Sent",
    "ops": ["send"],
}


class FakeTransport(GatewayTransport):
    def __init__(self) -> None:
        self.sent: list[str] = []
        self.reactions: list[tuple[str, str]] = []

    async def send_message(self, text: str) -> str:
        self.sent.append(text)
        return f"evt-{len(self.sent)}"

    async def add_reaction(self, event_id: str, emoji: str) -> None:
        self.reactions.append((event_id, emoji))


class Env:
    """Core + real store + fake transport + optional real audit log."""

    def __init__(self, tmp_path: Path, *, audit: bool = False, pending_timeout=None):
        self.now = datetime(2026, 11, 7, 12, 0, 0, tzinfo=UTC)
        self.store = GrantStore(
            str(tmp_path / "grants.db"),
            self.clock,
            registry=REGISTRY,
            **({"pending_timeout": pending_timeout} if pending_timeout else {}),
        )
        self.transport = FakeTransport()
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = AuditLog(self.audit_path, self.clock) if audit else None
        self.core = ApprovalGatewayCore(
            store=self.store,
            transport=self.transport,
            approver=APPROVER,
            now=self.clock,
            audit=self.audit,
        )

    def clock(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        self.now += timedelta(**kwargs)

    def submit(self, **overrides) -> int:
        item = {**ITEM, **overrides}
        return self.store.submit(request_id_hint="t", items=[item], justification="need it")

    def app(self, **options) -> ApprovalSurfaceApp:
        return build_approval_surface_app(self.core, TOKEN_ENV, options or None)

    def audit_lines(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text().splitlines() if line]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    return Env(tmp_path)


@pytest.fixture
def audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    return Env(tmp_path, audit=True)


# ----------------------------------------------------------------- ASGI call


async def call(
    app: ApprovalSurfaceApp,
    method: str,
    path: str,
    *,
    token: str | None = TOKEN,
    body: object = None,
    raw_body: bytes | None = None,
    root_path: str = "",
) -> tuple[int, dict | None]:
    """Drive the ASGI app with one request; return (status, json body)."""
    if raw_body is None:
        raw_body = b"" if body is None else json.dumps(body).encode()
    headers: list[tuple[bytes, bytes]] = []
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "root_path": root_path,
        "query_string": b"",
        "headers": headers,
    }
    sent: list[dict] = []
    state = {"read": False}

    async def receive() -> dict:
        if not state["read"]:
            state["read"] = True
            return {"type": "http.request", "body": raw_body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    await app(scope, receive, send)
    assert sent and sent[0]["type"] == "http.response.start"
    status = sent[0]["status"]
    payload = None
    if len(sent) > 1 and sent[1].get("body"):
        payload = json.loads(sent[1]["body"])
    return status, payload


# ------------------------------------------------------- apply_decision arms


async def test_approve_outcome_is_structured_and_capped_by_item_expiry(
    env: Env, tmp_path: Path
) -> None:
    cap = env.now + timedelta(minutes=10)
    rid = env.submit(expires_at=cap)
    outcome = await env.core.apply_decision(
        rid, "approve", timedelta(minutes=30), "hub:device-1", announce=False
    )
    # The store writes min(now + 30m, item cap) and the outcome reports it:
    # the caller cannot derive this, which is why it is in the body.
    assert outcome["outcome"] == "applied"
    assert outcome["state"] == "active"
    assert outcome["state_source"] == "approval"
    assert outcome["expires_at"] == cap.isoformat()
    assert outcome["reason"] is None and outcome["refusal"] is None
    assert outcome["item_count"] == 1
    assert outcome["principal"] == "hub:device-1"
    assert outcome["announced"] is False and outcome["notified"] is False
    assert env.store.get_record(rid).expires_at == cap


async def test_approve_duration_string_and_zero_refused(env: Env) -> None:
    rid = env.submit()
    outcome = await env.core.apply_decision(rid, "approve", "8h", announce=False)
    assert outcome["expires_at"] == (env.now + timedelta(hours=8)).isoformat()

    with pytest.raises(ValueError, match="must be > 0"):
        await env.core.apply_decision(rid, "approve", timedelta(0), announce=False)
    with pytest.raises(ValueError, match="invalid duration"):
        await env.core.apply_decision(rid, "approve", "0h", announce=False)
    with pytest.raises(ValueError, match="unsupported decision action"):
        await env.core.apply_decision(rid, "undo", None, announce=False)


async def test_unknown_request_is_refused_and_distinguishable(env: Env) -> None:
    outcome = await env.core.apply_decision(99, "approve", None, "hub:d", announce=False)
    assert outcome["outcome"] == "refused"
    assert outcome["refusal"] == "unknown_request"
    assert outcome["reason"] == "unknown_request"
    assert outcome["state"] == "unknown"
    assert outcome["state_source"] is None
    assert outcome["item_count"] == 0
    assert outcome["audit_head"] is None  # no audit log wired


async def test_already_decided_is_distinguished_from_unknown(env: Env) -> None:
    rid = env.submit()
    first = await env.core.apply_decision(rid, "approve", None, announce=False)
    second = await env.core.apply_decision(rid, "approve", None, announce=False)
    assert first["outcome"] == "applied"
    assert second["outcome"] == "refused"
    assert second["refusal"] == "already_decided"
    assert second["reason"] == "already_decided"
    assert second["state"] == "active"
    assert second["state_source"] == "approval"
    assert env.store.get(rid).value == "active"


async def test_reject_on_past_deadline_reports_expired_state_not_rejected(env: Env) -> None:
    rid = env.submit()
    env.advance(hours=13)  # past the store's 12h pending timeout
    outcome = await env.core.apply_decision(rid, "reject", None, "hub:d", announce=False)
    assert outcome["outcome"] == "refused"
    assert outcome["refusal"] == "expired"
    assert outcome["state"] == "expired"
    assert outcome["state_source"] == "pending_timeout"
    assert outcome["reason"] == "already_decided"  # the store's RejectReason value
    # Nothing was rewritten: the row is still STORED pending, its narrative
    # still the timeout (review P9's guard), never 'rejection'.
    record = env.store.get_record(rid)
    assert record.state == "expired"
    assert record.state_source == "pending_timeout"


async def test_revoke_is_one_verb_two_outcomes(env: Env) -> None:
    active = env.submit()
    approved = await env.core.apply_decision(active, "approve", None, announce=False)
    assert approved["state"] == "active"
    revoked = await env.core.apply_decision(active, "revoke", None, "hub:d", announce=False)
    assert revoked["outcome"] == "applied"
    assert revoked["state"] == "revoked"
    assert revoked["state_source"] == "revocation"

    pending = env.submit()
    killed = await env.core.apply_decision(pending, "revoke", None, "hub:d", announce=False)
    assert killed["outcome"] == "applied"
    assert killed["state"] == "rejected"
    assert killed["state_source"] == "pending_revoke"
    assert killed["expires_at"] is None


async def test_reject_and_revoke_arm_the_undo_window(env: Env) -> None:
    rejected = env.submit()
    await env.core.apply_decision(rejected, "reject", None, announce=False)
    assert rejected in env.core._undo_windows  # noqa: SLF001 - undo arming is the contract

    revoked = env.submit()
    await env.core.apply_decision(revoked, "revoke", None, announce=False)
    assert revoked in env.core._undo_windows  # noqa: SLF001


async def test_announce_false_posts_nothing(env: Env) -> None:
    rid = env.submit()
    await env.core.apply_decision(rid, "approve", None, announce=False)
    await env.core.apply_decision(env.submit(), "reject", None, announce=False)
    await env.core.apply_decision(env.submit(), "revoke", None, announce=False)
    await env.core.apply_decision(99, "approve", None, announce=False)
    assert env.transport.sent == []


async def test_room_path_is_a_thin_caller_of_the_same_machinery(env: Env) -> None:
    rid = env.submit()
    await env.core.handle_reply(APPROVER, f"approve {rid}")
    assert env.store.get_record(rid).state == "active"
    assert any("Approved" in text for text in env.transport.sent)

    other = env.submit()
    await env.core.handle_reaction(APPROVER, "evt-x", "\N{THUMBS DOWN SIGN}")
    assert env.store.get(other).value == "pending"  # unknown event: silent no-op
    await env.core.handle_reply(APPROVER, f"reject {other}")
    assert env.store.get_record(other).state == "rejected"


async def test_outcome_carries_post_write_audit_chain_head(audited: Env) -> None:
    rid = audited.submit()
    outcome = await audited.core.apply_decision(
        rid, "approve", None, "hub:device-7", announce=False
    )
    assert outcome["outcome"] == "applied"
    assert outcome["audit_head"] == audited.audit.head_hash
    assert outcome["audit_head"] != GENESIS
    lines = audited.audit_lines()
    assert lines[-1]["decision"] == "approved"
    assert lines[-1]["principal"] == "hub:device-7"
    assert lines[-1]["sha256"] == outcome["audit_head"]
    assert verify_chain(audited.audit_path).ok


async def test_refused_outcome_also_reports_the_chain_head(audited: Env) -> None:
    outcome = await audited.core.apply_decision(7, "reject", None, announce=False)
    assert outcome["outcome"] == "refused"
    assert outcome["audit_head"] == audited.audit.head_hash == GENESIS


# --------------------------------------------------------------- snapshot


async def test_snapshot_shape_deadline_and_timeout_passthrough(tmp_path: Path) -> None:
    env = Env(tmp_path, pending_timeout=timedelta(minutes=90))
    rid = env.submit(label="Sent mail", expires_at=env.now + timedelta(days=2))
    outcome = await env.core.apply_decision(env.submit(), "approve", "2h", announce=False)
    assert outcome["outcome"] == "applied"

    snap = env.core.snapshot()
    assert snap["pending_timeout_seconds"] == 90 * 60  # the ACTUAL configured value
    assert snap["generated_at"] == env.now.isoformat()
    assert snap["counts"] == {"pending": 1, "active": 1, "expired_recent": 0}

    entry = snap["pending"][0]
    assert entry["request_number"] == rid
    assert entry["created_at"] == env.now.isoformat()
    assert entry["pending_deadline"] == (env.now + timedelta(minutes=90)).isoformat()
    assert entry["justification"] == "need it"
    assert entry["state"] == "pending" and entry["state_source"] is None
    assert entry["items"] == [
        {
            "backend": "imap",
            "account": "work",
            "resource": "Sent",
            "label": "Sent mail",
            "ops": ["send"],
            "expires_at": (env.now + timedelta(days=2)).isoformat(),
        }
    ]

    active = snap["active"][0]
    assert active["state"] == "active" and active["state_source"] == "approval"
    assert active["expires_at"] == (env.now + timedelta(hours=2)).isoformat()
    assert active["decided_at"] == env.now.isoformat()


async def test_snapshot_reports_synthesized_timeout_state_in_its_own_slice(env: Env) -> None:
    started = env.now
    rid = env.submit()
    env.advance(hours=13)
    snap = env.core.snapshot()
    assert snap["pending"] == []
    assert snap["counts"]["pending"] == 0 and snap["counts"]["expired_recent"] == 1
    entry = snap["expired_recent"][0]
    assert entry["request_number"] == rid
    assert entry["state"] == "expired"
    assert entry["state_source"] == "pending_timeout"
    assert entry["created_at"] == started.isoformat()
    assert entry["pending_deadline"] == (started + timedelta(hours=12)).isoformat()
    # Effective-state recompute on read, not the stored 'pending' label.
    assert env.store._row(rid)["state"] == "pending"  # noqa: SLF001 - stored vs effective


async def test_snapshot_expired_active_grant_and_terminal_rows_excluded(env: Env) -> None:
    active = env.submit()
    await env.core.apply_decision(active, "approve", "1h", announce=False)
    rejected = env.submit()
    await env.core.apply_decision(rejected, "reject", None, announce=False)
    env.advance(hours=2)

    snap = env.core.snapshot()
    assert snap["pending"] == [] and snap["active"] == []
    assert [entry["request_number"] for entry in snap["expired_recent"]] == [active]
    assert snap["expired_recent"][0]["state_source"] == "grant_expiry"
    # The rejected row is terminal and never appears in the read model.
    numbers = {
        entry["request_number"]
        for entry in (*snap["pending"], *snap["active"], *snap["expired_recent"])
    }
    assert rejected not in numbers


async def test_snapshot_empty(env: Env) -> None:
    snap = env.core.snapshot()
    assert snap["pending"] == [] and snap["active"] == []
    assert snap["counts"] == {"pending": 0, "active": 0, "expired_recent": 0}
    assert snap["pending_timeout_seconds"] == 12 * 3600


# ------------------------------------------------------------- surface auth


def test_build_refuses_unset_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    env = Env(tmp_path)
    with pytest.raises(ValueError, match="unset or empty"):
        build_approval_surface_app(env.core, TOKEN_ENV)


def test_build_refuses_short_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(TOKEN_ENV, "too-short")
    env = Env(tmp_path)
    with pytest.raises(ValueError, match="shorter than"):
        build_approval_surface_app(env.core, TOKEN_ENV)
    assert MIN_TOKEN_LENGTH == 32


def test_build_refuses_unknown_option_and_bad_core(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="unknown option"):
        build_approval_surface_app(env.core, TOKEN_ENV, {"mountprefx": "/x"})
    with pytest.raises(ValueError, match="apply_decision"):
        build_approval_surface_app(object(), TOKEN_ENV)
    with pytest.raises(ValueError, match="bearer"):
        ApprovalSurfaceApp(env.core, "short")


async def test_auth_is_refused_before_any_body_parse(env: Env) -> None:
    app = env.app()
    status, payload = await call(app, "GET", "/approval/snapshot", token=None)
    assert status == 401 and payload == {"ok": False, "error": "unauthorized"}
    status, payload = await call(app, "GET", "/approval/snapshot", token="wrong" + "s" * 35)
    assert status == 401
    # Garbage body + no credential: 401, never a parse error, nothing applied.
    status, payload = await call(app, "POST", "/approval/decision", token=None, raw_body=b"{{{")
    assert status == 401
    status, _ = await call(app, "GET", "/approval/health", token=None)
    assert status == 401
    assert env.transport.sent == []


async def test_snapshot_and_health_over_http(env: Env) -> None:
    app = env.app()
    status, payload = await call(app, "GET", "/approval/snapshot")
    assert status == 200 and payload["counts"]["pending"] == 0
    status, payload = await call(app, "GET", "/approval/health")
    assert status == 200
    assert payload["ok"] is True
    assert payload["version"]
    assert payload["gateway_configured"] is False  # no audit chain on this core


async def test_health_reports_configured_with_audit(audited: Env) -> None:
    app = audited.app(broker_id="data", version="9.9.9")
    status, payload = await call(app, "GET", "/approval/health")
    assert status == 200
    assert payload == {
        "ok": True,
        "surface": "approval",
        "version": "9.9.9",
        "gateway_configured": True,
        "broker_id": "data",
    }


async def test_mount_prefix_and_root_path(env: Env) -> None:
    app = env.app(mount_prefix="/broker/approval")
    assert app.mount_prefix == "/broker/approval"
    status, _ = await call(app, "GET", "/broker/approval/snapshot")
    assert status == 200
    status, _ = await call(app, "GET", "/snapshot", root_path="/broker/approval")
    assert status == 200
    status, _ = await call(app, "GET", "/broker/approval/snapshot/")
    assert status == 200
    status, payload = await call(app, "GET", "/broker/approval/nope")
    assert status == 404 and payload["error"] == "not_found"
    status, payload = await call(app, "GET", "/broker/approval/decision")
    assert status == 405 and payload["allow"] == "POST"


# ------------------------------------------------------------- surface decide


async def test_http_approve_returns_applied_structured_body(env: Env) -> None:
    rid = env.submit()
    app = env.app()
    status, payload = await call(
        app,
        "POST",
        "/approval/decision",
        body={"request_number": rid, "action": "approve", "duration_seconds": 3600},
    )
    assert status == 200  # never a 4xx for a decision answer
    assert payload["outcome"] == "applied"
    assert payload["state"] == "active"
    assert payload["expires_at"] == (env.now + timedelta(hours=1)).isoformat()
    assert payload["http_hint"] == 200
    assert payload["principal"] == "approver:approval-surface"
    assert payload["notified"] is False and payload["announced"] is False
    assert env.store.get_record(rid).state == "active"
    assert env.transport.sent == []


async def test_http_refusals_are_success_answers_with_true_state(env: Env) -> None:
    app = env.app()
    rid = env.submit()
    await env.core.apply_decision(rid, "approve", None, announce=False)

    status, payload = await call(
        app, "POST", "/approval/decision", body={"request_number": rid, "action": "approve"}
    )
    assert status == 200
    assert payload["outcome"] == "refused" and payload["refusal"] == "already_decided"
    assert payload["state"] == "active" and payload["http_hint"] == 409

    status, payload = await call(
        app, "POST", "/approval/decision", body={"request_number": 4242, "action": "reject"}
    )
    assert status == 200
    assert payload["outcome"] == "refused" and payload["refusal"] == "unknown_request"
    assert payload["http_hint"] == 409

    expired = env.submit()
    env.advance(hours=13)
    status, payload = await call(
        app, "POST", "/approval/decision", body={"request_number": expired, "action": "reject"}
    )
    assert status == 200
    assert payload["refusal"] == "expired" and payload["state"] == "expired"
    assert payload["state_source"] == "pending_timeout"
    assert payload["http_hint"] == 410


async def test_http_revoke_pending_rejects_with_pending_revoke_source(env: Env) -> None:
    rid = env.submit()
    status, payload = await call(
        env.app(), "POST", "/approval/decision", body={"request_number": rid, "action": "revoke"}
    )
    assert status == 200 and payload["outcome"] == "applied"
    assert payload["state"] == "rejected" and payload["state_source"] == "pending_revoke"


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ({"action": "approve"}, "invalid_request_number"),
        ({"request_number": 0, "action": "approve"}, "invalid_request_number"),
        ({"request_number": "1", "action": "approve"}, "invalid_request_number"),
        ({"request_number": 1, "action": "undo"}, "invalid_action"),
        ({"request_number": 1}, "invalid_action"),
        ({"request_number": 1, "action": "approve", "duration_seconds": 0}, "invalid_duration"),
        ({"request_number": 1, "action": "approve", "duration_seconds": -5}, "invalid_duration"),
        ({"request_number": 1, "action": "approve", "duration_seconds": "3600"}, "invalid_duration"),
        ({"request_number": 1, "action": "approve", "decision_id": ""}, "invalid_decision_id"),
    ],
)
async def test_invalid_bodies_are_refused_and_audited(
    audited: Env, body: dict, reason: str
) -> None:
    status, payload = await call(audited.app(), "POST", "/approval/decision", body=body)
    assert status == 200
    assert payload["outcome"] == "refused"
    assert payload["refusal"] == reason
    assert payload["http_hint"] in (400, 413, 422)
    assert payload["audit_head"] == audited.audit.head_hash
    # Nothing applied, and the refusal is IN the chain with a fixed reason.
    assert audited.store.all_records() == []
    lines = audited.audit_lines()
    assert len(lines) == 1
    assert lines[0]["decision"] == "refused" and lines[0]["reason"] == reason
    assert lines[0]["principal"] == "surface:approval"
    assert verify_chain(audited.audit_path).ok


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b'"approve"', b"\xff\xfe"])
async def test_malformed_body_refused_nothing_applied_audited(audited: Env, raw: bytes) -> None:
    status, payload = await call(audited.app(), "POST", "/approval/decision", raw_body=raw)
    assert status == 200
    assert payload["outcome"] == "refused"
    assert payload["refusal"] == "malformed_body"
    assert payload["reason"] == "malformed_body"
    assert payload["state"] is None and payload["item_count"] == 0
    assert audited.store.all_records() == []
    lines = audited.audit_lines()
    assert lines and lines[-1]["decision"] == "refused"
    assert lines[-1]["reason"] == "malformed_body"
    assert verify_chain(audited.audit_path).ok


async def test_oversized_body_refused_before_parse(audited: Env) -> None:
    app = audited.app(max_body_bytes=64)
    blob = b'{"request_number": 1, "action": "approve", "pad": "' + b"x" * 200 + b'"}'
    status, payload = await call(app, "POST", "/approval/decision", raw_body=blob)
    assert status == 200
    assert payload["refusal"] == "body_too_large" and payload["http_hint"] == 413
    assert audited.store.all_records() == []
    assert audited.audit_lines()[-1]["reason"] == "body_too_large"


async def test_decision_id_replay_is_idempotent(env: Env, tmp_path: Path) -> None:
    env.audit = AuditLog(env.audit_path, env.clock)
    env.core._audit = env.audit  # noqa: SLF001 - wiring the chain into the fixture core
    rid = env.submit()
    app = env.app()
    body = {"request_number": rid, "action": "approve", "decision_id": "dec-1"}
    first_status, first = await call(app, "POST", "/approval/decision", body=body)
    lines_after_first = len(env.audit_lines())
    second_status, second = await call(app, "POST", "/approval/decision", body=body)
    assert first_status == second_status == 200
    assert first["outcome"] == "applied" and second["outcome"] == "applied"
    assert second["replayed"] is True
    assert second["audit_head"] == first["audit_head"]
    # Replayed from the cache: the core was never asked a second time.
    assert len(env.audit_lines()) == lines_after_first
    assert env.store.get_record(rid).state == "active"


async def test_decision_id_is_bounded_to_the_replay_cache(env: Env) -> None:
    app = env.app()
    app._replays = type(app._replays)()  # noqa: SLF001 - fresh bounded cache
    from access_broker_core.approvals import MAX_REPLAY_ENTRIES

    for index in range(MAX_REPLAY_ENTRIES + 5):
        rid = env.submit()
        await call(
            app,
            "POST",
            "/approval/decision",
            body={"request_number": rid, "action": "reject", "decision_id": f"d-{index}"},
        )
    assert len(app._replays) == MAX_REPLAY_ENTRIES  # noqa: SLF001


# ------------------------------------------------------- protected surfaces


def test_approval_surface_ids_are_route_shaped() -> None:
    ids = approval_surface_ids("/broker/approval")
    assert APPROVAL_SURFACE_ID in ids
    assert {
        "/broker/approval",
        "/broker/approval/snapshot",
        "/broker/approval/decision",
        "/broker/approval/health",
    } <= ids
    assert approval_surface_ids("") == frozenset(
        {APPROVAL_SURFACE_ID, "/snapshot", "/decision", "/health"}
    )


def test_register_protected_surfaces_into_a_context_frozenset() -> None:
    class Context:
        def __init__(self) -> None:
            self.protected_surfaces = frozenset({"/approvalroom"})

        def is_protected_surface(self, resource: str) -> bool:
            return resource in self.protected_surfaces

    ctx = Context()
    merged = register_protected_surfaces(ctx, approval_surface_ids("/approval"))
    assert isinstance(ctx.protected_surfaces, frozenset)
    assert "/approvalroom" in merged and "/approval/decision" in merged
    assert ctx.is_protected_surface("/approval/snapshot")
    assert not ctx.is_protected_surface("/some/other/room")


def test_register_protected_surfaces_into_a_mutable_set_and_union_only() -> None:
    surfaces: set[str] = {"/room"}
    merged = register_protected_surfaces(surfaces, ["/approval"])
    assert surfaces == {"/room", "/approval"}
    assert merged == frozenset(surfaces)
    register_protected_surfaces(surfaces, ["/approval"])  # idempotent
    assert surfaces == {"/room", "/approval"}


def test_register_protected_surfaces_refuses_bad_input() -> None:
    with pytest.raises(TypeError, match="set or expose"):
        register_protected_surfaces(object(), ["/approval"])
    with pytest.raises(TypeError, match="must be a string"):
        register_protected_surfaces(set(), [1])
    with pytest.raises(ValueError, match="non-empty"):
        register_protected_surfaces(set(), ["  "])

    class Context:
        protected_surfaces = 42

    with pytest.raises(TypeError, match="protected_surfaces must be"):
        register_protected_surfaces(Context(), ["/approval"])


def test_surface_ids_property_matches_helper(env: Env) -> None:
    app = env.app(mount_prefix="/mcp/approval")
    assert app.surface_ids == approval_surface_ids("/mcp/approval")
