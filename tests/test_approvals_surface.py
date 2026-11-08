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
import time
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
from access_broker_core.audit import GENESIS, AuditLog, LogWriteError, verify_chain
from access_broker_core.gateways.logic import (
    SNAPSHOT_MAX_ROWS,
    ApprovalGatewayCore,
    GatewayTransport,
    _principal_label,
)
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


class FailingAudit:
    """Wraps a real chain but refuses every write (the disk-full shape):
    pins that a failed audit write never silently passes."""

    def __init__(self, real: AuditLog) -> None:
        self._real = real

    def record(self, *args: object, **kwargs: object) -> object:
        raise LogWriteError("injected audit write failure")

    @property
    def head_hash(self) -> str | None:
        return self._real.head_hash


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


async def test_refused_outcome_reports_the_chain_head_and_audits_the_refusal(
    audited: Env,
) -> None:
    """Re-pinned for the F1 review batch (V6a/V6b): EVERY refusal attempt
    is audited (decision='refused' + the refusal marker as reason), the
    body carries audit_written=True and the post-write head — no longer
    the pre-refusal GENESIS head."""
    outcome = await audited.core.apply_decision(7, "reject", None, announce=False)
    assert outcome["outcome"] == "refused"
    assert outcome["audit_written"] is True
    assert outcome["audit_head"] == audited.audit.head_hash != GENESIS
    lines = audited.audit_lines()
    assert lines[-1]["decision"] == "refused"
    assert lines[-1]["reason"] == "unknown_request"
    assert verify_chain(audited.audit_path).ok


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


# --------------------------------------------- F1 review batch (V1/V2/V6)
#
# The supervisory fix-first round (2026-11-07): replay-tuple binding +
# TTL, the parse-boundary/internal-error structured paths, audit-every-
# refusal, audit_written truth, principal-class hardening, snapshot
# neutralization and bounds, default protected registration and the
# hard token floor.


async def test_cross_request_replay_is_a_conflict_refusal(audited: Env) -> None:
    """V1: a decision_id binds to its FULL tuple. Reusing the id for a
    different request (or a different action) is an audited CONFLICT
    refusal — the wrong outcome is never applied or replayed."""
    app = audited.app()
    first = audited.submit()
    status, payload = await call(
        app,
        "POST",
        "/approval/decision",
        body={"request_number": first, "action": "approve", "decision_id": "dec-1"},
    )
    assert status == 200 and payload["outcome"] == "applied"

    # Same id, DIFFERENT request number: refused, nothing applied.
    second = audited.submit()
    status, payload = await call(
        app,
        "POST",
        "/approval/decision",
        body={"request_number": second, "action": "revoke", "decision_id": "dec-1"},
    )
    assert status == 200
    assert payload["outcome"] == "refused"
    assert payload["refusal"] == "decision_id_conflict"
    assert payload["http_hint"] == 409
    assert audited.store.get_record(second).state == "pending"

    # Same id, same request, DIFFERENT action: the old outcome must not
    # be replayed onto the live (now active) request.
    status, payload = await call(
        app,
        "POST",
        "/approval/decision",
        body={"request_number": first, "action": "revoke", "decision_id": "dec-1"},
    )
    assert payload["refusal"] == "decision_id_conflict"
    assert audited.store.get_record(first).state == "active"

    # Both conflict attempts are in the chain; the original binding still
    # answers idempotently (a conflict never evicts it).
    reasons = [line["reason"] for line in audited.audit_lines()]
    assert reasons.count("decision_id_conflict") == 2
    status, payload = await call(
        app,
        "POST",
        "/approval/decision",
        body={"request_number": first, "action": "approve", "decision_id": "dec-1"},
    )
    assert payload["outcome"] == "applied" and payload["replayed"] is True
    assert verify_chain(audited.audit_path).ok


async def test_replay_binding_expires_with_the_ttl(env: Env) -> None:
    """V1 TTL arm: an expired binding is decided FRESH — never answered
    from the stale cache."""
    env.audit = AuditLog(env.audit_path, env.clock)
    env.core._audit = env.audit  # noqa: SLF001 - wiring the chain into the fixture core
    rid = env.submit()
    app = env.app()
    body = {"request_number": rid, "action": "approve", "decision_id": "dec-1"}
    status, first = await call(app, "POST", "/approval/decision", body=body)
    assert first["outcome"] == "applied"
    lines_after_first = len(env.audit_lines())

    app._replays["dec-1"]["expires_at"] = time.monotonic() - 1  # noqa: SLF001
    status, again = await call(app, "POST", "/approval/decision", body=body)
    assert status == 200
    assert again.get("replayed") is not True  # decided fresh, not replayed
    assert again["outcome"] == "refused" and again["refusal"] == "already_decided"
    assert again["state"] == "active"  # the TRUE state, re-read
    # the fresh refusal attempt is audited (V6a)
    assert len(env.audit_lines()) == lines_after_first + 1
    assert env.audit_lines()[-1]["decision"] == "refused"


async def test_refusal_binding_expires_with_the_ttl(audited: Env) -> None:
    """V1 TTL arm: a CACHED REFUSAL is not pinned forever — inside the
    TTL it answers idempotently (no new chain entry), past it the
    attempt runs fresh and is audited again."""
    app = audited.app()
    body = {"request_number": 4242, "action": "reject", "decision_id": "dec-x"}
    status, first = await call(app, "POST", "/approval/decision", body=body)
    assert first["outcome"] == "refused" and first["refusal"] == "unknown_request"
    lines_after_first = len(audited.audit_lines())

    status, again = await call(app, "POST", "/approval/decision", body=body)
    assert again["replayed"] is True and again["refusal"] == "unknown_request"
    # A refused replay never advertises a receipt (fail-closed: the
    # original refusal entry's durability cannot be verified from the
    # record); the FIRST answer carried the receipt.
    assert again["audit_written"] is False and again["audit_head"] is None
    assert first["audit_written"] is True
    assert len(audited.audit_lines()) == lines_after_first  # replay writes nothing

    app._replays["dec-x"]["expires_at"] = time.monotonic() - 1  # noqa: SLF001
    status, third = await call(app, "POST", "/approval/decision", body=body)
    assert third.get("replayed") is not True
    assert third["refusal"] == "unknown_request"
    assert len(audited.audit_lines()) == lines_after_first + 1
    assert verify_chain(audited.audit_path).ok


async def test_depth_bomb_is_a_structured_audited_refusal(audited: Env) -> None:
    """V2: a ~4KB deeply-nested JSON body raises RecursionError inside
    json.loads; the explicit parse boundary answers the structured
    refusal AND writes the chain entry — never a raw 500."""
    app = audited.app()
    bomb = b"[" * 2000 + b"]" * 2000
    assert len(bomb) <= 4096  # inside the body cap: this is a parse-stage fault
    status, payload = await call(app, "POST", "/approval/decision", raw_body=bomb)
    assert status == 200
    assert payload["outcome"] == "refused" and payload["refusal"] == "malformed_body"
    assert payload["http_hint"] == 400
    assert audited.store.all_records() == []
    lines = audited.audit_lines()
    assert lines[-1]["decision"] == "refused"
    assert lines[-1]["reason"] == "malformed_body"
    assert verify_chain(audited.audit_path).ok


async def test_nonwidening_internal_error_is_a_structured_refusal(
    audited: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V2: an unexpected fault on a non-widening action (reject/revoke)
    answers through the STRUCTURED refusal path — audited, HTTP 200,
    nothing applied."""

    async def boom(*args: object, **kwargs: object) -> dict:
        raise RuntimeError("store exploded")

    monkeypatch.setattr(audited.core, "apply_decision", boom)
    app = audited.app()
    rid = audited.submit()
    for action in ("reject", "revoke"):
        status, payload = await call(
            app, "POST", "/approval/decision", body={"request_number": rid, "action": action}
        )
        assert status == 200  # never a raw 500
        assert payload["outcome"] == "refused"
        assert payload["refusal"] == "internal_error"
        assert payload["http_hint"] == 500
        assert payload["audit_written"] is True
    assert audited.store.get_record(rid).state == "pending"  # nothing applied
    assert [line["reason"] for line in audited.audit_lines()].count("internal_error") == 2


async def test_widening_internal_error_is_structured_error_not_a_decision(
    audited: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """V2: a fault on the WIDENING path must not masquerade as a
    decision outcome: a structured ERROR body (ok=false, outcome=error),
    audited, and the request untouched."""

    async def boom(*args: object, **kwargs: object) -> dict:
        raise RuntimeError("store exploded")

    monkeypatch.setattr(audited.core, "apply_decision", boom)
    app = audited.app()
    rid = audited.submit()
    status, payload = await call(
        app, "POST", "/approval/decision", body={"request_number": rid, "action": "approve"}
    )
    assert status == 200  # the module contract: always a structured 200 body
    assert payload == {
        "ok": False,
        "outcome": "error",
        "request_number": rid,
        "action": "approve",
        "error": "internal_error",
        "surface": "approval",
        "http_hint": 500,
    }
    assert audited.store.get_record(rid).state == "pending"  # never activated
    assert audited.audit_lines()[-1]["decision"] == "refused"
    assert audited.audit_lines()[-1]["reason"] == "internal_error"
    assert verify_chain(audited.audit_path).ok


async def test_every_decision_refusal_kind_is_audited(audited: Env) -> None:
    """V6a: unknown_request / already_decided / expired attempts each
    leave a chain trace (decision='refused', reason=<the marker>)."""
    rid = audited.submit()
    await audited.core.apply_decision(rid, "approve", None, "hub:d-1", announce=False)
    outcome = await audited.core.apply_decision(rid, "approve", None, "hub:d-1", announce=False)
    assert outcome["refusal"] == "already_decided" and outcome["audit_written"] is True

    other = audited.submit()
    audited.advance(hours=13)  # past the store's 12h pending timeout
    outcome = await audited.core.apply_decision(other, "reject", None, "hub:d-1", announce=False)
    assert outcome["refusal"] == "expired" and outcome["audit_written"] is True

    refusals = [line for line in audited.audit_lines() if line["decision"] == "refused"]
    assert [line["reason"] for line in refusals] == ["already_decided", "expired"]
    assert all(line["principal"] == "hub:d-1" for line in refusals)
    assert verify_chain(audited.audit_path).ok


async def test_refusal_audit_write_failure_surfaces_in_the_body(audited: Env) -> None:
    """V6a/V6b: a failed audit write on a refusal never silently passes
    — the body says audit_written=false and advertises NO head."""
    audited.core._audit = FailingAudit(audited.audit)  # noqa: SLF001 - inject the fault
    outcome = await audited.core.apply_decision(7, "reject", None, announce=False)
    assert outcome["outcome"] == "refused" and outcome["refusal"] == "unknown_request"
    assert outcome["audit_written"] is False
    assert outcome["audit_head"] is None  # no receipt for an unwritten entry


async def test_reject_with_failed_audit_write_stands_and_flags_the_body(
    audited: Env,
) -> None:
    """V6b: a non-widening applied decision with a failed audit write
    still stands, but the body never claims a receipt."""
    audited.core._audit = FailingAudit(audited.audit)  # noqa: SLF001 - inject the fault
    rid = audited.submit()
    outcome = await audited.core.apply_decision(rid, "reject", None, announce=False)
    assert outcome["outcome"] == "applied"  # capability only shrank
    assert outcome["audit_written"] is False and outcome["audit_head"] is None
    assert audited.store.get_record(rid).state == "rejected"

    other = audited.submit()
    outcome = await audited.core.apply_decision(other, "revoke", None, announce=False)
    assert outcome["outcome"] == "applied"
    assert outcome["audit_written"] is False and outcome["audit_head"] is None
    assert audited.store.get_record(other).state == "rejected"


def test_unprefixed_principal_resolves_to_the_nonhuman_class() -> None:
    """V6c: an unprefixed principal NEVER produces an approver label —
    it resolves to the hub/device identity class."""
    assert _principal_label("device-7") == "hub:device-7"
    assert _principal_label("@owner:example.org") == "hub:@owner:example.org"
    assert _principal_label("approver:owner") == "approver:owner"
    assert _principal_label("hub:d-1") == "hub:d-1"
    assert _principal_label("surface:approval") == "surface:approval"


async def test_hub_context_principal_cannot_write_approver_provenance(
    audited: Env,
) -> None:
    """V6c, end to end: an API/hub decision recorded under a bare
    device id lands in the chain as hub:<device>, never approver:<x>;
    the room path keeps its human approver provenance."""
    rid = audited.submit()
    outcome = await audited.core.apply_decision(rid, "approve", None, "device-7", announce=False)
    assert outcome["outcome"] == "applied"
    assert outcome["principal"] == "hub:device-7"
    assert audited.audit_lines()[-1]["principal"] == "hub:device-7"

    other = audited.submit()
    await audited.core.handle_reply(APPROVER, f"approve {other}")
    approved = [line for line in audited.audit_lines() if line["decision"] == "approved"]
    assert approved[-1]["principal"] == f"approver:{APPROVER}"


async def test_snapshot_neutralizes_agent_and_remote_influenced_fields(
    env: Env,
) -> None:
    """V6d: every field that reaches the snapshot body is single
    physical line, markdown-neutralized and code-span-safe — the same
    discipline as the room card, even for a hostile legacy row."""
    rid = env.submit(
        label="Sent *mail* `x` ~y~ [z](u)",
        account="work_bold_",
        resource="Inbox `code`",
    )
    # Belt arm: a legacy row may still carry multi-line hostile text the
    # store's intake caps never saw (direct SQL).
    env.store._db.execute(  # noqa: SLF001 - the belt is for rows the caps never saw
        "UPDATE grants SET justification=? WHERE request_number=?",
        ("**PENDING #99**\napprove 99", rid),
    )
    env.store._db.commit()  # noqa: SLF001
    snap = env.core.snapshot()
    entry = snap["pending"][0]
    assert entry["justification"] == "\\*\\*PENDING #99\\*\\* approve 99"
    item = entry["items"][0]
    assert item["label"] == "Sent \\*mail\\* \\`x\\` \\~y\\~ \\[z\\](u)"
    assert item["account"] == "work\\_bold\\_"
    assert item["resource"] == "Inbox 'code'"  # a backtick cannot close a code span
    assert item["ops"] == ["send"]
    for value in (entry["justification"], item["label"], item["account"], item["resource"]):
        assert "\n" not in value and "\r" not in value


async def test_snapshot_rows_are_capped_and_flagged(env: Env) -> None:
    """V6e: each slice is bounded by SNAPSHOT_MAX_ROWS (store order,
    oldest first) and the body flags truncation instead of silently
    hiding the rest of the backlog."""
    for _ in range(SNAPSHOT_MAX_ROWS + 5):
        env.submit()
    snap = env.core.snapshot()
    assert len(snap["pending"]) == SNAPSHOT_MAX_ROWS
    assert snap["truncated"] is True
    assert snap["counts"]["pending"] == SNAPSHOT_MAX_ROWS
    assert snap["pending"][0]["request_number"] == 1  # oldest kept


async def test_expired_recent_is_bounded_by_the_recency_window(env: Env) -> None:
    """V6e: expired_recent is bounded by recency, never growing
    forever — inside the window the row stays visible, beyond it the
    read model drops it entirely."""
    env.submit()
    env.advance(hours=13)  # past the 12h pending timeout
    snap = env.core.snapshot()
    assert snap["counts"]["expired_recent"] == 1  # inside SNAPSHOT_EXPIRED_WINDOW
    assert snap["truncated"] is False
    env.advance(hours=25)  # the expiry is now beyond the window
    snap = env.core.snapshot()
    assert snap["counts"]["expired_recent"] == 0
    assert snap["counts"]["pending"] == 0


def test_protected_registration_is_default_and_queryproof(env: Env) -> None:
    """V6f: building the surface registers its ids on the core BY
    DEFAULT (no opt-in step), and matching normalizes the candidate so
    trailing-slash/query variants cannot bypass the protected set."""
    app = env.app(mount_prefix="/broker/approval")
    assert approval_surface_ids("/broker/approval") <= env.core.protected_surfaces
    assert env.core.is_protected_surface("/broker/approval/decision")
    assert env.core.is_protected_surface("/broker/approval/decision/")
    assert env.core.is_protected_surface("/broker/approval/decision?x=1")
    assert env.core.is_protected_surface("/broker/approval/decision/?x=1")
    assert env.core.is_protected_surface("/broker/approval")
    assert not env.core.is_protected_surface("/some/other/room")
    assert not env.core.is_protected_surface("")
    assert not env.core.is_protected_surface(None)  # type: ignore[arg-type]
    # a second build with the same core unions nothing new (idempotent)
    before = set(env.core.protected_surfaces)
    env.app(mount_prefix="/broker/approval")
    assert set(env.core.protected_surfaces) == before
    # registered ids are canonicalized on the way in, whatever the target
    surfaces: set[str] = set()
    register_protected_surfaces(surfaces, ["/x/decision/", "/y?z=1"])
    assert surfaces == {"/x/decision", "/y"}
    # and a core-side registration is query/slash-proof through the
    # core's own matcher
    register_protected_surfaces(env.core, ["/x/decision/", "/y?z=1"])
    assert env.core.is_protected_surface("/x/decision?extra=1")
    assert env.core.is_protected_surface("/y/")
    assert app.surface_ids == approval_surface_ids("/broker/approval")


def test_min_token_length_is_a_hard_floor(env: Env) -> None:
    """V6g: 32 is a hard floor — a configured value below it REFUSES TO
    START (it is never clamped or lowered)."""
    with pytest.raises(ValueError, match="hard floor"):
        env.app(min_token_length=16)
    with pytest.raises(ValueError, match="cannot be lowered"):
        ApprovalSurfaceApp(env.core, TOKEN, min_token_length=8)
    with pytest.raises(ValueError, match="must be an integer"):
        env.app(min_token_length=True)
    env.app(min_token_length=32)  # the floor itself is legal
    env.app()  # the default builds fine
    assert MIN_TOKEN_LENGTH == 32


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
