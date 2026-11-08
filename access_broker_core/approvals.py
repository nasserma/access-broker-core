"""REST approvals surface: the pulled read+decide API of the approval plane.

The design note's D-M default (sixth pass) flipped the relay to a
**pulled REST surface**: each broker exposes a small human-plane
read+decide API beside its MCP surface, a co-located hub polls it, and
the phone never reaches a broker. This module is the CORE half of that
surface — one mount helper every broker adopts, so the routes, the
credential class and the refusal semantics are identical everywhere
instead of re-implemented four times.

Three routes (all behind the same bearer credential):

- ``GET  <prefix>/snapshot`` — ``ApprovalGatewayCore.snapshot()``: every
  pending request (with its real deadline and the store's configured
  pending timeout), every active grant (with its expiry) and a separate
  ``expired_recent`` slice. Read-only.
- ``POST <prefix>/decision`` — a bounded JSON body
  (``request_number``, ``action``, optional ``duration_seconds``,
  optional ``decision_id``) applied through
  ``ApprovalGatewayCore.apply_decision(..., announce=False)``. The
  answer is ALWAYS an HTTP-200 structured body: ``applied`` or
  ``refused``. A refusal is an AUTHORITATIVE success answer — it is
  never a 4xx. The body carries ``http_hint`` (409 for
  already-decided/unknown, 410 for expired) so a client can style it,
  and it always carries the TRUE state + state_source.
- ``GET  <prefix>/health`` — ok, version, gateway_configured (plus
  broker_id when configured).

ASGI, not a framework: the core venv ships no web framework (the mcp SDK
builds on starlette, but the core must not depend on it), so this is a
plain ASGI sub-app. Mount it beside the broker's MCP app with any ASGI
mount (Starlette ``Mount``, ``uvicorn --root-path``, or a hand-rolled
path dispatcher): the ``mount_prefix`` option names the prefix, and the
app strips it from ``path``/``root_path`` before routing, so a mount at
``/mcp`` with ``mount_prefix='/approval'`` serves ``/mcp/approval/...``.

THIRD CREDENTIAL CLASS. This surface carries its own bearer token — the
approval-plane (hub/app) credential — read from the NAMED environment
variable at build time. It is SEPARATE, one-way, from:

- the AGENT credential (the MCP tool surface's token), and
- the TRANSFER credential (the data broker's ``/transfer`` token).

The core enforces set/unset and a minimum length (refuse-to-start: an
unauthenticated approval surface is never built, and a short token is
never accepted). One-way separation (the approval token is refused at
``/mcp`` and the agent token is refused here) is the ADOPTER's
refuse-to-start guard, mirroring the data broker's template
(``data_broker/server.py`` token-class guard); the core documents the
class, it cannot see the other brokers' env vars.

AUTH ORDER: the bearer is compared (constant-time, via the shared
static helper) BEFORE any body byte is parsed or any route is
dispatched, so an unauthenticated probe learns nothing about routes,
body shape or request state.

NO agent-facing tool is added anywhere: the MCP tool registration is
untouched. An agent can neither read this surface (no credential) nor
request access TO it — ``approval_surface_ids()`` +
``register_protected_surfaces()`` put every route id into the broker's
protected-surface set, the same guard the communications broker applies
to its approval room (an agent-influenced ``request_access`` naming an
approval route is refused before the wall sees it). As of this round
(review V6f) that registration is BY DEFAULT: building the surface
unions its route ids into ``core.protected_surfaces`` (the core exposes
``core.is_protected_surface``), matched on NORMALIZED paths (query
string and trailing slashes stripped), so a broker does not need a
separate opt-in step a wall could forget and a variant path cannot
bypass the set.

DECISION-ID REPLAY (review V1): a client ``decision_id`` binds the id
to the FULL decision tuple (request_number, action, duration) for a
bounded TTL (``REPLAY_TTL_SECONDS``). A retry with the SAME tuple
answers idempotently — re-read from the EFFECTIVE grant state, never
from a cached outcome body. A retry reusing the id with a DIFFERENT
tuple is a decision-id CONFLICT refusal (audited, nothing applied),
never a replay of the old outcome. Cache entries — refusals included —
expire with the TTL, so a mistyped id can never pin a stale answer;
after expiry the id is decided fresh.

UNDO LIMITATION (review V6h): the 15s undo window is armed on
reject/revoke exactly as in the room path, but it can be consumed ONLY
from the approval ROOM (``undo <id>`` typed there creates a NEW pending
request). An API decision cannot be undone from the API in this
release — there is no API undo verb (an owner decision, pending).
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from datetime import timedelta
from importlib import metadata
from typing import Any

from access_broker_core.auth.static import check_static_credential
from access_broker_core.gateways.logic import DECISION_ACTIONS, normalize_surface_id

logger = logging.getLogger(__name__)

#: Stable id of the surface itself; registered in the protected set so
#: an agent can never name the approval plane as a target resource.
APPROVAL_SURFACE_ID = "approval-surface"

DEFAULT_MOUNT_PREFIX = "/approval"

#: Minimum bearer length for the third credential class. Below this the
#: surface refuses to build (the token is the only thing standing
#: between a poller and a grant decision).
MIN_TOKEN_LENGTH = 32

#: Bounded request body: a decision is four small fields; anything
#: larger is refused before it is parsed.
MAX_BODY_BYTES = 4096

#: The duration grammar's ceiling (999 of the largest unit) expressed in
#: seconds — the REST body speaks whole seconds, the grammar caps at
#: 999d, and the core's store never sees an unbounded expiry from here.
MAX_DURATION_SECONDS = 999 * 24 * 60 * 60

#: Replay cache bound: one entry per client-supplied decision_id, FIFO.
MAX_REPLAY_ENTRIES = 256

#: Replay-window TTL in seconds (review V1): a cached decision binding —
#: refusals included — expires after this window, after which the same
#: decision_id is decided FRESH (a mistyped id can never pin a stale
#: answer; nothing is ever replayed from a cached outcome body, only
#: re-read from the effective grant state inside the window).
REPLAY_TTL_SECONDS = 300.0

_MAX_DECISION_ID_LENGTH = 128
_MAX_SURFACE_ID_LENGTH = 256

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")

#: Fixed refusal reasons for bodies that never reach the decision path.
#: Each one is AUDITED (decision='refused') so a malformed probe leaves a
#: chain trace even though nothing was applied.
REASON_MALFORMED_BODY = "malformed_body"
REASON_BODY_TOO_LARGE = "body_too_large"
REASON_INVALID_REQUEST_NUMBER = "invalid_request_number"
REASON_INVALID_ACTION = "invalid_action"
REASON_INVALID_DURATION = "invalid_duration"
REASON_INVALID_DECISION_ID = "invalid_decision_id"
REASON_INVALID_REQUEST = "invalid_request"
#: A decision_id reused for a DIFFERENT decision tuple (review V1): a
#: conflict, never a replay of the old outcome — nothing is applied.
REASON_DECISION_ID_CONFLICT = "decision_id_conflict"
#: The decision path failed unexpectedly (review V2): answered through
#: the STRUCTURED refusal/error paths (audited, HTTP 200 body), never a
#: raw 500 without a chain trace.
REASON_INTERNAL_ERROR = "internal_error"

_SURFACE_OPTION_KEYS = frozenset(
    {
        "mount_prefix",
        "principal",
        "broker_id",
        "version",
        "max_body_bytes",
        "min_token_length",
    }
)

#: refused outcome -> the status a client should style it with (carried
#: INSIDE the body; the HTTP status of a decision answer is always 200).
_HTTP_HINTS = {
    "expired": 410,
    "already_decided": 409,
    "unknown_request": 409,
    "audit_write_failed": 500,
    REASON_MALFORMED_BODY: 400,
    REASON_BODY_TOO_LARGE: 413,
    REASON_INVALID_REQUEST_NUMBER: 400,
    REASON_INVALID_ACTION: 400,
    REASON_INVALID_DURATION: 422,
    REASON_INVALID_DECISION_ID: 400,
    REASON_INVALID_REQUEST: 400,
    REASON_DECISION_ID_CONFLICT: 409,
    REASON_INTERNAL_ERROR: 500,
}


# --------------------------------------------------------------- surfaces


def _normalize_prefix(prefix: str) -> str:
    """Normalize a mount prefix to '/'+path with no trailing slash.

    '' (or '/') means "mounted at the root": routes are '/snapshot',
    '/decision', '/health'.
    """
    if not isinstance(prefix, str):
        raise ValueError(f"mount_prefix must be a string, got {prefix!r}")
    text = prefix.strip()
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    return text.rstrip("/")


def approval_surface_ids(mount_prefix: str = DEFAULT_MOUNT_PREFIX) -> frozenset[str]:
    """The reserved surface ids of one approval mount.

    Register these in a broker's protected set so an agent cannot make
    the approval plane itself a brokered resource (self-reference: the
    identity being approved asking for access to the surface that
    approves it). The set names the mount and each route, so neither a
    prefix-shaped nor a route-shaped resource slips through.
    """
    prefix = _normalize_prefix(mount_prefix)
    ids = {APPROVAL_SURFACE_ID}
    if prefix:
        ids.add(prefix)
        ids.update(f"{prefix}/{leaf}" for leaf in ("snapshot", "decision", "health"))
    else:
        ids.update(f"/{leaf}" for leaf in ("snapshot", "decision", "health"))
    return frozenset(ids)


def _normalize_surfaces(surfaces: Iterable[str]) -> frozenset[str]:
    """Validate reserved surface ids (one bounded line each) and store
    them in CANONICAL matching form (review V6f): the query string and
    trailing slashes are stripped, so a variant of a protected id
    cannot slip past an exact-match lookup."""
    if isinstance(surfaces, str):
        surfaces = (surfaces,)
    out: set[str] = set()
    try:
        iterator = iter(surfaces)
    except TypeError as exc:
        raise TypeError("surfaces must be an iterable of strings") from exc
    for surface in iterator:
        if not isinstance(surface, str):
            raise TypeError(f"surface id must be a string, got {surface!r}")
        text = surface.strip()
        if not text:
            raise ValueError("surface id must be a non-empty string")
        text = normalize_surface_id(text)
        if len(text) > _MAX_SURFACE_ID_LENGTH or _CONTROL_CHARS.search(text):
            raise ValueError("surface id must be one bounded line")
        out.add(text)
    return frozenset(out)


def register_protected_surfaces(target: Any, surfaces: Iterable[str]) -> frozenset[str]:
    """Union approval-surface ids into a broker's protected-surface set.

    Two accepted targets, matching how brokers carry the set today:

    - a mutable ``set`` — updated in place;
    - an object exposing a ``protected_surfaces`` attribute (the
      ``BrokerContext`` pattern in the communications broker: a field
      holding a frozenset plus an ``is_protected_surface`` check) — the
      attribute is REPLACED by the merged frozenset, so the broker's
      frozen contract is preserved.

    Call it AFTER the broker context is constructed (the field is
    normally computed in ``__post_init__`` from the gateway config; the
    approval mount is HTTP-side and has no gateway-config source).
    Union only: a registration can never remove a reserved id. Returns
    the merged frozenset.
    """
    ids = _normalize_surfaces(surfaces)
    if isinstance(target, set):
        target.update(ids)
        return frozenset(target)
    if not hasattr(target, "protected_surfaces"):
        raise TypeError(
            "target must be a set or expose a 'protected_surfaces' attribute"
        )
    current = target.protected_surfaces
    if isinstance(current, set):
        current.update(ids)
        merged = frozenset(current)
        target.protected_surfaces = merged
        return merged
    if current is None:
        existing: frozenset[str] = frozenset()
    elif isinstance(current, (frozenset, tuple, list)):
        existing = frozenset(current)
    else:
        raise TypeError(
            "protected_surfaces must be a set, frozenset, tuple, list or None"
        )
    merged = existing | ids
    target.protected_surfaces = merged
    return merged


# -------------------------------------------------------------------- app


def _package_version() -> str:
    """The installed core version, or 'unknown' (never fabricated)."""
    try:
        return metadata.version("access-broker-core")
    except metadata.PackageNotFoundError:  # pragma: no cover - installed in prod
        return "unknown"


def _bearer_token(scope: Mapping[str, Any]) -> str:
    """Extract a Bearer credential from the request headers ('' if absent).

    Parsing only: the comparison (constant-time) happens in the caller
    through ``check_static_credential``. A non-Bearer scheme — or no
    Authorization header at all — yields '', which the comparator
    denies by design (empty never authorizes).
    """
    for name, value in scope.get("headers", ()) or ():
        try:
            header = name.decode("latin-1").lower()
        except ValueError:  # pragma: no cover - headers are bytes per ASGI
            continue
        if header != "authorization":
            continue
        try:
            raw = value.decode("latin-1").strip()
        except ValueError:  # pragma: no cover - headers are bytes per ASGI
            return ""
        scheme, _, credential = raw.partition(" ")
        if scheme.lower() != "bearer":
            return ""
        return credential.strip()
    return ""


class ApprovalSurfaceApp:
    """The ASGI sub-app serving snapshot/decision/health.

    Construct through :func:`build_approval_surface_app`, which resolves
    the bearer from the named environment variable and refuses to start
    when it is unset or too short. The class itself takes an already
    resolved token (tests, or a broker that reads it from elsewhere);
    the minimum length is enforced here too, so a short token can never
    reach the comparison.
    """

    def __init__(
        self,
        core: Any,
        token: str,
        *,
        mount_prefix: str = DEFAULT_MOUNT_PREFIX,
        principal: str = "approver:approval-surface",
        broker_id: str | None = None,
        version: str | None = None,
        max_body_bytes: int = MAX_BODY_BYTES,
        min_token_length: int = MIN_TOKEN_LENGTH,
    ) -> None:
        if core is None or not callable(getattr(core, "apply_decision", None)):
            raise ValueError(
                "approval surface: core must expose apply_decision (an "
                "ApprovalGatewayCore)"
            )
        if not callable(getattr(core, "snapshot", None)):
            raise ValueError("approval surface: core must expose snapshot()")
        if not callable(getattr(core, "replayed_decision", None)):
            raise ValueError(
                "approval surface: core must expose replayed_decision() "
                "(the idempotent re-read a decision_id replay answers from)"
            )
        if (
            isinstance(min_token_length, bool)
            or not isinstance(min_token_length, int)
            or min_token_length < MIN_TOKEN_LENGTH
        ):
            # Review V6g: the token floor is HARD. A configured value below
            # 32 refuses to start — the floor is never silently lowered.
            raise ValueError(
                f"approval surface: min_token_length must be an integer >= "
                f"{MIN_TOKEN_LENGTH} (the token floor cannot be lowered; "
                "refusing to start)"
            )
        if not isinstance(token, str) or len(token) < min_token_length:
            raise ValueError(
                f"approval surface: bearer must be at least {min_token_length} "
                "characters (refusing to start)"
            )
        if not isinstance(principal, str) or not principal.strip():
            raise ValueError("approval surface: principal must be a non-empty string")
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int):
            raise ValueError("approval surface: max_body_bytes must be an integer")
        if max_body_bytes <= 0:
            raise ValueError("approval surface: max_body_bytes must be positive")
        self._core = core
        self._token = token
        self._mount_prefix = _normalize_prefix(mount_prefix)
        self._principal = principal.strip()
        self._broker_id = broker_id
        self._version = version or _package_version()
        self._max_body_bytes = max_body_bytes
        # decision_id -> {"fingerprint": (request_number, action,
        # duration_seconds), "expires_at": monotonic deadline}
        self._replays: OrderedDict[str, dict] = OrderedDict()
        # Review V6f: protected BY DEFAULT — the surface ids ride the core
        # itself (core.protected_surfaces / core.is_protected_surface), so
        # a broker that mounts this surface does not depend on a separate
        # opt-in registration step its wall could forget.
        if hasattr(core, "protected_surfaces"):
            register_protected_surfaces(core, approval_surface_ids(self._mount_prefix))

    # ------------------------------------------------------------ properties

    @property
    def mount_prefix(self) -> str:
        """The normalized prefix this app strips before routing."""
        return self._mount_prefix

    @property
    def surface_ids(self) -> frozenset[str]:
        """The ids to register in a broker's protected set."""
        return approval_surface_ids(self._mount_prefix)

    # --------------------------------------------------------------- routing

    def _route_path(self, scope: Mapping[str, Any]) -> str:
        """The route path, with root_path and the mount prefix stripped.

        Handles both a real ASGI mount (server sets ``root_path`` and
        strips the mount from ``path``) and mounting by prefix inside a
        larger app (``path`` still carries it).
        """
        path = str(scope.get("path", "") or "")
        root = str(scope.get("root_path", "") or "").rstrip("/")
        if root and (path == root or path.startswith(root + "/")):
            path = path[len(root):]
        prefix = self._mount_prefix
        if prefix and (path == prefix or path.startswith(prefix + "/")):
            path = path[len(prefix):]
        route = path or "/"
        if len(route) > 1:
            route = route.rstrip("/") or "/"
        return route

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            # Only HTTP is served. Lifespan/websocket scopes are not this
            # app's business and are ignored (no crash inside a mount).
            return
        # AUTH FIRST: before routing, before any body byte is read.
        if not check_static_credential(_bearer_token(scope), self._token):
            logger.warning(
                "approval surface: authentication refused (%s %s)",
                scope.get("method"),
                scope.get("path"),
            )
            await self._json(send, 401, {"ok": False, "error": "unauthorized"})
            return
        path = self._route_path(scope)
        method = str(scope.get("method", "GET")).upper()
        if path == "/health":
            await self._method_guard(send, method, "GET")
            if method == "GET":
                await self._handle_health(send)
            return
        if path == "/snapshot":
            await self._method_guard(send, method, "GET")
            if method == "GET":
                await self._handle_snapshot(send)
            return
        if path == "/decision":
            await self._method_guard(send, method, "POST")
            if method == "POST":
                await self._handle_decision(receive, send)
            return
        await self._json(send, 404, {"ok": False, "error": "not_found"})

    @staticmethod
    async def _method_guard(send: Any, method: str, allowed: str) -> None:
        if method != allowed:
            await ApprovalSurfaceApp._json(
                send, 405, {"ok": False, "error": "method_not_allowed", "allow": allowed}
            )

    # ------------------------------------------------------------- handlers

    async def _handle_health(self, send: Any) -> None:
        core = self._core
        payload = {
            "ok": True,
            "surface": "approval",
            "version": self._version,
            # "Configured" means the decision path can satisfy its
            # write-before-operate contract: an audit chain is bound. A
            # surface over a non-audited core is VISIBLE as such, never
            # silently degraded.
            "gateway_configured": getattr(core, "_audit", None) is not None,
        }
        if self._broker_id is not None:
            payload["broker_id"] = self._broker_id
        await self._json(send, 200, payload)

    async def _handle_snapshot(self, send: Any) -> None:
        await self._json(send, 200, self._core.snapshot())

    async def _handle_decision(self, receive: Any, send: Any) -> None:
        status, raw = await self._read_body(receive)
        if status == "disconnect":
            return  # the client went away; nothing to answer
        if status == "too_large":
            await self._refuse(send, None, REASON_BODY_TOO_LARGE)
            return
        parsed = self._parse_decision(raw)
        if isinstance(parsed, str):
            await self._refuse(send, None, parsed)
            return
        request_number, action, duration, decision_id = parsed
        # Review V1: the replay binding is the FULL decision tuple, not
        # the id alone — the same decision_id naming a different decision
        # is a conflict, never a replay of the old outcome.
        fingerprint = (
            request_number,
            action,
            duration.total_seconds() if duration is not None else None,
        )

        if decision_id is not None:
            cached = self._replays.get(decision_id)
            if cached is not None and time.monotonic() >= cached["expires_at"]:
                # TTL (review V1): refusals included — no id ever pins a
                # stale answer; after expiry the decision runs fresh.
                self._replays.pop(decision_id, None)
                cached = None
            if cached is not None:
                if cached["fingerprint"] != fingerprint:
                    # The same id bound to a DIFFERENT decision tuple:
                    # audited conflict refusal, nothing applied, and the
                    # original binding STANDS (a retry of the first
                    # decision still answers idempotently).
                    await self._refuse(send, request_number, REASON_DECISION_ID_CONFLICT)
                    return
                # Matching tuple: answer from the CURRENT effective grant
                # state (re-read), never from a stale cached body (V1).
                try:
                    outcome = await self._core.replayed_decision(
                        request_number, action, self._principal
                    )
                except Exception:  # noqa: BLE001 - a replay never applies anything
                    logger.exception(
                        "approval surface: replayed decision re-read failed "
                        "(request #%s action=%s)",
                        request_number,
                        action,
                    )
                    await self._refuse(send, request_number, REASON_INTERNAL_ERROR)
                    return
                payload = dict(outcome)
                payload["surface"] = "approval"
                payload["replayed"] = True
                payload["http_hint"] = self._http_hint(outcome)
                await self._json(send, 200, payload)
                return

        try:
            outcome = await self._core.apply_decision(
                request_number,
                action,
                duration,
                self._principal,
                announce=False,
            )
        except ValueError:
            # apply_decision validates the same fields; a body that got
            # here slipped past the surface's own validation.
            await self._refuse(send, request_number, REASON_INVALID_REQUEST)
            return
        except Exception:  # noqa: BLE001 - an internal fault must not 4xx
            logger.exception(
                "approval surface: decision path failed (request #%s action=%s)",
                request_number,
                action,
            )
            if action in ("reject", "revoke"):
                # Review V2: non-widening by construction (capability
                # only ever shrinks) — the structured refusal path is
                # always a safe answer for a reject/revoke fault.
                await self._refuse(send, request_number, REASON_INTERNAL_ERROR)
                return
            # Widening path (approve): a genuine server error must NOT
            # masquerade as a decision outcome — a structured ERROR body
            # (HTTP 200, ok=false, outcome=error), audited, never a raw
            # 500 without a chain trace.
            self._core.audit_surface_refusal(
                request_number, REASON_INTERNAL_ERROR, principal="surface:approval"
            )
            await self._json(
                send,
                200,
                {
                    "ok": False,
                    "outcome": "error",
                    "request_number": request_number,
                    "action": action,
                    "error": REASON_INTERNAL_ERROR,
                    "surface": "approval",
                    "http_hint": 500,
                },
            )
            return

        payload = dict(outcome)
        payload["surface"] = "approval"
        payload["http_hint"] = self._http_hint(outcome)
        if decision_id is not None:
            self._remember(decision_id, fingerprint)
        await self._json(send, 200, payload)

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _http_hint(outcome: Mapping[str, Any]) -> int:
        if outcome.get("outcome") == "applied":
            return 200
        return _HTTP_HINTS.get(str(outcome.get("refusal")), 409)

    def _remember(self, decision_id: str, fingerprint: tuple[int, str, float | None]) -> None:
        """Bind a decision_id to its decision tuple for the replay TTL
        (oldest binding out first). The cached OUTCOME body is never
        stored: a replay answers from the live record, so nothing stale
        can ever be served back."""
        self._replays[decision_id] = {
            "fingerprint": fingerprint,
            "expires_at": time.monotonic() + REPLAY_TTL_SECONDS,
        }
        while len(self._replays) > MAX_REPLAY_ENTRIES:
            self._replays.popitem(last=False)

    async def _read_body(self, receive: Any) -> tuple[str, bytes]:
        """Read the request body under the configured cap.

        Returns ('ok', bytes), ('too_large', b'') or ('disconnect', b'').
        Nothing is parsed here — the cap is enforced BEFORE any parser
        sees a byte.
        """
        chunks = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return "disconnect", b""
            chunk = message.get("body", b"") or b""
            chunks.extend(chunk)
            if len(chunks) > self._max_body_bytes:
                return "too_large", b""
            if not message.get("more_body", False):
                return "ok", bytes(chunks)

    def _parse_decision(
        self, raw: bytes
    ) -> tuple[int, str, timedelta | None, str | None] | str:
        """Validate a decision body; returns the fields or a refusal reason.

        Bounded, closed-schema: unknown keys are ignored (forward
        compatibility for a hub that adds a hint), but every REQUIRED
        field is validated strictly and a `duration_seconds` of 0 is
        refused (a zero-length grant is not an approval).
        """
        try:
            # Explicit parse boundary (review V2): json.loads raises
            # ValueError for malformed JSON / non-UTF-8 bytes and
            # RecursionError for a ~4KB deeply-nested depth bomb — BOTH
            # are parse-stage refusals (audited, structured, nothing
            # applied), never a raw 500 escaping the module contract.
            body = json.loads(raw)
        except (ValueError, RecursionError):
            return REASON_MALFORMED_BODY
        if not isinstance(body, dict):
            return REASON_MALFORMED_BODY
        request_number = body.get("request_number")
        if (
            isinstance(request_number, bool)
            or not isinstance(request_number, int)
            or request_number <= 0
        ):
            return REASON_INVALID_REQUEST_NUMBER
        action = body.get("action")
        if not isinstance(action, str) or action.strip().lower() not in DECISION_ACTIONS:
            return REASON_INVALID_ACTION
        duration_raw = body.get("duration_seconds")
        duration: timedelta | None = None
        if duration_raw is not None:
            if (
                isinstance(duration_raw, bool)
                or not isinstance(duration_raw, int)
                or duration_raw <= 0
                or duration_raw > MAX_DURATION_SECONDS
            ):
                return REASON_INVALID_DURATION
            duration = timedelta(seconds=duration_raw)
        decision_id = body.get("decision_id")
        if decision_id is not None:
            if (
                not isinstance(decision_id, str)
                or not decision_id.strip()
                or len(decision_id) > _MAX_DECISION_ID_LENGTH
                or _CONTROL_CHARS.search(decision_id)
            ):
                return REASON_INVALID_DECISION_ID
            decision_id = decision_id.strip()
        return request_number, action.strip().lower(), duration, decision_id

    async def _refuse(
        self, send: Any, request_number: int | None, reason: str
    ) -> None:
        """A body-level refusal: AUDITED with a fixed reason, answered
        as a structured 200 body (nothing was applied).

        The receipt head is advertised ONLY when the audit entry landed
        (review V6b): the body carries ``audit_written`` and a head of
        None on a failed write, never a receipt for an unwritten entry.
        """
        head, audit_written = self._core.audit_surface_refusal(
            request_number, reason, principal="surface:approval"
        )
        payload = {
            "outcome": "refused",
            "request_number": request_number,
            "action": None,
            "state": None,
            "state_source": None,
            "expires_at": None,
            "reason": reason,
            "refusal": reason,
            "item_count": 0,
            "principal": "surface:approval",
            "audit_written": audit_written,
            "audit_head": head,
            "announced": False,
            "notified": False,
            "surface": "approval",
            "http_hint": _HTTP_HINTS.get(reason, 400),
        }
        await self._json(send, 200, payload)

    @staticmethod
    async def _json(send: Any, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"x-content-type-options", b"nosniff"),
        ]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


def build_approval_surface_app(
    core: Any,
    token_env_name: str,
    options: Mapping[str, Any] | None = None,
) -> ApprovalSurfaceApp:
    """Build the approval surface sub-app, refusing to start unauthenticated.

    token_env_name: the environment variable holding the THIRD
    credential class (approval-plane hub/app bearer). Unset, empty or
    shorter than ``min_token_length`` (default 32) raises ValueError
    before the app exists — an approval surface with no credential is
    never mountable. The token value is never logged or echoed.

    options (all optional):
      mount_prefix (str, default '/approval') — the prefix the app is
        mounted under; stripped before routing. Pass the same prefix to
        ``approval_surface_ids`` / ``register_protected_surfaces``.
      principal (str, default 'approver:approval-surface') — the audit
        principal recorded for API decisions. A hub passes
        'hub:<device-id>'; the room keeps its own sender-derived label.
      broker_id (str) — surfaced in /health (never in decisions).
      version (str) — override the reported version.
      max_body_bytes (int, default 4096).
      min_token_length (int, default 32) — a HARD floor: a configured
      value below 32 REFUSES TO START (review V6g), it is never
      clamped or lowered.

    Unknown option keys are refused (refuse-to-start discipline: a typo
    must not silently disable a guard).
    """
    opts = dict(options or {})
    unknown = set(opts) - _SURFACE_OPTION_KEYS
    if unknown:
        raise ValueError(
            "approval surface: unknown option(s) "
            + ", ".join(sorted(repr(key) for key in unknown))
        )
    if not isinstance(token_env_name, str) or not token_env_name.strip():
        raise ValueError("approval surface: token_env_name must be a non-empty string")
    env_name = token_env_name.strip()
    token = os.environ.get(env_name)
    min_length = opts.get("min_token_length", MIN_TOKEN_LENGTH)
    if isinstance(min_length, bool) or not isinstance(min_length, int):
        raise ValueError("approval surface: min_token_length must be an integer")
    if min_length < MIN_TOKEN_LENGTH:
        # Review V6g: 32 is a HARD floor. A configured value below it
        # REFUSES TO START — the floor is never clamped or lowered.
        raise ValueError(
            f"approval surface: min_token_length {min_length} is below the "
            f"hard floor {MIN_TOKEN_LENGTH} (refusing to start)"
        )
    if not token:
        raise ValueError(
            f"approval surface: credential env var {env_name!r} is unset or empty "
            "(refusing to start an unauthenticated approval surface)"
        )
    if len(token) < min_length:
        raise ValueError(
            f"approval surface: credential in {env_name!r} is shorter than "
            f"{min_length} characters (refusing to start)"
        )
    broker_id = opts.get("broker_id")
    if broker_id is not None and not isinstance(broker_id, str):
        raise ValueError("approval surface: broker_id must be a string")
    return ApprovalSurfaceApp(
        core,
        token,
        mount_prefix=opts.get("mount_prefix", DEFAULT_MOUNT_PREFIX),
        principal=opts.get("principal", "approver:approval-surface"),
        broker_id=broker_id,
        version=opts.get("version"),
        max_body_bytes=opts.get("max_body_bytes", MAX_BODY_BYTES),
        min_token_length=min_length,
    )
