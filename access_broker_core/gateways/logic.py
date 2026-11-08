"""Gateway decision logic: transport-agnostic core of the approval plane.

Port of nextcloud-access-broker broker/matrixbot.py (GPL-3.0-or-later,
same author) with the platform-specific shell stripped out. Everything
here works on canonical gateway events and a transport interface of four
async operations (send_message, add_reaction, edit_message, delete_reaction
are NOT needed by v1: requests are never edited in place — every state
change posts a fresh confirmation).

Security invariants (ported verbatim in behavior, per the contract):
- Sender allowlist FIRST: everything from a non-approver sender is
  ignored silently (never acknowledged — the bot is not an oracle).
- All state transitions route through the GrantStore; the bot holds no
  authorization power of its own. approve() returns RejectReason rather
  than raising: decided/unknown numbers are reported, never retried.
- Every decision produces a visible confirmation plus a refreshed status
  block. Silent state changes are forbidden.
- Pending requests expire after 12h of silence with an expiry notice
  (one notice per expired request per process lifetime).
- The event->request mapping is in-memory ONLY. Correct because the
  store's restart-discard rule rejects every pending request at boot:
  after a restart, reactions to old request messages resolve to nothing
  (unknown events are silently ignored, indistinguishable from probes).

Vocabulary rework for the PIM domain (per S5 design note rev 2):
- Items render as D5 grant items: BACKEND account/resource + ops, not
  file paths. Instance → account in the message template.
- The store has no per-item approval in v1: `approve <id> [expiry]` is
  the full grammar; partial-item approval is a v2 store feature.
- Duration overrides are parsed here ('8h'/'30m'/'2d') and passed to the
  store as normalized timedeltas (store contract: grammar lives in the
  gateway, not the store).

Canonical emoji set (one grammar across all four gateways; a transport
without native reactions still accepts typed commands — the typed
grammar is the only decision door, and there is deliberately no
text-line control fallback: an unclickable "approve" line inside a bot
message would be indistinguishable from agent-influenced card text).

Message format contract (2026-09-29 suite-wide render pass; the format
IS the suite's format because all five brokers render through this
module):

- Every outbound type is ``[tag] <icon> **<headline>** — <tail>`` when
  the room is shared (the ``[tag]`` is stamped by ``_tag``), so a room
  carrying several brokers stays scannable while posts interleave.
- One verb, one icon; the decision confirmations reuse the reaction
  emojis the approver tapped (``_VERB_ICONS`` is built from
  ``DECISION_EMOJIS``), so the render and the pre-placed controls share
  one vocabulary.
- Item lines are ONE line per item: an index or bullet, the bold
  backend, the account, the resource in inline code and the sorted ops.
  They are ALWAYS template-controlled: the agent-supplied
  justification appears verbatim in exactly ONE labelled line
  ("Justification (agent, unverified):") and never reaches the item
  identity lines or the pre-placed reactions (suite SECURITY.md,
  "Bounded approval context").
- Agent-influenced fields are SINGLE-PHYSICAL-LINE at render: control
  characters, newlines and Unicode line separators are collapsed, and
  markdown emphasis/backticks are escaped (review P4/P16/P38 — a
  newline-bearing justification could otherwise forge a second card
  header and steer a typed ``approve N`` to a different request).
  The store refuses the same shapes at intake; this is the second belt.
- Matrix-safe markdown only: bold, inline code, bullets and em dashes.
  No tables (Element X collapses them), no nested emphasis.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import asyncio
import difflib
import logging
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import cast

from access_broker_core.audit import AuditLog, LogWriteError
from access_broker_core.grants import (
    DEFAULT_PENDING_TIMEOUT,
    GrantRecord,
    GrantStore,
    RejectReason,
    RequestState,
)

logger = logging.getLogger(__name__)

APPROVE_EMOJI = "\N{THUMBS UP SIGN}"
REJECT_EMOJI = "\N{THUMBS DOWN SIGN}"
REVOKE_EMOJI = "\N{PROHIBITED SIGN}"
STATUS_EMOJI = "\N{CLIPBOARD}"

DECISION_EMOJIS = (APPROVE_EMOJI, REJECT_EMOJI, REVOKE_EMOJI, STATUS_EMOJI)

UNDO_GRACE_SECONDS = 15
"""Seconds after a reject/revoke during which `undo <id>` re-opens the
request as a NEW pending request (never resurrects the decided number).
Deliberately short; restarts close all windows (fail closed)."""

DEFAULT_EXPIRY_LABEL = "24h"
"""Fallback expiry label, used ONLY when the store does not expose its
configured active TTL. The card reads ``GrantStore.active_ttl`` so a
broker that configures a different TTL never renders a lying card
(review P39)."""

DEFAULT_SEND_TIMEOUT_SECONDS = 10.0
"""Bounded transport call (review P21): ``notify_request`` runs INLINE
inside the agent's gated tool call, so a hung transport must never
stall it. Overridable per gateway via ``send_timeout_seconds``."""

_MAX_JUSTIFICATION_RENDER = 512
_MAX_LABEL_RENDER = 128
_MAX_SCREEN_RENDER = 256
_MAX_ECHO_RENDER = 64

#: Every character a transport may treat as a line break, or that
#: renders as an invisible control inside a bot-authored card.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")

#: Markdown constructs an agent-influenced field could use to fake
#: emphasis, code, links or strikethrough inside the card.
_MARKDOWN_CHARS = str.maketrans({c: "\\" + c for c in "*_`~[]"})


def _one_line(value: object, limit: int | None = None) -> str:
    """Collapse a value to ONE physical line (controls -> spaces)."""
    text = _CONTROL_CHARS.sub(" ", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    if limit is not None and len(text) > limit:
        text = text[: max(1, limit - 1)] + "…"
    return text


def _safe_text(value: object, limit: int | None = None) -> str:
    """One line + markdown-neutralized: the form for agent/remote free
    text rendered OUTSIDE inline code (justification, label, screen)."""
    return _one_line(value, limit).translate(_MARKDOWN_CHARS)


def _code_text(value: object, limit: int = 256) -> str:
    """One line + backtick-safe: the form for a value rendered INSIDE an
    inline code span (a backtick would close the span and let the tail
    render as markdown)."""
    return _one_line(value, limit).replace("`", "'")

# Decision verbs -> the reaction emoji that produced them. Built from
# DECISION_EMOJIS so the confirmation header always shows the control
# the approver tapped (test-pinned: the render and the pre-placed
# controls cannot drift apart).
_VERB_ICONS = {
    "Approved": APPROVE_EMOJI,
    "Rejected": REJECT_EMOJI,
    "Revoked": REVOKE_EMOJI,
}

# Non-decision notice icons (one meaning per icon, no reuse across
# meanings; every one is a plain pictograph Element X renders).
ICON_PENDING = "⏳"
ICON_ACTIVE = "✅"
ICON_STATUS = STATUS_EMOJI
ICON_EXPIRED = "⏱️"
ICON_UNDO_CLOSED = "⌛"
ICON_REFUSED = "❌"
ICON_WARNING = "⚠️"
ICON_UNKNOWN_COMMAND = "❓"
ICON_HELP = "📖"
ICON_LIFECYCLE = {"started": "🟢", "stopping": "⚪"}
ICON_LIFECYCLE_DEFAULT = "🔄"

# Every outbound message OPENS with one of these icons (format contract);
# the set is kept collision-free so an icon always means one thing.
MESSAGE_ICONS = (
    ICON_PENDING,
    ICON_ACTIVE,
    ICON_STATUS,
    ICON_EXPIRED,
    ICON_UNDO_CLOSED,
    ICON_REFUSED,
    ICON_WARNING,
    ICON_UNKNOWN_COMMAND,
    ICON_HELP,
    *ICON_LIFECYCLE.values(),
    *_VERB_ICONS.values(),
)

# Item-line bullet for the non-request renders (one list style suite-wide).
BULLET = "•"

# The one labelled line the agent-supplied free text may occupy.
JUSTIFICATION_LABEL = "Justification (agent, unverified)"
#: Content-screening verdict line label (design note 2026-10-01):
#: rendered ONLY when the adopting broker's screen produced a result —
#: bounded, one line, never part of item identity or the decision
#: reactions (bounded-approval-context invariant).
SCREEN_LABEL = "Screen (advisory, deterministic)"

_RULE = "———"

# Human text for the two store refusal reasons (display only: the store
# still returns the enum and the refusal semantics are unchanged). The
# approver should never read Python syntax in a decision reply.
_REJECT_REASON_TEXT = {
    RejectReason.UNKNOWN_REQUEST: "no pending request with that number"
    " (expired, already decided, or never issued)",
    RejectReason.ALREADY_DECIDED: "already decided",
}

_HELP_TEXT = f"""{ICON_HELP} **How to decide**

**Reactions** — tap on a request message:
{APPROVE_EMOJI} approve · {REJECT_EMOJI} reject · {REVOKE_EMOJI} revoke · {STATUS_EMOJI} status

**Commands** — type here:
`approve <id> [expiry]` — e.g. `approve 3`, `approve 3 8h`
`reject <id>` · `revoke <id>` · `revoke all` ·
`undo <id>` (15s after a reject/revoke) · `status`

`<required>` `[optional]`. The **#** shown in messages is **not part** of
the id: type `approve 3`, never `approve #3`. Expiry: `8h`, `30m`, `2d`."""

_REPLY_RE = re.compile(
    r"^(approve|reject|revoke|undo|status)\s*(\d+)?"
    r"(?:\s+(\d{1,3}[hmd]))?$",
    re.IGNORECASE,
)
_REPLY_TARGET_RE = re.compile(
    r"^revoke\s+(all)$",
    re.IGNORECASE,
)

_COMMANDS = ("approve", "reject", "revoke", "undo", "status")

# Shared-room routing (2026-09-21, owner decision Option B): when one
# approval room serves several broker gateways, every typed command is
# seen by every gateway's sync loop. Each gateway therefore claims only
# commands prefixed with its own tag ("comms approve 1"); unprefixed
# commands are refused with a hint (fail-closed: never guessed at), and
# other brokers' prefixed commands are ignored SILENTLY (the right
# gateway answers; a refusal from the wrong one is noise). The prefix is
# also stamped on every outbound message so the human can tell which
# broker is speaking when several share one @identity.
COMMAND_PREFIX_PATTERN = r"[a-z][a-z0-9_-]{0,31}"
"""The shape a broker tag must have. It is the FIRST group of the
inbound shared-room regex below, so a prefix outside this shape could
never be matched from an inbound line (review P30: an uppercase or
space-bearing prefix silently disabled every typed command). The
factory refuses such a prefix at boot."""

COMMAND_PREFIX_RE = re.compile(rf"^{COMMAND_PREFIX_PATTERN}$")

_COMMAND_PREFIX_RE = re.compile(
    rf"^({COMMAND_PREFIX_PATTERN})\s+(.+)$", re.DOTALL | re.IGNORECASE
)

_DURATION_RE = re.compile(r"^(\d{1,3})([hmd])$", re.IGNORECASE)
_DURATION_UNITS = {"h": "hours", "m": "minutes", "d": "days"}


def parse_duration(raw: str | None) -> timedelta | None:
    """'8h'/'30m'/'2d' -> timedelta; None/'' -> None; malformed -> ValueError."""
    if raw is None or raw == "":
        return None
    m = _DURATION_RE.match(raw.strip())
    if not m:
        raise ValueError(f"invalid duration: {raw!r} (use 8h / 30m / 2d)")
    value = int(m.group(1))
    if value == 0:
        raise ValueError(f"invalid duration: {raw!r} (must be > 0)")
    return timedelta(**{_DURATION_UNITS[m.group(2).lower()]: value})


def parse_reply(text: str) -> tuple[str, int | None, timedelta | None] | None:  # noqa: PLR0911
    """Parse a typed command into (action, request_number, duration).

    Forms: 'approve 47', 'approve 47 8h', 'reject 47', 'revoke 47',
    'revoke all', 'undo 47', 'status'. Returns None when unparseable
    (the caller replies with a teaching message). Unknown-number and
    already-decided handling is downstream (store semantics), not here.
    """
    if not isinstance(text, str):
        return None
    text = text.strip()
    m = _REPLY_RE.match(text)
    if not m:
        if _REPLY_TARGET_RE.match(text):
            return ("revoke_all", None, None)
        return None
    action = m.group(1).lower()
    if action == "status":
        return ("status", None, None)
    number = m.group(2)
    if number is None:
        return None
    rid = int(number)
    if rid <= 0:
        return None
    if action == "undo":
        return ("undo", rid, None)
    duration = parse_duration(m.group(3)) if m.group(3) else None
    return (action, rid, duration)


#: The verbs ``apply_decision`` accepts (the API's closed verb set; the
#: room's grammar additionally has undo/status/revoke-all, which are
#: deliberately not decision verbs on the approval surface).
DECISION_ACTIONS = ("approve", "reject", "revoke")

#: The structured refusal vocabulary of ``apply_decision``. ``reason``
#: carries the store's RejectReason value (unknown_request /
#: already_decided) when the store refused; ``refusal`` is the finer
#: marker that keeps the THREE stale-card states distinguishable —
#: unknown number, already decided, and effectively expired (the
#: design note's idempotency/stale-card rule: an expired request must
#: render as expired/pending_timeout, never as a bare "rejected").
REFUSAL_UNKNOWN_REQUEST = "unknown_request"
REFUSAL_ALREADY_DECIDED = "already_decided"
REFUSAL_EXPIRED = "expired"
REFUSAL_AUDIT_WRITE_FAILED = "audit_write_failed"

_PRINCIPAL_KINDS = frozenset({"approver", "agent", "hub", "surface", "transfer"})
_MAX_PRINCIPAL_LENGTH = 128


def _normalize_decision_duration(duration: timedelta | str | None) -> timedelta | None:
    """Validate a decision duration: positive timedelta, or a string in
    the EXISTING room grammar ('8h'/'30m'/'2d').

    ``None`` means "use the store's configured default TTL" (the room's
    ``approve <id>`` form). Zero is refused in every spelling (the
    grammar already refuses '0h'; a zero timedelta is refused here),
    because a zero-length grant is indistinguishable from "not
    approved" and would render as an active grant that authorizes
    nothing. Raises ValueError on anything else.
    """
    if duration is None:
        return None
    if isinstance(duration, bool):
        raise ValueError(f"invalid duration: {duration!r} (must be positive)")
    if isinstance(duration, timedelta):
        if duration <= timedelta(0):
            raise ValueError(f"invalid duration: {duration!r} (must be > 0)")
        return duration
    if isinstance(duration, str):
        parsed = parse_duration(duration)
        if parsed is None:
            raise ValueError(f"invalid duration: {duration!r} (use 8h / 30m / 2d)")
        return parsed
    raise ValueError(
        f"invalid duration: {duration!r} (a positive timedelta or an 8h/30m/2d string)"
    )


def _principal_label(principal: str) -> str:
    """Normalize an acting principal into the audit chain's label form.

    ``approver:<id>`` for human decisions (the room passes the sender
    and gets the prefix here), other declared kinds pass through
    unchanged (``hub:<device>``, ``surface:approval``, ``agent``,
    ``transfer``). Anything else is treated as an approver id, so an
    unqualified principal can never be mistaken for the agent in the
    chain. Refuses empty/oversized/control-bearing values.
    """
    if not isinstance(principal, str) or not principal.strip():
        raise ValueError("principal must be a non-empty string")
    text = principal.strip()
    if len(text) > _MAX_PRINCIPAL_LENGTH or _CONTROL_CHARS.search(text):
        raise ValueError("principal must be one bounded line")
    if text.split(":", 1)[0].lower() in _PRINCIPAL_KINDS:
        return text
    return f"approver:{text}"


def _refusal_display(action: str, reason: RejectReason) -> str:
    """The room's human wording for a refusal (byte-compatible with the
    pre-surface renderer, pinned by the existing gateway battery)."""
    if action == "approve":
        return _REJECT_REASON_TEXT[reason]
    if action == "reject":
        return "already decided or unknown"
    return "unknown, decided, or expired"


def closest_command(word: str) -> str | None:
    """Nearest known command for an unrecognized first word, or None."""
    if not word:
        return None
    match = difflib.get_close_matches(word.lower(), _COMMANDS, n=1, cutoff=0.6)
    return match[0] if match else None


def format_remaining(delta: timedelta) -> str:
    """Human time-left: whole hours at/above 2h, minutes below."""
    seconds = max(0, int(delta.total_seconds()))
    if seconds >= 2 * 3600:
        return f"{seconds // 3600}h"
    return f"{seconds // 60}m"


class TransportError(Exception):
    """Raised by transports on delivery failure; the gateway fails closed
    (the request stays pending; a notice is attempted on the next event).
    Also raised when a transport call exceeds the gateway's bounded send
    timeout — a hung approval transport must not stall the agent."""


class GatewayTransport:
    """Thin async interface every adapter implements (matrix-nio, Telegram
    Bot API, Teams Graph messages, signal-cli JSON-RPC). One room/chat/
    conversation; one allowlisted approver identity per gateway."""

    async def send_message(self, text: str) -> str:
        """Post a message; return the platform event/message id."""
        raise NotImplementedError

    async def add_reaction(self, event_id: str, emoji: str) -> None:
        """Pre-place a decision reaction on a posted message. Transports
        without native reactions implement this as a no-op."""


class ApprovalGatewayCore:
    """Routes the allowlisted approver's reactions and typed commands into
    GrantStore transitions and renders every outcome back through the
    transport. Transport-agnostic: tested once with a fake transport; the
    four adapters map platform events to (handle_reaction | handle_reply)
    and implement send_message/add_reaction.

    The core holds NO authorization power: it can only call store
    transitions, which refuse decided/unknown numbers.

    Shared-room routing: when ``shared_room=True`` and a ``command_prefix``
    is set, typed commands must carry the prefix ("comms approve 1"),
    unprefixed commands are refused with a hint, and every outbound
    message is tagged "[comms] ..." so the human can tell brokers apart
    in a room where several gateways post under one identity.
    """

    def __init__(
        self,
        store: GrantStore,
        transport: GatewayTransport,
        approver: str,
        now: Callable[[], datetime],
        audit: AuditLog | None = None,
        shared_room: bool = False,
        command_prefix: str | None = None,
        send_timeout_seconds: float = DEFAULT_SEND_TIMEOUT_SECONDS,
    ) -> None:
        """store: the GrantStore all decisions route through.
        transport: the gateway's I/O shell. approver: the single
        allowlisted sender identity on THIS gateway (platform-specific
        shape; Matrix user id, Telegram user id, Teams AAD object id,
        signal number/uuid). Messages from any other sender are ignored
        silently. now: injected clock. audit: the broker's AuditLog.
        When present, every HUMAN decision (approve, reject, revoke,
        undo) and the agent's submission is written into the
        hash-chained audit log — the audit record of owner decisions is
        a suite invariant (adversarial review finding F1, 2026-09-16).
        When None (tests, headless deployments) decision entries are
        skipped; ``build_gateway`` refuses an audit-less boot unless
        ``allow_without_audit`` is set explicitly (review P29).
        send_timeout_seconds: bounded transport call (review P21).

        Construction wiring: the transport is normally bound by the
        adapter builder before the gateway starts; ``bind_transport``
        is the public rebind the factory uses after the builder returns
        (review P15/P40 — the previous contract expected a private
        attribute assignment and could leave the core unable to send).
        """
        self._store = store
        self._transport = transport
        self._approver = approver
        self._now = now
        self._audit = audit
        self._event_to_request: dict[str, int] = {}
        self._swept: set[int] = set()
        self._undo_windows: dict[int, tuple[datetime, dict]] = {}
        if shared_room and not command_prefix:
            raise ValueError(
                "gateway shared_room=True requires a command_prefix "
                "(the tag this gateway answers to and stamps on outbound messages)"
            )
        if isinstance(send_timeout_seconds, bool) or not isinstance(
            send_timeout_seconds, (int, float)
        ) or send_timeout_seconds <= 0:
            raise ValueError(
                f"send_timeout_seconds must be a positive number, got {send_timeout_seconds!r}"
            )
        self._send_timeout = float(send_timeout_seconds)
        self._shared_room = bool(shared_room)
        self._prefix = command_prefix if command_prefix else ""

    # ------------------------------------------------------- wiring contract

    def bind_transport(self, transport: GatewayTransport) -> None:
        """Bind the adapter's real transport (public construction seam)."""
        if transport is None:
            raise ValueError("gateway core: transport must not be None")
        self._transport = transport

    @property
    def transport(self) -> GatewayTransport:
        """The transport the core currently sends through."""
        return self._transport

    @property
    def has_live_transport(self) -> bool:
        """False while the core still carries the factory placeholder
        (a builder that wired nothing). The factory refuses to return
        such a gateway: it looks healthy and cannot send."""
        return self._transport is not None and not getattr(
            self._transport, "IS_PLACEHOLDER", False
        )

    # ------------------------------------------------------------ audit

    def _audit_entry(
        self,
        rid: int,
        decision: str,
        reason: str,
        principal: str,
        items: list[dict] | None = None,
        then: Callable[[], object] | None = None,
    ) -> object:
        """Record one lifecycle entry per ITEM in the audit chain.

        ``principal`` names who acted: ``agent`` for the submission (the
        agent authored the request — review P27: the old code credited
        the human), ``approver:<sender>`` for every human decision.

        Every item is recorded (review P26): one entry per item, so a
        multi-item approval is reconstructable from the chain instead of
        summarizing only ``items[0]``. ``then`` rides the LAST entry, so
        the write-before-operate contract holds for the whole decision:
        the transition runs only after every entry is durable.

        With no audit log configured this is a pass-through to ``then``
        (headless/test mode; ``build_gateway`` refuses that boot unless
        it is explicit). Raises LogWriteError on write failure.
        """
        if self._audit is None:
            return then() if then is not None else None
        rows = [item for item in (items or []) if isinstance(item, dict)]
        if not rows:
            return self._audit.record(
                account="",
                resource="",
                operation="lifecycle",
                grant_id=rid,
                decision=decision,
                reason=reason,
                principal=principal,
                then=then,
            )
        result: object = None
        last = len(rows) - 1
        for index, item in enumerate(rows):
            ops = item.get("ops")
            result = self._audit.record(
                account=str(item.get("account", "")),
                resource=str(item.get("resource", "")),
                operation=",".join(sorted(str(op) for op in (ops or []))) or "lifecycle",
                grant_id=rid,
                decision=decision,
                reason=reason,
                backend=item.get("backend"),
                principal=principal,
                then=then if index == last else None,
            )
        return result

    def _audit_decision_as(
        self,
        rid: int,
        decision: str,
        reason: str,
        principal: str,
        items: list[dict] | None = None,
        then: Callable[[], object] | None = None,
    ) -> object:
        """One decision entry under an explicit principal label.

        The public decision path (``apply_decision``) and the room path
        both land here, so a hub decision and a room decision are
        recorded by the same code with the same write-before-operate
        seam.
        """
        return self._audit_entry(
            rid,
            decision,
            reason,
            principal,
            items=items,
            then=then,
        )

    def _audit_decision(
        self,
        rid: int,
        decision: str,
        reason: str,
        sender: str,
        items: list[dict] | None = None,
        then: Callable[[], object] | None = None,
    ) -> object:
        """One APPROVER decision: principal is ``approver:<sender>``."""
        return self._audit_decision_as(
            rid,
            decision,
            reason,
            f"approver:{sender}",
            items=items,
            then=then,
        )

    def _audit_head(self) -> str | None:
        """The post-write audit chain head, or None with no audit log.

        A decision receipt carries this so a client can verify the
        decision LANDED in the chain, not merely that the store
        transitioned (design note, sixth pass).
        """
        if self._audit is None:
            return None
        return getattr(self._audit, "head_hash", None)

    # ------------------------------------------------------------- posting

    @staticmethod
    def _item_resource_display(item: dict) -> str:
        """Display form of one grant item's resource: the human label
        when present (e.g. Matrix room name), else the raw resource.
        Matching never uses this — item['resource'] stays the wall key.
        Both parts are neutralized to one physical line: the label is
        remote-influenced on some brokers (a room name an admin sets)
        and the resource is agent-influenced (review P16/P38/P4)."""
        label = item.get("label")
        resource = str(item.get("resource", ""))
        safe_resource = _code_text(resource, 256)
        if isinstance(label, str) and label and label != resource:
            return f"{_safe_text(label, _MAX_LABEL_RENDER)} (`{safe_resource}`)"
        return f"`{safe_resource}`"

    def _item_line(self, item: dict, index: int | None = None) -> str:
        """ONE template-controlled item identity line.

        Only store-validated item fields reach this line: backend,
        account, resource (plus the display-only ``label``) and the
        sorted operation set. The agent-supplied justification is NOT
        an input here and can never appear on an item line or on a
        pre-placed reaction — the suite's "Bounded approval context"
        invariant. ``index`` numbers request items (1., 2., ...); the
        other renders bullet them.
        """
        ops = ", ".join(f"`{_code_text(op, 64)}`" for op in sorted(item.get("ops", [])))
        marker = f"{index}." if index is not None else BULLET
        return (
            f"{marker} **{_one_line(item['backend'], 64)}** {_one_line(item['account'], 128)}:"
            f" {self._item_resource_display(item)} — {ops}"
        )

    @staticmethod
    def _compose(*parts: str) -> str:
        """Join a decision body and the refreshed status with the suite
        rule — one separator everywhere, no table (Element X collapses
        tables)."""
        return f"\n\n{_RULE}\n\n".join(parts)

    def render_request(
        self,
        number: int,
        justification: str,
        items: list[dict],
        screen: str | None = None,
    ) -> str:
        """Markdown for a pending request: the header names the id, the
        item count and the default expiry (the three things the
        approver decides between), each item is ONE template-controlled
        line (backend/account/resource + ops) so item identity survives
        phone-width wrapping, and the agent-supplied justification sits
        in its own labelled line as commentary — never as the approval
        target. screen: optional bounded verdict line from the content
        screen (design note 2026-10-01), rendered directly below the
        justification; None = no screen ran and the card is
        byte-identical to the pre-screening card.

        The justification, the item labels and the screen line are each
        emitted as ONE physical line with markdown neutralized (review
        P4/P16/P38): a newline-bearing value can no longer forge a
        second card header, an item block or a ``Decide`` affordance.
        """
        count = len(items)
        lines = [
            f"{ICON_PENDING} **PENDING #{number}** — awaiting your approval"
            f" · {count} item{'s' if count != 1 else ''} ·"
            f" {self._expiry_label()} if approved",
        ]
        lines += [self._item_line(item, i) for i, item in enumerate(items, start=1)]
        lines += [
            f"{JUSTIFICATION_LABEL}: {_safe_text(justification, _MAX_JUSTIFICATION_RENDER)}"
        ]
        if screen is not None:
            lines.append(f"{SCREEN_LABEL}: {_safe_text(screen, _MAX_SCREEN_RENDER)}")
        lines += [
            "",
            f"**Decide** — {APPROVE_EMOJI} `approve {number}`, or"
            f" {REJECT_EMOJI} `reject {number}`"
            f" · shorter: `approve {number} 8h`",
            f"(react below: {APPROVE_EMOJI} {REJECT_EMOJI} {REVOKE_EMOJI} {STATUS_EMOJI})",
        ]
        return "\n".join(lines)

    def _expiry_label(self) -> str:
        """The default approval TTL as rendered on the card, read from
        the store's configuration (review P39: the old hardcoded '24h'
        misstated any broker with a different TTL)."""
        ttl = getattr(self._store, "active_ttl", None)
        if not isinstance(ttl, timedelta):
            return DEFAULT_EXPIRY_LABEL
        return format_remaining(ttl)

    async def post_request(
        self,
        number: int,
        justification: str,
        items: list[dict],
        *,
        screen: str | None = None,
    ) -> str:
        """Post a pending request and pre-place the four decision
        reactions (transports without reactions no-op). Returns the
        posted event id. The event→request mapping is in-memory only —
        sound because the store rejects all pending requests at restart,
        so post-restart reactions resolve to nothing. screen: optional
        screen verdict line (render_request).

        The reaction pre-placement is best-effort and BOUNDED (review
        P21): a hung reaction call degrades to typed commands, it does
        not stall the agent's tool call.
        """
        event_id = await self._post(
            self.render_request(number, justification, items, screen=screen)
        )
        for emoji in DECISION_EMOJIS:
            try:
                await asyncio.wait_for(
                    self._transport.add_reaction(event_id, emoji),
                    timeout=self._send_timeout,
                )
            except TimeoutError:
                logger.error(
                    "gateway: add_reaction timed out after %ss on %s; "
                    "the card stands, typed commands remain available",
                    self._send_timeout,
                    event_id,
                )
                break
        self._event_to_request[event_id] = number
        return event_id

    async def notify_request(
        self,
        request_number: int,
        justification: str,
        items: list[dict],
        *,
        screen: str | None = None,
    ) -> str:
        """Public entry point: render + post one pending request.

        The submission is audited here with ``principal=agent`` — the
        agent authored the request, not the human (review P27; the old
        entry credited the approver). Audit-write failure does NOT
        un-post the request — the submission is non-widening — but is
        surfaced loudly.

        screen (keyword-only, content-screening design note
        2026-10-01): the screening verdict line rendered next to the
        justification when a broker's screen produced one. None = no
        screen ran: the card is byte-identical to today's. Never part
        of item identity, never a reaction (bounded-approval-context
        invariant).
        """
        try:
            self._audit_entry(
                request_number,
                "submitted",
                "pending_approval",
                "agent",
                items,
            )
        except LogWriteError as exc:
            logger.error(
                "AUDIT: submit decision entry for request #%d failed: %s",
                request_number,
                exc,
            )
        return await self.post_request(request_number, justification, items, screen=screen)

    # ------------------------------------------------------------ reactions

    async def handle_reaction(self, sender: str, event_id: str, emoji: str) -> None:
        """Route a reaction to a decision, allowlist FIRST: a non-approver
        probing event ids gets no information (unknown events and
        forbidden senders are indistinguishable — both silently ignored)."""
        if sender != self._approver:
            logger.debug(
                "decision allowlist rejected: sender=%s emoji=%s event=%s",
                sender,
                emoji,
                event_id,
            )
            return
        rid = self._event_to_request.get(event_id)
        if rid is None:
            return  # not one of our request messages (or pre-restart)
        if emoji == APPROVE_EMOJI:
            await self._decide(rid, "approve", None, sender)
        elif emoji == REJECT_EMOJI:
            await self._decide(rid, "reject", None, sender)
        elif emoji == REVOKE_EMOJI:
            await self._revoke(rid, sender)
        elif emoji == STATUS_EMOJI:
            await self._post_summary()
        # other emojis: deliberately ignored

    async def handle_reply(self, sender: str, text: str) -> None:
        """Route a typed command ('approve 47 8h', 'reject 47', 'revoke
        47', 'revoke all', 'undo 47', 'status') — allowlist first, then
        shared-room prefix routing.

        The duration grammar is parsed defensively: a mistyped expiry
        ('approve 1 0h') used to raise ValueError straight through the
        adapter's event loop (review, sixth pass). It now routes to the
        refusal hint, so the human gets a teaching message and the
        gateway keeps running.
        """
        if sender != self._approver:
            return
        if self._shared_room:
            routed = await self._route_command(text)
            if routed is None:
                return  # another broker's command; the right gateway answers
            text = routed
        try:
            parsed = parse_reply(text)
        except ValueError as exc:
            logger.warning(
                "gateway: unparseable command from approver (%s): %r", exc, text
            )
            await self._post(
                f"{ICON_UNKNOWN_COMMAND} **Invalid expiry** in"
                f" `{_safe_text(text, _MAX_ECHO_RENDER)}` — use a positive"
                " number with `h`, `m` or `d`, e.g. `approve 3 8h`."
                " `status` lists every command."
            )
            return
        if parsed is None:
            first_word = text.strip().split(" ", 1)[0] if text.strip() else ""
            closest = closest_command(first_word)
            if closest:
                await self._post(
                    f"{ICON_UNKNOWN_COMMAND} **Unknown command** `{first_word}`"
                    f" — closest: `{closest}`. `status` lists every command."
                )
            else:
                await self._post(_HELP_TEXT)
            return
        action, rid, duration = parsed
        if action == "status":
            await self._post_summary()
        elif action == "revoke_all":
            await self._revoke_many(sender)
        elif rid is None:
            logger.warning("gateway: action %s without request number (parser bug)", action)
        elif action == "undo":
            await self._undo(rid, sender)
        elif action == "approve":
            await self._decide(rid, "approve", duration, sender)
        elif action == "reject":
            await self._decide(rid, "reject", None, sender)
        else:  # parse_reply only yields plain revoke here
            await self._revoke(rid, sender)

    # --------------------------------------------------- shared-room routing

    async def _post(self, text: str) -> str:
        """The ONE outbound choke point: stamps the broker tag in
        shared-room mode, then posts through the transport with a
        BOUNDED call (review P21).

        The agent's gated tool call awaits this path inline, so a hung
        transport is capped at ``send_timeout_seconds``: the timeout is
        logged loudly and surfaced as :class:`TransportError` — a card
        that was never delivered must not look delivered.
        """
        payload = self._tag(text)
        try:
            return await asyncio.wait_for(
                self._transport.send_message(payload), timeout=self._send_timeout
            )
        except TimeoutError:
            logger.error(
                "gateway: transport send_message timed out after %ss — "
                "abandoning the post (the approval card was NOT delivered)",
                self._send_timeout,
            )
            raise TransportError(
                f"gateway transport send timed out after {self._send_timeout}s"
            ) from None

    async def announce_lifecycle(self, state: str) -> None:
        """Post a gateway startup/shutdown notice to the room (owner
        directive 2026-09-21: the approval room itself must show which
        brokers are alive). Adapters call this after a successful
        start() and at the top of stop(); a delivery failure is logged
        and swallowed — a lifecycle notice must never kill the gateway.
        """
        if not self._transport:
            return
        icon = ICON_LIFECYCLE.get(state, ICON_LIFECYCLE_DEFAULT)
        try:
            await self._post(f"{icon} **gateway {state}**")
        except Exception:  # noqa: BLE001 - notice is best-effort
            logger.exception("gateway lifecycle notice failed")

    def _tag(self, text: str) -> str:
        """Stamp the broker tag on an outbound message (shared-room
        mode only; solo rooms need no labels)."""
        if self._shared_room:
            return f"[{self._prefix}] {text}"
        return text

    async def _route_command(self, text: str) -> str | None:
        """Resolve one inbound line in shared-room mode.

        Returns the command body to parse (prefix stripped), or None
        when this gateway must stay silent. Unprefixed commands are
        refused with a hint (fail-closed: never guessed at); other
        brokers' prefixed commands are ignored silently (the right
        gateway answers; a refusal from the wrong one is noise).
        """
        stripped = text.strip()
        m = _COMMAND_PREFIX_RE.match(stripped)
        if not m:
            # Unreachable in practice: the prefix regex matches any
            # "word rest" line, and the commands are single words.
            await self._post(
                f"{ICON_REFUSED} **Unprefixed command** — this room serves multiple"
                f" brokers. Prefix with `{self._prefix} approve 1`,"
                f" `{self._prefix} status`, ..."
            )
            return None
        tag, body = m.group(1).lower(), m.group(2).strip()
        if tag in _COMMANDS or _REPLY_TARGET_RE.match(stripped):
            # The line LOOKS like a bare command (first word is a known
            # command): refuse it as unprefixed, never silently drop.
            await self._post(
                f"{ICON_REFUSED} **Unprefixed command** — this room serves multiple"
                f" brokers. Prefix with `{self._prefix} {stripped.split(' ', 1)[0]}`..."
            )
            return None
        if tag != self._prefix:
            return None  # another broker's command
        return body

    # ------------------------------------------------------------------ undo

    async def _undo(self, rid: int, sender: str) -> None:
        """Undo a JUST-made reject/revoke within the 15s grace: creates a
        NEW pending request with the original items (never resurrects the
        decided number). Fail closed: unknown id, expired, or consumed
        window all refuse; a restart closes every window."""
        window = self._undo_windows.get(rid)
        if window is None or self._now() >= window[0]:
            self._undo_windows.pop(rid, None)
            await self._post(
                f"{ICON_UNDO_CLOSED} Undo window for #{rid} closed. "
                "File a new request if access is still needed."
            )
            return
        self._undo_windows.pop(rid)  # one shot
        payload = window[1]
        new_number = self._store.submit(
            request_id_hint=f"undo:{rid}",
            items=payload["items"],
            justification=payload["justification"],
        )
        # Undo re-opens capability (a fresh pending request): audit BEFORE
        # the request is posted. A failed entry aborts the undo (fail
        # closed) — the window is already consumed, so a retry needs a new
        # decision, which is the safe direction.
        self._audit_decision(
            new_number,
            "submitted",
            f"undo of #{rid}",
            sender,
            payload["items"],
        )
        logger.info(
            "decision: rid=%d action=undo outcome=recreated sender=%s new_rid=%d",
            rid,
            sender,
            new_number,
        )
        await self.post_request(new_number, payload["justification"], payload["items"])

    def _arm_undo(self, rid: int, record) -> None:
        """Record the undo window after a reject/revoke."""
        self._undo_windows[rid] = (
            self._now() + timedelta(seconds=UNDO_GRACE_SECONDS),
            {"justification": record.justification, "items": record.items},
        )

    # ------------------------------------------------------------- decisions

    async def apply_decision(
        self,
        request_number: int,
        action: str,
        duration: timedelta | str | None = None,
        principal: str = "approver",
        announce: bool = True,
    ) -> dict:
        """Apply ONE decision and return a STRUCTURED outcome.

        This is the approval surface's entry point. It is the EXISTING
        decision machinery, not a second one: the approve arm still
        writes its audit intent through the ``then=`` seam BEFORE the CAS
        transition (write-before-operate), the store's CAS is still the
        arbiter, reject/revoke still arm the 15s undo window, and
        ``announce=True`` still renders the same confirmation + status
        block through the transport. What is new is only the RETURN
        VALUE: a dict a client can act on without parsing prose.

        request_number: the one-time request number (per broker; never
        merged across brokers).
        action: one of ``DECISION_ACTIONS`` ('approve' | 'reject' |
        'revoke').
        duration: for approve, a positive timedelta or the room's
        duration grammar ('8h'/'30m'/'2d'); None = the store's
        configured active TTL. Duration 0 is refused (ValueError).
        principal: who is deciding — an approver id (normalized to
        ``approver:<id>``) or a declared label such as ``hub:<device>``.
        Recorded in the audit chain.
        announce: post the room confirmation. The approval surface
        passes False (the HTTP answer IS the confirmation); the room
        keeps True.

        Returns a dict with:
          outcome: 'applied' | 'refused'
          request_number, action
          state: the EFFECTIVE state after the attempt ('pending',
            'active', 'rejected', 'revoked', 'expired', 'unknown')
          state_source: the store's narrative ('approval', 'rejection',
            'revocation', 'pending_revoke', 'pending_timeout', ...)
          expires_at: ISO-8601 or None. On an approval this is the
            AUTHORITATIVE written expiry — min(now + duration,
            item-level caps) — which the caller cannot derive, which is
            why the response carries it.
          reason: the store's RejectReason value ('unknown_request' |
            'already_decided') when refused, else None.
          refusal: finer marker — 'unknown_request' | 'already_decided' |
            'expired' | 'audit_write_failed' | None. ``expired`` keeps a
            past-deadline pending row distinct from an already-decided
            one (state 'expired', state_source 'pending_timeout') rather
            than collapsing it into a bare rejection.
          item_count: number of affected items.
          audit_head: the post-write audit chain head hash (None when
            the core has no audit log) — a client verifies the decision
            LANDED in the chain, not merely that the store moved.
          principal, announced, notified.

        Raises ValueError for an invalid action, duration, principal or
        request number (a caller bug, refused before anything is read).
        A transport failure with ``announce=True`` raises
        :class:`TransportError` exactly as the room path does; the state
        change stands and the audit chain records it.
        """
        return await self._execute_decision(
            request_number, action, duration, principal, announce=announce
        )

    async def _execute_decision(
        self,
        request_number: int,
        action: str,
        duration: timedelta | str | None,
        principal: str,
        *,
        announce: bool,
    ) -> dict:
        """The ONE decision implementation (room + approval surface).

        ``_decide``/``_revoke`` are thin callers, so the room and the API
        cannot diverge: same audit seam, same CAS, same undo arming, same
        confirmations.
        """
        if isinstance(request_number, bool) or not isinstance(request_number, int):
            raise ValueError(f"request_number must be an integer, got {request_number!r}")
        if request_number <= 0:
            raise ValueError(f"request_number must be positive, got {request_number!r}")
        if action not in DECISION_ACTIONS:
            raise ValueError(
                f"unsupported decision action {action!r} (use {', '.join(DECISION_ACTIONS)})"
            )
        override = _normalize_decision_duration(duration)
        label = _principal_label(principal)
        rid = request_number

        try:
            current = self._store.get_record(rid)
        except LookupError:
            return await self._refuse_decision(
                rid, action, REFUSAL_UNKNOWN_REQUEST, None, label, announce
            )

        if action == "approve":
            if current.state != "pending":
                return await self._refuse_decision(
                    rid, action, self._refusal_kind(current), current, label, announce
                )

            def _commit() -> object:
                return self._store.approve(rid, duration=override)

            # Write-BEFORE-operate (review P10/A1): the approval entry is
            # durable BEFORE the CAS transition runs, through the audit
            # module's existing ``then`` seam. A failed audit write means
            # the store is never asked to widen: the grant does NOT become
            # active and nothing changed. (A lost CAS race after a
            # successful entry leaves an intent entry and posts the
            # store's refusal — the entry records the attempt, which is
            # the safe direction.)
            try:
                result = self._audit_decision_as(
                    rid, "approved", "grant_active", label, current.items, then=_commit
                )
            except LogWriteError as exc:
                logger.error(
                    "AUDIT: approve decision entry for request #%d failed (%s); "
                    "the grant was NOT activated (audit write refused the transition)",
                    rid,
                    exc,
                )
                if announce:
                    await self._post(
                        f"{ICON_WARNING} **Approve #{rid} REFUSED** — the audit entry"
                        " could not be written, so the grant was NOT activated and the"
                        " request is still pending. Resolve the audit log, then retry"
                        f" `approve {rid}`."
                    )
                return self._outcome(
                    "refused",
                    rid,
                    action,
                    record=current,
                    reason=REFUSAL_AUDIT_WRITE_FAILED,
                    refusal=REFUSAL_AUDIT_WRITE_FAILED,
                    principal=label,
                    announce=announce,
                    notified=announce,
                )
            if isinstance(result, RejectReason):
                record = self._record_or_none(rid)
                return await self._refuse_decision(
                    rid, action, self._refusal_kind(record), record, label, announce
                )
            record = cast(GrantRecord, result)
            logger.info(
                "decision: rid=%d action=approve outcome=granted principal=%s"
                " items=%d expiry=%s",
                rid,
                label,
                len(record.items),
                record.expires_at,
            )
            self._forget_request_events(rid)
            payload = self._compose(
                self._render_decision(record, "Approved", override), self._status_text()
            )
            return self._outcome(
                "applied",
                rid,
                action,
                record=record,
                principal=label,
                announce=announce,
                notified=await self._announce(payload, announce),
            )

        if action == "reject":
            applied = self._store.reject(rid)
            record = self._record_or_none(rid)
            if not applied:
                return await self._refuse_decision(
                    rid, action, self._refusal_kind(record), record, label, announce
                )
            assert record is not None  # reject() only returns True for a live row
            # Non-widening (capability only ever shrinks): audit failure
            # is surfaced loudly, the decision stands.
            try:
                self._audit_decision_as(
                    rid, "rejected", "rejected_by_approver", label, record.items
                )
            except LogWriteError as exc:
                logger.error(
                    "AUDIT: reject decision entry for request #%d failed: %s", rid, exc
                )
            logger.info(
                "decision: rid=%d action=reject outcome=rejected principal=%s", rid, label
            )
            self._arm_undo(rid, record)
            self._forget_request_events(rid)
            payload = self._compose(
                self._render_decision(record, "Rejected", None, undo=True),
                self._status_text(),
            )
            return self._outcome(
                "applied",
                rid,
                action,
                record=record,
                principal=label,
                announce=announce,
                notified=await self._announce(payload, announce),
            )

        # revoke: one verb, two outcomes (active -> revoked,
        # pending -> rejected/pending_revoke). The caller renders from
        # state + state_source, never from the verb.
        applied = self._store.revoke(rid)
        record = self._record_or_none(rid)
        if not applied:
            return await self._refuse_decision(
                rid, action, self._refusal_kind(record), record, label, announce
            )
        assert record is not None  # revoke() only returns True for a live row
        # Non-widening: audit failure surfaced loudly, revocation stands.
        try:
            self._audit_decision_as(
                rid, "revoked", "revoked_by_approver", label, record.items
            )
        except LogWriteError as exc:
            logger.error(
                "AUDIT: revoke decision entry for request #%d failed: %s", rid, exc
            )
        logger.info(
            "decision: rid=%d action=revoke outcome=%s principal=%s",
            rid,
            record.state,
            label,
        )
        self._arm_undo(rid, record)
        self._forget_request_events(rid)
        payload = self._compose(
            self._render_decision(record, "Revoked", None, undo=True), self._status_text()
        )
        return self._outcome(
            "applied",
            rid,
            action,
            record=record,
            principal=label,
            announce=announce,
            notified=await self._announce(payload, announce),
        )

    @staticmethod
    def _refusal_kind(record: GrantRecord | None) -> str:
        """Classify a refused decision into the three stale-card states."""
        if record is None:
            return REFUSAL_UNKNOWN_REQUEST
        if record.state == "expired":
            return REFUSAL_EXPIRED
        return REFUSAL_ALREADY_DECIDED

    def _record_or_none(self, rid: int) -> GrantRecord | None:
        """The record for ``rid``, or None when the number was never issued."""
        try:
            return self._store.get_record(rid)
        except LookupError:
            return None

    def _forget_request_events(self, rid: int) -> None:
        """Drop the event→request mappings of a decided request (the
        card is no longer live; a late reaction resolves to nothing)."""
        self._event_to_request = {
            event: number for event, number in self._event_to_request.items() if number != rid
        }

    async def _announce(self, payload: str, announce: bool) -> bool:
        """Post the confirmation, or deliberately stay silent.

        ``announce=False`` is the approval surface: its HTTP answer is
        the confirmation, and posting a card for a hub decision would
        double-notify the room. The state change and its audit entries
        are identical either way.
        """
        if not announce:
            return False
        await self._post(payload)
        return True

    def _outcome(
        self,
        outcome: str,
        rid: int,
        action: str,
        *,
        record: GrantRecord | None = None,
        reason: str | None = None,
        refusal: str | None = None,
        principal: str = "",
        announce: bool = False,
        notified: bool = False,
    ) -> dict:
        """Build the structured decision outcome (the surface's wire body)."""
        return {
            "outcome": outcome,
            "request_number": rid,
            "action": action,
            "state": (
                record.state
                if record is not None
                else ("unknown" if refusal == REFUSAL_UNKNOWN_REQUEST else None)
            ),
            "state_source": record.state_source if record is not None else None,
            "expires_at": (
                record.expires_at.isoformat()
                if record is not None and record.expires_at is not None
                else None
            ),
            "reason": reason,
            "refusal": refusal,
            "item_count": len(record.items) if record is not None else 0,
            "principal": principal,
            "audit_head": self._audit_head(),
            "announced": bool(announce),
            "notified": bool(notified),
        }

    async def _refuse_decision(
        self,
        rid: int,
        action: str,
        refusal: str,
        record: GrantRecord | None,
        principal: str,
        announce: bool,
    ) -> dict:
        """One refused decision: report it (never silently) and return
        the structured outcome. Nothing is written to the store."""
        reason = (
            RejectReason.UNKNOWN_REQUEST
            if refusal == REFUSAL_UNKNOWN_REQUEST
            else RejectReason.ALREADY_DECIDED
        )
        logger.info(
            "decision: rid=%d action=%s outcome=refused principal=%s refusal=%s state=%s",
            rid,
            action,
            principal,
            refusal,
            record.state if record is not None else "unknown",
        )
        notified = False
        if announce:
            await self._post(
                f"{ICON_REFUSED} Cannot {action} #{rid}: {_refusal_display(action, reason)}"
            )
            notified = True
        return self._outcome(
            "refused",
            rid,
            action,
            record=record,
            reason=reason.value,
            refusal=refusal,
            principal=principal,
            announce=announce,
            notified=notified,
        )

    def audit_surface_refusal(
        self,
        request_number: int | None,
        reason: str,
        principal: str = "surface:approval",
    ) -> str | None:
        """Record a refused decision attempt that never reached the store.

        The approval surface calls this for a malformed or invalid
        request body: the attempt is AUDITED with a fixed reason
        ('malformed_body', 'invalid_duration', ...) so a probe leaves a
        chain trace even though nothing was applied. Write failure is
        surfaced and swallowed (the refusal itself stands — nothing was
        applied either way); returns the chain head after the attempt.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("audit reason must be a non-empty string")
        rid = (
            request_number
            if isinstance(request_number, int)
            and not isinstance(request_number, bool)
            and request_number > 0
            else 0
        )
        try:
            self._audit_entry(rid, "refused", reason.strip(), _principal_label(principal))
        except LogWriteError as exc:
            logger.error(
                "AUDIT: surface refusal entry (#%s, reason=%s) failed: %s",
                rid,
                reason,
                exc,
            )
        return self._audit_head()

    # -------------------------------------------------------------- snapshot

    def snapshot(self) -> dict:
        """The approval plane's read model: what can be decided NOW.

        Queries ONLY rows the store currently holds as ``pending`` or
        ``active`` (``GrantStore.records_in_states`` — never an
        all-records history walk), then recomputes the effective state
        on read, so a past-deadline pending row reports its synthesized
        timeout state here rather than looking decidable.

        DEFAULT (documented choice): an effectively-expired row lands in
        a SEPARATE ``expired_recent`` slice and is excluded from
        ``pending``. Rationale — the surface's pending list is what a
        human can still act on; an expired row that still appeared
        unter pending would invite a decision the store must refuse.
        ``expired_recent`` keeps it visible (the app renders "expired",
        never "no such request"), and it is bounded to rows the store
        still holds as pending/active — terminal rows (rejected,
        revoked) are never in the snapshot.

        Returns: generated_at, pending_timeout_seconds (the store's
        ACTUAL configured timeout), pending, active, expired_recent,
        counts.
        """
        now = self._now()
        timeout = getattr(self._store, "pending_timeout", None)
        if not isinstance(timeout, timedelta):
            timeout = DEFAULT_PENDING_TIMEOUT
        pending: list[dict] = []
        active: list[dict] = []
        expired_recent: list[dict] = []
        for record in self._store.records_in_states(("pending", "active")):
            if record.state == "expired":
                expired_recent.append(self._snapshot_expired(record, timeout))
            elif record.state == "pending":
                pending.append(self._snapshot_pending(record, timeout))
            else:
                active.append(self._snapshot_active(record))
        return {
            "generated_at": now.isoformat(),
            "pending_timeout_seconds": int(timeout.total_seconds()),
            "pending": pending,
            "active": active,
            "expired_recent": expired_recent,
            "counts": {
                "pending": len(pending),
                "active": len(active),
                "expired_recent": len(expired_recent),
            },
        }

    @staticmethod
    def _snapshot_items(record: GrantRecord) -> list[dict]:
        """Item identity for the read model: the store's validated fields
        only (never anything parsed out of the justification)."""
        return [
            {
                "backend": item.get("backend"),
                "account": item.get("account"),
                "resource": item.get("resource"),
                "label": item.get("label"),
                "ops": list(item.get("ops") or []),
                "expires_at": item.get("expires_at"),
            }
            for item in record.items
        ]

    def _snapshot_pending(self, record: GrantRecord, timeout: timedelta) -> dict:
        return {
            "request_number": record.request_number,
            "created_at": record.created_at.isoformat(),
            "pending_deadline": (record.created_at + timeout).isoformat(),
            "justification": record.justification,
            "items": self._snapshot_items(record),
            "item_count": len(record.items),
            "state": record.state,
            "state_source": record.state_source,
        }

    def _snapshot_active(self, record: GrantRecord) -> dict:
        return {
            "request_number": record.request_number,
            "created_at": record.created_at.isoformat(),
            "decided_at": record.decided_at.isoformat() if record.decided_at else None,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "justification": record.justification,
            "items": self._snapshot_items(record),
            "item_count": len(record.items),
            "state": record.state,
            "state_source": record.state_source,
        }

    def _snapshot_expired(self, record: GrantRecord, timeout: timedelta) -> dict:
        """A row the store still holds as pending/active but whose
        effective state is expired (pending_timeout or grant_expiry)."""
        return {
            "request_number": record.request_number,
            "created_at": record.created_at.isoformat(),
            "pending_deadline": (
                (record.created_at + timeout).isoformat()
                if record.state_source == "pending_timeout"
                else None
            ),
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "item_count": len(record.items),
            "state": record.state,
            "state_source": record.state_source,
        }

    async def _decide(
        self, rid: int, action: str, duration: timedelta | None, sender: str
    ) -> None:
        """Room entry point for approve/reject — a THIN caller of the one
        decision implementation. The room's answer is the posted
        confirmation, so the structured outcome is discarded here."""
        await self._execute_decision(rid, action, duration, sender, announce=True)

    async def _revoke(self, rid: int, sender: str) -> None:
        """Room entry point for the operator kill switch (works on pending
        AND active grants; effective-expired grants refuse as a no-op).
        Also a thin caller of the one decision implementation."""
        await self._execute_decision(rid, "revoke", None, sender, announce=True)

    async def _revoke_many(self, sender: str) -> None:
        """'revoke all': every effective-ACTIVE grant. Revokes one at a
        time through the store, then posts ONE summary. Zero revocations
        is announced, never silent.

        The audit chain gets ONE addressable entry per revoked grant
        (review P26: the old synthetic ``grant_id=0`` summary row could
        not be tied to any grant).
        """
        numbers = self._store.revoke_all_grants()
        count = len(numbers)
        logger.info("decision: action=revoke_all outcome=done sender=%s count=%d", sender, count)
        for rid in numbers:
            # Non-widening: an audit failure is surfaced loudly and the
            # revocation stands.
            try:
                self._audit_decision(
                    rid,
                    "revoked",
                    "revoke_all",
                    sender,
                    self._store.get_record(rid).items,
                )
            except LogWriteError as exc:
                logger.error(
                    "AUDIT: revoke_all decision entry for #%d failed: %s", rid, exc
                )
        if not count:
            await self._post(f"{ICON_REFUSED} Nothing to revoke (all grants).")
            return
        await self._post(
            self._compose(
                f"{REVOKE_EMOJI} **Revoked {count} grant(s)** — no undo for a"
                " bulk revoke.",
                self._status_text(),
            )
        )

    # ------------------------------------------------------------ rendering

    def _render_decision(
        self, record, verb: str, duration: timedelta | None, undo: bool = False
    ) -> str:
        """One decision confirmation: verb icon + id + resulting expiry
        (ACTIVE only), the affected items as template-controlled bullet
        lines, and — for the reversible verbs (reject/revoke) — the undo
        window as the last line. The items come from the decided record
        (the store's authority), never from the request text."""
        head = f"{_VERB_ICONS[verb]} **{verb} #{record.request_number}**"
        if record.state == "active":
            expiry = (
                format_remaining(duration) + "."
                if duration
                else f"{self._expiry_label()}."
            )
            head += f" ({expiry})"
        else:
            head += "."
        if record.items:
            item_lines = [self._item_line(i) for i in record.items]
            head += "\n" + "\n".join(item_lines)
        if undo:
            head += (
                f"\n\nMistake? `undo {record.request_number}` within "
                f"{UNDO_GRACE_SECONDS}s re-opens it as a new request."
            )
        return head

    def _status_lines(self) -> list[str]:
        """The room's state block: active grants with their remaining
        TTL, then what is awaiting the approver. Item lines are the same
        template-controlled form as a request — a shared room shows
        every broker's items in one visual language."""
        lines = [f"{ICON_STATUS} **STATUS**"]
        lines.append("**Active grants**")
        active = [r for r in self._store.all_records() if r.state == "active"]
        if not active:
            lines.append("none")
        for rec in active:
            assert rec.expires_at is not None  # active grants always carry expiry
            remaining = format_remaining(rec.expires_at - self._now())
            lines.append(
                f"{ICON_ACTIVE} **#{rec.request_number}** — "
                + "+".join(sorted({op for i in rec.items for op in i["ops"]}))
                + f", {remaining} left"
            )
            lines += [self._item_line(item) for item in rec.items]
        lines.append("")
        pending = [r for r in self._store.all_records() if r.state == "pending"]
        if not pending:
            lines.append("**Awaiting your approval** — none")
        else:
            lines.append(f"**Awaiting your approval** ({len(pending)}):")
            now = self._now()
            for rec in pending:
                age = format_remaining(now - rec.created_at)
                line = f"{ICON_PENDING} **#{rec.request_number}** — waiting {age}"
                if now - rec.created_at >= timedelta(hours=4):
                    line += " — **stale?**"
                elif now - rec.created_at >= timedelta(hours=1):
                    pass  # aging display only, no state change
                lines.append(line)
        footer_parts = []
        if pending:
            footer_parts.append("Decide: `approve|reject <id> [expiry]`")
        if active:
            footer_parts.append("Kill: `revoke <id>` (mass: `revoke all`)")
        if footer_parts:
            lines.append("")
            lines.append(" · ".join(footer_parts))
        return lines

    def _status_text(self) -> str:
        return "\n".join(self._status_lines())

    async def _post_summary(self) -> None:
        await self._post(self._status_text())

    # ------------------------------------------------------------ housekeeping

    async def sweep(self) -> None:
        """One expiry notice per pending request that timed out, at most
        once per number per process lifetime. Called by the server loop."""
        for rec in self._store.all_records():
            if (
                rec.state in ("expired", "pending_timeout")
                or (
                    rec.state == "pending"
                    and self._now() - rec.created_at
                    >= self._store._pending_timeout  # noqa: SLF001 - sweep reads the rule
                )
            ) and rec.request_number not in self._swept:
                self._swept.add(rec.request_number)
                if rec.state == "pending":
                    continue  # not yet timed out; noticed only on real expiry
                await self._post(
                    f"{ICON_EXPIRED} **Request #{rec.request_number} expired"
                    " unanswered** — silence grants nothing. File a new request"
                    " if access is still needed."
                )

    async def request_state(self, request_number: int) -> RequestState:
        """Effective state of one request number (agent-facing status)."""
        return self._store.get(request_number)
