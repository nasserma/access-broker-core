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

Canonical emoji set (one grammar across all four gateways; transports
without native reactions still post the four controls as text lines):
approve 👍, reject 👎, revoke ⛔, status 📋.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import difflib
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from access_broker_core.audit import AuditLog, LogWriteError
from access_broker_core.grants import GrantStore, RejectReason, RequestState

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

_HELP_TEXT = """**How to decide**

**Reactions** — tap on a request message:
👍 approve · 👎 reject · ⛔ revoke · 📋 status

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
_REVOKE_TARGET_RE = re.compile(
    r"^revoke\s+(all)$",
    re.IGNORECASE,
)

_COMMANDS = ("approve", "reject", "revoke", "undo", "status")

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
        if _REVOKE_TARGET_RE.match(text):
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


@dataclass
class PendingRequest:
    """Gateway-side view of one posted (or unposted) pending request."""

    request_number: int
    justification: str
    items: list[dict]
    created_at: datetime = field(default_factory=datetime.now)


class TransportError(Exception):
    """Raised by transports on delivery failure; the gateway fails closed
    (the request stays pending; a notice is attempted on the next event)."""


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

    async def send_to_approver(self, text: str) -> str:
        """Direct-to-approver channel (1:1 chat) when the room is not the
        approval surface. Default: same as send_message."""
        return await self.send_message(text)


class ApprovalGatewayCore:
    """Routes the allowlisted approver's reactions and typed commands into
    GrantStore transitions and renders every outcome back through the
    transport. Transport-agnostic: tested once with a fake transport; the
    four adapters map platform events to (handle_reaction | handle_reply)
    and implement send_message/add_reaction.

    The core holds NO authorization power: it can only call store
    transitions, which refuse decided/unknown numbers.
    """

    def __init__(
        self,
        store: GrantStore,
        transport: GatewayTransport,
        approver: str,
        now: Callable[[], datetime],
        surface: str = "approvals",
        audit: AuditLog | None = None,
    ) -> None:
        """store: the GrantStore all decisions route through.
        transport: the gateway's I/O shell. approver: the single
        allowlisted sender identity on THIS gateway (platform-specific
        shape; Matrix user id, Telegram user id, Teams AAD object id,
        signal number/uuid). Messages from any other sender are ignored
        silently. now: injected clock. surface: platform destination
        identifier (room id / chat id / conversation id) — for logging
        and adapter use; the core never addresses a second surface.
        audit: the broker's AuditLog. When present, every HUMAN decision
        (submit, approve, reject, revoke, undo) is written into the
        hash-chained audit log with the approver identity — the audit
        record of owner decisions is a suite invariant (adversarial
        review finding F1, 2026-09-16). When None (tests, headless
        deployments) decision entries are skipped, as before."""
        self._store = store
        self._transport = transport
        self._approver = approver
        self._now = now
        self._surface = surface
        self._audit = audit
        self._event_to_request: dict[str, int] = {}
        self._swept: set[int] = set()
        self._undo_windows: dict[int, tuple[datetime, dict]] = {}

    # ------------------------------------------------------------ audit

    def _audit_decision(
        self,
        rid: int,
        decision: str,
        reason: str,
        sender: str,
        items: list[dict] | None = None,
    ) -> None:
        """Record one human decision in the audit chain.

        Entries carry the approver identity in ``principal`` — the human
        is an audit principal, not an anonymous actor. Item scope is
        summarized from the FIRST item (the store's items are the
        authority; the audit entry is the evidence of WHO decided and
        WHAT was decided on). Raises LogWriteError on write failure;
        callers on a state-WIDENING path (approve, undo-recreate) must
        fail closed, others log and proceed (mirrors tools.py).
        """
        if self._audit is None:
            return
        first = (items or [{}])[0]
        self._audit.record(
            account=str(first.get("account", "")),
            resource=str(first.get("resource", "")),
            operation=",".join(sorted(first.get("ops", []))) or "lifecycle",
            grant_id=rid,
            decision=decision,
            reason=reason,
            backend=first.get("backend"),
            principal=f"approver:{sender}",
        )

    # ------------------------------------------------------------- posting

    def render_request(self, number: int, justification: str, items: list[dict]) -> str:
        """Markdown for a pending request: header names the id, each item
        is ONE line (backend/account/resource + ops) so item identity
        survives phone-width wrapping."""
        lines = [
            f"⏳ **PENDING #{number}** — awaiting your approval",
            f"Justification: {justification}",
        ]
        for i, item in enumerate(items, start=1):
            ops = ", ".join(sorted(item.get("ops", [])))
            lines.append(
                f"{i}. **{item['backend']}** {item['account']}:"
                f"`{item['resource']}` — {ops}"
            )
        lines.append(
            "Expiry if approved: 24h (or `approve <id> 8h` for shorter)"
        )
        lines.append("Decide: `approve|reject <id> [expiry]`")
        return "\n".join(lines)

    async def post_request(self, number: int, justification: str, items: list[dict]) -> str:
        """Post a pending request and pre-place the four decision
        reactions (transports without reactions no-op). Returns the
        posted event id. The event→request mapping is in-memory only —
        sound because the store rejects all pending requests at restart,
        so post-restart reactions resolve to nothing."""
        event_id = await self._transport.send_message(
            self.render_request(number, justification, items)
        )
        for emoji in DECISION_EMOJIS:
            await self._transport.add_reaction(event_id, emoji)
        self._event_to_request[event_id] = number
        return event_id

    async def notify_request(
        self, request_number: int, justification: str, items: list[dict]
    ) -> str:
        """Public entry point: render + post one pending request.

        The submission decision is audited here (human-plane view of the
        agent's submit; agent-side ``submitted`` entries come from
        tools.py). Audit-write failure does NOT un-post the request —
        the submission is non-widening — but is surfaced loudly."""
        try:
            self._audit_decision(
                request_number, "submitted", "pending_approval", self._approver, items
            )
        except LogWriteError as exc:
            logger.error(
                "AUDIT: submit decision entry for request #%d failed: %s",
                request_number,
                exc,
            )
        return await self.post_request(request_number, justification, items)

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
        47', 'revoke all', 'undo 47', 'status') — allowlist first."""
        if sender != self._approver:
            return
        parsed = parse_reply(text)
        if parsed is None:
            first_word = text.strip().split(" ", 1)[0] if text.strip() else ""
            closest = closest_command(first_word)
            if closest:
                await self._transport.send_message(
                    f"Unknown command '{first_word}' — closest: `{closest}`. "
                    "Type `status` to see the command list."
                )
            else:
                await self._transport.send_message(_HELP_TEXT)
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

    # ------------------------------------------------------------------ undo

    async def _undo(self, rid: int, sender: str) -> None:
        """Undo a JUST-made reject/revoke within the 15s grace: creates a
        NEW pending request with the original items (never resurrects the
        decided number). Fail closed: unknown id, expired, or consumed
        window all refuse; a restart closes every window."""
        window = self._undo_windows.get(rid)
        if window is None or self._now() >= window[0]:
            self._undo_windows.pop(rid, None)
            await self._transport.send_message(
                f"Undo window for #{rid} closed. "
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

    async def _decide(
        self, rid: int, action: str, duration: timedelta | None, sender: str
    ) -> None:
        """Apply an approve/reject and post the outcome + refreshed
        status. No silent decisions; store RejectReason is reported,
        never swallowed."""
        if action == "approve":
            result = self._store.approve(rid, duration=duration)
            if isinstance(result, RejectReason):
                await self._refused(rid, action, result, sender)
                return
            # Write-BEFORE-notify: the state-widening decision is in the
            # audit chain before the human sees its confirmation. A failed
            # decision entry aborts the approval flow (fail closed): the
            # grant exists in the store but was never confirmed visibly,
            # which the approver will notice — the inverse (a confirmed
            # grant with no audit entry) is the F1 defect class.
            try:
                self._audit_decision(
                    rid, "approved", "grant_active", sender, result.items
                )
            except LogWriteError as exc:
                logger.error(
                    "AUDIT: approve decision entry for request #%d failed (%s); "
                    "not confirmed — the grant is ACTIVE in the store; recover "
                    "with revoke %d",
                    rid,
                    exc,
                    rid,
                )
                await self._transport.send_message(
                    f"⚠️ Approve #{rid} reached the grant store but its audit "
                    "entry FAILED — grant NOT confirmed (the grant IS active; "
                    f"re-approving will not work). Resolve the audit log, then "
                    f"revoke with `revoke {rid}` if this was not intended."
                )
                return
            logger.info(
                "decision: rid=%d action=approve outcome=granted sender=%s items=%d expiry=%s",
                rid,
                sender,
                len(result.items),
                result.expires_at,
            )
            self._event_to_request = {
                e: n for e, n in self._event_to_request.items() if n != rid
            }
            await self._transport.send_message(
                self._render_decision(result, "Approved", duration) + "\n\n——\n\n"
                + self._status_text()
            )
        else:
            if not self._store.reject(rid):
                await self._refused(rid, action, "already decided or unknown", sender)
                return
            # Non-widening (capability only ever shrinks): audit failure
            # is surfaced loudly, the decision stands.
            try:
                self._audit_decision(rid, "rejected", "rejected_by_approver", sender)
            except LogWriteError as exc:
                logger.error(
                    "AUDIT: reject decision entry for request #%d failed: %s", rid, exc
                )
            logger.info(
                "decision: rid=%d action=reject outcome=rejected sender=%s", rid, sender
            )
            record = self._store.get_record(rid)
            self._arm_undo(rid, record)
            self._event_to_request = {
                e: n for e, n in self._event_to_request.items() if n != rid
            }
            await self._transport.send_message(
                self._render_decision(record, "Rejected", None, undo=True)
                + "\n\n——\n\n"
                + self._status_text()
            )

    async def _refused(
        self, rid: int, action: str, reason: object, sender: str
    ) -> None:
        logger.info(
            "decision: rid=%d action=%s outcome=refused sender=%s reason=%s",
            rid,
            action,
            sender,
            reason,
        )
        await self._transport.send_message(f"Cannot {action} #{rid}: {reason}")

    async def _revoke(self, rid: int, sender: str) -> None:
        """Operator kill switch on one number (works on pending AND
        active grants; effective-expired grants refuse as no-op)."""
        if not self._store.revoke(rid):
            await self._refused(rid, "revoke", "unknown, decided, or expired", sender)
            return
        # Non-widening: audit failure surfaced loudly, revocation stands.
        try:
            self._audit_decision(rid, "revoked", "revoked_by_approver", sender)
        except LogWriteError as exc:
            logger.error(
                "AUDIT: revoke decision entry for request #%d failed: %s", rid, exc
            )
        logger.info("decision: rid=%d action=revoke outcome=revoked sender=%s", rid, sender)
        record = self._store.get_record(rid)
        self._arm_undo(rid, record)
        await self._transport.send_message(
            self._render_decision(record, "Revoked", None, undo=True)
            + "\n\n——\n\n"
            + self._status_text()
        )

    async def _revoke_many(self, sender: str) -> None:
        """'revoke all': every effective-ACTIVE grant. Revokes one at a
        time through the store, then posts ONE summary. Zero revocations
        is announced, never silent."""
        count = self._store.revoke_all()
        logger.info("decision: action=revoke_all outcome=done sender=%s count=%d", sender, count)
        if count:
            # Non-widening: one summary entry for the bulk decision;
            # individual revocations are traceable via the store + undo
            # windows; per-id entries would multiply without adding
            # evidentiary value beyond this one.
            try:
                self._audit_decision(
                    0, "revoked", f"revoke_all ({count} grants)", sender
                )
            except LogWriteError as exc:
                logger.error("AUDIT: revoke_all decision entry failed: %s", exc)
        if not count:
            await self._transport.send_message("Nothing to revoke (all grants).")
            return
        await self._transport.send_message(
            f"**Revoked {count} grant(s)**.\n\n——\n\n" + self._status_text()
        )

    # ------------------------------------------------------------ rendering

    def _render_decision(
        self, record, verb: str, duration: timedelta | None, undo: bool = False
    ) -> str:
        head = f"**{verb} #{record.request_number}**"
        if record.state == "active":
            expiry = (
                format_remaining(duration) + "." if duration else "24h."
            )
            head += f" ({expiry})"
        else:
            head += "."
        if record.items:
            item_lines = [
                f"  **{i['backend']}** {i['account']}:`{i['resource']}` — "
                + ", ".join(sorted(i.get("ops", [])))
                for i in record.items
            ]
            head += "\n" + "\n".join(item_lines)
        if undo:
            head += (
                f"\n\nMistake? `undo {record.request_number}` within "
                f"{UNDO_GRACE_SECONDS}s re-opens it as a new request."
            )
        return head

    def _status_lines(self) -> list[str]:
        lines = ["**Active grants**"]
        active = [r for r in self._store.all_records() if r.state == "active"]
        if not active:
            lines.append("none")
        for rec in active:
            assert rec.expires_at is not None  # active grants always carry expiry
            remaining = format_remaining(rec.expires_at - self._now())
            lines.append(
                f"✅ **#{rec.request_number}** — "
                + "+".join(sorted({op for i in rec.items for op in i["ops"]}))
                + f", {remaining} left"
            )
            for item in rec.items:
                lines.append(
                    f"   **{item['backend']}** {item['account']}:`{item['resource']}` — "
                    + ", ".join(sorted(item.get("ops", [])))
                )
        lines.append("")
        pending = [r for r in self._store.all_records() if r.state == "pending"]
        if not pending:
            lines.append("Awaiting your approval: none")
        else:
            lines.append(f"**Awaiting your approval** ({len(pending)}):")
            now = self._now()
            for rec in pending:
                age = format_remaining(now - rec.created_at)
                line = f"⏳ **#{rec.request_number}** — waiting {age}"
                if now - rec.created_at >= timedelta(hours=4):
                    line += " — **stale?**"
                elif now - rec.created_at >= timedelta(hours=1):
                    pass  # aging display only, no state change
                lines.append(line)
        footer_parts = []
        if pending:
            footer_parts.append("Decide a request: `approve|reject <id> [expiry]`")
        if active:
            footer_parts.append("Kill: `revoke <id>` (mass: `revoke all`)")
        if footer_parts:
            lines.append("")
            lines.append(" · ".join(f"`{p}`" for p in footer_parts))
        return lines

    def _status_text(self) -> str:
        return "\n".join(self._status_lines())

    async def _post_summary(self) -> None:
        await self._transport.send_message(self._status_text())

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
                await self._transport.send_message(
                    f"Request #{rec.request_number} expired unanswered. "
                    "Silence grants nothing."
                )

    async def request_state(self, request_number: int) -> RequestState:
        """Effective state of one request number (agent-facing status)."""
        return self._store.get(request_number)
