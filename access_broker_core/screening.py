"""Core content screening: deterministic inbound/outbound screen engine.

The content-direction wall that runs BEHIND the access wall
(``policy.py``). The access wall answers "may the agent do this?";
this module answers "is the CONTENT the operation is about to move
acceptable, in either direction?" It never grants, widens, or narrows
access: it can only refuse a content transit the access wall already
allowed, or annotate one.

Design note: review/contentScreeningDesignNote-2026-10-01.md (owner
rulings recorded inline: per-rule ``block`` | ``flag``, default
``block`` = fail-safe; deterministic-only v1, the model arm is a later
config flip that ANNOTATES, never releases).

Contract:

- PURE and SYNCHRONOUS in v1: no I/O, no clock, no network. The model
  arm, when it lands, is an isolated client behind a frozen protocol
  and fails open-to-unscreened; the deterministic engine keeps this
  module's purity.
- Deterministic rules scan the FULL payload bytes. Only the (dormant)
  model window is capped: ``MODEL_WINDOW_BYTES``.
- Fail-closed: a malformed payload or an engine error is REFUSED with
  ``screen_error`` — never raises, never proceeds. A rule HIT obeys the
  rule's configured action (``block`` default / ``flag``); an engine
  ERROR is always a refusal regardless of per-rule action.
- Config is additive: an absent ``screening:`` key means the screen is
  OFF (byte-identical broker behavior); a present-but-malformed block
  is refuse-to-start (``ValueError``), never ignored.
- Fixed vocabularies: verdicts, reasons, actions, and directions are
  enums; audit fields and tests are exact, the same discipline as
  ``policy.py::Reason``.

The seed rule vocabulary below is presented for owner review in the
stage report (plan Stage 1 item 2); it is configuration, not policy —
owners extend, disable, or tighten it per broker.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any

#: Dormant model-arm window cap (owner ruling 2026-10-01: 8 KiB default,
#: owner-configurable). The deterministic engine scans FULL bytes and is
#: NOT capped by this constant; only the later model annotator consumes it.
MODEL_WINDOW_BYTES = 8192

#: Hard cap on configured rule names and rules per direction (config is
#: owner-side, but a runaway config must refuse-to-start, not OOM the boot).
_MAX_RULES = 256
_MAX_NAME_LENGTH = 128


class ScreenAction(enum.Enum):
    """What a deterministic rule hit does. Owner ruling 2026-10-01:
    per-rule configurable, default BLOCK (fail-safe)."""

    BLOCK = "block"
    FLAG = "flag"


class ScreenDirection(enum.Enum):
    """Which content direction a rule applies to."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


class ScreenVerdict(enum.Enum):
    """Outcome of one screen run. Fixed vocabulary: audit fields and
    tests are exact."""

    CLEAR = "clear"
    REFUSED = "refused"
    FLAGGED = "flagged"
    #: Reserved for the later model arm (fail-open posture); never
    #: produced by the deterministic engine.
    UNSCREENED = "unscreened"


class ScreenReason(enum.Enum):
    """Fixed reason vocabulary carried on the result. ``clear`` means no
    rule hit. Rule hits name the rule. ``screen_error`` covers malformed
    payloads and engine errors (fail-closed)."""

    CLEAR = "clear"
    BLOCKED = "blocked"
    FLAGGED = "flagged"
    SCREEN_ERROR = "screen_error"
    #: Reserved for the later model arm (unreachable / timeout); never
    #: produced by the deterministic engine.
    MODEL_UNAVAILABLE = "model_unavailable"


@dataclass(frozen=True)
class ScreenRule:
    """One deterministic rule: a compiled regex, an action, a direction."""

    name: str
    pattern: re.Pattern[str]
    action: ScreenAction
    direction: ScreenDirection = ScreenDirection.BOTH


#: Screen payload content kinds. Metadata-only screens (data broker
#: inbound envelopes) pass ``kind=metadata``; body screens pass
#: ``kind=body``. The engine treats both identically (the kind rides
#: the audit line); it exists so an owner can scope rules by it.
KINDS = frozenset({"metadata", "body"})


@dataclass(frozen=True)
class ScreenPayload:
    """What the broker assembles at a wiring point. Bounded by design:
    the engine never receives bulk bytes that did not already transit
    the broker; the /transfer staged-byte boundary is untouched."""

    direction: ScreenDirection
    backend: str
    account: str
    resource: str
    op: str
    content: str
    kind: str = "body"


@dataclass(frozen=True)
class ScreenResult:
    """The outcome one wiring point acts on and audits. Audit value is
    ``verdict.value`` plus ``matched`` (rule names); the fixed audit
    field vocabulary maps verdicts 1:1."""

    verdict: ScreenVerdict
    reason: ScreenReason
    matched: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        """False = the operation must not proceed (fail-closed arm)."""
        return self.verdict is not ScreenVerdict.CLEAR and (
            self.verdict is ScreenVerdict.FLAGGED
            or self.verdict is ScreenVerdict.UNSCREENED
        ) or self.verdict is ScreenVerdict.CLEAR

    def audit_value(self) -> str | None:
        """The optional hashed audit field value (Stage 2 seam): None
        means the caller does not declare a screen."""
        return None if self.verdict is ScreenVerdict.CLEAR else self.verdict.value


def _compile(value: Any, where: str) -> re.Pattern[str]:
    if not isinstance(value, str) or not value:
        raise ValueError(f"screening rule {where}: pattern must be a non-empty string")
    try:
        return re.compile(value, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"screening rule {where}: invalid regex: {exc}") from exc


def _screen_action(value: Any, where: str) -> ScreenAction:
    # Owner ruling 2026-10-01: absent action = BLOCK (fail-safe default).
    if value is None:
        return ScreenAction.BLOCK
    try:
        return ScreenAction(str(value))
    except ValueError as exc:
        raise ValueError(f"screening rule {where}: unknown action {value!r}") from exc


def _screen_direction(value: Any, where: str) -> ScreenDirection:
    if value is None:
        return ScreenDirection.BOTH
    try:
        return ScreenDirection(str(value))
    except ValueError as exc:
        raise ValueError(f"screening rule {where}: unknown direction {value!r}") from exc


def _rule_name(value: Any, where: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_NAME_LENGTH
        or not re.fullmatch(r"[a-z0-9_]+", value)
    ):
        raise ValueError(
            f"screening rule {where}: name must be lowercase [a-z0-9_] (max {_MAX_NAME_LENGTH})"
        )
    return value


def _parse_rules(mapping: dict[str, Any], where: str) -> tuple[ScreenRule, ...]:
    raw = mapping.get("rules")
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"screening {where}: rules must be a list")
    rules: list[ScreenRule] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        where_i = f"{where}.rules[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"screening {where_i}: rule must be a mapping")
        if not isinstance(item.get("enabled", True), bool):
            raise ValueError(f"screening {where_i}: enabled must be a boolean")
        if item.get("enabled") is False:
            continue
        name = _rule_name(item.get("name"), where_i)
        if name in seen:
            raise ValueError(f"screening {where_i}: duplicate rule name {name!r}")
        seen.add(name)
        rules.append(
            ScreenRule(
                name=name,
                pattern=_compile(item.get("pattern"), where_i),
                action=_screen_action(item.get("action"), where_i),
                direction=_screen_direction(item.get("direction"), where_i),
            )
        )
    if len(rules) > _MAX_RULES:
        raise ValueError(f"screening {where}: more than {_MAX_RULES} rules")
    return tuple(rules)


def from_config(config: Any) -> ScreenConfig | None:
    """Parse the additive ``screening:`` config block. None = screen OFF
    (key absent or enabled absent/false): the broker's behavior is
    byte-identical. A present-but-malformed block raises ValueError —
    refuse-to-start, never ignore (suite invariant)."""

    if config is None:
        return None
    if not isinstance(config, dict):
        raise ValueError("screening: config block must be a mapping")
    enabled = config.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("screening: enabled must be a boolean")
    if enabled is not True:
        return None
    inbound = config.get("inbound", {})
    outbound = config.get("outbound", {})
    for label, block in (("inbound", inbound), ("outbound", outbound)):
        if not isinstance(block, dict):
            raise ValueError(f"screening {label}: must be a mapping")
    inbound_rules = _parse_rules(inbound, "inbound")
    outbound_rules = _parse_rules(outbound, "outbound")
    # Model arm is deferred (owner ruling 2026-10-01): a model block may
    # be present but MUST be disabled, or the boot refuses — the model
    # annotator does not exist yet and a config naming it is a lie.
    model = config.get("model")
    if model is not None:
        if not isinstance(model, dict):
            raise ValueError("screening.model: must be a mapping")
        if model.get("enabled") is True:
            raise ValueError(
                "screening.model: the model annotator is not implemented yet "
                "(design note §3 step 3, deferred); enabled must be false or absent"
            )
    return ScreenConfig(inbound_rules=inbound_rules, outbound_rules=outbound_rules)


def seed_rules() -> tuple[ScreenRule, ...]:
    """The seed rule vocabulary shipped by the core (presented for owner
    review in the Stage 1 report). Owners extend, disable, or tighten
    per broker; the seeds establish the pattern shapes. Secret-token
    shapes align with the audit module's credential-scrubbing intent
    (audit.py never stores them; this screen refuses to MOVE them).

    Patterns are deliberately narrow high-precision shapes; broad PII
    matching is owner config, not a seed.
    """

    return (
        # Token-shaped secrets (block by default in BOTH directions):
        # classic bearer/API-key prefixes with realistic tails.
        ScreenRule(
            name="secret_bearer_token",
            pattern=_compile(
                r"\b(?:Bearer|token|api[_-]?key)\s*[:=]?\s*['\"]?[A-Za-z0-9_\-\.]{16,}",
                "seed",
            ),
            action=ScreenAction.BLOCK,
        ),
        ScreenRule(
            name="secret_private_key",
            pattern=_compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |)PRIVATE KEY-----", "seed"),
            action=ScreenAction.BLOCK,
        ),
        # Prompt-injection signatures (INBOUND only; block default per
        # the fail-safe ruling — owners flip to flag if they prefer the
        # annotate-only posture for a class of reads).
        ScreenRule(
            name="injection_ignore_instructions",
            pattern=_compile(r"\bignore\b[^.]{0,30}\b(?:instructions|prompts?|rules?)\b", "seed"),
            action=ScreenAction.BLOCK,
            direction=ScreenDirection.INBOUND,
        ),
        ScreenRule(
            name="injection_reveal_system",
            # Long pattern: split across concatenated literals (E501).
            pattern=_compile(
                r"\b(?:reveal|repeat|print|output)\b[^.]{0,40}"
                r"\b(?:system prompt|instructions|secret)\b",
                "seed",
            ),
            action=ScreenAction.BLOCK,
            direction=ScreenDirection.INBOUND,
        ),
    )


@dataclass(frozen=True)
class ScreenConfig:
    """Parsed, immutable screen configuration (screen ON)."""

    inbound_rules: tuple[ScreenRule, ...] = ()
    outbound_rules: tuple[ScreenRule, ...] = ()

    def __post_init__(self) -> None:
        for rule in self.inbound_rules + self.outbound_rules:
            if not isinstance(rule, ScreenRule):
                raise ValueError("screening: rules must be ScreenRule instances")

    @classmethod
    def with_seeds(cls) -> ScreenConfig:
        """Convenience for adopters: the seed vocabulary as the starting
        config (inbound + outbound lists both carry the BOTH-direction
        seeds; direction filtering happens at run time)."""

        seeds = seed_rules()
        return cls(inbound_rules=seeds, outbound_rules=seeds)


def _valid_payload(payload: Any) -> bool:
    return (
        isinstance(payload, ScreenPayload)
        and isinstance(payload.direction, ScreenDirection)
        and isinstance(payload.backend, str)
        and isinstance(payload.account, str)
        and isinstance(payload.resource, str)
        and isinstance(payload.op, str)
        and isinstance(payload.content, str)
        and payload.kind in KINDS
    )


def run(config: ScreenConfig | None, payload: Any) -> ScreenResult:
    """Screen one payload deterministically. PURE: no I/O, no clock.

    - config None (screen off): CLEAR — the wiring point proceeds
      byte-identically and audits nothing (the caller passes no screen
      field). This is the only CLEAR that carries no evaluation.
    - Malformed payload or engine error: REFUSED / screen_error —
      fail-closed regardless of per-rule action (an engine error is
      never a rule hit).
    - Rule hit with action BLOCK (the default): REFUSED / blocked.
    - Rule hit with action FLAG: FLAGGED / flagged — proceed with the
      annotation; the wiring point renders it and audits it.
    """

    if config is None:
        return ScreenResult(ScreenVerdict.CLEAR, ScreenReason.CLEAR)
    if not _valid_payload(payload):
        return ScreenResult(ScreenVerdict.REFUSED, ScreenReason.SCREEN_ERROR)
    rules = (
        config.inbound_rules
        if payload.direction is ScreenDirection.INBOUND
        else config.outbound_rules
    )
    try:
        blocked: list[str] = []
        flagged: list[str] = []
        for rule in rules:
            if rule.direction is not ScreenDirection.BOTH and (
                rule.direction is not payload.direction
            ):
                continue
            if rule.pattern.search(payload.content) is not None:
                if rule.action is ScreenAction.BLOCK:
                    blocked.append(rule.name)
                else:
                    flagged.append(rule.name)
    except Exception:  # noqa: BLE001 - hostile-content defense
        return ScreenResult(ScreenVerdict.REFUSED, ScreenReason.SCREEN_ERROR)
    if blocked:
        return ScreenResult(
            ScreenVerdict.REFUSED, ScreenReason.BLOCKED, tuple(blocked)
        )
    if flagged:
        return ScreenResult(
            ScreenVerdict.FLAGGED, ScreenReason.FLAGGED, tuple(flagged)
        )
    return ScreenResult(ScreenVerdict.CLEAR, ScreenReason.CLEAR)
