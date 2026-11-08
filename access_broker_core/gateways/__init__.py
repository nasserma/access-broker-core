"""Gateway construction wiring: config section -> (core, adapter).

Core half of the approval plane (S1 extraction). The core provides:

- :class:`ApprovalGatewayCore` and :class:`GatewayTransport` (logic.py):
  ALL decision semantics, transport-agnostic, tested once.
- :class:`GatewayConfigError` and the shared config-field rules
  (env indirection, allowlisted approver = allowed_senders[0],
  one-gateway-per-process).
- An adapter REGISTRY: platform adapters (matrix, telegram, teams,
  signal shells) are per-broker and register their builders here at
  import/boot time via :func:`register_adapter`. The core never imports
  a platform SDK.

build_gateway contract (2026-11 hygiene round, reviews P5/P15/P29/P30):

- ``config_gateway_section`` is the ``gateway:`` mapping with EXACTLY
  ONE adapter key whose value is that adapter's field dict; config
  validation (per broker) enforces the one-gateway rule, the factory
  re-checks it and fails closed anyway. The only other accepted
  top-level key is ``allow_without_audit``.
- Every ``*_env`` field is environment-indirect: the value names an env
  var that MUST be set at boot (fail closed, never a silent None).
  Plain string values AND list values support ``${VARNAME}`` expansion
  (a list element is expanded in place; an unset variable refuses the
  boot). Secrets are never stored in config, only referenced.
- The allowlisted approver is ``allowed_senders[0]`` (one human owner
  per the D4 contract; the core allowlist-checks every inbound event),
  read from the RESOLVED fields so ``['${APPROVER_ID}']`` yields the
  human's id rather than a literal ``${APPROVER_ID}``.
- A builder MAY declare its field set (``register_adapter(..., fields=
  (...))``); when it does, an unknown key in that adapter's section
  refuses the boot instead of silently defaulting.
- ``shared_room=true`` requires a ``command_prefix`` whose shape the
  inbound command regex can actually match (``[a-z][a-z0-9_-]{0,31}``);
  anything else refuses to start (a prefix no line can carry silently
  disables every typed command).
- The factory REBINDS the core's transport from the adapter after the
  builder runs (``adapter.transport``) and REFUSES to return a core
  that still carries the placeholder: a gateway that cannot send is a
  wiring bug, not a working gateway.
- An audit log is REQUIRED: every human decision is an audit-class
  event. A headless/test deployment must say so explicitly with
  ``allow_without_audit: true`` (fail-closed default, review P29).
- Returns ``(core, adapter)``: the core owns all decision semantics and
  routes through the adapter's transport; the adapter owns start()/stop()
  and platform event intake. The server wires lifecycle around both.

Unknown adapter keys raise :class:`GatewayConfigError` with the
registered set named - a typo must stop the boot, not silently disable
approvals.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from access_broker_core.grants import GrantStore

from .logic import (
    COMMAND_PREFIX_RE,
    DEFAULT_SEND_TIMEOUT_SECONDS,
    ApprovalGatewayCore,
    GatewayTransport,
)

_ADAPTER_BUILDERS: dict[str, Callable] = {}
"""Broker-registered platform adapter builders (adapters are per-broker
platform shells; the core provides the registry seam and the shared
wiring contract)."""

_ADAPTER_FIELDS: dict[str, tuple[str, ...] | None] = {}
"""Per-adapter declared field sets (None = declares nothing, the
back-compat shape: no unknown-key validation for that adapter)."""

_SHARED_FIELDS = frozenset(
    {"allowed_senders", "shared_room", "command_prefix", "send_timeout_seconds"}
)

_TOP_LEVEL_KEYS = frozenset({"allow_without_audit"})


def register_adapter(
    name: str,
    builder: Callable,
    fields: tuple[str, ...] | list[str] | None = None,
) -> None:
    """Register a platform adapter builder under `name` (e.g. 'matrix').

    builder signature: (core, fields, approver) -> (adapter, surface).
    Re-registering a name replaces it (brokers own their adapter sets).

    fields: the adapter's declared field names. When given, an unknown
    key in that adapter's config section refuses the boot (review P30):
    a typo'd field used to pass through to the builder and fail later or
    silently default. ``<field>_env`` forms are accepted for every
    declared field.
    """
    _ADAPTER_BUILDERS[name] = builder
    _ADAPTER_FIELDS[name] = tuple(fields) if fields is not None else None


def supported_adapters() -> tuple[str, ...]:
    """The registered adapter names (for config error messages)."""
    return tuple(sorted(_ADAPTER_BUILDERS))


class GatewayConfigError(ValueError):
    """The gateway configuration section cannot be turned into a gateway."""


class _PlaceholderTransport(GatewayTransport):
    """Stand-in transport used ONLY between core construction and the
    rebind to the adapter's real transport (see build_gateway). Any use
    before the rebind is a wiring bug and must be loud; the factory
    refuses to return a core still carrying it."""

    IS_PLACEHOLDER = True

    async def send_message(self, text: str) -> str:  # noqa: ARG002 - interface signature
        # pragma: no cover - wiring bug guard
        raise RuntimeError("gateway core used before its adapter transport was wired")

    async def add_reaction(self, event_id: str, emoji: str) -> None:  # noqa: ARG002 - interface signature
        # pragma: no cover - wiring bug guard
        raise RuntimeError("gateway core used before its adapter transport was wired")


def _env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise GatewayConfigError(
            f"gateway config references environment variable {name!r}, which is not set"
        )
    return value


def _expand_env_reference(value: Any) -> Any:
    """Expand a single ``${VAR}`` reference (fail closed when unset)."""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        return _env_required(value[2:-1])
    return value


def _resolve_fields(section: dict[str, Any]) -> dict[str, Any]:
    """Resolve env-indirection in one adapter section.

    ``<name>_env: VAR`` -> ``name`` resolved from os.environ (required).
    Plain string values expand a single ``${VAR}`` reference. LIST and
    TUPLE values are expanded element-wise (review P5: a list used to
    pass through unexpanded, so ``allowed_senders: ['${OWNER}']`` became
    a literal approver nobody could ever match). Everything else passes
    through unchanged.
    """
    resolved: dict[str, Any] = {}
    for key, value in section.items():
        if isinstance(value, str) and key.endswith("_env"):
            resolved[key[: -len("_env")]] = _env_required(value)
        elif isinstance(value, (list, tuple)):
            resolved[key] = [_expand_env_reference(item) for item in value]
        else:
            resolved[key] = _expand_env_reference(value)
    return resolved


def _approver_of(fields: dict[str, Any], adapter: str) -> str:
    """The allowlisted approver: ``allowed_senders[0]`` of the RESOLVED
    fields (review P5: reading the raw section produced a literal
    ``${VAR}`` approver and a deaf gateway)."""
    senders = fields.get("allowed_senders")
    if (
        not isinstance(senders, (list, tuple))
        or not senders
        or not all(isinstance(s, str) and s for s in senders)
    ):
        raise GatewayConfigError(
            f"gateway.{adapter}: 'allowed_senders' must be a nonempty list of sender ids"
        )
    return senders[0]


def _validate_section_keys(
    adapter: str, section: dict[str, Any], declared: tuple[str, ...] | None
) -> None:
    """Refuse unknown adapter-section keys against the builder's
    declared field set (review P30). Adapters that declare nothing keep
    the historical pass-through behavior."""
    if declared is None:
        return
    allowed = set(declared) | set(_SHARED_FIELDS)
    unknown = sorted(
        str(key)
        for key in section
        if key not in allowed
        and not (str(key).endswith("_env") and str(key)[: -len("_env")] in allowed)
    )
    if unknown:
        raise GatewayConfigError(
            f"gateway.{adapter}: unknown field(s) {unknown} "
            f"(declared: {sorted(declared)}; shared: {sorted(_SHARED_FIELDS)}) - "
            "a typo must stop the boot, not silently default"
        )


def build_gateway(
    config_gateway_section: dict[str, Any],
    store: GrantStore,
    clock,
    audit=None,
) -> tuple[ApprovalGatewayCore, Any]:
    """Construct the ONE configured approval gateway from its config section.

    config_gateway_section: the ``gateway:`` mapping with exactly one
    registered adapter key whose value is that adapter's field dict, and
    optionally ``allow_without_audit: true``. store: the GrantStore all
    decisions route through. clock: injected clock (Callable[[], datetime])
    shared with the store/policy. audit: the broker's AuditLog; when
    absent the boot is REFUSED unless ``allow_without_audit`` is set —
    an approval plane that silently records nothing is the defect the
    audit chain exists to prevent (review P29).

    Returns (core, adapter): core is the ApprovalGatewayCore wired to the
    adapter's transport with approver = allowed_senders[0]; adapter is the
    platform gateway object (async start()/stop(), .transport). Raises
    GatewayConfigError on an unknown adapter, a section that does not name
    exactly one adapter, unknown adapter fields (when declared), an
    unset environment variable behind any ``*_env`` / ``${VAR}`` value, a
    ``command_prefix`` the inbound grammar cannot match, a missing audit
    log, or an adapter that wired no transport.
    """
    if not isinstance(config_gateway_section, dict) or not config_gateway_section:
        raise GatewayConfigError(
            "gateway config section must be a mapping with exactly one adapter key "
            f"(registered: {', '.join(supported_adapters())})"
        )
    adapter_keys = [
        k
        for k in config_gateway_section
        if not str(k).startswith("_") and k not in _TOP_LEVEL_KEYS
    ]
    if len(adapter_keys) != 1:
        raise GatewayConfigError(
            "exactly one gateway adapter must be configured, got: "
            f"{sorted(map(str, adapter_keys))} "
            f"(registered: {', '.join(supported_adapters())})"
        )
    adapter_key = str(adapter_keys[0])
    if adapter_key not in _ADAPTER_BUILDERS:
        registered = ", ".join(supported_adapters())
        if not registered:
            registered = "NONE - the broker must register its adapters"
        raise GatewayConfigError(
            f"unknown gateway adapter {adapter_key!r} (registered: {registered})"
        )

    allow_without_audit = config_gateway_section.get("allow_without_audit", False)
    if allow_without_audit not in (True, False):
        raise GatewayConfigError("gateway 'allow_without_audit' must be a boolean")

    section = config_gateway_section[adapter_key]
    if not isinstance(section, dict):
        raise GatewayConfigError(f"gateway.{adapter_key}: section must be a mapping")
    _validate_section_keys(adapter_key, section, _ADAPTER_FIELDS.get(adapter_key))
    fields = _resolve_fields(section)

    # Shared-room routing (owner decision 2026-09-21, Option B): one
    # approval room may serve several broker gateways; each declares its
    # tag and requires prefixes on every typed command. The prefix is
    # mandatory with shared_room and forbidden as a bare declaration
    # without it (a prefix in a solo room is dead config that would
    # surprise a future reader).
    shared_room = fields.get("shared_room", False)
    command_prefix = fields.pop("command_prefix", None)
    fields.pop("shared_room", None)
    if shared_room not in (True, False):
        raise GatewayConfigError(
            f"gateway.{adapter_key}: 'shared_room' must be a boolean"
        )
    if shared_room and (not isinstance(command_prefix, str) or not command_prefix.strip()):
        raise GatewayConfigError(
            f"gateway.{adapter_key}: shared_room=true requires a nonempty "
            "'command_prefix' (the tag this gateway answers to, e.g. 'comms')"
        )
    if not shared_room and command_prefix is not None:
        raise GatewayConfigError(
            f"gateway.{adapter_key}: 'command_prefix' is only valid with "
            "shared_room=true (a solo room needs no prefixes)"
        )
    command_prefix = command_prefix.strip() if command_prefix else None
    if command_prefix is not None and not COMMAND_PREFIX_RE.match(command_prefix):
        raise GatewayConfigError(
            f"gateway.{adapter_key}: 'command_prefix' {command_prefix!r} cannot "
            "match the inbound command grammar (lowercase letter, then "
            "[a-z0-9_-], at most 32 characters); a prefix no inbound line can "
            "carry would silently disable every typed command"
        )

    send_timeout = fields.pop("send_timeout_seconds", DEFAULT_SEND_TIMEOUT_SECONDS)
    if (
        isinstance(send_timeout, bool)
        or not isinstance(send_timeout, (int, float))
        or send_timeout <= 0
    ):
        raise GatewayConfigError(
            f"gateway.{adapter_key}: 'send_timeout_seconds' must be a positive number, "
            f"got {send_timeout!r}"
        )

    approver = _approver_of(fields, adapter_key)
    if audit is None and not allow_without_audit:
        raise GatewayConfigError(
            "refusing to build a gateway without an audit log: every human decision "
            "is an audit-class event (suite invariant 2). Set "
            "gateway.allow_without_audit: true ONLY for a headless/test deployment."
        )

    core = ApprovalGatewayCore(
        store=store,
        transport=_PlaceholderTransport(),
        approver=approver,
        now=clock,
        audit=audit,
        shared_room=bool(shared_room),
        command_prefix=command_prefix,
        send_timeout_seconds=float(send_timeout),
    )
    adapter, _surface = _ADAPTER_BUILDERS[adapter_key](core, fields, approver)
    # Enforce the sendability contract (review P15): the adapter owns the
    # transport, the factory binds it, and a builder that wired nothing
    # stops the boot instead of producing a healthy-looking deaf gateway.
    transport = getattr(adapter, "transport", None)
    if transport is not None:
        core.bind_transport(transport)
    if not core.has_live_transport:
        raise GatewayConfigError(
            f"gateway.{adapter_key}: the adapter builder bound no transport "
            "(return an adapter exposing .transport, or call core.bind_transport) - "
            "the core could not send a single message"
        )
    return core, adapter


__all__ = [
    "GatewayConfigError",
    "build_gateway",
    "register_adapter",
    "supported_adapters",
]
