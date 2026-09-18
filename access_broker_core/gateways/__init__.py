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

build_gateway contract (unchanged from the source repositories):

- ``config_gateway_section`` is the ``gateway:`` mapping with EXACTLY
  ONE adapter key whose value is that adapter's field dict; config
  validation (per broker) enforces the one-gateway rule, the factory
  re-checks it and fails closed anyway.
- Every ``*_env`` field is environment-indirect: the value names an env
  var that MUST be set at boot (fail closed, never a silent None). Plain
  string values also support ``${VARNAME}`` expansion. Secrets are never
  stored in config, only referenced.
- The allowlisted approver is ``allowed_senders[0]`` (one human owner
  per the D4 contract; the core allowlist-checks every inbound event).
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

from .logic import ApprovalGatewayCore, GatewayTransport

_ADAPTER_BUILDERS: dict[str, Callable] = {}
"""Broker-registered platform adapter builders (adapters are per-broker
platform shells; the core provides the registry seam and the shared
wiring contract)."""


def register_adapter(name: str, builder: Callable) -> None:
    """Register a platform adapter builder under `name` (e.g. 'matrix').

    builder signature: (core, fields, approver) -> (adapter, surface_id).
    Re-registering a name replaces it (brokers own their adapter sets)."""
    _ADAPTER_BUILDERS[name] = builder


def supported_adapters() -> tuple[str, ...]:
    """The registered adapter names (for config error messages)."""
    return tuple(sorted(_ADAPTER_BUILDERS))


class GatewayConfigError(ValueError):
    """The gateway configuration section cannot be turned into a gateway."""


class _PlaceholderTransport(GatewayTransport):
    """Stand-in transport used ONLY between core construction and the
    rebind to the adapter's real transport (see build_gateway). Any use
    before the rebind is a wiring bug and must be loud."""

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


def _resolve_fields(section: dict[str, Any]) -> dict[str, Any]:
    """Resolve env-indirection in one adapter section.

    ``<name>_env: VAR`` -> ``name`` resolved from os.environ (required).
    Plain string values expand a single ``${VAR}`` reference. Everything
    else passes through unchanged.
    """
    resolved: dict[str, Any] = {}
    for key, value in section.items():
        if isinstance(value, str) and key.endswith("_env"):
            resolved[key[: -len("_env")]] = _env_required(value)
        elif isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            resolved[key] = _env_required(value[2:-1])
        else:
            resolved[key] = value
    return resolved


def _approver_of(section: dict[str, Any], adapter: str) -> str:
    senders = section.get("allowed_senders")
    if (
        not isinstance(senders, (list, tuple))
        or not senders
        or not all(isinstance(s, str) and s for s in senders)
    ):
        raise GatewayConfigError(
            f"gateway.{adapter}: 'allowed_senders' must be a nonempty list of sender ids"
        )
    return senders[0]


def build_gateway(
    config_gateway_section: dict[str, Any],
    store: GrantStore,
    clock,
    audit=None,
) -> tuple[ApprovalGatewayCore, Any]:
    """Construct the ONE configured approval gateway from its config section.

    config_gateway_section: the ``gateway:`` mapping with exactly one
    registered adapter key whose value is that adapter's field dict.
    store: the GrantStore all decisions route through. clock: injected
    clock (Callable[[], datetime]) shared with the store/policy. audit:
    optional AuditLog; when present the gateway core writes every human
    decision into the hash-chained audit chain (review finding F1:
    decisions are audit-class events).

    Returns (core, adapter): core is the ApprovalGatewayCore wired to the
    adapter's transport with approver = allowed_senders[0]; adapter is the
    platform gateway object (async start()/stop(), .transport where the
    adapter exposes one). Raises GatewayConfigError on an unknown adapter,
    a section that does not name exactly one adapter, missing fields, or
    an unset environment variable behind any ``*_env`` / ``${VAR}`` value.
    """
    if not isinstance(config_gateway_section, dict) or not config_gateway_section:
        raise GatewayConfigError(
            "gateway config section must be a mapping with exactly one adapter key "
            f"(registered: {', '.join(supported_adapters())})"
        )
    adapter_keys = [k for k in config_gateway_section if not str(k).startswith("_")]
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

    section = config_gateway_section[adapter_key]
    if not isinstance(section, dict):
        raise GatewayConfigError(f"gateway.{adapter_key}: section must be a mapping")
    fields = _resolve_fields(section)

    approver = _approver_of(section, adapter_key)

    core = ApprovalGatewayCore(
        store=store,
        transport=_PlaceholderTransport(),
        approver=approver,
        now=clock,
        surface="",  # set by the builder below once the surface id is known
        audit=audit,
    )
    adapter, surface = _ADAPTER_BUILDERS[adapter_key](core, fields, approver)
    core._surface = surface  # noqa: SLF001 - construction wiring
    return core, adapter


__all__ = [
    "GatewayConfigError",
    "build_gateway",
    "register_adapter",
    "supported_adapters",
]
