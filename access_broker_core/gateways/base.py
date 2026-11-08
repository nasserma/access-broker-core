"""ApprovalGateway: the adapter contract that actually exists.

An adapter is a platform shell around ONE transport. It owns its
lifecycle (``start``/``stop``) and exposes the transport the core sends
through (``.transport``, rebound by the factory — see
``gateways.__init__.build_gateway``). It owns NO decision semantics: the
core holds all of them and can only call store transitions, which refuse
decided/unknown numbers.

The previous version of this module declared a three-method Protocol
(``start``/``stop``/``notify_request``) with synchronous signatures and
a ``notify_request`` method no adapter ever implemented (review P15:
the construction contract was fiction — the factory never rebound the
transport and this Protocol never described a real adapter). It is
replaced by the real shape below.

Matrix is the v1 adapter (per goal contract D6); Signal/Telegram/Teams
adapters are v2+. Adapters receive approval requests and deliver the
human decision back through the grant store, sharing the SQLite store
with the main loop.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Protocol, runtime_checkable

from .logic import GatewayTransport


@runtime_checkable
class ApprovalGateway(Protocol):
    """A chat gateway shell that brokers human approval decisions for Tier 2.

    ``transport`` is the send/reaction seam the core is wired to; a class
    satisfying this Protocol is what ``register_adapter``'s builder must
    return (the factory additionally refuses a missing transport).
    """

    async def start(self) -> None:
        """Start the gateway task (fail-closed on any startup error)."""
        ...

    async def stop(self) -> None:
        """Stop the gateway cleanly."""
        ...

    @property
    def transport(self) -> GatewayTransport:
        """The transport the approval core sends and reacts through."""
        ...


__all__ = ["ApprovalGateway"]
