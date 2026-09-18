"""ApprovalGateway interface for Tier 2 human-approval gateways.

Matrix is the v1 adapter (per goal contract D6); Signal/Telegram adapters
are v2+. Adapters receive approval requests and deliver the human decision
back through the grant store, sharing the SQLite store with the main loop.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Protocol


class ApprovalGateway(Protocol):
    """A chat gateway that brokers human approval decisions for Tier 2."""

    def start(self) -> None:
        """Start the gateway task (fail-closed on any startup error)."""
        ...

    def stop(self) -> None:
        """Stop the gateway cleanly."""
        ...

    def notify_request(self, request_number: str, summary: str) -> None:
        """Publish a pending approval request to the human operator."""
        ...
