"""Tier 1 HTTP transport auth: MCP OAuth 2.1 resource-server role.

Per the MCP 2026-07-28 authorization spec:
- RFC 9728 protected resource metadata documents the resource and its
  authorization servers.
- RFC 8707 audience binding: access tokens must be issued for this resource
  (audience), not merely for a trusted issuer.
- Scopes communicated via WWW-Authenticate step-up challenges.

DESIGN NOTE (production delegation): this module deliberately performs NO
crypto and NO network I/O. The bearer-token check takes a *claims dict*
produced by a pluggable verifier function; in production that verifier is
the MCP SDK's auth stack (``auth_server_provider`` / ``token_verifier``
parameters on ``MCPServer.__init__``), which owns real JWT signature
verification, ``exp``/``nbf`` checks, and issuer validation. Decoding a JWT
payload without signature verification is NOT acceptable as a validation
mechanism — that is exactly why verification is delegated and this module
only enforces the resource-server-side *authorization* decisions
(audience binding per RFC 8707 and scope possession).
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any


class AuthError(Exception):
    """Raised on any transport authentication failure."""


class HttpOAuthValidator:
    """Validates bearer tokens on the streamable-HTTP transport.

    ``resource`` is this server's resource identifier (RFC 8707 audience);
    ``issuer`` is the trusted authorization server URL;
    ``scopes_supported`` lists the scopes this resource accepts.

    ``verify_token`` is the pluggable verification function: it receives the
    raw bearer string and returns a claims mapping, raising ``AuthError``
    (or any exception) if the token is not authentic/valid. Production
    wiring passes the MCP SDK's verifier; tests inject claim factories.
    No JWT is ever decoded-without-verification here.
    """

    def __init__(
        self,
        resource: str,
        issuer: str,
        scopes_supported: list[str],
        verify_token: Callable[[str], dict[str, Any]],
        scope_claim: str = "scope",
    ) -> None:
        self.resource = resource
        self.issuer = issuer
        self.scopes_supported = list(scopes_supported)
        self._verify_token = verify_token
        self._scope_claim = scope_claim

    # ------------------------------------------------------------------
    # RFC 9728 protected resource metadata
    # ------------------------------------------------------------------

    def protected_resource_metadata(self) -> dict[str, Any]:
        """Build the RFC 9728 PRM document served at
        ``/.well-known/oauth-protected-resource``."""
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": list(self.scopes_supported),
            "bearer_methods_supported": ["header"],
        }

    # ------------------------------------------------------------------
    # Bearer check: audience binding (RFC 8707) + scope possession
    # ------------------------------------------------------------------

    def validate(self, token: str, required_scopes: list[str] | None = None) -> dict[str, Any]:
        """Validate a bearer token; returns the verified claims on success.

        The token is first handed to the pluggable verifier (production:
        MCP SDK auth_server_provider/token_verifier; tests: claim
        factories). Authorization decisions made HERE, on verified claims:

        - RFC 8707 audience binding: ``aud`` must include this resource's
          identifier. A token issued for another audience is refused even
          from a trusted issuer.
        - Every scope in ``required_scopes`` must be present in the token's
          scope claim (space-separated string or list).
        """
        claims = self._verify_token(token)
        if not isinstance(claims, dict):
            raise AuthError("token verifier returned invalid claims")

        audiences = claims.get("aud")
        if audiences is None:
            audiences = []
        elif isinstance(audiences, str):
            audiences = [audiences]
        elif not isinstance(audiences, list):
            raise AuthError("token 'aud' claim has an invalid shape")
        if self.resource not in audiences:
            raise AuthError(
                f"token audience binding failed (RFC 8707): expected {self.resource!r} "
                f"in aud, got {audiences!r}"
            )

        granted = _scope_set(claims.get(self._scope_claim))
        missing = [s for s in required_scopes or [] if s not in granted]
        if missing:
            raise AuthError(f"token missing required scope(s): {missing}")
        return claims

    # ------------------------------------------------------------------
    # WWW-Authenticate challenge (step-up)
    # ------------------------------------------------------------------

    def challenge(
        self,
        error: str = "invalid_token",
        error_description: str | None = None,
        required_scopes: list[str] | None = None,
    ) -> str:
        """Build the ``WWW-Authenticate`` header value (RFC 6750 / step-up).

        ``required_scopes`` nonempty => a step-up challenge carrying the
        scope demand, per the MCP 2026-07-28 step-up mechanism.
        """
        parts = [f'Bearer realm="{self.resource}"']
        if required_scopes:
            parts.append(f'scope="{" ".join(required_scopes)}"')
        if error:
            parts.append(f'error="{error}"')
        if error_description:
            parts.append(f'error_description="{_quote_safe(error_description)}"')
        return ", ".join(parts)


def _scope_set(raw: Any) -> set[str]:
    """Normalize a scope claim (space-separated string or list) to a set."""
    if raw is None:
        return set()
    if isinstance(raw, str):
        return set(raw.split())
    if isinstance(raw, (list, tuple)):
        return {str(s) for s in raw}
    return set()


def _quote_safe(text: str) -> str:
    """Escape for a quoted-string parameter value (RFC 7230)."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def decode_jwt_payload_unverified(token: str) -> dict[str, Any]:
    """Utility for TESTS ONLY: base64url-decode a JWT payload section.

    NOT a validation mechanism — production JWT verification delegates to
    the MCP SDK auth_server_provider (see module docstring). Kept here so
    test claim factories can round-trip a realistic token shape.
    """
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, ValueError) as exc:
        raise AuthError(f"malformed token: {exc}") from exc


__all__ = ["AuthError", "HttpOAuthValidator", "decode_jwt_payload_unverified"]
