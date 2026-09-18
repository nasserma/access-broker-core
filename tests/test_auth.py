"""Core auth tests: HttpOAuthValidator (RFC 9728/8707).

Extracted verbatim from groupware-access-broker tests/test_server_boot.py
(the validator section) at core founding; the boot/wiring sections remain
per-broker.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pytest

from access_broker_core.auth.http_oauth import AuthError, HttpOAuthValidator


def make_validator(claims=None):
    claims = claims if claims is not None else {
        "aud": "https://core.example.com/mcp",
        "scope": "pim.read",
    }
    seen = []

    def verifier(token: str) -> dict:
        seen.append(token)
        if token == "bad":
            raise AuthError("signature invalid (production verifier)")
        return claims

    v = HttpOAuthValidator(
        resource="https://core.example.com/mcp",
        issuer="https://auth.example.com",
        scopes_supported=["pim.read", "pim.tier2"],
        verify_token=verifier,
    )
    return v, seen


# HttpOAuthValidator
# ----------------------------------------------------------------------


def make_validator(claims=None):
    claims = claims if claims is not None else {
        "aud": "groupware_broker",
        "scope": "pim.read",
    }
    seen = []

    def verifier(token: str) -> dict:
        seen.append(token)
        if token == "bad":
            raise AuthError("signature invalid (production verifier)")
        return claims

    v = HttpOAuthValidator(
        resource="https://core.example.com/mcp",
        issuer="https://auth.example.com",
        scopes_supported=["pim.read", "pim.tier2"],
        verify_token=verifier,
    )
    return v, seen


def test_prm_document_shape():
    v, _ = make_validator()
    prm = v.protected_resource_metadata()
    assert prm["resource"] == "https://core.example.com/mcp"
    assert prm["authorization_servers"] == ["https://auth.example.com"]
    assert prm["scopes_supported"] == ["pim.read", "pim.tier2"]
    assert prm["bearer_methods_supported"] == ["header"]


def test_validate_audience_binding_ok():
    v, _ = make_validator({"aud": ["https://core.example.com/mcp"], "scope": "pim.read"})
    assert v.validate("tok", required_scopes=["pim.read"])["aud"] == [
        "https://core.example.com/mcp"
    ]


def test_validate_audience_binding_refused_for_wrong_audience():
    v, _ = make_validator({"aud": "https://other-resource.example.com"})
    with pytest.raises(AuthError, match="audience"):
        v.validate("tok")


def test_validate_audience_binding_refused_when_missing():
    v, _ = make_validator({"scope": "pim.read"})
    with pytest.raises(AuthError, match="aud"):
        v.validate("tok")


def test_validate_verifier_failure_propagates():
    v, seen = make_validator()
    with pytest.raises(AuthError, match="signature"):
        v.validate("bad")
    assert seen == ["bad"]


def test_validate_missing_scope_refused():
    v, _ = make_validator({"aud": "https://core.example.com/mcp", "scope": "pim.read"})
    with pytest.raises(AuthError, match="scope"):
        v.validate("tok", required_scopes=["pim.tier2"])


def test_challenge_basic_format():
    v, _ = make_validator()
    ch = v.challenge(error="invalid_token", error_description="expired")
    assert ch.startswith("Bearer ")
    assert 'error="invalid_token"' in ch
    assert 'error_description="expired"' in ch


def test_challenge_step_up_includes_scope():
    v, _ = make_validator()
    ch = v.challenge(error="insufficient_scope", required_scopes=["pim.tier2"])
    assert 'scope="pim.tier2"' in ch
    assert 'error="insufficient_scope"' in ch


