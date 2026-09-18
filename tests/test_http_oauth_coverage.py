"""Coverage completion for the core auth module: the branches the
groupware boot battery did not reach (invalid claim shapes, scope edge
cases, challenge formatting, the test-utility JWT decoder)."""

# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from access_broker_core.auth.http_oauth import (
    AuthError,
    HttpOAuthValidator,
    _quote_safe,
    _scope_set,
    decode_jwt_payload_unverified,
)


def make_validator(claims=None):
    claims = claims if claims is not None else {
        "aud": "https://core.example.com/mcp",
        "scope": "pim.read",
    }

    def verifier(token: str) -> dict:
        if token == "bad":
            raise AuthError("signature invalid (production verifier)")
        return claims

    return HttpOAuthValidator(
        resource="https://core.example.com/mcp",
        issuer="https://auth.example.com",
        scopes_supported=["pim.read", "pim.tier2"],
        verify_token=verifier,
    )


def test_invalid_claims_shape_refused():
    """A verifier returning a non-dict is an auth failure, never a crash."""
    v = HttpOAuthValidator(
        resource="https://core.example.com/mcp",
        issuer="https://auth.example.com",
        scopes_supported=["pim.read"],
        verify_token=lambda _t: "not-a-dict",
    )
    with pytest.raises(AuthError, match="invalid claims"):
        v.validate("tok")


def test_invalid_aud_claim_shape_refused():
    v = make_validator(claims={"aud": {"weird": True}, "scope": "pim.read"})
    with pytest.raises(AuthError, match="invalid shape"):
        v.validate("tok")


def test_scope_list_claim_normalized():
    """A list-shaped scope claim is accepted and set-normalized."""
    v = make_validator(claims={"aud": "https://core.example.com/mcp", "scope": ["pim.read", "extra"]})
    assert v.validate("tok")["aud"] == "https://core.example.com/mcp"


def test_scope_tuple_claim_normalized():
    v = make_validator(claims={"aud": "https://core.example.com/mcp", "scope": ("pim.read",)})
    assert v.validate("tok")


def test_scope_missing_denies_required_scope():
    v = make_validator(claims={"aud": "https://core.example.com/mcp"})
    with pytest.raises(AuthError, match="scope"):
        v.validate("tok", required_scopes=["pim.read"])


def test_scope_none_claim_denies_required_scope():
    v = make_validator(claims={"aud": "https://core.example.com/mcp", "scope": None})
    with pytest.raises(AuthError, match="scope"):
        v.validate("tok", required_scopes=["pim.read"])


def test_challenge_default_carries_invalid_token_error():
    """The challenge's default error is invalid_token (RFC 6750 posture)."""
    v = make_validator()
    ch = v.challenge()
    assert ch.startswith("Bearer ")
    assert 'error="invalid_token"' in ch


def test_challenge_escapes_quotes_in_description():
    v = make_validator()
    ch = v.challenge(error="invalid_token", error_description='say "hi"')
    assert '\\"hi\\"' in ch


def test_quote_safe_roundtrip():
    assert _quote_safe('a"b\\c') == 'a\\"b\\\\c'


def test_scope_set_shapes():
    assert _scope_set(None) == set()
    assert _scope_set("a b c") == {"a", "b", "c"}
    assert _scope_set(["a", "b"]) == {"a", "b"}
    assert _scope_set(("x",)) == {"x"}
    assert _scope_set(42) == set()


def test_decode_jwt_payload_unverified_roundtrip():
    import base64
    import json

    payload = {"aud": "https://core.example.com/mcp", "scope": "pim.read"}
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = f"header.{seg}.signature"
    assert decode_jwt_payload_unverified(token) == payload


def test_decode_jwt_payload_unverified_malformed():
    with pytest.raises(AuthError, match="malformed token"):
        decode_jwt_payload_unverified("not-a-jwt")

def test_challenge_empty_error_omits_error_field():
    """136->138: challenge(error="") omits the error field entirely."""
    v = make_validator()
    ch = v.challenge(error="")
    assert 'error=' not in ch
    assert ch.startswith("Bearer ")
