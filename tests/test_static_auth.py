"""Core auth tests: static credential check (stdio transport).

Ported from the source repos' constant-time compare pattern; the core
module is small and its contract is exact: constant-time comparison,
deny by default on any mismatch or empty input.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from access_broker_core.auth.static import AuthError, check_static_credential


def test_equal_credentials_ok():
    assert check_static_credential("secret-token", "secret-token") is True


def test_mismatched_credentials_denied():
    assert check_static_credential("secret-token", "other-token") is False


def test_empty_presented_denied():
    assert check_static_credential("", "secret-token") is False


def test_empty_expected_denied():
    assert check_static_credential("secret-token", "") is False


def test_both_empty_denied():
    """Deny by default: an empty-expected configuration authorizes nothing."""
    assert check_static_credential("", "") is False


def test_long_mismatch_same_outcome():
    assert check_static_credential("a" * 100, "b" * 100) is False


def test_auth_error_is_exception():
    assert issubclass(AuthError, Exception)


@pytest.mark.parametrize(
    ("presented", "expected"),
    [
        ("x", "secret-token"),
        ("secret-tokeN", "secret-token"),
        ("secret-token ", "secret-token"),
        (" secret-token", "secret-token"),
    ],
)
def test_near_miss_variants_denied(presented, expected):
    assert check_static_credential(presented, expected) is False

