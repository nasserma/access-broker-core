"""Tier 1 stdio auth: environment-configured credentials, constant-time compare.

Port pattern from nextcloud-access-broker server.py check_auth: bearer/static
credential comparison must be constant-time; failures deny by default.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

import hmac


class AuthError(Exception):
    """Raised on any static credential check failure."""


def check_static_credential(presented: str, expected: str) -> bool:
    """Constant-time comparison of a presented credential against the
    expected one.

    Deny by default on empty inputs: hmac.compare_digest("", "") is True,
    which would authorize an empty credential against an empty expected
    value (a misconfigured deployment). The core owns the fail-closed
    invariant: either side empty denies, always.
    """
    if not presented or not expected:
        return False
    return hmac.compare_digest(presented.encode(), expected.encode())
