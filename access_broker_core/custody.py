"""Core custody mechanics (S6-1): the custody-class declaration layer.

The suite invariant, made machine-readable: custody is a PREREQUISITE
layer, not a gating layer. Where a platform's credential cannot be
scoped (all-or-nothing API tokens), the broker-is-the-wall argument
carries the whole load, and that fact must be said permanently and
prominently in the broker's SECURITY.md. This module makes the saying
STRUCTURED: each broker declares its backends' custody classes at boot,
the declaration is refuse-to-start validated, and the audit chain
carries the class of the backend principal on every executed
operation.

Contract (Stage 6 goal contract, S6-1):

- CustodyClass is exactly three values: SCOPED (the credential is
  scope-limited at its source - Graph delegated scopes, app
  passwords), ACCOUNT_WIDE (the credential carries the whole account;
  the broker's wall is the operative boundary), UNSCOPABLE (no
  credential could ever scope this surface - stated permanently).
- CustodyRegistry is a registry the broker populates at boot; an EMPTY
  registry refuses to start (the policy-registry mechanism). A backend
  may not change its declared class once registered: the declaration
  is load-bearing, and a class that shifts under a live boot is a
  silent trust-boundary change.
- Fail-closed default: an unregistered backend declares ACCOUNT_WIDE.
  declared() never raises, so audit writers always obtain an answer;
  unregistered means the most conservative statement.
- The audit record's ``custody`` field is OPTIONAL and hashed only
  when present (the ``backend``/``principal`` pattern), so legacy
  lines without it still verify.

No protocol coupling, no I/O, no wall-clock reads, no network.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import enum


class CustodyClass(enum.Enum):
    """The custody class of a backend's credential.

    SCOPED: the credential is scope-limited at its source (delegated
    Graph scopes, app passwords). ACCOUNT_WIDE: the credential carries
    the entire account and the broker's wall is the load-bearing
    control. UNSCOPABLE: no credential for this surface could ever be
    scoped; said permanently, not fixed later.
    """

    SCOPED = "scoped"
    ACCOUNT_WIDE = "account_wide"
    UNSCOPABLE = "unscopable"


class CustodyRegistry:
    """Per-backend custody-class declarations, populated at boot.

    One instance per broker process. Refuse-to-start: :meth:`validate`
    is called by the broker's boot sequence; an empty registry must
    stop the boot, never serve (the policy-registry mechanism).
    """

    def __init__(self) -> None:
        self._classes: dict[str, CustodyClass] = {}

    def register(self, backend: str, cls: CustodyClass) -> None:
        """Declare a backend's custody class.

        Re-registering the same backend with the SAME class is
        idempotent. Changing a declared class is refused: the
        declaration is load-bearing and must not shift under a live
        boot. Non-CustodyClass values are refused (the seam normalizes
        nothing silently).
        """
        if not isinstance(cls, CustodyClass):
            raise ValueError(
                f"custody registry: custody class for {backend!r} "
                f"must be a CustodyClass member, got {cls!r}"
            )
        existing = self._classes.get(backend)
        if existing is not None and existing is not cls:
            raise ValueError(
                f"custody registry: custody class for {backend!r} "
                f"already declared as {existing.value!r}; refusing to "
                "change it at runtime"
            )
        self._classes[backend] = cls

    def validate(self) -> None:
        """Refuse-to-start guard: an empty custody registry must stop
        the boot (a broker that never declared its trust boundary must
        not serve)."""
        if not self._classes:
            raise ValueError("custody registry: no backend declares a custody class")

    def declared(self, backend: str) -> CustodyClass:
        """The custody class of a backend. Fail-closed: an unregistered
        backend declares ACCOUNT_WIDE (the most conservative
        statement). Never raises, so audit writers always obtain an
        answer."""
        return self._classes.get(backend, CustodyClass.ACCOUNT_WIDE)

    def declared_backends(self) -> list[str]:
        """The registered backend names, sorted (the validation set for
        boot-path batteries)."""
        return sorted(self._classes)
