"""Core policy mechanics: tier-classification registry, Decision, check().

The domain-independent half of the broker wall. The core owns the
EVALUATION MECHANICS: tier classification against a registered table,
component-prefix containment, and the check() skeleton's fail-closed
stage order. Each broker owns the SEMANTICS: its literal operation
tables, backend set, and resource normalizer, registered at boot.

Contract (Stage 1 goal contract section 3):

- The classification table is a registry: the broker populates it from
  its own operation tables at boot. An operation absent from the
  registered table classifies GATED (fail-closed). Boot validation
  refuses an empty registry (refuse-to-start): a broker that never
  registered its semantics must not serve.
- The backend set and resource normalizer are likewise registry-wired.
  The core enforces that check() always normalizes BOTH the grant
  resource and the request resource through the registered normalizer,
  so grant and request are judged identically.
- check() is the wall skeleton: fail-closed on every malformed input,
  expired grant, scope mismatch, op mismatch. Never raises; no I/O; no
  wall-clock reads (clock injected).

Stage order is normative (suite invariant 1, tier-first evaluation):
unknown backend -> backend mismatch -> account mismatch -> expiry ->
normalization (grant then request) -> empty-scope rules -> containment ->
ops check. No configuration changes it.

This module's patterns are ported from the same author's
groupware-access-broker policy.py and nextcloud-access-broker paths.py
(GPL-3.0-or-later); see AUTHORS.md for provenance.
"""

# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import enum
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any, NamedTuple, TypedDict

#: Bounded percent-decoding cap and resource length cap (mechanics
#: constants; the decode/length rules are domain-independent).
MAX_DECODE_PASSES = 4
MAX_RESOURCE_LENGTH = 1024


class OperationClass(enum.Enum):
    """Tier classification of an operation."""

    READ = "read"
    GATED = "gated"


class Reason(enum.Enum):
    """Fixed denial/allow reason enum: audit entries and tests are exact."""

    OK = "ok"
    UNKNOWN_BACKEND = "unknown_backend"
    BACKEND_MISMATCH = "backend_mismatch"
    ACCOUNT_MISMATCH = "account_mismatch"
    EXPIRED = "expired"
    MALFORMED_GRANT = "malformed_grant"
    MALFORMED_RESOURCE = "malformed_resource"
    NORMALIZATION_FAILURE = "normalization_failure"
    EMPTY_RESOURCE = "empty_resource"
    ESCAPES_NAMESPACE = "escapes_namespace"
    NOT_IN_SCOPE = "not_in_scope"
    OP_NOT_GRANTED = "op_not_granted"


class Decision(NamedTuple):
    """The outcome of a single check() evaluation.

    allowed=False means DENY (the checker fails closed). reason is a fixed
    Reason enum member, safe to surface to the requesting agent and exact
    for audit entries.
    """

    allowed: bool
    reason: Reason


class GrantItem(TypedDict, total=False):
    """One grant as seen by the checker (the suite's D5 shape)."""

    backend: str
    account: str
    resource: str
    ops: list[str]
    expires_at: datetime | None


class Request(TypedDict, total=False):
    """One operation request as seen by the checker."""

    backend: str
    account: str
    resource: str
    op: str


class PolicyError(Exception):
    """Internal normalization failure carrying its fixed deny Reason."""

    def __init__(self, reason: Reason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class PolicyRegistry:
    """The broker-registered semantics the core mechanics evaluate against.

    One instance per broker process, constructed at boot with the
    broker's operation table, backend set, and resource normalizer.
    Refuse-to-start: :meth:`validate` is called by the broker's boot
    sequence; an empty operation table or backend set must stop the
    boot, never serve.
    """

    def __init__(
        self,
        operation_class: dict[str, OperationClass],
        backends: frozenset[str] | set[str],
        normalize_resource: Callable[[Any, str], tuple[str, ...]],
        classify=None,
    ) -> None:
        """operation_class: the broker's literal table (op -> class).
        backends: the broker's backend families. normalize_resource:
        the broker's wall normalizer (raw resource -> component tuple,
        raising PolicyError on hostile input). classify: optional
        custom classifier; default reads the table with unknown ->
        GATED (fail-closed)."""
        # Coerce table values to THIS module's OperationClass: brokers
        # register their own enum instances and the value vocabulary is
        # identical ("read"/"gated"), but check() compares identity. The
        # registry is the seam boundary, so enum identity is normalized
        # HERE, once, at construction.
        self.operation_class = {
            op: OperationClass(cls.value) if hasattr(cls, "value") else cls
            for op, cls in operation_class.items()
        }
        self.backends = frozenset(backends)
        self._normalize = normalize_resource
        if classify is not None:
            self._classify = classify
        else:
            table = self.operation_class

            def _default_classify(operation: str) -> OperationClass:
                if not isinstance(operation, str):
                    return OperationClass.GATED
                return table.get(operation, OperationClass.GATED)

            self._classify = _default_classify

    def validate(self) -> None:
        """Refuse-to-start guard: empty registry must stop the boot."""
        if not self.operation_class:
            raise ValueError("policy registry: operation table is empty")
        if not self.backends:
            raise ValueError("policy registry: backend set is empty")

    def classify(self, operation: str) -> OperationClass:
        return self._classify(operation)

    def classify_tier(self, operation: str) -> int:
        """Map an operation to its tier: 1 (baseline) or 2 (brokered)."""
        return 1 if self._classify(operation) is OperationClass.READ else 2

    def normalize_resource(self, raw: Any, backend: str) -> tuple[str, ...]:
        return self._normalize(raw, backend)


def covers(
    grant_components: tuple[str, ...], request_components: tuple[str, ...]
) -> bool:
    """Exact component-prefix containment (recursion).

    ("Work",) covers ("Work",) and ("Work", "2026") but never
    ("Workers",).
    """
    return request_components[: len(grant_components)] == grant_components


def deny(reason: Reason) -> Decision:
    return Decision(False, reason)


def check(
    registry: PolicyRegistry,
    grant: GrantItem,
    request: Request,
    clock: Callable[[], datetime],
) -> Decision:  # noqa: C901, PLR0911, PLR0912, PLR0915
    """Decide whether one request item is covered by one grant item.

    The wall skeleton. Fails closed on every malformed input, expired
    grant, scope mismatch, and op mismatch. Never raises; never performs
    I/O; never reads wall-clock time.

    Stage order (normative, suite invariant 1 - tier-first: the tier
    classification drives the empty-scope rule; scope never overrides
    classification):
      - unknown backend in grant or request: denied before anything else.
      - backend mismatch between grant and request.
      - account mismatch: grants are per-account, never cross-account.
      - expiry: evaluated against the injected clock; uncomparable
        expires_at fails closed rather than raising.
      - normalization through the REGISTRY's normalizer for BOTH sides
        (grant and request judged identically), with the registry's
        backend-awareness.
      - empty normalized grant scope: refused wholesale (fail closed).
      - empty requested scope: deny for GATED (write-class); a read on
        the namespace root matches no (non-empty) grant scope.
      - exact component matching via :func:`covers`.
      - op check: requested op listed in the grant's ops, or READ-class
        implied by write-implies-read inside scope.
    """
    grant_backend = grant.get("backend")
    request_backend = request.get("backend")
    if not isinstance(grant_backend, str) or not isinstance(request_backend, str):
        return deny(Reason.UNKNOWN_BACKEND)
    if grant_backend not in registry.backends or request_backend not in registry.backends:
        return deny(Reason.UNKNOWN_BACKEND)
    if grant_backend != request_backend:
        return deny(Reason.BACKEND_MISMATCH)

    grant_account = grant.get("account")
    if not isinstance(grant_account, str) or grant_account != request.get("account"):
        return deny(Reason.ACCOUNT_MISMATCH)

    expires_at = grant.get("expires_at")
    if expires_at is not None:
        if not isinstance(expires_at, datetime):
            return deny(Reason.MALFORMED_GRANT)
        try:
            if expires_at <= clock():
                return deny(Reason.EXPIRED)
        except TypeError:
            # Incomparable expiry (naive vs aware): fail closed, never crash.
            return deny(Reason.EXPIRED)

    try:
        grant_components = registry.normalize_resource(
            grant.get("resource"), grant_backend
        )
        request_components = registry.normalize_resource(
            request.get("resource"), request_backend
        )
        raw_op = request.get("op")
        op = raw_op if isinstance(raw_op, str) else ""
        op_class = registry.classify(op)
    except PolicyError as exc:
        return deny(exc.reason)
    except Exception as exc:  # noqa: BLE001 - hostile-resource defense
        # The registered normalizer may carry its own PolicyError/Reason
        # subclasses (per-broker exception identity). The seam contract is
        # the reason VALUE, not the class: a normalizer failure is always
        # a deny with the reason it carries (matched by value against this
        # module's Reason); anything else is hostile/unexpected input and
        # is denied as a normalization failure (fail closed, never
        # propagate).
        reason = getattr(exc, "reason", None)
        value = getattr(reason, "value", None)
        if isinstance(value, str):
            try:
                return deny(Reason(value))
            except ValueError:
                pass
        return deny(Reason.NORMALIZATION_FAILURE)

    if not grant_components:
        # An empty normalized grant scope would cover the whole account
        # namespace: never grantable (fail closed).
        return deny(Reason.MALFORMED_GRANT)
    if not request_components:
        if op_class is OperationClass.GATED:
            return deny(Reason.EMPTY_RESOURCE)
        return deny(Reason.NOT_IN_SCOPE)

    if not covers(grant_components, request_components):
        return deny(Reason.NOT_IN_SCOPE)

    raw_ops = grant.get("ops")
    if raw_ops is None or not isinstance(raw_ops, (list, tuple, set, frozenset)):
        return deny(Reason.MALFORMED_GRANT)
    ops: Iterable[Any] = raw_ops
    if not all(isinstance(item, str) for item in ops):
        return deny(Reason.MALFORMED_GRANT)

    if op in ops:
        return Decision(True, Reason.OK)
    # Write implies READ inside the granted scope: any GATED (write-class)
    # operation in the ops list implicitly grants READ-class operations.
    if op_class is OperationClass.READ and any(
        registry.classify(item) is OperationClass.GATED for item in ops
    ):
        return Decision(True, Reason.OK)
    return deny(Reason.OP_NOT_GRANTED)
