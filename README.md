# access-broker-core

Shared security architecture for the access-broker suite: the grant
lifecycle, tier-classification mechanics, hash-chained audit log,
transport authentication, and the transport-agnostic approval-gateway
core, extracted from nextcloud-access-broker and groupware-access-broker
(same author; see AUTHORS.md for provenance).

## What is in the core

- **`policy`** — tier-classification registry mechanism, `Decision`,
  `GrantItem`/`Request` shapes, component-prefix containment, the
  `check()` evaluation skeleton. Domain semantics (operation tables,
  resource normalizers) belong to each broker and are registered at
  boot; an empty registry refuses to start.
- **`grants`** — GrantStore: conditional-SQL CAS state transitions,
  one-time request numbers, pending expiry, TTL, revoke, restart
  persistence, restart discard of pending. Silence grants nothing.
- **`audit`** — hash-chained JSONL, fsync per record, checkpoint sidecar
  (truncation detection), write-before-operate, secret scrubbing,
  `verify_chain`. Human decisions are audit-class events: the approver
  identity rides in `principal` (suite finding F1, fixed 2026-09-18).
- **`gateways`** — the ApprovalGateway interface and the
  transport-agnostic decision core (allowlist first, one-time numbers,
  undo windows, expiry sweep, approval summaries). Platform adapters
  (Matrix, Telegram, Teams, Signal shells) stay per-broker.
- **`auth`** — RFC 9728/8707 OAuth 2.1 resource-server validation
  (HTTP transport) and constant-time bearer checks (stdio).
- **`baselines`** — BaselineEngine: standing T0/T1 permission
  reassessment (the nextcloud-access-broker design note rev 2,
  implemented; the data broker consumes it).
- **`custody`** — CustodyRegistry/CustodyClass: the machine-readable
  custody-class declaration layer (S6-1); declarations are
  refuse-to-start validated and ride every audit record.

## What is NOT in the core

The walls (scope checkers), backend adapters, tool surfaces, config, and
server wiring are per-broker. The core owns the mechanics of
authorization, audit, and approval; each broker owns the semantics of
its domain. Every wall stays exhaustively tested (100% statement and
branch, hypothesis fuzz, unmocked) in its own repository — the core
provides the quality bar, not an exemption from it.

## Suite invariants (stated once, here)

1. Tier-first evaluation: classification precedes scope matching; gated
   operations always gate.
2. Write-before-operate: an operation without a durable audit entry does
   not run.
3. Fail-closed on every failure mode; silence grants nothing; restart
   never widens capability and never promotes suspended state.
4. The approval plane is severed from the execution plane; the approval
   gateway must not be the brokered platform+account combination.
5. Human decisions are audit-class events with the approver as
   principal.
6. The T0/T1 free lane exists in every broker; gating reads and
   reversible writes trains the owner to approve reflexively.

## Verification model

The core's correctness proof is verification by porting: each broker's
existing suite must pass against the core with zero behavior change.
See CHANGELOG.md for the founding compatibility matrix.

## License

GPL-3.0-or-later. See AUTHORS.md for provenance.