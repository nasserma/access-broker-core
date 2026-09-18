# Changelog

All notable changes to this project are documented in this file.
Format based on Keep a Changelog; versioning is SemVer.

## [0.1.0] - 2026-09-18 (founding release, in progress)

### Added (by extraction, provenance in AUTHORS.md)

- `policy`: tier-classification registry mechanism, `Decision`,
  `GrantItem`/`Request` shapes, component-prefix containment, `check()`
  evaluation skeleton (from groupware-access-broker policy.py, mechanics
  split per the Stage 1 goal contract section 3).
- `grants`: GrantStore with conditional-SQL CAS transitions, one-time
  request numbers, pending expiry, TTL, revoke, restart persistence and
  restart discard of pending (from groupware-access-broker grants.py).
- `audit`: AuditLog hash-chained JSONL, fsync per record, checkpoint
  sidecar, write-before-operate, secret scrubbing, `verify_chain`; human
  decisions are audit-class events with approver identity in `principal`
  (suite finding F1 semantics, fixed 2026-09-18) (from
  groupware-access-broker audit.py).
- `gateways`: ApprovalGateway interface + transport-agnostic decision
  core (from groupware-access-broker gateways/base.py + logic.py).
- `auth`: RFC 9728/8707 OAuth 2.1 resource-server validation + constant-
  time bearer checks (from groupware-access-broker auth/).

### Compatibility matrix (founding)

| Broker | Core version |
|---|---|
| groupware-access-broker | ==0.1.0 |
| nextcloud-access-broker | ==0.1.0 (shared modules: audit, grants, auth) |

### Provenance

Founded by extraction from nextcloud-access-broker and
groupware-access-broker (same author, GPL-3.0-or-later); see AUTHORS.md.
