# Changelog

All notable changes to this project are documented in this file.
Format based on Keep a Changelog; versioning is SemVer.

## [Unreleased] - 2026-09-29 (render pass appended; 2026-09-21 entry below)

**Released as 0.1.2** (commit-time version bump per the design note;
the 2026-09-21 entry below ships in the same release).

### Changed

- Approval-room message formats unified across every outbound type
  (request, approve/reject/revoke confirmations, revoke-all, status,
  lifecycle, expiry notice, undo-closed, refusals, parse errors, help,
  audit-failure warning). One grammar everywhere: `[tag] <icon>
  **<headline>**`, decision confirmations reuse the reaction emoji that
  produced them, item lines are one template-controlled line each
  (`<n>.` in requests, `•` elsewhere) and the agent-supplied
  justification is isolated in ONE labelled line
  (`Justification (agent, unverified):`). Request items are now
  numbered one-per-line with the resource in code and ops in code; the
  item count and default expiry moved into the request header; the
  status block gained a `📋 **STATUS**` header; refusal text renders
  the store's RejectReason as a sentence. No tables (Element X
  collapses them). Rendering stays pure (no I/O, no clock) and every
  decision/audit semantic is untouched.
- `revoke all` confirmation now states that a bulk revoke has no undo
  (the undo windows are armed per id, never for a bulk action).

## [Unreleased] - 2026-09-21

### Added

- Shared-room routing (Option B, owner decision 2026-09-21): one
  approval room may serve several broker gateways. Each gateway
  declares `shared_room: true` + `command_prefix` in its gateway
  config (refuse-to-start validated: a shared room requires a
  nonempty prefix; a prefix without a shared room is refused as dead
  config). Inbound: commands must carry the tag (`comms approve 1`);
  unprefixed commands are refused with a hint (fail-closed), other
  brokers' prefixed commands are ignored silently. Outbound: every
  message is stamped `[tag] ...` through a single `_post` choke
  point.
- `announce_lifecycle`: the gateway posts `gateway started` /
  `gateway stopping` notices to the approval room (owner directive);
  delivery failure is logged and swallowed.
- Grant items accept a display-only `label` (e.g. the Matrix room
  name) shown on request lines and decisions; the policy wall never
  reads it and matching stays by `resource`.
- `GrantStore` refuses a grants DB whose parent directory does not
  exist (named error, fail-closed boot).

## [0.1.0] - 2026-09-18 (founding release)

### Added (by extraction, provenance in AUTHORS.md)

- `policy`: tier-classification registry mechanism (PolicyRegistry with
  refuse-to-start validation and enum coercion at the seam), `Decision`,
  `GrantItem`/`Request` shapes, component-prefix containment, `check()`
  evaluation skeleton (from groupware-access-broker policy.py, mechanics
  split per the Stage 1 goal contract section 3).
- `grants`: GrantStore with conditional-SQL CAS transitions, one-time
  request numbers, pending expiry, TTL, revoke, restart persistence and
  restart discard of pending; registry-parameterized (from
  groupware-access-broker grants.py).
- `audit`: AuditLog hash-chained JSONL, fsync per record, checkpoint
  sidecar, write-before-operate, secret scrubbing, `verify_chain`; human
  decisions are audit-class events with approver identity in `principal`
  (suite finding F1 semantics) (from groupware-access-broker audit.py).
- `gateways`: ApprovalGatewayCore + transport-agnostic decision core;
  factory as an adapter REGISTRY (register_adapter) with the shared
  wiring contract (env resolution, allowed_senders[0], one-gateway rule,
  transport rebind); platform adapters stay per-broker (from
  groupware-access-broker gateways/).
- `auth`: HttpOAuthValidator (RFC 9728/8707 audience binding, scope
  step-up) and constant-time static credential check with the
  empty-credential deny-by-default guard (from groupware-access-broker
  auth/).
- `baselines`: BaselineEngine, standing T0/T1 permission
  reassessment (implementation of the nextcloud-access-broker
  baseline-permissions design note rev 2, landed during Stage 4; the
  data broker is its natural consumer).
- `custody`: CustodyRegistry / CustodyClass, the machine-readable
  custody-class declaration layer (S6-1): per-backend declarations
  refuse-to-start validated at boot, carried on every audit record
  (from the automation broker's custody spec).

### Fixed (at extraction)

- Enum identity at the registry seam: registries carrying a broker's own
  OperationClass instances are coerced to the core enum at construction
  (value vocabulary identical; enforced at the boundary).
- Empty-credential deny-by-default in check_static_credential
  (hmac.compare_digest("", "") is True; the core owns the fail-closed
  invariant the source masked).
- verify_chain sidecar blind spot (Stage 8 disposition): a log with
  records but no `.head` checkpoint now verifies NOT-ok ("checkpoint
  missing") instead of passing on chain-hash alone; fresh empty logs
  (no records, no sidecar) still verify ok. Regression tests cover
  both directions.

### Verified

- Verification by porting: groupware-access-broker's complete suite
  (633 tests) passes against the core with zero behavior change; the
  core's own batteries (405) at 100% statement+branch coverage.
- nextcloud-access-broker: port attempted (S1g); found to be a
  production MIGRATION (incompatible on-disk chain format, older grants
  API generation), deferred with evidence in MIGRATION_NOTES.md.

### Compatibility matrix (founding)

| Broker | Core version | Status |
|---|---|---|
| groupware-access-broker | ==0.1.0 | consumes (verified by porting) |
| nextcloud-access-broker | — | shares architecture; migration deferred (see MIGRATION_NOTES.md) |
