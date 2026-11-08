# Changelog

All notable changes to this project are documented in this file.
Format based on Keep a Changelog; versioning is SemVer.

## [0.4.0] - 2026-11-08

The app-protocol BLOCKED-item closure B1–B8 (approval-client design
note `review/approvalClientDesignNote-2026-11-07.md`, decisions
D-A..D-N plus the pass amendments; the protocol.md §12 BLOCKED list; the
R1–R15 supervisory contract from the 2026-11-07 review). The approval
hub is extended in lockstep against the same wire shapes in this
release window; adopting brokers re-pin at their next release.

### Breaking (wire contract)

- **The decision route now REQUIRES four app-protocol fields** beyond
  the verb tuple (`request_number`, `action`, optional
  `duration_seconds`/`decision_id`):
  - `issued_at` — when the caller composed the decision,
    timezone-qualified ISO 8601. Refused (`stale_issued_at`, HTTP-hint
    409) when further than ±120s from the broker's clock — checked
    BEFORE the replay cache and before any store read; a naive or
    unparseable timestamp is refused (`invalid_issued_at`).
  - `expected_state` — the literal `"pending"`: the caller declares it
    composed the decision against a pending card (`invalid_expected_state`).
  - `request_digest` — the canonical sha256 the card carried
    (64 lowercase hex, `invalid_request_digest` on a bad shape). The
    broker RECOMPUTES it from the live record and refuses
    (`request_digest_mismatch`, 409, audited, nothing applied) on
    disagreement — on the fresh path AND the `decision_id` replay path:
    what the human signed must be byte-identical to what the broker holds.
  - `device_id` — which enrolled device decided (`invalid_device_id`).
  The route stamps its own provenance (`channel="android-app"`,
  `credential_class="approval-device"`) — never client-declared.
  The approval hub is updated in lockstep in this release window;
  released adopters re-pin when they take the surface.
- **Approve-by-reaction is refused (D-F).** A reaction cannot carry the
  one-time code, so the 👍 reaction is disabled on the room path:
  refused visibly with teaching text and audited
  (`one_time_code_reaction_cannot_carry_code`), the request stays
  pending. Typed `approve <id> <code>` (or the approval app) is the only
  approve.

### Added (B1–B8)

- **Audit provenance fields (B1/R6).** Four optional-when-present
  fields ride the hash chain exactly as custody/screen do: `device_id`
  (bounded single-line id), `credential_class` (fixed vocabulary:
  `approval-device`), `channel` (`android-app` | `text-fallback`),
  `request_digest` (64 lowercase hex). Fail-closed shape/vocabulary
  gates before the write; legacy chains still verify.
- **Canonical request digest + short code (B3/B5).**
  `canonical_request_payload` / `request_digest` / `digest_code`: the
  authorization's identity bytes (request number + per-item
  backend/account/resource/sorted-ops/expiry, snapshot-normalized), the
  sha256 over them, and a base32 first-bytes short code printed on the
  room card and carried on the app's card for eye cross-check.
- **One-time approve codes (B4/D-F).** The hub mints a single-use code
  (8 chars of the no-I/O/0/1 alphabet) and registers it through the new
  audited `POST <prefix>/code` route (body: `request_number`, `code`,
  `ttl_seconds` in [60, 900]; refusals `invalid_code` /
  `invalid_code_ttl` / `unknown_request` / `code_not_pending`, fixed
  reasons, the code never registered on a refusal; `/code` joins the
  protected surface ids). Codes are stored hashed, consumed only on a
  successful gate, in-memory only. Typed approve is code-gated with
  visible teaching refusals (`code_missing` / `code_malformed` /
  `code_unknown` / `code_expired` / `code_invalid`), each audited.
- **Provenance stamping (R6/R11).** Every decision arm and refusal
  stamps provenance into its chain entries: the approval surface stamps
  device/credential_class/channel/digest; room decisions (typed,
  reactions, undo, revoke-all) stamp `channel="text-fallback"` — a
  mixed-provenance history stays readable in the chain.
- **Snapshot markers (B5/B8).** Pending and active snapshot rows carry
  `request_digest` + `digest_code`; both also carry the explicit
  screen-absence marking `screen: null` +
  `screen_advisory_incomplete: true` (the core never persists a screen
  verdict — an absence must never render as a clean pass). The
  terminal expired slice carries no screen marking.
- **`parse_reply` gains an approve-only code slot** (4-tuple return):
  `approve <id> [expiry] <code>`; a code typed after
  reject/revoke/undo/status is dropped by the parser (the narrowing is
  approve-only). Room card, help text and Decide line teach the new
  affordance.

### Owner decisions pending

- **B9 (an API undo verb) is NOT added**: the 15s undo window remains
  room-path-only, as documented since the F1 round (V6h).
- **The 120s decision freshness window, the 900s one-time-code maximum
  TTL and the 60–900s registration window are implementation defaults**
  flagged for owner confirmation; they are module constants
  (`DECISION_FRESHNESS_SECONDS`, `ONE_TIME_CODE_MAX_TTL_SECONDS`,
  `ONE_TIME_CODE_MIN_TTL_SECONDS`), not config, in this release.

### Security notes (details in SECURITY.md)

- The provenance fields ride the hash chain the way custody/screen do —
  optional-when-present, hashed, fail-closed vocabulary; legacy chains
  verify unchanged.
- The decision freshness window (120s) is deliberately tighter than the
  replay TTL (300s): a replayed decision_id cannot resurrect a
  decision composed against authorization state older than the window.
- One-time codes are in-memory only and hashed at rest: a broker
  restart discards them together with the pending requests they gate
  (the store's restart-discard rule), so a code can never outlive its
  request.

## [0.3.0] - 2026-11-07

Hygiene round driven by the full supervisory review
(`reports/supervisoryReviewFull-2026-11-07.md`); no API removals that
affect a released broker, but eight behavior changes are listed first.

### Changed (behavior)

- **`grants`: intake caps on agent-supplied text (P4/P16/P38).**
  `submit()` now refuses a justification that is not one physical line
  (newline, C0/C1 control characters and U+2028/U+2029) or longer than
  `MAX_JUSTIFICATION_LENGTH` (512); more than `MAX_ITEMS` (10) items;
  and an item `label` that is not one line of at most
  `MAX_LABEL_LENGTH` (128). Previously all three were unbounded and
  multi-line, so a hostile justification could forge a second card
  header and steer a typed `approve N` to a different request.
- **`gateways`: render is single-line-by-construction (P4/P16/P38).**
  The justification, the item label and the screen line each render as
  ONE physical line with markdown emphasis, code ticks, brackets and
  tildes escaped. Second belt behind the store's intake caps: a row
  written by an older core still cannot forge a card line.
- **`policy.check()`: an undeclared operation can never be granted
  (P24).** A requested op the registry never declared is now denied with
  the new `Reason.UNDECLARED_OPERATION`, even when a grant row carries
  the literal string. Previously the ops check trusted the row's own
  list, so a grant written before a table change silently widened the
  wall.
- **`screening.from_config`: validate-then-enable (P7/P18).** The block
  is validated in full before `enabled` decides anything: a malformed
  rule, an uncompilable pattern, an unknown key (block, direction block
  or model block) or a bad action refuses the boot even with
  `enabled: false` or absent; a disabled rule is still name/pattern
  validated before it is skipped. An `enabled: true` block with zero
  rules is refused — it could not distinguish "screen clean" from
  "screen off" in the audit chain.
- **`screening.run`: a `BOTH` payload direction is refused** at the
  payload seam (REFUSED/`screen_error`). `BOTH` is a rule scope; the old
  code screened such a transit against the outbound list only.
- **`screening.ScreenResult.audit_value()` returns the fixed audit
  vocabulary, never `None` (P18).** CLEAR maps to `"clear"` (explicit
  recording, per `audit.py`'s own wording), a rule block to
  `"refused"`, an engine failure to `"screen_error"` (mapped by reason —
  `ScreenVerdict` stays intact and `SCREEN_VALUES` is unchanged), FLAG
  to `"flagged"`.
- **`policy.PolicyRegistry` refuses a classifier that contradicts its
  table (P14)** and refuses bare-string table values (P18) at
  construction. The fail-open mapping previously pinned by
  `test_policy_core_coverage.py` is now pinned as a refuse-to-start.
- **`baselines`: scope containment runs through the wall normalizer
  (P8-adjacent).** `_resource_within` normalizes both sides with
  `registry.normalize_resource` and compares with `policy.covers`;
  `Knowledge/../Secret` no longer matches a `Knowledge` baseline.

### Added

- **Audit ordering on the widening path (P10/A1):** `approve` writes its
  audit entry through the existing `AuditLog.record(then=...)`
  write-before-operate seam, so the CAS commit runs only after the entry
  is durable; a failed audit write leaves the grant pending.
- **Audit completeness (P26/P27):** one entry per item (a multi-item
  decision is reconstructable from the chain); `principal="agent"` for
  the submission and `principal="approver:<id>"` for decisions;
  `revoke_all` records one row per revoked grant (the synthetic
  `grant_id=0` summary row is gone). `GrantStore.revoke_all_grants()`
  returns the revoked numbers and `revoke_all()` keeps its count.
- **Bounded transport sends (P21):** `notify_request`/`_post` cap every
  transport call at `send_timeout_seconds` (default 10, configurable per
  gateway); a timeout logs loudly and raises `TransportError` so an
  undelivered card is never reported as delivered.
- **Gateway factory contracts (P15/P29/P30):** `build_gateway` rebinds
  the core's transport from the adapter (public
  `core.bind_transport`) and refuses a gateway that cannot send;
  refuses unknown adapter-section keys against the builder's declared
  `register_adapter(..., fields=...)`; refuses a `command_prefix` the
  inbound grammar cannot match; and refuses `audit=None` unless
  `gateway.allow_without_audit: true` (fail-closed default).
- **`_resolve_fields` expands list values (P5):** `allowed_senders:
  ['${OWNER}']` resolves to the owner id (or the boot fails when the
  variable is unset); `_approver_of` reads the RESOLVED fields.
- **`reject()` honors effective state (P9):** a stale reject tap on an
  effectively-expired pending row no longer rewrites its
  `pending_timeout` story into `rejection`.
- **CI proves the parity batteries (P6):** the workflow checks the
  sibling broker out, exports `GROUPWARE_PATH`, and FAILS when any test
  is skipped — the 274 tests that used to skip now run, and the green
  pipeline can no longer be 46% of the package.
- **`approvals`: the REST approvals surface (goal-contract Stage E1a).**
  New module `access_broker_core/approvals.py`, no framework dependency
  (raw ASGI; the core venv carries no starlette). Public
  `apply_decision(request_number, action, duration, principal,
  announce=True)` on `ApprovalGatewayCore` — the same machinery the room
  path uses (`_decide` is its thin caller), returning a structured
  outcome: applied/refused, state, state_source, the COMPUTED capped
  `expires_at`, the `RejectReason` value, the item count, and
  `audit_head` (the post-write chain head, so a client can verify the
  decision landed in the audit chain). The three refusal states
  (unknown_request / already_decided / expired) are distinguishable in
  the outcome; every refusal — including malformed body, oversize and
  invalid-number rejections — is audited with a fixed reason and never
  applied. `core.snapshot()` returns the bounded read model: generated_at,
  pending_timeout_seconds (the store's actual value, never hardcoded),
  pending entries with `pending_deadline = created_at + pending_timeout`,
  separate expired_recent slice, counts; queries only stored
  pending/active rows, never a history walk.
  `build_approval_surface_app(core, token_env_name, options)` mounts the
  routes (`/approval/snapshot`, `/approval/decision`, `/approval/health`)
  as a beside-the-MCP app: the bearer is the THIRD credential class
  (approval-plane hub/app token, minimum 32 chars, refuse-to-start on
  unset/short), compared constant-time BEFORE any body parse, body cap
  4096 bytes, and a refusal answers with a structured 200 body (an
  authoritative refusal is never a 4xx; the hint rides in the body).
  Client `decision_id` gives a bounded idempotent-replay window.
  `register_protected_surfaces(target, surfaces)` unions the approval
  surface + every route id into a broker's protected surface set (the
  comms BrokerContext pattern) so an agent cannot request_access the
  approval plane. No agent-facing tool is added.
- `GrantStore.active_ttl` so the card's expiry label reads the
  configured TTL instead of a hardcoded constant (P39).

### Fixed (F1 review batch, 2026-11-07)

Fix-first round from the supervisory review of the approvals surface
(`reports/supervisoryReviewGoal1-2026-11-07.md`, items V1/V2/V6; the
surface is unreleased, so these land inside the same 0.3.0 section).

- **`approvals`: decision replay is tuple-bound with a TTL (V1, high).**
  A client `decision_id` binds to the FULL decision tuple
  (request_number, action, duration) for `REPLAY_TTL_SECONDS` (300s;
  refusal bindings included). Reusing the id for a different decision
  is an audited `decision_id_conflict` refusal — the old outcome is
  never replayed and nothing is applied — and a matching retry answers
  from the CURRENT effective grant state through the new
  `ApprovalGatewayCore.replayed_decision` (applied only when the live
  (state, state_source) is exactly what that verb produces, else
  refused with the true state), never from a cached outcome body.
  After the TTL the id is decided fresh, so a mistyped id can no longer
  pin a stale answer.
- **`approvals`: explicit parse boundary, structured internal faults
  (V2, high).** `json.loads` RecursionError (a ~4KB deeply-nested
  depth bomb) is caught at the parse boundary and answers the
  structured, audited `malformed_body` refusal — never a raw 500 with
  no chain trace. An unexpected fault on a NON-widening action
  (reject/revoke) answers through the structured refusal path
  (`internal_error`, audited); on the WIDENING path (approve) it
  answers a structured ERROR body (`ok=false`, `outcome=error`,
  HTTP 200, audited) that never masquerades as a decision outcome.
- **`gateways`: every decision refusal is audited (V6a).** Unknown /
  already-decided / expired attempts each write a chain entry
  (`decision='refused'`, `reason=<the refusal marker>`, the acting
  principal), so the chain now contains every authority-relevant
  attempt; a failed refusal audit write surfaces as
  `audit_written=false` in the outcome body instead of silently
  passing.
- **Outcome bodies carry `audit_written` (V6b).** The receipt head is
  advertised ONLY when the write landed: a non-widening reject/revoke
  whose audit entry failed no longer claims a chain receipt, and
  `audit_surface_refusal` returns `(head, written)` so a surface
  refusal body never advertises a head for an unwritten entry.
- **`gateways`: an unprefixed principal resolves to the non-human class
  (V6c).** `_principal_label` maps a bare string to `hub:<value>`,
  never `approver:<x>`, so a hub mount cannot be configured to write
  human-approver provenance into the chain. The room path passes its
  sender explicitly approver-prefixed, so room labels are byte-identical.
- **`snapshot` is neutralized and bounded (V6d/V6e).** Every agent- or
  remote-influenced field that reaches the body (justification, item
  backend/account/resource/label/ops) is single-physical-line,
  markdown-neutralized and code-span-safe — the room card's own
  render-time discipline; each slice is capped at `SNAPSHOT_MAX_ROWS`
  (256, store order, `truncated: true` in the body when hit) and
  `expired_recent` drops rows whose effective expiry is older than
  `SNAPSHOT_EXPIRED_WINDOW` (24h), so the read model is bounded in rows
  and recency instead of growing forever.
- **Protected-surface registration is by default (V6f).** Building the
  approval surface unions its route ids into
  `core.protected_surfaces` (consult `core.is_protected_surface` at
  the wall); matching NORMALIZES the candidate path (query string and
  trailing slashes stripped) so a variant cannot bypass the protected
  set, and registered ids are canonicalized on the way in.
- **`min_token_length` 32 is a hard floor (V6g).** A configured value
  below 32 REFUSES TO START — the token floor is never clamped or
  lowered.
- **Undo limitation documented (V6h).** The 15s undo window is armed
  for the room path only; an API decision cannot be undone from the
  API in this release (no API undo verb — an owner decision, pending).
  Documented in the `approvals` module docstring and the README
  approvals section.

### Removed

- `gateways.base.ApprovalGateway`'s fictional three-method Protocol
  (`notify_request` was never implemented by any adapter) — replaced by
  the contract that exists. Dead members removed: `_surface`
  (write-only), `GatewayTransport.send_to_approver` (never called),
  `PendingRequest` (never instantiated), the vacuous Protocol test and
  the pass-body stub `test_empty_grant_list_denies_everything`.
- The false claim that transports without reactions post the four
  controls as text lines: the typed grammar is the only decision door.

## [0.2.0] - 2026-10-01

### Added

- **`screening`: deterministic content-screen engine (Stage 1 of the
  content-screening plan; design note
  `review/contentScreeningDesignNote-2026-10-01.md`, all decisions
  owner-resolved 2026-10-01).** A content-direction wall BEHIND the
  access wall: deterministic rules inspect what a legitimately
  authorized operation is about to move, inbound or outbound. Pure,
  synchronous, no I/O. Per-rule action `block` (default, fail-safe) or
  `flag` (annotate and proceed) — owner ruling 2026-10-01. Fail-closed:
  malformed payload and engine errors REFUSE with `screen_error`
  (an engine error is never a rule hit). Refuse-to-start on malformed
  config (unknown action/direction, bad regex, duplicate names, a
  `screening.model` block with `enabled: true` — the model annotator
  does not exist yet). Absent `screening:` key = screen off =
  byte-identical broker behavior. Deterministic rules scan FULL bytes;
  `MODEL_WINDOW_BYTES` (8 KiB) is dormant until the model arm lands
  later as a config flip (resolved decision 3). Seed rule vocabulary:
  secret_bearer_token, secret_private_key (both directions),
  injection_ignore_instructions, injection_reveal_system (inbound).
- **Audit `screen` field (Stage 2):** optional record field carrying
  the screen verdict — fixed vocabulary (clear | flagged | refused |
  unscreened | model_unavailable | screen_error), fail-closed gate
  before write, hashed inside the record (custody-pattern seam, S6-1).
  None = undeclared; legacy lines verify unchanged.
- **Approval-card screen line (Stage 2):** one bounded labelled line
  (`Screen (advisory, deterministic)`) directly below the justification
  on a pending request, rendered ONLY when the adopting broker's screen
  produced a result; never item identity, never a reaction
  (bounded-approval-context invariant). `render_request`,
  `post_request`, `notify_request` gain a keyword-only `screen=None`
  parameter — all existing positional callers unchanged (blast-radius
  verified across all five suites).

### Changed

- Version 0.1.2 → 0.2.0 (minor: additive optional module + optional
  audit/card fields; no behavior change for non-adopting brokers).

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
