# access-broker-core

Shared security architecture for the access-broker suite: the grant
lifecycle, policy wall mechanics, hash-chained audit log, transport
authentication, and the transport-agnostic approval-gateway core,
extracted from nextcloud-access-broker and groupware-access-broker
(same author; see AUTHORS.md for provenance).

## Why access brokers

The Model Context Protocol connects AI agents to real infrastructure:
file stores, chat platforms, mail servers, a home. Its permission model
is static. An MCP server declares a list of tools; the client shows the
list to the user once, at install time; the user approves; from then on,
every tool call runs with the server's full credential.

The model cannot express what matters once the infrastructure is real.

- A grant is all-or-nothing at install time. There is no scoped, expiring
  grant for one folder, one room, or one lock. Approving the server
  approves everything it can reach.
- There is no per-operation review. After install, a destructive write
  runs as freely as a harmless read.
- There is no audit of agent decisions. What the agent requested, what
  was refused, and who approved what is recorded nowhere the owner
  controls.
- There is no human gate for sensitive actions. The only approval
  happened between the agent and the client, before any concrete
  operation existed.
- The credential at the server carries everything the server can do.
  Tool descriptions that promise restraint are advisory; the token is
  not.

An access broker is an MCP server that closes these gaps for one domain.
It holds the real credential, exposes a deliberately small tool surface,
and turns access into an explicit object: a scoped, expiring, audited,
human-approved grant, evaluated per operation.

## The access broker model

The suite implements one model with seven properties. Every broker
carries all of them; the mechanics live in access-broker-core.

1. A tier model per domain. Every operation is classified before it can
   be requested. T0/T1 are free-lane reads and reversible actions that
   run without a grant. T2 operations are sensitive and require
   per-operation human approval through an approval gateway on a chat
   platform; the agent cannot self-approve, and batches do not exist.
   T3 operations are always gated and, where the action is irreversible,
   are never offered as tools at all.

2. Declared operations. Each tool names the operation it performs. The
   wall, the broker's scope checker, validates the resource and the
   operation against active grants before anything executes. The free
   lane is defined by the domain tier table, not by what happens to be
   exposed.

3. Write-before-operate, hash-chained audit. Every request, execution,
   refusal, and human decision is an audit-class event written to a
   hash-chained log before the operation runs. `verify_chain` detects
   tampering, including truncation. The chain, not memory, is the record
   of what the agent did and why.

4. Fail-closed everywhere. Any configuration or validation failure
   refuses the boot. Unknown or malformed input denies. A restart never
   widens capability and never promotes pending or suspended state.

5. Approval separation. The approval gateway account is never a brokered
   account. A broker that could approve its own requests is a design
   failure, and the configuration is refused at boot.

6. Custody declarations. The broker declares, machine-readably, what its
   backend credentials can reach. An undeclared trust boundary refuses
   to start, and the custody class rides every audit record.

7. The D5 two-surface model in the data domain. The agent surface
   handles metadata and reasoning; bulk bytes move through a separate
   transfer surface addressed only by a CLI holding its own token, with
   SHA-256 verify-then-write. File content never enters LLM context.

## The suite

[access-broker-core](https://github.com/nasserma/access-broker-core)
carries the mechanics: the grant store (conditional-SQL CAS state
machine), policy wall evaluation, the hash-chained audit log, the
approval-gateway substrate, the custody registry, the baseline engine,
and transport authentication. Each broker is a thin domain layer: a
scope-checker wall, backend adapters, a tier table, and tool surfaces.
One repo per broker; no monorepo.

| Broker | Domain | Repository |
|---|---|---|
| data-access-broker | WebDAV and OneDrive file stores | https://github.com/nasserma/data-access-broker |
| communications-access-broker | Matrix and Microsoft Teams chat | to be published |
| groupware-access-broker | Mail, calendar, contacts, tasks over IMAP/SMTP, CalDAV/CardDAV, MS Graph | to be published |
| automation-access-broker | Physical automation: Home Assistant entities and services, extendable to any actuated device | to be published |

## Status

v0.3.0 (this tree; the last published tag is v0.1.1 and the v0.2.0/v0.3.0
releases are cut from the hygiene round). Two brokers consume it in their
suites (groupware verified by porting; the data broker consumes the
published release). The founding compatibility matrix, which records the
core version each released broker requires, lives in CHANGELOG.md and
grows with each broker release.

What v0.3.0 changed in the security posture, in one place: agent-supplied
card text is capped and rendered single-line-by-construction; the
approval transition writes its audit entry BEFORE the state commit; bulk
revokes are per-grant audit rows; a gateway cannot boot without an audit
log (unless `allow_without_audit: true` says so out loud) and cannot
return without a live transport; a screen config that is present but
malformed refuses the boot even when disabled, and an enabled zero-rule
screen is refused; a requested operation the registry never declared can
never be granted; and the CI parity gate cannot be earned by skipping:
the parity job requires the sibling groupware repo at the configured
remote and FAILS CLOSED — permanently red, with every skip visible —
until that repo is published (the sibling remote does not exist today;
publication sequencing is the owner's, and the workflow itself is
unchanged).

## What the core owns

- **`policy`**: the tier-classification registry mechanism, `Decision`,
  `GrantItem`/`Request` shapes, component-prefix containment, and the
  `check()` evaluation skeleton. Domain semantics (operation tables,
  resource normalizers) belong to each broker and are registered at
  boot; an empty registry refuses to start.
- **`grants`**: GrantStore, conditional-SQL CAS state transitions,
  one-time request numbers, pending expiry, TTL, revoke, restart
  persistence, restart discard of pending. Silence grants nothing.
- **`audit`**: hash-chained JSONL, fsync per record, a checkpoint
  sidecar (truncation detection), write-before-operate, secret
  scrubbing, `verify_chain`. Human decisions are audit-class events:
  the approver identity rides in `principal` (suite finding F1, fixed
  2026-09-18).
- **`gateways`**: the ApprovalGateway adapter contract and the
  transport-agnostic decision core (allowlist first, one-time numbers,
  undo windows, expiry sweep, approval summaries, shared-room routing
  with a leading `[tag]` on every outbound message). The typed command
  grammar is the only decision door: a transport without native
  reactions accepts typed commands, and there is deliberately no
  text-line control fallback (an unclickable "approve" line inside a
  bot message is indistinguishable from agent-influenced card text).
  Sends are bounded (`send_timeout_seconds`, default 10) so a hung
  transport cannot stall the agent's gated tool call. One message format
  grammar serves the whole suite: `[tag] <icon> **<headline>**`, item
  identity on one template-controlled line per item, the agent's
  justification isolated in one labelled line, Matrix-safe markdown
  only (no tables). Platform adapters (Matrix, Telegram, Teams, Signal
  shells) stay per-broker.
- **`auth`**: RFC 9728/8707 OAuth 2.1 resource-server validation (HTTP
  transport) and constant-time bearer checks (stdio).
- **`baselines`**: BaselineEngine, standing T0/T1 permission
  reassessment (the nextcloud-access-broker design note rev 2,
  implemented; the data broker consumes it).
- **`custody`**: CustodyRegistry/CustodyClass, the machine-readable
  custody-class declaration layer (S6-1); declarations are
  refuse-to-start validated and ride every audit record.
- **`approvals`** (v0.3.0, Stage E1a): the REST approvals surface —
  `apply_decision` (the room path's machinery with a structured outcome
  carrying the computed capped `expires_at` and the post-write
  `audit_head`), `snapshot()` (the bounded read model with
  `pending_deadline` and the store's actual `pending_timeout_seconds`),
  and `build_approval_surface_app` (raw-ASGI mount of
  `/approval/snapshot|decision|health` beside an MCP app). Its bearer is
  the THIRD credential class (approval-plane hub/app token, >= 32 chars,
  refuse-to-start, constant-time before any body parse, 4096-byte body
  cap; refusals answer as structured 200 bodies and are audited). The
  approval routes join the broker's protected surfaces — by DEFAULT as
  of the F1 review round: building the surface unions its ids into
  `core.protected_surfaces` (consult `core.is_protected_surface`; paths
  are normalized, so query-string and trailing-slash variants cannot
  bypass the set) — so an agent cannot request_access the plane. No
  agent-facing tool exists for decisions.

  The 15s undo window is armed for the ROOM path only: an API decision
  cannot be undone from the API in this release (there is no API undo
  verb; an owner decision, pending). A rejected or revoked request is
  re-opened only from the approval room (`undo <id>`), which files a NEW
  pending request.

  F1 review round (2026-11-07, same unreleased 0.3.0): a decision
  replay binds the client `decision_id` to its full decision tuple with
  a TTL — a mismatching reuse is an audited conflict refusal and a
  matching retry answers from the live grant state, never a cached
  outcome; a deeply-nested JSON body answers the structured audited
  refusal (no raw 500); every decision refusal is audited and the
  outcome body carries `audit_written`, advertising the chain head only
  when the write landed; an unprefixed principal resolves to the
  hub/device class, never the human-approver class; the snapshot
  neutralizes every field it returns, caps each slice (256 rows,
  `truncated` flag) and bounds `expired_recent` to a 24h recency
  window; and the 32-character token floor is hard (a configured lower
  value refuses to start).

- **`screening`** (v0.2.0, optional): the deterministic content screen
  engine — the content-direction wall that runs BEHIND the access wall.
  Pure, synchronous, no I/O. Per-rule `block` (default, fail-safe) or
  `flag` action; fail-closed on malformed payload and engine errors
  (`screen_error`, never a rule hit); refuse-to-start on malformed
  config; screen off (absent `screening:` key) is byte-identical
  broker behavior. VALIDATE-THEN-ENABLE (v0.3.0): a present-but-
  malformed block refuses the boot even with `enabled: false` or absent
  (a bad rule, pattern, action or unknown key cannot hide behind the
  off switch), a disabled rule is still name/pattern validated, and an
  enabled block with zero rules is refused because it cannot
  distinguish "screen clean" from "screen off". A payload direction of
  `BOTH` is refused (BOTH is a rule scope, not a transit direction).
  The screen verdict rides the audit record's optional `screen` field
  with the fixed vocabulary — a clear verdict is recorded explicitly as
  `clear`, a rule block as `refused`, and an ENGINE failure as
  `screen_error`, so the chain can tell a rule from a bug. Deterministic
  rules scan full bytes; the 8 KiB MODEL_WINDOW_BYTES cap is dormant
  until the later model annotator lands (a config enabling
  `screening.model` refuses to start). For pending requests the screen
  rides one bounded line on the approval card. Design note:
  `review/contentScreeningDesignNote-2026-10-01.md`.

## What brokers own

The walls (scope checkers), backend adapters, tool surfaces, config,
and server wiring are per-broker. The core owns the mechanics of
authorization, audit, and approval; each broker owns the semantics of
its domain: its tier table, its scope object, its resource
normalizers. The wall supplies the harness and the quality bar; every
wall stays exhaustively tested (100% statement and branch, hypothesis
fuzz, unmocked) in its own repository. The core provides that bar, not
an exemption from it.

## Suite invariants (stated once, here)

1. Tier-first evaluation: classification precedes scope matching; gated
   operations always gate.
2. Write-before-operate: an operation without a durable audit entry does
   not run.
3. Fail-closed on every failure mode; silence grants nothing; restart
   never widens capability and never promotes suspended state.
4. The approval plane is severed from the execution plane; the approval
   gateway must not be the brokered platform+account combination.
   **BROKER-SIDE property:** the core exposes the seam (approver
   resolution, allowlist, one gateway per broker) but holds no mechanism
   that can prove two distinct credentials are in use. Severance and the
   suite's two-token minimum are DECLARED and enforced by each broker's
   config validation; the R1-R15 app-era work states them there. Do not
   read this invariant as something the core enforces.
5. Human decisions are audit-class events with the approver as
   principal.
6. The T0/T1 free lane exists in every broker; gating reads and
   reversible writes trains the owner to approve reflexively.
7. The content screen annotates or refuses content, never access: a
   screen result feeds no grant, tier classification, or policy
   decision. Deterministic rules may block a content transit the wall
   already allowed (per-rule, default block); a model screen, when it
   exists, may only annotate. The screen grants nothing and widens
   nothing.

## Verification model

A core change is not proven in this repository alone. The acceptance
test is the ported suite: each broker's existing test suite must pass
against the changed core with zero behavior change. Verification by
porting is the gate for every core release.

The compatibility matrix tracks the pairing in the other direction:
which core version each released broker requires. The founding matrix
(groupware-access-broker ==0.1.0, nextcloud-access-broker deferred to
migration) is in CHANGELOG.md; each broker release extends it.

## Security

Each broker repository carries its own SECURITY.md with the domain
threat model, the custody declarations, and the compensating controls
for that domain. The invariants above are the shared spine those
documents build on.

## Provenance

Author and maintainer: Nasser Mohieddin Abukhdeir. The primary
implementation model was GLM (glm-5.3), with glm-5.3-flash as the
delegated sub-agent model. See AUTHORS.md for the full provenance
record.

## License

GPL-3.0-or-later.