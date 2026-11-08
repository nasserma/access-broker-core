# Security addendum — 0.4.0 app-protocol closure (B1–B8)

**Scope:** the security-relevant properties of the 0.4.0 changes
(approval-client design note `review/approvalClientDesignNote-2026-11-07.md`,
items B1–B8). The shared spine is the suite invariants in README.md;
each broker repository carries its own SECURITY.md with the domain
threat model. This file is the core's own record of what changed in the
chain, the wire and the code lifecycle — stated once, here.

## Audit provenance fields (B1/R6)

The four app-protocol fields — `device_id`, `credential_class`,
`channel`, `request_digest` — ride the hash-chained audit log **the same
way `custody` and `screen` do**:

- **optional-when-present:** a caller passing nothing writes legacy
  lines, and every chain written before 0.4.0 still verifies
  byte-for-byte (no re-hash, no migration);
- **hashed when present:** the fields are part of the record payload
  that produces the chain hash, so a provenance statement is tamper-evident
  with the rest of the entry;
- **fail-closed gates before the write:** `device_id` is a bounded
  single-line id (`[A-Za-z0-9._:-]{1,128}`), `credential_class` a fixed
  vocabulary (`approval-device`), `channel` a fixed vocabulary
  (`android-app` | `text-fallback`), `request_digest` 64 lowercase hex.
  A value outside its shape or vocabulary raises before any record is
  built — the chain never carries an out-of-vocabulary provenance
  statement;
- **stamped by the route, never client-declared (channel/class):** the
  approval surface stamps `channel="android-app"` +
  `credential_class="approval-device"` itself; the room path stamps
  `channel="text-fallback"`. A client can name its device and its
  digest, never its own channel or credential class.

## Decision freshness vs the replay window (B6/R4)

The decision route requires a timezone-qualified `issued_at` and
refuses (`stale_issued_at`, HTTP-hint 409) anything further than
**`DECISION_FRESHNESS_SECONDS` = 120s** from the broker's clock — past
OR future (bounded both ways) — checked **before** the `decision_id`
replay cache and before any store read.

The window is deliberately **tighter than the replay TTL**
(`REPLAY_TTL_SECONDS` = 300s): a replayed `decision_id` cannot resurrect
a decision composed against authorization state older than the
freshness window, so idempotent retry can never be used as a
stale-authorization oracle. The freshness gate reads the broker's wall
clock, not the caller's; the wire speaks UTC and a naive timestamp is
refused.

The digest bound (R5) is the second half of the same property: the
broker recomputes the canonical request digest from the live record and
refuses `request_digest_mismatch` (409, audited, nothing applied) on
both the fresh and the replay paths — what the human signed must be
byte-identical to what the broker holds.

## One-time approve codes (B4/D-F)

- **In-memory only:** the code registry is process state, like the undo
  windows. A broker restart discards it **together with the pending
  requests it gates** (the store's restart-discard rule), so a code can
  never outlive its request — there is nothing on disk to steal or
  replay across a restart.
- **Hashed at rest (in memory):** the registry stores the sha256 of the
  normalized code and compares constant-time; the plaintext exists only
  in the hub's registration call and the human's typed command.
- **Single-use, success-only:** the code is consumed only when the
  comparison succeeds; a failed attempt (wrong, malformed, unknown,
  expired) consumes nothing.
- **Bounded lifetime:** registration accepts `ttl_seconds` in [60, 900]
  only; an out-of-window TTL is refused (the code never registers), so
  no eternal approval code can exist as a standing bypass of the D-F
  narrowing (approve-by-reaction is refused; typed approve is
  code-gated).

## Constants flagged for owner confirmation

`DECISION_FRESHNESS_SECONDS` (120), `ONE_TIME_CODE_MIN_TTL_SECONDS`
(60) and `ONE_TIME_CODE_MAX_TTL_SECONDS` (900) are implementation
defaults, not config, in this release — flagged in CHANGELOG 0.4.0 as
owner decisions pending. B9 (an API undo verb) was not added; the undo
window remains room-path-only.
