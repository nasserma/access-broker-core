# Design Note — Approval-Room Message Format (shared-room first)

Status: IMPLEMENTED 2026-09-29 (owner go; released in 0.1.2). Scope:
`access_broker_core/gateways/logic.py` rendering only, plus the
shared-room config/label/storage changes the owner had already
accepted (2026-09-21 entry) that ship in the same release. Deviations
and open points are recorded in §7; the two owner decisions that
remain (🛇 vs ⛔, groupware renderer retirement) are noted there and
in the suite plan.

---

## 1. Problem

The approval plane is going shared: the owner expects several brokers —
automation, communications, data, groupware (and the nextcloud lineage) — to
post into ONE approval room, each stamped `[prefix]` by the core's `_post`
choke point. Two defects show up the moment more than one broker is in the
room, and one shows up even in a solo room.

- **Item identity does not survive the room, or the phone.** In the current
  renders the resource was glued to the account with no space
  (`**webdav** cloud:`/Shared/budget.xlsx``), the ops were bare text, and
  the justification line sat directly under the item lines with no label
  separating agent text from template text. With three brokers interleaving
  posts, the approver cannot tell in one glance which line names the
  backend/resource and which is agent commentary.
- **No consistent visual grammar.** Every message type had its own
  punctuation and its own idea of an icon: `⏳ **PENDING #N** — awaiting…`
  in requests, `**Approved #N**` with no icon in confirmations, `**Active
  grants**` with no type marker in status, `gateway started` completely
  plain, `Cannot approve #N: RejectReason.UNKNOWN_REQUEST` showing Python
  enum syntax to the human, and the status footer wrapping already-backticked
  commands in a second pair of backticks (`` `Kill: `revoke <id>` (mass:
  `revoke all`)` `` — a malformed code span that renders as a literal
  backtick in Element X).
- **Redundant instructions.** A request repeated the decide instruction
  (`Decide: `approve|reject <id> [expiry]``) and stated the expiry twice, and
  the default expiry was not in the header, so the three facts the approver
  actually weighs (what, how many, how long) were spread across five lines.

The invocation layer is not implicated; the failure is entirely in the
rendered text.

## 2. Proposed revision (implemented, uncommitted)

One message grammar for the whole suite, applied to every outbound type:

```
[tag] <icon> **<headline>** — <tail>          # shared room; solo rooms drop [tag]
```

- **Header first.** The first line is `icon + bold headline + an em-dash
  tail` and carries the three decision facts for a request (id, item count,
  default expiry).
- **Item lines are one line, one item, template-controlled:**
  `<n>.` in a request, `•` in every other render, then
  `**backend** account: resource — `op`, `op``. The resource keeps its
  human `label` when the item supplies one (`Front Door (`lock.front_door`)`).
- **One labelled comment line.** The agent-supplied justification appears
  verbatim exactly once, on `Justification (agent, unverified): <text>` —
  never on an item line and never on a pre-placed reaction.
- **One icon vocabulary, no reuse:** decisions reuse the reaction emoji the
  approver tapped (👍 👎 🛇), type notices use ⏳ status 📋 active ✅ expired
  ⏱️ undo-closed ⌛ refused ❌ warning ⚠️ unknown-command ❓ help 📖 lifecycle
  🟢 / ⚪.
- **Consistent decision phrasing.** Every instruction names a real command:
  `**Decide** — 👍 `approve N`, or 👎 `reject N` · shorter: `approve N 8h``
  plus the reaction legend `(react below: 👍 👎 🛇 📋)`; the status footer is
  `Decide: `approve|reject <id> [expiry]` · Kill: `revoke <id>` (mass:
  `revoke all`)`.
- **Human refusal text.** The store's `RejectReason` enum is translated for
  display only (`unknown_request` → "no pending request with that number
  (expired, already decided, or never issued)"); the enum is still what the
  store returns and the decision path is unchanged.
- **Matrix-safe markdown only.** Bold, inline code, bullets, em dashes, one
  `———` rule. No tables (Element X collapses them), no nested emphasis.

## 3. What changes

| File | Change |
|---|---|
| `access_broker_core/gateways/logic.py` | Icon/format constants (`ICON_*`, `MESSAGE_ICONS`, `BULLET`, `JUSTIFICATION_LABEL`, `_VERB_ICONS`, `_REJECT_REASON_TEXT`, `_RULE`); new `_item_line()` and `_compose()`; reworked `render_request`, `_render_decision`, `_status_lines`, `_revoke_many`, `_refused`, `_undo`-closed notice, `sweep` notice, `announce_lifecycle`, `_route_command` hints, parse-error hint, `_HELP_TEXT`; approval audit-failure warning re-worded (facts unchanged). |
| `tests/test_gateway_logic.py` | Format-contract battery added (see §9); three pre-existing assertions updated to the new leading-emoji form. |
| `CHANGELOG.md` | `[Unreleased] - 2026-09-29` entry. |
| `README.md` | `gateways` bullet now states the shared format grammar. |
| `review/ApprovalRoomFormatDesignNote-2026-09-29.md` | This note (untracked). |

Version bump: the note proposes a **patch** bump (`0.1.1` → `0.1.2`) at
commit time; no public Python API changed (no signature changed; new names
are additive module constants).

## 4. What does NOT change

- The decision path: `_decide`, `_revoke`, `_revoke_many`, `_undo`,
  `handle_reaction`, `handle_reply`, the store calls, the undo window
  duration and arming, the one-time request numbers, the audit entries and
  their `principal`/`decision`/`reason` values. No state transition moved.
- The shared-room routing semantics: allowlist first, prefix required,
  other brokers' prefixed commands ignored silently, unprefixed commands
  refused fail-closed.
- The pre-placed reactions and their order (`DECISION_EMOJIS`, 👍 👎 🛇 📋).
- `_tag` / `_post` (the single outbound choke point) and the `[tag] ` stamp.
- The sweep rule (one notice per number per process lifetime), the pending
  timeout, the 15 s undo grace, `DEFAULT_EXPIRY_LABEL = "24h"`.
- `gateways/__init__.py` factory, config keys, the `label` field contract
  (display only; the policy wall still matches by `resource`).
- The store, policy wall, audit log, custody, baselines: untouched.
- Purity: no I/O, no wall clock beyond the injected `now` already threaded
  through (`_status_lines` aging and `sweep`).

## 5. Why the security model is preserved (suite invariants, one by one)

- **Bounded approval context (automation `SECURITY.md`).** Item lines accept
  only store-validated fields (`backend`, `account`, `resource`, display-only
  `label`, sorted `ops`). The justification is never an input to
  `_item_line()`. The invariant is asserted by
  `test_justification_isolation_invariant` (hostile justification containing
  a fake item line and a fake command: verbatim exactly once on the labelled
  line, zero occurrences on item lines, header still names the real id) and
  `test_justification_isolation_in_decision_render` (justification absent
  from the confirmation entirely).
- **Allowlist first / no oracle.** Unchanged; the new refusal hints only post
  after the allowlist check has passed. Non-approver input still produces
  silence (`test_non_approver_*` unchanged and green).
- **One-time numbers / no resurrection.** Unchanged; `render_request`
  interpolates the store-issued number only.
- **Silence grants nothing.** The sweep notice keeps its exact fail-closed
  phrase: `⏱️ **Request #N expired unanswered** — silence grants nothing.`
- **Fail-closed parse errors with closest-command hints.** The hint keeps
  `closest: `approve`` and adds a pointer to `status`; unparseable
  non-command text still gets the help card.
- **Undo window messaging.** Kept verbatim (`Mistake? `undo N` within 15s
  re-opens it as a new request.`), now with a ⌛ notice when the window has
  closed. The `revoke all` confirmation now says there is no bulk undo —
  that is a truthfulness fix: `_undo_windows` is armed per id and never for
  a bulk revoke, so the old summary implied an undo that does not exist.
- **Write-before-notify (F1).** The approval audit-failure warning was
  re-worded (headline first) but still states every fact: the grant store
  committed, the audit entry failed, re-approving will not work, recover
  with `revoke N`.

## 6. Before / after, every outbound type

All examples below are real output from the old revision (`git show
HEAD:...logic.py`) and the new revision, same inputs. `[tag] ` is prefixed
by `_post` in shared-room mode; it is shown where it matters.

### 1. Pending request (3 items, one labelled)

Before — resource glued to account, ops bare, justification unlabelled, expiry stated twice:

```
⏳ **PENDING #4** — awaiting your approval
Justification: send the reply
1. **homeassistant** home:`lock.front_door` — get_state
2. **webdav** cloud:`/Shared/budget.xlsx` — read, write
3. **imap** work:`Sent` — send
Expiry if approved: 24h (or `approve <id> 8h` for shorter)
Decide: `approve|reject <id> [expiry]`
```

After — count + default expiry in the header, resource spaced and in code, ops in code, justification labelled and isolated:

```
⏳ **PENDING #4** — awaiting your approval · 3 items · 24h if approved
1. **homeassistant** home: Front Door (`lock.front_door`) — `get_state`
2. **webdav** cloud: `/Shared/budget.xlsx` — `read`, `write`
3. **imap** work: `Sent` — `send`
Justification (agent, unverified): send the reply

**Decide** — 👍 `approve 4`, or 👎 `reject 4` · shorter: `approve 4 8h`
(react below: 👍 👎 🛇 📋)
```

Shared room: `[comms] ⏳ **PENDING #4** — awaiting your approval · 3 items · 24h if approved`
(the tag stays the first token; every type below is stamped the same way).

### 2. Approve confirmation + refreshed status

Before — no icon, items indented not bulleted, status untitled, footer malformed:

```
**Approved #1** (8h.)
  **homeassistant** home:`lock.front_door` — get_state
  **webdav** cloud:`/Shared/budget.xlsx` — read, write
  **imap** work:`Sent` — send

——

**Active grants**
✅ **#1** — get_state+read+send+write, 8h left
   **homeassistant** home:`lock.front_door` — get_state
   **webdav** cloud:`/Shared/budget.xlsx` — read, write
   **imap** work:`Sent` — send

Awaiting your approval: none

`Kill: `revoke <id>` (mass: `revoke all`)`
```

After — 👍 mirrors the tapped control, one bullet per item, titled status, clean footer:

```
👍 **Approved #1** (8h.)
• **homeassistant** home: Front Door (`lock.front_door`) — `get_state`
• **webdav** cloud: `/Shared/budget.xlsx` — `read`, `write`
• **imap** work: `Sent` — `send`

———

📋 **STATUS**
**Active grants**
✅ **#1** — get_state+read+send+write, 8h left
• **homeassistant** home: Front Door (`lock.front_door`) — `get_state`
• **webdav** cloud: `/Shared/budget.xlsx` — `read`, `write`
• **imap** work: `Sent` — `send`

**Awaiting your approval** — none

Kill: `revoke <id>` (mass: `revoke all`)
```

### 3. Reject / revoke confirmation with undo hint

Before:

```
**Rejected #2**.
  **homeassistant** home:`lock.front_door` — get_state
  …

Mistake? `undo 2` within 15s re-opens it as a new request.
```

After:

```
👎 **Rejected #2**.
• **homeassistant** home: Front Door (`lock.front_door`) — `get_state`
…

Mistake? `undo 2` within 15s re-opens it as a new request.
```

(`Revoked #3` is `🛇` — see the icon-vocabulary caveat in §7.)

### 4. Revoke-all summary

Before:

```
**Revoked 2 grant(s)**.

——

**Active grants**
none

**Awaiting your approval** (1):
⏳ **#3** — waiting 0m

`Decide a request: `approve|reject <id> [expiry]``
```

After (the no-undo fact is now stated; the summary no longer implies one):

```
🛇 **Revoked 2 grant(s)** — no undo for a bulk revoke.

———

📋 **STATUS**
**Active grants**
none

**Awaiting your approval** (1):
⏳ **#3** — waiting 0m

Decide: `approve|reject <id> [expiry]`
```

### 5. Status (active + pending, aging)

Before — no type marker, footer malformed, `Awaiting your approval: none` inconsistent with the counted form:

```
**Active grants**
none

**Awaiting your approval** (1):
⏳ **#3** — waiting 0m

`Decide a request: `approve|reject <id> [expiry]``
```

After:

```
📋 **STATUS**
**Active grants**
none

**Awaiting your approval** (1):
⏳ **#3** — waiting 0m

Decide: `approve|reject <id> [expiry]`
```

Empty case: `**Awaiting your approval** — none` (was `Awaiting your approval: none`).
Aging markers (`**stale?**` past 4 h, and the 1–4 h silent band) are unchanged.

### 6. Lifecycle notice

Before: `gateway started` · After: `🟢 **gateway started**`
(stopping: `⚪ **gateway stopping**`; any other state falls back to `🔄`.)
Shared room: `[comms] 🟢 **gateway started**`.

### 7. Sweep expiry notice

Before: `Request #4 expired unanswered. Silence grants nothing.`
After: `⏱️ **Request #4 expired unanswered** — silence grants nothing. File a new request if access is still needed.`

### 8. Undo-window-closed notice

Before: `Undo window for #5 closed. File a new request if access is still needed.`
After: `⌛ Undo window for #5 closed. File a new request if access is still needed.`

### 9. Unprefixed-command refusal (shared room)

Before: `Unprefixed command — this room serves multiple brokers. Prefix with `comms approve`...`
After (`[comms] ` tagged):
`❌ **Unprefixed command** — this room serves multiple brokers. Prefix with `comms approve`...`
The fail-closed behaviour is unchanged (never guessed at, never silently dropped).

### 10. Parse-error hint / help card

Before: `Unknown command 'aproove' — closest: `approve`. Type `status` to see the command list.`
After: `❓ **Unknown command** `aproove` — closest: `approve`. `status` lists every command.`
Help card keeps its content, gains the `📖` marker and code-formatted `<id>` placeholders:
`📖 **How to decide** …`.

### 11. Decision refusal (store reason)

Before: `Cannot approve #99: RejectReason.UNKNOWN_REQUEST`
After: `❌ Cannot approve #99: no pending request with that number (expired, already decided, or never issued)`
(`revoke` refusals keep the store's own free text: `❌ Cannot revoke #99: unknown, decided, or expired`.)

### 12. Approval audit-failure warning (fail-closed, F1)

Before:

```
⚠️ Approve #4 reached the grant store but its audit entry FAILED — grant NOT confirmed (the grant IS active; re-approving will not work). Resolve the audit log, then revoke with `revoke 4` if this was not intended.
```

After (headline first; every fact retained):

```
⚠️ **Approve #4 NOT confirmed** — the grant store committed the grant, but its audit entry FAILED. Resolve the audit log, then `revoke 4` if this was not intended. (Re-approving will not work.)
```

## 7. Deviations and open points

1. **`REVOKE_EMOJI` renders as `🛇` in our text, not the `⛔` glyph.** The
   core has always used `"\N{PROHIBITED SIGN}"` (U+1F6C7) for the canonical
   set; `⛔` is U+26D4 NO ENTRY. The render now reuses the constant, so the
   confirmation header shows exactly the emoji the bot pre-placed — which is
   the point of reusing it. If the owner wants the friendlier `⛔` in the
   room, that is a change to `REVOKE_EMOJI` and affects the pre-placed
   reaction too; it is deliberately NOT made here (one revision, one
   concern) and is flagged as an owner decision.
2. **Pending rows in the status block stay one line each** (no item bullets),
   deliberately: the decision affordance is the request message and its
   pre-placed reactions, and item bullets under every pending row would
   double the status height in a room with several brokers. Active grants DO
   carry item bullets (a live grant must be inspectable). Rationale recorded
   in `test_status_block_shape`.
3. **The approval audit-failure warning is re-worded, not just re-marked**
   (task said keep fail-closed semantics; the facts are all retained). One
   existing integration assertion pinned the old words
   (`"audit" in t.lower() and "FAILED" in t`) — the new text still matches
   both, so no core test needed changing for it.
4. **`_REJECT_REASON_TEXT` is display-only.** It maps the two enum members
   the store returns; any other value passes through verbatim (so a future
   reason cannot be silently mislabelled as unknown).
5. **Item lines keep `account` outside code font** (was also outside before).
   `backend` and `resource` are bold/code; the account reads as plain text
   because it is a short local name. If the owner prefers the account in code
   font too, it is a one-character change in `_item_line`.

## 8. Impact scan (report only — no other repo touched)

Exact-string assertions that pin gateway message text, and whether this
change breaks them. "Own tree" excludes each repo's nested
`access-broker-core/` submodule copy and `build/lib/` mirrors (those pin the
submodule revision and follow it).

| Repo | File:line | Pinned string | Breaks? |
|---|---|---|---|
| groupware | `tests/test_gateway_logic.py:171` | `PENDING #1` | No |
| groupware | `tests/test_gateway_logic.py:191` | `Approved #1` | No |
| groupware | `tests/test_gateway_logic.py:192` | `Active grants` | No |
| groupware | `tests/test_gateway_logic.py:201` | `Rejected #1` | No |
| groupware | `tests/test_gateway_logic.py:206` | `PENDING #2` | No |
| groupware | `tests/test_gateway_logic.py:218` | `window for #1 closed` | No |
| groupware | `tests/test_gateway_logic.py:221` | `PENDING #2` (absence) | No |
| groupware | `tests/test_gateway_logic.py:230` | `Revoked #1` | No |
| groupware | `tests/test_gateway_logic.py:238` | `Awaiting your approval` | No |
| groupware | `tests/test_gateway_logic.py:305,312,322` | `Cannot approve #1` / `#99` | No |
| groupware | `tests/test_gateway_logic.py:332` | `Revoked #1` | No |
| groupware | `tests/test_gateway_logic.py:346` | `Revoked 1 grant(s)` | No |
| groupware | `tests/test_gateway_logic.py:349` | `Nothing to revoke` | No |
| groupware | `tests/test_gateway_logic.py:355` | `closest: \`approve\`` | No |
| groupware | `tests/test_gateway_logic.py:358` | `How to decide` | No |
| groupware | `tests/test_gateway_logic.py:376` | `Active grants` | No |
| groupware | `tests/test_gateway_logic.py:378` | `Awaiting your approval** (1)` | No |
| groupware | `tests/test_gateway_logic.py:388` | `stale?` | No |
| groupware | `tests/test_gateway_logic.py:397` | `expired unanswered` | No |
| groupware | `tests/test_gateway_integration.py:233` | `PENDING #1` | No |
| groupware | `tests/test_gateway_integration.py:249` | `Approved #1` | No |
| groupware | `tests/test_gateway_integration.py:250` | `Active grants` | No |
| groupware | `tests/test_gateway_integration.py:258` | `Revoked #1` | No |
| groupware | `tests/test_gateway_integration.py:314,320` | `#{n} expired unanswered` | No |
| groupware | `tests/test_gateway_integration.py:459` | `Approved #` (absence, F1) | No |
| groupware | `tests/test_gateway_integration.py:592` | `Cannot revoke` | No |
| groupware | `supporting_documentation/stages/S6_report_C.md:67` | `#N expired unanswered` (prose) | No |
| automation | `tests/test_gateway_matrix.py`, `tests/test_tools.py` | none pin gateway render text (fake cores) | No |
| automation | `CHANGELOG.md:128`, `README.md:105` | `gateway started` / `gateway stopping` (prose) | No — both phrases are still in the notice |
| automation | `tests/test_scratch_dendrite_gateway.py:127` | `notify_request` used, no text pin | No |
| communications | `CHANGELOG.md:39` | `gateway started` / `gateway stopping` (prose) | No |
| communications | `deploymentWalk_2026-09-21.md:193,253` | adapter log line `matrix gateway started (room=…)` | No — that is a logger line, not the room notice |
| communications | `tests/` | no gateway-render text pins | No |
| data | `tests/` | no gateway-render text pins | No |
| data | `CHANGEOVER_2026-09-18-s4Execution.md`, `SECURITY.md`, `ROTATION.md` | `PENDING`/`closest` in unrelated senses | No |
| nextcloud lineage (`nextcloudAccessBroker`) | `broker/matrixbot.py:42,208,216,219,294,297,346,411,432,468,474,489,508,526,528,536,546,549,594` | its OWN ported copy of the renderer | Separate lineage — not this core; needs the same pass only if the owner keeps it in step |
| nextcloud lineage | `tests/test_server.py:180`, `tests/test_matrixbot.py:89`, `tests/test_matrixbot_d61.py:94,128,129,139,231,232,244`, `tests/test_matrixbot_d62_aging.py:85`, `tests/test_matrixbot_d62_undo.py:93,138`, `tests/test_matrixbot_d62_footer.py:55,69,77,90,102,104,105,117`, `tests/test_d6h_revoke_all.py:80,91,105,119` | `PENDING #N`, `awaiting your approval`, `Active grants`, `Awaiting your approval`, `**stale?**`, `Mistake?`, `Kill: \`revoke <id>\``, `Decide a request: …`, `Decide: …`, `Revoked 1 grant(s)`, `Nothing to revoke` | No — these test the lineage's own `broker/matrixbot.py`, not this core |
| nextcloud lineage | `DEVIATIONS.md:293,300,305` | documents the lineage's own message vocabulary | No (same reason) |

**Files that DO need a change in their owner's next stage** (exact-string
pins that break against the new render):

| Repo | File:line | Pinned string | Breaks because |
|---|---|---|---|
| groupware | `groupware_broker/gateways/logic.py:69-289,363-666` | the whole old render set | This is the groupware broker's OWN pre-core copy of the renderer — it is a second renderer that will need the same format pass (or deletion in favour of the core) before groupware can show the shared-room format. Not a core test; a broker source file. |
| groupware | `tests/test_gateway_integration.py` (F1 warning arm) | `"audit" in t.lower() and "FAILED" in t` | **No** — the re-worded warning still contains both; verified green against the new core. |

No exact-string assertion in the four broker suites' own (non-submodule)
tests is broken by the core render change: every pin listed above matches the
new text, which is a deliberate design constraint — the suite's own test
corpus was used as the containment check for the redesign.

## 9. Verification (this working tree, uncommitted)

Command shape: per-file, each file in its own process with a hard timeout,
repo venv (`accessBrokerCore/.venv/bin/python`), `-m "not integration"`.
Baseline (before) and after, both runs:

| File | Before | After |
|---|---|---|
| tests/test_audit.py | 54 passed | 54 passed |
| tests/test_auth.py | 8 passed | 8 passed |
| tests/test_baselines.py | 23 passed | 23 passed |
| tests/test_baselines_coverage.py | 45 passed | 45 passed |
| tests/test_custody.py | 15 passed | 15 passed |
| tests/test_gateway_factory.py | 20 passed | 20 passed |
| tests/test_gateway_integration.py | 23 passed | 23 passed |
| tests/test_gateway_logic.py | 46 passed | 73 passed |
| tests/test_grants.py | 74 passed | 74 passed |
| tests/test_http_oauth_coverage.py | 13 passed | 13 passed |
| tests/test_policy.py | 156 passed | 156 passed |
| tests/test_policy_core_coverage.py | 10 passed | 10 passed |
| tests/test_static_auth.py | 11 passed | 11 passed |
| tests/test_vocabulary.py | 4 passed | 4 passed |

0 skipped in every file (the groupware sibling checkout resolves on this
machine, so the parity batteries ran). `ruff check .` → All checks passed.
Coverage of the changed module (`--cov=access_broker_core.gateways.logic
--cov-branch`, three gateway batteries): **100%** (348 statements, 120
branches, 0 missing) — the note's only new test-visible behaviour.
`--cov-fail-under=100` is satisfied.

New tests (all in `tests/test_gateway_logic.py`): icon-uniqueness, request
header vs pre-placed controls, one numbered item line per item, the
justification isolation invariant (request and decision), single item-line
helper, item count singular/plural, no-repeated-instruction, verb icons,
lifecycle format + unknown state + swallowed failure + no-transport no-op,
status block/empty/active-items, posted-summary icon, sweep notice, undo-closed
notice, refusal + unknown-command + help icons, revoke-all format, audit-failure
warning, every-outbound-type-opens-with-an-icon sweep, shared-room tagging of
every outbound type, shared-room header pattern, unprefixed refusal floor,
solo-room untagged, render purity, no markdown tables.

## 10. Owner test checklist (negative cases included)

1. Solo room: post a request — no `[tag]`, item lines one per item, the
   justification on its own labelled line, `⏳` header.
2. Shared room with 2 brokers: both post; every message opens with its
   `[prefix]`; an unprefixed `approve 1` is refused with the hint and decides
   nothing; `otherbroker approve 1` produces silence.
3. Approve by 👍 and by `approve N 8h`: confirmation opens with 👍 and shows
   the resulting expiry; status block follows.
4. Reject by 👎, then `undo N` inside 15 s (re-created as a new number) and
   after 15 s (⌛ closed notice, no new request).
5. `revoke all` with grants and with none (🛇 summary with the no-undo note /
   ❌ nothing to revoke); confirm no undo is possible afterwards.
6. `approve 99` → human refusal text, no Python enum; `aproove 3` → ❓ closest;
   `frobnicate` → 📖 help card.
7. Leave a request unanswered past 12 h → exactly one ⏱️ notice, and only one
   even after further sweeps.
8. Force an audit write failure on approve → ⚠️ NOT-confirmed warning naming
   the recovery `revoke N`; the grant is still active in the store.
9. Element X: render a request and a status block — bold and inline code
   render, no table, no literal backticks.
10. Negative: a hostile justification that contains a fake item line,
    `approve 1`, or a fake `**PENDING #99**` header must appear only on the
    labelled justification line, and the header must still name the real id.

## 11. Not yet decided / not yet verified

- The `🛇` vs `⛔` glyph question (§7.1) — owner call.
- Whether the groupware broker's own `groupware_broker/gateways/logic.py`
  copy is retired in favour of the core or given the same format pass (§8).
- Account-in-code-font styling (§7.5) — owner taste.
- No live-room render was executed (dev tree only; no deploy, no publish).
