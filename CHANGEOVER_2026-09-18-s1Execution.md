# CHANGEOVER — 2026-09-18 — Stage 1 executed (access-broker-core founded)

Author: Hermes Agent (research profile) for Nasser Mohieddin Abukhdeir.
Stage: S1 per the goal contract
(reports/accessBrokerCoreGoalContract.pdf), executed in full with NO
owner testing (owner instruction: testing deferred to end of line).

## Outcome (one paragraph)

access-broker-core is founded, extracted, and proven. Stages 1a-1f
complete; 1g attempted and amended (a migration, not an extraction —
evidence in MIGRATION_NOTES.md); 1h founding release recorded in
CHANGELOG. The core: policy mechanics behind a PolicyRegistry seam,
GrantStore, hash-chained audit with F1 decision semantics, gateway
decision core + adapter-registry factory, RFC 9728/8707 auth. Verified
by porting: groupware's complete 633-test suite passes against the core
with zero behavior change; the core's own batteries at 100% statement+
branch coverage (405 tests). Repos: accessBrokerCore/ (new, 6 commits),
groupwareAccessBroker/ (1 commit: consumes the core via editable path
dependency). GitHub publication is the owner's separate task, unchanged.

## State of record

- accessBrokerCore/: git, 6 commits, clean tree. Verification:
  `uv run pytest -q` (405) and `uv run pytest -q --cov=access_broker_core
  --cov-branch` (100% gate green), `uv run ruff check .`.
- groupwareAccessBroker/: commit 647048b, clean tree.
  `uv run pytest -q` (633/1 skipped), ruff clean, S6 conformance PASS
  (scratch servers Dovecot 10143 / Radicale 1523 UP at session end).
- Dependency direction: groupware -> core (editable path dep in
  pyproject + tool.uv.sources). Core has ZERO groupware imports at
  runtime (its batteries use sys.path test shims only).

## Seam decisions (recorded in code comments + contract amendments)

1. PolicyRegistry: operation table + backend set + normalizer registered
   at boot; refuse-to-start validation; enum coercion to the core's
   OperationClass at construction (the 1f seam defect).
2. Normalizer exceptions: the seam contract is the deny Reason VALUE,
   not exception identity; alien exceptions deny fail-closed.
3. Gateway factory: adapters are per-broker, registered via
   register_adapter(name, builder); the core factory keeps env
   resolution, approver extraction, one-gateway rule, transport rebind.
4. Grants API: registry is a constructor parameter; partial-item
   approval remains v2 (nextcloud's item_numbers is the older generation).

## S1g amendment (the honest finding)

nextcloud-access-broker cannot port behavior-preservingly: its audit is
the format-parent (instance/path fields, str clock; different chain
hashes on disk) and its grants.py is the older API generation
(create_request, item_numbers approval). Porting = production migration
of a deployed Gate 7 system. Deferred with evidence to
MIGRATION_NOTES.md; the cost belongs in the Stage 4 data-broker
supersession decision. The goal contract's 1g is amended by this record.

## Owner's deferred testing (end of line, unchanged)

1. Groupware manual testing per TEST_CASES.md (now exercising the core
   through the registry seam — nothing observable changed).
2. Weekend S0 remainder: Gate 7 close-out → rotation → rebuild →
   Gate 8 → v0.1.0; publication after rotation, history verified.

## Next stages

- Stage 2 (smart home broker): builds on core 0.1.0; design doc already
  ruled. The HA wall registers its entity/class semantics via
  PolicyRegistry — the seam the comms and data brokers will reuse.
- Stage 4 (data broker): nextcloud migration decision lives here.
