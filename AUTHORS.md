# Authors and provenance

**Nasser Mohieddin Abukhdeir** — author and maintainer.
University of Waterloo, Chemical Engineering.

## Provenance (from birth, per the goal contract)

`access-broker-core` was founded in September 2026 by extracting the
shared security architecture from two prior works by the same author:

- `nextcloud-access-broker` (the reference implementation: grant
  lifecycle, hash-chained write-before-operate audit, the wall pattern)
- `groupware-access-broker` (the first generalization: transport-agnostic
  approval-gateway core, tier-first evaluation mechanics, RFC 9728/8707
  transport auth)

Both are GPL-3.0-or-later; this extraction is legitimate self-plagiarism
by the same author and is documented here and in CHANGELOG.md per the IP
hygiene commitments established in the groupware goal contract (section
5, 04_ipHygiene).

The extracted modules were designed and adversarially reviewed in their
source repositories (review records: groupware S1/S2/S3/S5 gates, the
2026-09-16 in-session adversarial review and its F1 finding, the
2026-09-18 boot-path regression suite). The core inherits that review
history by provenance.