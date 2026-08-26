# WebGoat IDOR CVSS Registry Integration

Date: 2026-07-21

## Field

`l2.webgoat-idor.cvss-evidence-registry-integration`

## Narrow Claim Candidate

One raw-free, source-bound WebGoat IDOR CVSS v4 benchmark profile can be
re-derived from its exact CWE and execution evidence inputs and attached to
exactly one retained L2 registry candidate. The attachment supplies
`CWE-639`, mechanism truth `present`, score `7.1`, severity `high`, and
expected disposition `warn` only for the pinned benchmark scenario.

It does not admit the scenario. The candidate retains
`state_reset_missing`, remains `HOLD`, and cannot create an L2 pass, a
scanner-accuracy result, a TP/FP/FN measurement, or a release decision.

## Source Receipt Portability Contract

The L2 source identity remains pinned to each preregistered repository,
commit, commit tree, source-tree digest, license binding, and raw receipt
reference. Every supplied checkout is re-verified against raw Git blobs,
the index tree, and strict Git fsck before candidate extraction.

The registry accepts either the exact preregistered raw receipt or a receipt
whose canonical semantic fingerprint differs only by
`git_porcelain_clean`. That flag is recorded as informational because its
value can change across valid Windows Git checkout environments. The
registry emits the preregistered receipt hash, observed receipt hash,
semantic fingerprint, and equivalence mode. No other receipt field is
excluded from the fingerprint, and the current verifier must still reproduce
the supplied receipt exactly.

## Dynamic Evidence

Two CVSS derivations produced the same canonical evidence SHA-256:

`3e35367092f45b014aea4283a99031cdef0cfabeb1b85d737928c28e90b6ac87`

Two full registry materializations over the six pinned public source trees
also produced the same registry SHA-256:

`3caf64e7195e577d9fa44a633c412ef07a84fb4f7d1db91b6fa9479a9981ed9b`

Both materialization and validation intentionally returned exit `2`:
`registry_contract_valid=true`, `phase_2_l2_status=HOLD`, and
`release_gate_passed=false`. The registry extracted 414 retained candidates.
All six source receipts were blob-exact; three matched their historical raw
receipt byte-for-byte and three used the explicitly recorded porcelain-only
equivalence path.

The attached WebGoat scenario is:

`webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:2da84111e81ac5d4`

Its retained deficit list is exactly `state_reset_missing`. The CVSS source
is `source_bound_benchmark_profile`; it is not an inferred production
severity.

## Test Attestation

The focused source, registry, CVSS, CWE, and execution evidence suite
reported `88 passed` in 112.17 seconds. It covers exact receipt acceptance,
porcelain-only variance acceptance, non-porcelain fingerprint rejection,
raw source mutation detection, exact one-candidate attachment, input-chain
revalidation, and conflict rejection when a candidate already has a different
CWE or CVSS classification.

## Required External Decision

Claude Opus reviews the focused source files read-only. Grok 4.5 and Cline
GLM 5.2 receive the sanitized review packet. This field remains `HOLD` until
all three issue compatible `GO` receipts for one target and the local receipt
validator produces `FIX`.

## Remaining Blockers

- Registry state-reset evidence is still absent for the attached candidate.
- The other 413 retained candidates remain incomplete.
- This integration does not establish real-app recall, precision, or release
  readiness.
