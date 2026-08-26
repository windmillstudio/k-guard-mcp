# WebGoat IDOR Execution Evidence Registry Integration

Date: 2026-07-21

## Scope

This field connects one previously validated, raw-free WebGoat IDOR execution
pair to exactly one retained L2 registry candidate. It is deliberately a
narrow evidence-integration field, not an L2 completion or release field.

The registry accepts an attachment only when the canonical execution evidence,
the adapter and replay-tool provenance, the WebGoat source receipt, the pinned
selector, source content digest, and source-root-cause identity all agree.
The positive and negative process outcomes must have different normalized
result hashes. The attachment is rejected if it cannot be supplied again when
the registry is validated.

## Bound Candidate and Retained Deficits

The only attached candidate is the upstream WebGoat integration test:

- repository: `webgoat/webgoat` at
  `5142935bf7c279882c3b0fc0ecec42c447de6fd5`;
- scenario id:
  `webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:2da84111e81ac5d4`;
- root-cause identity:
  `2da84111e81ac5d492a9932982dde73fc513c8a0b14ed53abd3aa8cb95bc0166`;
- source: `IDORIntegrationTest.java`, line `28`, content digest
  `bcf5db68da5b1574a4710a2cb087a4907ece95e4688310ef7213c957d2ddf6a9`.

Only this candidate receives a `process` oracle with expected exit `0` and a
`process` negative control with expected exit `1`. HTTP fields remain null;
there is no shell interpolation. The positive normalized result digest is
`148c53f8f020ff6213746b781b2f0ee3f842e0f10cef43f51cb392155a44c655` and
the negative-control digest is
`e07e779759f7c27da53419d8a78b852c26730cd7609c45ef682dca7cec102c69`.

The candidate remains `HOLD`. It still has no source-bound CWE, CVSS v4
severity, expected disposition, mechanism truth, or registry `state_reset`
command. Pair cleanup is not treated as registry state-reset admission, and
`registry_state_reset_admitted` remains `false`.

## Dynamic Evidence

The actual registry was materialized twice from the pinned six-source corpus,
calculator receipt, source admission, source receipts, and execution-evidence
record. Both runs intentionally returned exit `2` and `HOLD`, because the L2
registry remains incomplete. The CLI report makes this distinction explicit:
`registry_contract_valid=true` means structural validation completed, while
`exit_contract=0=phase_2_l2_pass;2=validated_hold_not_release` means that
exit `2` is a valid but non-promoting qualification result, not an input error.
Their output SHA-256 values are identical:

| Run | Registry SHA-256 | Status | Exit |
| --- | --- | --- | --- |
| r3 | `4af5638fa9b793524a0b93f41dcb07f1df3137229984822b2a79f544e6d568cb` | `HOLD` | `2` |
| r4 | `4af5638fa9b793524a0b93f41dcb07f1df3137229984822b2a79f544e6d568cb` | `HOLD` | `2` |

Validation with the same execution-evidence input also returned
`registry_contract_valid=true`, `HOLD`, and exit `2`. Validation without the
execution-evidence input returned exit `1` before it could emit a valid
registry report; the attached registry is therefore not silently reproducible
from a weaker input set.

Across all 414 retained candidates, the attached pair reduces exactly one
missing positive-oracle count and one missing negative-control count. No
candidate is admitted, no severity is inferred, no scanner output is claimed,
and the release gate remains false.

## Tests

The focused suite was run twice with no skips:

```text
python -m pytest -q tests/test_replay_l2_webgoat_idor.py tests/test_derive_l2_webgoat_idor_execution_evidence.py tests/test_materialize_l2_oracles.py tests/test_supervisor_reviews.py
```

Each run reported `82 passed`.

The final full regression on the same review target reported:

```text
python -m pytest -q
2213 passed, 5 skipped
```

The focused tests cover exact one-candidate attachment, selector ambiguity,
self-admitted state-reset rejection, missing-input revalidation rejection,
adapter/replay provenance mismatch rejection, and the CLI distinction between
a structurally valid `HOLD` result and an invalid-input error.

## Nonclaims

This field does not establish scanner accuracy, TP/FP/FN/TN, CWE or CVSS
truth, an upstream fixed revision, registry scenario admission, L2 completion,
product performance, or release approval. The full L2 registry and product
release remain `HOLD` until their independent qualification gates are met.
