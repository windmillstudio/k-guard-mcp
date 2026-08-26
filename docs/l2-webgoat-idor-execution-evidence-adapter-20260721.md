# WebGoat IDOR Execution Evidence Adapter

Date: 2026-07-21

## Scope

This field turns one already validated WebGoat IDOR positive/negative execution
pair into a canonical, raw-free process-evidence record. It does not integrate
the record into the L2 registry yet.

The adapter accepts only these immutable inputs:

- one canonical raw-blob WebGoat source receipt;
- one canonical positive execution receipt with two equivalent successful runs;
- one canonical generated negative-control receipt with two equivalent rejected
  runs;
- the exact pinned source identity, integration-test selector, and normalized
  result hashes.

It fails closed when any receipt changes, source provenance changes, an
execution run or cleanup proof is incomplete, the negative control mutates the
source checkout, or the positive and negative result hashes are equal.

## Process Contract

The output contains an `oracle` and a `negative_control` in the L2 v3
`process` command shape. Both have null HTTP fields and an exact normalized
result hash. The positive process expects exit `0`; the generated negative
control expects exit `1`. The complete Maven integration command is carried
without shell interpolation.

The record binds the source selector to:

- `webgoat/webgoat` commit
  `5142935bf7c279882c3b0fc0ecec42c447de6fd5`;
- `IDORIntegrationTest.java`, line `28`, and its source content digest;
- source receipt
  `7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b`.

The source receipt is pinned and structurally checked here. Recomputing it
from a pristine WebGoat checkout remains the source-materialization field's
responsibility; this adapter does not claim an independent re-materialization.

## Dynamic Result

The adapter was run twice over the same canonical positive and generated
negative-control receipts. Both outputs were byte-identical:

| Run | Evidence SHA-256 | Status |
| --- | --- | --- |
| r1 | `38a4468071f51f0408bbe08713068522f86645de7f1988b66f07c9f92226bb4e` | `EXECUTION_EVIDENCE_PASS` |
| r2 | `38a4468071f51f0408bbe08713068522f86645de7f1988b66f07c9f92226bb4e` | `EXECUTION_EVIDENCE_PASS` |

The positive normalized result digest is
`148c53f8f020ff6213746b781b2f0ee3f842e0f10cef43f51cb392155a44c655`.
The negative-control digest is
`e07e779759f7c27da53419d8a78b852c26730cd7609c45ef682dca7cec102c69`.
They are distinct. Each side has two equivalent normalized runs, passed
per-run cleanup, passed image cleanup, and the negative control reports that
the source checkout was not mutated.

`state_reset_evidence_proven` means that cleanup evidence exists for this
execution pair only. It deliberately does not mark the L2 registry's
`state_reset` command as admitted.

## Tests

`tests/test_derive_l2_webgoat_idor_execution_evidence.py` covers canonical
derivation, source selector binding, source receipt tampering, distinct
positive/negative result requirements, source-checkout mutation, immutable
selector verification, raw-free output, and no-overwrite output creation.

The related focused suite passed twice with `76 passed` and no skips:

```text
python -m pytest -q tests/test_replay_l2_webgoat_idor.py tests/test_derive_l2_webgoat_idor_execution_evidence.py tests/test_materialize_l2_oracles.py tests/test_supervisor_reviews.py
```

On the same final review target, the full suite passed with `2207 passed, 5
skipped`:

```text
python -m pytest -q
```

## Nonclaims

This field proves neither an independently fixed upstream revision nor scanner
accuracy. It does not assign CWE/CVSS, label TP/FP/FN/TN, admit a registry
scenario, prove L2 completion, or grant product or release approval. The
control is a generated pair, not an upstream fixed revision. L2 and product
release remain `HOLD` until registry evidence integration, a source-bound
severity rubric, signing/provenance, and the remaining qualification gates are
complete.
