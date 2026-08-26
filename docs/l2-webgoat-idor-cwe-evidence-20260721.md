# WebGoat IDOR Source-Bound CWE Evidence

Date: 2026-07-21

## Scope

This field derives a raw-free, source-bound benchmark classification for one
WebGoat IDOR scenario. It verifies two exact Git blobs at the pinned WebGoat
commit, then records a CWE-639 mapping and a present authorization-bypass
mechanism. It does not calculate CVSS or promote the registry, product, or
release.

The test blob proves the IDOR lesson, a cross-user profile read, requested
`userId,role` attributes, and a cross-user role mutation. The implementation
blob proves a user-controlled `userId` path variable, a cross-user key
condition, profile disclosure, and the teaching code's missing-horizontal-
authorization anchor. Both blobs are checked through `git show` at the pinned
commit and against the immutable source receipt.

`CWE-639` is used because MITRE defines it as authorization bypass through a
user-controlled key, including one user accessing another user's record by
changing an identifying key. The standard reference is
https://cwe.mitre.org/data/definitions/639.html.

## Dynamic Evidence

The adapter ran twice using the pinned WebGoat Git root and source receipt.
Both canonical outputs were byte-identical:

| Run | Evidence SHA-256 | Status |
| --- | --- | --- |
| r1 | `01f98199baf0680b96e36119a7ac1fa5756dec79293394825ab9723da1d7d7ee` | `CWE_MECHANISM_EVIDENCE_PASS` |
| r2 | `01f98199baf0680b96e36119a7ac1fa5756dec79293394825ab9723da1d7d7ee` | `CWE_MECHANISM_EVIDENCE_PASS` |

The result records `CWE-639` and `mechanism_truth=present`, but records
`cvss_v4=null`, `expected_disposition=null`,
`customer_deployment_severity_admitted=false`, and
`release_gate_passed=false`.

## Tests

The focused suite was run twice with no skips and reported `87 passed` each
time:

```text
python -m pytest -q tests/test_replay_l2_webgoat_idor.py tests/test_derive_l2_webgoat_idor_execution_evidence.py tests/test_derive_l2_webgoat_idor_cwe_evidence.py tests/test_materialize_l2_oracles.py tests/test_supervisor_reviews.py
```

An initial full-suite run had one pre-existing SCA process-runner timeout
failure. The isolated test then passed five consecutive times, and an idle
full-suite re-run passed with `2218 passed, 5 skipped`. This residual
instability is not used as product-performance evidence.

The adapter tests reject missing source anchors, missing implementation blob
bindings, forged CWE mapping, forged claim boundaries, and output overwrite.

## Nonclaims

This field does not assign a customer-deployment CVSS score, High/Critical
severity, expected release disposition, scanner finding, TP/FP/FN/TN label,
registry admission, L2 completion, performance metric, H100 result, or
product release approval. CVSS remains deferred until a separately
source-bound asset-impact profile is available.
