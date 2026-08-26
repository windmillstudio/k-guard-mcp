# L2 WebGoat IDOR Execution Contract Evidence

Date: 2026-07-21

## Scope

This packet records one narrow execution contract. It does not admit a scanner
finding, a severity, a CWE classification, TP/FP/FN metrics, or a release
decision.

The target is the upstream WebGoat integration test
`org.owasp.webgoat.integration.IDORIntegrationTest` from:

- repository: `webgoat/webgoat`
- commit: `5142935bf7c279882c3b0fc0ecec42c447de6fd5`
- commit tree: `6c45e60db0995416a5bbe5977657a78d5084dcf7`
- raw-blob source tree SHA-256:
  `0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c`

## Implementation

The runner is [replay_l2_webgoat_idor.py](../scripts/replay_l2_webgoat_idor.py).
It performs these steps:

1. Re-verifies the source checkout with the existing raw Git-blob verifier.
2. Builds a disposable source-derived image from the fixed Temurin 25 digest.
   Its online Maven warmup is explicitly non-evidence but becomes an immutable
   input through the locally resolved image ID.
3. Starts two fresh containers and two fresh cache volumes from that image.
4. Runs only the selected upstream integration test with Docker `network none`,
   read-only root filesystem, `cap-drop ALL`, `no-new-privileges`, a non-root
   user, bounded PID/memory/CPU, hardened tmpfs, and no host port publishing.
5. Copies the report into a dedicated owned evidence volume before container
   exit, then normalizes only the expected two dynamic case identities,
   Failsafe counts, and pass/fail state. Raw Maven output, classpaths,
   reports, and source content are not emitted.
6. Requires exact equality of the two normalized projections and removes the
   owned containers, volumes, and source-derived image. Any failure leaves the
   execution contract on HOLD.

Focused unit tests are in
[test_replay_l2_webgoat_idor.py](../tests/test_replay_l2_webgoat_idor.py).

## Live Result

Evidence receipt:
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-idor-execution-contract-20260721-r3\receipt.json`

- receipt SHA-256:
  `3d1e162931ec875f1b9de8564ff08733677e7125347eb559c91318c67e86a874`
- source-derived image ID:
  `sha256:7cde75ce2426f5187626a1333a1237df44f9734f0b13e4686b203dfe519ed917`
- source verifier SHA-256:
  `0197723df7c3da7833f1f541259f2d530fa95343ccda66508e5cb536ecff0f90`
- two offline runs: PASS
- normalized test result per run: 2 tests, 0 errors, 0 failures, 0 skipped
- normalized projections: exactly equal
- isolation checks: all true on both runs
- owned container, volume, and image cleanup: PASS
- receipt verification: PASS
- release gate: false

Focused regression result:

```text
python -m pytest -q tests/test_replay_l2_webgoat_idor.py tests/test_materialize_l2_runtime.py tests/test_materialize_l2_oracles.py
127 passed
```

Full regression result:

```text
python -m pytest -q
2166 passed, 5 skipped in 713.07s
```

## Machine-Enforced Boundary

The receipt has `execution_contract_status=EXECUTION_CONTRACT_PASS` only when
both normalized offline runs match. It always retains these blockers:

- `source_bound_severity_rubric_missing`
- `negative_control_missing`
- `scanner_finding_mapping_missing`
- `evidence_signature_missing`

The receipt schema forces `tp_fp_fn_admitted=false` and
`release_gate_passed=false`. It therefore proves only reproducible isolated
execution of the selected upstream test, not a product detection claim.

A separate source-derived negative-control receipt now tests whether this
upstream test reacts to a deterministic copied-source control variant. It does
not alter this r3 receipt's historical blockers or promote it to scanner
accuracy. See
[l2-webgoat-idor-negative-control-evidence-20260721.md](l2-webgoat-idor-negative-control-evidence-20260721.md).

## Review Request

Review the runner, its focused tests, and this evidence packet for false
claims, input/provenance gaps, isolation escapes, cleanup defects, and any
path by which this execution-only result could be promoted to TP/FP/FN or a
release gate. The acceptable dispositions are `GO_MEASUREMENT_PATCH`,
`HOLD`, or `BLOCKED`.
