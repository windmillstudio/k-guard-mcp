# L2 WebGoat IDOR Negative-Control Evidence

Date: 2026-07-21

## Scope

This packet records one narrow test-sensitivity contract. It proves that a
source-derived, deterministic control variant causes the selected upstream
IDOR integration test to produce its exact expected failing projection. It does
not admit a scanner finding, a severity, a CWE classification, TP/FP/FN
metrics, a production remediation, or a release decision.

The control is bound to the same WebGoat source and positive execution receipt
as the prior execution-only packet:

- repository: `webgoat/webgoat`
- commit: `5142935bf7c279882c3b0fc0ecec42c447de6fd5`
- source receipt SHA-256:
  `7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b`
- positive execution receipt SHA-256:
  `3d1e162931ec875f1b9de8564ff08733677e7125347eb559c91318c67e86a874`

## Contract

The runner is [replay_l2_webgoat_idor.py](../scripts/replay_l2_webgoat_idor.py)
with its `negative-control` subcommand. It performs these steps:

1. Canonically validates the positive execution receipt and re-verifies the
   source checkout through the raw Git-blob verifier.
2. Copies the verified checkout into a disposable build context. The original
   checkout is not patched.
3. Applies exactly two anchored changes to
   `IDOREditOtherProfile.java`: disable the vulnerable other-profile branch in
   the copied variant and explicitly reject the same unauthorized branch. The
   original file hash, patched file hash, patch hash, and variant-tree hash are
   recorded without returning source text.
4. Builds a separately labelled, source-derived image. Online Maven warmup is
   non-evidence; the locally resolved image ID is recorded and removed later.
5. Runs the same upstream `IDORIntegrationTest` twice in fresh, offline Docker
   containers with no host ports, read-only root, dropped capabilities,
   no-new-privileges, non-root user, bounded resources, hardened tmpfs, and
   separate cache/evidence volumes.
6. Requires the exact JUnit/Failsafe projection produced by this control:
   `testIDORLesson` failure, `testIDORLesson()[1]` pass,
   `testIDORLesson()[2]` failure; 3 completed tests, 2 failures, 0 errors,
   0 skips, and Maven exit code 1. The parent failure is the framework's
   dynamic-test reporting behavior and is explicitly required, not ignored.
7. Requires equality of the two normalized runs and removes all owned
   containers, volumes, and source-derived images. Any mismatch is HOLD.

The runner preserves only hashes, test identities, outcome classes, and count
projections. It does not retain raw Maven output, source content, classpaths,
or full report XML.

## Live Result

Evidence receipt:
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-idor-negative-control-20260721-r5\receipt.json`

- receipt SHA-256:
  `baee6c365c87526a5a7b00717c14616e7497eb55f804a9a0fdf9fe36160bddaa`
- runner SHA-256:
  `d9f52d4fca410fe4c27cd9c4e8aa0e9ea7e696e80df34f67f5b04ef69bd1ce29`
- patched variant tree SHA-256:
  `06027554fa9d1ba3eeb61850562ef77e670384163e077671e7ce976727d1f5b2`
- normalized two-run projection SHA-256:
  `6787dbc45386772cf31c0b9cce209cd426812438a367a038d91b01f54308d23f`
- two control runs: PASS, exact normalized equality
- per run: Maven exit 1 as expected; 3 completed, 2 failures, 0 errors,
  0 skips; named outcomes exactly match the contract
- isolation checks, owned-resource cleanup, and receipt verification: PASS
- release gate: false

The earlier `r1`, `r2`, and `r3` receipts are retained HOLD evidence. They
exposed an unreachable-code control patch and then the JUnit parent-case
reporting difference. The first passing r4 receipt is retained as well. r5
adds an exact pin to the positive r3 receipt SHA-256 and makes Docker inspect
errors fail cleanup rather than count as already removed.

Focused and full regression results for the r5 code revision:

```text
python -m pytest -q tests/test_replay_l2_webgoat_idor.py tests/test_materialize_l2_runtime.py tests/test_materialize_l2_oracles.py
137 passed in 46.46s

python -m pytest -q
2176 passed, 5 skipped in 728.16s
```

## Machine-Enforced Boundary

The receipt always keeps these blockers:

- `evidence_signature_missing`
- `independent_upstream_fixed_revision_missing`
- `scanner_finding_mapping_missing`
- `source_bound_severity_rubric_missing`

Its schema forces `independent_upstream_fixed_revision_proven=false`,
`scanner_accuracy_proven=false`, `severity_or_cwe_admitted=false`,
`tp_fp_fn_admitted=false`, and `release_gate_passed=false`.

This is therefore a fixed execution-sensitivity subfield only after external
review. It does not remove the static L2 registry's broader admission gaps.
