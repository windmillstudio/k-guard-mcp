# L2 WebGoat IDOR Scanner Mapping Evidence

Date: 2026-07-21

## Scope

This packet fixes one narrow L2 subfield: a source-bound WebGoat IDOR execution
pair can now be connected to one deterministic K-Guard static observation. It
does not admit a TP, FP, FN, CWE, CVSS severity, release decision, or a general
Java authorization claim.

The target is the pinned upstream WebGoat source:

- repository: `webgoat/webgoat`
- commit: `5142935bf7c279882c3b0fc0ecec42c447de6fd5`
- source receipt SHA-256:
  `7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b`

The joined execution artifacts are the previously verified positive and
negative-control receipts:

- positive execution receipt SHA-256:
  `3d1e162931ec875f1b9de8564ff08733677e7125347eb559c91318c67e86a874`
- negative-control receipt SHA-256:
  `baee6c365c87526a5a7b00717c14616e7497eb55f804a9a0fdf9fe36160bddaa`

## Implementation

[polyglot.py](../src/k_guard_mcp/detectors/polyglot.py) now has a narrow
Spring/JVM observer for a route that simultaneously has all of these signals:

1. A mutating Spring route with a path-variable target and a request body.
2. A request-body identity explicitly differs from an authentication identity.
3. The route persists the cross-account change.
4. No visible delegated-role or ownership policy is present.

The observer emits `API_IDOR_ROUTE_PARAM_LOOKUP` as `high` / `medium` with
subtype `java_spring_cross_account_write_observe`. Medium confidence keeps it
in the existing manual-review hold lane; it is not an automatic release-block
rule.

The same change repairs the shared Java/Kotlin brace matcher so quotes and
braces inside `//` or `/* ... */` comments cannot make it skip a real method.
This was the reason the original WebGoat source was silently missed.

[observe_l2_webgoat_idor_scanner.py](../scripts/observe_l2_webgoat_idor_scanner.py)
re-verifies the complete source checkout, validates both execution receipts,
binds the integration-test PUT route to the Spring implementation route, scans
the implementation twice, and emits only hashes, line numbers, rule metadata,
and normalized result projections. It pins the source identity, execution
receipt identities, route locations, target finding line, and redacted line
fingerprint. It refuses a changed or partial PASS.

## Live Result

Two fresh observer executions produced byte-identical canonical receipts:

| Run | Receipt path | SHA-256 | Status |
| --- | --- | --- | --- |
| r3 | `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-idor-scanner-mapping-20260721-r3\receipt.json` | `0cbfd99d8e1ac3f95874aca03d3c52037c99ee94b5b76e2234395897a5d9edc1` | `SCANNER_MAPPING_PASS` |
| r4 | `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-idor-scanner-mapping-20260721-r4\receipt.json` | `0cbfd99d8e1ac3f95874aca03d3c52037c99ee94b5b76e2234395897a5d9edc1` | `SCANNER_MAPPING_PASS` |

Each receipt contains two equal in-process observations. The mapped finding is
one `API_IDOR_ROUTE_PARAM_LOOKUP` candidate at implementation line 53, with
the redacted fingerprint `03baf357e91b1c5d`. No source text, HTTP body,
credential, or raw tool output is retained in the receipt.

Focused regression was repeated on the unchanged candidate:

```text
python -m pytest -q tests/test_observe_l2_webgoat_idor_scanner.py tests/test_public_app_regressions.py tests/test_replay_l2_webgoat_idor.py tests/test_materialize_l2_oracles.py tests/test_supervisor_reviews.py
117 passed

same command repeated: 117 passed
```

Full repository regression on the same candidate:

```text
python -m pytest -q
2196 passed, 5 skipped in 788.19s
```

The five skips are pre-existing configured or platform-scoped checks. They do
not skip this observer, the Java detector, L2 oracle materialization, or the
supervisor receipt validator.

## Machine-Enforced Boundary

The observer receipt has these facts and no broader ones:

- `source_bound_scanner_mapping_proven=true`
- `scanner_accuracy_proven=false`
- `severity_or_cwe_admitted=false`
- `tp_fp_fn_admitted=false`
- `release_gate_admitted=false`

The remaining mandatory blockers are:

- `evidence_signature_missing`
- `independent_upstream_fixed_revision_missing`
- `source_bound_severity_rubric_missing`

The base six-app L2 registry therefore remains at zero admitted scenarios and
overall L2 remains `HOLD`. This mapping is evidence for the next admission
subgates, not a way around them.
