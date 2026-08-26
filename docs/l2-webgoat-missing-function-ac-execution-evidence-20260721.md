# WebGoat Missing Function Access Control Execution Evidence

## Field

`l2.webgoat-missing-function-ac.execution-contract`

This field binds one preregistered WebGoat access-control scenario to a raw-free
positive and negative Docker replay pair. It is not a scanner-accuracy result
and does not change the L2 or release decision.

## Bound Scenario

| Item | Value |
| --- | --- |
| App | `webgoat` |
| Source commit | `5142935bf7c279882c3b0fc0ecec42c447de6fd5` |
| Source selector | `AccessControlIntegrationTest#testLesson` |
| Scenario ID | `webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:fbfda4592bc795b9` |
| Positive receipt SHA-256 | `ef6ebea1b3db517f1d2f5823439d4b164febc44a2552c6fe2baf5b758f71d8cd` |
| Negative receipt SHA-256 | `ef4db0a19a190d0dd17e35e1f8f128a47abe3acf7504e9bb63852b6354a5430b` |
| Evidence SHA-256 | `c7f21fcb7218a9b343f05944ded38ee3d1f3bd00da4675b51f206ef5dd172215` |

The source receipt used by this field is the current canonical materialization
receipt. Its `git_porcelain_clean` value is informational; the source identity
is also bound by the locked semantic receipt hash, commit tree, and scanner
visible tree hash.

## Dynamic Result

The positive replay ran the exact integration test twice. Both runs passed with
the same normalized result. The negative replay changed only the copied source
variant so that a client-supplied admin flag is not persisted. Both negative
runs failed the same expected test case. Each run used a no-network, read-only,
non-root container with bounded resources and owned-volume cleanup. The copied
source variant did not mutate the authoritative checkout.

The evidence contains result and report hashes only. It contains no response
body, test output, credentials, or full source payload.

## Reproduce

```powershell
python scripts/replay_l2_webgoat_missing_function_ac.py verify `
  --receipt <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-execution-contract-20260721-r2\receipt.json

python scripts/replay_l2_webgoat_missing_function_ac.py verify-negative-control `
  --receipt <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-negative-control-20260721-r2\receipt.json `
  --positive-receipt <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-execution-contract-20260721-r2\receipt.json

python scripts/derive_l2_webgoat_missing_function_ac_execution_evidence.py validate `
  --evidence <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-execution-evidence-20260721-r3\evidence.json
```

## Claim Boundary

Proven by this field:

- The source-bound process pair is reproducible twice per side.
- The minimum copied-source control distinguishes the upstream test result.
- Per-run and image cleanup completed.

Not proven by this field:

- A complete upstream remediation or a complete access-control model.
- CWE or CVSS classification.
- K-Guard scanner precision, recall, TP, FP, FN, or TN.
- Registry admission, L2 gate success, or release approval.
