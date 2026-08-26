# WebGoat Missing Function Access Control CWE Evidence

## Field

l2.webgoat-missing-function-ac.source-bound-cwe-mechanism-evidence

This field derives raw-free, source-bound classification evidence for one
pinned WebGoat access-control scenario. It does not evaluate K-Guard's
detectors or promote a release gate.

## Bound Scenario

| Item | Value |
| --- | --- |
| App | webgoat |
| Source commit | 5142935bf7c279882c3b0fc0ecec42c447de6fd5 |
| Test selector | AccessControlIntegrationTest#testLesson |
| Mechanism | Client-supplied admin privilege is persisted, then accepted by the privileged endpoint |
| CWE mapping | CWE-266 Incorrect Privilege Assignment |
| Scenario ID | webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:fbfda4592bc795b9 |
| Evidence SHA-256 | b1ea12427937ac29ccf9b3d64b2953d06c17d1c86a001015802161598cc1edf4 |

CWE-266 is the mapping used because the pinned scenario assigns a privileged
role from client-controlled user data. It is a mapping-permitted Base CWE, not
the broader CWE-269 privilege-management category.

## Evidence Contract

The adapter verifies the pinned source receipt, its semantic identity, both
exact Git blobs, and the source anchors below:

- The integration test selects MissingFunctionAC, submits an admin value,
  creates the user, and requests the privileged endpoint.
- The implementation receives a client-controlled User, saves it, and later
  uses the persisted admin role for the privileged endpoint.

The artifact records paths, hashes, anchor identifiers, and classification
identifiers only. It contains no source body, test output, response body,
credential, or model response.

Two independent derivations from the same source root produced byte-identical
canonical evidence:

| Run | SHA-256 | Status |
| --- | --- | --- |
| r1 | b1ea12427937ac29ccf9b3d64b2953d06c17d1c86a001015802161598cc1edf4 | CWE_MECHANISM_EVIDENCE_PASS |
| r2 | b1ea12427937ac29ccf9b3d64b2953d06c17d1c86a001015802161598cc1edf4 | CWE_MECHANISM_EVIDENCE_PASS |

## Reproduce

~~~powershell
python scripts/derive_l2_webgoat_missing_function_ac_cwe_evidence.py validate --evidence <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-cwe-evidence-20260721-r1\evidence.json
~~~

## Claim Boundary

Proven by this field:

- One pinned benchmark scenario has a source-bound CWE-266 mechanism
  classification.
- The classification is deterministic for the bound source receipt.

Not proven by this field:

- A customer deployment's severity or impact.
- CVSS, expected disposition, scanner detection, or actionability.
- TP, FP, FN, TN, registry admission, L2 completion, H100, or product release.
