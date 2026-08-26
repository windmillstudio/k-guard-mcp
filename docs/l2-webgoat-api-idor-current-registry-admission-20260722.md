# WebGoat API IDOR Current Registry Admission

Date: 2026-07-22

## Field

`l2.webgoat.api-idor.current-registry-admission`

## Selection Rule

The current L2 registry has 414 retained candidates. Before this field, only
one site-plane scenario was admitted; API, data, and operations each had zero
admitted scenarios. The selected candidate is the one API-plane scenario that
already has a complete, independently source-bound execution, CWE, CVSS, and
state-reset input chain:

`webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:2da84111e81ac5d4`

This is not a volume-based choice. It is the first unrepresented macro-plane
with a complete machine-oracle input chain. Data and operations remain
unrepresented because no complete source-bound chain is available for either
plane yet.

## Narrow Claim

The current registry can re-derive and attach the complete API IDOR chain and
the previously admitted site Missing Function Access Control chain together.
Each chain admits exactly its own WebGoat candidate. The two attachments do
not cross-admit a candidate or make the aggregate L2 gate pass.

The field does not establish API-plane coverage, detector accuracy, TP/FP/FN,
runtime exploitability, H100 qualification, or product release readiness.

## Current Evidence Inputs

The API IDOR CVSS and state-reset adapters were re-derived twice against the
current registry source. Their canonical hashes are identical across repeats.

| Evidence | r1 SHA-256 | r2 SHA-256 |
| --- | --- | --- |
| IDOR CVSS v4 benchmark profile | `6b3b814eb95ec003a6769a0efe2055a8b9d2f5350ee10a412e3030877571cfee` | `6b3b814eb95ec003a6769a0efe2055a8b9d2f5350ee10a412e3030877571cfee` |
| IDOR state-reset evidence | `6e7fe2a3496fb62c96548189c0ecdcb23842e5aa2e98d6fc284f894bd253e876` | `6e7fe2a3496fb62c96548189c0ecdcb23842e5aa2e98d6fc284f894bd253e876` |

The source-bound IDOR execution and CWE evidence, the two cleanup receipts,
and the current site Missing Function Access Control evidence are supplied to
both registry runs. All source receipts remain blob-exact.

## Dynamic Result

Two independent materializations produced the same canonical registry:

| Run | Registry SHA-256 | Candidate count | Admitted scenarios | Exit |
| --- | --- | ---: | ---: | ---: |
| r1 | `7933feb424141650d8681ced3293ec3331f2657c48034308f5d4b4e53c3f9b0b` | 414 | 2 | 2 |
| r2 | `7933feb424141650d8681ced3293ec3331f2657c48034308f5d4b4e53c3f9b0b` | 414 | 2 | 2 |

The two admitted scenarios are `webgoat:site` Missing Function Access Control
and `webgoat:api` IDOR. Each explicit revalidation also returned exit `2` with
`registry_contract_valid=true`, `phase_2_l2_status=HOLD`, and
`release_gate_passed=false`. Exit `2` is the documented valid-HOLD result, not
an input error.

The registry still has 412 candidates without a complete oracle. It also has
zero Critical scenarios, does not represent all six applications, and does not
meet any L2 or release count threshold.

## Regression Contract

`tests/test_materialize_l2_oracles.py` now exercises both complete chains in
the same materialization. It asserts that exactly the two separately selected
candidates pass, that both scenario IDs are retained, that the summary reports
two admitted High/Critical scenarios, and that validation requires every input
from both chains.

Focused result:

```text
1 passed, 63 deselected
```

Registry suite result:

```text
64 passed
```

## Required Supervisor Decision

Claude Opus 4.8 reviews the changed test and this contract as direct files.
Grok 4.5 and Cline GLM-5.2 review the same sanitized evidence packet. A FIX
receipt can approve only this current-registry coexistence field. It cannot
promote either detector or alter the overall L2/release HOLD boundary.
