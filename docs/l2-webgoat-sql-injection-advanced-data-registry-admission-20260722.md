# WebGoat SQL Injection Advanced Data-Plane Registry Admission

## Scope

This record admits exactly one source-bound WebGoat SQL Injection Advanced
benchmark scenario to the L2 oracle registry. It is a data-plane evidence
attachment, not a claim that K-Guard detects SQL injection in arbitrary
applications.

The admitted selector is:

- Repository: `webgoat/webgoat`
- Commit: `5142935bf7c279882c3b0fc0ecec42c447de6fd5`
- Test: `SqlInjectionAdvancedIntegrationTest#runTests`
- Scenario: `webgoat:upstream-test-org-owasp-webgoat-integration-sqlinjectionadvancedintegrationtest-runtests:d89982fbf77e5530`
- CWE: `CWE-89`
- Pinned benchmark profile: `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`, 7.1/high/warn

## Evidence Contract

The attachment requires all six bound inputs. Missing any one of them is a
hard error rather than a partial admission:

1. Source-bound positive execution evidence.
2. Source-bound CWE mechanism evidence.
3. Source-bound CVSS profile evidence using the pinned FIRST CVSS v4 calculator.
4. Source-bound state-reset evidence.
5. Positive replay receipt.
6. Negative-control replay receipt.

The source receipt distinguishes the observed raw receipt hash
`52ba9d0e5a85539790e9b68f82ad4d389847b4331354276e196af64367af7aaa`
from the source semantic fingerprint
`4b518fc464fcbc9eed993895c3aa628958828a3c8a6f6733e24739c84628dded`.
The registry accepts that known porcelain variance only through its explicit
semantic equivalence contract.

The negative control escapes the user-supplied SQL literal in a temporary
variant checkout. It must fail while the positive upstream scenario passes;
the checked source checkout is required to remain unchanged. Evidence records
hashes and normalized result facts only. Raw command output and response
bodies are not retained.

## Repetition Result

The SQL-only registry was materialized twice from the exact same inputs:

- `phase4-l2-webgoat-sql-injection-advanced-registry-20260722-r1`
- `phase4-l2-webgoat-sql-injection-advanced-registry-20260722-r2`

Both canonical registry files have SHA-256
`ae7d2c57e8678e18d9db27026fec85e7e0fa760cf4fe5eddd62790f601f82b3d`
and are byte-identical. The registry attaches one high-severity WebGoat
scenario and leaves the other 413 candidates HOLD. Its exit code is `2`, the
explicit validated-HOLD outcome, because the broader L2 inventory and release
requirements are not satisfied.

## Non-Claims

This admission does not establish scanner precision, recall, TP/FP/FN/TN,
production SQL injection coverage, Korean application performance, or release
readiness. It does not alter the product release gate: `release_gate_passed`
remains `false`.

The field becomes eligible for an internal FIX decision only after the focused
tests, repeated dynamic evidence, and independent Claude Opus, Grok, and GLM
reviews agree on this exact scope. A field FIX is still not product GO.
