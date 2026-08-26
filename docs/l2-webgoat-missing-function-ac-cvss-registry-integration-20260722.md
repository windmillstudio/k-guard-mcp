# WebGoat Missing Function Access Control CVSS Registry Integration

Date: 2026-07-22

## Field

`l2.webgoat-missing-function-ac.cvss-registry-integration`

## Narrow Claim

One pinned WebGoat Missing Function Access Control scenario can receive a
source-bound, benchmark-only CVSS v4 profile after a separate adapter
re-derives the profile from the exact execution evidence, CWE evidence, and
pinned FIRST CVSS v4 calculator source.

The profile is deliberately limited to the benchmark scenario:

- vector: `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`
- score and severity: `7.1`, `high`
- expected disposition: `warn`

`PR:L` is required because the upstream integration test supplies an
authenticated session cookie. The profile does not claim unauthenticated
access, customer-environment impact, or a subsequent-system impact.

The registry re-derives and validates the exact CVSS artifact, checks current
adapter and materializer hashes, verifies the child-evidence hashes and source
selector, binds the pinned calculator receipt, and attaches the result to only
the `AccessControlIntegrationTest` candidate. The CVSS artifact cannot
self-admit a scenario, L2, scanner accuracy, TP/FP/FN, or release readiness.

## Dynamic Evidence

The CVSS adapter generated canonical raw-free evidence twice from the same
bound inputs. Both artifacts have SHA-256:

`68ad72dd5484f36cad2ee7124a9ee3be9d65208a29d3a07f7bf39fee46211aca`

Because the registry contract changed, the state-reset proof was also
re-derived twice against the current materializer. Both artifacts have
SHA-256:

`0b37227fa5c83ccd099219f7e64a3424bc6b276777072e86f9bc69954791dc9b`

The full six-source registry was materialized twice with all four Missing
Function AC evidence types. Both registry files have SHA-256:

`b6cb0b6dc070c368cae8569d98ea3344d4c69a98810d48f04e5376ec27313419`

Both runs returned exit `2`: the registry contract was valid and the phase-2
L2 gate remained `HOLD`, not a release pass.

The one bound candidate is:

`webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:fbfda4592bc795b9`

It now has a positive execution result, negative control, CWE-266 mechanism,
CVSS profile, expected disposition, and state-reset proof. Its `deficits` are
empty and its candidate admission is `PASS`.

This does not change the overall result:

- retained candidates: `414`
- admitted high/critical scenarios: `1`
- candidates without a complete oracle: `413`
- phase-2 L2 status: `HOLD`
- release gate: `false`

## Reproduce

```powershell
python scripts/derive_l2_webgoat_missing_function_ac_cvss_evidence.py derive `
  --cwe-evidence <missing-function-cwe-evidence> `
  --execution-evidence <missing-function-execution-evidence> `
  --calculator-root <pinned-first-calculator-root> `
  --calculator-receipt <pinned-first-calculator-receipt> `
  --output <new-cvss-evidence.json>

python scripts/materialize_l2_oracles.py materialize `
  --sources-root <six-pinned-source-root> `
  --calculator-root <pinned-first-calculator-root> `
  --calculator-receipt <pinned-first-calculator-receipt> `
  --source-admission <locked-source-admission> `
  --source-receipts-dir <verified-source-receipts> `
  --missing-function-ac-execution-evidence <execution-evidence> `
  --missing-function-ac-cwe-evidence <cwe-evidence> `
  --missing-function-ac-cvss-evidence <cvss-evidence> `
  --missing-function-ac-state-reset-evidence <state-reset-evidence> `
  --missing-function-ac-state-reset-positive-receipt <positive-receipt> `
  --missing-function-ac-state-reset-negative-receipt <negative-receipt> `
  --output <new-registry.json>
```

Any omitted bound input, changed child hash, mismatched selector, changed
calculator binding, stale adapter, or stale materializer hash fails closed.

## Nonclaims

This field does not establish a production severity for customer code, a
complete access-control model, scanner TP/FP/FN/TN, H100 completion, L2
completion, automated blocking, or release readiness. The one source-bound
scenario is not a scorecard achievement until its separately defined
measurement gates are met.
