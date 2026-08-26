# WebGoat Missing Function Access Control State-Reset Registry Integration

Date: 2026-07-22

## Field

`l2.webgoat-missing-function-ac.state-reset-registry-integration`

## Narrow Claim Candidate

One source-bound WebGoat Missing Function Access Control scenario can receive a
state-reset contract only after a separate adapter re-derives it from the exact
execution evidence, positive receipt, and negative-control receipt. The
adapter requires two cleanup runs per side, four unique run nonces, removal of
the owned container and two owned volumes per run, and absence of each
source-derived image after cleanup.

The registry binds the result to exactly one retained candidate after checking
the current adapter hashes, replay hash, materializer hash, source receipt
semantic fingerprint, source selector, and all three input hashes. The
evidence cannot self-admit a scenario, L2, scanner accuracy, TP/FP/FN, or a
release.

## Dynamic Evidence

The adapter generated the following canonical raw-free evidence twice from the
same pinned inputs:

`e0d6c44aba8f07db77da87a5efcceb973c821bf33dba2c5d9cab29c0f996c58d`

The two six-source registry materializations were byte-identical:

`238ca8db7ed1d3cfebbe64e7be6f8e3189380db1da3933dd9d3a1f6b78f310f2`

Both runs returned exit `2`, which means the registry contract was valid but
the phase-2 L2 gate stayed `HOLD`. `release_gate_passed` remained `false`.

The bound candidate is:

`webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:fbfda4592bc795b9`

It now has execution, negative control, CWE mechanism, and state-reset
evidence. Its remaining deficits are exactly:

- `cvss_v4_high_critical_missing`
- `expected_disposition_missing`

The registry still has 414 candidates and 413 candidates without a complete
oracle. No scenario was newly admitted by this field.

## Reproduce

```powershell
python scripts/derive_l2_webgoat_missing_function_ac_state_reset_evidence.py derive `
  --execution-evidence <missing-function-execution-evidence> `
  --positive-receipt <positive-receipt> `
  --negative-receipt <negative-receipt> `
  --output <new-state-reset-evidence.json>

python scripts/materialize_l2_oracles.py materialize `
  --sources-root <six-pinned-source-root> `
  --calculator-root <pinned-calculator-root> `
  --calculator-receipt <pinned-calculator-receipt> `
  --source-admission <locked-source-admission> `
  --source-receipts-dir <verified-source-receipts> `
  --missing-function-ac-execution-evidence <execution-evidence> `
  --missing-function-ac-cwe-evidence <cwe-evidence> `
  --missing-function-ac-state-reset-evidence <state-reset-evidence> `
  --missing-function-ac-state-reset-positive-receipt <positive-receipt> `
  --missing-function-ac-state-reset-negative-receipt <negative-receipt> `
  --output <new-registry.json>
```

The expected exit code is `2` until the entire registry passes. Supplying a
state-reset evidence file without both bound receipts, or validating an
attached registry without the same input chain, fails closed.

## Nonclaims

This field does not establish production severity, a complete access-control
model, scanner TP/FP/FN/TN, H100, L2 completion, automated blocking, or
release readiness. The candidate remains an observation-only scanner result
until independent scoring and observe-to-warn-to-block promotion are complete.
