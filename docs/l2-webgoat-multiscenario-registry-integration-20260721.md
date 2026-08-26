# WebGoat Multi-Scenario Registry Attachment

Date: 2026-07-21

## Field

`l2.webgoat.multiscenario-registry-attachment`

This field adds one typed, fail-closed attachment path for the already
validated MissingFunctionAC execution and CWE evidence. The existing WebGoat
IDOR attachment remains independently bound. The registry therefore holds two
different WebGoat source selectors without allowing one scenario's evidence to
be applied to the other.

## Contract

The MissingFunctionAC attachment requires both inputs together:

- execution evidence with a positive process result and a distinct negative
  control result;
- CWE mechanism evidence with `CWE-266` and mechanism truth `present`.

Both inputs must have current typed-adapter and replay provenance, identical
source metadata, identical selector data, and an authoritative WebGoat source
receipt. The source receipt may be byte-exact or differ only by the explicitly
informational `git_porcelain_clean` field. Any other receipt difference is
rejected.

The registry locates exactly one retained candidate using the app id, scenario
id, source-root-cause identity, source path, line, and content hash. It then
attaches the process pair, CWE, and mechanism truth. It does not attach CVSS,
expected disposition, or state reset, and it cannot admit the scenario.

## Operation

Materialize or validate the registry with both typed inputs:

```powershell
python scripts/materialize_l2_oracles.py materialize `
  --sources-root <six-pinned-source-root> `
  --calculator-root <pinned-calculator-root> `
  --calculator-receipt <pinned-calculator-receipt> `
  --source-admission <locked-source-admission> `
  --source-receipts-dir <verified-source-receipts> `
  --execution-evidence <optional-idor-execution-evidence> `
  --missing-function-ac-execution-evidence <missing-function-execution-evidence> `
  --missing-function-ac-cwe-evidence <missing-function-cwe-evidence> `
  --output <new-registry.json>
```

`exit 2` is the expected result for a structurally valid registry that remains
`HOLD`. `exit 0` is reserved for a complete L2 pass. Omitting either
MissingFunctionAC input from validation of an attached registry must fail with
an input error rather than silently weakening the registry.

## Dynamic Result

The pinned six-source corpus was materialized twice with both WebGoat scenario
attachments. Each materialization returned `HOLD` with exit `2` and produced
the same registry SHA-256:

`7dc1381d155e5de77a4c1229cb8ed013f59666bd7826de14028c4be587ba43a6`

The attached MissingFunctionAC candidate is:

`webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:fbfda4592bc795b9`

Its retained deficits are exactly:

- `cvss_v4_high_critical_missing`
- `expected_disposition_missing`
- `state_reset_missing`

The registry records `source_receipt_equivalence` as
`informational_porcelain_variance`; the semantic receipt fingerprint, pinned
commit, tree, and source-tree digest still match. The existing IDOR execution
pair remains attached to its own different selector.

## Regression Attestation

The focused attachment, replay, evidence, and supervisor-contract suite ran
twice with no skips:

```text
python -m pytest -q tests/test_materialize_l2_oracles.py tests/test_replay_l2_webgoat_missing_function_ac.py tests/test_derive_l2_webgoat_missing_function_ac_execution_evidence.py tests/test_derive_l2_webgoat_missing_function_ac_cwe_evidence.py tests/test_supervisor_reviews.py
```

Both runs reported `88 passed`. The full repository regression then reported
`2263 passed, 5 skipped`.

## Nonclaims

This field does not establish a production severity, a complete access-control
model, scanner TP/FP/FN/TN, H100, L2 completion, or product release readiness.
The overall registry and release gate remain `HOLD`.
