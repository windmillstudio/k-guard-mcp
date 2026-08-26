# WebGoat IDOR State-Reset Registry Integration

Date: 2026-07-21

## Field

`l2.webgoat-idor.state-reset-registry-integration`

## Narrow Claim Candidate

One source-bound WebGoat IDOR process scenario can receive a state-reset
contract only after a separate adapter re-derives it from the exact execution
evidence, positive receipt, and negative-control receipt. The state-reset
adapter requires two cleanups for each side, four unique run nonces, removal
of the owned container and two owned volumes per run, and absence of each
source-derived image after cleanup.

The registry binds that contract to exactly one retained candidate. It does
not let execution evidence self-admit reset evidence, and it does not let
state-reset evidence self-admit the scenario, L2, scanner accuracy, TP/FP/FN,
or release status.

## Dynamic Evidence

The current registry code produced these new raw-free inputs:

- CVSS evidence SHA-256:
  `78663f1cb587abae6bea4dc41d32ddd47bf68f38d6537f1d45f806aaa8f4a7ae`
- State-reset evidence SHA-256:
  `e7f8e42e9ccb811e5a15499f20cd45a493adc324806ee020513694dcd8a12fd4`

Two complete registry materializations over the six independently verified
source trees produced the identical canonical registry SHA-256:

`4cadd8acfd80386628aa559a886f6b1f317a460b5e0f6e410bffdd116c37c264`

Both materialization runs and both explicit validation runs returned exit `2`
with `registry_contract_valid=true`, `phase_2_l2_status=HOLD`, and
`release_gate_passed=false`. Supplying a state-reset evidence file without its
positive and negative receipt inputs returned exit `1` and wrote no registry.

The 414-candidate registry has exactly one admitted scenario:

`webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:2da84111e81ac5d4`

That candidate has an empty deficit list and a `process` state-reset command.
The remaining 413 candidates are incomplete. The result is therefore a
scenario-level evidence admission, not L2 completion, a detector-quality
measurement, or a release result.

## Test Attestation

The focused state-reset, CVSS, CWE, execution, replay, registry, and
supervisor-receipt suite passed twice:

- `112 passed in 94.74s`
- `112 passed in 88.46s`

It covers independent receipt derivation, cleanup failure rejection, nonce
collision rejection, execution self-admission rejection, input-chain
revalidation, exactly-one-candidate attachment, missing-input fail-closed
behavior, and preservation of the overall HOLD boundary.

## Remaining Blockers

- Full regression must pass on this exact target before supervisor review.
- Claude Opus direct-files, Grok 4.5 packet, and GLM 5.2 packet review must
  all issue compatible `GO` receipts before this narrow field is `FIX`.
- The other 413 candidates, independent oracle differentials, TP/FP/FN
  measurement, H100, and product release all remain `HOLD`.
