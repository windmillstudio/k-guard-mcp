# WebGoat IDOR CVSS Benchmark Evidence

Date: 2026-07-21

## Field

`l2.webgoat-idor.source-bound-cvss-benchmark-profile`

## Narrow approved claim candidate

One pinned WebGoat IDOR benchmark scenario has a raw-free CVSS v4.0 profile
derived only after its source-bound CWE-639/mechanism evidence, execution
selector evidence, and the pinned FIRST calculator source contract agree.
The profile is `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N`,
with score `7.1`, severity `high`, and expected disposition `warn`.

The scope is exactly `pinned_webgoat_benchmark_scenario`. It is not a customer
deployment severity, a scanner finding, a registry admission, an oracle label,
an L2 pass, a TP/FP/FN measurement, or a release decision.

## Implementation contract

`scripts/derive_l2_webgoat_idor_cvss_evidence.py` accepts only canonical CWE
and execution evidence whose selectors match exactly. It revalidates the
source-bound child adapters, validates the preregistered FIRST calculator
source through the L2 registry contract, runs the pinned calculator locally,
and rejects any score other than `7.1` for the fixed vector.

The output contains identifiers, digests, metric identifiers, and fixed
classification values only. It contains no raw source, execution output,
credential, or customer data. The validator rejects a forged selector,
calculator identity, profile, claim boundary, or adapter provenance. Output
creation is canonical and refuses overwrite.

## Evidence

Two independent derivations from the same immutable source inputs produced the
same evidence SHA-256:

`ecc9fe5cb3430758712cb639af0cb3d5710830a8520a42d74dad3883424c3a92`

The repeat proves deterministic artifact generation for this one profile. It
does not prove risk discovery, recall, precision, actionability, or product
release readiness.

## Test attestation

- Focused source/evidence/registry suite: `59 passed` in 45.21 seconds.
- Full regression: `2223 passed, 5 skipped` in 761.09 seconds.
- Required evidence derivation repeat: two matching canonical outputs.

## Required external decision

Claude Opus reviews the listed files read-only. Grok 4.5 and Cline GLM 5.2
receive only the sanitized review packet. This field is `HOLD` until all three
return a compatible `GO` receipt for the same target and manifest, and the
machine receipt validator returns `FIX`.

## Remaining blockers

- Registry attachment is documented separately in
  `l2-webgoat-idor-cvss-registry-integration-20260721.md`; that attachment
  still does not admit a scenario.
- The generated negative control and registry state-reset evidence remain
  separate prerequisites for scenario admission.
- No customer application severity, High/Critical finding, or release authority
  is created by this benchmark profile.
