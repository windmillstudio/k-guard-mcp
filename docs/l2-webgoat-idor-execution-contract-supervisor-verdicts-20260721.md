# L2 WebGoat IDOR Execution Contract Supervisor Verdicts

Date: 2026-07-21

Target:

- runner: `scripts/replay_l2_webgoat_idor.py`
- focused tests: `tests/test_replay_l2_webgoat_idor.py`
- evidence packet: `docs/l2-webgoat-idor-execution-contract-evidence-20260721.md`
- live receipt SHA-256:
  `3d1e162931ec875f1b9de8564ff08733677e7125347eb559c91318c67e86a874`

## Final Verdicts

| Supervisor | Scope | Verdict | Blocking finding |
| --- | --- | --- | --- |
| Claude Opus 4.8 | Direct read-only file review | `GO_MEASUREMENT_PATCH` | None |
| Grok 4.5 | Packet-only review | `GO_MEASUREMENT_PATCH` | None |
| Cline GLM-5.2 | Packet-only review; direct tools require interactive approval | `GO_MEASUREMENT_PATCH` | None |

Claude reviewed the runner and focused tests directly. Grok and GLM did not
claim direct source or receipt access; their verdicts apply only to the supplied
raw-free packet and its stated boundaries.

## Fixed Scope

The following narrow field is FIX:

`WebGoat IDOR upstream integration test can be executed twice from a pinned,
source-derived image under the recorded offline Docker isolation contract, with
equal normalized 2/0/0/0 outcomes and owned-resource cleanup.`

It is not a scanner accuracy finding and it is not product release evidence.

## Retained Admission Blockers

All reviewers accepted that these remain mandatory blockers for any broader
claim. They are intentionally retained in the receipt schema:

- `evidence_signature_missing`
- `negative_control_missing`
- `scanner_finding_mapping_missing`
- `source_bound_severity_rubric_missing`

Therefore the runner keeps `tp_fp_fn_admitted=false`,
`severity_or_cwe_admitted=false`, and `release_gate_passed=false`.

## Residual Risks

- Maven dependency resolution happens during the source-derived image build;
  the image ID seals the realized input, but transitive dependency provenance is
  not independently attested yet.
- Two-run equality proves normalized execution repeatability for one image, not
  statistical field reliability.
- The evidence bundle is unsigned. The receipt remains intentionally
  non-promotable until a separate provenance/signature field is completed.
