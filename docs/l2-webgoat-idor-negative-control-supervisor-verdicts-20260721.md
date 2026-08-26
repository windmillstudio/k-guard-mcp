# L2 WebGoat IDOR Negative-Control Supervisor Verdicts

Date: 2026-07-21

Target revision:

- runner: `scripts/replay_l2_webgoat_idor.py`
- focused tests: `tests/test_replay_l2_webgoat_idor.py`
- evidence packet:
  `docs/l2-webgoat-idor-negative-control-evidence-20260721.md`
- live receipt SHA-256:
  `baee6c365c87526a5a7b00717c14616e7497eb55f804a9a0fdf9fe36160bddaa`
- runner SHA-256:
  `d9f52d4fca410fe4c27cd9c4e8aa0e9ea7e696e80df34f67f5b04ef69bd1ce29`
- regression:
  `137 passed` focused, `2176 passed, 5 skipped` full

## Final Verdicts

| Supervisor | Scope | Verdict | Blocking finding |
| --- | --- | --- | --- |
| Claude Opus 4.8 | Direct read-only runner, test, and document review | `GO_MEASUREMENT_PATCH` | None |
| Grok 4.5 | No-tool supplied-evidence packet review | `GO_MEASUREMENT_PATCH` | None |
| Cline GLM-5.2 | No-tool supplied-evidence packet review | `GO_MEASUREMENT_PATCH` | None |

Claude could not open the live receipt outside its sandboxed workspace. Its
direct verdict therefore relies on code-enforced receipt validation and the
documented receipt hashes. Grok and GLM did not claim direct repository or
receipt access; their reviews apply only to the supplied raw-free packet.

## Fixed Scope

The following narrow field is FIX:

`A specific canonical positive WebGoat IDOR execution receipt can be bound to a
deterministic copied-source authorization control. Two fresh isolated runs
produce the exact expected negative projection and clean up every owned Docker
resource, while the receipt remains non-promotable.`

This is an execution-sensitivity contract. It is not a scanner accuracy result,
a CVSS/CWE classification, TP/FP/FN evidence, an independent upstream fix, or
release evidence.

## Retained Blockers

The receipt schema and all three reviews retain these blockers:

- `evidence_signature_missing`
- `independent_upstream_fixed_revision_missing`
- `scanner_finding_mapping_missing`
- `source_bound_severity_rubric_missing`

Therefore `scanner_accuracy_proven=false`, `tp_fp_fn_admitted=false`, and
`release_gate_passed=false` remain mandatory. The static L2 registry still has
zero admitted scenarios, so L2 overall remains HOLD.

## Nonblocking Review Notes

- The positive receipt SHA-256 is now explicitly pinned to the r3 artifact.
- Docker inspect errors for resources created by the run now fail cleanup;
  they cannot be treated as successful removal.
- The label `r3` appears both in the positive receipt identity and in the
  historical negative-control iteration numbering. The evidence filenames make
  the two artifacts distinct; this naming overlap has no machine effect.
