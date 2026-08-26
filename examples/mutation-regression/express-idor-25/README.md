# Express IDOR 25-case seeded regression

This checked-in fixture makes the published 25-case mutation result reproducible from a clean clone. It is intentionally narrow: one app, one detector rule, one exact find/replace operator, and 25 paths. It is regression evidence, not a public benchmark or owned/partner field validation.

From the repository root:

```bash
python -m k_guard_mcp.cli mutation-apply \
  --source examples/mutation-regression/express-idor-25/source \
  --plan examples/mutation-regression/express-idor-25/mutation-plan.json \
  --output tmp/reproduced-mutation-pack

python -m k_guard_mcp.cli mutation-evaluate \
  --pack tmp/reproduced-mutation-pack \
  --output tmp/reproduced-mutation-evaluation
```

Expected contract:

- `mutation_count`: 25
- `case_counts`: TP 25, FN 0, FP 0, TN 25
- `validation_claim_status`: `seeded_mutation_regression_ready`
- `diversity.evidence_grade`: `single_pattern_seeded_regression`
- `claim_boundary.not_a_public_or_field_benchmark`: `true`

Generated timestamps, path references, evidence signatures, and whole-file hashes can differ between machines. The semantic score and claim boundary above must match.
