# WebGoat Missing Function Access Control Scanner Differential Evidence

## Field

`l2.webgoat-missing-function-ac.scanner-differential`

This field measures one bounded Spring Java observation against one
source-bound WebGoat vulnerable/negative-control pair. It does not establish
product accuracy, product TP/FP/FN/TN, H100, severity promotion, or release
approval.

## Hypothesis And Baseline

The pre-change scanner was frozen before the observer was added. On the exact
source-bound pair it emitted zero `API_PRIVILEGED_FIELD_MASS_ASSIGNMENT`
findings for both the vulnerable source and the negative control.

| Item | Value |
| --- | --- |
| Pre-change baseline receipt | `f687619333d2dd85a505879041412d5c3cebb160648a02270d6a3bee0d257371` |
| Vulnerable source | `MissingFunctionACUsers.java` at WebGoat `5142935bf7c279882c3b0fc0ecec42c447de6fd5` |
| Dynamic oracle | upstream `AccessControlIntegrationTest#testLesson` |
| Negative control | exact `force-created-user-nonadmin.v1` copied-source patch |
| Candidate rule | `API_PRIVILEGED_FIELD_MASS_ASSIGNMENT` |
| Detector subtype | `java_spring_privileged_field_mass_assignment_observe` |
| Candidate disposition | High severity, medium confidence, manual-review observation; not an automatic release rule |

The candidate detects a privileged-route request body that is directly
persisted without a visible authorization policy. It deliberately suppresses
only an unconditional final restrictive setter such as `setAdmin(false)` before
the persistence call. Conditional setters, comments, and setters after the
persistence call do not suppress it.

## Result

The candidate emitted one relevant vulnerable-side finding at the bound
persistence line and zero relevant fixed-side findings. The result was repeated
twice with byte-identical canonical receipts.

| Run | Receipt SHA-256 | Result |
| --- | --- | --- |
| r2 | `c5a9728385f0b6c9e55260e6c92eef6e4c88f1c2ce0a3c93e17c9d4737ae1fdb` | TP=1, TN=1, FP=0, FN=0 on this one generated pair |
| r3 | `c5a9728385f0b6c9e55260e6c92eef6e4c88f1c2ce0a3c93e17c9d4737ae1fdb` | byte-identical repeat |

The measurement binds the current source commit, execution evidence, CWE
mechanism evidence, positive and negative replay receipts, exact patch hashes,
the pre-change baseline, and the current scanner/detector hashes. A source or
evidence mismatch produces `HOLD` rather than a partial score.

## Reproduce

```powershell
python scripts/measure_l2_webgoat_missing_function_ac_scanner_differential.py measure `
  --source-root <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-sources\phase2-l2-cvss-registry-r2\webgoat `
  --execution-evidence <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-execution-evidence-20260721-r3\evidence.json `
  --cwe-evidence <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-cwe-evidence-20260721-r1\evidence.json `
  --positive-receipt <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-execution-contract-20260721-r2\receipt.json `
  --negative-receipt <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-negative-control-20260721-r2\receipt.json `
  --prechange-baseline <LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-missing-function-ac-scanner-baseline-20260722-r1\baseline.json `
  --output <new-receipt.json>

python scripts/measure_l2_webgoat_missing_function_ac_scanner_differential.py verify `
  --receipt <new-receipt.json>
```

## Claim Boundary

Proven by this field only:

- The actual pre-change scanner missed this one source-bound pair.
- The candidate observer distinguishes the vulnerable source from the exact
  negative control twice without changing the authoritative source checkout.
- The rule stays a manual-review observation under the release policy.

Not proven:

- That every direct request-body persistence is a privilege-assignment bug.
- Precision, recall, specificity, or FP/FN rates beyond this one pair.
- An independent upstream fixed revision, customer deployment severity, or
  complete business authorization model.
- L2 completion, H100, automatic blocking, or product release.
