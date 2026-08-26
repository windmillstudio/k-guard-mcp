# L2 WebGoat IDOR Scanner Differential Evidence

Date: 2026-07-21

## Field

`l2.webgoat-idor.scanner-differential`

## Narrow Claim

This field measures one source-bound vulnerable/fixed WebGoat pair. It checks
whether the Java observer continues to identify the vulnerable cross-account
write while no longer reporting the same rule after the exact negative-control
patch has installed an explicit denial branch.

It is not a product accuracy result. One pair cannot establish population
precision, recall, specificity, High/Critical recall, severity calibration, or
release eligibility.

## Provenance Contract

The measurement requires all of these inputs at the command line:

1. The six-app source root and the WebGoat child root.
2. The preregistered source-admission artifact.
3. A complete directory of six current raw-blob source receipts.
4. The pinned positive and negative WebGoat Docker execution receipts.

The current WebGoat source receipt is accepted only through the authoritative
six-app source-admission verifier. Its raw receipt differs from the historical
execution receipt solely because `git_porcelain_clean` is informational; the
semantic source fingerprint, source tree, commit, origin, Git blobs, index,
and license binding must still match. The measurement records both receipt
hashes and the equivalence mode without retaining source text.

The accepted historical source-admission artifact has SHA-256
`32b9618dfdcb3ff4f8e87fa5012c36eff51a1beba2dd0e0357a7bbd9c99ecc1a`.
An attempt using a later non-preregistered admission artifact was recorded as
`HOLD`; it was not substituted or silently accepted.

## A/B Definition

`HEAD` cannot serve as this field's A/B baseline because the cross-account JVM
observer itself is an uncommitted candidate change relative to `HEAD`. Calling
that an earlier product baseline would make the vulnerable side disappear and
would be misleading.

Instead, the receipt defines the baseline as the exact current candidate with
only `_java_cross_account_mismatch_is_explicitly_rejected` forced to `false`.
The candidate code and the counterfactual definition are both hashed in the
receipt. This isolates one hypothesis: whether visible, complete rejection of
the same mismatch should suppress the candidate. It does not represent an
older shipped version.

The negative variant is created only in a temporary copy using the same patch
identity and file/tree hashes that the already-validated negative Docker
receipt used. The original checkout is source-admission verified before and
after the measurement.

## Operation

Run a new output path for every measurement; existing evidence is immutable.

```text
python scripts/measure_l2_webgoat_idor_scanner_differential.py measure \
  --source-root <six-app-root>/webgoat \
  --sources-root <six-app-root> \
  --source-admission <locked-source-admission.json> \
  --source-receipts-dir <six-current-source-receipts> \
  --positive-receipt <positive-execution-receipt.json> \
  --negative-receipt <negative-control-receipt.json> \
  --output <new-output>/receipt.json

python scripts/measure_l2_webgoat_idor_scanner_differential.py verify \
  --receipt <new-output>/receipt.json
```

The command fails closed when a source root is not the WebGoat child of the
six-app root, source admission is not preregistered, a receipt loses raw-blob
proof, the dynamic patch differs from the runtime oracle, the baseline does
not reproduce the original false positive, the candidate still reports the
fixed side, or the two candidate runs differ.

## Live Result

Two complete measurements produced byte-identical canonical receipts:

| Run | Receipt path | SHA-256 | Status |
| --- | --- | --- | --- |
| r4 | `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-idor-scanner-differential-20260721-r4\receipt.json` | `193da41ab72ac9f84ee7404de9455e5e3741d6258b297b2313f9bce499a4a687` | `SCANNER_DIFFERENTIAL_PASS` |
| r5 | `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-webgoat-idor-scanner-differential-20260721-r5\receipt.json` | `193da41ab72ac9f84ee7404de9455e5e3741d6258b297b2313f9bce499a4a687` | `SCANNER_DIFFERENTIAL_PASS` |

The pre-suppression counterfactual reported one relevant candidate for the
fixed side. The current candidate reported one expected High/medium IDOR
candidate for the vulnerable side and zero relevant candidates for the fixed
side. The receipt records the local pair score as `TP=1`, `TN=1`, `FP=0`, and
`FN=0`; those numbers apply only to this one generated differential.

## Test Attestation

Focused regression on the final candidate passed twice:

```text
python -m pytest -q tests/test_measure_l2_webgoat_idor_scanner_differential.py \
  tests/test_capture_supervisor_target.py \
  tests/test_supervisor_reviews.py \
  tests/test_public_app_regressions.py \
  tests/test_observe_l2_webgoat_idor_scanner.py \
  tests/test_replay_l2_webgoat_idor.py \
  tests/test_materialize_l2_oracles.py \
  tests/test_holdout_runtime_probe.py

158 passed
same command repeated: 158 passed
```

The complete repository test corpus passed as two deterministic shards on the
same candidate. A one-process run exceeded the local 15-minute command limit,
so it is not used as a passing attestation. The shards are the sorted
`tests/test_*.py` file list split into the first 57 and remaining 56 files;
together they match the collected corpus exactly.

```text
A shard: 1106 passed, 2 skipped in 351.50s
B shard: 1168 passed, 3 skipped in 510.12s
combined: 2274 passed, 5 skipped = 2279 collected tests
```

`python scripts/release_hygiene.py` also passed. The configured skips do not
skip this measurement, the Java observer, source-admission verification, or
the L2 runtime contracts.

The Windows runtime-probe fixture creates its venv from an independent copied
base runtime without site packages. This prevents hardlinks created by an
unrelated host-process test from contaminating the normal fixture. It does not
relax the control: the dedicated scanner-prefix hardlink test still requires a
fail-closed runtime attestation.

Supervisor review receipts use target v2. In addition to `head_git_oid` and
the dirty path-set hash, every receipt must bind `dirty_worktree_sha256`, a
content-bound fingerprint over the Git diff and untracked file state. Changing
the contents of an already-dirty path therefore invalidates prior reviews even
when the path list is unchanged.

## Machine-Enforced Boundary

The result fixes only this narrow differential field when supervisor review
also approves it. The receipt explicitly keeps all broader claims false:

- `product_accuracy_proven=false`
- `product_tp_fp_fn_tn_proven=false`
- `recall_or_specificity_proven=false`
- `severity_or_cwe_admitted=false`
- `release_gate_admitted=false`
- `release_gate_passed=false`

Next work remains the independent public-oracle and generated-pair corpus
needed to measure real TP/FP/FN distribution before any block-rule promotion.
