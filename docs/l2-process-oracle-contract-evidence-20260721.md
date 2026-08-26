# L2 Process-Mode Oracle Contract Evidence

Date: 2026-07-21

## Scope

This field fixes one L2 registry contract defect. Upstream WebGoat and
WrongSecrets integration tests execute through Maven/JUnit processes, but the
old registry required every command to have an HTTP status and body hash. It
also required every command, including a negative control, to exit with zero.
That made a source-bound process execution pair impossible to represent.

The field introduces two explicit command kinds:

- `http`: requires an HTTP status, body hash, and normalized result hash.
- `process`: requires no HTTP status or body field, but still requires an
  exact normalized result hash.

An `oracle` and `state_reset` must still expect exit code `0`. A
`negative_control` may expect a non-zero rejection exit, but its expected
outcome must differ from the positive oracle. A process record carrying HTTP
only fields is malformed and fails closed.

## Dynamic Result

The six pinned L2 source checkouts were materialized twice using the locked
source admission and FIRST CVSS calculator inputs. The raw-free registry files
were byte-identical:

| Run | Registry SHA-256 | Status |
| --- | --- | --- |
| r3 | `235d65b57b91a0db032a2b2e5f3e93cb48a03f04ad381ab5ae6b980ea6e29ef3` | `HOLD` |
| r4 | `235d65b57b91a0db032a2b2e5f3e93cb48a03f04ad381ab5ae6b980ea6e29ef3` | `HOLD` |

Both re-validation runs returned the expected HOLD exit code after fully
recomputing the registry. The candidate count remains `414`; admitted
High/Critical scenarios remain `0`.

The old HTTP-only deficits disappeared only for the `269` executable-test
candidates. Their remaining `oracle_expected_result_sha256_missing` deficit
still prevents admission. CWE, CVSS, expected disposition, negative-control,
and reset deficits remain. This is intentional: the field removes a schema
mismatch, not evidence requirements.

## Tests

`tests/test_materialize_l2_oracles.py` covers deterministic registry
materialization, process result-hash requirements, process/HTTP field
separation, a non-zero process rejection control, rejection of an
indistinguishable negative control, and rejection of a v2 registry under the
v3 contract. The focused suite passed with `37 passed`
before final target sealing.

## Nonclaims

This field does not admit an L2 scenario, label a TP/FP/FN/TN, assign a CWE or
CVSS value, prove scanner accuracy, run a scanner against the L2 pool, or
grant release authority. L2 overall and product release remain `HOLD`.

The next evidence field is a source-bound execution-result adapter for the
existing WebGoat positive/negative pair. It must bind the normalized result
hashes and reset proof without accepting a self-declared result or severity.
