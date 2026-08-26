# L2 Runtime Port Lifetime Review

## Change hypothesis

Docker Desktop may leave an ephemeral published host port blank in
`HostConfig.PortBindings` before container start, then expose the assigned
loopback port only through `NetworkSettings.Ports` after start. Treating the
pre-start blank value as an isolation failure prevents valid loopback-only
local harnesses from reaching their post-start health check.

## Implemented boundary

- Before start, require exactly one configured `127.0.0.1` binding and permit
  either Docker Desktop's empty ephemeral value or an already assigned
  loopback port.
- After start, require a concrete `127.0.0.1` port from runtime inspection.
- Reject `0.0.0.0`, additional configured bindings, missing runtime binding,
  invalid ports, or a global binding.
- Keep source provenance, non-root execution, read-only root filesystem,
  network isolation, egress denial, health checks, cleanup, and the release
  gate unchanged.

## Changed files

- `scripts/materialize_l2_runtime.py`
  - SHA-256: `c899bbe8b12acc77f7e9a8774d0d92d1062f82d1e4d0e1ae657a5a84327ff9d1`
- `tests/test_materialize_l2_runtime.py`
  - SHA-256: `004690a8c2da0a178ad7b16add0e57f947adc059dffa18f31b7578f50412ad78`

## Verification

- Focused L2 runtime plus oracle tests: `84 passed`.
- Full repository test suite after the added regressions: `2,123 passed, 5 skipped`.
- A disposable local Docker probe confirmed that a pre-start loopback binding
  has an empty configured host port while the post-start runtime binding is
  loopback-only and assigned.
- The fresh L2 runtime receipt is valid but still `HOLD` for all six apps:
  source-built provenance and full runtime isolation are not claimed as
  satisfied. No release result changed from `false` to `true`.

## Evidence boundary

The post-change receipt is
`<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-runtime-20260721-r7-poststart-port\runtime-observation.json`
with SHA-256
`d156189bd4d641af5591f0bcfb99db139a17e5e95e6234d86c08ac43b1110f6c`.

The test suite now also pins the exact post-start Docker Desktop shape:
an empty configured `HostConfig` port plus an assigned loopback
`NetworkSettings` port. A separate pre-start global-binding control remains
an explicit HOLD.

## External supervisor disposition

| Reviewer | Model | Verdict | Scope |
| --- | --- | --- | --- |
| Claude | Opus 4.8 | `GO_MEASUREMENT_PATCH` | Repository-only re-audit of the current code and tests. |
| Grok | 4.5 | `GO_MEASUREMENT_PATCH` | One-turn audit of the exact implementation and test excerpts. |
| Cline | GLM top tier | `BLOCKED_AUTH` | Local provider authentication is not yet accepted by the CLI. |

The two available supervisors agree that the patch remains fail-closed. Under
the operating contract it is `TEMPORARY_PENDING_REVIEW` until Cline GLM can
perform the same review. It is never an L2 admission or product-release GO.

This is a measurement-infrastructure correction only. It does not establish
L2 oracle admission, scanner accuracy, runtime exploitability, or product
release readiness.
