# L2 Tmpfs Ownership Contract Review

## Change Scope

L2 runtime plans can now declare tmpfs ownership as one atomic tuple:
`uid`, `gid`, and `mode`. Existing plans that declare only `path` and
`size_bytes` remain valid for backward compatibility. A new owned tmpfs row
must satisfy all of the following conditions:

- all three ownership fields appear together;
- the runtime UID is non-root and the GID may be `0`, which is required by
  the source-built Juice Shop image's OpenShift-compatible group model;
- every declared tmpfs UID/GID exactly matches `run_as`;
- the mode is four octal digits, owner-writable, and grants no world
  permissions;
- the size stays within the existing 4 KiB to 64 MiB per-mount bound.

The Docker create argument serializes the declared tuple. Docker inspect is
then parsed as comma-separated options and fails closed on a missing,
conflicting, duplicate, or unsafe option. In particular, `ro`, `exec`,
`suid`, and `dev` cannot coexist with the expected writable hardened mount.
This removes the former gap in which a plan could rely on a manual tmpfs
ownership setup that was not represented or rechecked by the harness.

The official Juice Shop plan sets `run_as: 65532:0`; every one of its seven
owned tmpfs mounts uses that same `uid: 65532`, `gid: 0`, and `mode: 0770`.
The group-zero mode is intentional for the image's container-local
OpenShift-compatible group model, not a claim about host-root access.

## Replay Gate

`materialize_l2_runtime.py compare-replays` accepts two distinct, already
verified runtime receipts. It requires equal source-admission hash, runtime
plan hash, tool provenance, app-status map, and a bounded decision projection.
The projection includes each app's status and blockers plus boolean evidence
for build, network, container, post-start/post-health, health, egress, and
cleanup. It intentionally excludes incidental Docker image IDs and command
receipt hashes, which may differ across equivalent local builds.

Each collection also records only a SHA-256 hash of a fresh 32-byte execution
nonce. Replay comparison requires both nonce hashes and receipt hashes to be
different. This rejects a byte-for-byte copied receipt at another path; it is
not a substitute for an externally signed provenance bundle.

The command writes a canonical comparison artifact and returns nonzero when
the replay gate is `HOLD`. It never grants L2-wide or release authority.

## Verification

- Focused L2 runtime tests: `83 passed`.
- Full repository regression: `2154 passed, 5 skipped` in `736.71s`.
  The skips remain separately configured or platform-scoped checks rather
  than this L2 contract.
- Docker Desktop 29.5.3 accepted and preserved
  `uid=65532,gid=0,mode=0770` on a read-only BusyBox control container.
- Official six-app plan:
  `<LOCAL_USER_HOME>\Desktop\mcp\k-guard-live-evidence\phase2-l2-runtime-juice-ownership-contract-20260721-r1\runtime-plan.json`
  has SHA-256
  `b073c39a2586b3fc5197267cca8d7d1f66b87b62170cfb52b5a50efbe1ffee8e`.
- The plan source-builds Juice Shop, builds an adapter whose rootfs extends
  that exact source image, and mounts seven declared writable paths as
  the exact runtime identity `65532:0` with mode `0770` and bounded
  capacities.
- Two current-tool replays produced valid receipts:
  `runtime-observation-r5-nonce-tool.json` and
  `runtime-observation-r6-nonce-tool.json`.
  In both runs, Juice Shop was `PASS`; source/adapter provenance, read-only
  rootfs, no host port publish, hardened tmpfs, internal health HTTP 200,
  denied egress, and owned cleanup all passed. The egress assertion uses the
  digest-pinned BusyBox helper on the internal bridge and requires its
  external `wget` request to return the denied result; its separate command
  self-test runs with no network.
- `replay-comparison-r5-r6-nonce.json` records `replay_gate: PASS`, equal
  plan/admission/tool provenance/app-status/decision values, and distinct
  execution nonces and receipt hashes. It has matching
  decision-projection SHA-256
  `11e51a8f1cf4342722e89c4eac8564e71780d5de59616e025626301fca574d20`.
- Focused coverage includes
  `test_runtime_plan_keeps_legacy_tmpfs_and_allows_nonroot_uid_with_root_group`,
  `test_container_projection_rejects_missing_or_forged_tmpfs_owner_mode`,
  `test_runtime_replay_comparison_requires_equal_decision_projection`, and
  `test_runtime_replay_comparison_rejects_copied_receipt_nonce`.

## Explicit Non-Claims

- The six-app L2 runtime gate remains `HOLD`: crAPI, NodeGoat, PyGoat,
  WebGoat, and WrongSecrets still lack complete current runtime evidence.
- The replay gate proves result reproducibility for the bounded runtime
  decision projection. It does not prove deterministic Docker image IDs,
  scanner accuracy, recall, or release readiness.
- This change does not promote any new vulnerability detector, block rule,
  or product release decision.
