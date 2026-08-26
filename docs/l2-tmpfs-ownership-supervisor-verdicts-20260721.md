# L2 Tmpfs Ownership Supervisor Verdicts

## Review Target

The reviewed change is limited to declarative tmpfs ownership/capacity,
Docker inspect revalidation, nonce-bound runtime replay comparison, and the
bounded Juice Shop evidence described in
`l2-tmpfs-ownership-contract-review-20260721.md` and
`l2-tmpfs-ownership-evidence-20260721.md`.

## Verdicts

| Reviewer | Review basis | Verdict |
| --- | --- | --- |
| Claude Opus 4.8 | Direct read-only review of the runtime script, tests, and repository evidence packet | `GO_MEASUREMENT_PATCH` |
| Grok 4.5 | Structured bounded evidence packet | `GO_MEASUREMENT_PATCH` |
| GLM-5.2 via Cline | Structured bounded evidence packet; no repository file-tool claim | `GO_MEASUREMENT_PATCH` |

All three reviewers reported no blocking issue for the narrow measurement
patch. Their common nonblocking boundary is that only Juice Shop has runtime
PASS evidence; five apps and the six-app L2 gate remain `HOLD`.

## Accepted Nonblocking Limits

- `gid: 0` with `mode: 0770` deliberately grants the container-local runtime
  group access. The plan documents this OpenShift-compatible image model; it
  is not an owner-only or host-root claim.
- Replay comparison proves equality of the bounded decision projection. It
  intentionally does not require deterministic Docker image IDs or raw
  command-receipt hashes.
- The repository evidence packet binds external artifact hashes but is not an
  independently signed provenance bundle.
- Five full-suite skips are configuration or platform scoped and remain
  outside this patch.

## Fix Decision

`FIX: L2 tmpfs ownership and nonce-bound replay measurement contract.`

This FIX does not promote the six-app L2 runtime gate, scanner accuracy,
detector block policy, or product release. Those remain separate HOLD gates.
