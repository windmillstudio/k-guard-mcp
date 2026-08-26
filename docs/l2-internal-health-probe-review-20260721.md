# L2 Internal Health Probe Review

## Change Scope

The L2 runtime harness no longer publishes an application port on the host.
Each app receives only its fixed app-id network alias on the existing internal
bridge. A digest-pinned BusyBox helper joins that internal bridge briefly to
perform the health request, then exits. The helper runs read-only, non-root,
with all capabilities dropped and no-new-privileges enabled.

This replaces a Docker Desktop failure mode in which an internal Docker
network did not expose an allocated loopback host port even after the app was
running. The old host probe could therefore report a false infrastructure
failure or tempt the harness to weaken the network isolation contract.

The container contract now fails closed when either Docker port-binding view
contains an effective host publish. It also requires the expected internal DNS
alias. Health evidence stores only the helper command receipt hashes and the
parsed HTTP status, never the response body or raw headers. The harness
re-inspects the same app container after the health probe, so a transient
response followed by a crash cannot pass the isolation check.

The exact helper digest must be present locally before collection. The harness
does not pull it during a run; an absent or mismatched helper image becomes a
fail-closed HOLD. Health plans accept only HTTP `200` through `399`, because
the helper's successful `wget` contract cannot reliably attest an error
response as healthy. Before any app request, the harness checks the pinned
helper's own `wget --help` output for the required `-S` server-response flag;
missing support also becomes a HOLD without contacting the app.

## Verification

- Focused L2 runtime tests: `65 passed`.
- Full repository regression: `2136 passed, 5 skipped`.
- The five full-suite skips are outside this L2 health contract: current-source
  contest evidence binding, POSIX permissions on Windows, an unconfigured real
  Semgrep executable, a separately requested L3 Docker smoke run, and a
  separately configured L4 live replay.
- Dynamic Docker Desktop control:
  - source-built Juice Shop with an experimental immutable seed adapter;
  - internal bridge only, no host port publish, read-only root filesystem,
    non-root `65532:0`, dropped capabilities, no host mount;
  - the pinned BusyBox helper returned HTTP `200` on attempt 2;
  - helper digest, image ID, `wget -S` support, command completion, and
    expected-status checks were all true;
  - the app remained `running` after the probe, with no effective host port
    publish.
- Added fail-closed coverage for a wrong helper image, a non-digest helper
  reference, an unexpected status, a nonzero `wget` result, timeout/truncated
  output, and a probe followed by an exited or replaced app container. These
  cases prove that post-probe re-inspection changes the app result to `HOLD`.
- Dynamic negative control: the same internal app was probed on an unopened
  port. The helper remained trusted and executable, but `request_succeeded`
  and `response_status_observed` were false, producing `passed: false` while
  the app remained running. This confirms that a failed probe is not silently
  converted into a pass.

## Independent Review

- Claude Opus 4.8 reviewed the three in-repository files and returned
  `GO_MEASUREMENT_PATCH` after the fail-closed tests were added.
- Grok 4.5 independently reviewed the same three files and returned
  `GO_MEASUREMENT_PATCH`.
- GLM-5.2 initially could not read repository files in a non-interactive Cline
  session and correctly returned `HOLD` for missing evidence. It then reviewed
  a supplied, bounded evidence packet and returned `GO_MEASUREMENT_PATCH`.
  Its verdict is secondary to the Claude and Grok direct file reviews.

The dynamic control uses an adapter experiment outside the repository to make
Juice Shop's documented writable paths ephemeral. It proves the internal
health-probe mechanism, not a full L2 admission result.

## Explicit Non-Claims

- L2 remains `HOLD`: the other five apps and the approved one-to-one oracle
  registry are still incomplete.
- This is not an accuracy, recall, or release-GO claim for K-Guard.
- The temporary adapter still needs a separately reviewed declarative tmpfs
  ownership and capacity contract before it can become an official runtime
  plan.

## Reviewer Questions

1. Does removing host publishing preserve or strengthen the isolation claim on
   Docker Desktop and Linux Docker engines?
2. Does the helper command and status parsing remain fail-closed when output is
   malformed, truncated, or not a permitted status?
3. Is re-inspecting the app after probing sufficient for this narrow runtime
   check, or is a stronger stability interval required before later promotion?
4. Are the test and dynamic-control boundaries stated accurately without
   implying an L2 or product release pass?
