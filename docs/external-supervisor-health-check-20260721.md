# External Supervisor Health Check

Date: 2026-07-21

## Purpose

This receipt confirms that the three required external review lanes can be
invoked from the current environment before the next narrow implementation
field begins. It is an availability receipt, not a product-performance result,
not a security assessment, and not a release approval.

## Sanitized check

Each provider received the same no-tool request for one exact terminal JSON
object. No repository file, source snippet, customer data, or tool use was
requested. The process exit code and final terminal response were retained;
provider reasoning streams, credentials, and token streams were discarded.
The initial check used the legacy `GO` token. It is explicitly not a review
receipt and cannot be supplied to the receipt validator. All subsequent health
checks use `{"status":"HEALTHY","approval":false}` so availability cannot be
mistaken for a field or product approval.

| Lane | Requested model | Exit | Terminal result | Review use |
| --- | --- | ---: | --- | --- |
| Claude | `claude-opus-4-8` | 0 | Legacy `GO`, `healthy`; recheck uses `HEALTHY` | Read-only direct-file or sanitized-packet review |
| Grok | `grok-4.5` | 0 | Legacy `GO`, `healthy`; recheck uses `HEALTHY` | Read-only no-tool sanitized-packet review |
| Cline GLM | `cline-pass/glm-5.2` | 0 | Legacy `GO`, `healthy`; recheck uses `HEALTHY` | Read-only no-tool sanitized-packet review; direct tool access needs an interactive read-only approval receipt |

## Recheck after protocol hardening

The three lanes were invoked again with the exact terminal response
`{"status":"HEALTHY","approval":false,"scope":"no-tool-health-check"}`.
Claude, Grok, and Cline GLM each returned that object with exit 0. This is the
current health-check format; it is intentionally schema-incompatible with a
field-review receipt.

## Operating decision

All three lanes are available for the L2 oracle-admission field. Every narrow
field must use the common review packet and receipt schema in
`docs/oracle-program-operating-contract-ko.md`. A provider failure later in
the work is recorded as `BLOCKED_PROVIDER`, `BLOCKED_AUTH`,
`BLOCKED_RATE_LIMIT`, or `BLOCKED_TIMEOUT`; implementation may continue only
under the temporary-pending rule and the field remains non-FIX. The
machine-enforced receipt validation entry point is
`scripts/validate_supervisor_review_receipts.py`.

## Next field

The next implementation field remains source-bound L2 oracle admission across
the six local vulnerable applications. It is intentionally not a detector
expansion: the 414 existing candidates need machine-oracle records before they
can enter TP/FP/FN measurement.
