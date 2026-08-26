# Commercial Claims and Roadmap Guardrails

## Allowed Claims

- K-Guard MCP is a local-first scanner for source repositories and localhost app probes.
- It detects common Korean PII patterns, common secret formats, risky configuration, and experimental heuristic source-to-sink flow candidates.
- Korean business registration numbers are organization identifiers bounded by checksum syntax validation on synthetic/vendor-authored fixtures. They are not natural-person PII and not independent field or live registry validation.
- Historical Korean corporate registration numbers (before 2025-01-31) may be recognized with the old Annex alternating 1,2 checksum. Current numbers are 4+2+7 digits with no checksum; explicit field context yields unverified syntax/context recognition only, never registry validation.
- Privacy-first ambiguity: if a 13-digit value is a plausible Korean resident or foreigner registration number, that natural-person ID wins over a corporate/business label, CSV header, or split JSON key. It is emitted and redacted as RRN/FRN, never as an organization identifier.
- The frozen 68-case Korean sensitive/org holdout is an evaluator-authored post-implementation inspection of synthetic oracles. Scoring is per-case any-rule recall (`must_all` plus each `must_any` group, minus `forbidden`). A 68/68 exact-repeat result is not blind evaluation, field accuracy, or live registry validation.
- Korean fixture-corpus FPR is `false_positive_count / measurable_negative_count`. `negative_count` is every declared negative case. `targeted_absence_case_count` is negatives that only assert selected rules are absent and are excluded from the FPR denominator. A zero measurable-negative denominator is reported as 0.0, not as coverage or validity.
- It redacts serialized JSON, Markdown, flow-map report output, and MCP responses.
- It does not follow redirects to non-allowlisted hosts during dynamic probing.

## Claims Not Allowed

- Do not claim legal compliance certification.
- Do not claim full runtime taint analysis.
- Do not claim live secret validation with external vendors.
- Do not claim complete binary document coverage.
- Do not market perfect detection from small fixture scores.
- Do not treat context-only current corporate numbers as registry-validated.
- Do not claim the 68-case holdout as blind, field-accuracy, or registry-validation evidence.
- Do not present Korean fixture FPR as if every targeted-absence case were in the denominator.

## Binary Extractor Roadmap

- Phase 1: archive traversal with size and depth caps.
- Phase 2: PDF and Office text extraction with redaction-gated reports.
- Phase 3: HWP/HWPX extraction for Korean document workflows.
- Phase 4: image OCR for screenshots and scanned forms.

Each extractor must ship with fixture corpora, redaction bypass tests, size caps, and timeout controls.

## Operational Runbook for Integrators

- Run the MCP server locally or inside a trusted developer network boundary.
- Treat MCP tool arguments as untrusted input.
- Keep MCP `probe_http` disabled by default; enable it with `K_GUARD_MCP_ENABLE_PROBE=1` only for trusted localhost test targets.
- Treat `MCP_PROBE_ENABLED_AUDIT` findings as activation records for partner reviews.
- Keep MCP argument and inline-text budgets enabled unless a deployment owner explicitly approves a higher limit.
- Keep MCP logs off by default for scan payloads.
- Do not forward raw scanner exceptions to users or external telemetry.
- Pin tool versions in internal deployment manifests.
- Keep generated reports local unless organizational policy allows sharing.
- Use `k-guard feedback --type fp|fn --rule RULE --text TEXT --output feedback.jsonl` to capture sanitized drift reports.
- Use `k-guard feedback-export --input feedback.jsonl --output feedback-summary.json --reviewed` to summarize local false-positive and false-negative drift before corpus updates.
- Treat false-negative feedback as higher leakage risk; FN snippets use extra conservative token masking because the detector may have missed the sensitive value.
- `feedback-export` fails closed unless `--reviewed` or `K_GUARD_FEEDBACK_EXPORT_REVIEWED=1` is supplied.
- Review exported feedback summaries before any external transmission; never transmit raw feedback logs.
- Track field FP/FN rates separately from fixture scores and block GA-level accuracy claims until design-partner data has an agreed baseline.
