# K-Guard MCP Threat Model and Non-Goals

## Scope

K-Guard MCP is a local-first scanner for vibe-coded repositories. It inspects source files, selected configuration files, localhost HTTP responses, explicitly authorized external HTTP responses, and heuristic data-flow signals before a developer shares code, logs, screenshots, or generated artifacts with another tool or person.

## Protected Assets

- Korean personal data, including direct identifiers and identifying combinations.
- Secrets such as API keys, database URLs, private keys, JWTs, and cloud credentials.
- Local source code context that may reveal sensitive implementation details.
- Scan reports exported through CLI, JSON, Markdown, or MCP tool responses.
- Local SVG/HTML flow visualizations exported from scan results.

## Trust Boundaries

- The scanned repository is treated as untrusted input.
- Repository text is analyzed as data by deterministic local detectors and is never promoted to an agent instruction by K-Guard.
- Serialized outputs are treated as potentially shareable artifacts and must pass through central redaction.
- Dynamic probing is restricted to localhost, `127.0.0.1`, and `::1` by default.
- External dynamic probing is in scope only when the operator records an authorization basis: owned target, partner approval, bug-bounty scope, configured allowlist, or domain proof in the dashboard.
- Redirects to non-allowlisted hosts are detected but not followed.
- MCP clients are treated as callers that may display or forward results, so MCP responses are sanitized.
- A client or independent reviewer that chooses to read source files directly crosses a separate trust boundary and must isolate repository text from its instruction channel.

## In-Scope Threats

- Raw personal data or secrets appearing in JSON, Markdown, or MCP responses.
- Raw personal data or secrets appearing in SVG/HTML flow visualizations.
- Obfuscated values using base64, hex, zero-width characters, homoglyph-like spacing, split lines, nested JSON, or CRLF formatting.
- Korean composite personal data, where separate weak identifiers become high-risk when joined in one semantic record.
- Public client environment variable misuse, debug settings, permissive CORS, and source map exposure.
- Localhost or explicitly authorized external endpoints that return sensitive data, headers, debug traces, exposed metadata, backup files, debug/runtime endpoints, or unsafe redirects.
- Experimental heuristic source-to-sink flows from request, environment, storage, or database reads to logs, responses, files, external HTTP, or MCP responses.
- Direct web/API/auth failure patterns including request-to-SQL/command/path/URL/HTML sinks, mass assignment, open redirect, browser token storage, weak cookie flags, plaintext password comparison, and decode-only JWT handling.
- Korean high-impact data field declarations without uncommented, field-correlated encryption/tokenization, access-control, or access-audit evidence.
- Release-readiness gaps such as missing JavaScript dependency lockfiles, CI gate evidence, authentication tests, or API rate-limit markers.

## Non-Goals

- This is not a formal AST taint-analysis engine.
- This is not a runtime intrusion detector or WAF.
- This does not validate whether a secret is live with an external provider.
- This does not scan production traffic or remote third-party websites by default.
- This does not perform unauthorized external scanning; external probes require operator opt-in and recorded authorization evidence.
- This does not guarantee legal compliance; it provides developer-facing risk evidence and fix guidance.
- This does not replace human review for release, privacy impact assessment, or legal approval.
- The `korean_senior` profile proves that four automated review domains ran under the recorded scope; it does not understand business intent like a human senior, prove exploitability, or certify Korean privacy-law compliance.
- Dynamic findings store only redacted fingerprints, detector subtype, body/header location, and keyed response hashes; matching hashes support reproducibility checks but are not proof that two deployments are semantically identical.

## Safety Controls

- Central redaction is applied at model serialization and report rendering.
- SVG/HTML flow visualizations are local, dependency-free, and redaction-gated.
- Flow visualization text is XML/HTML-escaped separately from PII redaction so repo-derived labels cannot break out of SVG/HTML structure.
- Redaction failure is fail-closed: output is replaced with a redaction-failed finding instead of raw evidence.
- Dynamic HTTP probing blocks non-local hosts before request execution unless the target is explicitly authorized and allowlisted for that audit.
- Redirect responses are inspected without automatically following them.
- MCP `probe_http` is disabled by default and requires `K_GUARD_MCP_ENABLE_PROBE=1` opt-in for trusted localhost targets.
- MCP external `probe_http` additionally requires `K_GUARD_MCP_ENABLE_EXTERNAL_PROBE=1` and either `K_GUARD_MCP_EXTERNAL_ALLOWED_HOSTS` or per-call `external_authorized=true` with an authorization note.
- Dynamic probes pin `localhost` requests to literal `127.0.0.1` before HTTP execution to avoid hostname resolution drift.
- MCP tool arguments and inline text have explicit default budgets to reduce resource-exhaustion risk.
- Workspace file enumeration stops after the configured file limit plus one overflow entry during MCP preflight.
- Guardian compares content-addressed source-tree snapshots before and after each workspace audit; a mismatch is a blocking coverage failure. Immutable CI checkouts remain the release-authority boundary because this is detection, not filesystem transaction locking.
- Findings use validated severity and confidence values.
- Workspace review metadata records `repository_content_role=data_only`, `raw_source_returned=false`, and the separate client-read boundary.
- Results are deduplicated and sorted to keep reviewable output.
- Flow graph edges are capped per file and link nearest sinks by kind to avoid noisy denial-of-review reports.
- MCP workspace budgets are calculated after applying dependency/cache exclusions such as `.git`, `node_modules`, `.venv`, `__pycache__`, and generated cache subtrees. Deployable `build`, `dist`, `.next` source text and source maps remain audit candidates; oversized, unreadable, symlinked, or changed candidates fail closed.

## Known Residual Risks

- Regex-based detectors can miss novel obfuscation or produce false positives in domain-specific text.
- Experimental heuristic flow analysis may miss cross-file, framework-specific, or asynchronous flows.
- Encoded-content detection only redacts decoded content that matches known sensitive patterns.
- Binary formats such as HWP, DOCX, PDFs, images, and archives require additional extractors.
- MCP SDK behavior should be regression-tested on every supported SDK version.

## Release Gate

A commercial release candidate must pass:

- Unit and integration tests, including actual MCP SDK integration.
- At least 30 adversarial redaction cases.
- Korean fixture recall of at least 95 percent.
- Korean fixture false-positive rate no higher than 20 percent for measurable negatives.
- At least three positive and two negative Korean governance workspace cases with all required unique/sensitive/linkable/access-log rules observed.
- Guardian and every release target fixed at `fail_on=high`, with high/critical findings and four-domain target evidence recomputed by the data-release gate.
- Dependency audit with zero known vulnerabilities in the tested environment.
- CycloneDX SBOM generation.
- Large-repository benchmark with throughput and flow-edge caps met.
