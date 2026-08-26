# Upstream Adoption Record

This record separates adopted implementation from product ideas that were only
reviewed. It exists so release reviewers can reproduce the licensing decision.

| Upstream | Revision | License | Decision | K-Guard change |
|---|---|---|---|---|
| Pipelock core | `8d401dc2d3228bab61f5321e30590defe51d8ead` | Apache-2.0 | Adapt a bounded subset with attribution | Unicode/confusable/invisible normalization before MCP threat matching |
| Pipelock enterprise | same checkout | Elastic License 2.0 | Excluded | No code, rules, or assets used |
| Snyk Agent Scan | `f3a4621a089c937ee3586917e04a4c26a6c6d27c` | Apache-2.0 | Clean-room pattern adoption | Known-path plus bounded recursive MCP config discovery |
| Cisco MCP Scanner | `2dff7041427d5f7234ba86a1ab455846b3cffdc7` | Apache-2.0 | Clean-room bounded design adoption | Unique-import Python parameter-to-sink summaries across files |
| AgentShield | `25d91f0002214c408da4ceaac7def20bad40ca10` | MIT | Reviewed only | No code incorporated in this change |
| MCP Firewall | reviewed separately | AGPL-3.0 | Idea boundary only | No code incorporated |

## Detection Contract Added

- Unicode NFKC, format/invisible control removal, selected cross-script
  confusables, escaped text, percent/HTML decoding, Base64 payloads, split code
  fragments, and three-line rolling windows are scanned with strict budgets.
- Findings retain only HMAC evidence hashes, detector subtype, transform mode,
  and line range. Decoded or original payloads are not returned.
- JSON MCP server maps are parsed for shell wrappers, mutable package execution,
  plain remote HTTP, and fixed credentials.
- Discovery overflow, unsafe links, and read failures produce high-severity
  coverage findings instead of a silent pass.

## Claims Not Made

This change does not provide exhaustive Unicode confusable coverage, decrypt or
decompress arbitrary payloads, prove package ownership, execute MCP servers, or
replace Guardian's runtime and field-accuracy gates.
