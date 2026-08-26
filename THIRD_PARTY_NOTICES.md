# Third-Party Notices

K-Guard MCP is primarily distributed under the MIT License. The following
upstream work informed or was adapted by the files named below.

## Pipelock

- Project: `https://github.com/luckyPipewrench/pipelock`
- Reviewed revision: `8d401dc2d3228bab61f5321e30590defe51d8ead`
- Upstream file: `internal/normalize/normalize.go`
- Upstream copyright: Copyright 2026 Josh Waldrep
- License: Apache License 2.0, reproduced in `LICENSES/Apache-2.0.txt`
- K-Guard file: `src/k_guard_mcp/mcp_normalization.py`
- Modifications: reimplemented in Python; reduced the confusable table to the
  MCP threat vocabulary; added strict size/count budgets, percent/HTML/Unicode
  escape decoding, bounded Base64 replacement, source-line mapping, code
  fragment collapse, and rolling multi-line candidates.
- Exclusion: no file under Pipelock's `enterprise/` directory was copied or
  adapted.

## Snyk Agent Scan

- Project: `https://github.com/snyk/agent-scan`
- Reviewed revision: `f3a4621a089c937ee3586917e04a4c26a6c6d27c`
- Upstream reference: `src/agent_scan/well_known_clients.py`
- License: Apache License 2.0, reproduced in `LICENSES/Apache-2.0.txt`
- K-Guard file: `src/k_guard_mcp/server.py`
- Use: the well-known-client inventory pattern informed K-Guard's independently
  implemented, bounded config discovery. K-Guard keeps its install contract
  limited to ChatGPT, Grok, Codex, and Antigravity.

## Cisco MCP Scanner

- Project: `https://github.com/cisco-ai-defense/mcp-scanner`
- Reviewed revision: `2dff7041427d5f7234ba86a1ab455846b3cffdc7`
- Upstream reference: `mcpscanner/core/static_analysis/interprocedural/cross_file_analyzer.py`
- Upstream copyright: Copyright 2025 Cisco Systems, Inc. and its affiliates
- License: Apache License 2.0, reproduced in `LICENSES/Apache-2.0.txt`
- K-Guard file: `src/k_guard_mcp/taint.py`
- Use: the reverse entry-parameter/call-graph analysis design informed a
  clean-room bounded Python AST function-summary pass. K-Guard's implementation
  requires a unique imported helper and direct parameter dependency before it
  raises an existing sink rule.

Apache names and project names are used only for attribution. They do not imply
endorsement of K-Guard MCP.

## Tree-sitter

- Projects: `https://github.com/tree-sitter/py-tree-sitter` and
  `https://github.com/tree-sitter/tree-sitter-java`
- Packages: `tree-sitter==0.26.0` and `tree-sitter-java==0.23.5`
- License: MIT, reproduced in `LICENSES/Tree-sitter-MIT.txt` and
  `LICENSES/Tree-sitter-Java-MIT.txt`
- K-Guard file: `src/k_guard_mcp/java_flow.py`
- Use: parse Java into a concrete syntax tree before bounded request-to-SQL
  flow analysis. K-Guard's control-flow, collection, helper-summary, source,
  and sink logic is independently implemented.

## CLCERT Beacon Verifier

- Project: `https://github.com/clcert/beacon-verifier`
- Reviewed revision: `7523756d84c309a01b3606b0602e8d082a47d867`
- Upstream reference: `docs/signature.md` and
  `scripts/chain_consistency_version2.py`
- Upstream copyright: Copyright 2018 CLCERT - University of Chile
- License: MIT, reproduced in `LICENSES/CLCERT-Beacon-Verifier-MIT.txt`
- K-Guard file: `src/k_guard_mcp/h100_selector.py`
- Use: the public NIST Beacon 2.0 signed-message field ordering and verifier
  workflow informed an independently bounded implementation that additionally
  validates the system trust path, certificate ID, output hash, adjacent pulse
  link, precommitment, candidate seal, and H100 quotas.

## PyYAML

- Project: `https://github.com/yaml/pyyaml`
- Package: `PyYAML>=6.0.2,<7`
- License: MIT, reproduced in `LICENSES/PyYAML-MIT.txt`
- K-Guard file: `src/k_guard_mcp/detectors/config.py`
- Use: parse GitHub Actions workflow structure before assigning mutable-action
  findings to supporting-review or manual-hold lanes.
