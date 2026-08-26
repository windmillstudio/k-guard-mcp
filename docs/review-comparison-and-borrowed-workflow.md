# Review Comparison And Borrowed Workflow

This note compares the attached "VibeSec MCP" product review with the current K-Guard MCP implementation.

## Verdict

K-Guard MCP is already deeper than the review concept in privacy evidence depth, Korean PII coverage, raw-free evidence, runtime MCP observation, and cross-plane analysis. The review is stronger in MCP client workflow naming: diff scan, fix recipe, deploy gate, and explicit MCP config review as separate tools.

## Where K-Guard Already Exceeds The Review

| Area | Review concept | K-Guard current state |
|---|---|---|
| Korean privacy | Generic PII/security scanner | Korean PII, Korean composite PII, PIPC-style metadata, Korean fixture FP/FN scoreboard |
| Evidence policy | Finding cards and explanations | Raw-free evidence hash, redaction-gated JSON/Markdown/SARIF/dashboard/MCP output |
| Data flow | Suggested source-to-sink analysis | JS/TS heuristic flow plus Python AST taint to log/response/DB/external HTTP/LLM/MCP sinks |
| Runtime MCP | Mostly MCP config/security awareness | Runtime MCP JSON/JSONL observer for tool result PII, secret, hidden instruction, and onward sink flow |
| Storage | Mentioned dependency/config | Read-only SQLite/log/json/csv/tsv connector and retention/deletion marker review |
| Cross-plane verdict | Not explicit | Korean PII + LLM/MCP/external/data-at-rest correlation |
| Dynamic probe | General safe probe idea | Baseline probe plus opt-in bounded deep exposure checks for env/git/backup/debug paths |
| Verification | Suggested tests | pytest, authorized dynamic harness, adversarial redaction corpus, fixture metrics, SARIF/CI |

## Borrowed From The Review

The review's strongest product idea is not another detector. It is the workflow vocabulary an IDE agent can choose naturally.

Borrowed and implemented:

- `scan_diff`: inspect the current git diff without returning raw diff text.
- `scan_mcp_config`: make MCP config review a first-class tool instead of hiding it inside workspace scan.
- `explain_rule`: turn a rule id into human-friendly impact, fix steps, tests, and verification.
- `suggest_fix`: return a dry-run fix recipe instead of applying code automatically.
- `guardian_audit`: provide the canonical pre-deploy release gate across workspace, HTTP, MCP runtime export, and prior reports.
- `security_gate`: provide a quick workspace-only pre-check, with Guardian remaining the release gate users should trust for ship/no-ship decisions.
- install and doctor flows for ChatGPT, Grok, Codex, and Antigravity.

## Still Useful Later

These ideas remain good future work, but are not implemented in this sprint:

- `apply_fix` with explicit approval and dry-run default.
- `generate_security_tests` that writes framework-specific regression tests.
- dedicated Next.js/Express/FastAPI/Supabase/Firebase IDOR/RLS/webhook/upload/XSS AST rules.
- additional signed distribution channels beyond the current Python wheel/sdist.
- MCP resources/prompts such as `kguard://report/latest` and a review-before-deploy prompt.

## Positioning

Do not present K-Guard as merely "VibeSec style general web scanner." The stronger positioning is:

K-Guard MCP is a local-first Korean privacy and MCP audit gate for vibe-coded apps. It shows where Korean personal data, secrets, runtime MCP tool outputs, local storage, and web responses can cross into logs, responses, external HTTP, LLMs, or MCP tools, while keeping evidence raw-free.

The borrowed workflow tools make that depth usable in the four supported clients: ChatGPT, Grok, Codex, and Antigravity. Cursor, Claude Code, and Cline configuration files may be audited as inputs, but those clients are not installation targets.
