from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from k_guard_mcp.collector import collect_files, is_semantic_noise_asset, read_text
from k_guard_mcp.hashing import evidence_hash
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding, FlowEdge, FlowMap, FlowNode
from k_guard_mcp.taint import JS_TS_SUFFIXES, AstTaintAnalyzer


SOURCE_PATTERNS = [
    ("request_body", re.compile(r"\b(req|request)\.(body|json|form|query|params)\b|formData\(", re.IGNORECASE)),
    ("env", re.compile(r"\b(process\.env|os\.environ|getenv)\b", re.IGNORECASE)),
    ("storage", re.compile(r"\b(localStorage|sessionStorage|cookies?\b)", re.IGNORECASE)),
    ("db_read", re.compile(r"\b(findUnique|findMany|select\s+.+\s+from|\.find\(|\.query\()", re.IGNORECASE)),
    ("llm_context", re.compile(r"\b(messages|prompt|systemPrompt|developerMessage|chat\.completions|responses\.create)\b", re.IGNORECASE)),
    ("mcp_input", re.compile(r"\b(FastMCP|@mcp\.tool|tool_input|toolInput|ctx\.request|params)\b", re.IGNORECASE)),
]

SOURCE_PREFILTERS = {
    "request_body": ("req.", "request.", "formdata("),
    "env": ("process.env", "os.environ", "getenv"),
    "storage": ("localstorage", "sessionstorage", "cookie"),
    "db_read": ("findunique", "findmany", "select", ".find(", ".query("),
    "llm_context": ("messages", "prompt", "chat.completions", "responses.create"),
    "mcp_input": ("fastmcp", "@mcp.tool", "tool_input", "toolinput", "ctx.request", "params"),
}

SINK_PATTERNS = [
    ("log", re.compile(r"\b(console\.log|logger\.(info|debug|warn|error)|print\()", re.IGNORECASE)),
    ("response", re.compile(r"\b(res\.json|response\.json|jsonify|return\s+.*Response)\b", re.IGNORECASE)),
    ("external_http", re.compile(r"\b(fetch|axios\.|requests\.|httpx\.)", re.IGNORECASE)),
    ("db_write", re.compile(r"\b(create|update|insert\s+into|save\(|\.set\()", re.IGNORECASE)),
    ("file_write", re.compile(r"\b(writeFile|open\(.*['\"]w|fs\.write)", re.IGNORECASE)),
    ("mcp_response", re.compile(r"\b@mcp\.tool|FastMCP|return\s+.*tool", re.IGNORECASE)),
    ("llm_call", re.compile(r"\b(openai|anthropic|gemini|chat\.completions|responses\.create|generateContent)\b", re.IGNORECASE)),
    ("mcp_tool_call", re.compile(r"\b(call_tool|tool_call|use_mcp_tool|mcp\.tool|FastMCP|ClientSession)\b", re.IGNORECASE)),
]

SINK_PREFILTERS = {
    "log": ("console.log", "logger.", "print("),
    "response": ("res.json", "response.json", "jsonify", "return"),
    "external_http": ("fetch", "axios.", "requests.", "httpx."),
    "db_write": ("create", "update", "insert", "save(", ".set("),
    "file_write": ("writefile", "open(", "fs.write"),
    "mcp_response": ("@mcp.tool", "fastmcp", "return"),
    "llm_call": ("openai", "anthropic", "gemini", "chat.completions", "responses.create", "generatecontent"),
    "mcp_tool_call": ("call_tool", "tool_call", "use_mcp_tool", "mcp.tool", "fastmcp", "clientsession"),
}

FLOW_PREFILTERS = tuple(
    sorted({marker for markers in (*SOURCE_PREFILTERS.values(), *SINK_PREFILTERS.values()) for marker in markers})
)
SENSITIVE_PREFILTERS = (
    "email",
    "phone",
    "name",
    "address",
    "rrn",
    "birth",
    "token",
    "secret",
    "password",
    "apikey",
    "api_key",
    "api-key",
    "주민",
    "전화",
    "이메일",
    "주소",
    "이름",
)

SENSITIVE_HINT = re.compile(r"(email|phone|name|address|rrn|birth|token|secret|password|api[_-]?key|주민|전화|이메일|주소|이름)", re.IGNORECASE)
FLOW_HINT = re.compile(
    r"(req\.|request\.|formData\(|process\.env|os\.environ|getenv|localStorage|sessionStorage|cookies?\b|"
    r"findUnique|findMany|select\s+.+\s+from|\.find\(|\.query\(|messages|prompt|systemPrompt|"
    r"developerMessage|chat\.completions|responses\.create|FastMCP|@mcp\.tool|tool_input|toolInput|"
    r"ctx\.request|params|console\.log|logger\.|print\(|res\.json|response\.json|jsonify|return\s+.*Response|"
    r"fetch|axios\.|requests\.|httpx\.|create|update|insert\s+into|save\(|\.set\(|writeFile|open\(.*['\"]w|"
    r"fs\.write|return\s+.*tool|openai|anthropic|gemini|generateContent|call_tool|tool_call|use_mcp_tool|"
    r"mcp\.tool|ClientSession)",
    re.IGNORECASE,
)


class FlowAnalyzer:
    def __init__(self, id_factory: IdFactory | None = None, max_line_distance: int = 30, max_edges_per_file: int = 60, max_findings_per_rule_per_file: int = 20) -> None:
        self.ids = id_factory or IdFactory()
        self.max_line_distance = max_line_distance
        self.max_edges_per_file = max_edges_per_file
        self.max_findings_per_rule_per_file = max_findings_per_rule_per_file
        self.ast_taint = AstTaintAnalyzer(self.ids)

    def build(self, root: str | Path) -> FlowMap:
        flow = FlowMap(method="heuristic+ast-taint+js-ts-taint", precision="line-distance+python-intra-procedural-ast+js-ts-intra-file+limited-interprocedural-taint")
        node_counter = 0
        node_ids: dict[tuple[str, int, str], str] = {}
        edge_seen: set[tuple[str, str, str]] = set()
        files: list[tuple[Path, str]] = []
        self.ast_taint.reset_project_summaries()
        for path in collect_files(root):
            if path.suffix.lower() not in {*JS_TS_SUFFIXES, ".py"}:
                continue
            text = read_text(path)
            if not text:
                continue
            if is_semantic_noise_asset(path, text):
                continue
            files.append((path, text))
            self.ast_taint.collect_project_file(path, text)
        for path, text in files:
            self.ast_taint.append_file(flow, path, text)
            sources, sinks = self._scan_file(path, text)
            if not sources or not sinks:
                continue
            file_edge_count = 0
            file_finding_counts: dict[str, int] = {}
            for source in sources:
                if not source["sensitive"]:
                    continue
                if file_edge_count >= self.max_edges_per_file:
                    break
                source_id, node_counter = _node_id(flow, node_ids, node_counter, "source", source, path)
                for sink in _nearest_sinks_by_kind(source, sinks, self.max_line_distance):
                    if file_edge_count >= self.max_edges_per_file:
                        break
                    sink_id, node_counter = _node_id(flow, node_ids, node_counter, "sink", sink, path)
                    edge_key = (source_id, sink_id, "nearest line-distance heuristic")
                    if edge_key not in edge_seen:
                        edge_seen.add(edge_key)
                        flow.edges.append(FlowEdge(source_id, sink_id, "nearest line-distance heuristic"))
                        file_edge_count += 1
                    if sink["kind"] == "log":
                        _append_capped_finding(
                            flow,
                            file_finding_counts,
                            self.max_findings_per_rule_per_file,
                            Finding(
                                id=self.ids.next(),
                                source="flow",
                                rule_id="FLOW_PII_TO_LOG",
                                severity="medium",
                                confidence="low",
                                title="Sensitive input may flow to logs",
                                file=str(path),
                                line_start=int(sink["line"]),
                                line_end=int(sink["line"]),
                                evidence=_edge_evidence(source, sink),
                                why_it_matters="Logs often leave the application boundary and may retain personal data or secrets.",
                                recommendation="Avoid logging whole request/user objects; log minimal IDs or masked fields.",
                                audit_depth=4,
                                inspected_scope="Static source-to-sink evidence graph linked sensitive source and log sink by file, line, and raw-free line hashes.",
                                not_inspected="This edge is heuristic and does not prove runtime execution or request authorization state.",
                            ),
                        )
                    if sink["kind"] == "external_http" and source["sensitive"]:
                        _append_capped_finding(
                            flow,
                            file_finding_counts,
                            self.max_findings_per_rule_per_file,
                            Finding(
                                id=self.ids.next(),
                                source="flow",
                                rule_id="FLOW_SENSITIVE_TO_EXTERNAL_HTTP",
                                severity="medium",
                                confidence="low",
                                title="Sensitive input may flow to external HTTP call",
                                file=str(path),
                                line_start=int(sink["line"]),
                                line_end=int(sink["line"]),
                                evidence=_edge_evidence(source, sink),
                                why_it_matters="Sensitive data sent to external services can become a privacy or compliance risk.",
                                recommendation="Verify data minimization, user consent, and masking before external transmission.",
                                audit_depth=4,
                                inspected_scope="Static source-to-sink evidence graph linked sensitive source and outbound HTTP sink by file, line, and raw-free line hashes.",
                                not_inspected="This edge is heuristic and does not prove the external request executes with real user data.",
                            ),
                        )
                    if sink["kind"] in {"llm_call", "mcp_tool_call", "mcp_response"} and source["sensitive"]:
                        _append_capped_finding(
                            flow,
                            file_finding_counts,
                            self.max_findings_per_rule_per_file,
                            Finding(
                                id=self.ids.next(),
                                source="flow",
                                rule_id="FLOW_SENSITIVE_TO_AGENTIC_SINK",
                                severity="medium",
                                confidence="low",
                                title="Sensitive input may flow to LLM or MCP tool boundary",
                                file=str(path),
                                line_start=int(sink["line"]),
                                line_end=int(sink["line"]),
                                evidence=_edge_evidence(source, sink),
                                why_it_matters="LLM and MCP tool boundaries can forward personal data into prompts, tool outputs, logs, or third-party services.",
                                recommendation="Minimize and redact personal data before LLM/MCP calls, and document the approved sink purpose.",
                                audit_depth=4,
                                inspected_scope="Static source-to-sink evidence graph linked sensitive source and LLM/MCP sink by file, line, and raw-free line hashes.",
                                not_inspected="This edge is heuristic and does not intercept live tool calls or model requests.",
                            ),
                        )
        return flow

    def _scan_file(self, path: Path, text: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        sources: list[dict[str, object]] = []
        sinks: list[dict[str, object]] = []
        for idx, line in enumerate(text.splitlines(), start=1):
            for role, kind, sensitive, line_hash in _flow_line_signals(line):
                if role == "source":
                    sources.append({"kind": kind, "line": idx, "label": f"{kind} at {path.name}:{idx}", "sensitive": sensitive, "line_hash": line_hash})
                    continue
                if kind == "log" and self.ast_taint.python_log_line_is_inactive(path, line):
                    continue
                sinks.append({"kind": kind, "line": idx, "label": f"{kind} at {path.name}:{idx}", "sensitive": sensitive, "line_hash": line_hash})
        return sources, sinks


@lru_cache(maxsize=32768)
def _flow_line_signals(line: str) -> tuple[tuple[str, str, bool, str], ...]:
    lower = line.lower()
    if not any(marker in lower for marker in FLOW_PREFILTERS):
        return ()
    source_kinds = tuple(
        kind
        for kind, pattern in SOURCE_PATTERNS
        if any(marker in lower for marker in SOURCE_PREFILTERS[kind]) and pattern.search(line)
    )
    sink_kinds = tuple(
        kind
        for kind, pattern in SINK_PATTERNS
        if any(marker in lower for marker in SINK_PREFILTERS[kind]) and pattern.search(line)
    )
    if not source_kinds and not sink_kinds:
        return ()
    sensitive = any(marker in lower for marker in SENSITIVE_PREFILTERS)
    line_hash = evidence_hash(line)
    return tuple(
        [("source", kind, sensitive, line_hash) for kind in source_kinds]
        + [("sink", kind, sensitive, line_hash) for kind in sink_kinds]
    )


def _node_id(flow: FlowMap, node_ids: dict[tuple[str, int, str], str], node_counter: int, kind: str, item: dict[str, object], path: Path) -> tuple[str, int]:
    key = (str(path), int(item["line"]), str(item["kind"]))
    if key in node_ids:
        return node_ids[key], node_counter
    node_counter += 1
    node_id = f"N{node_counter}"
    node_ids[key] = node_id
    flow.nodes.append(FlowNode(node_id, kind, str(item["label"]), str(path), int(item["line"])))
    return node_id, node_counter


def _nearest_sinks_by_kind(source: dict[str, object], sinks: list[dict[str, object]], max_line_distance: int) -> list[dict[str, object]]:
    nearest: dict[str, dict[str, object]] = {}
    source_line = int(source["line"])
    for sink in sinks:
        distance = abs(source_line - int(sink["line"]))
        if distance > max_line_distance:
            continue
        kind = str(sink["kind"])
        previous = nearest.get(kind)
        if previous is None or distance < abs(source_line - int(previous["line"])):
            nearest[kind] = sink
    return list(nearest.values())


def _append_capped_finding(flow: FlowMap, counts: dict[str, int], limit: int, finding: Finding) -> None:
    count = counts.get(finding.rule_id, 0)
    if count >= limit:
        return
    counts[finding.rule_id] = count + 1
    flow.findings.append(finding)


def _edge_evidence(source: dict[str, object], sink: dict[str, object]) -> str:
    return (
        f"{source['label']} -> {sink['label']}; "
        f"source_hash={source.get('line_hash', 'unknown')} sink_hash={sink.get('line_hash', 'unknown')}"
    )
