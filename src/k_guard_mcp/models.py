from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from html import escape
from typing import Any

from k_guard_mcp.redaction import redact_text, sanitize_any, sanitize_untrusted_locator
from k_guard_mcp.severity import severity_rank, validate_confidence, validate_severity


@dataclass(frozen=True)
class Component:
    label: str
    evidence: str
    line: int | None = None


@dataclass(frozen=True)
class Entity:
    label: str
    evidence: str
    line: int
    context: str
    confidence: str = "medium"
    scope: str = "line"


@dataclass
class Finding:
    id: str
    source: str
    rule_id: str
    severity: str
    confidence: str
    title: str
    evidence: str
    why_it_matters: str
    recommendation: str
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    url: str | None = None
    method: str | None = None
    status: int | None = None
    scope: str | None = None
    artifact_scope: str | None = None
    components: list[Component] = field(default_factory=list)
    privacy_class: str | None = None
    pipc_basis: str | None = None
    audit_depth: int | None = None
    inspected_scope: str | None = None
    not_inspected: str | None = None
    fix_verification: str = "Re-run the same scan and confirm this finding is resolved."

    def __post_init__(self) -> None:
        self.severity = validate_severity(self.severity)
        self.confidence = validate_confidence(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        try:
            payload = asdict(self)
            payload["file"] = sanitize_untrusted_locator(self.file, "path")
            payload["url"] = sanitize_untrusted_locator(self.url, "url")
            return sanitize_any(payload)
        except Exception:
            return {
                "id": self.id,
                "source": self.source,
                "rule_id": self.rule_id,
                "severity": self.severity,
                "confidence": self.confidence,
                "title": "Redaction failed",
                "evidence": "<redaction-failed>",
                "why_it_matters": "Output was suppressed because the redaction layer failed.",
                "recommendation": "Inspect locally with debug tooling; do not publish unsanitized output.",
                "file": None,
                "line_start": None,
                "line_end": None,
                "url": None,
                "method": None,
                "status": None,
                "scope": None,
                "artifact_scope": None,
                "components": [],
                "privacy_class": None,
                "pipc_basis": None,
                "audit_depth": None,
                "inspected_scope": None,
                "not_inspected": None,
                "fix_verification": "Fix the redaction error and re-run the scan.",
            }

    def dedupe_key(self) -> tuple[Any, ...]:
        return (
            self.source,
            self.rule_id,
            self.file,
            self.line_start,
            self.line_end,
            self.url,
            self.method,
            self.status,
            self.evidence,
        )


@dataclass
class FlowNode:
    id: str
    kind: str
    label: str
    file: str | None = None
    line: int | None = None


@dataclass
class FlowEdge:
    source: str
    target: str
    label: str


@dataclass
class FlowMap:
    method: str = "heuristic"
    precision: str = "line-distance"
    nodes: list[FlowNode] = field(default_factory=list)
    edges: list[FlowEdge] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "experimental": True,
            "method": self.method,
            "precision": self.precision,
            "limitations": "Source-to-sink triage combines line-distance heuristics with Python AST, lightweight JS/TS taint, and limited JS/TS route-to-service summaries; confirm findings with code review.",
            "nodes": [
                {**asdict(node), "file": sanitize_untrusted_locator(node.file, "path")}
                for node in self.nodes
            ],
            "edges": [asdict(edge) for edge in self.edges],
            "findings": [finding.to_dict() for finding in self.findings],
            "mermaid": self.to_mermaid(),
            "svg": self.to_svg(),
        }

    def to_mermaid(self) -> str:
        lines = ["flowchart LR"]
        for node in self.nodes:
            safe_label = node.label.replace('"', "'")
            lines.append(f'  {node.id}["{safe_label}"]')
        for edge in self.edges:
            safe_label = edge.label.replace('"', "'")
            lines.append(f"  {edge.source} -->|{safe_label}| {edge.target}")
        return "\n".join(lines)

    def to_svg(self, max_nodes: int = 80, max_edges: int = 120) -> str:
        nodes = self.nodes[:max_nodes]
        node_ids = {node.id for node in nodes}
        edges = [edge for edge in self.edges if edge.source in node_ids and edge.target in node_ids][:max_edges]
        groups = {
            "source": [node for node in nodes if node.kind == "source"],
            "processor": [node for node in nodes if node.kind not in {"source", "sink"}],
            "sink": [node for node in nodes if node.kind == "sink"],
        }
        if not groups["processor"]:
            groups["processor"] = []
        max_rows = max(1, *(len(group) for group in groups.values()))
        width = 980
        height = max(300, 120 + max_rows * 78)
        columns = {"source": 120, "processor": 450, "sink": 780}
        positions: dict[str, tuple[int, int]] = {}

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Experimental data flow risk map" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            "<defs><marker id=\"arrow\" markerWidth=\"10\" markerHeight=\"10\" refX=\"8\" refY=\"3\" orient=\"auto\" markerUnits=\"strokeWidth\"><path d=\"M0,0 L0,6 L9,3 z\" fill=\"#475569\"/></marker></defs>",
            "<style>.kg-title{font:700 18px sans-serif;fill:#111827}.kg-note{font:12px sans-serif;fill:#475569}.kg-node{stroke:#334155;stroke-width:1.2;rx:8}.kg-source{fill:#dbeafe}.kg-processor{fill:#f1f5f9}.kg-sink{fill:#fee2e2}.kg-label{font:12px sans-serif;fill:#111827}.kg-meta{font:10px sans-serif;fill:#475569}.kg-edge{stroke:#475569;stroke-width:1.4;fill:none;marker-end:url(#arrow)}.kg-edge-label{font:10px sans-serif;fill:#334155}</style>",
            '<rect x="0" y="0" width="980" height="' + str(height) + '" fill="#ffffff"/>',
            '<text class="kg-title" x="24" y="32">K-Guard Data Flow Risk Map</text>',
            '<text class="kg-note" x="24" y="54">EXPERIMENTAL source-to-sink visualization. Confirm every path with code review.</text>',
            '<text class="kg-note" x="120" y="88">Sources</text>',
            '<text class="kg-note" x="450" y="88">Processing</text>',
            '<text class="kg-note" x="780" y="88">Sinks</text>',
        ]

        for kind, group in groups.items():
            x = columns[kind]
            if not group and kind == "processor":
                continue
            for index, node in enumerate(group):
                y = 116 + index * 78
                positions[node.id] = (x, y)
                parts.extend(_svg_node(node, x, y, kind))

        for edge in edges:
            if edge.source not in positions or edge.target not in positions:
                continue
            sx, sy = positions[edge.source]
            tx, ty = positions[edge.target]
            parts.append(f'<path class="kg-edge" d="M {sx + 172} {sy + 26} C {sx + 235} {sy + 26}, {tx - 48} {ty + 26}, {tx - 8} {ty + 26}"/>')
            label_x = (sx + tx) // 2 + 60
            label_y = (sy + ty) // 2 + 18
            parts.append(f'<text class="kg-edge-label" x="{label_x}" y="{label_y}">{_svg_text(edge.label, 54)}</text>')

        if len(self.nodes) > max_nodes or len(self.edges) > max_edges:
            parts.append(f'<text class="kg-note" x="24" y="{height - 24}">Visualization truncated: nodes {len(nodes)}/{len(self.nodes)}, edges {len(edges)}/{len(self.edges)}.</text>')
        parts.append("</svg>")
        return "".join(parts)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    flow_map: FlowMap | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> "ScanResult":
        deduped = _dedupe_findings(self.findings)
        deduped.sort(key=lambda item: (severity_rank(item.severity), item.file or "", item.line_start or 0, item.rule_id, item.evidence))
        self.findings = deduped
        if self.flow_map:
            flow_findings = _dedupe_findings(self.flow_map.findings)
            flow_findings.sort(key=lambda item: (severity_rank(item.severity), item.file or "", item.line_start or 0, item.rule_id, item.evidence))
            self.flow_map.findings = flow_findings
        return self

    def summary(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        try:
            payload = {
                "summary": self.summary(),
                "findings": [finding.to_dict() for finding in self.findings],
                "flow_map": self.flow_map.to_dict() if self.flow_map else None,
            }
            if self.metadata:
                payload["metadata"] = self.metadata
            return sanitize_any(payload)
        except Exception:
            return {
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
                "findings": [
                    {
                        "id": "redaction-failed",
                        "source": "report",
                        "rule_id": "REPORT_REDACTION_FAILED",
                        "severity": "info",
                        "confidence": "high",
                        "title": "Redaction failed",
                        "evidence": "<redaction-failed>",
                        "why_it_matters": "Report output was suppressed because the redaction layer failed.",
                        "recommendation": "Fix the redaction error and re-run the scan locally.",
                    }
                ],
                "flow_map": None,
            }


def _report_dedupe_key(finding: Finding) -> tuple[Any, ...]:
    evidence = str(finding.evidence or "")
    selected_semantic_rule = "detector_subtype=" in evidence and finding.rule_id.startswith(("WEB_", "API_", "AUTH_"))
    multipath_sink_rule = finding.rule_id.startswith(("AST_TAINT_", "FLOW_", "JS_TS_TAINT_")) or (
        "source_line=" in evidence and ("sink_line=" in evidence or "call_line=" in evidence)
    )
    if "object_ref=" not in evidence and (selected_semantic_rule or multipath_sink_rule):
        return (
            "sink-action",
            finding.rule_id,
            finding.file,
            finding.line_start,
            finding.line_end,
            finding.url,
            finding.method,
            finding.status,
            finding.scope,
            finding.artifact_scope,
        )
    return ("exact", *finding.dedupe_key())


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    by_key: dict[tuple[Any, ...], Finding] = {}
    for finding in findings:
        key = _report_dedupe_key(finding)
        current = by_key.get(key)
        if current is None:
            by_key[key] = replace(finding, components=list(finding.components))
            continue
        by_key[key] = _merge_duplicate_findings(current, finding, preserve_traces=key[0] == "sink-action")
    return list(by_key.values())


def _merge_duplicate_findings(current: Finding, incoming: Finding, *, preserve_traces: bool) -> Finding:
    components = _merge_components(current.components, incoming.components)
    if preserve_traces and (current.source, current.evidence) != (incoming.source, incoming.evidence):
        components = _merge_components(
            components,
            [_source_trace_component(current), _source_trace_component(incoming)],
        )
    severity = current.severity if severity_rank(current.severity) <= severity_rank(incoming.severity) else incoming.severity
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    confidence = current.confidence if confidence_rank[current.confidence] <= confidence_rank[incoming.confidence] else incoming.confidence
    audit_depths = [depth for depth in (current.audit_depth, incoming.audit_depth) if depth is not None]
    return replace(
        current,
        severity=severity,
        confidence=confidence,
        audit_depth=max(audit_depths) if audit_depths else None,
        components=components,
    )


def _merge_components(first: list[Component], second: list[Component]) -> list[Component]:
    merged: list[Component] = []
    seen: set[tuple[str, str, int | None]] = set()
    for component in [*first, *second]:
        key = (component.label, component.evidence, component.line)
        if key in seen:
            continue
        seen.add(key)
        merged.append(component)
    return merged


def _source_trace_component(finding: Finding) -> Component:
    match = re.search(r"\bsource_line=(\d+)\b", str(finding.evidence or ""))
    line = int(match.group(1)) if match else finding.line_start
    return Component(
        label=f"source_trace:{finding.source}",
        evidence=str(finding.evidence or ""),
        line=line,
    )


def _svg_node(node: FlowNode, x: int, y: int, kind: str) -> list[str]:
    css_kind = "kg-processor" if kind == "processor" else f"kg-{kind}"
    location = ""
    if node.file:
        location = _flow_display_path(str(sanitize_untrusted_locator(node.file, "path") or ""))
        if node.line:
            location = f"{location}:{node.line}"
    return [
        f'<rect class="kg-node {css_kind}" x="{x}" y="{y}" width="180" height="52"/>',
        f'<text class="kg-label" x="{x + 10}" y="{y + 21}">{_svg_text(node.label, 28)}</text>',
        f'<text class="kg-meta" x="{x + 10}" y="{y + 39}">{_svg_text(location or node.kind, 34)}</text>',
    ]


def _flow_display_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    absolute = normalized.startswith("/") or (len(normalized) >= 3 and normalized[1:3] == ":/")
    if not absolute:
        return value
    parts = [part for part in normalized.split("/") if part]
    return "<local>/" + "/".join(parts[-3:])


def _svg_text(value: str, max_len: int) -> str:
    text = redact_text(str(value)).replace("\n", " ").replace("\r", " ")
    if len(text) > max_len:
        text = text[: max_len - 1] + "..."
    return escape(text, quote=True)
