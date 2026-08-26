from __future__ import annotations

import json
from html import escape
from pathlib import Path

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.models import ScanResult
from k_guard_mcp.redaction import redact_text
from k_guard_mcp.release_policy import is_release_blocking_finding
from k_guard_mcp.severity import severity_rank


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def write_json(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(to_json(result), encoding="utf-8")


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict[str, object]] = {}
    sarif_results: list[dict[str, object]] = []
    for finding in result.findings:
        safe = finding.to_dict()
        rule_id = str(safe.get("rule_id") or finding.rule_id)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": redact_text(str(safe.get("title") or finding.title))},
                "fullDescription": {"text": redact_text(str(safe.get("why_it_matters") or finding.why_it_matters))},
                "help": {"text": redact_text(str(safe.get("recommendation") or finding.recommendation))},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "source": finding.source,
                    "tags": _rule_tags(rule_id),
                },
            }
        location = _sarif_location(safe)
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": redact_text(str(safe.get("evidence") or ""))},
                "locations": [location],
                "partialFingerprints": {
                    "kGuardFinding": evidence_hash("|".join(str(part) for part in finding.dedupe_key())),
                },
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "source": finding.source,
                    "privacy_class": safe.get("privacy_class"),
                    "audit_depth": safe.get("audit_depth"),
                    "pipc_basis": safe.get("pipc_basis"),
                    "inspected_scope": safe.get("inspected_scope"),
                    "not_inspected": safe.get("not_inspected"),
                    "evidence_hash_scheme": evidence_hash_scheme(),
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "K-Guard MCP",
                        "informationUri": "https://github.com/local/k-guard-mcp",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "raw_free": True,
                    "local_first": True,
                    "summary": result.summary(),
                    "evidence_hash_scheme": evidence_hash_scheme(),
                },
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def write_sarif(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(to_sarif(result), encoding="utf-8")


def has_findings_at_or_above(result: ScanResult, severity: str) -> bool:
    return any(is_release_blocking_finding(finding, severity) for finding in result.findings)


def to_markdown(result: ScanResult) -> str:
    lines = ["# K-Guard MCP Security Report", ""]
    summary = result.summary()
    lines.append("## Summary")
    lines.append("")
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity}: {summary.get(severity, 0)}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
    for finding in result.findings:
        safe_finding = finding.to_dict()
        location = safe_finding.get("file") or safe_finding.get("url") or "scan target"
        if finding.line_start:
            location = f"{location}:{finding.line_start}"
        lines.append(f"### [{finding.severity.upper()}] {redact_text(finding.title)}")
        lines.append("")
        lines.append(f"- Rule: `{finding.rule_id}`")
        lines.append(f"- Source: `{finding.source}`")
        lines.append(f"- Confidence: `{finding.confidence}`")
        lines.append(f"- Location: `{location}`")
        if finding.method or finding.status:
            lines.append(f"- HTTP: `{finding.method or ''}` status `{finding.status or ''}`")
        lines.append(f"- Evidence: `{safe_finding.get('evidence', '')}`")
        lines.append(f"- Why: {redact_text(finding.why_it_matters)}")
        lines.append(f"- Recommendation: {redact_text(finding.recommendation)}")
        lines.append("")
    if result.flow_map and result.flow_map.nodes:
        lines.append("## Data Flow Risk Map")
        lines.append("")
        lines.append(f"EXPERIMENTAL source-to-sink triage map. Method: `{result.flow_map.method}`. Precision: `{result.flow_map.precision}`. Confirm flow findings with code review before release decisions.")
        lines.append("")
        lines.append("```mermaid")
        lines.append(redact_text(result.flow_map.to_mermaid()))
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def write_markdown(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(to_markdown(result), encoding="utf-8")


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_location(safe_finding: dict[str, object]) -> dict[str, object]:
    uri = str(safe_finding.get("file") or safe_finding.get("url") or "scan-target")
    region: dict[str, object] = {}
    line = safe_finding.get("line_start")
    if isinstance(line, int):
        region["startLine"] = max(line, 1)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": region,
        }
    }


def _rule_tags(rule_id: str) -> list[str]:
    tags = ["k-guard"]
    if rule_id.startswith("MCP_") or "MCP" in rule_id:
        tags.extend(["mcp", "owasp-llm"])
    if "PII" in rule_id or rule_id.startswith("KR_"):
        tags.extend(["privacy", "korean-pii"])
    if "EXFIL" in rule_id or "EXTERNAL_HTTP" in rule_id:
        tags.append("exfiltration")
    if "PROMPT" in rule_id or "HIDDEN_INSTRUCTION" in rule_id or "TOOL_POISONING" in rule_id:
        tags.append("prompt-injection")
    return sorted(set(tags))


def to_flow_svg(result: ScanResult) -> str:
    if result.flow_map:
        return result.flow_map.to_svg()
    return '<svg xmlns="http://www.w3.org/2000/svg" width="640" height="120" viewBox="0 0 640 120"><text x="24" y="64">No flow map available.</text></svg>'


def write_flow_svg(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(to_flow_svg(result), encoding="utf-8")


def to_flow_html(result: ScanResult) -> str:
    svg = to_flow_svg(result)
    findings = []
    for finding in result.findings:
        safe_finding = finding.to_dict()
        if not str(safe_finding.get("rule_id", "")).startswith("FLOW_"):
            continue
        findings.append(
            "<tr>"
            f"<td>{escape(str(safe_finding.get('severity', '')))}</td>"
            f"<td>{escape(str(safe_finding.get('rule_id', '')))}</td>"
            f"<td>{escape(str(safe_finding.get('file') or ''))}</td>"
            f"<td>{escape(str(safe_finding.get('evidence') or ''))}</td>"
            "</tr>"
        )
    table = "\n".join(findings) if findings else '<tr><td colspan="4">No flow findings.</td></tr>'
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8"/>',
            '<meta name="viewport" content="width=device-width, initial-scale=1"/>',
            "<title>K-Guard Data Flow Risk Map</title>",
            "<style>body{font-family:Arial,sans-serif;margin:24px;color:#111827;background:#f8fafc}main{max-width:1120px;margin:0 auto}section{margin:18px 0}table{border-collapse:collapse;width:100%;background:white}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;font-size:13px}th{background:#e2e8f0}.note{color:#475569}</style>",
            "</head>",
            "<body><main>",
            "<h1>K-Guard Data Flow Risk Map</h1>",
            '<p class="note">EXPERIMENTAL heuristic-only visualization. Confirm every path with code review before release decisions.</p>',
            f"<section>{svg}</section>",
            "<section><h2>Flow Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Evidence</th></tr></thead><tbody>",
            table,
            "</tbody></table></section>",
            "</main></body></html>",
        ]
    )


def write_flow_html(result: ScanResult, path: str | Path) -> None:
    Path(path).write_text(to_flow_html(result), encoding="utf-8")
