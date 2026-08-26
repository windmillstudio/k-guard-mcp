from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding


PRIVACY_RULE = re.compile(r"^(PII_|KR_COMBO_|KR_DATA_(?:UNIQUE|SENSITIVE|LINKABLE)|DYN_RESPONSE_PII|CONNECTOR_.*PII|CONNECTOR_SQLITE_SENSITIVE_SCHEMA|RUNTIME_MCP_TOOL_RESULT_PII)", re.IGNORECASE)
AGENTIC_RULE = re.compile(r"(AGENTIC|LLM|MCP_PII_TO_AGENTIC|RUNTIME_MCP_PII_TO_AGENTIC)", re.IGNORECASE)
EXTERNAL_RULE = re.compile(r"(EXTERNAL_HTTP|EXTERNAL_SINK|EXFIL)", re.IGNORECASE)
AT_REST_RULE = re.compile(r"CONNECTOR_.*(PII_AT_REST|SECRET_AT_REST|SENSITIVE_SCHEMA)", re.IGNORECASE)


class CrossPlaneAnalyzer:
    def __init__(self, id_factory: IdFactory | None = None, max_findings: int = 30) -> None:
        self.ids = id_factory or IdFactory()
        self.max_findings = max_findings

    def scan(self, findings: list[Finding], root: str | Path | None = None) -> list[Finding]:
        privacy_by_scope: dict[str, list[Finding]] = defaultdict(list)
        sinks_by_scope: dict[str, list[Finding]] = defaultdict(list)
        at_rest = [finding for finding in findings if AT_REST_RULE.search(finding.rule_id)]
        for finding in findings:
            scope = _scope_key(finding, root)
            if PRIVACY_RULE.search(finding.rule_id):
                privacy_by_scope[scope].append(finding)
            if (AGENTIC_RULE.search(finding.rule_id) or EXTERNAL_RULE.search(finding.rule_id)) and finding.confidence != "low":
                sinks_by_scope[scope].append(finding)
        results: list[Finding] = []
        for scope, privacy_findings in privacy_by_scope.items():
            sink_findings = sinks_by_scope.get(scope, [])
            if not sink_findings:
                continue
            sink_rules = {finding.rule_id for finding in sink_findings}
            if any(AGENTIC_RULE.search(rule) for rule in sink_rules):
                results.append(self._finding("CROSS_PLANE_KR_PII_TO_AGENTIC_SINK", "critical", scope, privacy_findings, sink_findings, root))
            if any(EXTERNAL_RULE.search(rule) for rule in sink_rules):
                results.append(self._finding("CROSS_PLANE_KR_PII_TO_EXTERNAL_SINK", "high", scope, privacy_findings, sink_findings, root))
            if len(results) >= self.max_findings:
                break
        if at_rest and any(AGENTIC_RULE.search(finding.rule_id) or EXTERNAL_RULE.search(finding.rule_id) for finding in findings) and len(results) < self.max_findings:
            results.append(
                Finding(
                    id=self.ids.next(),
                    source="cross-plane",
                    rule_id="CROSS_PLANE_KR_PII_AT_REST_WITH_AGENTIC_OR_EXTERNAL_FLOW",
                    severity="high",
                    confidence="low",
                    title="Personal data at rest appears in a project that also has agentic/external flow signals",
                    file=str(Path(root)) if root else None,
                    evidence=f"at_rest_count={len(at_rest)} sink_signal_count={sum(1 for item in findings if AGENTIC_RULE.search(item.rule_id) or EXTERNAL_RULE.search(item.rule_id))} scope_hash={evidence_hash(str(root or 'scan'))} scheme={evidence_hash_scheme()}",
                    why_it_matters="A project that stores personal data and also has agentic/external transfer paths needs stronger minimization and policy gates.",
                    recommendation="Review whether stored personal data can reach LLM/MCP/external sinks and add redaction/policy gates before those boundaries.",
                    audit_depth=5,
                    inspected_scope="Connector findings and flow/runtime findings were correlated at project scope without raw values.",
                    not_inspected="This project-level verdict does not prove the exact same record moved from storage to the sink.",
                )
            )
        return results[: self.max_findings]

    def _finding(self, rule_id: str, severity: str, scope: str, privacy_findings: list[Finding], sink_findings: list[Finding], root: str | Path | None) -> Finding:
        return Finding(
            id=self.ids.next(),
            source="cross-plane",
            rule_id=rule_id,
            severity=severity,
            confidence="medium",
            title="Cross-plane Korean personal-data flow verdict",
            file=scope if scope != "scan" else (str(Path(root)) if root else None),
            evidence=(
                f"scope_hash={evidence_hash(scope)} privacy_rules={_rule_summary(privacy_findings)} "
                f"sink_rules={_rule_summary(sink_findings)} scheme={evidence_hash_scheme()}"
            ),
            why_it_matters="This combines privacy classification with sink evidence, which is closer to an audit verdict than isolated pattern matches.",
            recommendation="Treat this as a release-review blocker until the data purpose, minimization, redaction, and sink approval are documented.",
            audit_depth=5,
            inspected_scope="Static/dynamic/runtime/connector findings were correlated by file/event scope into a raw-free cross-plane verdict.",
            not_inspected="Correlation by file/project scope still needs runtime lineage or a live proxy to prove exact record movement.",
        )


def _scope_key(finding: Finding, root: str | Path | None) -> str:
    if finding.file:
        return str(Path(finding.file))
    if finding.url:
        return finding.url
    return str(Path(root)) if root else "scan"


def _rule_summary(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    return ",".join(f"{rule}={counts[rule]}" for rule in sorted(counts)[:8])
