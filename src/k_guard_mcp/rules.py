from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding
from k_guard_mcp.detectors.mcp_threat import is_mcp_adjacent_text


@dataclass(frozen=True)
class LocalRule:
    rule_id: str
    severity: str
    confidence: str
    title: str
    pattern: re.Pattern[str]
    why: str
    recommendation: str


BUILTIN_RULES = [
    LocalRule(
        "RULE_YARA_LITE_MCP_PROMPT_INJECTION",
        "critical",
        "high",
        "YARA-lite MCP prompt injection marker",
        re.compile(r"(ignore previous instructions|developer message|system prompt|do not reveal|이전 지시.*무시|숨겨진 지시)", re.IGNORECASE),
        "Prompt-injection markers in MCP-adjacent files can alter agent behavior before the user notices.",
        "Remove adversarial instructions and require transparent tool descriptions.",
    ),
    LocalRule(
        "RULE_YARA_LITE_EXFIL_COMMAND",
        "critical",
        "medium",
        "YARA-lite exfiltration command marker",
        re.compile(
            r"(?:"
            r"\b(?:curl|wget|nc|netcat|scp|Invoke-WebRequest|iwr)\b"
            r"(?=[^\r\n]{0,180}(?:"
            r"[?&](?:token|secret|cookie|password|api[_-]?key|개인정보|주민|전화)="
            r"|\$(?:\{)?[A-Za-z0-9_]*(?:TOKEN|SECRET|COOKIE|PASSWORD|API_KEY)[A-Za-z0-9_]*"
            r"|\$\{\{\s*secrets\."
            r"|(?:--data(?:-binary)?|-d|--form|-F|--upload-file|-T|--post-data|--post-file)[^\r\n]{0,80}(?:token|secret|cookie|password|api[_-]?key)"
            r"|(?:<|\|)\s*\.env\b"
            r"))[^\r\n]{0,220}"
            r"|\b(?:env|printenv|cat\s+\.env)\b[^\r\n]{0,80}\|[^\r\n]{0,40}\b(?:curl|wget|nc|netcat|scp)\b"
            r")",
            re.IGNORECASE,
        ),
        "Shell/network commands near sensitive terms are strong exfiltration review signals.",
        "Remove the command or prove the destination, purpose, minimization, and operator approval.",
    ),
    LocalRule(
        "RULE_YARA_LITE_KR_BULK_SCHEMA",
        "medium",
        "medium",
        "YARA-lite Korean bulk personal-data schema",
        re.compile(r"(name|이름|성명).{0,80}(phone|전화|휴대폰).{0,80}(email|이메일|address|주소|rrn|주민)", re.IGNORECASE),
        "A schema or table shape appears designed to hold Korean personal-data records even if sample values are absent.",
        "Confirm the endpoint/storage is authenticated, minimized, and excluded from logs/fixtures.",
    ),
]

_BUILTIN_RULES_BY_ID = {rule.rule_id: rule for rule in BUILTIN_RULES}


class RulePackDetector:
    def __init__(self, id_factory: IdFactory | None = None, rules: list[LocalRule] | None = None) -> None:
        self.ids = id_factory or IdFactory()
        self.rules = BUILTIN_RULES if rules is None else rules
        self._uses_builtin_rules = rules is None

    def scan_text(self, text: str, file: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        mcp_context = is_mcp_adjacent_text(file, text)
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule in self.rules:
                if rule.rule_id == "RULE_YARA_LITE_MCP_PROMPT_INJECTION" and not mcp_context:
                    continue
                if rule.rule_id == "RULE_YARA_LITE_EXFIL_COMMAND" and _comment_only(line):
                    continue
                matched = (
                    _builtin_rule_matches(rule.rule_id, line)
                    if self._uses_builtin_rules
                    else rule.pattern.search(line) is not None
                )
                if not matched:
                    continue
                key = (rule.rule_id, line_no)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        id=self.ids.next(),
                        source="rule-pack",
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        title=rule.title,
                        file=file,
                        line_start=line_no,
                        line_end=line_no,
                        evidence=f"line_hash={evidence_hash(line)} scheme={evidence_hash_scheme()} matched={rule.rule_id}",
                        why_it_matters=rule.why,
                        recommendation=rule.recommendation,
                        audit_depth=2,
                        inspected_scope="Built-in local YARA-lite rules scanned this file without network access.",
                        not_inspected="This is a deterministic rule signal, not an LLM semantic judgment or runtime execution trace.",
                    )
                )
        return findings


@lru_cache(maxsize=16384)
def _builtin_rule_matches(rule_id: str, line: str) -> bool:
    return _BUILTIN_RULES_BY_ID[rule_id].pattern.search(line) is not None


def _comment_only(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", ";", "<!--", "*"))
