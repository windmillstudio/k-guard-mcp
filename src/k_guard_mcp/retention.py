from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from k_guard_mcp.collector import collect_files, read_text
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.ids import IdFactory
from k_guard_mcp.models import Finding


PRIVACY_SIGNAL = re.compile(r"(PII|KR_COMBO|KR_DATA_(?:UNIQUE|SENSITIVE|LINKABLE)|CONNECTOR_.*(?:PII|SENSITIVE_SCHEMA)|DYN_RESPONSE_PII|AST_TAINT|FLOW_SENSITIVE|FLOW_PII)", re.IGNORECASE)
RETENTION_MARKER = re.compile(r"(retention|retention_days|ttl|expires?_at|보존기간|보관기간|보존|파기\s*예정|삭제\s*예정)", re.IGNORECASE)
DELETION_MARKER = re.compile(r"(delete_user|deleteAccount|delete_account|erase|erasure|withdrawal|탈퇴|삭제|파기|destroy|anonymi[sz]e|remove_personal)", re.IGNORECASE)
RETENTION_DURATION = re.compile(r"(?:\b\d+\s*(?:days?|months?|years?|hours?)\b|\d+\s*(?:일|개월|년|시간))", re.IGNORECASE)
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".java", ".kt", ".php", ".rb", ".sql", ".vue", ".svelte"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env"}


class RetentionDeletionAnalyzer:
    def __init__(self, id_factory: IdFactory | None = None) -> None:
        self.ids = id_factory or IdFactory()

    def scan(self, root: str | Path, findings: list[Finding]) -> list[Finding]:
        privacy_findings = [finding for finding in findings if PRIVACY_SIGNAL.search(finding.rule_id)]
        if not privacy_findings:
            return []
        marker_counts, marker_hashes = self._markers(root)
        results: list[Finding] = []
        if marker_counts["retention"] == 0:
            results.append(
                Finding(
                    id=self.ids.next(),
                    source="retention",
                    rule_id="RETENTION_POLICY_MISSING_FOR_PERSONAL_DATA",
                    severity="medium",
                    confidence="low",
                    title="Personal-data signals found but no retention policy marker was found",
                    file=str(Path(root)),
                    evidence=f"privacy_signal_count={len(privacy_findings)} retention_markers=0 deletion_markers={marker_counts['deletion']} marker_hash={marker_hashes.get('deletion', 'none')} scheme={evidence_hash_scheme()}",
                    why_it_matters="If personal data is collected or stored, the product needs a retention period and deletion plan.",
                    recommendation="Add explicit retention settings or documentation and make sure storage/log cleanup jobs enforce them.",
                    audit_depth=3,
                    inspected_scope="Production code/config and concrete-duration policy text were scanned for retention evidence after personal-data findings were found.",
                    not_inspected="This static check does not inspect live scheduler jobs, backups, or production database retention state.",
                )
            )
        if marker_counts["deletion"] == 0:
            results.append(
                Finding(
                    id=self.ids.next(),
                    source="retention",
                    rule_id="RETENTION_ERASURE_PATH_MISSING_FOR_PERSONAL_DATA",
                    severity="medium",
                    confidence="low",
                    title="Personal-data signals found but no deletion/erasure path marker was found",
                    file=str(Path(root)),
                    evidence=f"privacy_signal_count={len(privacy_findings)} retention_markers={marker_counts['retention']} deletion_markers=0 marker_hash={marker_hashes.get('retention', 'none')} scheme={evidence_hash_scheme()}",
                    why_it_matters="Korean privacy review should verify how a user/customer record is deleted or anonymized, not only where it appears.",
                    recommendation="Add a deletion/anonymization path for user records and verify logs/storage copies are also cleaned.",
                    audit_depth=3,
                    inspected_scope="Production code/config was scanned for deletion or erasure-path evidence after personal-data findings were found.",
                    not_inspected="This static check does not execute deletion flows or verify that backups/logs were purged.",
                )
            )
        return results

    def _markers(self, root: str | Path) -> tuple[Counter[str], dict[str, str]]:
        counts: Counter[str] = Counter()
        hashes: dict[str, str] = {}
        for path in collect_files(root):
            text = read_text(path)
            if not text:
                continue
            suffix = path.suffix.lower()
            is_source_or_config = suffix in SOURCE_SUFFIXES | CONFIG_SUFFIXES or path.name.lower() in {"dockerfile", "compose.yaml", "compose.yml"}
            is_policy_text = suffix in {".md", ".txt"}
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith(("//", "#", "--", "/*", "*", "todo")):
                    continue
                retention_evidence = is_source_or_config and RETENTION_MARKER.search(line)
                concrete_policy = is_policy_text and RETENTION_MARKER.search(line) and RETENTION_DURATION.search(line)
                if retention_evidence or concrete_policy:
                    counts["retention"] += 1
                    hashes.setdefault("retention", evidence_hash(line))
                if is_source_or_config and DELETION_MARKER.search(line):
                    counts["deletion"] += 1
                    hashes.setdefault("deletion", evidence_hash(line))
        return counts, hashes
