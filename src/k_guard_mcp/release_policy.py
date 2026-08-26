from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from k_guard_mcp.severity import severity_rank


DIRECT_RELEASE_SCOPES = frozenset(
    {"runtime_source", "configuration", "database_migration", "deployable_artifact", "workspace_evidence"}
)
SUPPORTING_REVIEW_SCOPES = frozenset(
    {
        "benchmark",
        "content_data",
        "documentation",
        "example",
        "generated",
        "repository_asset",
        "test_fixture",
        "third_party",
    }
)
REPOSITORY_WIDE_RULE_PREFIXES = (
    "CONNECTOR_SECRET_AT_REST",
    "KR_PII_",
    "PII_",
    "SECRET_",
)
MANUAL_REVIEW_RULE_PREFIXES = ("KR_", "PII_", "SECRET_")
INTENT_REQUIRED_MANUAL_REVIEW_RULES = frozenset({"CONFIG_DOCKER_SOCK"})
AUTOMATIC_RELEASE_RULES = frozenset(
    {
        "AUTH_JWT_DECODE_WITHOUT_VERIFY",
        "CONFIG_CSP_UNSAFE_EVAL",
        "MCP_STATIC_CREDENTIAL_IN_CONFIG",
        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
        "WEB_UNTRUSTED_INPUT_TO_CODE_EXECUTION",
    }
)
HISTORICAL_AUTOMATIC_RELEASE_RULES = {
    "k_guard_release_lanes_v5": frozenset(
        {
            "AUTH_JWT_DECODE_WITHOUT_VERIFY",
            "CONFIG_CSP_UNSAFE_EVAL",
            "CONFIG_GHA_MUTABLE_ACTION_REF",
            "MCP_STATIC_CREDENTIAL_IN_CONFIG",
            "WEB_UNTRUSTED_INPUT_TO_COMMAND",
            "WEB_UNTRUSTED_INPUT_TO_CODE_EXECUTION",
        }
    )
}
POLICY_INTEGRITY_RULES = frozenset(
    {
        "DB_POLICY_ANALYSIS_INCOMPLETE",
        "STATIC_ANALYSIS_LIMIT_REACHED",
    }
)
POLICY_INTEGRITY_RULE_PREFIXES = (
    "DEEP_ANALYSIS_",
    "GUARDIAN_RELEASE_",
    "GUARDIAN_SCAN_",
    "GUARDIAN_TARGET_",
    "MCP_ARGUMENT_BUDGET_",
    "MCP_EXHAUSTIVE_",
    "MCP_GUARDIAN_",
    "MCP_SCAN_INVENTORY_",
    "MCP_SECURITY_GATE_",
    "MCP_WORKSPACE_",
    "SCA_COVERAGE_",
)
POLICY_INTEGRITY_RULE_SUFFIXES = (
    "_ANALYSIS_INCOMPLETE",
    "_CONTRACT_INVALID",
    "_COVERAGE_INCOMPLETE",
    "_EVIDENCE_MISSING",
    "_LIMIT_REACHED",
    "_PARSE_FAILED",
)

RELEASE_BLOCKING_LANE = "release_blocking"
MANUAL_REVIEW_HOLD_LANE = "manual_review_hold"
POLICY_INTEGRITY_HOLD_LANE = "policy_integrity_hold"
DIRECT_RELEASE_BLOCKING_LANE = "direct_release_blocking"
SUPPORTING_ARTIFACT_BLOCKING_LANE = "supporting_artifact_blocking"
SUPPORTING_REVIEW_LANE = "supporting_review"
RELEASE_BLOCKING_POLICY = "k_guard_release_lanes_v6"


def automatic_release_rules_for_policy(policy: str) -> frozenset[str] | None:
    if policy == RELEASE_BLOCKING_POLICY:
        return AUTOMATIC_RELEASE_RULES
    return HISTORICAL_AUTOMATIC_RELEASE_RULES.get(policy)


def is_release_blocking_finding(finding: Any, threshold: str) -> bool:
    return release_lane(finding, threshold) in {
        RELEASE_BLOCKING_LANE,
        MANUAL_REVIEW_HOLD_LANE,
        POLICY_INTEGRITY_HOLD_LANE,
    }


def release_lane(finding: Any, threshold: str = "high") -> str:
    return _release_lane_with_rules(finding, threshold, AUTOMATIC_RELEASE_RULES)


def release_lane_for_policy(
    finding: Any,
    policy: str,
    threshold: str = "high",
) -> str:
    rules = automatic_release_rules_for_policy(policy)
    if rules is None:
        return POLICY_INTEGRITY_HOLD_LANE
    return _release_lane_with_rules(finding, threshold, rules)


def _release_lane_with_rules(
    finding: Any,
    threshold: str,
    automatic_rules: frozenset[str],
) -> str:
    severity = str(_value(finding, "severity") or "info")
    if severity_rank(severity) > severity_rank(threshold):
        return SUPPORTING_REVIEW_LANE

    raw_scope = _value(finding, "artifact_scope")
    scope = str(raw_scope or "")
    if not scope or scope not in DIRECT_RELEASE_SCOPES | SUPPORTING_REVIEW_SCOPES:
        return POLICY_INTEGRITY_HOLD_LANE

    rule_id = str(_value(finding, "rule_id") or "")
    if (
        rule_id in POLICY_INTEGRITY_RULES
        or rule_id.startswith(POLICY_INTEGRITY_RULE_PREFIXES)
        or rule_id.endswith(POLICY_INTEGRITY_RULE_SUFFIXES)
    ):
        return POLICY_INTEGRITY_HOLD_LANE

    confidence = str(_value(finding, "confidence") or "low")
    if scope in SUPPORTING_REVIEW_SCOPES:
        if (
            scope != "third_party"
            and confidence == "high"
            and rule_id.startswith(REPOSITORY_WIDE_RULE_PREFIXES)
        ):
            return MANUAL_REVIEW_HOLD_LANE
        return SUPPORTING_REVIEW_LANE

    if rule_id in INTENT_REQUIRED_MANUAL_REVIEW_RULES:
        return MANUAL_REVIEW_HOLD_LANE

    if (
        confidence != "high"
        or rule_id.startswith(MANUAL_REVIEW_RULE_PREFIXES)
        or rule_id not in automatic_rules
    ):
        return MANUAL_REVIEW_HOLD_LANE
    return RELEASE_BLOCKING_LANE


def release_accounting_lane(finding: Any, threshold: str = "high") -> str:
    lane = release_lane(finding, threshold)
    if lane in {SUPPORTING_REVIEW_LANE, MANUAL_REVIEW_HOLD_LANE, POLICY_INTEGRITY_HOLD_LANE}:
        return lane

    scope = str(_value(finding, "artifact_scope") or "workspace_evidence")
    if scope in SUPPORTING_REVIEW_SCOPES:
        return SUPPORTING_ARTIFACT_BLOCKING_LANE
    return DIRECT_RELEASE_BLOCKING_LANE


def release_hold_counts(findings: Iterable[Any], threshold: str = "high") -> dict[str, int]:
    counts = Counter(release_lane(finding, threshold) for finding in findings)
    return _hold_count_payload(counts)


def release_hold_counts_for_policy(
    findings: Iterable[Any],
    policy: str,
    threshold: str = "high",
) -> dict[str, int]:
    counts = Counter(
        release_lane_for_policy(finding, policy, threshold) for finding in findings
    )
    return _hold_count_payload(counts)


def _hold_count_payload(counts: Counter[str]) -> dict[str, int]:
    automatic = counts[RELEASE_BLOCKING_LANE]
    manual = counts[MANUAL_REVIEW_HOLD_LANE]
    integrity = counts[POLICY_INTEGRITY_HOLD_LANE]
    return {
        "blocking_count": automatic + manual + integrity,
        "automatic_release_blocking_count": automatic,
        "manual_review_hold_count": manual,
        "policy_integrity_hold_count": integrity,
    }


def _value(finding: Any, key: str) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(key)
    return getattr(finding, key, None)
