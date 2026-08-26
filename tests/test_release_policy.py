from __future__ import annotations

import pytest

from k_guard_mcp.models import Finding, ScanResult
from k_guard_mcp.release_policy import (
    AUTOMATIC_RELEASE_RULES,
    DIRECT_RELEASE_BLOCKING_LANE,
    MANUAL_REVIEW_HOLD_LANE,
    POLICY_INTEGRITY_HOLD_LANE,
    RELEASE_BLOCKING_POLICY,
    SUPPORTING_REVIEW_LANE,
    automatic_release_rules_for_policy,
    is_release_blocking_finding,
    release_accounting_lane,
    release_hold_counts,
    release_lane,
    release_lane_for_policy,
)
from k_guard_mcp.reports import has_findings_at_or_above
from k_guard_mcp.scanner import build_review_triage


EXPECTED_AUTOMATIC_RELEASE_RULES = frozenset(
    {
        "AUTH_JWT_DECODE_WITHOUT_VERIFY",
        "CONFIG_CSP_UNSAFE_EVAL",
        "MCP_STATIC_CREDENTIAL_IN_CONFIG",
        "WEB_UNTRUSTED_INPUT_TO_CODE_EXECUTION",
        "WEB_UNTRUSTED_INPUT_TO_COMMAND",
    }
)
UNADJUDICATED_FAIL_CLOSED_RULES = frozenset(
    {
        "CONFIG_GHA_MUTABLE_ACTION_REF",
        "CONFIG_CORS_REFLECTED_CREDENTIALS",
        "CONFIG_FIREBASE_PRIVATE_KEY",
        "CONFIG_SUPABASE_SERVICE_ROLE",
        "MCP_AUTOMATIC_TOOL_APPROVAL",
        "MCP_INSECURE_REMOTE_TRANSPORT",
        "MCP_MUTABLE_GIT_SOURCE",
        "MCP_PRIVILEGED_CONTAINER_SURFACE",
        "MCP_UNPINNED_PACKAGE_EXECUTION",
    }
)


def _finding(*, rule_id: str, scope: str, severity: str = "high", confidence: str = "high") -> Finding:
    return Finding(
        id=f"{rule_id}-{scope}",
        source="fixture",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        title="fixture",
        evidence="raw_returned=false",
        why_it_matters="fixture",
        recommendation="fixture",
        artifact_scope=scope,
    )


def test_runtime_findings_block_but_documentation_heuristics_remain_review_only() -> None:
    runtime = _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_COMMAND", scope="runtime_source")
    documentation = _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_COMMAND", scope="documentation")

    assert is_release_blocking_finding(runtime, "high")
    assert not is_release_blocking_finding(documentation, "high")
    assert release_lane(runtime) == "release_blocking"
    assert release_lane(documentation) == "supporting_review"


def test_every_automatic_rule_requires_direct_high_confidence_evidence() -> None:
    for rule_id in AUTOMATIC_RELEASE_RULES:
        direct = _finding(rule_id=rule_id, scope="runtime_source")
        supporting = _finding(rule_id=rule_id, scope="documentation")
        uncertain = _finding(rule_id=rule_id, scope="runtime_source", confidence="medium")

        assert release_lane(direct) == "release_blocking"
        assert release_lane(supporting) == SUPPORTING_REVIEW_LANE
        assert release_lane(uncertain) == MANUAL_REVIEW_HOLD_LANE


def test_automatic_release_rule_set_is_limited_to_adjudication_backed_rules() -> None:
    assert AUTOMATIC_RELEASE_RULES == EXPECTED_AUTOMATIC_RELEASE_RULES
    assert RELEASE_BLOCKING_POLICY == "k_guard_release_lanes_v6"


def test_historical_policy_replays_its_bound_rules_without_reenabling_current_rules() -> None:
    finding = _finding(
        rule_id="CONFIG_GHA_MUTABLE_ACTION_REF",
        scope="configuration",
    )

    assert "CONFIG_GHA_MUTABLE_ACTION_REF" in (
        automatic_release_rules_for_policy("k_guard_release_lanes_v5") or ()
    )
    assert release_lane_for_policy(
        finding,
        "k_guard_release_lanes_v5",
    ) == "release_blocking"
    assert release_lane(finding) == MANUAL_REVIEW_HOLD_LANE
    assert release_lane_for_policy(
        finding,
        "unknown-policy",
    ) == POLICY_INTEGRITY_HOLD_LANE


@pytest.mark.parametrize("threshold", ["critical", "high", "medium", "low", "info"])
@pytest.mark.parametrize(
    ("severity", "confidence"),
    [("medium", "high"), ("high", "medium"), ("high", "high")],
)
def test_mutable_action_rule_cannot_enter_the_automatic_lane_before_qualification(
    threshold: str,
    severity: str,
    confidence: str,
) -> None:
    finding = _finding(
        rule_id="CONFIG_GHA_MUTABLE_ACTION_REF",
        scope="configuration",
        severity=severity,
        confidence=confidence,
    )

    assert "CONFIG_GHA_MUTABLE_ACTION_REF" not in AUTOMATIC_RELEASE_RULES
    assert release_lane(finding, threshold) != "release_blocking"


@pytest.mark.parametrize("rule_id", sorted(UNADJUDICATED_FAIL_CLOSED_RULES))
def test_unadjudicated_high_confidence_rules_remain_fail_closed_manual_holds(rule_id: str) -> None:
    finding = _finding(rule_id=rule_id, scope="configuration", confidence="high")

    assert rule_id not in AUTOMATIC_RELEASE_RULES
    assert release_lane(finding) == MANUAL_REVIEW_HOLD_LANE
    assert is_release_blocking_finding(finding, "high")


def test_high_confidence_repository_secret_blocks_outside_third_party() -> None:
    test_secret = _finding(rule_id="SECRET_API_KEY", scope="test_fixture")
    vendor_secret_example = _finding(rule_id="SECRET_API_KEY", scope="third_party")

    assert is_release_blocking_finding(test_secret, "high")
    assert not is_release_blocking_finding(vendor_secret_example, "high")
    assert release_lane(test_secret) == MANUAL_REVIEW_HOLD_LANE


def test_release_accounting_lane_distinguishes_direct_and_supporting_blockers() -> None:
    runtime = _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_COMMAND", scope="runtime_source")
    supporting_secret = _finding(rule_id="SECRET_API_KEY", scope="test_fixture")
    supporting_review = _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_SQL", scope="documentation")
    unknown_scope = _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_SQL", scope="unclassified")

    assert release_accounting_lane(runtime) == DIRECT_RELEASE_BLOCKING_LANE
    assert release_accounting_lane(supporting_secret) == MANUAL_REVIEW_HOLD_LANE
    assert release_accounting_lane(supporting_review) == SUPPORTING_REVIEW_LANE
    assert release_accounting_lane(unknown_scope) == POLICY_INTEGRITY_HOLD_LANE


def test_review_triage_accounts_for_supporting_artifact_blockers() -> None:
    findings = [
        _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_COMMAND", scope="runtime_source"),
        _finding(rule_id="SECRET_API_KEY", scope="test_fixture"),
        _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_SQL", scope="documentation"),
    ]

    triage = build_review_triage(findings)

    assert triage["blocking_finding_count"] == 2
    assert triage["automatic_release_blocking_count"] == 1
    assert triage["manual_review_hold_count"] == 1
    assert triage["policy_integrity_hold_count"] == 0
    assert triage["direct_release_blocking_count"] == 1
    assert triage["supporting_artifact_blocking_count"] == 0
    assert triage["supporting_review_high_critical_count"] == 1


def test_deployable_artifact_blocks_even_when_detector_confidence_is_medium() -> None:
    source_map_secret = _finding(
        rule_id="SECRET_OPENAI_STYLE_KEY",
        scope="deployable_artifact",
        severity="critical",
        confidence="medium",
    )

    assert is_release_blocking_finding(source_map_secret, "high")
    assert release_lane(source_map_secret) == MANUAL_REVIEW_HOLD_LANE


def test_medium_confidence_runtime_findings_hold_for_manual_review() -> None:
    finding = _finding(
        rule_id="WEB_UNTRUSTED_INPUT_TO_SQL",
        scope="runtime_source",
        confidence="medium",
    )

    assert is_release_blocking_finding(finding, "high")
    assert release_lane(finding) == MANUAL_REVIEW_HOLD_LANE


def test_unqualified_high_confidence_rule_holds_for_manual_review() -> None:
    finding = _finding(
        rule_id="WEB_UNTRUSTED_INPUT_TO_SQL",
        scope="runtime_source",
        confidence="high",
    )

    assert is_release_blocking_finding(finding, "high")
    assert release_lane(finding) == MANUAL_REVIEW_HOLD_LANE


def test_docker_socket_access_is_fail_closed_manual_hold_not_automatic_block() -> None:
    finding = _finding(
        rule_id="CONFIG_DOCKER_SOCK",
        scope="configuration",
        confidence="high",
    )

    assert is_release_blocking_finding(finding, "high")
    assert release_lane(finding) == MANUAL_REVIEW_HOLD_LANE


def test_analysis_incomplete_findings_hold_on_policy_integrity() -> None:
    finding = _finding(
        rule_id="STATIC_ANALYSIS_LIMIT_REACHED",
        scope="workspace_evidence",
    )

    assert is_release_blocking_finding(finding, "high")
    assert release_lane(finding) == POLICY_INTEGRITY_HOLD_LANE


def test_parser_failures_hold_on_policy_integrity_without_inflating_actionability() -> None:
    finding = _finding(
        rule_id="PYTHON_AST_PARSE_FAILED",
        scope="runtime_source",
    )

    assert is_release_blocking_finding(finding, "high")
    assert release_lane(finding) == POLICY_INTEGRITY_HOLD_LANE


def test_control_failures_are_not_counted_as_detection_actionability() -> None:
    vulnerability = _finding(rule_id="WEB_UNTRUSTED_INPUT_TO_COMMAND", scope="runtime_source")
    manual = _finding(
        rule_id="WEB_UNTRUSTED_INPUT_TO_FILE_PATH",
        scope="runtime_source",
        confidence="medium",
    )
    control_failure = _finding(
        rule_id="MCP_SECURITY_GATE_SCAN_FAILED",
        scope="workspace_evidence",
    )

    counts = release_hold_counts([vulnerability, manual, control_failure])

    assert counts == {
        "blocking_count": 3,
        "automatic_release_blocking_count": 1,
        "manual_review_hold_count": 1,
        "policy_integrity_hold_count": 1,
    }


def test_cli_fail_on_uses_release_policy_without_dropping_supporting_findings() -> None:
    supporting = _finding(rule_id="MCP_EXFILTRATION_INTENT", scope="documentation", severity="critical")
    result = ScanResult(findings=[supporting]).finalize()

    assert not has_findings_at_or_above(result, "high")
    assert result.findings == [supporting]
