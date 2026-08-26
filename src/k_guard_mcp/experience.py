from __future__ import annotations

import re
from typing import Any

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.provenance import canonical_json, object_artifact, verify_evidence_bundle


PRODUCT_NAME = "K-Guard MCP"
PERSONA_NAME = "안경선배"
PERSONA_ROLE = "바이브코딩 선배"
NORTH_STAR = "만드는 흐름은 끊지 않고, 출하는 대충 넘기지 않는다."
CLAIM_BOUNDARY = "시니어 개발자의 출하 전 검수 질문을 자동화한 게이트이며, 인간의 사업 판단이나 무결점 보증을 대신하지 않습니다."
GENERIC_CLAIM_BOUNDARY = "지정된 도구와 범위의 검수 결과입니다. 이 결과만으로 출하를 승인하지 않으며, 최종 판정은 완료된 1차 검수 영수증으로 start_review_before_ship을 시작한 Guardian high 게이트에서 내립니다."
QUALIFICATION_COVERAGE_RULES = frozenset({"DEEP_ANALYSIS_COVERAGE_INCOMPLETE", "SCA_COVERAGE_INCOMPLETE"})
CONTROL_RULE_PREFIXES = (
    "MCP_ARGUMENT_BUDGET_",
    "MCP_CHECK_MY_APP_",
    "MCP_CONFIG_DISCOVERY_",
    "MCP_DIFF_",
    "MCP_EXHAUSTIVE_",
    "MCP_GUARDIAN_",
    "MCP_RELEASE_REVIEW_",
    "MCP_REVIEW_",
    "MCP_SCAN_",
    "MCP_SECURITY_GATE_",
    "MCP_TEXT_INPUT_BUDGET_",
    "MCP_WORKSPACE_",
)


def apply_senpai_experience(
    report: dict[str, Any],
    *,
    tool_name: str,
    inspected_scope: str,
) -> dict[str, Any]:
    """Add a raw-free, non-authoritative product voice without changing scan evidence."""
    counts = _severity_counts(report)
    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []
    rule_ids = _safe_rule_ids(findings)
    blocking_count = counts["critical"] + counts["high"]
    review_triage = _review_triage(report)
    blocking_action_group_count = _as_int(review_triage.get("blocking_action_group_count"))
    review_count = counts["medium"] + counts["low"]
    runtime_policy = _runtime_policy(report)
    runtime_block_count = _as_int(runtime_policy.get("block_decision_count"))
    runtime_redact_count = _as_int(runtime_policy.get("redact_decision_count"))
    control_incomplete = _control_incomplete(report, rule_ids)
    control_rule_ids = [rule_id for rule_id in rule_ids if _is_control_rule_id(rule_id)]
    confirmed_blocking_findings = [
        str(finding.get("rule_id") or "")
        for finding in findings
        if isinstance(finding, dict)
        and str(finding.get("severity") or "").lower() in {"critical", "high"}
        and str(finding.get("rule_id") or "") not in control_rule_ids
    ]
    confirmed_blocking_count = len(confirmed_blocking_findings)
    confirmed_blocking_rule_ids = list(dict.fromkeys(rule_id for rule_id in confirmed_blocking_findings if rule_id))

    if control_incomplete:
        code = "hold_incomplete"
        message = "선배 판정: 검수 미완료. 지금은 통과로 보면 안 됩니다."
        confirmed = f" 동시에 이미 확인된 critical/high 위험이 {confirmed_blocking_count}건 있습니다." if confirmed_blocking_count else ""
        why = "검수가 끝까지 실행되지 않았거나 확인 범위가 비어 있어, 발견 없음과 안전함을 구분할 수 없습니다." + confirmed
        next_actions = _incomplete_actions(findings, control_rule_ids, confirmed_blocking_rule_ids)
    elif runtime_block_count > 0:
        code = "hold_runtime"
        message = "선배 판정: 실행 중 막아야 할 흐름을 잡았습니다."
        why = f"런타임 정책이 위험한 전달을 {runtime_block_count}건 차단했습니다. 우회해서 출하할 근거는 없습니다."
        next_actions = _generic_actions(rule_ids, retry=True)
    elif blocking_count > 0:
        code = "fix_first"
        message = "선배 판정: 지금은 멈춤. 먼저 고칠 게 있어요."
        grouped = f" {blocking_action_group_count}개 조치 그룹으로 묶었습니다." if blocking_action_group_count else ""
        why = f"critical/high 항목이 {blocking_count}건 확인됐습니다.{grouped} 빠르게 만든 흐름은 살리되, 이 항목은 출하 전에 닫아야 합니다."
        next_actions = _generic_actions(rule_ids, retry=True)
    elif review_count > 0:
        code = "review_findings"
        message = "선배 판정: 바로 막을 수준은 아니지만, 정리하고 가는 게 좋습니다."
        why = f"medium/low 항목이 {review_count}건 남았습니다. 현재 확인 범위 밖의 위험까지 없다고 뜻하지는 않습니다."
        next_actions = _generic_actions(rule_ids, retry=True)
    else:
        code = "scoped_clear"
        message = "선배 판정: 이번 확인 범위에서는 큰 문제는 안 보입니다."
        why = "현재 도구가 실제로 확인한 범위에서는 차단 기준에 해당하는 신호가 없었습니다. 출하 승인과는 별개입니다."
        next_actions = [
            "같은 커밋을 기준으로 결과를 남겨 두세요.",
            "출하 전에는 start_review_before_ship으로 네 영역을 모두 확인하세요.",
        ]

    presentation = _presentation(code, message, why, next_actions)
    report["experience"] = {
        "verdict": {"code": code, "message": message},
        "why": why,
        "next_actions": next_actions[:3],
        "presentation": presentation,
        "details": {
            "product": PRODUCT_NAME,
            "persona": PERSONA_NAME,
            "role": PERSONA_ROLE,
            "tool": tool_name,
            "inspected_scope": inspected_scope,
            "finding_counts": counts,
            "blocking_count": blocking_count,
            "confirmed_blocking_count": confirmed_blocking_count,
            "control_rule_ids": control_rule_ids[:3],
            "blocking_action_group_count": blocking_action_group_count,
            "review_triage": review_triage,
            "runtime_block_count": runtime_block_count,
            "runtime_redact_count": runtime_redact_count,
            "top_rule_ids": rule_ids[:3],
            "control_incomplete": control_incomplete,
            "release_authority": False,
            "canonical_release_tool": "start_review_before_ship",
            "canonical_release_engine": "review_before_ship",
            "claim_boundary": GENERIC_CLAIM_BOUNDARY,
            "presentation": presentation,
            "raw_returned": False,
        },
    }
    return report


def _review_triage(report: dict[str, Any]) -> dict[str, Any]:
    metadata = report.get("metadata", {}) if isinstance(report.get("metadata"), dict) else {}
    coverage = metadata.get("review_coverage", {}) if isinstance(metadata.get("review_coverage"), dict) else {}
    triage = coverage.get("review_triage", {}) if isinstance(coverage.get("review_triage"), dict) else {}
    return triage


def apply_guardian_experience(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    qualification = report.get("release_qualification", {}) if isinstance(report.get("release_qualification"), dict) else {}
    gate = report.get("guardian_gate") if isinstance(report.get("guardian_gate"), dict) else None
    blocking_targets = _as_int(summary.get("blocking_target_count"))
    coverage_gaps = _as_int(summary.get("coverage_gap_target_count"))
    review_passed = review.get("passed") is True
    application_assurance = _application_assurance(report, review_passed)
    report["application_assurance"] = application_assurance
    auditor_qualification = _auditor_qualification(qualification)
    report["auditor_qualification"] = auditor_qualification
    gate_evaluated_passed = (
        gate.get("evaluation_passed", gate.get("passed")) is True
        if gate is not None
        else False
    )
    authority_blockers = (
        _release_authority_blockers(report, review)
        if gate is not None and gate_evaluated_passed
        else []
    )
    if gate is not None:
        evaluated_passed = gate.get("evaluation_passed", gate.get("passed")) is True
        gate["evaluation_passed"] = evaluated_passed
        gate["canonical_release_authority"] = evaluated_passed and not authority_blockers
        gate["operator_keyed_evidence"] = "operator_keyed_evidence_required" not in authority_blockers
        gate["authority_blockers"] = authority_blockers
        gate["passed"] = evaluated_passed and not authority_blockers
        if gate["passed"] is True:
            gate["recommendation"] = "Canonical high-threshold release authority is bound to the current app, target evidence, source snapshot, and operator-keyed bundle."
        elif evaluated_passed and authority_blockers:
            gate["recommendation"] = "Canonical release authority is unavailable: " + ", ".join(authority_blockers)

    if gate is not None and gate.get("passed") is True:
        verdict_code = "ship"
        verdict = "설정한 기준에서는 출하 가능합니다."
        summary_line = "검수 범위가 채워졌고 현재 출하를 막는 항목이 없습니다."
        next_actions = [
            "같은 커밋의 Guardian 보고서와 증거 묶음을 릴리스 산출물로 보관하세요.",
            "배포 직전에 동일한 high 기준으로 Guardian을 한 번 더 실행하세요.",
        ]
    elif gate is not None and authority_blockers:
        verdict_code = "hold_authority"
        verdict = "아직 출하하지 마세요. 출하 권한 증거가 부족합니다."
        summary_line = "korean_senior 단일 앱 범위와 운영자 키 서명이 모두 필요합니다."
        next_actions = [
            "모든 manifest 대상에 동일한 app_id와 korean_senior 프로필을 지정하세요.",
            "K_GUARD_EVIDENCE_HMAC_KEY를 설정하고 같은 소스에서 Guardian을 다시 실행하세요.",
        ]
    elif gate is not None and not review_passed:
        verdict_code = "hold_coverage"
        verdict = "아직 출하하지 마세요. 검수 범위부터 채워야 합니다."
        summary_line = "문제가 없다는 뜻이 아니라, 확인해야 할 영역의 증거가 부족합니다."
        next_actions = _coverage_actions(review)
    elif gate is not None and application_assurance.get("status") == "risk_blocked":
        verdict_code = "hold_fix"
        verdict = "아직 출하하지 마세요. 앱에서 막는 항목부터 고칩니다."
        summary_line = str(application_assurance.get("message") or "검수한 앱 범위에 critical/high 위험이 남았습니다.")
        next_actions = _finding_actions(report)
    elif gate is not None and bool(qualification) and qualification.get("passed") is not True and not _has_actionable_nonqualification_blocker(report):
        failed_gates = gate.get("failed_qualification_gates", []) if isinstance(gate.get("failed_qualification_gates"), list) else []
        verdict_code = "hold_qualification"
        verdict = "아직 출하하지 마세요. 필수 검증 증거가 덜 찼습니다."
        summary_line = "앱 위험 검수는 CLEAR지만, 감사 도구 자체의 deep/multilanguage, SCA, Streamable HTTP 런타임, DB 제어, field accuracy 증거가 덜 찼습니다."
        next_actions = [
            "현재 소스에서 9개 언어 deep 분석, SCA, control-validate 보고서를 운영자 키로 생성하세요.",
            "Streamable HTTP 프록시의 POST/GET/DELETE, JSON/SSE, 허용/거부, 감사 체인 매트릭스를 실행하세요.",
            "12~20개 owned/partner 앱의 사전등록·독립 라벨링 field 보고서를 완성하세요.",
        ]
        if failed_gates:
            summary_line = summary_line + " 미완료: " + ", ".join(str(item) for item in failed_gates[:3])
    elif gate is not None and coverage_gaps > 0:
        verdict_code = "hold_coverage"
        verdict = "아직 출하하지 마세요. 검수 범위부터 채워야 합니다."
        summary_line = "문제가 없다는 뜻이 아니라, 확인해야 할 영역의 증거가 부족합니다."
        next_actions = _coverage_actions(review)
    elif gate is not None and blocking_targets > 0:
        verdict_code = "hold_fix"
        verdict = "아직 출하하지 마세요. 막는 항목부터 고칩니다."
        summary_line = f"출하를 막는 대상이 {blocking_targets}개 있습니다."
        next_actions = _finding_actions(report)
    elif gate is not None and qualification.get("passed") is not True:
        failed_gates = gate.get("failed_qualification_gates", []) if isinstance(gate.get("failed_qualification_gates"), list) else []
        verdict_code = "hold_qualification"
        verdict = "아직 출하하지 마세요. 필수 검증 증거가 덜 찼습니다."
        summary_line = "deep/multilanguage, SCA, Streamable HTTP 권한 런타임, DB 제어, field accuracy 중 하나 이상이 완료되지 않았습니다."
        next_actions = [
            "현재 앱 소스의 9개 언어 Semgrep deep 분석, SCA, control-validate 보고서를 운영자 키로 생성하세요.",
            "Streamable HTTP 프록시를 실제 MCP 왕복에 사용하고 권한 허용·거부와 감사 체인 증거를 남기세요.",
            "12~20개 owned/partner 앱의 사전등록·독립 라벨링 field 보고서를 완성하세요.",
        ]
        if failed_gates:
            summary_line = summary_line + " 미완료: " + ", ".join(str(item) for item in failed_gates[:3])
    elif gate is not None:
        verdict_code = "hold_fix"
        verdict = "아직 출하하지 마세요. 막는 항목부터 고칩니다."
        summary_line = f"출하를 막는 대상이 {blocking_targets}개 있습니다."
        next_actions = _finding_actions(report)
    else:
        verdict_code = "review_only"
        verdict = "검수는 끝났지만 출하 판정은 아직입니다."
        summary_line = "현재 결과는 검토용입니다. high 기준의 Guardian 게이트를 실행해야 출하 판정이 생깁니다."
        next_actions = [
            "guardian_audit를 fail_on=high로 다시 실행하세요.",
            "네 영역의 review_contract가 모두 통과했는지 확인하세요.",
        ]

    presentation = _presentation(verdict_code, verdict, summary_line, next_actions)
    report["experience"] = {
        "product": PRODUCT_NAME,
        "persona": PERSONA_NAME,
        "role": PERSONA_ROLE,
        "north_star": NORTH_STAR,
        "verdict_code": verdict_code,
        "verdict": {"code": verdict_code, "message": verdict},
        "verdict_message": verdict,
        "why": summary_line,
        "summary": summary_line,
        "next_actions": next_actions[:3],
        "application_assurance": application_assurance,
        "auditor_qualification": auditor_qualification,
        "presentation": presentation,
        "details": {
            "tool": "guardian_audit",
            "release_authority": gate.get("canonical_release_authority") is True if gate is not None else False,
            "application_assurance": application_assurance,
            "auditor_qualification": auditor_qualification,
            "presentation": presentation,
            "raw_returned": False,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "raw_returned": False,
    }
    return report


def _auditor_qualification(qualification: dict[str, Any]) -> dict[str, Any]:
    gates = qualification.get("gates", {}) if isinstance(qualification.get("gates"), dict) else {}
    failed = [str(name) for name, value in gates.items() if not isinstance(value, dict) or value.get("passed") is not True]
    passed = qualification.get("passed") is True
    return {
        "passed": passed,
        "status": "qualified" if passed else "evidence_incomplete",
        "failed_gates": [str(item) for item in failed[:10]],
        "meaning": "Version-level evidence that K-Guard's analyzers and runtime controls meet the configured release qualification contract.",
        "separate_from_application_assurance": True,
        "release_authority_effect": "required_for_canonical_ship",
        "raw_returned": False,
    }


def _application_assurance(report: dict[str, Any], review_passed: bool) -> dict[str, Any]:
    blocker_count = 0
    blocker_rules: set[str] = set()
    for target in report.get("targets", []) if isinstance(report.get("targets"), list) else []:
        if not isinstance(target, dict):
            continue
        for finding in target.get("findings", []) if isinstance(target.get("findings"), list) else []:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "").lower()
            rule_id = str(finding.get("rule_id") or "")
            if severity in {"critical", "high"} and rule_id not in QUALIFICATION_COVERAGE_RULES:
                blocker_count += 1
                if rule_id:
                    blocker_rules.add(rule_id)
    passed = review_passed and blocker_count == 0
    if not review_passed:
        status = "coverage_incomplete"
        message = "앱 위험 판정에 필요한 네 영역 검수 범위가 아직 덜 찼습니다."
    elif blocker_count:
        status = "risk_blocked"
        message = f"검수한 앱 범위에 critical/high 위험이 {blocker_count}건 남았습니다."
    else:
        status = "clear_in_reviewed_scope"
        message = "검수한 앱 범위의 critical/high 위험은 해소됐습니다."
    return {
        "passed": passed,
        "status": status,
        "message": message,
        "blocking_finding_count": blocker_count,
        "blocking_rule_ids": sorted(blocker_rules)[:10],
        "qualification_findings_excluded": sorted(QUALIFICATION_COVERAGE_RULES),
        "release_authority": False,
        "claim_boundary": "앱 자체의 검수 범위 판정이며 SHIP 승인이 아닙니다. SHIP은 Guardian qualification과 canonical release authority까지 통과해야 합니다.",
        "raw_returned": False,
    }


def _has_actionable_nonqualification_blocker(report: dict[str, Any]) -> bool:
    qualification_coverage_rules = {
        "DEEP_ANALYSIS_COVERAGE_INCOMPLETE",
        "SCA_COVERAGE_INCOMPLETE",
    }
    for target in report.get("targets", []) if isinstance(report.get("targets"), list) else []:
        if not isinstance(target, dict) or target.get("gate", {}).get("passed") is not False:
            continue
        for finding in target.get("findings", []) if isinstance(target.get("findings"), list) else []:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("severity") or "").lower() in {"critical", "high"} and str(finding.get("rule_id") or "") not in qualification_coverage_rules:
                return True
    return False


def _presentation(code: str, verdict: str, why: str, next_actions: list[str]) -> dict[str, Any]:
    return {
        "schema": "k_guard_senpai_presentation.v1",
        "order": ["verdict", "why", "next_actions", "details"],
        "verdict": {"code": code, "message": verdict},
        "why": why,
        "next_actions": next_actions[:3],
        "details_after_actions": True,
        "raw_returned": False,
    }


def _release_authority_blockers(report: dict[str, Any], review: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    gate = report.get("guardian_gate", {}) if isinstance(report.get("guardian_gate"), dict) else {}
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    drift = report.get("drift", {}) if isinstance(report.get("drift"), dict) else {}
    qualification = report.get("release_qualification", {}) if isinstance(report.get("release_qualification"), dict) else {}
    if qualification.get("passed") is not True:
        blockers.append("release_qualification_required")
    if (
        review.get("profile") != "korean_senior"
        or review.get("strict_domain_enforcement") is not True
        or review.get("release_gate_enabled") is not True
        or review.get("canonical_release_authority") is not True
        or review.get("release_authority") != "canonical"
        or review.get("report_only") is not False
    ):
        blockers.append("korean_senior_profile_required")
    if review.get("single_app_scope") is not True or not str(review.get("app_id") or "").strip():
        blockers.append("single_nonempty_app_id_required")
    if (
        gate.get("enabled") is not True
        or gate.get("fail_on") != "high"
        or gate.get("evaluation_passed", gate.get("passed")) is not True
        or gate.get("review_contract_passed") is not True
        or gate.get("review_profile") != "korean_senior"
        or gate.get("missing_review_domains") != []
        or gate.get("release_qualification_passed") is not True
        or gate.get("failed_qualification_gates") != []
        or _as_int(gate.get("blocking_target_count")) != _as_int(summary.get("blocking_target_count"))
        or _as_int(gate.get("new_blocking_finding_count")) != _as_int(drift.get("new_blocking_finding_count"))
        or _as_int(summary.get("blocking_target_count")) != 0
        or _as_int(summary.get("coverage_gap_target_count")) != 0
        or _as_int(drift.get("new_blocking_finding_count")) != 0
    ):
        blockers.append("canonical_high_guardian_gate_required")
    if not _authority_targets_are_bound(report, str(review.get("app_id") or "")):
        blockers.append("target_release_evidence_binding_required")
    expected_claim = release_authority_claim(report)
    if report.get("release_authority_claim") != expected_claim:
        blockers.append("release_authority_claim_mismatch")
    bundle = report.get("evidence_bundle")
    if not verify_evidence_bundle(bundle, require_operator_key=True):
        blockers.append("operator_keyed_evidence_required")
    elif not _bundle_binds_release_claim(bundle, report, expected_claim):
        blockers.append("release_evidence_binding_required")
    return blockers


def release_authority_claim(report: dict[str, Any]) -> dict[str, Any]:
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    targets = report.get("targets", []) if isinstance(report.get("targets"), list) else []
    target_refs: list[dict[str, Any]] = []
    for row in targets:
        if not isinstance(row, dict):
            continue
        evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
        snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
        target_refs.append(
            {
                "app_id_hash": evidence_hash(str(row.get("app_id") or "")),
                "target_id_hash": evidence_hash(str(row.get("target_id") or "")),
                "kind": str(row.get("kind") or ""),
                "audit_profile": str(row.get("audit_profile") or ""),
                "fail_on": str(row.get("fail_on") or ""),
                "status": str(row.get("status") or ""),
                "gate_passed": row.get("gate", {}).get("passed") if isinstance(row.get("gate"), dict) else None,
                "review_evidence_hash": evidence_hash(canonical_json(evidence)),
                "target_evidence_hash": evidence_hash(
                    canonical_json(_authority_target_projection(row))
                ),
                "source_tree_sha256": str(snapshot.get("tree_sha256") or ""),
                "source_tree_complete": snapshot.get("complete") is True if row.get("kind") == "workspace" else None,
                "raw_returned": False,
            }
        )
    target_refs.sort(key=lambda item: (item["app_id_hash"], item["target_id_hash"], item["kind"]))
    return {
        "schema": "k_guard_guardian_release_authority_claim.v1",
        "method": report.get("method"),
        "app_id_hash": evidence_hash(str(review.get("app_id") or "")),
        "profile": review.get("profile"),
        "gate_threshold": _gate_input_projection(report).get("fail_on"),
        "summary_hash": evidence_hash(canonical_json(report.get("summary", {}))),
        "drift_hash": evidence_hash(canonical_json(report.get("drift", {}))),
        "execution_contract_hash": evidence_hash(canonical_json(report.get("execution_contract", {}))),
        "review_contract_hash": evidence_hash(canonical_json(review)),
        "release_qualification_hash": evidence_hash(canonical_json(report.get("release_qualification", {}))),
        "guardian_gate_input_hash": evidence_hash(canonical_json(_gate_input_projection(report))),
        "target_count": len(target_refs),
        "target_refs": target_refs,
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _gate_input_projection(report: dict[str, Any]) -> dict[str, Any]:
    gate = report.get("guardian_gate", {}) if isinstance(report.get("guardian_gate"), dict) else {}
    return {
        "enabled": gate.get("enabled"),
        "evaluation_passed": gate.get("evaluation_passed", gate.get("passed")),
        "fail_on": gate.get("fail_on"),
        "blocking_target_count": gate.get("blocking_target_count"),
        "new_blocking_finding_count": gate.get("new_blocking_finding_count"),
        "review_contract_passed": gate.get("review_contract_passed"),
        "review_profile": gate.get("review_profile"),
        "missing_review_domains": gate.get("missing_review_domains"),
        "release_qualification_passed": gate.get("release_qualification_passed"),
        "failed_qualification_gates": gate.get("failed_qualification_gates"),
    }


def _authority_targets_are_bound(report: dict[str, Any], app_id: str) -> bool:
    targets = report.get("targets", [])
    if not isinstance(targets, list) or not targets or not app_id:
        return False
    for row in targets:
        if not isinstance(row, dict):
            return False
        if (
            str(row.get("app_id") or "") != app_id
            or row.get("audit_profile") != "korean_senior"
            or row.get("fail_on") != "high"
            or row.get("status") != "completed"
            or not isinstance(row.get("gate"), dict)
            or row["gate"].get("passed") is not True
        ):
            return False
        coverage = row.get("coverage", {}) if isinstance(row.get("coverage"), dict) else {}
        scope = row.get("scope_contract", {}) if isinstance(row.get("scope_contract"), dict) else {}
        business = row.get("business_context", {}) if isinstance(row.get("business_context"), dict) else {}
        assertion_ref = scope.get("assertion_ref", {}) if isinstance(scope.get("assertion_ref"), dict) else {}
        findings = row.get("findings", [])
        if (
            coverage.get("coverage_gap") is not False
            or scope.get("assertion_present") is not True
            or scope.get("ownership_or_partner_scope_verified_by_k_guard") is not False
            or assertion_ref.get("raw_returned") is not False
            or not str(assertion_ref.get("hash") or "")
            or business.get("purpose_present") is not True
            or business.get("purpose_explicit") is not True
            or business.get("user_scope_present") is not True
            or not (
                business.get("data_classes")
                or _as_int(business.get("custom_data_class_count")) > 0
            )
            or not isinstance(findings, list)
        ):
            return False
        for finding in findings:
            if not isinstance(finding, dict):
                return False
            severity = str(finding.get("severity") or "").strip().lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                return False
            if severity in {"critical", "high"}:
                return False
        if row.get("kind") == "workspace":
            evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
            snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
            inventory = evidence.get("scan_inventory_consistency", {}) if isinstance(evidence.get("scan_inventory_consistency"), dict) else {}
            candidate_hash = str(inventory.get("scanner_candidate_path_set_sha256") or "")
            if (
                snapshot.get("complete") is not True
                or snapshot.get("limit_exceeded") is not False
                or len(str(snapshot.get("tree_sha256") or "")) != 64
                or inventory.get("matched") is not True
                or inventory.get("raw_returned") is not False
                or _as_int(inventory.get("before_candidate_count"), -1) != _as_int(inventory.get("after_candidate_count"), -2)
                or _as_int(inventory.get("before_candidate_count"), -1) != _as_int(inventory.get("scanner_candidate_count"), -2)
                or _as_int(inventory.get("before_candidate_count"), -1)
                != _as_int(inventory.get("reviewed_candidate_count", inventory.get("scanned_text_file_count")), -2)
                or _as_int(inventory.get("unscanned_candidate_count"), -1) != 0
                or len(candidate_hash) != 64
                or str(inventory.get("before_candidate_path_set_sha256") or "") != candidate_hash
                or str(inventory.get("after_candidate_path_set_sha256") or "") != candidate_hash
            ):
                return False
    return True


def _bundle_binds_release_claim(
    bundle: object,
    report: dict[str, Any],
    claim: dict[str, Any],
) -> bool:
    if not isinstance(bundle, dict):
        return False
    if bundle.get("subject") != "guardian_audit" or bundle.get("producer") != "k_guard_mcp.guardian":
        return False
    expected = [
        object_artifact("summary", report.get("summary", {})),
        object_artifact("review_contract", report.get("review_contract", {})),
        object_artifact("guardian_gate", report.get("guardian_gate", {}), role="gate"),
        object_artifact("release_authority_claim", claim, role="gate"),
        object_artifact(
            "target_refs",
            release_target_evidence_refs(report.get("targets", [])),
        ),
    ]
    artifacts = bundle.get("artifacts", []) if isinstance(bundle.get("artifacts"), list) else []
    for expected_artifact in expected:
        match = next(
            (
                item
                for item in artifacts
                if isinstance(item, dict)
                and item.get("label") == expected_artifact.get("label")
                and item.get("role", "evidence") == expected_artifact.get("role", "evidence")
            ),
            None,
        )
        if not isinstance(match, dict):
            return False
        if any(
            match.get(key) != expected_artifact.get(key)
            for key in ("hash", "hash_scheme", "byte_count", "content_sha256", "exists_at_bundle_time")
        ):
            return False
        if match.get("raw_returned") is not False:
            return False
    return True


def release_target_evidence_refs(rows: object) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if not isinstance(rows, list):
        return refs
    for row in rows:
        if not isinstance(row, dict):
            continue
        projection = _authority_target_projection(row)
        refs.append(
            {
                "app_id": row.get("app_id", ""),
                "app_id_hash": evidence_hash(str(row.get("app_id") or "")),
                "target_id_hash": evidence_hash(str(row.get("target_id") or "")),
                "hash_scheme": evidence_hash_scheme(),
                "kind": row.get("kind", "unknown"),
                "status": row.get("status", "unknown"),
                "audit_profile": row.get("audit_profile", "standard"),
                "gate_passed": row.get("gate", {}).get("passed") if isinstance(row.get("gate"), dict) else None,
                "finding_count": len(row.get("findings", [])) if isinstance(row.get("findings"), list) else 0,
                "rule_count": len(row.get("rule_ids", [])) if isinstance(row.get("rule_ids"), list) else 0,
                "business_context_hash": evidence_hash(canonical_json(row.get("business_context", {}))),
                "scope_contract_hash": evidence_hash(canonical_json(row.get("scope_contract", {}))),
                "requested_review_hash": evidence_hash(canonical_json(row.get("requested_review", {}))),
                "review_evidence_hash": evidence_hash(canonical_json(row.get("review_evidence", {}))),
                "gate_hash": evidence_hash(canonical_json(row.get("gate", {}))),
                "coverage_hash": evidence_hash(canonical_json(row.get("coverage", {}))),
                "findings_hash": evidence_hash(canonical_json(row.get("findings", []))),
                "rule_ids_hash": evidence_hash(canonical_json(row.get("rule_ids", []))),
                "target_evidence_hash": evidence_hash(canonical_json(projection)),
                "raw_returned": False,
            }
        )
    return refs


def _authority_target_projection(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "app_id": row.get("app_id", ""),
        "target_id": row.get("target_id", ""),
        "kind": row.get("kind", "unknown"),
        "status": row.get("status", "unknown"),
        "audit_profile": row.get("audit_profile", "standard"),
        "fail_on": row.get("fail_on", ""),
        "gate": row.get("gate", {}),
        "coverage": row.get("coverage", {}),
        "business_context": row.get("business_context", {}),
        "scope_contract": row.get("scope_contract", {}),
        "requested_review": row.get("requested_review", {}),
        "review_evidence": row.get("review_evidence", {}),
        "findings": row.get("findings", []),
        "rule_ids": row.get("rule_ids", []),
    }


def _coverage_actions(review: dict[str, Any]) -> list[str]:
    domains = review.get("domains", {}) if isinstance(review.get("domains"), dict) else {}
    missing_domains = [str(name) for name, value in domains.items() if not isinstance(value, dict) or value.get("passed") is not True]
    actions = []
    if missing_domains:
        actions.append("빠진 검수 영역을 채우세요: " + ", ".join(sorted(missing_domains)))
    actions.append("workspace, flow, deep HTTP, 목적·데이터·사용자·범위 증거를 다시 확인하세요.")
    actions.append("같은 소스 커밋에서 Guardian을 다시 실행하세요.")
    return actions


def _finding_actions(report: dict[str, Any]) -> list[str]:
    top_rules = report.get("top_rules", []) if isinstance(report.get("top_rules"), list) else []
    rule_ids = [str(item.get("rule_id")) for item in top_rules if isinstance(item, dict) and item.get("rule_id")][:3]
    actions = []
    if rule_ids:
        actions.append("우선 고칠 규칙: " + ", ".join(rule_ids))
    actions.append("각 규칙에 suggest_fix를 호출하고 수정 후 같은 게이트를 다시 실행하세요.")
    return actions


def _severity_counts(report: dict[str, Any]) -> dict[str, int]:
    severities = ("critical", "high", "medium", "low", "info")
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    counts = {severity: max(0, _as_int(summary.get(severity))) for severity in severities}
    if any(counts.values()):
        return counts
    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "").lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _safe_rule_ids(findings: list[Any]) -> list[str]:
    rule_ids: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "").strip().upper()
        if not re.fullmatch(r"[A-Z0-9_.:-]{1,100}", rule_id) or rule_id in rule_ids:
            continue
        rule_ids.append(rule_id)
    return rule_ids


def _runtime_policy(report: dict[str, Any]) -> dict[str, Any]:
    metadata = report.get("metadata", {}) if isinstance(report.get("metadata"), dict) else {}
    policy = metadata.get("runtime_policy", {}) if isinstance(metadata.get("runtime_policy"), dict) else {}
    return policy


def _control_incomplete(report: dict[str, Any], rule_ids: list[str]) -> bool:
    gate = report.get("security_gate", {}) if isinstance(report.get("security_gate"), dict) else {}
    if gate.get("control_failed") is True or (
        gate and str(gate.get("control_status") or "completed") != "completed"
    ):
        return True
    contract = report.get("execution_contract", {}) if isinstance(report.get("execution_contract"), dict) else {}
    if contract.get("coverage_gap") is True:
        return True
    return any(_is_control_rule_id(rule_id) for rule_id in rule_ids)


def _is_control_rule_id(rule_id: str) -> bool:
    control_markers = ("FAILED", "DISABLED", "BUDGET", "INVALID", "MISSING", "NOT_EXECUTED", "REQUIRED")
    return rule_id.startswith(CONTROL_RULE_PREFIXES) or (
        rule_id.startswith("MCP_") and any(marker in rule_id for marker in control_markers)
    )


def _incomplete_actions(
    findings: list[Any],
    control_rule_ids: list[str],
    confirmed_blocking_rule_ids: list[str],
) -> list[str]:
    actions: list[str] = []
    if control_rule_ids:
        actions.append("검수 미완료 규칙: " + ", ".join(control_rule_ids[:3]))
    else:
        actions.append("검수 실행 상태와 범위 증거를 확인하세요.")

    remediation = ""
    for finding in findings:
        if not isinstance(finding, dict) or str(finding.get("rule_id") or "") not in control_rule_ids:
            continue
        remediation = " ".join(str(finding.get("recommendation") or finding.get("remediation") or "").split())[:240]
        if remediation:
            break
    actions.append(
        f"복구 후 같은 도구와 범위로 다시 실행: {remediation}"
        if remediation
        else "미완료 원인을 복구한 뒤 같은 도구와 같은 범위로 다시 실행하세요."
    )
    if confirmed_blocking_rule_ids:
        actions.append("이미 확인된 차단 위험 수정: " + ", ".join(confirmed_blocking_rule_ids[:3]))
    return actions[:3]


def _generic_actions(rule_ids: list[str], *, retry: bool) -> list[str]:
    actions: list[str] = []
    if rule_ids:
        actions.append("먼저 확인할 규칙: " + ", ".join(rule_ids[:3]))
    if retry:
        actions.append("원인을 고친 뒤 같은 도구와 같은 범위로 다시 확인하세요.")
    actions.append("출하 판정은 start_review_before_ship으로 네 영역을 모두 확인하세요.")
    return actions[:3]


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
