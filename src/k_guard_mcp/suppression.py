from __future__ import annotations

import csv
import hashlib
import io
import re
from collections import Counter
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.experience import release_target_evidence_refs
from k_guard_mcp.models import Finding, ScanResult
from k_guard_mcp.provenance import canonical_json
from k_guard_mcp.recipes import recipe_for_rule
from k_guard_mcp.redaction import sanitize_any
from k_guard_mcp.severity import severity_rank


SUPPRESSION_FIELDS = [
    "app_id",
    "audit_profile",
    "release_scope_hash",
    "target_id",
    "rule_id",
    "finding_fingerprint",
    "file",
    "line_start",
    "owner",
    "reason",
    "expires",
    "notes",
]
SUPPRESSION_EVIDENCE_FRESHNESS_SECONDS = 24 * 60 * 60
UNSUPPRESSIBLE_RULE_PREFIXES = (
    "DEEP_ANALYSIS_COVERAGE_",
    "GUARDIAN_",
    "MCP_ARGUMENT_BUDGET_",
    "MCP_DEEP_ACTIVE_PROBE_",
    "MCP_DIFF_SCAN_FAILED",
    "MCP_EXTERNAL_PROBE_",
    "MCP_GUARDIAN_",
    "MCP_PROBE_DISABLED",
    "MCP_SECURITY_GATE_",
    "MCP_SESSION_PROBE_",
    "MCP_TEXT_INPUT_BUDGET_",
    "MCP_WORKSPACE_BUDGET_",
    "MCP_WORKSPACE_SCAN_BUDGET_",
    "SCA_COVERAGE_",
)


def write_suppression_template(path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUPPRESSION_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "app_id": "owned-app-01",
                "audit_profile": "korean_senior",
                "release_scope_hash": "paste-source-tree-or-review-evidence-hash",
                "rule_id": "JS_TS_EXPRESS_IDOR_ROUTE_PARAM",
                "finding_fingerprint": "paste-finding-fingerprint-from-report",
                "target_id": "app-workspace",
                "file": "",
                "line_start": "",
                "owner": "team-or-person",
                "reason": "documented false positive or accepted bounded risk",
                "expires": "2026-12-31",
                "notes": "suppression must be renewed before expiry",
            }
        )


def apply_suppressions_to_result(
    result: ScanResult,
    suppression_path: str | Path | None,
    target_id: str = "",
    *,
    app_id: str = "",
    audit_profile: str = "standard",
    release_scope_hash: str = "",
) -> ScanResult:
    if not suppression_path:
        return result
    policy = _load_policy(suppression_path)
    policy_findings = list(policy["invalid_findings"])
    kept: list[Finding] = []
    suppressed = []
    for finding in result.findings:
        finding_dict = finding.to_dict()
        finding_dict["app_id"] = app_id
        finding_dict["audit_profile"] = audit_profile
        finding_dict["release_scope_hash"] = release_scope_hash
        finding_dict["finding_fingerprint"] = finding_fingerprint(finding_dict)
        finding_dict["target_id"] = target_id
        match = _matching_record(finding_dict, policy["valid"])
        if match:
            if _is_unsuppressible_rule(str(finding_dict.get("rule_id") or "")):
                policy_findings.append(_invalid_policy_finding("SUPPRESSION_POLICY_UNSUPPRESSIBLE_RULE", f"rule_id={finding_dict.get('rule_id')} fingerprint={finding_dict.get('finding_fingerprint')}"))
                kept.append(finding)
                continue
            suppressed.append(_suppressed_summary(finding_dict, match))
            continue
        kept.append(finding)
    kept.extend(policy_findings)
    metadata = dict(result.metadata)
    metadata["suppression_policy"] = _suppression_evidence(policy, policy_findings, suppressed, suppression_path)
    return ScanResult(findings=kept, flow_map=result.flow_map, metadata=metadata).finalize()


def apply_suppressions_to_guardian_report(report: dict[str, Any], suppression_path: str | Path | None) -> dict[str, Any]:
    if not suppression_path:
        return report
    policy = _load_policy(suppression_path)
    policy_findings = list(policy["invalid_findings"])
    rows = report.get("targets", [])
    pre_suppression_sha256 = _guardian_target_evidence_sha256(rows)
    attestation = report.get("execution_attestation", {}) if isinstance(report.get("execution_attestation"), dict) else {}
    execution_input_binding = {
        "execution_id": report.get("execution_id"),
        "pre_suppression_target_evidence_sha256": pre_suppression_sha256,
        "valid": bool(
            pre_suppression_sha256
            and pre_suppression_sha256 == attestation.get("target_evidence_sha256")
            and attestation.get("execution_id") == report.get("execution_id")
        ),
        "raw_returned": False,
    }
    if execution_input_binding["valid"] is not True:
        policy_findings.append(
            _invalid_policy_finding(
                "SUPPRESSION_EXECUTION_ATTESTATION_MISMATCH",
                f"execution_id_ref={evidence_hash(str(report.get('execution_id') or ''))}",
            )
        )
    active_records = policy["valid"] if execution_input_binding["valid"] is True else []
    suppressed: list[dict[str, Any]] = []
    for row in (rows if isinstance(rows, list) else []):
        if not isinstance(row, dict):
            continue
        binding = _guardian_row_suppression_binding(row)
        kept_findings = []
        for finding in row.get("findings", []):
            if not isinstance(finding, dict):
                continue
            finding = dict(finding)
            finding.update(binding)
            finding["target_id"] = row.get("target_id", "")
            finding["finding_fingerprint"] = finding_fingerprint(finding)
            match = _matching_record(finding, active_records)
            if match:
                if _is_unsuppressible_rule(str(finding.get("rule_id") or "")):
                    policy_findings.append(_invalid_policy_finding("SUPPRESSION_POLICY_UNSUPPRESSIBLE_RULE", f"rule_id={finding.get('rule_id')} fingerprint={finding.get('finding_fingerprint')}"))
                    kept_findings.append(finding)
                    continue
                suppressed.append(_suppressed_summary(finding, match))
                continue
            kept_findings.append(finding)
        row["findings"] = kept_findings
        _refresh_guardian_row(row)
    if policy_findings:
        invalid_dicts = [finding.to_dict() for finding in policy_findings]
        rows.append(_suppression_policy_error_row(invalid_dicts))
    report["targets"] = rows
    all_findings = _all_guardian_findings(rows)
    report["findings"] = all_findings
    report["summary"] = _guardian_summary(rows)
    report["top_rules"] = _top_rules(all_findings)
    report["fix_plan"] = _fix_plan(all_findings)
    _refresh_guardian_drift(report, rows)
    report["suppression_policy"] = _suppression_evidence(
        policy,
        policy_findings,
        suppressed,
        suppression_path,
        execution_input_binding=execution_input_binding,
    )
    if isinstance(report.get("execution_contract"), dict):
        report["execution_contract"]["suppression_policy"] = "applied_fail_closed" if policy_findings else "applied"
        report["execution_contract"]["suppressed_finding_count"] = len(suppressed)
    return sanitize_any(report)


def finding_fingerprint(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("app_id") or ""),
        str(finding.get("audit_profile") or ""),
        str(finding.get("release_scope_hash") or ""),
        str(finding.get("target_id") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("source") or ""),
        str(finding.get("file") or finding.get("url") or ""),
        str(finding.get("line_start") or ""),
        str(finding.get("evidence") or ""),
    ]
    return evidence_hash("|".join(parts))


def _path_ref(path: str | Path) -> dict[str, Any]:
    text = str(path)
    return {"hash": evidence_hash(text), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _load_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path)
    valid: list[dict[str, str]] = []
    invalid_findings: list[Finding] = []
    evaluated_at = datetime.now(UTC).isoformat()
    if not policy_path.exists():
        invalid_findings.append(_invalid_policy_finding("SUPPRESSION_POLICY_NOT_FOUND", f"suppression_path_ref={evidence_hash(str(path))}"))
        return {
            "valid": valid,
            "invalid_findings": invalid_findings,
            "evaluated_at": evaluated_at,
            "policy_sha256": "",
            "byte_count": 0,
            "exists": False,
        }
    try:
        content = policy_path.read_bytes()
        text = content.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text, newline="")))
    except (OSError, UnicodeError, csv.Error):
        invalid_findings.append(_invalid_policy_finding("SUPPRESSION_POLICY_UNREADABLE", f"suppression_path_ref={evidence_hash(str(path))}"))
        return {
            "valid": valid,
            "invalid_findings": invalid_findings,
            "evaluated_at": evaluated_at,
            "policy_sha256": "",
            "byte_count": 0,
            "exists": True,
        }
    for index, row in enumerate(rows, start=2):
        normalized = {field: str(row.get(field, "") or "").strip() for field in SUPPRESSION_FIELDS}
        error = _policy_row_error(normalized)
        if error:
            invalid_findings.append(_invalid_policy_finding("SUPPRESSION_POLICY_ROW_INVALID", f"row={index} error={error}"))
            continue
        valid.append(normalized)
    return {
        "valid": valid,
        "invalid_findings": invalid_findings,
        "evaluated_at": evaluated_at,
        "policy_sha256": hashlib.sha256(content).hexdigest(),
        "byte_count": len(content),
        "exists": True,
    }


def _suppression_evidence(
    policy: dict[str, Any],
    policy_findings: list[Finding],
    suppressed: list[dict[str, Any]],
    suppression_path: str | Path,
    *,
    execution_input_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evaluated_at = str(policy.get("evaluated_at") or "")
    try:
        evaluated = datetime.fromisoformat(evaluated_at)
        if evaluated.tzinfo is None:
            evaluated = evaluated.replace(tzinfo=UTC)
        evaluated = evaluated.astimezone(UTC)
    except ValueError:
        evaluated = datetime.now(UTC)
        evaluated_at = evaluated.isoformat()
    policy_expiries = sorted({str(row.get("expires") or "") for row in policy.get("valid", []) if row.get("expires")})
    freshness_end = evaluated + timedelta(seconds=SUPPRESSION_EVIDENCE_FRESHNESS_SECONDS)
    if policy_expiries:
        expiry_end = datetime.combine(date.fromisoformat(policy_expiries[0]), time.max, tzinfo=UTC)
        freshness_end = min(freshness_end, expiry_end)
    waived_refs = [
        {
            "app_id_hash": str(item.get("app_id_hash") or ""),
            "audit_profile": str(item.get("audit_profile") or ""),
            "release_scope_hash": str(item.get("release_scope_hash") or ""),
            "target_id": str(item.get("target_id") or ""),
            "rule_id": str(item.get("rule_id") or ""),
            "finding_fingerprint": str(item.get("finding_fingerprint") or ""),
            "expires": str(item.get("expires") or ""),
            "owner_hash": evidence_hash(str(item.get("owner") or "")),
            "reason_hash": str(item.get("reason_hash") or ""),
            "raw_returned": False,
        }
        for item in suppressed
    ]
    waived_refs.sort(key=lambda item: (item["app_id_hash"], item["target_id"], item["rule_id"], item["finding_fingerprint"]))
    return {
        "schema": "k_guard_suppression_evidence.v2",
        "path_ref": _path_ref(suppression_path),
        "source": {
            "content_sha256": str(policy.get("policy_sha256") or ""),
            "byte_count": int(policy.get("byte_count", 0)),
            "exists_at_evaluation": policy.get("exists") is True,
            "raw_returned": False,
        },
        "policy_sha256": str(policy.get("policy_sha256") or ""),
        "evaluated_at": evaluated_at,
        "fresh_until": freshness_end.isoformat(),
        "freshness_seconds": SUPPRESSION_EVIDENCE_FRESHNESS_SECONDS,
        "policy_expiries": policy_expiries,
        "valid_count": len(policy.get("valid", [])),
        "invalid_count": len(policy_findings),
        "suppressed_count": len(suppressed),
        "suppressed": suppressed,
        "waived_finding_refs": waived_refs,
        "execution_input_binding": execution_input_binding or {},
        "fail_closed_on_invalid_policy": True,
        "required_fields": [
            "app_id",
            "audit_profile",
            "release_scope_hash",
            "target_id",
            "rule_id",
            "finding_fingerprint",
            "owner",
            "reason",
            "expires",
        ],
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _guardian_target_evidence_sha256(rows: object) -> str:
    if not isinstance(rows, list):
        return ""
    return hashlib.sha256(canonical_json(release_target_evidence_refs(rows)).encode("utf-8")).hexdigest()


def _policy_row_error(row: dict[str, str]) -> str:
    for field in (
        "app_id",
        "audit_profile",
        "release_scope_hash",
        "target_id",
        "rule_id",
        "finding_fingerprint",
        "owner",
        "reason",
        "expires",
    ):
        if not row.get(field):
            return f"missing_{field}"
    if row["audit_profile"] != "korean_senior":
        return "audit_profile_must_be_korean_senior"
    if not re.fullmatch(r"[0-9a-f]{16,64}", row["release_scope_hash"]):
        return "invalid_release_scope_hash"
    try:
        expires = date.fromisoformat(row["expires"])
    except ValueError:
        return "invalid_expires"
    if expires < datetime.now(UTC).date():
        return "expired"
    return ""


def _matching_record(finding: dict[str, Any], records: list[dict[str, str]]) -> dict[str, str] | None:
    for record in records:
        if record["app_id"] != str(finding.get("app_id") or ""):
            continue
        if record["audit_profile"] != str(finding.get("audit_profile") or ""):
            continue
        if record["release_scope_hash"] != str(finding.get("release_scope_hash") or ""):
            continue
        if record["target_id"] != str(finding.get("target_id") or ""):
            continue
        if record["rule_id"] != str(finding.get("rule_id") or ""):
            continue
        if record["finding_fingerprint"] != str(finding.get("finding_fingerprint") or ""):
            continue
        if record.get("file") and record["file"] != str(finding.get("file") or ""):
            continue
        if record.get("line_start") and record["line_start"] != str(finding.get("line_start") or ""):
            continue
        return record
    return None


def _suppressed_summary(finding: dict[str, Any], record: dict[str, str]) -> dict[str, Any]:
    return {
        "app_id_hash": evidence_hash(str(finding.get("app_id") or "")),
        "audit_profile": finding.get("audit_profile", ""),
        "release_scope_hash": finding.get("release_scope_hash", ""),
        "target_id": finding.get("target_id", ""),
        "rule_id": finding.get("rule_id", ""),
        "finding_fingerprint": finding.get("finding_fingerprint", ""),
        "owner": record.get("owner", ""),
        "expires": record.get("expires", ""),
        "reason_hash": evidence_hash(record.get("reason", "")),
        "raw_reason_returned": False,
    }


def _guardian_row_suppression_binding(row: dict[str, Any]) -> dict[str, str]:
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
    tree_sha256 = str(snapshot.get("tree_sha256") or "")
    release_scope_hash = tree_sha256 if len(tree_sha256) == 64 else evidence_hash(canonical_json(evidence))
    return {
        "app_id": str(row.get("app_id") or ""),
        "audit_profile": str(row.get("audit_profile") or ""),
        "release_scope_hash": release_scope_hash,
    }


def _invalid_policy_finding(rule_id: str, evidence: str) -> Finding:
    return Finding(
        id=f"suppression-{rule_id.lower()}-{evidence_hash(evidence)}",
        source="suppression-policy",
        rule_id=rule_id,
        severity="high",
        confidence="high",
        title="Suppression policy is invalid",
        evidence=f"{evidence} scheme={evidence_hash_scheme()} raw_returned=false",
        why_it_matters="Invalid suppressions can hide release blockers without owner, reason, expiry, or evidence binding.",
        recommendation="Fix the suppression CSV so every row has rule_id, finding_fingerprint, owner, reason, and a future expires date.",
        audit_depth=4,
        inspected_scope="Suppression policy metadata was validated without returning raw reason text.",
        not_inspected="K-Guard does not approve the business risk behind a suppression; it only enforces policy shape and expiry.",
    )


def _is_unsuppressible_rule(rule_id: str) -> bool:
    return rule_id.startswith(UNSUPPRESSIBLE_RULE_PREFIXES)


def _refresh_guardian_row(row: dict[str, Any]) -> None:
    findings = [item for item in row.get("findings", []) if isinstance(item, dict)]
    summary = Counter(str(item.get("severity") or "info") for item in findings)
    row["summary"] = {severity: summary.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")}
    fail_on = str(row.get("fail_on") or "high")
    blocking = [item for item in findings if severity_rank(str(item.get("severity") or "info")) <= severity_rank(fail_on)]
    coverage_gap = bool(row.get("coverage", {}).get("coverage_gap"))
    row["gate"] = {
        "passed": not blocking and not coverage_gap,
        "blocking_count": len(blocking) + (1 if coverage_gap else 0),
        "recommendation": "Fix coverage gap before release." if coverage_gap else ("Fix blocking findings before deploy." if blocking else "No blocking findings at this threshold."),
    }
    row["rule_ids"] = sorted({str(item.get("rule_id")) for item in findings if item.get("rule_id")})
    row["fixes"] = _fix_plan(findings, limit=10)


def _suppression_policy_error_row(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = Counter(str(item.get("severity") or "info") for item in findings)
    return {
        "target_id": "suppression-policy",
        "kind": "policy",
        "locator": "<suppression-policy>",
        "owner": "release",
        "authorization": {"authorized": True, "note": "local policy validation"},
        "fail_on": "high",
        "status": "error",
        "summary": {severity: summary.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")},
        "gate": {"passed": False, "blocking_count": len(findings), "recommendation": "Fix invalid suppression policy before release."},
        "coverage": {"executed": True, "coverage_gap": False, "status": "error"},
        "rule_ids": sorted({str(item.get("rule_id")) for item in findings if item.get("rule_id")}),
        "findings": findings,
        "fixes": _fix_plan(findings, limit=10),
    }


def _all_guardian_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in rows:
        for finding in row.get("findings", []):
            if isinstance(finding, dict):
                item = dict(finding)
                item.setdefault("target_id", row.get("target_id", ""))
                findings.append(item)
    return findings


def _guardian_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    for row in rows:
        kind_counts[str(row.get("kind", "unknown"))] += 1
        status_counts[str(row.get("status", "unknown"))] += 1
        for severity, count in row.get("summary", {}).items():
            severity_counts[severity] += int(count)
    return {
        "target_count": len(rows),
        "blocking_target_count": sum(1 for row in rows if not row.get("gate", {}).get("passed", True)),
        "coverage_gap_target_count": sum(1 for row in rows if row.get("coverage", {}).get("coverage_gap")),
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")},
        "kind_counts": dict(sorted(kind_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
    }


def _refresh_guardian_drift(report: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    drift = report.get("drift")
    if not isinstance(drift, dict) or not drift.get("comparison_available"):
        return
    current_blocking = Counter(_drift_record_key(record) for record in _finding_key_records(rows) if record["blocking"])
    old_new_blocking = [item for item in drift.get("new_blocking_findings", []) if isinstance(item, dict)]
    new_blocking = []
    for item in old_new_blocking:
        key = _drift_record_key(item)
        if current_blocking.get(key, 0) <= 0:
            continue
        current_blocking[key] -= 1
        new_blocking.append(item)
    drift["new_blocking_findings"] = new_blocking
    drift["new_blocking_finding_count"] = len(new_blocking)
    drift["suppression_policy"] = "recomputed_after_suppression"


def _finding_key_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for row in rows:
        fail_on = str(row.get("fail_on") or "high")
        for finding in row.get("findings", []):
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            records.append(
                {
                    "drift_key": _guardian_drift_key(row, finding),
                    "target_id": row.get("target_id"),
                    "rule_id": finding.get("rule_id"),
                    "severity": severity,
                    "source": finding.get("source"),
                    "location": str(finding.get("file") or finding.get("url") or "target"),
                    "line_start": finding.get("line_start"),
                    "method": finding.get("method"),
                    "status": finding.get("status"),
                    "blocking": severity_rank(severity) <= severity_rank(fail_on),
                }
            )
    return records


def _guardian_drift_key(row: dict[str, Any], finding: dict[str, Any]) -> str:
    return "|".join(
        [
            str(row.get("target_id", "")),
            str(finding.get("rule_id", "")),
            str(finding.get("source", "")),
            str(finding.get("file") or finding.get("url") or "target"),
            str(finding.get("line_start") or ""),
            str(finding.get("method") or ""),
            str(finding.get("status") or ""),
        ]
    )


def _drift_record_key(record: dict[str, Any]) -> tuple[str, ...]:
    if record.get("drift_key"):
        return ("drift_key", str(record.get("drift_key") or ""))
    return (
        str(record.get("target_id") or ""),
        str(record.get("rule_id") or ""),
        str(record.get("source") or ""),
        str(record.get("location") or ""),
        str(record.get("line_start") or ""),
        str(record.get("method") or ""),
        str(record.get("status") or ""),
    )


def _top_rules(findings: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    counts = Counter(str(finding.get("rule_id")) for finding in findings if finding.get("rule_id"))
    return [{"rule_id": rule, "count": count} for rule, count in counts.most_common(limit)]


def _fix_plan(findings: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id:
            grouped.setdefault(rule_id, []).append(finding)
    items: list[dict[str, Any]] = []
    for rule_id, group in grouped.items():
        recipe = recipe_for_rule(rule_id)
        max_severity = sorted((str(item.get("severity") or "info") for item in group), key=severity_rank)[0]
        items.append(
            {
                "rule_id": rule_id,
                "title": recipe.get("title", rule_id),
                "max_severity": max_severity,
                "affected_findings": len(group),
                "affected_targets": sorted({str(item.get("target_id")) for item in group if item.get("target_id")}),
                "impact": recipe.get("impact", ""),
                "fix_steps": recipe.get("fix_steps", []),
                "test_suggestions": recipe.get("test_suggestions", []),
                "verification": recipe.get("verification", ""),
            }
        )
    items.sort(key=lambda item: (severity_rank(str(item["max_severity"])), -int(item["affected_findings"]), str(item["rule_id"])))
    return items[:limit]
