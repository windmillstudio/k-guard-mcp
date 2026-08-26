from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from k_guard_mcp.provenance import object_artifact, path_artifact, verify_evidence_bundle
from k_guard_mcp.control_validation import control_validation_toolchain_contract
from k_guard_mcp.language_validation import PINNED_SEMGREP_VERSION, REQUIRED_LANGUAGES, current_language_validation_contract
from k_guard_mcp.mcp_http_proxy import mcp_http_proxy_toolchain_contract


QUALIFICATION_SCHEMA = "k_guard_release_qualification.v1"
MAX_REPORT_BYTES = 64 * 1024 * 1024
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

_FIELD_PROJECTION_KEYS = (
    "schema",
    "method",
    "toolchain_contract",
    "profile",
    "evidence_tier",
    "raw_free",
    "sample",
    "verdict_counts",
    "case_counts",
    "metric_contract",
    "rates",
    "rates_confidence_intervals",
    "holdout",
    "holdout_candidate_rates",
    "evaluation",
    "reproducibility",
    "repeat_guardian_source",
    "field_preregistration",
    "field_roster_source",
    "primary_guardian_evidence",
    "repeat_guardian_evidence",
    "thresholds",
    "gate_checks",
    "claim_status",
    "candidate_app_refs",
    "candidate_target_refs",
    "candidate_finding_refs",
    "evaluation_app_refs",
    "evaluation_target_refs",
)


def evaluate_release_qualification(
    *,
    deep_analyzer_reports: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None,
    sca_reports: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None,
    language_validation_report_path: str | Path | None,
    mcp_http_proxy_report_path: str | Path | None,
    field_validation_report_path: str | Path | None,
    control_validation_report_path: str | Path | None,
    workspace_snapshots: dict[str, dict[str, Any]],
    current_guardian_toolchain: dict[str, Any],
) -> dict[str, Any]:
    deep = [dict(item) for item in (deep_analyzer_reports or []) if isinstance(item, dict)]
    sca = [dict(item) for item in (sca_reports or []) if isinstance(item, dict)]
    deep_error = "" if deep else "missing"
    deep_ref = object_artifact("deep_analyzer_reports", deep, role="qualification_input")
    sca_ref = object_artifact("software_composition_reports", sca, role="qualification_input")
    language, language_error, language_ref = _load_report(language_validation_report_path, "language_validation_report")
    runtime, runtime_error, runtime_ref = _load_report(mcp_http_proxy_report_path, "mcp_http_proxy_report")
    field, field_error, field_ref = _load_report(field_validation_report_path, "field_validation_report")
    controls, controls_error, controls_ref = _load_report(control_validation_report_path, "control_validation_report")

    deep_checks = _deep_checks(deep, deep_error, workspace_snapshots)
    language_checks = _language_checks(language, language_error)
    sca_checks = _sca_checks(sca, workspace_snapshots)
    runtime_checks = _runtime_checks(runtime, runtime_error)
    field_checks = _field_checks(field, field_error, current_guardian_toolchain)
    control_checks = _control_checks(controls, controls_error)
    gates = {
        "deep_multilang": _gate((*deep_checks, *language_checks)),
        "software_composition": _gate(sca_checks),
        "streamable_http_runtime": _gate(runtime_checks),
        "agent_database_controls": _gate(control_checks),
        "field_accuracy": _gate(field_checks),
    }
    passed = all(gate["passed"] for gate in gates.values())
    missing_inputs = [
        name
        for name, value in (
            ("deep_analyzer_reports", deep),
            ("software_composition_reports", sca),
            ("language_validation_report", language),
            ("mcp_http_proxy_report", runtime),
            ("field_validation_report", field),
            ("control_validation_report", controls),
        )
        if not value
    ]
    return {
        "schema": QUALIFICATION_SCHEMA,
        "passed": passed,
        "canonical_release_prerequisite": True,
        "fail_closed": True,
        "gates": gates,
        "missing_inputs": missing_inputs,
        "workspace_snapshot_count": len(workspace_snapshots),
        "input_evidence": {
            "deep_analyzer_report": deep_ref,
            "software_composition_reports": sca_ref,
            "language_validation_report": language_ref,
            "mcp_http_proxy_report": runtime_ref,
            "field_validation_report": field_ref,
            "control_validation_report": controls_ref,
        },
        "claim_boundary": {
            "development_pack_is_not_field_accuracy": True,
            "runtime_enforcement_is_not_application_correctness": True,
            "synthetic_policy_controls_are_not_production_policy_proof": True,
            "field_validation_is_not_a_security_certificate": True,
            "human_business_intent_and_legal_compliance_claimed": False,
        },
        "raw_free": True,
    }


def _deep_checks(
    reports: list[dict[str, Any]],
    load_error: str,
    workspace_snapshots: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    snapshots = [
        report.get("input_snapshot", {}) if isinstance(report.get("input_snapshot"), dict) else {}
        for report in reports
    ]
    findings = [
        item
        for report in reports
        for item in (report.get("findings", []) if isinstance(report.get("findings"), list) else [])
    ]
    blocking = [
        item
        for item in findings
        if isinstance(item, dict) and str(item.get("severity") or "").lower() in {"critical", "high"}
    ]
    current_language_contract = current_language_validation_contract()
    expected_hashes = current_language_contract.get("hashes", {}) if isinstance(current_language_contract.get("hashes"), dict) else {}
    return (
        _check("deep_report_loaded", not load_error, load_error or "loaded"),
        _check("deep_schema", bool(reports) and all(report.get("schema") == "k_guard_analyzer_run.v1" for report in reports), len(reports)),
        _check("deep_complete", bool(reports) and all(report.get("complete") is True and report.get("control_errors") == [] for report in reports), len(reports)),
        _check("deep_profile", bool(reports) and all(report.get("analyzer_subtype") == "semgrep-ce-intrafile" and report.get("profile_name") == "semgrep-deep.yml" for report in reports), len(reports)),
        _check("deep_current_toolchain", current_language_contract.get("complete") is True and bool(reports) and all(report.get("executable_version") == PINNED_SEMGREP_VERSION and report.get("adapter_sha256") == expected_hashes.get("adapter_sha256") and report.get("profile_sha256") == expected_hashes.get("profile_sha256") and report.get("rules_sha256") == expected_hashes.get("profile_rules_sha256") and report.get("command_contract_sha256") == expected_hashes.get("adapter_command_contract_sha256") for report in reports), len(reports)),
        _check("deep_operator_signature", bool(reports) and all(_bound_report_bundle(report, "evidence_bundle", "analyzer-run", "analysis") for report in reports), "operator-keyed"),
        _check("deep_workspace_coverage", bool(reports) and len(reports) == len(workspace_snapshots), {"reports": len(reports), "workspaces": len(workspace_snapshots)}),
        _check("deep_source_snapshot_complete", bool(snapshots) and all(snapshot.get("complete") is True and _valid_sha256(snapshot.get("tree_sha256")) for snapshot in snapshots), len(snapshots)),
        _check("deep_source_snapshot_current", _snapshot_multiset(snapshots) == _snapshot_multiset(list(workspace_snapshots.values())) and bool(snapshots), [snapshot.get("tree_sha256", "") for snapshot in snapshots]),
        _check("deep_no_high_critical", not blocking, len(blocking)),
    )


def _language_checks(report: dict[str, Any], load_error: str) -> tuple[dict[str, Any], ...]:
    metrics = report.get("metrics", {}) if isinstance(report.get("metrics"), dict) else {}
    overall = metrics.get("overall", {}) if isinstance(metrics.get("overall"), dict) else {}
    matrix = overall.get("confusion_matrix", {}) if isinstance(overall.get("confusion_matrix"), dict) else {}
    requirements = report.get("requirements", {}) if isinstance(report.get("requirements"), dict) else {}
    runs = report.get("analyzer_runs", []) if isinstance(report.get("analyzer_runs"), list) else []
    current_contract = current_language_validation_contract()
    return (
        _check("language_report_loaded", not load_error, load_error or "loaded"),
        _check("language_schema", report.get("schema") == "k_guard_language_validation_report.v1", report.get("schema")),
        _check("language_ready", report.get("complete") is True and report.get("ready") is True, report.get("status")),
        _check("language_operator_signature", _bound_report_bundle(report, "evidence_bundle", "language-validation-report", "validation"), "operator-keyed"),
        _check("language_current_toolchain", current_contract.get("complete") is True and report.get("hashes") == current_contract.get("hashes"), report.get("hashes", {})),
        _check("language_scope", report.get("languages") == list(REQUIRED_LANGUAGES), report.get("languages")),
        _check("language_zero_fn_fp", matrix.get("fn") == 0 and matrix.get("fp") == 0 and int(matrix.get("tp", 0)) >= 45 and int(matrix.get("tn", 0)) >= 45, matrix),
        _check("language_repeat_exact", report.get("repeat", {}).get("exact") is True if isinstance(report.get("repeat"), dict) else False, report.get("repeat", {}).get("exact") if isinstance(report.get("repeat"), dict) else None),
        _check("language_requirements_complete", bool(requirements) and all(value is True for value in requirements.values()), len(requirements)),
        _check("language_input_snapshots_bound", len(runs) == 2 and all(isinstance(run, dict) and run.get("input_snapshot_complete") is True and _valid_sha256(run.get("input_tree_sha256")) for run in runs), len(runs)),
    )


def _sca_checks(
    reports: list[dict[str, Any]],
    workspace_snapshots: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    inventories = [
        report.get("inventory", {}) if isinstance(report.get("inventory"), dict) else {}
        for report in reports
    ]
    snapshots = [
        report.get("input_snapshot", {}) if isinstance(report.get("input_snapshot"), dict) else {}
        for report in reports
    ]
    adapters = [
        adapter
        for report in reports
        for adapter in (report.get("adapters", []) if isinstance(report.get("adapters"), list) else [])
        if isinstance(adapter, dict)
    ]
    findings = [
        finding
        for report in reports
        for finding in (report.get("findings", []) if isinstance(report.get("findings"), list) else [])
        if isinstance(finding, dict)
    ]
    manifest_count = sum(int(inventory.get("manifest_count", 0)) for inventory in inventories)
    requested = sum(len(report.get("requested_ecosystems", [])) for report in reports if isinstance(report.get("requested_ecosystems"), list))
    audited = sum(len(report.get("audited_ecosystems", [])) for report in reports if isinstance(report.get("audited_ecosystems"), list))
    return (
        _check("sca_reports_loaded", bool(reports) and len(reports) == len(workspace_snapshots), {"reports": len(reports), "workspaces": len(workspace_snapshots)}),
        _check("sca_schema", bool(reports) and all(report.get("schema") == "k_guard_sca_run.v1" for report in reports), len(reports)),
        _check("sca_complete", bool(reports) and all(report.get("complete") is True and report.get("control_errors") == [] for report in reports), len(reports)),
        _check("sca_operator_signature", bool(reports) and all(_bound_report_bundle(report, "evidence_bundle", "sca-run", "analysis") for report in reports), "operator-keyed"),
        _check("sca_source_snapshot_complete", bool(snapshots) and all(snapshot.get("complete") is True and _valid_sha256(snapshot.get("tree_sha256")) for snapshot in snapshots), len(snapshots)),
        _check("sca_manifest_inventory_complete", bool(inventories) and all(int(inventory.get("uncovered_manifest_count", 0)) == 0 for inventory in inventories), manifest_count),
        _check("sca_ecosystem_coverage", (manifest_count == 0 and requested == audited == 0) or (manifest_count > 0 and requested == audited and audited > 0), {"manifest_count": manifest_count, "requested": requested, "audited": audited}),
        _check("sca_engine_and_command_contract", (not adapters and manifest_count == 0) or (bool(adapters) and all(str(adapter.get("engine", {}).get("version") or "") and adapter.get("engine", {}).get("command_contract", {}).get("shell") is False for adapter in adapters if isinstance(adapter.get("engine"), dict))), len(adapters)),
        _check("sca_no_known_vulnerabilities", not findings, len(findings)),
    )


def _control_checks(report: dict[str, Any], load_error: str) -> tuple[dict[str, Any], ...]:
    repeat = report.get("repeat", {}) if isinstance(report.get("repeat"), dict) else {}
    domains = report.get("domains", {}) if isinstance(report.get("domains"), dict) else {}
    cases = report.get("cases", []) if isinstance(report.get("cases"), list) else []
    current = control_validation_toolchain_contract()
    return (
        _check("control_report_loaded", not load_error, load_error or "loaded"),
        _check("control_schema", report.get("schema") == "k_guard_control_validation.v1", report.get("schema")),
        _check("control_complete", report.get("complete") is True and report.get("passed") is True, report.get("passed")),
        _check("control_operator_signature", _bound_report_bundle(report, "evidence_bundle", "control-validation-report", "validation"), "operator-keyed"),
        _check("control_current_toolchain", current.get("complete") is True and report.get("toolchain_contract") == current, report.get("toolchain_contract", {})),
        _check("control_repeat_exact", repeat.get("run_count") == 2 and repeat.get("exact") is True and _valid_sha256(repeat.get("projection_sha256")), repeat),
        _check("control_case_inventory", int(report.get("case_count", 0)) >= 18 and len(cases) == int(report.get("case_count", 0)), len(cases)),
        _check("control_all_cases_passed", bool(cases) and all(isinstance(case, dict) and case.get("passed") is True for case in cases), len(cases)),
        _check("control_agent_jit_jea", isinstance(domains.get("agent_jit_jea"), dict) and domains["agent_jit_jea"].get("passed") is True and int(domains["agent_jit_jea"].get("case_count", 0)) >= 8, domains.get("agent_jit_jea", {})),
        _check("control_database_ast_rbac_isolation", isinstance(domains.get("database_ast_rbac_isolation"), dict) and domains["database_ast_rbac_isolation"].get("passed") is True and int(domains["database_ast_rbac_isolation"].get("case_count", 0)) >= 10, domains.get("database_ast_rbac_isolation", {})),
    )


def _runtime_checks(report: dict[str, Any], load_error: str) -> tuple[dict[str, Any], ...]:
    execution = report.get("execution", {}) if isinstance(report.get("execution"), dict) else {}
    contract = report.get("enforcement_contract", {}) if isinstance(report.get("enforcement_contract"), dict) else {}
    access = report.get("access_control", {}) if isinstance(report.get("access_control"), dict) else {}
    audit = access.get("audit", {}) if isinstance(access.get("audit"), dict) else {}
    policy = report.get("policy", {}) if isinstance(report.get("policy"), dict) else {}
    settings = policy.get("settings", {}) if isinstance(policy.get("settings"), dict) else {}
    persistence = policy.get("audit_persistence", {}) if isinstance(policy.get("audit_persistence"), dict) else {}
    counts = report.get("counts", {}) if isinstance(report.get("counts"), dict) else {}
    validation = report.get("runtime_validation", {}) if isinstance(report.get("runtime_validation"), dict) else {}
    validation_checks = validation.get("checks", {}) if isinstance(validation.get("checks"), dict) else {}
    official_sdk = validation.get("official_sdk_interoperability", {}) if isinstance(validation.get("official_sdk_interoperability"), dict) else {}
    official_checks = official_sdk.get("checks", {}) if isinstance(official_sdk.get("checks"), dict) else {}
    try:
        current_mcp_sdk_version = importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        current_mcp_sdk_version = ""
    current_toolchain = mcp_http_proxy_toolchain_contract()
    return (
        _check("runtime_report_loaded", not load_error, load_error or "loaded"),
        _check("runtime_schema", report.get("schema") == "k_guard_mcp_http_proxy_report.v1" and report.get("transport") == "streamable_http", report.get("schema")),
        _check("runtime_complete", report.get("complete") is True and report.get("passed") is True and report.get("control_errors") == [], report.get("control_status")),
        _check("runtime_operator_signature", _bound_report_bundle(report, "evidence_bundle", "runtime-report", "runtime"), "operator-keyed"),
        _check("runtime_exercised", execution.get("runtime_exercised") is True, execution.get("runtime_exercised")),
        _check("runtime_toolchain_bound", current_toolchain.get("complete") is True and execution.get("toolchain_contract") == current_toolchain and execution.get("toolchain_sha256") == current_toolchain.get("sha256"), execution.get("toolchain_sha256", "")),
        _check("runtime_bidirectional_enforcement", contract.get("client_to_server") == "inspect_block_or_redact_before_forward" and contract.get("server_to_client") == "inspect_block_or_redact_before_forward" and contract.get("fail_closed_on_control_gap") is True, contract.get("fail_closed_on_control_gap")),
        _check("runtime_validation_profile", validation.get("schema") == "k_guard_mcp_http_runtime_validation.v1" and validation.get("profile") == "synthetic_streamable_http_complete_mediation" and validation.get("complete") is True and validation.get("passed") is True, validation.get("profile")),
        _check("runtime_validation_repeat", validation.get("run_count") == 2 and validation.get("repeat_exact") is True and _valid_sha256(validation.get("matrix_projection_sha256")), validation),
        _check("runtime_validation_all_checks", bool(validation_checks) and all(value is True for value in validation_checks.values()), validation_checks),
        _check("runtime_official_sdk_interoperability", official_sdk.get("passed") is True and official_sdk.get("sdk") == "mcp-python-sdk" and official_sdk.get("sdk_version") == current_mcp_sdk_version and bool(official_checks) and all(value is True for value in official_checks.values()), official_sdk),
        _check("runtime_origin_and_header_policy", settings.get("require_origin") is True and settings.get("forward_authorization") is False, settings),
        _check("runtime_persistent_audit_fail_closed", persistence.get("configured") is True and persistence.get("healthy") is True and persistence.get("fail_closed_on_error") is True, persistence),
        _check("runtime_access_default_deny", access.get("schema") == "k_guard_access_controller_summary.v1" and access.get("complete") is True and access.get("default_action") == "deny", access.get("default_action")),
        _check("runtime_access_audit_chain", audit.get("enabled") is True and audit.get("error_count") == 0 and int(audit.get("entry_count", 0)) > 0 and _valid_sha256(audit.get("last_entry_sha256")), audit),
        _check("runtime_access_allow_and_deny_exercised", int(counts.get("access_decisions_allow", 0)) > 0 and int(counts.get("access_decisions_deny", 0)) > 0, {"allow": counts.get("access_decisions_allow", 0), "deny": counts.get("access_decisions_deny", 0)}),
        _check("runtime_tool_inventory_filtered", int(counts.get("access_tool_lists_filtered", 0)) > 0, counts.get("access_tool_lists_filtered", 0)),
        _check("runtime_transport_method_matrix", all(int(counts.get(name, 0)) > 0 for name in ("requests_post", "requests_get", "requests_delete")), {name: counts.get(name, 0) for name in ("requests_post", "requests_get", "requests_delete")}),
        _check("runtime_json_and_sse_matrix", int(counts.get("json_responses_forwarded", 0)) > 0 and int(counts.get("sse_streams_forwarded", 0)) > 0 and int(counts.get("sse_events_forwarded", 0)) > 0, {name: counts.get(name, 0) for name in ("json_responses_forwarded", "sse_streams_forwarded", "sse_events_forwarded")}),
        _check("runtime_lifecycle_matrix", int(counts.get("server_requests_correlated", 0)) > 0 and int(counts.get("sessions_deleted", 0)) > 0, {"correlated": counts.get("server_requests_correlated", 0), "deleted": counts.get("sessions_deleted", 0)}),
        _check("runtime_no_findings", report.get("finding_count") == 0, report.get("finding_count")),
    )


def _field_checks(
    report: dict[str, Any],
    load_error: str,
    current_guardian_toolchain: dict[str, Any],
) -> tuple[dict[str, Any], ...]:
    sample = report.get("sample", {}) if isinstance(report.get("sample"), dict) else {}
    prereg = report.get("field_preregistration", {}) if isinstance(report.get("field_preregistration"), dict) else {}
    checks = report.get("gate_checks", []) if isinstance(report.get("gate_checks"), list) else []
    return (
        _check("field_report_loaded", not load_error, load_error or "loaded"),
        _check("field_schema", report.get("schema") == "k_guard_field_validation.v1" and report.get("profile") == "field", report.get("schema")),
        _check("field_ready", report.get("claim_status") == "field_validation_ready", report.get("claim_status")),
        _check("field_operator_signature", _bound_field_bundle(report), "operator-keyed"),
        _check("field_current_toolchain", bool(current_guardian_toolchain) and current_guardian_toolchain.get("complete") is True and report.get("toolchain_contract") == current_guardian_toolchain, report.get("toolchain_contract", {})),
        _check("field_app_count", 12 <= int(sample.get("app_count", 0)) <= 20, sample.get("app_count")),
        _check("field_roster_preregistered", prereg.get("roster_ready") is True and prereg.get("roster_signed") is True and prereg.get("roster_target_binding") is True, prereg.get("roster_row_count")),
        _check("field_all_gate_checks", bool(checks) and all(isinstance(item, dict) and item.get("passed") is True for item in checks), len(checks)),
    )


def _bound_report_bundle(report: dict[str, Any], bundle_key: str, label: str, role: str) -> bool:
    bundle = report.get(bundle_key)
    if not verify_evidence_bundle(bundle, require_operator_key=True):
        return False
    projection = {key: value for key, value in report.items() if key != bundle_key}
    expected = object_artifact(label, projection, role=role)
    return _bundle_has_artifact(bundle, expected)


def _bound_field_bundle(report: dict[str, Any]) -> bool:
    bundle = report.get("validation_evidence_envelope")
    if not verify_evidence_bundle(bundle, require_operator_key=True):
        return False
    projection = {key: report.get(key) for key in _FIELD_PROJECTION_KEYS}
    expected = object_artifact("field_validation_projection", projection, role="gate")
    return _bundle_has_artifact(bundle, expected)


def _bundle_has_artifact(bundle: Any, expected: dict[str, Any]) -> bool:
    if not isinstance(bundle, dict) or not isinstance(bundle.get("artifacts"), list):
        return False
    return any(
        isinstance(item, dict)
        and all(item.get(key) == expected.get(key) for key in ("label", "role", "hash", "byte_count"))
        for item in bundle["artifacts"]
    )


def _gate(checks: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    failed = [check["name"] for check in checks if check["passed"] is not True]
    return {
        "passed": not failed,
        "checks": list(checks),
        "failed_checks": failed,
        "raw_free": True,
    }


def _check(name: str, passed: bool, observed: Any) -> dict[str, Any]:
    if isinstance(observed, (dict, list, tuple)):
        observed = hashlib.sha256(
            json.dumps(observed, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
    elif not isinstance(observed, (str, int, float, bool)) and observed is not None:
        observed = type(observed).__name__
    return {"name": name, "passed": bool(passed), "observed": observed, "raw_free": True}


def _load_report(path_value: str | Path | None, label: str) -> tuple[dict[str, Any], str, dict[str, Any]]:
    artifact = path_artifact(label, path_value or "", role="qualification_input")
    if not path_value:
        return {}, "missing", artifact
    try:
        path = Path(path_value)
        if not path.is_file() or path.is_symlink():
            return {}, "missing_or_symlink", artifact
        size = path.stat().st_size
        if size <= 0 or size > MAX_REPORT_BYTES:
            return {}, "size_invalid", artifact
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(payload, dict):
            return {}, "schema_invalid", artifact
        return payload, "", artifact
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {}, "invalid_json", artifact


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _snapshot_multiset(values: list[dict[str, Any]]) -> Counter[str]:
    return Counter(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        for value in values
        if isinstance(value, dict)
    )


__all__ = ["QUALIFICATION_SCHEMA", "evaluate_release_qualification"]
