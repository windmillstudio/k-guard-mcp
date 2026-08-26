from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import secrets
import urllib.parse
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from k_guard_mcp import __version__
from k_guard_mcp.analyzers import SemgrepAnalyzerAdapter
from k_guard_mcp.collector import collect_candidate_files, file_inventory_fingerprint
from k_guard_mcp.dynamic import ALLOWED_HOSTS, _allowed_host, _selected_probe_paths
from k_guard_mcp.experience import (
    NORTH_STAR,
    apply_guardian_experience,
    release_authority_claim,
    release_target_evidence_refs,
)
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.models import Finding, ScanResult
from k_guard_mcp.provenance import canonical_json, evidence_bundle, object_artifact, path_artifact, source_tree_snapshot
from k_guard_mcp.recipes import recipe_for_rule
from k_guard_mcp.redaction import sanitize_any
from k_guard_mcp.release_policy import (
    RELEASE_BLOCKING_POLICY,
    is_release_blocking_finding,
    release_hold_counts,
)
from k_guard_mcp.release_qualification import evaluate_release_qualification
from k_guard_mcp.sca import SoftwareCompositionAnalyzer
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.session import SessionMaterial, load_session_material
from k_guard_mcp.severity import severity_rank


GUARDIAN_MANIFEST_FIELDS = [
    "app_id",
    "target_id",
    "kind",
    "locator",
    "authorized",
    "authorization_note",
    "deep_active",
    "session_file",
    "include_flow",
    "fail_on",
    "owner",
    "business_purpose",
    "data_classes",
    "user_scope",
    "public_endpoints",
    "scope_basis",
    "scope_proof_ref",
    "audit_profile",
    "notes",
]

GUARDIAN_KIND_ALIASES = {
    "workspace": "workspace",
    "code": "workspace",
    "repo": "workspace",
    "http": "http",
    "url": "http",
    "site": "http",
    "mcp_events": "mcp_events",
    "runtime": "mcp_events",
    "events": "mcp_events",
    "report": "report",
    "json": "report",
}

SAFE_MANIFEST_SLUG = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


def guardian_manifest_policy(manifest_path: str | Path) -> dict[str, Any]:
    manifest = Path(manifest_path)
    targets = _read_manifest(manifest)
    policy: dict[str, Any] = {
        "target_count": len(targets),
        "requires_probe": False,
        "requires_external_probe": False,
        "requires_deep_active_probe": False,
        "requires_session_probe": False,
        "external_hosts": [],
    }
    external_hosts: set[str] = set()
    for target in targets:
        if target.get("kind") != "http":
            continue
        policy["requires_probe"] = True
        if _truthy(target.get("deep_active", "")):
            policy["requires_deep_active_probe"] = True
        if target.get("session_file", "").strip():
            policy["requires_session_probe"] = True
        parsed = urllib.parse.urlparse(target.get("locator", "") if "://" in target.get("locator", "") else "https://" + target.get("locator", ""))
        host = (parsed.hostname or "").strip("[]").lower()
        if host and not _allowed_host(host, ALLOWED_HOSTS):
            external_hosts.add(host)
            policy["requires_external_probe"] = True
    policy["external_hosts"] = sorted(external_hosts)
    return policy


def guardian_manifest_resource_usage(
    manifest_path: str | Path,
    max_targets: int | None = None,
    max_files: int | None = None,
) -> dict[str, int]:
    manifest = Path(manifest_path)
    targets = _read_manifest(manifest)
    local_files: list[Path] = []
    try:
        if manifest.is_file():
            local_files.append(manifest.resolve())
    except OSError:
        pass
    if max_targets is not None and len(targets) > max_targets:
        try:
            manifest_bytes = manifest.stat().st_size
        except OSError:
            manifest_bytes = 0
        return {
            "target_count": len(targets),
            "local_file_count": len(local_files),
            "local_total_bytes": manifest_bytes,
            "projected_http_request_count": 0,
        }
    if max_files is not None and len(local_files) > max_files:
        return _guardian_resource_usage(len(targets), local_files, 0)
    projected_http_requests = 0
    for target in targets:
        kind = target.get("kind")
        if kind == "workspace":
            locator = Path(_resolve_locator(manifest.parent, target.get("locator", "")))
            remaining = None if max_files is None else max_files - len(local_files) + 1
            for path in collect_candidate_files(locator, max_files=remaining):
                try:
                    local_files.append(path.resolve())
                except OSError:
                    continue
        elif kind in {"mcp_events", "report"}:
            locator = Path(_resolve_locator(manifest.parent, target.get("locator", "")))
            try:
                if locator.is_file():
                    local_files.append(locator.resolve())
            except OSError:
                pass
        if max_files is not None and len(local_files) > max_files:
            return _guardian_resource_usage(len(targets), local_files, projected_http_requests)
        if kind != "http":
            continue
        profile = "deep" if _truthy(target.get("deep_active", "")) else "baseline"
        paths = set(_selected_probe_paths(None, profile))
        paths.update(_safe_manifest_probe_paths(target.get("public_endpoints", "")))
        per_session = len(paths) * 3
        projected_http_requests += per_session * (2 if target.get("session_file", "").strip() else 1)
        if target.get("session_file", "").strip():
            session = Path(_resolve_locator(manifest.parent, target["session_file"]))
            try:
                if session.is_file():
                    local_files.append(session.resolve())
            except OSError:
                pass
        if max_files is not None and len(local_files) > max_files:
            return _guardian_resource_usage(len(targets), local_files, projected_http_requests)
    return _guardian_resource_usage(len(targets), local_files, projected_http_requests)


def _guardian_resource_usage(target_count: int, local_files: list[Path], projected_http_requests: int) -> dict[str, int]:
    total_bytes = 0
    for path in local_files:
        try:
            total_bytes += path.stat().st_size
        except OSError:
            continue
    return {
        "target_count": target_count,
        "local_file_count": len(local_files),
        "local_total_bytes": total_bytes,
        "projected_http_request_count": projected_http_requests,
    }


def guardian_current_source_snapshots(manifest_path: str | Path) -> dict[str, dict[str, Any]]:
    manifest = Path(manifest_path)
    snapshots: dict[str, dict[str, Any]] = {}
    for target in _read_manifest(manifest):
        if target.get("kind") != "workspace":
            continue
        workspace = Path(_resolve_locator(manifest.parent, target.get("locator", "")))
        snapshots[target["target_id"]] = source_tree_snapshot(workspace)
    return snapshots


def write_guardian_manifest_template(path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "app_id": "primary-app",
            "target_id": "app-workspace",
            "kind": "workspace",
            "locator": ".",
            "authorized": "true",
            "authorization_note": "local project",
            "deep_active": "false",
            "session_file": "",
            "include_flow": "true",
            "fail_on": "high",
            "owner": "team",
            "business_purpose": "pre-release audit for the primary app workspace",
            "data_classes": "personal_data, secrets, runtime_config",
            "user_scope": "owned_or_partner_app_users",
            "public_endpoints": "",
            "scope_basis": "local_workspace",
            "scope_proof_ref": "repo owner assertion",
            "audit_profile": "korean_senior",
            "notes": "static/code/config/MCP/connector audit",
        },
        {
            "app_id": "primary-app",
            "target_id": "local-dev-web",
            "kind": "http",
            "locator": "http://127.0.0.1:3000",
            "authorized": "true",
            "authorization_note": "local target",
            "deep_active": "true",
            "session_file": "",
            "include_flow": "",
            "fail_on": "high",
            "owner": "team",
            "business_purpose": "pre-release read-only web runtime audit",
            "data_classes": "runtime_response, personal_data",
            "user_scope": "local test users",
            "public_endpoints": "/,/api,/api/users",
            "scope_basis": "local_http",
            "scope_proof_ref": "local dev server",
            "audit_profile": "korean_senior",
            "notes": "safe GET/OPTIONS dynamic audit",
        },
        {
            "app_id": "primary-app",
            "target_id": "mcp-runtime",
            "kind": "mcp_events",
            "locator": "mcp-events.jsonl",
            "authorized": "true",
            "authorization_note": "local runtime export",
            "deep_active": "false",
            "session_file": "",
            "include_flow": "",
            "fail_on": "high",
            "owner": "team",
            "business_purpose": "MCP runtime forwarding and redaction audit",
            "data_classes": "tool_events, personal_data, secrets",
            "user_scope": "owned local MCP session",
            "public_endpoints": "",
            "scope_basis": "local_runtime_export",
            "scope_proof_ref": "operator exported runtime JSONL",
            "audit_profile": "korean_senior",
            "notes": "MCP runtime observer",
        },
        {
            "app_id": "primary-app",
            "target_id": "dashboard-export",
            "kind": "report",
            "locator": "k-guard-report.json",
            "authorized": "true",
            "authorization_note": "raw-free dashboard export",
            "deep_active": "false",
            "session_file": "",
            "include_flow": "",
            "fail_on": "high",
            "owner": "team",
            "business_purpose": "aggregate prior raw-free K-Guard evidence",
            "data_classes": "raw_free_findings",
            "user_scope": "report scope",
            "public_endpoints": "",
            "scope_basis": "raw_free_report_import",
            "scope_proof_ref": "report owner assertion",
            "audit_profile": "korean_senior",
            "notes": "aggregate an existing raw-free report",
        },
    ]
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GUARDIAN_MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def run_guardian_audit(
    manifest_path: str | Path,
    previous_report_path: str | Path | None = None,
    run_probes: bool = False,
    scanner: KGuardScanner | None = None,
    fail_on_override: str | None = None,
    semgrep_executable: str | Path | None = None,
    language_validation_report_path: str | Path | None = None,
    mcp_http_proxy_report_path: str | Path | None = None,
    field_validation_report_path: str | Path | None = None,
    control_validation_report_path: str | Path | None = None,
    sca_analyzer: SoftwareCompositionAnalyzer | None = None,
    run_sca: bool = False,
) -> dict[str, Any]:
    started_at = datetime.now(UTC)
    execution_id = secrets.token_hex(16)
    scanner = scanner or KGuardScanner()
    active_toolchain = guardian_toolchain_contract(scanner)
    manifest = Path(manifest_path)
    targets = _read_manifest(manifest)
    rows: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    for target in targets:
        row, findings = _run_target(target, scanner, run_probes=run_probes, manifest_dir=manifest.parent, fail_on_override=fail_on_override)
        rows.append(row)
        all_findings.extend(findings)
    release_gate_enabled = fail_on_override == "high"
    workspace_snapshots = {
        str(row.get("target_id") or ""): dict(
            row.get("review_evidence", {}).get("source_tree_snapshot", {})
        )
        for row in rows
        if row.get("kind") == "workspace"
        and isinstance(row.get("review_evidence"), dict)
        and isinstance(row.get("review_evidence", {}).get("source_tree_snapshot"), dict)
    }
    deep_reports: list[dict[str, Any]] = []
    sca_reports: list[dict[str, Any]] = []
    workspace_targets = [target for target in targets if target.get("kind") == "workspace"]
    if release_gate_enabled:
        executable = str(semgrep_executable or os.environ.get("K_GUARD_SEMGREP_EXECUTABLE", "semgrep"))
        active_sca = sca_analyzer or SoftwareCompositionAnalyzer()
        for workspace_target in workspace_targets:
            workspace_path = _resolve_locator(manifest.parent, workspace_target.get("locator", ""))
            deep_reports.append(SemgrepAnalyzerAdapter(executable=executable).analyze(workspace_path).to_report())
            if run_sca:
                try:
                    sca_reports.append(active_sca.analyze(workspace_path).to_report())
                except Exception as exc:
                    sca_reports.append(_failed_sca_report(exc))
        _merge_release_analysis(rows, deep_reports, sca_reports)
        all_findings = [
            dict(finding)
            for row in rows
            for finding in (row.get("findings", []) if isinstance(row.get("findings"), list) else [])
            if isinstance(finding, dict)
        ]
    previous = _load_previous(previous_report_path)
    baseline = _baseline_contract(previous, previous_report_path, release_gate_enabled)
    drift = _drift_summary(previous, rows, baseline)
    summary = _summary(rows)
    intent_contract = _intent_contract(rows)
    review_contract = _review_contract(rows, intent_contract, release_gate_enabled=release_gate_enabled)
    release_qualification = evaluate_release_qualification(
        deep_analyzer_reports=deep_reports,
        sca_reports=sca_reports,
        language_validation_report_path=language_validation_report_path,
        mcp_http_proxy_report_path=mcp_http_proxy_report_path,
        field_validation_report_path=field_validation_report_path,
        control_validation_report_path=control_validation_report_path,
        workspace_snapshots=workspace_snapshots,
        current_guardian_toolchain=active_toolchain,
    )
    completed_at = datetime.now(UTC)
    report = {
        "generated_at": completed_at.isoformat(),
        "execution_id": execution_id,
        "method": "guardian_audit",
        "execution_attestation": build_guardian_execution_attestation(
            execution_id,
            started_at.isoformat(),
            completed_at.isoformat(),
            rows,
        ),
        "toolchain_contract": active_toolchain,
        "raw_free": True,
        "manifest": _safe_path(manifest, manifest.parent, "manifest", ""),
        "run_probes": run_probes,
        "run_sca": run_sca,
        "baseline": baseline,
        "execution_contract": _execution_contract(rows, run_probes=run_probes, release_gate_enabled=release_gate_enabled, baseline=baseline),
        "intent_contract": intent_contract,
        "review_contract": review_contract,
        "deep_analyzer_reports": deep_reports,
        "software_composition_reports": sca_reports,
        "release_qualification": release_qualification,
        "summary": summary,
        "drift": drift,
        "top_rules": _top_rules(all_findings),
        "fix_plan": _fix_plan(all_findings),
        "targets": rows,
        "safety": {
            "dynamic_methods": "GET/OPTIONS only through K-Guard SafeHttpProbe",
            "external_probe_default": "disabled unless caller explicitly enables probes and target row records authorization",
            "not_used": [
                "password guessing",
                "credential stuffing",
                "form submission",
                "mutation",
                "exploit payloads",
                "recursive crawling",
                "cross-host redirect following",
            ],
            "raw_values_stored": False,
            "depth_policy": "Persistent within the authorized manifest scope; no mutation, login attempts, brute force, recursive crawling, or cross-host redirect following.",
        },
    }
    apply_guardian_experience(report)
    refresh_guardian_evidence_bundle(report, manifest)
    return sanitize_any(report)


def _failed_sca_report(exc: BaseException) -> dict[str, Any]:
    return {
        "schema": "k_guard_sca_run.v1",
        "complete": False,
        "passed": False,
        "control_errors": ["sca_unhandled_control_failure"],
        "requested_ecosystems": [],
        "audited_ecosystems": [],
        "findings": [],
        "adapters": [],
        "input_snapshot": {"complete": False, "raw_returned": False},
        "inventory": {"manifest_count": 0, "lock_count": 0, "uncovered_manifest_count": 0, "raw_returned": False},
        "counts": {"finding_count": 0, "audited_ecosystem_count": 0},
        "error_ref": evidence_hash(f"{type(exc).__name__}:{exc}"),
        "raw_free": True,
    }


def _merge_release_analysis(
    rows: list[dict[str, Any]],
    deep_reports: list[dict[str, Any]],
    sca_reports: list[dict[str, Any]],
) -> None:
    workspace_rows = [row for row in rows if row.get("kind") == "workspace"]
    for index, row in enumerate(workspace_rows):
        deep = deep_reports[index] if index < len(deep_reports) else {}
        sca = sca_reports[index] if index < len(sca_reports) else {}
        extras: list[dict[str, Any]] = []
        deep_complete = deep.get("complete") is True and deep.get("control_errors") == []
        sca_complete = sca.get("complete") is True and sca.get("control_errors") == []
        if not deep_complete:
            extras.append(
                _qualification_finding(
                    row,
                    rule_id="DEEP_ANALYSIS_COVERAGE_INCOMPLETE",
                    severity="high",
                    title="Deep static analysis did not cover the release workspace",
                    evidence=f"report_ref={evidence_hash(canonical_json(deep))} raw_returned=false",
                    recommendation="Install the pinned Semgrep engine, resolve every control error, and rerun Guardian on the unchanged source tree.",
                    artifact_scope="workspace_evidence",
                )
            )
        for item in deep.get("findings", []) if isinstance(deep.get("findings"), list) else []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity") or "high").lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "high"
            fingerprint = str(item.get("fingerprint") or evidence_hash(canonical_json(item)))
            finding = _qualification_finding(
                row,
                rule_id=str(item.get("rule_id") or "DEEP_ANALYZER_FINDING"),
                severity=severity,
                title=str(item.get("message") or "Deep static analysis finding"),
                evidence=f"deep_fingerprint={fingerprint} analyzer_subtype={item.get('analyzer_subtype', 'unknown')} raw_returned=false",
                recommendation=str(item.get("recommendation") or "Review and remediate the deep analyzer finding, then rerun Guardian."),
                artifact_scope="runtime_source",
                file=str(item.get("file") or "") or None,
                line_start=int(item.get("line_start", 0)) or None,
                line_end=int(item.get("line_end", 0)) or None,
                confidence=str(item.get("confidence") or "high"),
                identifier=f"deep-{fingerprint[:24]}",
            )
            extras.append(finding)
        if not sca_complete:
            extras.append(
                _qualification_finding(
                    row,
                    rule_id="SCA_COVERAGE_INCOMPLETE",
                    severity="high",
                    title="Software composition analysis did not complete",
                    evidence=f"report_ref={evidence_hash(canonical_json(sca))} raw_returned=false",
                    recommendation="Add complete lockfiles, install the required local audit engines, resolve control errors, and rerun Guardian.",
                    artifact_scope="configuration",
                )
            )
        for item in sca.get("findings", []) if isinstance(sca.get("findings"), list) else []:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity") or "unknown").lower()
            if severity not in {"critical", "high", "medium", "low"}:
                severity = "high"
            package_ref = item.get("package_ref", {}) if isinstance(item.get("package_ref"), dict) else {}
            version_ref = item.get("installed_version_ref", {}) if isinstance(item.get("installed_version_ref"), dict) else {}
            fingerprint = str(item.get("fingerprint") or evidence_hash(canonical_json(item)))
            extras.append(
                _qualification_finding(
                    row,
                    rule_id="SCA_VULNERABLE_LOCKED_DEPENDENCY",
                    severity=severity,
                    title="A locked dependency has a known vulnerability",
                    evidence=(
                        f"vulnerability_id={item.get('vulnerability_id', 'unknown')} "
                        f"package_ref={package_ref.get('hash', '')} version_ref={version_ref.get('hash', '')} "
                        f"fingerprint={fingerprint} raw_returned=false"
                    ),
                    recommendation="Upgrade to a non-vulnerable locked version, regenerate the lockfile, and rerun Guardian.",
                    artifact_scope="configuration",
                    identifier=f"sca-{fingerprint[:24]}",
                )
            )
        _append_qualification_findings(row, extras, deep_complete=deep_complete, sca_complete=sca_complete)


def _qualification_finding(
    row: dict[str, Any],
    *,
    rule_id: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
    artifact_scope: str,
    file: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    confidence: str = "high",
    identifier: str | None = None,
) -> dict[str, Any]:
    finding = Finding(
        id=identifier or f"guardian-{rule_id.lower()}",
        source="guardian-release-analysis",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence if confidence in {"high", "medium", "low"} else "high",
        title=title,
        evidence=evidence,
        why_it_matters="A release gate must include complete deep source and dependency evidence instead of treating missing analysis as clean.",
        recommendation=recommendation,
        file=file,
        line_start=line_start,
        line_end=line_end,
        artifact_scope=artifact_scope,
        inspected_scope="Guardian release qualification analysis over the bound workspace snapshot.",
        not_inspected="This automated evidence does not prove business intent, exploitability, or deployed cloud policy.",
    ).to_dict()
    finding["target_id"] = row.get("target_id")
    return finding


def _append_qualification_findings(
    row: dict[str, Any],
    extras: list[dict[str, Any]],
    *,
    deep_complete: bool,
    sca_complete: bool,
) -> None:
    current = [dict(item) for item in row.get("findings", []) if isinstance(item, dict)]
    deduped: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    for item in [*current, *extras]:
        key = (
            str(item.get("rule_id") or ""),
            str(item.get("evidence") or ""),
            str(item.get("file") or ""),
            int(item.get("line_start") or 0),
        )
        deduped[key] = item
    findings = list(deduped.values())
    severity_counts = Counter(str(item.get("severity") or "info") for item in findings)
    threshold = str(row.get("fail_on") or "high")
    threshold_findings = [
        item
        for item in findings
        if _severity_at_or_above(str(item.get("severity") or "info"), threshold)
    ]
    blocking = [item for item in findings if is_release_blocking_finding(item, threshold)]
    hold_counts = release_hold_counts(threshold_findings, threshold)
    blocking_scopes = Counter(str(item.get("artifact_scope") or "workspace_evidence") for item in blocking)
    action_groups = {
        (str(item.get("rule_id") or ""), str(item.get("artifact_scope") or "workspace_evidence"))
        for item in blocking
    }
    row["findings"] = findings
    row["summary"] = {
        severity: severity_counts.get(severity, 0)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    row["gate"] = {
        "passed": not blocking,
        "blocking_count": len(blocking),
        "supporting_review_at_threshold_count": len(threshold_findings) - len(blocking),
        "blocking_policy": RELEASE_BLOCKING_POLICY,
        "automatic_release_blocking_count": hold_counts["automatic_release_blocking_count"],
        "manual_review_hold_count": hold_counts["manual_review_hold_count"],
        "policy_integrity_hold_count": hold_counts["policy_integrity_hold_count"],
        "blocking_action_group_count": len(action_groups),
        "blocking_artifact_scope_counts": dict(sorted(blocking_scopes.items())),
        "recommendation": "Fix blocking findings before deploy." if blocking else "No blocking findings at this threshold.",
    }
    coverage = dict(row.get("coverage", {})) if isinstance(row.get("coverage"), dict) else {}
    coverage["qualification_analysis_gap"] = not (deep_complete and sca_complete)
    coverage["coverage_gap"] = bool(coverage.get("coverage_gap")) or not (deep_complete and sca_complete)
    row["coverage"] = coverage
    review_evidence = dict(row.get("review_evidence", {})) if isinstance(row.get("review_evidence"), dict) else {}
    review_evidence["release_analysis"] = {
        "deep_complete": deep_complete,
        "sca_complete": sca_complete,
        "merged_finding_count": len(extras),
        "raw_returned": False,
    }
    row["review_evidence"] = review_evidence
    row["rule_ids"] = sorted({str(item.get("rule_id")) for item in findings if item.get("rule_id")})
    row["fixes"] = _fixes_for_findings(findings)
    sanitized = sanitize_any(row)
    row.clear()
    row.update(sanitized)


def build_guardian_gate(report: dict[str, Any], fail_on: str | None) -> dict[str, Any] | None:
    if not fail_on:
        return None
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    drift = report.get("drift", {}) if isinstance(report.get("drift"), dict) else {}
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    qualification = report.get("release_qualification", {}) if isinstance(report.get("release_qualification"), dict) else {}
    gates = qualification.get("gates", {}) if isinstance(qualification.get("gates"), dict) else {}
    blocking_targets = int(summary.get("blocking_target_count", 0))
    new_blocking = int(drift.get("new_blocking_finding_count", 0))
    review_passed = review.get("passed") is True
    required_qualification_gates = {
        "deep_multilang",
        "software_composition",
        "streamable_http_runtime",
        "agent_database_controls",
        "field_accuracy",
    }
    missing_qualification_gates = sorted(required_qualification_gates - set(gates))
    failed_qualification_gates = sorted(
        {
            *missing_qualification_gates,
            *(
                name
                for name, gate in gates.items()
                if name in required_qualification_gates
                and (not isinstance(gate, dict) or gate.get("passed") is not True)
            ),
        }
    )
    qualification_passed = qualification.get("passed") is True and not failed_qualification_gates
    evaluation_passed = (
        blocking_targets == 0
        and new_blocking == 0
        and review_passed
        and qualification_passed
    )
    return {
        "enabled": True,
        "evaluation_passed": evaluation_passed,
        "passed": evaluation_passed,
        "fail_on": fail_on,
        "blocking_target_count": blocking_targets,
        "new_blocking_finding_count": new_blocking,
        "review_contract_passed": review_passed,
        "review_profile": review.get("profile", "missing"),
        "missing_review_domains": list(review.get("missing_review_domains", [])) if isinstance(review.get("missing_review_domains"), list) else [],
        "release_qualification_passed": qualification_passed,
        "failed_qualification_gates": failed_qualification_gates,
        "required_qualification_gates": sorted(required_qualification_gates),
        "recommendation": (
            "Fix blocking findings, complete all review domains, and satisfy deep/multilanguage, Streamable HTTP runtime, and field-accuracy qualification."
            if not evaluation_passed
            else "No Guardian blockers remain and all mandatory release qualifications are bound."
        ),
    }


def refresh_guardian_evidence_bundle(report: dict[str, Any], manifest_path: str | Path | None = None) -> dict[str, Any]:
    if "toolchain_contract" not in report:
        report["toolchain_contract"] = guardian_toolchain_contract()
    for _ in range(2):
        report["release_authority_claim"] = release_authority_claim(report)
        report["evidence_bundle"] = evidence_bundle(
            "guardian_audit",
            "k_guard_mcp.guardian",
            [
                path_artifact("guardian_manifest", manifest_path or report.get("manifest", ""), role="input"),
                object_artifact("report_identity", guardian_report_identity(report), role="identity"),
                object_artifact("execution_attestation", report.get("execution_attestation", {}), role="identity"),
                object_artifact("toolchain_contract", report.get("toolchain_contract", {}), role="identity"),
                object_artifact("summary", report.get("summary", {})),
                object_artifact("execution_contract", report.get("execution_contract", {})),
                object_artifact("intent_contract", report.get("intent_contract", {})),
                object_artifact("review_contract", report.get("review_contract", {})),
                object_artifact("deep_analyzer_reports", report.get("deep_analyzer_reports", []), role="analysis"),
                object_artifact("software_composition_reports", report.get("software_composition_reports", []), role="analysis"),
                object_artifact("release_qualification", report.get("release_qualification", {}), role="gate"),
                object_artifact("baseline", report.get("baseline", {})),
                object_artifact("drift", report.get("drift", {})),
                object_artifact("guardian_gate", report.get("guardian_gate", {}), role="gate"),
                object_artifact("release_authority_claim", report["release_authority_claim"], role="gate"),
                object_artifact("experience", report.get("experience", {})),
                object_artifact("suppression_policy", report.get("suppression_policy", {}), role="policy"),
                object_artifact("target_refs", release_target_evidence_refs(report.get("targets", []))),
                object_artifact("top_rules", report.get("top_rules", [])),
            ],
        )
        apply_guardian_experience(report)
    return report


def build_validation_guardian_evidence(
    *,
    method: str,
    generated_at: str,
    targets: list[dict[str, Any]],
    evidence_input_path: str | Path,
    scanner: KGuardScanner | None = None,
) -> dict[str, Any]:
    """Bind non-authoritative benchmark findings to a real Guardian execution."""
    completed_at = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    if completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=UTC)
    started_at = completed_at - timedelta(microseconds=1)
    execution_id = secrets.token_hex(16)
    active_scanner = scanner or KGuardScanner()
    report = {
        "generated_at": completed_at.isoformat(),
        "execution_id": execution_id,
        "method": method,
        "execution_attestation": build_guardian_execution_attestation(
            execution_id,
            started_at.isoformat(),
            completed_at.isoformat(),
            targets,
        ),
        "toolchain_contract": guardian_toolchain_contract(active_scanner),
        "raw_free": True,
        "targets": targets,
        "validation_execution": {
            "release_authority": False,
            "purpose": "benchmark_or_seeded_regression_evidence",
            "raw_returned": False,
        },
    }
    refresh_guardian_evidence_bundle(report, evidence_input_path)
    return sanitize_any(report)


def guardian_report_identity(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": report.get("generated_at"),
        "execution_id": report.get("execution_id"),
        "method": report.get("method"),
        "raw_returned": False,
    }


def build_guardian_execution_attestation(
    execution_id: str,
    started_at: str,
    completed_at: str,
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    target_projection = release_target_evidence_refs(targets)
    target_evidence_sha256 = hashlib.sha256(canonical_json(target_projection).encode("utf-8")).hexdigest()
    return {
        "schema": "k_guard_guardian_execution_attestation.v1",
        "execution_id": execution_id,
        "started_at": started_at,
        "completed_at": completed_at,
        "target_count": len(targets),
        "target_evidence_sha256": target_evidence_sha256,
        "locally_signed_not_remote_attestation": True,
        "raw_returned": False,
    }


def guardian_execution_attestation_valid(report: dict[str, Any]) -> bool:
    attestation = report.get("execution_attestation", {}) if isinstance(report.get("execution_attestation"), dict) else {}
    try:
        started = datetime.fromisoformat(str(attestation.get("started_at") or "").replace("Z", "+00:00"))
        completed = datetime.fromisoformat(str(attestation.get("completed_at") or "").replace("Z", "+00:00"))
    except ValueError:
        return False
    targets = report.get("targets", []) if isinstance(report.get("targets"), list) else []
    expected = build_guardian_execution_attestation(
        str(report.get("execution_id") or ""),
        str(attestation.get("started_at") or ""),
        str(attestation.get("completed_at") or ""),
        targets,
    )
    current_target_sha256 = expected["target_evidence_sha256"]
    attested_target_sha256 = str(attestation.get("target_evidence_sha256") or "")
    expected["target_evidence_sha256"] = attested_target_sha256
    suppression = report.get("suppression_policy", {}) if isinstance(report.get("suppression_policy"), dict) else {}
    suppression_binding = suppression.get("execution_input_binding", {}) if isinstance(suppression.get("execution_input_binding"), dict) else {}
    digest_valid = attested_target_sha256 == current_target_sha256 or bool(
        suppression_binding.get("valid") is True
        and suppression_binding.get("execution_id") == report.get("execution_id")
        and suppression_binding.get("pre_suppression_target_evidence_sha256") == attested_target_sha256
    )
    return bool(
        re.fullmatch(r"[0-9a-f]{32}", str(report.get("execution_id") or ""))
        and started.tzinfo is not None
        and completed.tzinfo is not None
        and started <= completed
        and attestation == expected
        and digest_valid
    )


def guardian_toolchain_contract(scanner: KGuardScanner | None = None) -> dict[str, Any]:
    active_scanner = scanner or KGuardScanner()
    package_root = Path(__file__).resolve().parent
    module_paths = sorted(
        (
            *package_root.rglob("*.py"),
            *(package_root / "analyzer_profiles").glob("*.yml"),
            *(path for path in (package_root / "validation_packs").rglob("*") if path.is_file()),
        ),
        key=lambda item: item.relative_to(package_root).as_posix(),
    )
    digest = hashlib.sha256()
    hashed_count = 0
    for path in sorted(module_paths, key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(package_root).as_posix().encode("utf-8")
            content = path.read_bytes()
        except (OSError, ValueError):
            continue
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        hashed_count += 1
    return {
        "schema": "k_guard_guardian_toolchain.v1",
        "package_version": __version__,
        "scanner_class": f"{type(active_scanner).__module__}.{type(active_scanner).__qualname__}",
        "ruleset_source_sha256": digest.hexdigest(),
        "expected_module_count": len(module_paths),
        "hashed_module_count": hashed_count,
        "complete": bool(module_paths) and hashed_count == len(module_paths),
        "source_scope": [
            "k_guard_mcp/**/*.py",
            "k_guard_mcp/analyzer_profiles/*.yml",
            "k_guard_mcp/validation_packs/**/*",
        ],
        "raw_returned": False,
    }


def write_guardian_report(report: dict[str, Any], output_path: str | Path, markdown_path: str | Path | None = None, html_path: str | Path | None = None) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if markdown_path:
        markdown = Path(markdown_path)
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(guardian_to_markdown(report), encoding="utf-8")
    if html_path:
        html = Path(html_path)
        html.parent.mkdir(parents=True, exist_ok=True)
        html.write_text(guardian_to_html(report), encoding="utf-8")


def guardian_to_markdown(report: dict[str, Any]) -> str:
    contract = report.get("execution_contract", {}) if isinstance(report.get("execution_contract"), dict) else {}
    intent = report.get("intent_contract", {}) if isinstance(report.get("intent_contract"), dict) else {}
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    experience = report.get("experience", {}) if isinstance(report.get("experience"), dict) else {}
    verdict_value = experience.get("verdict", {})
    verdict_message = (
        str(verdict_value.get("message") or "검수 결과를 확인하세요.")
        if isinstance(verdict_value, dict)
        else str(verdict_value or "검수 결과를 확인하세요.")
    )
    lines = [
        "# 안경선배 Guardian Report",
        "",
        f"> {verdict_message}",
        f"> {experience.get('summary', '')}",
        "",
        f"- north_star: `{experience.get('north_star', NORTH_STAR)}`",
        f"- verdict_code: `{experience.get('verdict_code', 'review_only')}`",
        "",
        f"- generated_at: `{report.get('generated_at')}`",
        f"- run_probes: `{report.get('run_probes')}`",
        f"- target_count: `{report.get('summary', {}).get('target_count', 0)}`",
        f"- blocking_target_count: `{report.get('summary', {}).get('blocking_target_count', 0)}`",
        f"- coverage_gap_target_count: `{report.get('summary', {}).get('coverage_gap_target_count', 0)}`",
        f"- new_blocking_finding_count: `{report.get('drift', {}).get('new_blocking_finding_count', 0)}`",
        f"- execution_mode: `{contract.get('mode', 'report')}`",
        f"- baseline_status: `{contract.get('baseline_status', report.get('baseline', {}).get('status', 'initial_snapshot'))}`",
        f"- business_intent_complete: `{intent.get('business_purpose_complete', False)}`",
        f"- business_intent_explicit_complete: `{intent.get('business_purpose_explicit_complete', False)}`",
        f"- scope_assertion_complete: `{intent.get('scope_assertion_complete', False)}`",
        f"- review_profile: `{review.get('profile', 'missing')}`",
        f"- review_contract_passed: `{review.get('passed', False)}`",
        f"- authorized_dynamic_execution: `{contract.get('authorized_dynamic_execution', 'not_requested')}`",
        f"- http_executed_count: `{contract.get('http_executed_count', 0)}` / `{contract.get('http_target_count', 0)}`",
        f"- skipped_target_count: `{contract.get('skipped_target_count', 0)}`",
        f"- error_target_count: `{contract.get('error_target_count', 0)}`",
        "",
        "## Targets",
        "",
        "| target | kind | status | gate | critical | high | medium | fix count |",
        "|---|---|---|---|---:|---:|---:|---:|",
    ]
    review_lines = ["", "## Review Domains", "", "| domain | passed | missing |", "|---|---:|---|"]
    for name, domain in review.get("domains", {}).items():
        if not isinstance(domain, dict):
            continue
        review_lines.append(f"| `{name}` | {domain.get('passed', False)} | {', '.join(str(item) for item in domain.get('missing', []))} |")
    lines[lines.index("## Targets"):lines.index("## Targets")] = review_lines
    for row in report.get("targets", []):
        summary = row.get("summary", {}) if isinstance(row, dict) else {}
        lines.append(
            f"| `{row.get('target_id')}` | `{row.get('kind')}` | `{row.get('status')}` | `{row.get('gate', {}).get('passed')}` | "
            f"{summary.get('critical', 0)} | {summary.get('high', 0)} | {summary.get('medium', 0)} | {len(row.get('fixes', []))} |"
        )
    lines.extend(["", "## Fix Plan", "", "| rule | affected | max severity | first fix step |", "|---|---:|---|---|"])
    for item in report.get("fix_plan", []):
        steps = item.get("fix_steps", [])
        first_step = steps[0] if isinstance(steps, list) and steps else ""
        lines.append(f"| `{item.get('rule_id')}` | {item.get('affected_findings')} | `{item.get('max_severity')}` | {first_step} |")
    if report.get("drift", {}).get("new_blocking_findings"):
        lines.extend(["", "## New Blocking Findings", "", "| target | rule | severity | source | location |", "|---|---|---|---|---|"])
        for item in report["drift"]["new_blocking_findings"][:50]:
            lines.append(f"| `{item.get('target_id')}` | `{item.get('rule_id')}` | `{item.get('severity')}` | `{item.get('source')}` | `{item.get('location')}` |")
    return "\n".join(lines) + "\n"


def guardian_to_html(report: dict[str, Any]) -> str:
    from html import escape

    summary = report.get("summary", {})
    contract = report.get("execution_contract", {}) if isinstance(report.get("execution_contract"), dict) else {}
    intent = report.get("intent_contract", {}) if isinstance(report.get("intent_contract"), dict) else {}
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    experience = report.get("experience", {}) if isinstance(report.get("experience"), dict) else {}
    review_rows = []
    for name, domain in review.get("domains", {}).items():
        if not isinstance(domain, dict):
            continue
        review_rows.append(
            f'<tr><td>{escape(str(name))}</td><td>{escape(str(domain.get("passed", False)))}</td><td>{escape(", ".join(str(item) for item in domain.get("missing", [])))}</td></tr>'
        )
    target_rows = []
    for row in report.get("targets", []):
        target_summary = row.get("summary", {}) if isinstance(row, dict) else {}
        cls = "blocked" if not row.get("gate", {}).get("passed", True) else "ok"
        target_rows.append(
            "<tr class=\"{cls}\"><td>{target}</td><td>{kind}</td><td>{status}</td><td>{gate}</td><td>{critical}</td><td>{high}</td><td>{medium}</td><td>{fixes}</td></tr>".format(
                cls=cls,
                target=escape(str(row.get("target_id", ""))),
                kind=escape(str(row.get("kind", ""))),
                status=escape(str(row.get("status", ""))),
                gate=escape(str(row.get("gate", {}).get("passed", ""))),
                critical=escape(str(target_summary.get("critical", 0))),
                high=escape(str(target_summary.get("high", 0))),
                medium=escape(str(target_summary.get("medium", 0))),
                fixes=escape(str(len(row.get("fixes", [])))),
            )
        )
    fix_cards = []
    for item in report.get("fix_plan", []):
        steps = item.get("fix_steps", [])
        step_items = "".join(f"<li>{escape(str(step))}</li>" for step in steps[:4]) if isinstance(steps, list) else ""
        fix_cards.append(
            f"<article><h2>{escape(str(item.get('rule_id', '')))}</h2><p>{escape(str(item.get('title', '')))}</p><ol>{step_items}</ol></article>"
        )
    verdict_value = experience.get("verdict", {})
    verdict_message = (
        str(verdict_value.get("message") or "검수 결과를 확인하세요.")
        if isinstance(verdict_value, dict)
        else str(verdict_value or "검수 결과를 확인하세요.")
    )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="ko">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>안경선배 Guardian Report</title>",
            "<style>body{font-family:Inter,system-ui,sans-serif;margin:0;background:#f2f3ee;color:#171a18}main{max-width:1180px;margin:0 auto;padding:24px}.brand{font:700 13px ui-monospace,Consolas,monospace;color:#9cff57}.hero{background:#111613;color:#f7f8f2;border:1px solid #303831;border-left:6px solid #d94c5c;border-radius:8px;padding:18px;margin-bottom:14px}.hero h1{margin:5px 0 8px;font-size:26px}.hero p{margin:0;color:#cbd3ca}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.metric,article{background:white;border:1px solid #cfd4cc;border-radius:8px;padding:12px}.metric b{display:block;font-size:24px}table{width:100%;border-collapse:collapse;background:white;margin-top:14px}th,td{border:1px solid #cfd4cc;padding:8px;font-size:13px;text-align:left}th{background:#e7eae3}.blocked td:first-child{border-left:5px solid #b42318}.ok td:first-child{border-left:5px solid #067647}.fixes{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:14px}h2{font-size:16px;margin:0 0 8px}</style>",
            "</head>",
            "<body><main>",
            '<section class="hero">',
            '<div class="brand">K-GUARD MCP / 안경선배</div>',
            f"<h1>{escape(verdict_message)}</h1>",
            f"<p>{escape(str(experience.get('summary', '')))}</p>",
            "</section>",
            '<section class="metrics">',
            f'<div class="metric">targets<b>{escape(str(summary.get("target_count", 0)))}</b></div>',
            f'<div class="metric">blocking targets<b>{escape(str(summary.get("blocking_target_count", 0)))}</b></div>',
            f'<div class="metric">coverage gaps<b>{escape(str(summary.get("coverage_gap_target_count", 0)))}</b></div>',
            f'<div class="metric">critical<b>{escape(str(summary.get("severity_counts", {}).get("critical", 0)))}</b></div>',
            f'<div class="metric">high<b>{escape(str(summary.get("severity_counts", {}).get("high", 0)))}</b></div>',
            f'<div class="metric">new blockers<b>{escape(str(report.get("drift", {}).get("new_blocking_finding_count", 0)))}</b></div>',
            "</section>",
            "<section><h2>Execution Contract</h2><table><tbody>",
            f'<tr><th>mode</th><td>{escape(str(contract.get("mode", "report")))}</td></tr>',
            f'<tr><th>baseline</th><td>{escape(str(contract.get("baseline_status", report.get("baseline", {}).get("status", "initial_snapshot"))))}</td></tr>',
            f'<tr><th>business intent complete</th><td>{escape(str(intent.get("business_purpose_complete", False)))}</td></tr>',
            f'<tr><th>business intent explicit</th><td>{escape(str(intent.get("business_purpose_explicit_complete", False)))}</td></tr>',
            f'<tr><th>scope assertion complete</th><td>{escape(str(intent.get("scope_assertion_complete", False)))}</td></tr>',
            f'<tr><th>review profile</th><td>{escape(str(review.get("profile", "missing")))}</td></tr>',
            f'<tr><th>review contract passed</th><td>{escape(str(review.get("passed", False)))}</td></tr>',
            f'<tr><th>dynamic execution</th><td>{escape(str(contract.get("authorized_dynamic_execution", "not_requested")))}</td></tr>',
            f'<tr><th>HTTP executed</th><td>{escape(str(contract.get("http_executed_count", 0)))} / {escape(str(contract.get("http_target_count", 0)))}</td></tr>',
            f'<tr><th>skipped</th><td>{escape(str(contract.get("skipped_target_count", 0)))}</td></tr>',
            f'<tr><th>errors</th><td>{escape(str(contract.get("error_target_count", 0)))}</td></tr>',
            "</tbody></table></section>",
            "<section><h2>Review Domains</h2><table><thead><tr><th>domain</th><th>passed</th><th>missing</th></tr></thead><tbody>",
            "\n".join(review_rows),
            "</tbody></table></section>",
            "<section><h2>Targets</h2><table><thead><tr><th>target</th><th>kind</th><th>status</th><th>gate</th><th>critical</th><th>high</th><th>medium</th><th>fixes</th></tr></thead><tbody>",
            "\n".join(target_rows),
            "</tbody></table></section>",
            '<section><h2>Fix Plan</h2><div class="fixes">',
            "\n".join(fix_cards) if fix_cards else "<article>No fixes required.</article>",
            "</div></section>",
            "</main></body></html>",
        ]
    )


def _read_manifest(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Guardian manifest not found: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        return []
    targets = [_normalize_target(row, index) for index, row in enumerate(rows, start=1)]
    target_ids = [target["target_id"] for target in targets]
    if len(set(target_ids)) != len(target_ids):
        raise ValueError("Guardian manifest target_id values must be unique.")
    return targets


def _normalize_target(row: dict[str, str], index: int) -> dict[str, str]:
    target = {field: str(row.get(field, "") or "").strip() for field in GUARDIAN_MANIFEST_FIELDS}
    target["target_id"] = target["target_id"] or f"target-{index:03d}"
    requested_kind = target["kind"].lower()
    target["_kind_ref"] = evidence_hash(requested_kind)
    target["kind"] = GUARDIAN_KIND_ALIASES.get(requested_kind, "unknown")
    target["fail_on"] = target["fail_on"] or "high"
    target["audit_profile"] = target["audit_profile"].lower() or "standard"
    return target


KNOWN_DATA_CLASSES = {
    "personal_data",
    "secrets",
    "runtime_config",
    "runtime_response",
    "tool_events",
    "raw_free_findings",
    "payments",
    "health",
    "children",
    "location",
    "biometric",
    "employee",
    "public_content",
}


def _business_context(target: dict[str, str]) -> dict[str, Any]:
    explicit_purpose = target.get("business_purpose") or ""
    purpose = explicit_purpose or target.get("notes") or ""
    data_classes, custom_count = _normalized_data_classes(target.get("data_classes", ""))
    endpoints = _manifest_list(target.get("public_endpoints", ""))
    scope = target.get("user_scope", "")
    return {
        "assertion_source": "guardian_manifest",
        "purpose_present": bool(purpose.strip()),
        "purpose_explicit": bool(explicit_purpose.strip()),
        "purpose_ref": _raw_free_ref(purpose, "business_purpose") if purpose.strip() else {},
        "data_classes": data_classes,
        "custom_data_class_count": custom_count,
        "user_scope_present": bool(scope.strip()),
        "user_scope_ref": _raw_free_ref(scope, "user_scope") if scope.strip() else {},
        "public_endpoint_count": len(endpoints),
        "public_endpoint_refs": [_raw_free_ref(endpoint, "public_endpoint") for endpoint in endpoints[:20]],
        "raw_returned": False,
    }


def _scope_contract(target: dict[str, str], kind: str) -> dict[str, Any]:
    basis = (target.get("scope_basis") or _inferred_scope_basis(target, kind)).strip()
    proof = target.get("scope_proof_ref") or ""
    authorization_note = target.get("authorization_note", "")
    return {
        "assertion_boundary": "external_scope_assertion_ref",
        "basis": basis or "unspecified",
        "assertion_present": bool(proof.strip()),
        "assertion_ref": _raw_free_ref(proof, "scope_proof_ref") if proof.strip() else {},
        "legacy_authorization_note_present": bool(authorization_note.strip()),
        "legacy_authorization_note_ref": _raw_free_ref(authorization_note, "authorization_note") if authorization_note.strip() else {},
        "ownership_or_partner_scope_verified_by_k_guard": False,
        "raw_returned": False,
    }


def _inferred_scope_basis(target: dict[str, str], kind: str) -> str:
    if kind == "workspace":
        return "local_workspace"
    if kind == "mcp_events":
        return "local_runtime_export"
    if kind == "report":
        return "raw_free_report_import"
    if kind == "http" and not _external_http_target(target.get("locator", "")):
        return "local_http"
    if target.get("authorization_note", "").strip():
        return "manifest_authorization_note"
    return "unspecified"


def _normalized_data_classes(value: str) -> tuple[list[str], int]:
    known: set[str] = set()
    custom = 0
    for item in _manifest_list(value):
        normalized = item.lower().replace(" ", "_").replace("-", "_")
        if normalized in KNOWN_DATA_CLASSES:
            known.add(normalized)
        else:
            custom += 1
    return sorted(known), custom


def _manifest_list(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").replace("|", ",").replace(";", ",").split(",") if part.strip()]


def _safe_manifest_probe_paths(value: str) -> list[str]:
    paths: list[str] = []
    for item in _manifest_list(value)[:50]:
        if len(item) > 240 or "\r" in item or "\n" in item or "{" in item or "}" in item:
            continue
        parsed = urllib.parse.urlsplit(item)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or ".." in parsed.path.split("/"):
            continue
        normalized = parsed.path or "/"
        if parsed.query:
            normalized += "?" + parsed.query
        if normalized not in paths:
            paths.append(normalized)
    return paths


def _raw_free_ref(value: str, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "hash": evidence_hash(str(value or "")),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _safe_manifest_slug(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if SAFE_MANIFEST_SLUG.fullmatch(text):
        return text
    return f"{label}:{evidence_hash(text)}"


def _safe_manifest_locator(value: str, kind: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if kind == "http":
        parsed = urllib.parse.urlparse(text if "://" in text else "https://" + text)
        host = (parsed.hostname or "").strip("[]").lower()
        if not host:
            return f"locator:{evidence_hash(text)}"
        port = f":{parsed.port}" if parsed.port else ""
        return urllib.parse.urlunparse((parsed.scheme or "https", f"{host}{port}", "/", "", "", ""))
    if text in {".", ".."} or SAFE_MANIFEST_SLUG.fullmatch(text):
        return text
    return f"locator:{evidence_hash(text)}"


def _run_target(
    target: dict[str, str],
    scanner: KGuardScanner,
    run_probes: bool,
    manifest_dir: Path,
    fail_on_override: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    kind = target["kind"]
    fail_on = fail_on_override or target.get("fail_on") or "high"
    authorized = _truthy(target.get("authorized", ""))
    declared_probe_paths = _manifest_list(target.get("public_endpoints", ""))
    valid_probe_paths = _safe_manifest_probe_paths(target.get("public_endpoints", ""))
    row_base = {
        "app_id": _safe_manifest_slug(target.get("app_id", ""), "app_id"),
        "app_id_ref": _raw_free_ref(target.get("app_id", ""), "app_id") if target.get("app_id", "").strip() else {},
        "target_id": _safe_manifest_slug(target["target_id"], "target_id"),
        "target_ref": _raw_free_ref(target["target_id"], "target_id"),
        "kind": kind,
        "kind_ref": {
            "hash": target.get("_kind_ref", evidence_hash(kind)),
            "hash_scheme": evidence_hash_scheme(),
            "raw_returned": False,
        },
        "locator": _safe_manifest_locator(target["locator"], kind),
        "locator_ref": _raw_free_ref(target["locator"], "locator"),
        "owner": _safe_manifest_slug(target.get("owner", ""), "owner"),
        "owner_ref": _raw_free_ref(target.get("owner", ""), "owner") if target.get("owner", "").strip() else {},
        "authorization": {
            "authorized": _truthy(target.get("authorized", "")),
            "note_present": bool(target.get("authorization_note", "").strip()),
            "note_ref": _raw_free_ref(target.get("authorization_note", ""), "authorization_note") if target.get("authorization_note", "").strip() else {},
        },
        "business_context": _business_context(target),
        "scope_contract": _scope_contract(target, kind),
        "audit_profile": _safe_manifest_slug(target.get("audit_profile", "standard"), "audit_profile") or "standard",
        "requested_review": {
            "flow_analysis": kind == "workspace" and _truthy(target.get("include_flow", "true")),
            "deep_active": kind == "http" and _truthy(target.get("deep_active", "")),
            "session_present": kind == "http" and bool(target.get("session_file", "").strip()),
            "declared_public_endpoint_count": len(declared_probe_paths),
            "valid_public_endpoint_count": len(valid_probe_paths),
            "invalid_public_endpoint_count": max(0, len(declared_probe_paths) - len(valid_probe_paths)),
        },
        "fail_on": fail_on,
    }
    if not authorized:
        return _coverage_failure_row(
            row_base,
            "GUARDIAN_TARGET_AUTHORIZATION_REQUIRED",
            "Guardian target authorization is required",
            "The manifest row does not set authorized=true, so K-Guard did not inspect this target.",
            "Only add owned, partner-approved, bug-bounty scoped, or local targets and record the authorization note.",
            manifest_dir,
            target["locator"],
        )
    try:
        if kind == "workspace":
            workspace_path = Path(_resolve_locator(manifest_dir, target["locator"]))
            if not workspace_path.exists():
                return _coverage_failure_row(
                    row_base,
                    "GUARDIAN_TARGET_LOCATOR_NOT_FOUND",
                    "Guardian workspace target was not found",
                    "The configured workspace locator does not exist, so the code/config audit did not run.",
                    "Fix the manifest locator or remove the target row before trusting the guardian report.",
                    manifest_dir,
                    target["locator"],
                )
            snapshot_before = source_tree_snapshot(workspace_path)
            candidates_before = file_inventory_fingerprint(workspace_path, collect_candidate_files(workspace_path))
            result = scanner.scan_workspace(workspace_path, include_flow=_truthy(target.get("include_flow", "true")))
            candidates_after = file_inventory_fingerprint(workspace_path, collect_candidate_files(workspace_path))
            snapshot_after = source_tree_snapshot(workspace_path)
            snapshot_complete = snapshot_before.get("complete") is True and snapshot_after.get("complete") is True
            source_consistent = snapshot_complete and snapshot_before == snapshot_after
            result.metadata["source_tree_snapshot"] = snapshot_after
            result.metadata["source_tree_consistency"] = {
                "matched": source_consistent,
                "complete": snapshot_complete,
                "before_tree_sha256": snapshot_before.get("tree_sha256", ""),
                "after_tree_sha256": snapshot_after.get("tree_sha256", ""),
                "before_file_count": snapshot_before.get("file_count", 0),
                "after_file_count": snapshot_after.get("file_count", 0),
                "raw_returned": False,
            }
            review_coverage = result.metadata.get("review_coverage", {})
            inventory = review_coverage.get("inventory", {}) if isinstance(review_coverage, dict) else {}
            reviewed_candidate_count = int(
                inventory.get("reviewed_candidate_count", inventory.get("scanned_text_file_count", -1))
            )
            scan_inventory_matched = (
                candidates_before == candidates_after
                and int(inventory.get("supported_file_count", -1)) == int(candidates_before["candidate_count"])
                and reviewed_candidate_count == int(candidates_before["candidate_count"])
                and int(inventory.get("unscanned_candidate_count", -1)) == 0
                and inventory.get("candidate_path_set_sha256") == candidates_before["candidate_path_set_sha256"]
                and inventory.get("candidate_content_set_sha256") == candidates_before["candidate_content_set_sha256"]
                and candidates_before.get("content_fingerprint_complete") is True
                and candidates_after.get("content_fingerprint_complete") is True
                and inventory.get("content_fingerprint_complete") is True
                and inventory.get("candidate_set_complete") is True
            )
            result.metadata["scan_inventory_consistency"] = {
                "matched": scan_inventory_matched,
                "before_candidate_count": candidates_before["candidate_count"],
                "after_candidate_count": candidates_after["candidate_count"],
                "scanner_candidate_count": inventory.get("supported_file_count", 0),
                "reviewed_candidate_count": reviewed_candidate_count,
                "scanned_text_file_count": inventory.get("scanned_text_file_count", 0),
                "unscanned_candidate_count": inventory.get("unscanned_candidate_count", 0),
                "oversized_candidate_count": inventory.get("oversized_candidate_count", 0),
                "unsafe_link_candidate_count": inventory.get("unsafe_link_candidate_count", 0),
                "before_candidate_path_set_sha256": candidates_before["candidate_path_set_sha256"],
                "after_candidate_path_set_sha256": candidates_after["candidate_path_set_sha256"],
                "scanner_candidate_path_set_sha256": inventory.get("candidate_path_set_sha256", ""),
                "before_candidate_content_set_sha256": candidates_before["candidate_content_set_sha256"],
                "after_candidate_content_set_sha256": candidates_after["candidate_content_set_sha256"],
                "scanner_candidate_content_set_sha256": inventory.get("candidate_content_set_sha256", ""),
                "content_fingerprint_complete": (
                    candidates_before.get("content_fingerprint_complete") is True
                    and candidates_after.get("content_fingerprint_complete") is True
                    and inventory.get("content_fingerprint_complete") is True
                ),
                "raw_returned": False,
            }
            coverage_finding_added = False
            if not scan_inventory_matched:
                result.findings.append(
                    Finding(
                        id=scanner.ids.next(),
                        source="guardian",
                        rule_id="GUARDIAN_SCAN_INVENTORY_MISMATCH",
                        severity="high",
                        confidence="high",
                        title="Guardian did not scan every supported release candidate",
                        file=str(workspace_path),
                        evidence=(
                            f"before_candidates={candidates_before['candidate_count']} "
                            f"after_candidates={candidates_after['candidate_count']} "
                            f"scanner_candidates={inventory.get('supported_file_count', 0)} "
                            f"reviewed_candidates={reviewed_candidate_count} "
                            f"scanned_text={inventory.get('scanned_text_file_count', 0)} "
                            f"unscanned={inventory.get('unscanned_candidate_count', 0)} raw_returned=false"
                        ),
                        why_it_matters="A release decision cannot omit a supported source, configuration, or deployable generated text artifact.",
                        recommendation="Make every supported candidate readable and stable, then rerun Guardian against an immutable checkout.",
                        audit_depth=4,
                        inspected_scope="Guardian independently compared the before/after candidate-set fingerprint with the scanner inventory.",
                        not_inspected="No release claim is made for a mismatched or unreadable candidate set.",
                    )
                )
                coverage_finding_added = True
            if not snapshot_complete:
                result.findings.append(
                    Finding(
                        id=scanner.ids.next(),
                        source="guardian",
                        rule_id="GUARDIAN_RELEASE_SNAPSHOT_INCOMPLETE",
                        severity="high",
                        confidence="high",
                        title="Workspace release snapshot was incomplete",
                        file=str(workspace_path),
                        evidence=(
                            f"before_complete={str(snapshot_before.get('complete') is True).lower()} "
                            f"after_complete={str(snapshot_after.get('complete') is True).lower()} "
                            f"before_limit_exceeded={str(snapshot_before.get('limit_exceeded') is True).lower()} "
                            f"after_limit_exceeded={str(snapshot_after.get('limit_exceeded') is True).lower()} raw_returned=false"
                        ),
                        why_it_matters="Release authority cannot rely on a tree hash that silently omitted unreadable or out-of-bound deployable files.",
                        recommendation="Reduce the workspace below the documented snapshot bounds or remove unreadable/symlinked trees, then rerun Guardian.",
                        audit_depth=4,
                        inspected_scope="Guardian used the independent bounded release snapshot collector before and after the workspace scan.",
                        not_inspected="No release claim is made for files omitted after a collector bound or filesystem error.",
                    )
                )
                coverage_finding_added = True
            elif not source_consistent:
                result.findings.append(
                    Finding(
                        id=scanner.ids.next(),
                        source="guardian",
                        rule_id="GUARDIAN_SOURCE_CHANGED_DURING_AUDIT",
                        severity="high",
                        confidence="high",
                        title="Workspace source changed during Guardian audit",
                        file=str(workspace_path),
                        evidence=(
                            f"before_tree_sha256={snapshot_before.get('tree_sha256', '')} "
                            f"after_tree_sha256={snapshot_after.get('tree_sha256', '')} "
                            f"before_files={snapshot_before.get('file_count', 0)} after_files={snapshot_after.get('file_count', 0)} "
                            "raw_returned=false"
                        ),
                        why_it_matters="A release decision must describe one stable source state; concurrent edits make findings and provenance ambiguous.",
                        recommendation="Stop writers, rerun Guardian against an immutable checkout or CI commit, and sign only the stable rerun.",
                        audit_depth=4,
                        inspected_scope="Guardian compared content-addressed source-tree snapshots immediately before and after the workspace audit.",
                        not_inspected="This does not provide filesystem-level transactional locking; use an immutable CI checkout for the release authority.",
                    )
                )
                coverage_finding_added = True
            if coverage_finding_added:
                result.finalize()
            return _row_from_result(row_base, result, "completed", manifest_dir, target["locator"])
        if kind == "mcp_events":
            event_path = Path(_resolve_locator(manifest_dir, target["locator"]))
            if not event_path.exists() or not event_path.is_file():
                return _coverage_failure_row(
                    row_base,
                    "GUARDIAN_TARGET_LOCATOR_NOT_FOUND",
                    "Guardian MCP event target was not found",
                    "The configured MCP runtime/event export file does not exist, so runtime observation did not run.",
                    "Export MCP runtime events to the configured JSONL path or update the manifest locator.",
                    manifest_dir,
                    target["locator"],
                )
            result = scanner.observe_mcp_events(event_path.read_text(encoding="utf-8"), str(event_path))
            return _row_from_result(row_base, result, "completed", manifest_dir, target["locator"])
        if kind == "report":
            report_path = Path(_resolve_locator(manifest_dir, target["locator"]))
            if not report_path.exists() or not report_path.is_file():
                return _coverage_failure_row(
                    row_base,
                    "GUARDIAN_TARGET_LOCATOR_NOT_FOUND",
                    "Guardian report target was not found",
                    "The configured raw-free report file does not exist, so import aggregation did not run.",
                    "Write the K-Guard JSON report first or update the manifest locator.",
                    manifest_dir,
                    target["locator"],
                )
            result = _result_from_report(str(report_path))
            return _row_from_result(row_base, result, "completed", manifest_dir, target["locator"])
        if kind == "http":
            if not run_probes:
                if fail_on_override is not None:
                    return _coverage_failure_row(
                        row_base,
                        "GUARDIAN_HTTP_PROBE_NOT_EXECUTED_IN_GATE",
                        "Guardian HTTP target was not executed in gate mode",
                        "The manifest contains an HTTP target, but guardian was run with --fail-on without --run-probes.",
                        "Re-run guardian with --run-probes for authorized HTTP rows, or remove the HTTP row from the gate manifest.",
                        manifest_dir,
                        target["locator"],
                    )
                return _skipped_row(row_base, "skipped_probe_requires_run_probes")
            if _external_http_target(target["locator"]) and not target.get("authorization_note", "").strip():
                return _coverage_failure_row(
                    row_base,
                    "GUARDIAN_EXTERNAL_AUTHORIZATION_NOTE_REQUIRED",
                    "External HTTP target needs authorization evidence",
                    "The external target row is authorized=true but has an empty authorization_note.",
                    "Record the owned domain, partner approval, bug-bounty scope, or allowlist basis before probing.",
                    manifest_dir,
                    target["locator"],
                )
            allowed_hosts = _allowed_hosts_for_target(target["locator"])
            active_profile = "deep" if _truthy(target.get("deep_active", "")) else "baseline"
            probe_paths = _selected_probe_paths(None, active_profile)
            for path in valid_probe_paths:
                if path not in probe_paths:
                    probe_paths.append(path)
            session = _load_session_headers(
                manifest_dir,
                target.get("session_file", ""),
                target["locator"],
            )
            session_headers = session.headers if session else None
            identity_assertion = session.identity_assertion if session else None
            if identity_assertion:
                identity_path = str(identity_assertion["path"])
                if identity_path not in probe_paths:
                    probe_paths.append(identity_path)
                if identity_path not in valid_probe_paths:
                    valid_probe_paths.append(identity_path)
            authorization_note = target.get("authorization_note") or "guardian manifest authorization"
            if session_headers:
                unauthenticated_result = scanner.probe_http(
                    target["locator"],
                    active_profile=active_profile,
                    allowed_hosts=allowed_hosts,
                    authorization_note=authorization_note,
                    paths=probe_paths,
                    required_paths=valid_probe_paths,
                )
                authenticated_result = scanner.probe_http(
                    target["locator"],
                    session_headers=session_headers,
                    active_profile=active_profile,
                    allowed_hosts=allowed_hosts,
                    paths=probe_paths,
                    required_paths=valid_probe_paths,
                    identity_assertion=identity_assertion,
                )
                result = _merge_http_review_results(unauthenticated_result, authenticated_result)
            else:
                result = scanner.probe_http(
                    target["locator"],
                    active_profile=active_profile,
                    allowed_hosts=allowed_hosts,
                    authorization_note=authorization_note,
                    paths=probe_paths,
                    required_paths=valid_probe_paths,
                )
            dynamic_contract = result.metadata.get("dynamic_probe_contract", {})
            review_status = "completed" if dynamic_contract.get("coverage_complete") is True else "incomplete_fail_closed"
            return _row_from_result(row_base, result, review_status, manifest_dir, target["locator"])
        return _coverage_failure_row(
            row_base,
            "GUARDIAN_TARGET_KIND_UNKNOWN",
            "Guardian target kind is unknown",
            "Unknown manifest kind; kind_ref is available in the target envelope and raw_returned=false.",
            "Use one of: workspace, http, mcp_events, report.",
            manifest_dir,
            target["locator"],
        )
    except Exception as exc:
        return _coverage_failure_row(
            row_base,
            "GUARDIAN_TARGET_FAILED",
            "Guardian target failed",
            (
                f"error_type={type(exc).__name__} "
                f"error_ref={evidence_hash(f'{type(exc).__name__}:{exc}')} "
                f"scheme={evidence_hash_scheme()} raw_returned=false"
            ),
            "Verify the manifest locator, kind, authorization, session file, and target availability.",
            manifest_dir,
            target["locator"],
        )


def _coverage_failure_row(
    row_base: dict[str, Any],
    rule_id: str,
    title: str,
    evidence: str,
    recommendation: str,
    manifest_dir: Path,
    target_locator: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    finding = Finding(
        id=f"guardian-{rule_id.lower()}",
        source="guardian",
        rule_id=rule_id,
        severity=str(row_base.get("fail_on") or "high"),
        confidence="high",
        title=title,
        evidence=evidence,
        why_it_matters="A configured guardian target could not be audited, so the report would otherwise overstate coverage.",
        recommendation=recommendation,
    )
    return _row_from_result(row_base, ScanResult(findings=[finding]).finalize(), "error", manifest_dir, target_locator)


def _row_from_result(row_base: dict[str, Any], result: ScanResult, status: str, manifest_dir: Path, target_locator: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings = []
    for finding in result.findings:
        item = finding.to_dict()
        item["target_id"] = row_base["target_id"]
        _normalize_finding_locations(item, manifest_dir, row_base["target_id"], target_locator)
        findings.append(item)
    threshold_findings = [
        finding
        for finding in result.findings
        if _severity_at_or_above(finding.severity, row_base["fail_on"])
    ]
    blocking = [
        finding for finding in result.findings if is_release_blocking_finding(finding, row_base["fail_on"])
    ]
    hold_counts = release_hold_counts(threshold_findings, row_base["fail_on"])
    blocking_scope_counts = Counter(finding.artifact_scope or "workspace_evidence" for finding in blocking)
    blocking_action_groups = {
        (finding.rule_id, finding.artifact_scope or "workspace_evidence")
        for finding in blocking
    }
    row = {
        **row_base,
        "status": status,
        "summary": result.summary(),
        "gate": {
            "passed": not blocking,
            "blocking_count": len(blocking),
            "supporting_review_at_threshold_count": len(threshold_findings) - len(blocking),
            "blocking_policy": RELEASE_BLOCKING_POLICY,
            "automatic_release_blocking_count": hold_counts["automatic_release_blocking_count"],
            "manual_review_hold_count": hold_counts["manual_review_hold_count"],
            "policy_integrity_hold_count": hold_counts["policy_integrity_hold_count"],
            "blocking_action_group_count": len(blocking_action_groups),
            "blocking_artifact_scope_counts": dict(sorted(blocking_scope_counts.items())),
            "recommendation": "Fix blocking findings before deploy." if blocking else "No blocking findings at this threshold.",
        },
        "coverage": {
            "executed": status == "completed",
            "coverage_gap": status != "completed",
            "status": status,
        },
        "review_evidence": result.metadata,
        "rule_ids": sorted({finding.rule_id for finding in result.findings}),
        "findings": findings,
        "fixes": _fixes_for_findings(findings),
    }
    return sanitize_any(row), sanitize_any(findings)


def _merge_http_review_results(unauthenticated: ScanResult, authenticated: ScanResult) -> ScanResult:
    unauth_contract = unauthenticated.metadata.get("dynamic_probe_contract", {})
    auth_contract = authenticated.metadata.get("dynamic_probe_contract", {})
    session_headers_recognized = auth_contract.get("authenticated") is True
    auth_acceptance_observed, auth_transition_path_refs = _auth_acceptance_transition(unauth_contract, auth_contract)
    identity_verified = auth_contract.get("identity_assertion_matched") is True
    authenticated_comparison = session_headers_recognized and auth_acceptance_observed and identity_verified
    base_coverage = unauthenticated.metadata.get("review_coverage", {})
    domains = {
        name: dict(value) if isinstance(value, dict) else value
        for name, value in base_coverage.get("domains", {}).items()
    } if isinstance(base_coverage, dict) else {}
    if isinstance(domains.get("api_exposure"), dict):
        domains["api_exposure"]["unauthenticated_and_authenticated_compared"] = authenticated_comparison
        domains["api_exposure"]["session_headers_recognized"] = session_headers_recognized
        domains["api_exposure"]["auth_acceptance_observed"] = auth_acceptance_observed
        domains["api_exposure"]["identity_verified"] = identity_verified
    review_coverage = dict(base_coverage) if isinstance(base_coverage, dict) else {}
    review_coverage["domains"] = domains
    review_coverage["authorization_comparison"] = (
        "unauthenticated_plus_operator_session" if authenticated_comparison else "unauthenticated_plus_unrecognized_headers"
    )
    review_coverage["raw_returned"] = False
    required_refs = sorted(set(unauth_contract.get("required_path_refs", [])) | set(auth_contract.get("required_path_refs", [])))
    reached_refs = sorted(
        set(unauth_contract.get("required_path_reached_refs", []))
        & set(auth_contract.get("required_path_reached_refs", []))
    )
    merged_findings = [*unauthenticated.findings, *authenticated.findings]
    if session_headers_recognized and not auth_acceptance_observed:
        merged_findings.append(
            Finding(
                id="guardian-dyn-auth-session-acceptance-unproven",
                source="dynamic-authorization-comparison",
                rule_id="DYN_AUTH_SESSION_ACCEPTANCE_UNPROVEN",
                severity="high",
                confidence="high",
                title="Operator session did not prove an authenticated response transition",
                evidence=(
                    "detector_subtype=auth_session_acceptance_unproven "
                    f"unauth_observation_count={len(unauth_contract.get('response_observations', []))} "
                    f"auth_observation_count={len(auth_contract.get('response_observations', []))} raw_returned=false"
                ),
                why_it_matters="Recognizing an Authorization or Cookie header does not prove that the target accepted it or that authenticated paths were reviewed.",
                recommendation="Provide a valid, scoped test-user session and at least one declared path that transitions from an auth wall to an authenticated response, then rerun Guardian.",
                audit_depth=4,
                inspected_scope="Unauthenticated and operator-session GET observations were compared by path reference, status, auth-wall class, private-data signal, and raw-free response hash.",
                not_inspected="User identity, role, ownership, and object-level authorization remain unproven when no authenticated transition is observed.",
            )
        )
    if session_headers_recognized and not identity_verified and not any(
        finding.rule_id == "DYN_AUTH_IDENTITY_UNVERIFIED" for finding in merged_findings
    ):
        merged_findings.append(
            Finding(
                id="guardian-dyn-auth-identity-unverified",
                source="dynamic-authorization-comparison",
                rule_id="DYN_AUTH_IDENTITY_UNVERIFIED",
                severity="high",
                confidence="high",
                title="Authenticated identity assertion was not verified",
                evidence=(
                    "detector_subtype=auth_identity_assertion_unverified "
                    f"assertion_supplied={str(auth_contract.get('identity_assertion_supplied') is True).lower()} "
                    f"assertion_matched={str(identity_verified).lower()} raw_returned=false"
                ),
                why_it_matters="A Cookie or Authorization header and a 2xx transition do not prove which user or role the server accepted.",
                recommendation="Bind the session file to the exact origin and add a short-lived identity_assertion with the expected status and SHA-256 of a stable test-user identity response.",
                audit_depth=4,
                inspected_scope="The authenticated response at the asserted path was compared with the operator-provided status and body digest without returning body content.",
                not_inspected="Object-level authorization still requires at least two separately asserted principals and resource ownership tests.",
            )
        )
    result = ScanResult(
        findings=merged_findings,
        metadata={
            "dynamic_probe_contract": {
                "active_profile": unauth_contract.get("active_profile", auth_contract.get("active_profile", "baseline")),
                "authenticated_comparison": authenticated_comparison,
                "session_headers_recognized": session_headers_recognized,
                "auth_acceptance_observed": auth_acceptance_observed,
                "identity_verified": identity_verified,
                "auth_transition_path_refs": auth_transition_path_refs,
                "request_count": int(unauth_contract.get("request_count", 0)) + int(auth_contract.get("request_count", 0)),
                "error_request_count": int(unauth_contract.get("error_request_count", 0)) + int(auth_contract.get("error_request_count", 0)),
                "observed_path_count": max(int(unauth_contract.get("observed_path_count", 0)), int(auth_contract.get("observed_path_count", 0))),
                "successful_get_path_count": max(int(unauth_contract.get("successful_get_path_count", 0)), int(auth_contract.get("successful_get_path_count", 0))),
                "required_path_count": len(required_refs),
                "required_path_reached_count": len(reached_refs),
                "required_path_refs": required_refs,
                "required_path_reached_refs": reached_refs,
                "methods": sorted(set(unauth_contract.get("methods", [])) | set(auth_contract.get("methods", []))),
                "coverage_complete": (
                    unauth_contract.get("coverage_complete") is True
                    and auth_contract.get("coverage_complete") is True
                    and authenticated_comparison
                    and len(reached_refs) == len(required_refs)
                ),
                "unauthenticated": unauth_contract,
                "authenticated": auth_contract,
                "raw_returned": False,
            },
            "review_coverage": review_coverage,
        },
    )
    return result.finalize()


def _auth_acceptance_transition(unauthenticated: dict[str, Any], authenticated: dict[str, Any]) -> tuple[bool, list[str]]:
    unauth_by_path = _get_observations_by_path(unauthenticated)
    auth_by_path = _get_observations_by_path(authenticated)
    transitions: list[str] = []
    for path_ref in sorted(set(unauth_by_path) & set(auth_by_path)):
        before = unauth_by_path[path_ref]
        after = auth_by_path[path_ref]
        after_status = after.get("status")
        if not isinstance(after_status, int) or not 200 <= after_status < 300 or after.get("auth_wall") is True:
            continue
        hashes_differ = bool(before.get("response_hash")) and before.get("response_hash") != after.get("response_hash")
        moved_through_auth_wall = before.get("auth_wall") is True and (hashes_differ or before.get("status") != after_status)
        revealed_private_signal = (
            before.get("private_data_signal") is not True
            and after.get("private_data_signal") is True
            and hashes_differ
        )
        if moved_through_auth_wall or revealed_private_signal:
            transitions.append(path_ref)
    return bool(transitions), transitions


def _get_observations_by_path(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    observations = contract.get("response_observations", [])
    if not isinstance(observations, list):
        return {}
    selected: dict[str, dict[str, Any]] = {}
    for observation in observations:
        if not isinstance(observation, dict) or observation.get("method") != "GET":
            continue
        path_ref = observation.get("path_ref")
        if isinstance(path_ref, str) and path_ref:
            selected[path_ref] = observation
    return selected


def _skipped_row(row_base: dict[str, Any], status: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    row = {
        **row_base,
        "status": status,
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "gate": {"passed": True, "blocking_count": 0, "recommendation": "Target was not executed."},
        "coverage": {"executed": False, "coverage_gap": True, "status": status},
        "review_evidence": {},
        "rule_ids": [],
        "findings": [],
        "fixes": [],
    }
    return row, []


def _result_from_report(path: str) -> ScanResult:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("raw_free") is not True:
        raise ValueError("Imported Guardian report must be an explicit raw_free JSON object.")
    findings: list[Finding] = []
    for index, item in enumerate(data.get("findings", []), start=1):
        if not isinstance(item, dict):
            continue
        rule_id = _safe_manifest_slug(str(item.get("rule_id") or "IMPORTED_FINDING"), "rule_id") or "IMPORTED_FINDING"
        source = _safe_manifest_slug(str(item.get("source") or "imported-report"), "source") or "imported-report"
        severity = str(item.get("severity") or "info").lower()
        confidence = str(item.get("confidence") or "medium").lower()
        findings.append(
            Finding(
                id=f"imported-{index}",
                source=source,
                rule_id=rule_id,
                severity=severity if severity in {"critical", "high", "medium", "low", "info"} else "info",
                confidence=confidence if confidence in {"high", "medium", "low"} else "medium",
                title=f"Imported raw-free finding: {rule_id}",
                evidence=f"imported_finding_ref={evidence_hash(canonical_json(item))} scheme={evidence_hash_scheme()} raw_returned=false",
                why_it_matters="An explicitly raw-free K-Guard report recorded this finding for aggregate release review.",
                recommendation="Review the source report locally and verify the finding with the original scanner workflow.",
            )
        )
    return ScanResult(findings=findings, metadata={"import_contract": {"raw_free_asserted": True, "raw_metadata_returned": False}}).finalize()


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    blocking_targets = 0
    coverage_gap_targets = 0
    for row in rows:
        kind_counts[str(row.get("kind", "unknown"))] += 1
        status_counts[str(row.get("status", "unknown"))] += 1
        for severity, count in row.get("summary", {}).items():
            severity_counts[severity] += int(count)
        if not row.get("gate", {}).get("passed", True):
            blocking_targets += 1
        if row.get("coverage", {}).get("coverage_gap"):
            coverage_gap_targets += 1
    return {
        "target_count": len(rows),
        "blocking_target_count": blocking_targets,
        "coverage_gap_target_count": coverage_gap_targets,
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in ("critical", "high", "medium", "low", "info")},
        "kind_counts": dict(sorted(kind_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
    }


def _intent_contract(rows: list[dict[str, Any]]) -> dict[str, Any]:
    target_count = len(rows)
    business_present = 0
    business_explicit = 0
    data_class_present = 0
    user_scope_present = 0
    scope_assertion_present = 0
    for row in rows:
        business = row.get("business_context", {}) if isinstance(row.get("business_context"), dict) else {}
        scope = row.get("scope_contract", {}) if isinstance(row.get("scope_contract"), dict) else {}
        if business.get("purpose_present"):
            business_present += 1
        if business.get("purpose_explicit"):
            business_explicit += 1
        if business.get("data_classes") or int(business.get("custom_data_class_count", 0)):
            data_class_present += 1
        if business.get("user_scope_present"):
            user_scope_present += 1
        if scope.get("assertion_present"):
            scope_assertion_present += 1
    return {
        "business_intent_assertion_source": "guardian_manifest",
        "human_business_intent_understanding_claimed": False,
        "scope_assertion_boundary": "external assertion; K-Guard stores only raw-free refs and does not prove ownership/partner status by itself",
        "target_count": target_count,
        "business_purpose_present_count": business_present,
        "business_purpose_explicit_count": business_explicit,
        "data_class_present_count": data_class_present,
        "user_scope_present_count": user_scope_present,
        "scope_assertion_present_count": scope_assertion_present,
        "business_purpose_complete": target_count == 0 or business_present == target_count,
        "business_purpose_explicit_complete": target_count == 0 or business_explicit == target_count,
        "data_class_complete": target_count == 0 or data_class_present == target_count,
        "user_scope_complete": target_count == 0 or user_scope_present == target_count,
        "scope_assertion_complete": target_count == 0 or scope_assertion_present == target_count,
        "raw_returned": False,
    }


def _review_contract(rows: list[dict[str, Any]], intent_contract: dict[str, Any], *, release_gate_enabled: bool) -> dict[str, Any]:
    profiles = sorted({str(row.get("audit_profile") or "standard").lower() for row in rows}) or ["standard"]
    supported_profiles = {"standard", "korean_senior"}
    profile_supported = len(profiles) == 1 and profiles[0] in supported_profiles
    profile = profiles[0] if profile_supported else "invalid_or_mixed"
    strict = profile == "korean_senior"
    declared_app_ids = [str(row.get("app_id") or "").strip() for row in rows]
    app_ids = sorted({app_id for app_id in declared_app_ids if app_id})
    app_id_complete = bool(rows) and all(declared_app_ids)
    single_app_scope = app_id_complete and len(app_ids) == 1
    authority_app_id = app_ids[0] if single_app_scope else ""
    scoped_rows = rows if not strict or single_app_scope else []
    completed = [row for row in scoped_rows if row.get("status") == "completed"]
    workspace_candidates = [row for row in completed if row.get("kind") == "workspace" and _review_source_kind(row) == "workspace"]
    workspaces = [row for row in workspace_candidates if _workspace_review_is_substantive(row)]
    http_candidates = [row for row in scoped_rows if row.get("kind") == "http" and _review_source_kind(row) == "http"]
    http_rows = [
        row
        for row in http_candidates
        if row.get("status") == "completed" and _http_probe_completed_without_errors(row)
    ]
    deep_http = [row for row in http_rows if row.get("requested_review", {}).get("deep_active")]
    flow_workspaces = [
        row
        for row in workspaces
        if row.get("requested_review", {}).get("flow_analysis")
        and row.get("review_evidence", {}).get("review_coverage", {}).get("flow_analysis_executed") is True
    ]
    invalid_endpoint_count = sum(int(row.get("requested_review", {}).get("invalid_public_endpoint_count", 0)) for row in scoped_rows)
    valid_endpoint_count = sum(int(row.get("requested_review", {}).get("valid_public_endpoint_count", 0)) for row in http_rows)
    intent_ready = all(
        intent_contract.get(key) is True
        for key in (
            "business_purpose_explicit_complete",
            "data_class_complete",
            "user_scope_complete",
            "scope_assertion_complete",
        )
    )
    domains = {
        "site_security": _review_domain(
            bool(workspaces and deep_http),
            ["completed workspace static review", "completed deep HTTP GET/OPTIONS review"],
            [] if workspaces and deep_http else _missing_parts(("workspace_static", bool(workspaces)), ("deep_http", bool(deep_http))),
        ),
        "api_exposure": _review_domain(
            bool(workspaces and http_rows and valid_endpoint_count > 0 and invalid_endpoint_count == 0),
            ["completed route/data-flow review", "completed HTTP API exposure review", "valid declared endpoint paths"],
            _missing_parts(
                ("workspace_api_review", bool(workspaces)),
                ("http_api_review", bool(http_rows)),
                ("declared_endpoint_scope", valid_endpoint_count > 0),
                ("valid_declared_endpoints", invalid_endpoint_count == 0),
            ),
        ),
        "data_management": _review_domain(
            bool(workspaces and intent_ready),
            ["Korean PII and high-impact field review", "retention/erasure and local-storage review", "explicit purpose/data/user/scope assertions"],
            _missing_parts(("workspace_data_review", bool(workspaces)), ("explicit_intent_scope_contract", intent_ready)),
        ),
        "operational_risk": _review_domain(
            bool(workspaces and flow_workspaces),
            ["dependency/CI/test/rate-limit evidence review", "static data-flow analysis executed"],
            _missing_parts(("workspace_operational_review", bool(workspaces)), ("flow_analysis", bool(flow_workspaces))),
        ),
    }
    missing_domains = [name for name, domain in domains.items() if not domain["passed"]]
    base_ready = bool(rows) and bool(completed) and profile_supported
    domain_ready = not missing_domains
    if release_gate_enabled:
        passed = base_ready and strict and single_app_scope and domain_ready
    else:
        passed = base_ready and (not strict or (single_app_scope and domain_ready))
    canonical_release_authority = release_gate_enabled and passed and strict and single_app_scope
    return {
        "profile": profile,
        "profile_values": profiles,
        "profile_supported": profile_supported,
        "strict_domain_enforcement": strict,
        "release_gate_enabled": release_gate_enabled,
        "canonical_release_authority": canonical_release_authority,
        "release_authority": "canonical" if canonical_release_authority else "none",
        "report_only": not canonical_release_authority,
        "app_id": authority_app_id,
        "app_id_ref": _raw_free_ref(authority_app_id, "app_id") if authority_app_id else {},
        "app_id_values": app_ids,
        "app_id_present_count": sum(1 for app_id in declared_app_ids if app_id),
        "app_id_complete": app_id_complete,
        "single_app_scope": single_app_scope,
        "app_scope_enforced": strict,
        "passed": passed,
        "coverage_grade": "korean_senior_gate_ready" if canonical_release_authority else ("report_ready" if passed else "incomplete"),
        "target_count": len(rows),
        "completed_target_count": len(completed),
        "workspace_review_count": len(workspaces),
        "workspace_attempted_count": len(workspace_candidates),
        "workspace_empty_or_unsupported_count": len(workspace_candidates) - len(workspaces),
        "http_review_count": len(http_rows),
        "http_attempted_count": len(http_candidates),
        "http_failed_execution_count": len(http_candidates) - len(http_rows),
        "deep_http_review_count": len(deep_http),
        "flow_review_count": len(flow_workspaces),
        "invalid_public_endpoint_count": invalid_endpoint_count,
        "valid_public_endpoint_count": valid_endpoint_count,
        "domains": domains,
        "missing_review_domains": missing_domains,
        "human_business_intent_or_legal_compliance_claimed": False,
        "claim_boundary": "Automated pre-release senior-auditor profile with fail-closed coverage evidence; not a human intent, legal-compliance, or exploit-proof guarantee.",
        "raw_returned": False,
    }


def _review_source_kind(row: dict[str, Any]) -> str:
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    coverage = evidence.get("review_coverage", {}) if isinstance(evidence.get("review_coverage"), dict) else {}
    return str(coverage.get("source_kind") or "")


def _http_probe_completed_without_errors(row: dict[str, Any]) -> bool:
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    contract = evidence.get("dynamic_probe_contract", {}) if isinstance(evidence.get("dynamic_probe_contract"), dict) else {}
    request_count = int(contract.get("request_count", 0))
    error_count = int(contract.get("error_request_count", request_count))
    required_count = int(contract.get("required_path_count", 0))
    required_reached = int(contract.get("required_path_reached_count", 0))
    return request_count > 0 and error_count == 0 and required_count > 0 and required_reached == required_count


def _workspace_review_is_substantive(row: dict[str, Any]) -> bool:
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    coverage = evidence.get("review_coverage", {}) if isinstance(evidence.get("review_coverage"), dict) else {}
    inventory = coverage.get("inventory", {}) if isinstance(coverage.get("inventory"), dict) else {}
    reviewed_candidate_count = int(
        inventory.get("reviewed_candidate_count", inventory.get("scanned_text_file_count", 0))
    )
    consistency = evidence.get("source_tree_consistency", {}) if isinstance(evidence.get("source_tree_consistency"), dict) else {}
    scan_inventory = evidence.get("scan_inventory_consistency", {}) if isinstance(evidence.get("scan_inventory_consistency"), dict) else {}
    return (
        consistency.get("matched") is True
        and consistency.get("raw_returned") is False
        and scan_inventory.get("matched") is True
        and scan_inventory.get("raw_returned") is False
        and reviewed_candidate_count > 0
        and reviewed_candidate_count == int(inventory.get("supported_file_count", -1))
        and int(inventory.get("unscanned_candidate_count", -1)) == 0
        and int(inventory.get("production_source_file_count", 0)) > 0
        and int(inventory.get("scanned_production_source_file_count", 0)) > 0
        and int(inventory.get("substantive_production_source_file_count", 0)) > 0
    )


def _review_domain(passed: bool, evidence: list[str], missing: list[str]) -> dict[str, Any]:
    return {"passed": passed, "evidence": evidence, "missing": missing, "raw_returned": False}


def _missing_parts(*items: tuple[str, bool]) -> list[str]:
    return [name for name, present in items if not present]


def _execution_contract(rows: list[dict[str, Any]], run_probes: bool, release_gate_enabled: bool, baseline: dict[str, Any]) -> dict[str, Any]:
    http_rows = [row for row in rows if row.get("kind") == "http"]
    skipped = [row for row in rows if str(row.get("status", "")).startswith("skipped")]
    errors = [row for row in rows if row.get("status") == "error"]
    coverage_gaps = [row for row in rows if row.get("coverage", {}).get("coverage_gap")]
    if not http_rows:
        dynamic_execution = "no_http_targets"
    elif run_probes and not any(row.get("coverage", {}).get("coverage_gap") for row in http_rows):
        dynamic_execution = "executed"
    elif run_probes:
        dynamic_execution = "attempted_with_gaps"
    elif release_gate_enabled:
        dynamic_execution = "required_but_not_requested"
    else:
        dynamic_execution = "not_requested"
    return {
        "mode": "release_gate" if release_gate_enabled else "report",
        "run_probes": run_probes,
        "http_target_count": len(http_rows),
        "http_executed_count": sum(1 for row in http_rows if row.get("status") == "completed"),
        "skipped_target_count": len(skipped),
        "error_target_count": len(errors),
        "coverage_gap_target_count": len(coverage_gaps),
        "authorized_dynamic_execution": dynamic_execution,
        "gate_requires_probe_execution": release_gate_enabled,
        "baseline_status": baseline.get("status", "initial_snapshot"),
        "baseline_policy": baseline.get("policy", ""),
        "depth": [
            "workspace scan",
            "HTTP GET/OPTIONS probe when run_probes is true",
            "bounded deep probe when manifest deep_active is true",
            "MCP runtime event review",
            "existing raw-free report drift comparison",
            "fix plan and verification suggestions",
        ],
    }


def _top_rules(findings: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    counts = Counter(str(finding.get("rule_id")) for finding in findings if finding.get("rule_id"))
    return [{"rule_id": rule, "count": count} for rule, count in counts.most_common(limit)]


def _fix_plan(findings: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id:
            grouped[rule_id].append(finding)
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
                "artifact_scope_counts": dict(
                    sorted(Counter(str(item.get("artifact_scope") or "workspace_evidence") for item in group).items())
                ),
                "direct_release_finding_count": sum(
                    1
                    for item in group
                    if str(item.get("artifact_scope") or "workspace_evidence")
                    in {"runtime_source", "configuration", "workspace_evidence"}
                ),
                "supporting_artifact_finding_count": sum(
                    1
                    for item in group
                    if str(item.get("artifact_scope") or "workspace_evidence")
                    not in {"runtime_source", "configuration", "workspace_evidence"}
                ),
                "impact": recipe.get("impact", ""),
                "fix_steps": recipe.get("fix_steps", []),
                "test_suggestions": recipe.get("test_suggestions", []),
                "verification": recipe.get("verification", ""),
            }
        )
    items.sort(key=lambda item: (severity_rank(str(item["max_severity"])), -int(item["affected_findings"]), str(item["rule_id"])))
    return items[:limit]


def _fixes_for_findings(findings: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    return _fix_plan(findings, limit=limit)


def _baseline_contract(previous: dict[str, Any] | None, previous_report_path: str | Path | None, release_gate_enabled: bool) -> dict[str, Any]:
    requested = bool(str(previous_report_path or "").strip())
    if previous is not None:
        status = "comparison_loaded"
        policy = "A previous guardian report is loaded; drift counts show new and resolved findings relative to that report."
    elif requested:
        status = "previous_report_missing"
        policy = "The requested previous report was not loaded; current findings are evaluated by target gates, but drift new/resolved counts are not inferred."
    else:
        status = "initial_snapshot"
        policy = "No previous guardian report was provided; this run establishes the initial baseline and does not label every current finding as new drift."
    return {
        "status": status,
        "previous_report_requested": requested,
        "previous_loaded": previous is not None,
        "release_gate_enabled": release_gate_enabled,
        "policy": policy,
        "gate_policy": "Release gates evaluate current blockers and coverage gaps even on the first run; drift is used only when a previous report is loaded.",
    }


def _drift_summary(previous: dict[str, Any] | None, rows: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any]:
    if previous is None:
        return {
            "previous_loaded": False,
            "baseline_status": baseline.get("status", "initial_snapshot"),
            "comparison_available": False,
            "new_finding_count": 0,
            "resolved_finding_count": 0,
            "new_blocking_finding_count": 0,
            "new_blocking_findings": [],
            "policy": baseline.get("policy", ""),
        }
    current = _finding_keys(rows)
    old = _finding_keys(previous.get("targets", [])) if previous else set()
    new_keys = sorted(current - old)
    resolved_keys = sorted(old - current)
    new_blocking = [item for item in _finding_key_records(rows) if item["key"] in new_keys and item["blocking"]]
    return {
        "previous_loaded": previous is not None,
        "baseline_status": baseline.get("status", "comparison_loaded"),
        "comparison_available": True,
        "new_finding_count": len(new_keys),
        "resolved_finding_count": len(resolved_keys),
        "new_blocking_finding_count": len(new_blocking),
        "new_blocking_findings": [{key: value for key, value in item.items() if key != "key"} for item in new_blocking[:50]],
    }


def _finding_keys(rows: list[dict[str, Any]]) -> set[str]:
    return {item["key"] for item in _finding_key_records(rows)}


def _finding_key_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for row in rows:
        fail_on = str(row.get("fail_on") or "high")
        for finding in row.get("findings", []):
            if not isinstance(finding, dict):
                continue
            location = str(finding.get("file") or finding.get("url") or "target")
            key = "|".join(
                [
                    str(row.get("target_id", "")),
                    str(finding.get("rule_id", "")),
                    str(finding.get("source", "")),
                    location,
                    str(finding.get("line_start") or ""),
                    str(finding.get("method") or ""),
                    str(finding.get("status") or ""),
                ]
            )
            severity = str(finding.get("severity") or "info")
            records.append(
                {
                    "key": key,
                    "drift_key": key,
                    "target_id": row.get("target_id"),
                    "rule_id": finding.get("rule_id"),
                    "severity": severity,
                    "source": finding.get("source"),
                    "location": location,
                    "line_start": finding.get("line_start"),
                    "method": finding.get("method"),
                    "status": finding.get("status"),
                    "blocking": is_release_blocking_finding(finding, fail_on),
                }
            )
    return records


def _load_previous(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    previous = Path(path)
    if not previous.exists():
        return None
    return json.loads(previous.read_text(encoding="utf-8"))


def _resolve_locator(manifest_dir: Path, locator: str) -> str:
    if not locator:
        return str(manifest_dir)
    parsed = urllib.parse.urlparse(locator)
    if parsed.scheme in {"http", "https"}:
        return locator
    path = Path(locator)
    if path.is_absolute():
        return str(path)
    return str((manifest_dir / path).resolve())


def _allowed_hosts_for_target(url: str) -> set[str]:
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    allowed = set(ALLOWED_HOSTS)
    if parsed.hostname:
        allowed.add(parsed.hostname.strip("[]").lower())
    return allowed


def _external_http_target(url: str) -> bool:
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").strip("[]").lower()
    return bool(host and not _allowed_host(host, ALLOWED_HOSTS))


def _normalize_finding_locations(item: dict[str, Any], manifest_dir: Path, target_id: str, target_locator: str) -> None:
    target_base = _target_base_path(manifest_dir, target_locator)
    if item.get("file"):
        item["file"] = _safe_path(item["file"], target_base or manifest_dir, target_id, str(item.get("file") or ""))
    if item.get("url"):
        item["url"] = _safe_url(str(item["url"]))


def _target_base_path(manifest_dir: Path, target_locator: str) -> Path | None:
    parsed = urllib.parse.urlparse(target_locator)
    if parsed.scheme in {"http", "https"}:
        return None
    return Path(_resolve_locator(manifest_dir, target_locator))


def _safe_path(path: str | Path, base_dir: Path, label: str, fallback: str) -> str:
    text = str(path or fallback or "").strip()
    if not text:
        return fallback or label
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme in {"http", "https"}:
        return _safe_url(text)
    candidate = Path(text)
    try:
        resolved = candidate.resolve()
        base = base_dir.resolve()
        try:
            return str(resolved.relative_to(base)).replace("\\", "/")
        except ValueError:
            return f"{label}:{resolved.name}" if resolved.name else label
    except Exception:
        return f"{label}:{candidate.name}" if candidate.name else (fallback or label)


def _safe_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").strip("[]").lower()
    if not host:
        return "unknown-url"
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme or "https", f"{host}{port}", path, "", "", ""))


def _load_session_headers(
    manifest_dir: Path,
    session_file: str,
    target_url: str,
) -> SessionMaterial | None:
    if not session_file:
        return None
    return load_session_material(
        session_file,
        base_dir=manifest_dir,
        target_url=target_url,
    )


def _truthy(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _severity_at_or_above(severity: str, threshold: str) -> bool:
    return severity_rank(severity) <= severity_rank(threshold)
