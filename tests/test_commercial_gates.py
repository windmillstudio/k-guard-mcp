import csv
import contextlib
import hashlib
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from k_guard_mcp.data_release import (
    _field_thresholds_are_strict,
    _validation_checks,
    run_data_release_gate as _run_data_release_gate,
)
from k_guard_mcp.cli import main as cli_main
from k_guard_mcp.experience import apply_guardian_experience
from k_guard_mcp.field_campaign import FIELD_APP_ROSTER_FIELDS
from k_guard_mcp.field_validation import FIELD_REVIEW_FIELDS, GROUND_TRUTH_FIELDS, run_field_validation, sign_field_validation_inputs, write_field_preregistration
from k_guard_mcp.guardian import GUARDIAN_MANIFEST_FIELDS, build_guardian_execution_attestation, guardian_toolchain_contract, refresh_guardian_evidence_bundle
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.models import Finding, ScanResult
from k_guard_mcp.provenance import source_tree_snapshot
from k_guard_mcp.reports import to_json, to_markdown
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.scoreboard import evaluate_fixture_corpus
from k_guard_mcp.suppression import (
    SUPPRESSION_FIELDS,
    _guardian_row_suppression_binding,
    apply_suppressions_to_guardian_report,
    finding_fingerprint as suppression_fingerprint,
)
from k_guard_mcp.validation import finding_fingerprint, run_validation_review


FIXTURES = Path(__file__).parent / "fixtures"
ADVERSARIAL_CORPUS = json.loads((FIXTURES / "adversarial_redaction_corpus.json").read_text(encoding="utf-8"))
KOREAN_CORPUS_PATH = FIXTURES / "korean_fixture_corpus.json"
KOREAN_CORPUS = json.loads(KOREAN_CORPUS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def _release_operator_key(monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "test-release-operator-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    monkeypatch.setenv(
        "K_GUARD_FIELD_REVIEWER_HMAC_KEYS",
        json.dumps(
            {
                "reviewer-a": "commercial-reviewer-a-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "reviewer-b": "commercial-reviewer-b-key-9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBA",
            }
        ),
    )
    monkeypatch.setenv("K_GUARD_FIELD_CUSTODIAN_HMAC_KEY", "commercial-custodian-key-2468013579-QWERTYUIOPASDFGHJKL")


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _guardian_manifest_for(report_path: Path) -> Path:
    return report_path.with_suffix(".manifest.csv")


def run_data_release_gate(*args, **kwargs):
    if args and "guardian_manifest_path" not in kwargs:
        kwargs["guardian_manifest_path"] = _guardian_manifest_for(Path(args[0]))
    if len(args) > 1 and "validation_review_path" not in kwargs:
        kwargs["validation_review_path"] = Path(args[1]).with_suffix(".review.csv")
    if len(args) > 1 and "validation_repeat_guardian_report_path" not in kwargs:
        kwargs["validation_repeat_guardian_report_path"] = Path(args[1]).with_suffix(".repeat-guardian.json")
    if len(args) > 1 and "validation_ground_truth_path" not in kwargs:
        kwargs["validation_ground_truth_path"] = Path(args[1]).with_suffix(".ground-truth.csv")
    if len(args) > 1 and "validation_preregistration_path" not in kwargs:
        kwargs["validation_preregistration_path"] = Path(args[1]).with_suffix(".preregistration.json")
    if len(args) > 1 and "validation_roster_path" not in kwargs:
        kwargs["validation_roster_path"] = Path(args[1]).with_suffix(".roster.csv")
    return _run_data_release_gate(*args, **kwargs)


def _path_ref(path: Path) -> dict:
    return {"hash": evidence_hash(str(path)), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _content_ref(path: Path) -> dict:
    return {"hash": evidence_hash(path.read_text(encoding="utf-8")), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _bundle_ref(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    bundle = data.get("evidence_bundle", {}) if isinstance(data, dict) else {}
    signature = bundle.get("signature", {}) if isinstance(bundle.get("signature"), dict) else {}
    return {
        "bundle_sha256": str(bundle.get("bundle_sha256") or ""),
        "signature_sha256_hash": evidence_hash(str(signature.get("signature_sha256") or "")),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _intent_contract(target_count: int) -> dict:
    return {
        "business_intent_assertion_source": "guardian_manifest",
        "human_business_intent_understanding_claimed": False,
        "scope_assertion_boundary": "external assertion; K-Guard stores only raw-free refs and does not prove ownership/partner status by itself",
        "target_count": target_count,
        "business_purpose_present_count": target_count,
        "business_purpose_explicit_count": target_count,
        "data_class_present_count": target_count,
        "user_scope_present_count": target_count,
        "scope_assertion_present_count": target_count,
        "business_purpose_complete": True,
        "business_purpose_explicit_complete": True,
        "data_class_complete": True,
        "user_scope_complete": True,
        "scope_assertion_complete": True,
        "raw_returned": False,
    }


def _review_contract(workspace_count: int, total_count: int) -> dict:
    return {
        "profile": "korean_senior",
        "profile_values": ["korean_senior"],
        "profile_supported": True,
        "strict_domain_enforcement": True,
        "release_gate_enabled": True,
        "canonical_release_authority": True,
        "release_authority": "canonical",
        "report_only": False,
        "app_id": "primary-app",
        "app_id_values": ["primary-app"],
        "app_id_present_count": total_count,
        "app_id_complete": True,
        "single_app_scope": True,
        "app_scope_enforced": True,
        "passed": True,
        "domains": {
            name: {"passed": True, "missing": [], "raw_returned": False}
            for name in ("site_security", "api_exposure", "data_management", "operational_risk")
        },
        "missing_review_domains": [],
        "completed_target_count": total_count,
        "workspace_review_count": workspace_count,
        "http_review_count": 1,
        "deep_http_review_count": 1,
        "flow_review_count": workspace_count,
        "valid_public_endpoint_count": 1,
        "invalid_public_endpoint_count": 0,
        "human_business_intent_or_legal_compliance_claimed": False,
        "raw_returned": False,
    }


def _target_contract(target_id: str) -> dict:
    return {
        "app_id": "primary-app",
        "target_id": target_id,
        "kind": "workspace",
        "status": "completed",
        "audit_profile": "korean_senior",
        "fail_on": "high",
        "gate": {"passed": True},
        "coverage": {"executed": True, "coverage_gap": False, "status": "completed"},
        "requested_review": {
            "flow_analysis": True,
            "deep_active": False,
            "valid_public_endpoint_count": 0,
            "invalid_public_endpoint_count": 0,
        },
        "review_evidence": {
            "source_tree_snapshot": {
                "schema": "k_guard_source_tree_snapshot.v1",
                "tree_sha256": hashlib.sha256(f"source:{target_id}".encode()).hexdigest(),
                "complete": True,
                "raw_returned": False,
            },
            "source_tree_consistency": {"matched": True, "raw_returned": False},
            "scan_inventory_consistency": {
                "matched": True,
                "before_candidate_count": 1,
                "after_candidate_count": 1,
                "scanner_candidate_count": 1,
                "scanned_text_file_count": 1,
                "unscanned_candidate_count": 0,
                "before_candidate_path_set_sha256": hashlib.sha256(f"candidate:{target_id}".encode()).hexdigest(),
                "after_candidate_path_set_sha256": hashlib.sha256(f"candidate:{target_id}".encode()).hexdigest(),
                "scanner_candidate_path_set_sha256": hashlib.sha256(f"candidate:{target_id}".encode()).hexdigest(),
                "raw_returned": False,
            },
            "review_coverage": {
                "source_kind": "workspace",
                "flow_analysis_executed": True,
                "inventory": {"supported_file_count": 1, "scanned_text_file_count": 1, "unscanned_candidate_count": 0, "candidate_set_complete": True, "candidate_path_set_sha256": hashlib.sha256(f"candidate:{target_id}".encode()).hexdigest(), "production_source_file_count": 1, "scanned_production_source_file_count": 1, "substantive_production_source_file_count": 1, "raw_returned": False},
                "raw_returned": False,
            }
        },
        "business_context": {
            "purpose_present": True,
            "purpose_explicit": True,
            "purpose_ref": {"hash": evidence_hash(f"purpose:{target_id}"), "hash_scheme": evidence_hash_scheme(), "raw_returned": False},
            "data_classes": ["personal_data"],
            "custom_data_class_count": 0,
            "user_scope_present": True,
            "user_scope_ref": {"hash": evidence_hash(f"scope:{target_id}"), "hash_scheme": evidence_hash_scheme(), "raw_returned": False},
            "raw_returned": False,
        },
        "scope_contract": {
            "assertion_boundary": "external_scope_assertion_ref",
            "basis": "local_workspace",
            "assertion_present": True,
            "assertion_ref": {"hash": evidence_hash(f"proof:{target_id}"), "hash_scheme": evidence_hash_scheme(), "raw_returned": False},
            "ownership_or_partner_scope_verified_by_k_guard": False,
            "raw_returned": False,
        },
    }


def _http_target_contract(target_id: str = "release-http") -> dict:
    target = _target_contract(target_id)
    target.update(
        {
            "kind": "http",
            "requested_review": {
                "flow_analysis": False,
                "deep_active": True,
                "valid_public_endpoint_count": 1,
                "invalid_public_endpoint_count": 0,
            },
            "review_evidence": {
                "review_coverage": {"source_kind": "http", "raw_returned": False},
                "dynamic_probe_contract": {
                    "request_count": 2,
                    "error_request_count": 0,
                    "required_path_count": 1,
                    "required_path_reached_count": 1,
                    "required_path_refs": [evidence_hash("/")],
                    "required_path_reached_refs": [evidence_hash("/")],
                    "methods": ["GET", "OPTIONS"],
                    "raw_returned": False,
                },
            },
        }
    )
    return target


def _guardian_release_report(path: Path, target_ids: list[str] | None = None) -> Path:
    target_ids = target_ids or [f"app-{index:02d}" for index in range(1, 6)]
    targets = []
    manifest_rows = []
    for target_id in target_ids:
        workspace = path.parent / f"{path.stem}-{target_id}"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "app.py").write_text("def release_source():\n    return 'ok'\n", encoding="utf-8")
        target = _target_contract(target_id)
        target["review_evidence"]["source_tree_snapshot"] = source_tree_snapshot(workspace)
        target.update({"findings": [], "rule_ids": []})
        targets.append(target)
        manifest_rows.append(
            {
                "app_id": "primary-app",
                "target_id": target_id,
                "kind": "workspace",
                "locator": workspace.name,
                "authorized": "true",
                "authorization_note": "local",
                "include_flow": "true",
                "fail_on": "high",
                "owner": "team",
                "business_purpose": "release review",
                "data_classes": "personal_data",
                "user_scope": "owned users",
                "scope_basis": "local_workspace",
                "scope_proof_ref": "assertion",
                "audit_profile": "korean_senior",
            }
        )
    http_target = _http_target_contract()
    http_target.update({"findings": [], "rule_ids": []})
    targets.append(http_target)
    manifest_rows.append(
        {
            "app_id": "primary-app",
            "target_id": "release-http",
            "kind": "http",
            "locator": "http://127.0.0.1:1",
            "authorized": "true",
            "authorization_note": "local",
            "deep_active": "true",
            "fail_on": "high",
            "owner": "team",
            "business_purpose": "runtime review",
            "data_classes": "runtime_response",
            "user_scope": "owned users",
            "public_endpoints": "/",
            "scope_basis": "local_http",
            "scope_proof_ref": "assertion",
            "audit_profile": "korean_senior",
        }
    )
    manifest = _guardian_manifest_for(path)
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GUARDIAN_MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(manifest_rows)
    intent = _intent_contract(len(targets))
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "execution_id": "e" * 32,
        "method": "guardian_audit",
        "toolchain_contract": guardian_toolchain_contract(),
        "raw_free": True,
        "baseline": {},
        "summary": {"blocking_target_count": 0, "coverage_gap_target_count": 0},
        "drift": {"new_blocking_finding_count": 0},
        "execution_contract": {"mode": "release_gate"},
        "intent_contract": intent,
        "review_contract": _review_contract(len(target_ids), len(targets)),
        "release_qualification": {
            "schema": "k_guard_release_qualification.v1",
            "passed": True,
            "canonical_release_prerequisite": True,
            "fail_closed": True,
            "gates": {
                "deep_multilang": {"passed": True, "checks": [], "failed_checks": [], "raw_free": True},
                "software_composition": {"passed": True, "checks": [], "failed_checks": [], "raw_free": True},
                "streamable_http_runtime": {"passed": True, "checks": [], "failed_checks": [], "raw_free": True},
                "agent_database_controls": {"passed": True, "checks": [], "failed_checks": [], "raw_free": True},
                "field_accuracy": {"passed": True, "checks": [], "failed_checks": [], "raw_free": True},
            },
            "missing_inputs": [],
            "raw_free": True,
        },
        "guardian_gate": {
            "enabled": True,
            "evaluation_passed": True,
            "passed": True,
            "fail_on": "high",
            "blocking_target_count": 0,
            "new_blocking_finding_count": 0,
            "review_contract_passed": True,
            "review_profile": "korean_senior",
            "missing_review_domains": [],
            "release_qualification_passed": True,
            "failed_qualification_gates": [],
        },
        "top_rules": [],
        "targets": targets,
    }
    payload["execution_attestation"] = build_guardian_execution_attestation(
        payload["execution_id"], payload["generated_at"], payload["generated_at"], targets
    )
    refresh_guardian_evidence_bundle(payload, manifest)
    return _write_json(
        path,
        payload,
    )


def _validation_source_findings(target_ids: list[str]) -> list[dict]:
    total = 80 if len(target_ids) >= 12 else len(target_ids)
    findings = []
    for index in range(1, total + 1):
        target_id = target_ids[(index - 1) % len(target_ids)]
        findings.append(
            {
                "target_id": target_id,
                "rule_id": f"FIELD_ROUTE_RISK_{index:03d}",
                "source": "js-ts-framework",
                "severity": "critical" if index <= 5 else "high",
                "file": f"src/field_case_{index:03d}.ts",
                "line_start": index,
                "line_end": index,
                "evidence": f"detector_subtype=field_route_risk case_ref={index:03d} raw_returned=false",
            }
        )
    return findings


def _validation_source_guardian_report(path: Path, target_ids: list[str] | None = None) -> Path:
    target_ids = target_ids or [f"app-{index:02d}" for index in range(1, 13)]
    findings = _validation_source_findings(target_ids)
    intent = _intent_contract(len(target_ids))
    targets = []
    by_target = {target_id: [] for target_id in target_ids}
    for finding in findings:
        by_target[finding["target_id"]].append(finding)
    for index, target_id in enumerate(target_ids, start=1):
        target = _target_contract(target_id)
        target["app_id"] = f"partner-{index:02d}"
        target.update({"findings": by_target[target_id], "rule_ids": [finding["rule_id"] for finding in by_target[target_id]]})
        targets.append(target)
    generated_at = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()
    payload = {
        "generated_at": generated_at,
        "execution_id": "c" * 32,
        "method": "guardian_audit",
        "toolchain_contract": guardian_toolchain_contract(),
        "raw_free": True,
        "baseline": {},
        "summary": {"target_count": len(targets), "blocking_target_count": len(target_ids), "coverage_gap_target_count": 0},
        "drift": {"new_blocking_finding_count": 0},
        "execution_contract": {"mode": "report", "skipped_target_count": 0, "error_target_count": 0, "coverage_gap_target_count": 0},
        "intent_contract": intent,
        "top_rules": [{"rule_id": "FIELD_ROUTE_RISK", "count": len(findings)}],
        "targets": targets,
    }
    payload["execution_attestation"] = build_guardian_execution_attestation(
        payload["execution_id"], payload["generated_at"], payload["generated_at"], targets
    )
    manifest = path.with_suffix(".manifest.csv")
    manifest.write_text("app_id,target_id,kind\nfixture,fixture,workspace\n", encoding="utf-8")
    refresh_guardian_evidence_bundle(payload, manifest)
    return _write_json(
        path,
        payload,
    )


def _ready_validation_report(path: Path, source_guardian: Path, target_ids: list[str] | None = None, true_positive: int = 80, false_positive: int = 0) -> Path:
    target_ids = target_ids or [f"app-{index:02d}" for index in range(1, 13)]
    findings = _validation_source_findings(target_ids)
    assert true_positive + false_positive == len(findings)
    review = path.with_suffix(".review.csv")
    with review.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        for index, finding in enumerate(findings):
            target_index = target_ids.index(finding["target_id"]) + 1
            verdict = "true_positive" if index < true_positive else "false_positive"
            writer.writerow(
                {
                    "app_id": f"partner-{target_index:02d}",
                    "target_id": finding["target_id"],
                    "rule_id": finding["rule_id"],
                    "finding_fingerprint": finding_fingerprint(finding),
                    "reviewer_1": "reviewer-a",
                    "verdict_1": verdict,
                    "reviewer_2": "reviewer-b",
                    "verdict_2": verdict,
                    "adjudicator": "",
                    "final_verdict": verdict,
                    "notes": "manual raw-free review",
                }
            )
    ground_truth = path.with_suffix(".ground-truth.csv")
    with ground_truth.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        for index in range(1, 121):
            target_index = ((index - 1) % len(target_ids)) + 1
            target_id = target_ids[target_index - 1]
            vulnerable = index <= 80
            expected = "vulnerable" if vulnerable else "clean"
            writer.writerow(
                {
                    "app_id": f"partner-{target_index:02d}",
                    "target_id": target_id,
                    "case_id": f"field-case-{index:03d}",
                    "severity": "critical" if index <= 5 else "high",
                    "expected_outcome": expected,
                    "expected_rule_ids": f"FIELD_ROUTE_RISK_{index:03d}",
                    "file": f"src/field_case_{index:03d}.ts",
                    "line_start": index,
                    "line_end": index,
                    "stratum": ("top", "mid", "long_tail")[(target_index - 1) % 3],
                    "split": "holdout" if index <= 35 or index >= 81 else "development",
                    "source_kind": "owned_partner",
                    "source_ref": f"partner-scope-{target_index:02d}-case-{index:03d}",
                    "reproduction_count": 2,
                    "reviewer_1": "reviewer-a",
                    "verdict_1": expected,
                    "reviewer_2": "reviewer-b",
                    "verdict_2": expected,
                    "adjudicator": "",
                    "final_verdict": expected,
                    "notes": "manual raw-free ground truth",
                }
            )
    sign_field_validation_inputs(ground_truth_path=ground_truth, review_path=review)
    roster = path.with_suffix(".roster.csv")
    with roster.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_APP_ROSTER_FIELDS)
        writer.writeheader()
        for target_index, target_id in enumerate(target_ids, start=1):
            writer.writerow(
                {
                    "app_id": f"partner-{target_index:02d}",
                    "target_id": target_id,
                    "stratum": ("top", "mid", "long_tail")[(target_index - 1) % 3],
                    "source_revision": f"{target_index:040x}",
                    "scope_basis": "partner",
                    "scope_assertion_ref": f"commercial-scope-ticket-{target_index:02d}",
                    "recruitment_status": "accepted",
                    "authorization_status": "approved",
                    "scan_consent": "true",
                    "aggregate_consent": "true",
                }
            )
    preregistration = path.with_suffix(".preregistration.json")
    write_field_preregistration(
        ground_truth,
        preregistration,
        custodian_id="commercial-custodian",
        roster_path=roster,
    )
    source_payload = json.loads(source_guardian.read_text(encoding="utf-8"))
    source_payload["generated_at"] = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    source_payload["execution_id"] = "c" * 32
    source_payload["execution_attestation"] = build_guardian_execution_attestation(
        source_payload["execution_id"],
        source_payload["generated_at"],
        source_payload["generated_at"],
        source_payload["targets"],
    )
    source_manifest = source_guardian.with_suffix(".manifest.csv")
    if not source_manifest.is_file():
        source_manifest.write_text("app_id,target_id,kind\nfixture,fixture,workspace\n", encoding="utf-8")
    refresh_guardian_evidence_bundle(source_payload, source_manifest)
    _write_json(source_guardian, source_payload)
    repeat = path.with_suffix(".repeat-guardian.json")
    repeat_payload = dict(source_payload)
    repeat_payload["generated_at"] = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
    repeat_payload["execution_id"] = "d" * 32
    repeat_payload["execution_attestation"] = build_guardian_execution_attestation(
        repeat_payload["execution_id"],
        repeat_payload["generated_at"],
        repeat_payload["generated_at"],
        repeat_payload["targets"],
    )
    repeat_manifest = repeat.with_suffix(".manifest.csv")
    repeat_manifest.write_text(source_manifest.read_text(encoding="utf-8"), encoding="utf-8")
    refresh_guardian_evidence_bundle(repeat_payload, repeat_manifest)
    _write_json(repeat, repeat_payload)
    return _write_json(
        path,
        run_field_validation(
            source_guardian,
            repeat,
            ground_truth,
            review,
            preregistration_path=preregistration,
            roster_path=roster,
        ),
    )


def _korean_score_report(path: Path) -> Path:
    return _write_json(path, evaluate_fixture_corpus(KOREAN_CORPUS_PATH))


def _valid_mcp_intercept_pack(
    root: Path,
    event_count: int = 2,
    *,
    app_id: str = "primary-app",
    session_id: str = "release-session-01",
    guardian_path: Path | None = None,
) -> tuple[Path, Path]:
    guardian = guardian_path or root / "guardian.json"
    events_path = root / "mcp-events.jsonl"
    forwarded = root / "forwarded.jsonl"
    events = [
        {
            "event": "tool_call",
            "tool": "safe.read",
            "arguments": {"path": "README.md", "event_index": index},
        }
        for index in range(1, event_count + 1)
    ]
    events_path.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8")
    mcp = root / "mcp.json"
    with contextlib.redirect_stdout(io.StringIO()):
        exit_code = cli_main(
            [
                "mcp-intercept",
                "--events",
                str(events_path),
                "--forwarded-output",
                str(forwarded),
                "--report",
                str(mcp),
                "--app-id",
                app_id,
                "--session-id",
                session_id,
                "--guardian-report",
                str(guardian),
            ]
        )
    assert exit_code == 0
    return mcp, forwarded


def test_adversarial_redaction_corpus_has_at_least_30_cases():
    assert len(ADVERSARIAL_CORPUS) >= 30


@pytest.mark.parametrize("case", ADVERSARIAL_CORPUS, ids=[case["name"] for case in ADVERSARIAL_CORPUS])
def test_adversarial_redaction_case_never_reaches_serialized_outputs(case):
    result = ScanResult(
        findings=[
            Finding(
                id=f"case-{case['name']}",
                source="static",
                rule_id="RAW_CORPUS",
                severity="critical",
                confidence="high",
                title=f"raw corpus {case['name']}",
                evidence=case["raw"],
                why_it_matters=case["raw"],
                recommendation=case["raw"],
            )
        ]
    ).finalize()
    serialized = to_json(result) + "\n" + to_markdown(result)
    for forbidden in case["forbidden"]:
        assert forbidden not in serialized, case["name"]


@pytest.mark.parametrize("case", KOREAN_CORPUS["positives"], ids=[case["name"] for case in KOREAN_CORPUS["positives"]])
def test_korean_fixture_positive_case(case):
    result = KGuardScanner().scan_text(case["text"], case.get("file", "fixture.txt"))
    rules = {finding.rule_id for finding in result.findings}
    assert any(rule in rules for rule in case["expected_any"])


@pytest.mark.parametrize("case", KOREAN_CORPUS["negatives"], ids=[case["name"] for case in KOREAN_CORPUS["negatives"]])
def test_korean_fixture_negative_case(case):
    result = KGuardScanner().scan_text(case["text"], case.get("file", "negative.txt"))
    rules = {finding.rule_id for finding in result.findings}
    for absent in case.get("expected_absent", []):
        assert absent not in rules
    if "expected_absent" not in case:
        assert not rules


def test_korean_fixture_corpus_recall_and_false_positive_rate():
    report = evaluate_fixture_corpus(KOREAN_CORPUS_PATH)
    measurable = sum(1 for case in KOREAN_CORPUS["negatives"] if "expected_absent" not in case)
    targeted = sum(1 for case in KOREAN_CORPUS["negatives"] if "expected_absent" in case)
    assert report["positive_count"] == len(KOREAN_CORPUS["positives"])
    assert report["negative_count"] == len(KOREAN_CORPUS["negatives"])
    assert report["measurable_negative_count"] == measurable
    assert report["targeted_absence_case_count"] == targeted
    assert report["false_positive_rate_denominator"] == measurable
    assert report["false_positive_rate_denominator_name"] == "measurable_negative_count"
    assert report["thresholds"]["false_positive_rate_denominator"] == "measurable_negative_count"
    assert report["recall"] >= 0.95
    if measurable == 0:
        assert report["false_positive_rate"] == 0.0
    else:
        assert report["false_positive_rate"] <= 0.2
    assert report["passed"] is True


def test_synthetic_corpus_requires_org_registration_rules():
    report = evaluate_fixture_corpus(KOREAN_CORPUS_PATH)
    required_org = {"KR_ORG_BUSINESS_REGISTRATION", "KR_ORG_CORPORATE_REGISTRATION"}
    assert required_org.issubset(set(report["coverage"]["required_org_rules"]))
    missing = set(report["coverage"]["missing_required_rules"])
    assert required_org.isdisjoint(missing)
    assert report["coverage"]["all_required_rules_observed"] is True


def test_org_registration_coverage_fails_closed_when_missing(tmp_path):
    corpus_path = tmp_path / "no-org.json"
    corpus_path.write_text(
        json.dumps(
            {
                "positives": [{"name": "email", "text": "email=hong@example.com", "expected_any": ["PII_EMAIL"]}],
                "negatives": [{"name": "plain", "text": "hello world"}],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    report = evaluate_fixture_corpus(corpus_path)
    missing = set(report["coverage"]["missing_required_rules"])
    assert "KR_ORG_BUSINESS_REGISTRATION" in missing
    assert "KR_ORG_CORPORATE_REGISTRATION" in missing
    assert report["coverage"]["all_required_rules_observed"] is False


def test_scoreboard_fpr_zero_denominator_is_safe(tmp_path):
    corpus_path = tmp_path / "targeted-only.json"
    corpus_path.write_text(
        json.dumps(
            {
                "positives": [{"name": "email", "text": "email=hong@example.com", "expected_any": ["PII_EMAIL"]}],
                "negatives": [
                    {
                        "name": "targeted",
                        "text": "name: 홍길동 안내 페이지",
                        "expected_absent": ["KR_COMBO_PERSON_RRN"],
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    report = evaluate_fixture_corpus(corpus_path)
    assert report["negative_count"] == 1
    assert report["measurable_negative_count"] == 0
    assert report["targeted_absence_case_count"] == 1
    assert report["false_positive_rate_denominator"] == 0
    assert report["false_positive_rate"] == 0.0


def test_data_release_gate_requires_full_commercial_evidence_pack(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is True
    guardian_payload = json.loads(guardian.read_text(encoding="utf-8"))
    assert guardian_payload["guardian_gate"]["authority_blockers"] == []
    assert guardian_payload["guardian_gate"]["recommendation"].startswith("Canonical high-threshold")
    assert report["data_release_gate"]["blocking_check_count"] == 0
    assert report["evidence_bundle"]["schema"] == "k_guard_evidence_bundle.v1"
    artifacts = {
        (artifact.get("label"), artifact.get("role")): artifact
        for artifact in report["evidence_bundle"]["artifacts"]
    }
    assert artifacts[("validation_repeat_guardian_report", "repeat_input")]["content_sha256"]
    assert artifacts[("validation_ground_truth_csv", "ground_truth")]["content_sha256"]
    assert artifacts[("validation_preregistration", "preregistration")]["content_sha256"]
    assert artifacts[("korean_fixture_corpus", "ground_truth")]["content_sha256"]
    assert report["thresholds"]["max_validation_false_negative_count"] == 0
    assert report["thresholds"]["max_validation_benign_high_critical_candidate_count"] == 0
    passed_checks = {check["name"] for check in report["checks"] if check["passed"]}
    assert "guardian_evidence_bundle_present" in passed_checks
    assert "guardian_scope_assertion_refs_present" in passed_checks
    assert "validation_source_guardian_evidence_bundle_present" in passed_checks
    assert "validation_recomputed_from_originals" in passed_checks
    assert "validation_recomputed_projection_match" in passed_checks

    report_only_mcp = json.loads(mcp.read_text(encoding="utf-8"))
    del report_only_mcp["metadata"]["runtime_policy"]["interceptor"]["forwarded_output_ref"]
    mcp.write_text(json.dumps(report_only_mcp, ensure_ascii=False), encoding="utf-8")
    blocked = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert blocked["passed"] is False
    assert "mcp_interceptor_forwarded_stream_present" in {check["name"] for check in blocked["checks"] if not check["passed"]}


def test_data_release_separates_ninety_percent_point_precision_from_eighty_percent_wilson_floor(tmp_path):
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation_path = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["rates"]["precision"] = 0.89
    validation["rates_confidence_intervals"]["precision_95"]["lower"] = 0.81
    validation["holdout_candidate_rates"]["precision"] = 0.89
    validation["holdout_candidate_rates"]["precision_confidence_interval_95"]["lower"] = 0.81

    checks = []
    _validation_checks(validation, checks, 12, 20, 20, 0.20)
    by_name = {check["name"]: check for check in checks}

    assert by_name["validation_precision_floor"]["passed"] is False
    assert by_name["validation_precision_confidence_lower"]["passed"] is True
    assert by_name["validation_holdout_candidate_precision_floor"]["passed"] is False
    assert by_name["validation_holdout_candidate_precision_confidence_lower"]["passed"] is True

    validation["rates"]["precision"] = 0.91
    validation["rates_confidence_intervals"]["precision_95"]["lower"] = 0.79
    validation["holdout_candidate_rates"]["precision"] = 0.91
    validation["holdout_candidate_rates"]["precision_confidence_interval_95"]["lower"] = 0.79
    inverse_checks = []
    _validation_checks(validation, inverse_checks, 12, 20, 20, 0.20)
    inverse_by_name = {check["name"]: check for check in inverse_checks}

    assert inverse_by_name["validation_precision_floor"]["passed"] is True
    assert inverse_by_name["validation_precision_confidence_lower"]["passed"] is False
    assert inverse_by_name["validation_holdout_candidate_precision_floor"]["passed"] is True
    assert inverse_by_name["validation_holdout_candidate_precision_confidence_lower"]["passed"] is False
    assert validation["thresholds"]["min_precision"] == 0.9
    assert validation["thresholds"]["min_precision_confidence_lower"] == 0.8
    assert _field_thresholds_are_strict(validation["thresholds"]) is True

    lowered_point = dict(validation["thresholds"], min_precision=0.89)
    lowered_wilson = dict(validation["thresholds"], min_precision_confidence_lower=0.79)
    assert _field_thresholds_are_strict(lowered_point) is False
    assert _field_thresholds_are_strict(lowered_wilson) is False


def test_data_release_gate_rejects_unsigned_or_misbound_interceptor_evidence(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")

    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    unsigned = json.loads(mcp.read_text(encoding="utf-8"))
    unsigned.pop("evidence_bundle")
    mcp.write_text(json.dumps(unsigned, ensure_ascii=False), encoding="utf-8")
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is False
    assert "mcp_interceptor_operator_signed_evidence" in {check["name"] for check in report["checks"] if not check["passed"]}

    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, app_id="different-app")
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is False
    assert "mcp_interceptor_app_matches_guardian" in {check["name"] for check in report["checks"] if not check["passed"]}

    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, session_id="")
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is False
    assert "mcp_interceptor_session_binding_present" in {check["name"] for check in report["checks"] if not check["passed"]}

    other_guardian = _guardian_release_report(tmp_path / "other-guardian.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, guardian_path=other_guardian)
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "mcp_interceptor_guardian_path_binding_matches" in failed
    assert "mcp_interceptor_guardian_content_binding_matches" in failed


def test_guardian_ship_is_revoked_when_signed_target_evidence_is_tampered(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    original = json.loads(guardian.read_text(encoding="utf-8"))

    scope_tampered = json.loads(json.dumps(original))
    scope_tampered["targets"][0]["scope_contract"]["assertion_present"] = False
    apply_guardian_experience(scope_tampered)

    finding_tampered = json.loads(json.dumps(original))
    finding_tampered["targets"][0]["findings"].append(
        {
            "rule_id": "TAMPERED_HIGH_FINDING",
            "severity": "high",
            "source": "test",
            "evidence": "raw_returned=false",
        }
    )
    apply_guardian_experience(finding_tampered)

    for candidate in (scope_tampered, finding_tampered):
        assert candidate["guardian_gate"]["passed"] is False
        assert candidate["experience"]["verdict_code"] == "hold_authority"
        assert "target_release_evidence_binding_required" in candidate["guardian_gate"]["authority_blockers"]
        assert "release_authority_claim_mismatch" in candidate["guardian_gate"]["authority_blockers"]


def test_data_release_gate_rejects_source_or_manifest_changed_after_guardian_signature(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    manifest = _guardian_manifest_for(guardian)
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    assert run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)["passed"] is True

    rows = list(csv.DictReader(manifest.read_text(encoding="utf-8").splitlines()))
    workspace = manifest.parent / rows[0]["locator"]
    (workspace / "app.py").write_text("def changed_after_audit():\n    return 'changed'\n", encoding="utf-8")
    changed_source = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert changed_source["passed"] is False
    assert "guardian_source_snapshots_match_current_manifest" in {check["name"] for check in changed_source["checks"] if not check["passed"]}

    (workspace / "app.py").write_text("def release_source():\n    return 'ok'\n", encoding="utf-8")
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    changed_manifest = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert changed_manifest["passed"] is False
    assert "guardian_evidence_bundle_matches_report" in {check["name"] for check in changed_manifest["checks"] if not check["passed"]}


def test_data_release_gate_reopens_and_verifies_repeat_guardian(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    repeat = validation.with_suffix(".repeat-guardian.json")
    assert run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)["passed"] is True

    payload = json.loads(repeat.read_text(encoding="utf-8"))
    payload["execution_id"] = payload["execution_id"][:-1] + "f"
    repeat.write_text(json.dumps(payload), encoding="utf-8")
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "validation_repeat_guardian_content_binding" in failed
    assert "validation_repeat_guardian_evidence_bundle" in failed


def test_data_release_gate_revalidates_reviewer_and_custodian_keys_from_originals(tmp_path, monkeypatch):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    initial = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    initial_failures = [check["name"] for check in initial["checks"] if not check["passed"]]
    assert initial["passed"] is True, initial_failures

    monkeypatch.delenv("K_GUARD_FIELD_REVIEWER_HMAC_KEYS", raising=False)
    monkeypatch.delenv("K_GUARD_FIELD_CUSTODIAN_HMAC_KEY", raising=False)
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "validation_recomputed_from_originals" in failed


def test_data_release_gate_requires_korean_senior_four_domain_review(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["review_contract"]["profile"] = "standard"
    guardian_data["review_contract"]["passed"] = True
    refresh_guardian_evidence_bundle(guardian_data, guardian)
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_review_profile_korean_senior" in failed


def test_data_release_gate_recomputes_four_domains_from_target_evidence(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["targets"] = [row for row in guardian_data["targets"] if row.get("kind") == "workspace"]
    guardian_data["intent_contract"] = _intent_contract(len(guardian_data["targets"]))
    guardian_data["review_contract"]["passed"] = True
    for domain in guardian_data["review_contract"]["domains"].values():
        domain["passed"] = True
    guardian_data["guardian_gate"]["passed"] = True
    refresh_guardian_evidence_bundle(guardian_data, guardian)
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")

    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_review_contract_matches_target_evidence" in failed


def test_data_release_gate_rejects_critical_only_guardian_threshold(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["guardian_gate"]["fail_on"] = "critical"
    for target in guardian_data["targets"]:
        target["fail_on"] = "critical"
    refresh_guardian_evidence_bundle(guardian_data, guardian)
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert report["passed"] is False
    assert {"guardian_release_threshold_high", "guardian_target_thresholds_high"}.issubset(failed)


def test_data_release_gate_requires_korean_governance_workspace_corpus(tmp_path):
    corpus_path = tmp_path / "without-governance.json"
    corpus = dict(KOREAN_CORPUS)
    corpus.pop("workspace_cases", None)
    corpus_path.write_text(json.dumps(corpus, ensure_ascii=False), encoding="utf-8")
    korean = _write_json(tmp_path / "korean.json", evaluate_fixture_corpus(corpus_path))
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, corpus_path)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert report["passed"] is False
    assert {
        "korean_governance_positive_case_floor",
        "korean_governance_negative_case_floor",
        "korean_governance_required_rule_coverage",
    }.issubset(failed)


def test_korean_governance_negative_case_cannot_emit_other_governance_rules(tmp_path):
    corpus = json.loads(json.dumps(KOREAN_CORPUS))
    fake_negative = corpus["workspace_cases"][-1]
    fake_negative["files"] = {"identity.ts": "type IdentityVerification = { ci: string; di: string };\n"}
    fake_negative["expected_absent"] = ["KR_DATA_UNIQUE_IDENTIFIER_CONTROL_GAP"]
    corpus_path = tmp_path / "fake-negative.json"
    corpus_path.write_text(json.dumps(corpus, ensure_ascii=False), encoding="utf-8")

    report = evaluate_fixture_corpus(corpus_path)
    assert report["passed"] is False
    assert report["workspace_negative_case_count"] == 2
    assert report["workspace_negative_passed_count"] == 1
    assert report["workspace_cases"][-1]["passed"] is False


@pytest.mark.parametrize("severity", ["high ", "urgent", None])
def test_data_release_gate_rejects_malformed_or_padded_target_severity(tmp_path, severity):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["targets"][0]["findings"] = [{"rule_id": "MALFORMED_SEVERITY", "severity": severity}]
    refresh_guardian_evidence_bundle(guardian_data, guardian)
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert report["passed"] is False
    assert "guardian_no_recomputed_high_critical_findings" in failed


def test_data_release_gate_rejects_insufficient_real_app_validation(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json", target_ids=["single-app"])
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json", target_ids=["single-app"])
    validation = _write_json(
        tmp_path / "validation.json",
        {
            "raw_free": True,
            "guardian_report_ref": _path_ref(source_guardian),
            "claim_status": "insufficient_design_partner_sample",
            "sample": {
                "app_count": 1,
                "review_app_id_count": 1,
                "candidate_target_count": 1,
                "candidate_count": 5,
                "reviewed_candidate_count": 5,
                "invalid_review_count": 0,
            },
            "verdict_counts": {"false_negative": 0, "false_positive": 0, "inconclusive": 0, "true_positive": 5, "benign": 0},
            "rates": {"false_positive_rate": 0.0},
            "candidate_target_refs": [{"hash": evidence_hash("single-app"), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}],
            "candidate_finding_refs": [{"hash": "fabricated", "hash_scheme": evidence_hash_scheme(), "raw_returned": False}],
        },
    )
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, event_count=1)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "validation_claim_ready" in failed
    assert "validation_min_design_partner_apps" in failed


def test_data_release_gate_requires_guardian_intent_and_provenance(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data.pop("intent_contract")
    guardian_data.pop("evidence_bundle")
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_evidence_bundle_present" in failed
    assert "guardian_business_intent_contract_present" in failed


def test_data_release_gate_requires_operator_keyed_evidence_mode(tmp_path, monkeypatch):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY", raising=False)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "evidence_hmac_operator_key_configured" in failed


def test_data_release_gate_rejects_forged_operator_keyed_evidence_bundle(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["evidence_bundle"]["bundle_sha256"] = "0" * 64
    guardian_data["evidence_bundle"]["signature"]["signature_sha256"] = "1" * 64
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_evidence_bundle_present" in failed


def test_data_release_gate_rejects_replayed_signed_guardian_bundle(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    other_guardian = _guardian_release_report(tmp_path / "other-guardian.json", target_ids=["other-01", "other-02", "other-03", "other-04", "other-05"])
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["evidence_bundle"] = json.loads(other_guardian.read_text(encoding="utf-8"))["evidence_bundle"]
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_evidence_bundle_matches_report" in failed


def test_data_release_gate_rejects_target_scope_contract_lie(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["targets"][0]["scope_contract"]["assertion_present"] = False
    guardian_data["targets"][0]["scope_contract"]["assertion_ref"] = {}
    refresh_guardian_evidence_bundle(guardian_data, guardian)
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_target_scope_assertions_present" in failed


def test_data_release_gate_rejects_target_scope_contract_tamper_without_resign(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["targets"][0]["scope_contract"]["assertion_ref"]["hash"] = evidence_hash("different external proof")
    guardian.write_text(json.dumps(guardian_data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "guardian_evidence_bundle_matches_report" in failed


def test_data_release_gate_rejects_validation_source_target_scope_contract_lie(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    source_data = json.loads(source_guardian.read_text(encoding="utf-8"))
    source_data["targets"][0]["scope_contract"]["assertion_present"] = False
    source_data["targets"][0]["scope_contract"]["assertion_ref"] = {}
    refresh_guardian_evidence_bundle(source_data, source_guardian)
    source_guardian.write_text(json.dumps(source_data, ensure_ascii=False), encoding="utf-8")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "validation_source_guardian_target_scope_assertions_present" in failed


def test_data_release_gate_binds_validation_to_source_guardian_content(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    source_data = json.loads(source_guardian.read_text(encoding="utf-8"))
    source_data["tampered_after_validation"] = True
    source_guardian.write_text(json.dumps(source_data, ensure_ascii=False, indent=2), encoding="utf-8")
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert "validation_report_bound_to_source_guardian_content" in failed


def test_data_release_gate_accepts_independent_design_partner_targets(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json", target_ids=["different-01", "different-02", "different-03", "different-04", "different-05"])
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert report["passed"] is True
    assert report["commercial_mcp_contract"]["design_partner_validation_source_is_independent_from_release_app"] is True


def test_data_release_gate_requires_validation_candidates_in_source_guardian_report(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _write_json(
        tmp_path / "validation-source-guardian.json",
        {
            "method": "guardian_audit",
            "raw_free": True,
            "targets": [{"target_id": f"app-{index:02d}", "findings": []} for index in range(1, 6)],
            "execution_contract": {"mode": "report"},
        },
    )
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "validation_source_guardian_has_candidates" in failed
    assert "validation_finding_refs_match_source_guardian_candidates" in failed


def test_data_release_gate_requires_raw_free_guardian_shaped_validation_source(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    source_data = json.loads(source_guardian.read_text(encoding="utf-8"))
    source_data["raw_free"] = False
    source_data["method"] = "not_guardian_audit"
    del source_data["execution_contract"]
    source_guardian.write_text(json.dumps(source_data, ensure_ascii=False), encoding="utf-8")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "validation_source_guardian_raw_free" in failed
    assert "validation_source_guardian_method" in failed
    assert "validation_source_guardian_contract_present" in failed


def test_data_release_gate_verifies_forwarded_jsonl_content_hash(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    forwarded.write_text(json.dumps({"tampered": True}, ensure_ascii=False) + "\n", encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "mcp_forwarded_output_hash_matches" in failed
    assert "mcp_forwarded_output_byte_count_matches" in failed
    assert "mcp_forwarded_output_event_count_matches_report" in failed


def test_data_release_gate_rejects_mcp_observed_forwarded_event_count_mismatch(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, event_count=1)
    data = json.loads(mcp.read_text(encoding="utf-8"))
    data["metadata"]["runtime_policy"]["interceptor"]["event_count"] = 10
    mcp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "mcp_interceptor_input_output_event_count_consistent" in failed


def test_data_release_gate_rejects_raw_pii_in_forwarded_jsonl_even_when_hashes_match(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, event_count=1)
    forwarded_text = json.dumps({"event": "tool_result", "content": "홍길동 010-1234-5678"}, ensure_ascii=False) + "\n"
    forwarded.write_text(forwarded_text, encoding="utf-8")
    data = json.loads(mcp.read_text(encoding="utf-8"))
    data["metadata"]["runtime_policy"]["interceptor"]["forwarded_output_ref"].update(
        {
            "content_hash": evidence_hash(forwarded_text),
            "byte_count": len(forwarded_text.encode("utf-8")),
            "line_count": 1,
            "event_count": 1,
        }
    )
    mcp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "mcp_forwarded_output_raw_free_scan" in failed


def test_data_release_gate_rejects_json_escaped_pii_in_forwarded_jsonl(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path, event_count=1)
    forwarded_text = '{"event":"tool_result","content":"010\\u002d1234\\u002d5678"}\n'
    forwarded.write_text(forwarded_text, encoding="utf-8")
    data = json.loads(mcp.read_text(encoding="utf-8"))
    data["metadata"]["runtime_policy"]["interceptor"]["forwarded_output_ref"].update(
        {
            "content_hash": evidence_hash(forwarded_text),
            "byte_count": len(forwarded_text.encode("utf-8")),
            "line_count": 1,
            "event_count": 1,
        }
    )
    mcp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "mcp_forwarded_output_raw_free_scan" in failed


def test_data_release_gate_rejects_benign_high_critical_labels(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    data = json.loads(validation.read_text(encoding="utf-8"))
    data["claim_status"] = "blocked_benign_high_critical_labels"
    data["verdict_counts"]["benign"] = 1
    data["verdict_counts"]["true_positive"] = 3
    validation.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    korean = _korean_score_report(tmp_path / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "validation_claim_ready" in failed
    assert "validation_no_benign_high_critical_candidates" in failed


def test_data_release_gate_rejects_fabricated_korean_corpus_without_raw_free_coverage(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _write_json(
        tmp_path / "korean.json",
        {
            "raw_free": False,
            "passed": True,
            "recall": 1.0,
            "false_positive_rate": 0.0,
            "positive_count": 37,
            "negative_count": 19,
        },
    )
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "korean_corpus_raw_free" in failed
    assert "korean_corpus_required_rule_coverage" in failed


def test_data_release_gate_rejects_self_attested_korean_corpus_metrics(tmp_path):
    guardian = _guardian_release_report(tmp_path / "guardian.json")
    source_guardian = _validation_source_guardian_report(tmp_path / "validation-source-guardian.json")
    validation = _ready_validation_report(tmp_path / "validation.json", source_guardian)
    korean = _write_json(
        tmp_path / "korean.json",
        {
            "raw_free": True,
            "passed": True,
            "recall": 1.0,
            "false_positive_rate": 0.0,
            "positive_count": 37,
            "negative_count": 19,
            "coverage": {"all_required_rules_observed": True, "missing_required_rules": []},
        },
    )
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    failed = {check["name"] for check in report["checks"] if not check["passed"]}

    assert report["passed"] is False
    assert "korean_corpus_report_matches_recomputed_score" in failed


def test_validation_report_rejects_review_app_ids_not_bound_to_guardian(tmp_path):
    findings = [
        {
            "target_id": "single-app",
            "rule_id": f"RULE_{index}",
            "source": "static",
            "severity": "high",
            "file": "app.ts",
            "line_start": index,
            "evidence": f"fixture_hash={index}",
        }
        for index in range(1, 6)
    ]
    guardian = tmp_path / "guardian.json"
    guardian.write_text(json.dumps({"targets": [{"app_id": "owned-app", "target_id": "single-app", "findings": findings}]}, ensure_ascii=False), encoding="utf-8")
    review = tmp_path / "review.csv"
    rows = ["app_id,target_id,rule_id,finding_fingerprint,verdict,reviewer,notes"]
    for index, item in enumerate(findings, start=1):
        rows.append(f"claimed-app-{index},single-app,{item['rule_id']},{finding_fingerprint(item)},true_positive,cto,confirmed")
    review.write_text("\n".join(rows) + "\n", encoding="utf-8")

    report = run_validation_review(guardian, review)

    assert report["sample"]["review_app_id_count"] == 0
    assert report["sample"]["app_count"] == 1
    assert report["sample"]["candidate_target_count"] == 1
    assert len(report["candidate_target_refs"]) == 1
    assert report["sample"]["invalid_review_count"] == 5
    assert report["claim_status"] == "blocked_invalid_review_labels"


def test_validation_report_blocks_benign_high_critical_candidate_labels(tmp_path):
    findings = [
        {
            "target_id": f"app-{index:02d}",
            "rule_id": "PII_RRN",
            "source": "static",
            "severity": "high",
            "file": f"app-{index}.txt",
            "line_start": 1,
            "evidence": f"fixture_hash={index}",
        }
        for index in range(1, 6)
    ]
    guardian = tmp_path / "guardian.json"
    guardian.write_text(json.dumps({"targets": [{"app_id": item["target_id"], "target_id": item["target_id"], "findings": [item]} for item in findings]}, ensure_ascii=False), encoding="utf-8")
    review = tmp_path / "review.csv"
    rows = ["app_id,target_id,rule_id,finding_fingerprint,verdict,reviewer,notes"]
    for index, item in enumerate(findings, start=1):
        verdict = "benign" if index == 1 else "true_positive"
        rows.append(f"{item['target_id']},{item['target_id']},PII_RRN,{finding_fingerprint(item)},{verdict},cto,confirmed")
    review.write_text("\n".join(rows) + "\n", encoding="utf-8")

    report = run_validation_review(guardian, review)

    assert report["verdict_counts"]["benign"] == 1
    assert report["claim_status"] == "blocked_benign_high_critical_labels"


def test_validation_report_rejects_overbroad_manual_claim_scope(tmp_path):
    findings = [
        {
            "target_id": f"app-{index:02d}",
            "rule_id": "PII_RRN",
            "source": "static",
            "severity": "high",
            "file": f"app-{index}.txt",
            "line_start": 1,
            "evidence": f"fixture_hash={index}",
        }
        for index in range(1, 22)
    ]
    guardian = tmp_path / "guardian.json"
    guardian.write_text(json.dumps({"targets": [{"app_id": item["target_id"], "target_id": item["target_id"], "findings": [item]} for item in findings]}, ensure_ascii=False), encoding="utf-8")
    review = tmp_path / "review.csv"
    rows = ["app_id,target_id,rule_id,finding_fingerprint,verdict,reviewer,notes"]
    for item in findings:
        rows.append(f"{item['target_id']},{item['target_id']},PII_RRN,{finding_fingerprint(item)},true_positive,cto,confirmed")
    review.write_text("\n".join(rows) + "\n", encoding="utf-8")

    report = run_validation_review(guardian, review)
    assert report["sample"]["app_count"] == 21
    assert report["claim_status"] == "sample_scope_too_broad_for_manual_claim"


def _complete_release_inputs(root: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    guardian = _guardian_release_report(root / "guardian.json")
    source_guardian = _validation_source_guardian_report(root / "validation-source-guardian.json")
    validation = _ready_validation_report(root / "validation.json", source_guardian)
    korean = _korean_score_report(root / "korean.json")
    mcp, forwarded = _valid_mcp_intercept_pack(root)
    return guardian, validation, korean, mcp, forwarded, source_guardian


def test_data_release_rejects_cross_app_workspace_http_coverage_pooling(tmp_path):
    guardian, validation, korean, mcp, forwarded, source_guardian = _complete_release_inputs(tmp_path)
    manifest = _guardian_manifest_for(guardian)
    manifest_rows = list(csv.DictReader(manifest.read_text(encoding="utf-8").splitlines()))
    manifest_rows[-1]["app_id"] = "unrelated-app"
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GUARDIAN_MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(manifest_rows)
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    guardian_data["targets"][-1]["app_id"] = "unrelated-app"
    refresh_guardian_evidence_bundle(guardian_data, manifest)
    _write_json(guardian, guardian_data)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    failed = {check["name"] for check in report["checks"] if not check["passed"]}
    assert report["passed"] is False
    assert {"guardian_single_app_release_scope", "guardian_review_contract_matches_target_evidence"}.issubset(failed)


def test_data_release_rejects_hand_built_unsigned_validation_json(tmp_path):
    guardian, validation, korean, mcp, forwarded, source_guardian = _complete_release_inputs(tmp_path)
    validation_data = json.loads(validation.read_text(encoding="utf-8"))
    validation_data.pop("validation_evidence_envelope")
    _write_json(validation, validation_data)

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    assert "validation_operator_signed_evidence_envelope" in {check["name"] for check in report["checks"] if not check["passed"]}


def test_data_release_rejects_review_csv_changed_after_signed_validation(tmp_path):
    guardian, validation, korean, mcp, forwarded, source_guardian = _complete_release_inputs(tmp_path)
    review = validation.with_suffix(".review.csv")
    review.write_text(review.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    report = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)

    assert report["passed"] is False
    assert "validation_review_csv_matches_signed_sha256" in {check["name"] for check in report["checks"] if not check["passed"]}


def test_run_validation_review_requires_operator_key(tmp_path, monkeypatch):
    guardian = _validation_source_guardian_report(tmp_path / "guardian.json")
    review = tmp_path / "review.csv"
    review.write_text("app_id,target_id,rule_id,finding_fingerprint,verdict,reviewer,notes\n", encoding="utf-8")
    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY", raising=False)

    with pytest.raises(RuntimeError, match="K_GUARD_EVIDENCE_HMAC_KEY"):
        run_validation_review(guardian, review)


def test_data_release_revalidates_signed_suppression_expiry(tmp_path):
    guardian, validation, korean, mcp, forwarded, source_guardian = _complete_release_inputs(tmp_path)
    manifest = _guardian_manifest_for(guardian)
    guardian_data = json.loads(guardian.read_text(encoding="utf-8"))
    finding = {
        "target_id": guardian_data["targets"][0]["target_id"],
        "rule_id": "TEST_RELEASE_WAIVER",
        "source": "test",
        "severity": "medium",
        "file": "app.py",
        "line_start": 1,
        "evidence": "fixture_hash=suppression-expiry raw_returned=false",
    }
    guardian_data["targets"][0]["findings"] = [finding]
    guardian_data["targets"][0]["rule_ids"] = [finding["rule_id"]]
    guardian_data["execution_attestation"] = build_guardian_execution_attestation(
        guardian_data["execution_id"],
        guardian_data["generated_at"],
        guardian_data["generated_at"],
        guardian_data["targets"],
    )
    binding = _guardian_row_suppression_binding(guardian_data["targets"][0])
    bound_finding = {**finding, **binding}
    policy_path = tmp_path / "suppressions.csv"
    with policy_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUPPRESSION_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                **binding,
                "target_id": finding["target_id"],
                "rule_id": finding["rule_id"],
                "finding_fingerprint": suppression_fingerprint(bound_finding),
                "owner": "release-owner",
                "reason": "bounded fixture waiver",
                "expires": "2099-01-01",
            }
        )
    guardian_data = apply_suppressions_to_guardian_report(guardian_data, policy_path)
    refresh_guardian_evidence_bundle(guardian_data, manifest)
    _write_json(guardian, guardian_data)
    mcp, forwarded = _valid_mcp_intercept_pack(tmp_path)
    first_pass = run_data_release_gate(
        guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH
    )
    first_blockers = [
        check["name"]
        for check in first_pass["checks"]
        if check["severity"] == "blocker" and not check["passed"]
    ]
    assert first_pass["passed"] is True, first_blockers

    changed_scope = json.loads(json.dumps(guardian_data))
    changed_scope["targets"][0]["review_evidence"]["source_tree_snapshot"]["tree_sha256"] = "f" * 64
    refresh_guardian_evidence_bundle(changed_scope, manifest)
    _write_json(guardian, changed_scope)
    replayed_scope = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert replayed_scope["passed"] is False
    assert "guardian_suppression_release_scope_bound" in {
        check["name"] for check in replayed_scope["checks"] if not check["passed"]
    }

    policy = guardian_data["suppression_policy"]
    policy["fresh_until"] = "2000-01-01T23:59:59+00:00"
    policy["policy_expiries"] = ["2000-01-01"]
    policy["suppressed"][0]["expires"] = "2000-01-01"
    policy["waived_finding_refs"][0]["expires"] = "2000-01-01"
    refresh_guardian_evidence_bundle(guardian_data, manifest)
    _write_json(guardian, guardian_data)

    replayed = run_data_release_gate(guardian, validation, korean, mcp, forwarded, source_guardian, KOREAN_CORPUS_PATH)
    assert replayed["passed"] is False
    assert "guardian_suppression_evidence_fresh" in {check["name"] for check in replayed["checks"] if not check["passed"]}


@pytest.mark.parametrize("parameter", ["max_validation_false_positive_rate", "max_korean_false_positive_rate"])
@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), -0.01, 0.2000001, "0.1", True])
def test_data_release_rejects_noncanonical_false_positive_limits(parameter, value):
    report = _run_data_release_gate("", "", "", "", **{parameter: value})
    check_name = f"{parameter}_canonical" if parameter.startswith("max_validation") else "max_korean_false_positive_rate_canonical"
    checks = {check["name"]: check for check in report["checks"]}

    assert report["passed"] is False
    assert checks[check_name]["passed"] is False
    assert report["thresholds"][parameter.replace("max_korean_false_positive_rate", "max_korean_corpus_false_positive_rate")] is None
    json.dumps(report, allow_nan=False)


@pytest.mark.parametrize("value", [0.0, 0.20])
def test_data_release_accepts_canonical_false_positive_limit_boundaries(value):
    report = _run_data_release_gate(
        "",
        "",
        "",
        "",
        max_validation_false_positive_rate=value,
        max_korean_false_positive_rate=value,
    )
    checks = {check["name"]: check for check in report["checks"]}
    assert checks["max_validation_false_positive_rate_canonical"]["passed"] is True
    assert checks["max_korean_false_positive_rate_canonical"]["passed"] is True
