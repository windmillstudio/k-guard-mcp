from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("contest_readiness", ROOT / "scripts" / "contest_readiness.py")
assert SPEC and SPEC.loader
contest_readiness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contest_readiness)


def test_contest_readiness_separates_internal_submission_from_external_award_evidence() -> None:
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        pytest.skip("current-source contest evidence is release-only and cannot bind uncommitted tracked changes")
    required_generated_evidence = (
        ROOT / contest_readiness.CURRENT_WHEEL_SMOKE,
        ROOT / contest_readiness.CURRENT_PUBLIC_REPLAY / "campaign.json",
        ROOT / contest_readiness.SUBMISSION_VIDEO_ATTESTATION,
        ROOT / contest_readiness.SUBMISSION_REPORT_ATTESTATION,
        ROOT / "submission" / "SHA256SUMS",
    )
    if not all(path.is_file() for path in required_generated_evidence):
        pytest.skip("current-source contest evidence has not been generated yet")
    legacy_report = contest_readiness.build_report(ROOT)

    assert legacy_report["package_ready"] is False
    assert legacy_report["submission_ready"] is False
    assert legacy_report["award_evidence_ready"] is False
    assert legacy_report["status"] == "package_verification_blocked"
    assert legacy_report["internal_checks"]["submission_report_bound_and_verified"] is False
    assert legacy_report["internal_checks"]["fresh_wheel_stdio_current_source_passed"] is True
    assert "submission_release_archives_match_current_source" in legacy_report["internal_checks"]
    assert legacy_report["internal_checks"]["declared_sbom_component_count_matches_live_artifacts"] is True
    assert legacy_report["diagnostics"]["declared_sbom_component_count_errors"] == []
    assert legacy_report["internal_checks"]["current_source_public_replay_passed"] is False
    assert legacy_report["external_checks"] == {
        "owned_partner_field_apps_at_least_12": False,
        "historical_client_recordings_at_least_3": False,
        "historical_public_app_effectiveness_qualified": True,
    }
    assert legacy_report["metrics"]["legacy_brand_hit_count"] == 0
    assert legacy_report["metrics"]["evidence_error_count"] == 0
    assert legacy_report["metrics"]["client_evidence_error_count"] == 7
    assert legacy_report["metrics"]["public_effectiveness_error_count"] == 0
    assert legacy_report["metrics"]["verified_client_count"] == 0
    assert legacy_report["metrics"]["public_app_count"] == 12
    assert legacy_report["metrics"]["public_candidate_actionable_rate"] == 1.0
    assert legacy_report["metrics"]["public_reference_probe_detection_rate"] == 1.0
    assert legacy_report["internal_checks"]["historical_client_evidence_contract_valid"] is False
    assert legacy_report["internal_checks"]["current_self_attested_client_process_evidence_at_least_3"] is False
    assert legacy_report["internal_checks"]["historical_public_effectiveness_evidence_contract_valid"] is True

    invalid_report = contest_readiness.build_report(
        ROOT,
        r2_current_source_succession_contract=ROOT / "missing-r2-current-source-succession-contract.json",
    )
    assert invalid_report["package_ready"] is False
    assert invalid_report["internal_checks"]["r2_current_source_evidence_succession_contract_valid"] is False
    assert invalid_report["diagnostics"]["r2_current_source_evidence_succession_contract"]["errors"] == [
        "r2_current_source_succession_contract_missing"
    ]



def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seal_synthetic_succession_bundle(contract_path: Path) -> None:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    cycle_root = next(parent.parent for parent in contract_path.parents if parent.name == "evidence")
    manifest_path = contract_path.with_name("hash-manifest.json")
    manifest = {
        "schema": contest_readiness.R2_SUCCESSION_MANIFEST_SCHEMA,
        "raw_returned": False,
        "active_contract_sha256": contract["active_contract_binding"]["active"]["sha256"],
        "contract": {"path": contract_path.name, "sha256": _sha256(contract_path)},
        "source_binding": contract["source_binding"],
        "inherited_evidence": contract["inherited_evidence"],
    }
    _write_json(manifest_path, manifest)
    artifacts = []
    for artifact_path in (contract_path, manifest_path):
        artifacts.append({
            "path": artifact_path.relative_to(cycle_root).as_posix(),
            "byte_count": artifact_path.stat().st_size,
            "sha256": _sha256(artifact_path),
        })
    event = {
        "schema": contest_readiness.R2_WORK_EVENT_SCHEMA,
        "sequence": 1,
        "event_id": "11111111-1111-4111-8111-111111111111",
        "recorded_at_kst": "2026-07-27T09:00:00+09:00",
        "cycle_id": "product-hardening-r2",
        "phase_id": "phase-0",
        "work_item_id": contest_readiness.R2_SUCCESSION_ACTIVATION_WORK_ITEM,
        "actor": {"role": "synthetic-test", "model": "synthetic-test", "session_id": "synthetic-test"},
        "action": contest_readiness.R2_SUCCESSION_ACTIVATION_ACTION,
        "status": "PASS",
        "summary": "synthetic activation for deterministic fail-closed validation",
        "repository": {
            "path": "repo",
            "commit": contract["source_binding"]["head"],
            "tree": contract["source_binding"]["tree"],
            "dirty_count": 0,
        },
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
        "previous_event_sha256": None,
        "event_sha256": "",
        "raw_returned": False,
    }
    event["event_sha256"] = contest_readiness._canonical_json_sha256(
        {key: value for key, value in event.items() if key != "event_sha256"}
    )
    _write_json(cycle_root / "operations" / "logs" / "events" / "000001-11111111-1111-4111-8111-111111111111.json", event)


def _synthetic_succession_contract(tmp_path: Path) -> Path:
    cycle_root = tmp_path / "cycle"
    active = cycle_root / "operations" / "ACTIVE.md"
    documents = [cycle_root / "operations" / "docs" / f"{index:02d}.md" for index in range(4)]
    for path in (active, *documents):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(path.name, encoding="utf-8")
    binding = {"head": "a" * 40, "tree": "b" * 40, "repo_clean_before": True}
    gate_path = cycle_root / "evidence" / "product-hardening-r2" / "phase-0" / "synthetic" / "gate-status.json"
    gates = {
        "clean_head": {"pass": True, "observed": {"head": binding["head"], "tree": binding["tree"], "dirty": False}},
        "current_public_replay": {"pass": False},
        "current_source_readiness": {"pass": False},
        "fresh_wheel_external": {"pass": True},
        "full_regression": {"pass": False},
        "required_supervisor_runtime_health": {"pass": True},
        "submission_report_current_binding": {"pass": False},
    }
    _write_json(gate_path, {"schema": contest_readiness.R2_GATE_STATUS_SCHEMA, "status": "HOLD", "release_status": "HOLD", "failed_gate_ids": list(contest_readiness.R2_SUCCESSION_REQUIRED_GATES), "gates": gates})
    inherited = []
    for name in sorted(contest_readiness.R2_SUCCESSION_REQUIRED_ARTIFACTS):
        artifact = gate_path if name == "gate_status" else gate_path.with_name(f"{name}.json")
        if not artifact.exists():
            _write_json(artifact, {"artifact": name})
        inherited.append({"name": name, "path": str(artifact), "sha256": _sha256(artifact)})
    contract_path = gate_path.with_name("succession-contract.json")
    contract = {
        "schema": contest_readiness.R2_SUCCESSION_CONTRACT_SCHEMA,
        "contract_version": contest_readiness.R2_SUCCESSION_CONTRACT_VERSION,
        "raw_returned": False,
        "source_binding": binding,
        "active_contract_binding": {"active": {"path": str(active), "sha256": _sha256(active)}, "documents": [{"path": str(path), "sha256": _sha256(path)} for path in documents]},
        "invariants": {"historical_sealed_artifacts_immutable": True, "fixed_thresholds_unchanged": True, "denominators_unchanged": True, "oracle_definitions_unchanged": True, "labels_severity_and_exclusions_unchanged": True, "legacy_readiness_pass_claim_prohibited": True, "release_status": "HOLD", "phase_status": "HOLD"},
        "inherited_evidence": inherited,
        "measured_gate_status": {"status": "HOLD", "release_status": "HOLD", "failed_gate_ids": list(contest_readiness.R2_SUCCESSION_REQUIRED_GATES)},
    }
    _write_json(contract_path, contract)
    _seal_synthetic_succession_bundle(contract_path)
    return contract_path


def test_r2_current_source_succession_contract_is_hash_bound_and_fail_closed(tmp_path: Path) -> None:
    valid_path = _synthetic_succession_contract(tmp_path / "valid")
    report = contest_readiness.build_report(ROOT, r2_current_source_succession_contract=valid_path)

    assert report["package_ready"] is False
    assert report["status"] == "package_verification_blocked"
    assert report["internal_checks"]["r2_current_source_evidence_succession_contract_valid"] is True
    assert report["internal_checks"]["fresh_wheel_stdio_current_source_passed"] is True
    assert report["internal_checks"]["submission_report_bound_and_verified"] is False
    assert report["internal_checks"]["current_source_public_replay_passed"] is False
    assert report["internal_checks"]["r2_current_source_full_regression_passed"] is False
    assert report["metrics"]["r2_current_source_failed_gate_count"] == 4
    assert "submission_release_archives_match_current_source" in report["internal_checks"]
    assert report["internal_checks"]["declared_sbom_component_count_matches_live_artifacts"] is True
    assert report["diagnostics"]["declared_sbom_component_count_errors"] == []
    unrelated_environment_blockers = {
        "three_minute_demo_video_valid",
        "submission_video_attestation_valid",
        "submission_artifact_manifest_valid",
        "submission_release_archives_match_current_source",
        "evidence_integrity_passed",
        "historical_client_evidence_contract_valid",
        "current_self_attested_client_process_evidence_at_least_3",
    }
    assert [item for item in report["blockers"] if item not in unrelated_environment_blockers] == [
        "submission_report_bound_and_verified",
        "current_source_public_replay_passed",
        "r2_current_source_full_regression_passed",
        "owned_partner_field_apps_at_least_12",
        "historical_client_recordings_at_least_3",
    ]
    assert "submission_report_external_urls_incomplete" in report["diagnostics"]["submission_report_errors"]
    assert report["external_checks"]["owned_partner_field_apps_at_least_12"] is False
    assert report["metrics"]["owned_partner_app_count"] == 0

    source_path = _synthetic_succession_contract(tmp_path / "source-tamper")
    source_contract = json.loads(source_path.read_text(encoding="utf-8"))
    source_contract["source_binding"]["head"] = "c" * 40
    _write_json(source_path, source_contract)
    _seal_synthetic_succession_bundle(source_path)
    assert contest_readiness._r2_current_source_succession_status(source_path, ROOT)[2] == ["r2_current_source_succession_source_binding_invalid"]

    manifest_path = _synthetic_succession_contract(tmp_path / "manifest-missing").with_name("hash-manifest.json")
    manifest_path.unlink()
    assert contest_readiness._r2_current_source_succession_status(manifest_path.with_name("succession-contract.json"), ROOT)[2] == ["r2_current_source_succession_manifest_missing"]

    event_contract = _synthetic_succession_contract(tmp_path / "event-missing")
    event_path = event_contract.parents[4] / "operations" / "logs" / "events" / "000001-11111111-1111-4111-8111-111111111111.json"
    event_path.unlink()
    assert contest_readiness._r2_current_source_succession_status(event_contract, ROOT)[2] == ["r2_current_source_succession_activation_event_missing"]

    gate_path = _synthetic_succession_contract(tmp_path / "gate-tamper")
    gate_contract = json.loads(gate_path.read_text(encoding="utf-8"))
    status_path = Path(next(item["path"] for item in gate_contract["inherited_evidence"] if item["name"] == "gate_status"))
    gate_status = json.loads(status_path.read_text(encoding="utf-8"))
    gate_status["gates"]["current_public_replay"]["pass"] = True
    _write_json(status_path, gate_status)
    for item in gate_contract["inherited_evidence"]:
        if item["name"] == "gate_status":
            item["sha256"] = _sha256(status_path)
    _write_json(gate_path, gate_contract)
    _seal_synthetic_succession_bundle(gate_path)
    assert contest_readiness._r2_current_source_succession_status(gate_path, ROOT)[2] == ["r2_current_source_succession_gate_status_invalid"]


def test_contest_readiness_fails_brand_consistency_on_legacy_active_copy(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "legacy.md").write_text(contest_readiness.LEGACY_PERSONA, encoding="utf-8")

    assert contest_readiness._legacy_brand_hits(tmp_path) == ["docs/legacy.md"]


def _honest_claim_text() -> str:
    return (
        "역사적 공개 앱 AI 판정: revision 9488898, 공개 개발 앱 12개, 후보 31건, 검토자 3명. "
        "동일 모델 계열이며 사람 수동 판정이 아님. "
        "현재 코드 공개 앱 재현: 12개 앱 × 2회 exact repeat, 자동 release-blocking 후보 14건, "
        "취약 probe 11/11, benign probe 1/1. "
        "BenchmarkJava 최초 HOLD. Juliet 첫 결과 TP 180, FN 30. "
        "수정 후 재생 post-tuning TP 210, FN 0이며 Juliet replay는 integrity FAIL로 제외하고 독립 holdout이 아님. "
        "역사적 OWASP Python은 integrity FAIL로 현재 근거에서 제외한다. "
        "tested revision add8fe38, product source 72e2aea 최종 full-regression receipt는 "
        "3,265 collected / 3,261 passed / 4 skipped / 0 failed / 0 errors인 bounded product regression이며 "
        "detector accuracy가 아님. "
        "평가자 작성 68건 한국 개인정보 holdout은 구현 후 합성 점검이며 fixture와 합쳐 "
        "185회 separate-lane execution으로만 표기하고 "
        "blind/field accuracy·실시간 등록 검증 아님. "
        "field 0/12, field evidence pending. "
        "CycloneDX 1.5 SBOM component 41개, active dependency closure 41개. "
        "제출 시연영상은 180초 H.264 1920x1080, 전체 디코딩, VoxCPM2 한국어 나레이션 오디오 스트림 1."
    )


def _claim_metric_pack() -> tuple[dict, dict, dict, dict]:
    public = {
        "metrics": {
            "app_count": 12,
            "candidate_count": 31,
            "reviewer_count": 3,
            "true_positive_probe_detected": 11,
            "true_positive_probe_count": 11,
        }
    }
    first = {"metrics": {"true_positive": 180, "false_negative": 30, "false_positive": 0, "true_negative": 210}}
    replay = {
        "metrics": {"true_positive": 210, "false_negative": 0},
        "claim_boundary": {"not_an_independent_holdout": True},
    }
    current_public = {
        "app_count": 12,
        "candidate_count": 14,
        "true_positive_probe_count": 11,
        "true_positive_probe_detected": 11,
        "benign_probe_count": 1,
        "benign_probe_detected": 1,
    }
    return public, first, replay, current_public


def test_submission_claims_require_current_metrics_and_honest_boundaries(tmp_path: Path) -> None:
    public, first, replay, current_public = _claim_metric_pack()
    current = _honest_claim_text()
    for relative in contest_readiness.SUBMISSION_CLAIM_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(current, encoding="utf-8")

    assert contest_readiness._submission_claim_errors(
        tmp_path, public, first, replay, current_public
    ) == []

    stale = tmp_path / contest_readiness.SUBMISSION_CLAIM_FILES[0]
    stale.write_text(current + " 과거 수치 44.44%", encoding="utf-8")
    errors = contest_readiness._submission_claim_errors(
        tmp_path, public, first, replay, current_public
    )
    assert errors == [
        f"stale_claim:stale_actionable_rate_44_44:{contest_readiness.SUBMISSION_CLAIM_FILES[0].as_posix()}"
    ]


def test_submission_claims_reject_conflated_current_31_and_stale_revision(tmp_path: Path) -> None:
    public, first, replay, current_public = _claim_metric_pack()
    current = _honest_claim_text()
    for relative in contest_readiness.SUBMISSION_CLAIM_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(current, encoding="utf-8")

    conflated = tmp_path / contest_readiness.SUBMISSION_CLAIM_FILES[0]
    conflated.write_text(
        current.replace("후보 14건", "후보 31건").replace("현재 코드", "현재 코드 revision 9f2fd7e"),
        encoding="utf-8",
    )
    errors = contest_readiness._submission_claim_errors(
        tmp_path, public, first, replay, current_public
    )
    joined = " ".join(errors)
    assert "stale_claim:stale_current_candidates_31:" in joined
    assert "stale_claim:stale_current_revision_9f2fd7e:" in joined


def test_submission_claims_reject_current_candidate_count_31_in_source_metrics(
    tmp_path: Path,
) -> None:
    public, first, replay, current_public = _claim_metric_pack()
    current_public = dict(current_public)
    current_public["candidate_count"] = 31
    current = _honest_claim_text()
    for relative in contest_readiness.SUBMISSION_CLAIM_FILES:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(current, encoding="utf-8")

    assert contest_readiness._submission_claim_errors(
        tmp_path, public, first, replay, current_public
    ) == ["source_evidence_metrics_not_at_expected_revision"]


def test_submission_video_rejects_metadata_only_fabrication(tmp_path: Path) -> None:
    video = tmp_path / "demo.mp4"
    video.write_bytes(b"not a decodable video" * 10_000)
    attestation = tmp_path / "video-verification.json"
    attestation.write_text(
        json.dumps(
            {
                "schema": "k_guard_submission_video_verification.v1",
                "video_sha256": "0" * 64,
                "byte_count": video.stat().st_size,
                "valid": True,
                "fully_decoded": True,
                "video_stream_count": 1,
                "audio_stream_count": 0,
                "raw_returned": False,
            }
        ),
        encoding="utf-8",
    )

    status, errors = contest_readiness._submission_video_status(video, attestation)

    assert status["valid"] is False
    assert errors


def test_submission_video_accepts_digest_bound_attestation_without_media_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(contest_readiness.shutil, "which", lambda _name: None)

    status, errors = contest_readiness._submission_video_status(
        ROOT / contest_readiness.SUBMISSION_VIDEO,
        ROOT / contest_readiness.SUBMISSION_VIDEO_ATTESTATION,
    )

    assert errors == []
    assert status["valid"] is True
    assert status["live_reverified"] is False


def test_current_evidence_revision_must_bind_the_expected_package(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(contest_readiness, "package_tree_sha256_at_revision", lambda _root, _revision: "b" * 64)

    errors = contest_readiness._revision_package_errors(
        tmp_path,
        "a" * 40,
        "c" * 64,
        "fresh_wheel_smoke",
    )

    assert errors == ["fresh_wheel_smoke_source_revision_package_mismatch"]


def test_language_validation_contract_fails_closed_when_pack_cannot_load() -> None:
    errors = contest_readiness._language_validation_contract_errors(
        {
            "schema": "k_guard_language_validation_contract.v1",
            "complete": False,
            "hashes": {},
            "raw_free": True,
        }
    )

    assert "language_validation_pack_incomplete" in errors
    assert "language_validation_pack_sha256_invalid" in errors


def test_release_workflow_contract_requires_sha_pins_and_release_binding(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on:\n  workflow_call:\nsteps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
    (workflows / "release.yml").write_text("jobs:\n  build:\n    steps: []\n", encoding="utf-8")
    (workflows / "k-guard-audit.yml").write_text(
        "steps:\n"
        f"  - uses: actions/checkout@{'3' * 40}\n"
        "    with:\n"
        "      fetch-depth: 0\n"
        "  - run: python -m pytest -q\n",
        encoding="utf-8",
    )

    errors = contest_readiness._release_workflow_contract_errors(tmp_path)

    assert "ci_action_not_sha_pinned:4" in errors
    assert "release_compatibility_call_missing" in errors
    assert "release_tag_version_check_missing" in errors
    assert "release_durable_publish_missing" in errors


def test_checkout_steps_require_full_history_for_evidence_bound_revisions() -> None:
    checkout_sha = "3" * 40
    shallow = f"steps:\n  - uses: actions/checkout@{checkout_sha}\n"
    complete = f"steps:\n  - uses: actions/checkout@{checkout_sha}\n    with:\n      fetch-depth: 0\n"

    assert contest_readiness._workflow_checkout_history_errors(shallow, "ci") == [
        "ci_checkout_full_history_missing:2"
    ]
    assert contest_readiness._workflow_checkout_history_errors(complete, "ci") == []


def test_field_award_gate_rejects_fabricated_summary_without_primary_sources(tmp_path: Path) -> None:
    fake_campaign = {"app_count": 12, "ready": True}

    app_count, errors = contest_readiness._field_award_evidence_status(tmp_path, fake_campaign)

    assert app_count == 12
    assert "field_campaign_schema_fields_invalid" in errors
    assert "field_campaign_schema_invalid" in errors
    assert "field_evidence_source_missing:validation_report" in errors


def test_field_award_gate_keeps_signed_synthetic_contract_blocked_without_external_anchor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture_spec = importlib.util.spec_from_file_location(
        "contest_field_fixture",
        ROOT / "tests" / "test_field_validation.py",
    )
    assert fixture_spec and fixture_spec.loader
    fixture = importlib.util.module_from_spec(fixture_spec)
    fixture_spec.loader.exec_module(fixture)
    monkeypatch.setenv(
        "K_GUARD_EVIDENCE_HMAC_KEY",
        "contest-field-validation-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    )
    monkeypatch.setenv("K_GUARD_FIELD_REVIEWER_HMAC_KEYS", json.dumps(fixture.REVIEWER_KEYS))
    monkeypatch.setenv("K_GUARD_FIELD_CUSTODIAN_HMAC_KEY", fixture.CUSTODIAN_KEY)
    evidence = tmp_path / "evidence" / "field"
    evidence.mkdir(parents=True)
    primary, repeat, ground_truth, review, preregistration, roster = fixture._field_pack(evidence)
    shutil.copy2(preregistration, evidence / "preregistration.json")
    campaign = contest_readiness.evaluate_field_campaign_readiness(roster)
    validation = contest_readiness.run_field_validation(
        primary,
        repeat,
        ground_truth,
        review,
        profile="field",
        preregistration_path=evidence / "preregistration.json",
        roster_path=roster,
    )
    (evidence / "campaign-status.json").write_text(json.dumps(campaign), encoding="utf-8")
    (evidence / "field-validation.json").write_text(json.dumps(validation), encoding="utf-8")

    app_count, errors = contest_readiness._field_award_evidence_status(tmp_path, campaign)

    assert app_count == 12
    assert errors == ["field_evidence_source_missing:external_attestation"]


def test_external_field_attestation_requires_out_of_band_digest_pin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence" / "field"
    evidence.mkdir(parents=True)
    campaign = {"app_count": 12, "roster_content_sha256": "a" * 64}
    validation = {"claim_status": "field_validation_ready"}
    campaign_path = evidence / "campaign-status.json"
    validation_path = evidence / "field-validation.json"
    attestation_path = evidence / "external-verifier-attestation.json"
    campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
    validation_path.write_text(json.dumps(validation), encoding="utf-8")
    attestation = {
        "schema": "k_guard_external_field_attestation.v1",
        "issued_at": "2026-07-13T12:00:00+09:00",
        "campaign_status_sha256": hashlib.sha256(campaign_path.read_bytes()).hexdigest(),
        "field_validation_sha256": hashlib.sha256(validation_path.read_bytes()).hexdigest(),
        "roster_content_sha256": "a" * 64,
        "app_count": 12,
        "verifier": {
            "verifier_id": "independent-reviewer-01",
            "organization": "External Review Lab",
            "role": "independent_field_evidence_verifier",
            "independence_statement": "No project implementation or labeling role.",
            "raw_returned": False,
        },
        "assertions": {
            "ownership_scope_assertions_reviewed": True,
            "partner_authorizations_reviewed": True,
            "scan_and_aggregate_consent_reviewed": True,
            "independent_dual_review_process_reviewed": True,
            "primary_and_repeat_executions_reviewed": True,
            "no_synthetic_or_training_apps": True,
            "reviewer_identity_assurance_is_external": True,
            "raw_returned": False,
        },
        "claim_boundary": (
            "External verifier attestation confirms reviewed assertions and process evidence; "
            "K-Guard still does not independently prove legal ownership, human identity, or award eligibility."
        ),
        "raw_returned": False,
    }
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
    digest = hashlib.sha256(attestation_path.read_bytes()).hexdigest()

    without_anchor = contest_readiness._external_field_attestation_errors(
        tmp_path, campaign, validation, attestation_path
    )
    monkeypatch.setenv(contest_readiness.TRUSTED_FIELD_ATTESTATION_SHA256_ENV, digest)
    with_anchor = contest_readiness._external_field_attestation_errors(
        tmp_path, campaign, validation, attestation_path
    )

    assert without_anchor == ["field_external_attestation_trust_anchor_missing"]
    assert with_anchor == []


def test_current_public_replay_requires_every_bound_report_file(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "current-source-replay-v1"
    evidence_dir.mkdir()
    current = ROOT / contest_readiness.CURRENT_PUBLIC_REPLAY
    for name in ("campaign.json", "candidate-queue.json", "reference-probes.json"):
        shutil.copy2(current / name, evidence_dir / name)

    package_hash = contest_readiness.package_tree_sha256(ROOT / "src" / "k_guard_mcp")
    _, errors = contest_readiness._current_public_replay_status(evidence_dir, package_hash, ROOT)

    assert "current_public_report_file_set_invalid" in errors
    assert any(error.startswith("current_public_report_missing:") for error in errors)


def test_current_public_replay_rejects_source_candidate_response_hash(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "current-source-replay-v1"
    shutil.copytree(ROOT / contest_readiness.CURRENT_PUBLIC_REPLAY, evidence_dir)
    queue_path = evidence_dir / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    candidate = queue["candidates"][0]
    assert candidate["location"]["kind"] == "source"
    candidate["response_hash"] = "a" * 64
    queue_path.write_text(json.dumps(queue), encoding="utf-8")

    package_hash = contest_readiness.package_tree_sha256(ROOT / "src" / "k_guard_mcp")
    _, errors = contest_readiness._current_public_replay_status(evidence_dir, package_hash, ROOT)

    assert f"current_public_candidate_evidence_shape_invalid:{candidate['app']}" in errors


def test_current_public_replay_candidate_coverage_uses_nonzero_policy_sampling(
    tmp_path: Path,
) -> None:
    evidence_dir = tmp_path / "current-source-replay-v1"
    shutil.copytree(ROOT / contest_readiness.CURRENT_PUBLIC_REPLAY, evidence_dir)
    queue_path = evidence_dir / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))

    zero_sample_app = next(
        app for app, count in queue["sampling"]["sampled_by_app"].items() if count == 0
    )
    assert zero_sample_app not in {row["app"] for row in queue["candidates"]}

    package_hash = contest_readiness.package_tree_sha256(ROOT / "src" / "k_guard_mcp")
    _, errors = contest_readiness._current_public_replay_status(
        evidence_dir, package_hash, ROOT
    )

    assert "current_public_candidate_app_coverage_invalid" not in errors
    assert "current_public_candidate_sample_count_invalid" not in errors


def test_public_report_rejects_finding_with_only_a_severity(tmp_path: Path) -> None:
    campaign = json.loads(
        (ROOT / contest_readiness.CURRENT_PUBLIC_REPLAY / "campaign.json").read_text(encoding="utf-8")
    )
    app_row = next(row for row in campaign["apps"] if row["app"] == "go-dvwa")
    source = ROOT / contest_readiness.CURRENT_PUBLIC_REPLAY / "reports" / "go-dvwa-run1.json"
    report = json.loads(source.read_text(encoding="utf-8"))
    report["findings"].append({"severity": "info"})
    report["summary"]["info"] += 1
    mutated_row = json.loads(json.dumps(app_row))
    mutated_row["finding_counts"]["info"] += 1
    mutated_row["finding_counts"]["total"] += 1
    mutated = tmp_path / "mutated-report.json"
    mutated.write_text(json.dumps(report), encoding="utf-8")

    _, errors = contest_readiness._public_report_contract(mutated, mutated_row)

    assert "report_finding_invalid" in errors


def test_public_probe_metrics_fail_closed_without_integer_coercion() -> None:
    assert contest_readiness._public_probe_metrics_valid(
        {"probe_count": 12, "detected": 12, "false_negative": 0}
    ) is True
    assert contest_readiness._public_probe_metrics_valid(
        {"probe_count": "not-an-int", "detected": 12, "false_negative": 0}
    ) is False


def test_fresh_wheel_smoke_digest_must_match_submitted_artifact() -> None:
    smoke = json.loads((ROOT / contest_readiness.CURRENT_WHEEL_SMOKE).read_text(encoding="utf-8"))
    smoke["wheel_sha256"] = "0" * 64
    smoke["wheel_artifact"]["sha256"] = "0" * 64
    package_hash = contest_readiness.package_tree_sha256(ROOT / "src" / "k_guard_mcp")

    errors = contest_readiness._fresh_wheel_smoke_errors(smoke, package_hash, ROOT)

    assert "fresh_wheel_smoke_wheel_artifact_digest_mismatch" in errors


def test_fresh_wheel_smoke_rejects_digest_matched_non_wheel_artifact(tmp_path: Path) -> None:
    smoke = json.loads((ROOT / contest_readiness.CURRENT_WHEEL_SMOKE).read_text(encoding="utf-8"))
    wheel_dir = tmp_path / contest_readiness.SUBMISSION_WHEEL_DIR
    wheel_dir.mkdir(parents=True)
    wheel = wheel_dir / "k_guard_mcp-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"digest-matched-not-a-wheel")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    package_hash = "a" * 64
    smoke["schema"] = "k_guard_fresh_wheel_stdio_smoke.v3"
    smoke["wheel_sha256"] = digest
    smoke["source_package_tree_sha256"] = package_hash
    smoke["installed_package_tree_sha256"] = package_hash
    smoke["wheel_artifact"] = {
        "filename": wheel.name,
        "byte_count": wheel.stat().st_size,
        "sha256": digest,
        "package_tree_sha256": package_hash,
        "package_file_count": 1,
        "distribution": "k-guard-mcp",
        "version": "0.1.0",
        "artifact_role": "installed_smoke_input",
        "raw_returned": False,
    }

    errors = contest_readiness._fresh_wheel_smoke_errors(smoke, package_hash, tmp_path)

    assert "fresh_wheel_smoke_wheel_artifact_unreadable" in errors


def test_submission_report_attestation_revision_must_resolve(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    docx = tmp_path / contest_readiness.SUBMISSION_REPORT_DOCX
    pdf = tmp_path / contest_readiness.SUBMISSION_REPORT_PDF
    attestation = tmp_path / contest_readiness.SUBMISSION_REPORT_ATTESTATION
    docx.parent.mkdir(parents=True)
    docx.write_bytes(b"bounded-docx")
    pdf.write_bytes(b"bounded-pdf")
    package_hash = "a" * 64
    payload = {
        "schema": "k_guard_official_contest_report_verification.v1",
        "source_revision": "0" * 40,
        "package_tree_hash_schema": contest_readiness.TREE_HASH_SCHEMA,
        "analyzer_package_tree_sha256": package_hash,
        "docx_sha256": hashlib.sha256(docx.read_bytes()).hexdigest(),
        "pdf_sha256": hashlib.sha256(pdf.read_bytes()).hexdigest(),
        "page_count": contest_readiness.OFFICIAL_REPORT_TOTAL_PAGES,
        "body_page_count": 3,
        "body_page_limit": contest_readiness.OFFICIAL_REPORT_MAX_BODY_PAGES,
        "appendix_page_count": contest_readiness.OFFICIAL_REPORT_APPENDIX_PAGES,
        "docx_section_count": 2,
        "a4_mixed_orientation_verified": True,
        "visual_reviewed_all_pages": True,
        "placeholder_count": 0,
        "repository_url": "https://github.com/windmillstudio/k-guard-mcp",
        "youtube_url": "https://youtu.be/example",
        "external_urls_complete": True,
        "raw_returned": False,
    }
    attestation.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(contest_readiness, "package_tree_sha256", lambda _path: package_hash)
    monkeypatch.setattr(
        contest_readiness,
        "verify_official_report",
        lambda *_args, **_kwargs: type(
            "Result",
            (),
            {
                "body_page_count": 3,
                "appendix_page_count": 3,
                "docx_section_count": 2,
                "placeholder_count": 0,
                "repository_url": "https://github.com/windmillstudio/k-guard-mcp",
                "youtube_url": "https://youtu.be/example",
                "external_urls_complete": True,
            },
        )(),
    )
    monkeypatch.setattr(
        contest_readiness,
        "package_tree_sha256_at_revision",
        lambda _root, _revision: (_ for _ in ()).throw(ValueError("missing revision")),
    )
    errors = contest_readiness._submission_report_errors(tmp_path)

    assert "submission_report_attestation_source_revision_unresolvable" in errors


def test_submission_report_attestation_rejects_docx_and_pdf_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    for relative in (
        contest_readiness.SUBMISSION_REPORT_DOCX,
        contest_readiness.SUBMISSION_REPORT_PDF,
        contest_readiness.SUBMISSION_REPORT_ATTESTATION,
    ):
        source = ROOT / relative
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    attestation_path = tmp_path / contest_readiness.SUBMISSION_REPORT_ATTESTATION
    payload = json.loads(attestation_path.read_text(encoding="utf-8"))
    payload["docx_sha256"] = "0" * 64
    payload["pdf_sha256"] = "1" * 64
    attestation_path.write_text(json.dumps(payload), encoding="utf-8")
    package_hash = str(payload["analyzer_package_tree_sha256"])
    monkeypatch.setattr(contest_readiness, "package_tree_sha256", lambda _path: package_hash)
    monkeypatch.setattr(
        contest_readiness,
        "verify_official_report",
        lambda *_args, **_kwargs: type(
            "Result",
            (),
            {
                "body_page_count": payload.get("body_page_count"),
                "appendix_page_count": payload.get("appendix_page_count"),
                "docx_section_count": payload.get("docx_section_count"),
                "placeholder_count": payload.get("placeholder_count"),
                "repository_url": payload.get("repository_url"),
                "youtube_url": payload.get("youtube_url"),
                "external_urls_complete": payload.get("external_urls_complete"),
            },
        )(),
    )
    monkeypatch.setattr(
        contest_readiness,
        "package_tree_sha256_at_revision",
        lambda _root, _revision: package_hash,
    )

    errors = contest_readiness._submission_report_errors(tmp_path)

    assert "submission_report_attestation_docx_digest_mismatch" in errors
    assert "submission_report_attestation_pdf_digest_mismatch" in errors


def test_submission_release_archive_errors_fail_closed_when_committed_archives_are_missing(
    tmp_path: Path,
) -> None:
    errors = contest_readiness._submission_release_archive_errors(tmp_path)

    assert errors
    assert all(error.startswith("committed_release_archives") for error in errors)


def test_submission_release_archive_errors_fail_closed_on_stale_and_tampered_archives(
    tmp_path: Path,
) -> None:
    from tests.test_release_archives import _write_archives, _write_readme_fixture

    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / contest_readiness.SUBMISSION_WHEEL_DIR
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})

    assert contest_readiness._submission_release_archive_errors(tmp_path) == []

    stale = b"def scan():\n    return 'stale'\n"
    _write_archives(
        dist,
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
        content_overrides={"src/k_guard_mcp/scanner.py": stale},
        wheel_overrides={"k_guard_mcp/scanner.py": stale},
    )
    stale_errors = contest_readiness._submission_release_archive_errors(tmp_path)
    assert stale_errors
    assert any("src/k_guard_mcp/scanner.py" in error for error in stale_errors)

    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})
    with zipfile.ZipFile(dist / "k_guard_mcp-0.1.0-source.zip", "a") as archive:
        archive.writestr("k_guard_mcp-0.1.0/extra.txt", b"tampered")
    tampered_errors = contest_readiness._submission_release_archive_errors(tmp_path)
    assert tampered_errors
    assert any("member set differs" in error or "source ZIP" in error for error in tampered_errors)

    (dist / "k_guard_mcp-0.1.0.tar.gz").unlink()
    wrong_errors = contest_readiness._submission_release_archive_errors(tmp_path)
    assert wrong_errors
    assert any("source distribution" in error or "committed_release_archives:" in error for error in wrong_errors)


def _write_declared_component_count_artifact(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, bytes):
        path.write_bytes(payload)
        return
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
        return
    path.write_text(json.dumps(payload), encoding="utf-8")


def _matching_declared_component_count_payloads(count: int) -> tuple[dict, dict]:
    return (
        {"bomFormat": "CycloneDX", "components": [{"name": f"component-{index}"} for index in range(count)]},
        {"component_count": count},
    )


def test_declared_sbom_component_count_errors_fail_closed_on_missing_malformed_wrong_type_and_mismatch(
    tmp_path: Path,
) -> None:
    expected = contest_readiness.DECLARED_SBOM_COMPONENT_COUNT
    stale = 40 if expected != 40 else 42
    missing_errors = contest_readiness._declared_sbom_component_count_errors(tmp_path)
    assert missing_errors == [
        "declared_sbom_component_count_missing:sbom.cdx.json",
        "declared_sbom_component_count_missing:license-report.json",
        "declared_sbom_component_count_missing:submission/release/sbom.cdx.json",
        "declared_sbom_component_count_missing:submission/release/license-report.json",
    ]

    _write_declared_component_count_artifact(tmp_path / "sbom.cdx.json", b"{")
    _write_declared_component_count_artifact(tmp_path / "license-report.json", [])
    _write_declared_component_count_artifact(
        tmp_path / "submission" / "release" / "sbom.cdx.json",
        {"bomFormat": "CycloneDX", "components": {"name": "not-a-list"}},
    )
    _write_declared_component_count_artifact(
        tmp_path / "submission" / "release" / "license-report.json",
        {"component_count": True},
    )
    assert contest_readiness._declared_sbom_component_count_errors(tmp_path) == [
        "declared_sbom_component_count_malformed:sbom.cdx.json",
        "declared_sbom_component_count_malformed:license-report.json",
        "declared_sbom_component_count_wrong_type:submission/release/sbom.cdx.json",
        "declared_sbom_component_count_wrong_type:submission/release/license-report.json",
    ]

    sbom, license_report = _matching_declared_component_count_payloads(stale)
    _write_declared_component_count_artifact(tmp_path / "sbom.cdx.json", sbom)
    _write_declared_component_count_artifact(tmp_path / "license-report.json", license_report)
    _write_declared_component_count_artifact(tmp_path / "submission" / "release" / "sbom.cdx.json", sbom)
    _write_declared_component_count_artifact(
        tmp_path / "submission" / "release" / "license-report.json",
        {"component_count": str(expected)},
    )
    assert contest_readiness._declared_sbom_component_count_errors(tmp_path) == [
        "declared_sbom_component_count_mismatch:sbom.cdx.json",
        "declared_sbom_component_count_mismatch:license-report.json",
        "declared_sbom_component_count_mismatch:submission/release/sbom.cdx.json",
        "declared_sbom_component_count_wrong_type:submission/release/license-report.json",
    ]

    matching_sbom, matching_license = _matching_declared_component_count_payloads(expected)
    _write_declared_component_count_artifact(tmp_path / "sbom.cdx.json", matching_sbom)
    _write_declared_component_count_artifact(tmp_path / "license-report.json", matching_license)
    _write_declared_component_count_artifact(tmp_path / "submission" / "release" / "sbom.cdx.json", matching_sbom)
    _write_declared_component_count_artifact(
        tmp_path / "submission" / "release" / "license-report.json",
        matching_license,
    )
    assert contest_readiness._declared_sbom_component_count_errors(tmp_path) == []


def test_declared_sbom_component_count_errors_accept_live_artifacts_matching_claim_constant() -> None:
    assert contest_readiness.DECLARED_SBOM_COMPONENT_COUNT == 41
    assert contest_readiness.DECLARED_SBOM_COMPONENT_COUNT_ARTIFACTS == (
        ("sbom.cdx.json", "components"),
        ("license-report.json", "component_count"),
        ("submission/release/sbom.cdx.json", "components"),
        ("submission/release/license-report.json", "component_count"),
    )
    assert contest_readiness._declared_sbom_component_count_errors(ROOT) == []


def test_build_report_surfaces_declared_sbom_component_count_internal_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    errors = ["declared_sbom_component_count_mismatch:sbom.cdx.json"]
    monkeypatch.setattr(
        contest_readiness,
        "_declared_sbom_component_count_errors",
        lambda _root: errors,
    )
    report = contest_readiness.build_report(ROOT)

    assert report["internal_checks"]["declared_sbom_component_count_matches_live_artifacts"] is False
    assert report["diagnostics"]["declared_sbom_component_count_errors"] == errors
    assert "declared_sbom_component_count_matches_live_artifacts" in report["blockers"]


def test_r2_succession_local_and_inherited_never_lets_inherited_true_mask_local_failure() -> None:
    combine = contest_readiness._local_and_inherited
    assert combine(False, True) is False
    assert combine(True, False) is False
    assert combine(False, False) is False
    assert combine(True, True) is True
    assert combine("true", True) is False
    assert combine(1, True) is False


def test_r2_succession_inherited_fresh_wheel_true_does_not_mask_local_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_path = _synthetic_succession_contract(tmp_path / "fresh-wheel-mask")
    monkeypatch.setattr(
        contest_readiness,
        "_fresh_wheel_smoke_errors",
        lambda *_args, **_kwargs: ["local_fresh_wheel_failed"],
    )
    report = contest_readiness.build_report(
        ROOT,
        r2_current_source_succession_contract=contract_path,
    )

    assert report["internal_checks"]["fresh_wheel_stdio_current_source_passed"] is False
    assert report["internal_checks"]["submission_report_bound_and_verified"] is False
    assert report["internal_checks"]["current_source_public_replay_passed"] is False
    assert "fresh_wheel_stdio_current_source_passed" in report["blockers"]
    assert "owned_partner_field_apps_at_least_12" in report["blockers"]
    assert report["external_checks"]["owned_partner_field_apps_at_least_12"] is False
    assert report["metrics"]["owned_partner_app_count"] == 0
    assert "submission_report_external_urls_incomplete" in report["diagnostics"]["submission_report_errors"]


def test_r2_succession_inherited_true_does_not_mask_local_submission_or_replay_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract_path = _synthetic_succession_contract(tmp_path / "inherited-true-mask")
    original_report_errors = contest_readiness._submission_report_errors
    original_replay = contest_readiness._current_public_replay_status

    def failed_report(root):
        return [*original_report_errors(root), "local_submission_report_failed"]

    def failed_replay(*args, **kwargs):
        metrics, _errors = original_replay(*args, **kwargs)
        return metrics, ["local_public_replay_failed"]

    monkeypatch.setattr(contest_readiness, "_submission_report_errors", failed_report)
    monkeypatch.setattr(contest_readiness, "_current_public_replay_status", failed_replay)
    monkeypatch.setattr(contest_readiness, "_r2_gate_passed", lambda _gates, _name: True)
    report = contest_readiness.build_report(
        ROOT,
        r2_current_source_succession_contract=contract_path,
    )

    assert report["internal_checks"]["submission_report_bound_and_verified"] is False
    assert report["internal_checks"]["fresh_wheel_stdio_current_source_passed"] is True
    assert report["internal_checks"]["current_source_public_replay_passed"] is False
    assert "submission_report_bound_and_verified" in report["blockers"]
    assert "current_source_public_replay_passed" in report["blockers"]
    assert "owned_partner_field_apps_at_least_12" in report["blockers"]
    assert report["external_checks"]["owned_partner_field_apps_at_least_12"] is False
    assert report["metrics"]["owned_partner_app_count"] == 0
    assert "submission_report_external_urls_incomplete" in report["diagnostics"]["submission_report_errors"]
