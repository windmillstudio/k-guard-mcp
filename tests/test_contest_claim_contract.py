from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "contest_claim_contract", ROOT / "scripts" / "contest_claim_contract.py"
)
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)

CLAIM_FILES = (
    ROOT / "docs" / "contest-2026-submission-ko.md",
    ROOT / "docs" / "contest-2026-result-report-draft-ko.md",
    ROOT / "docs" / "contest-2026-result-report.html",
    ROOT / "submission" / "report" / "k-guard-contest-result-report.html",
)

HONEST = (
    "역사적 공개 앱 AI 판정: revision 9488898, 공개 개발 앱 12개, 후보 31건, 검토자 3명. "
    "동일 모델 계열이며 사람 수동 판정이 아님. "
    "현재 코드 공개 앱 재현: 12개 앱 × 2회 exact repeat, 자동 release-blocking 후보 14건, "
    "취약 probe 11/11, benign probe 1/1. "
    "BenchmarkJava 최초 HOLD. Juliet 첫 결과 TP 180, FN 30. "
    "수정 후 재생 post-tuning TP 210, FN 0이며 Juliet replay는 integrity FAIL로 제외하고 독립 holdout이 아님. "
    "역사적 OWASP Python은 integrity FAIL로 현재 근거에서 제외한다. "
    "tested revision add8fe38, product source 72e2aea 최종 full-regression receipt는 "
    "3,265 collected / 3,261 passed / 4 skipped / 0 failed / 0 errors인 bounded product regression이며 detector accuracy가 아님. "
    "평가자 작성 68건 한국 개인정보 holdout은 구현 후 합성 점검이며 fixture와 합쳐 "
    "185회 separate-lane execution으로만 표기하고 "
    "blind/field accuracy·실시간 등록 검증 아님. "
    "field 0/12, field evidence pending. "
    "CycloneDX 1.5 SBOM component 41개, active dependency closure 41개. "
    "제출 시연영상은 180초 H.264 1920x1080, 전체 디코딩, VoxCPM2 한국어 나레이션 오디오 스트림 1."
)


def test_claim_contract_pins_current_product_revision_not_a_stale_test_count() -> None:
    assert contract.CURRENT_PRODUCT_SOURCE_REVISION_SHORT == "72e2aea"


def test_claim_contract_accepts_separated_historical_31_and_current_14() -> None:
    assert contract.claim_surface_errors(HONEST) == []


def test_claim_contract_rejects_current_31_and_stale_revision() -> None:
    errors = contract.claim_surface_errors(
        HONEST.replace("후보 14건", "후보 31건") + " current-source 9f2fd7e"
    )
    assert "stale_claim:stale_current_candidates_31" in errors
    assert "stale_claim:stale_current_revision_9f2fd7e" in errors


def test_claim_contract_rejects_stale_pytest_1317() -> None:
    errors = contract.claim_surface_errors(HONEST + " 1,317 passed, 2 skipped")
    assert "stale_claim:stale_pytest_1317" in errors


def test_claim_contract_requires_product_regression_not_detector_accuracy() -> None:
    missing_regression = HONEST.replace("product source 72e2aea 최종 full-regression receipt", "many tests")
    errors = contract.claim_surface_errors(missing_regression)
    assert "missing_claim:product_regression_current_source" in errors
    assert "missing_claim:product_regression_receipt" in errors


def test_claim_contract_requires_completed_current_regression_accounting() -> None:
    errors = contract.claim_surface_errors(
        HONEST.replace("tested revision add8fe38", "tested revision pending")
        .replace("3,265 collected", "count pending")
        .replace("3,261 passed", "pass pending")
        .replace("4 skipped", "skip pending")
        .replace("0 failed / 0 errors", "result pending")
    )
    assert "missing_claim:product_regression_tested_revision" in errors
    assert "missing_claim:product_regression_collected_3265" in errors
    assert "missing_claim:product_regression_passed_3261" in errors
    assert "missing_claim:product_regression_skipped_4" in errors
    assert "missing_claim:product_regression_zero_failures" in errors


def test_claim_contract_rejects_stale_regression_3191_and_six_skips() -> None:
    errors = contract.claim_surface_errors(
        HONEST + " 이전 기록은 3,191 passed, 6 skipped였다."
    )
    assert "stale_claim:stale_pytest_3191" in errors
    assert "stale_claim:stale_pytest_skipped_6" in errors


def test_claim_contract_requires_field_0_of_12_and_demo_narration_audio() -> None:
    errors = contract.claim_surface_errors(
        HONEST.replace("field 0/12", "field pending").replace("VoxCPM2 한국어 나레이션 오디오 스트림 1", "")
    )
    assert "missing_claim:field_0_of_12" in errors
    assert "missing_claim:demo_narration_audio" in errors


def test_claim_contract_keeps_juliet_replay_as_regression_not_holdout() -> None:
    errors = contract.claim_surface_errors(
        HONEST.replace("독립 holdout이 아님", "새 독립 holdout")
    )
    assert "missing_claim:not_new_holdout" in errors


def test_source_metrics_keep_historical_31_and_current_14_apart() -> None:
    historical = {
        "app_count": 12,
        "candidate_count": 31,
        "reviewer_count": 3,
        "true_positive_probe_detected": 11,
        "true_positive_probe_count": 11,
    }
    current = {
        "app_count": 12,
        "candidate_count": 14,
        "true_positive_probe_count": 11,
        "true_positive_probe_detected": 11,
        "benign_probe_count": 1,
        "benign_probe_detected": 1,
    }
    first = {"true_positive": 180, "false_negative": 30, "false_positive": 0, "true_negative": 210}
    replay = {
        "true_positive": 210,
        "false_negative": 0,
        "claim_boundary": {"not_an_independent_holdout": True},
    }
    assert contract.source_metrics_match_contract(historical, current, first, replay) is True
    current_conflated = dict(current)
    current_conflated["candidate_count"] = 31
    assert contract.source_metrics_match_contract(historical, current_conflated, first, replay) is False
    historical_conflated = dict(historical)
    historical_conflated["candidate_count"] = 14
    assert contract.source_metrics_match_contract(historical_conflated, current, first, replay) is False


def test_live_contest_claim_surfaces_match_contract() -> None:
    for path in CLAIM_FILES:
        errors = contract.claim_surface_errors(path.read_text(encoding="utf-8"))
        assert errors == [], path.as_posix()
        text = path.read_text(encoding="utf-8")
        assert "9f2fd7e" not in text
        assert "1,317 passed" not in text
        assert "3,101 passed" not in text
        assert "3,191 passed" not in text
        assert "6 skipped" not in text
        assert "72e2aea" in text
        assert "add8fe38" in text
        assert "full-regression receipt" in text
        assert "3,265 collected" in text
        assert "3,261 passed" in text
        assert "4 skipped" in text
        assert "185회 separate-lane execution" in text
        assert "평가자 작성" in text
        assert "구현 후" in text
        assert "합성 점검" in text
        assert "blind/field accuracy·실시간 등록 검증 아님" in text
        assert "candidate 31건" in text or "후보 31" in text
        assert "후보 14" in text
        assert "9488898" in text
        assert contract.component_count_claim_errors(text, contract.DECLARED_SBOM_COMPONENT_COUNT) == []


def _live_declared_component_counts() -> dict[str, int]:
    sbom = json.loads((ROOT / "sbom.cdx.json").read_text(encoding="utf-8"))
    license_report = json.loads((ROOT / "license-report.json").read_text(encoding="utf-8"))
    submission_sbom = json.loads((ROOT / "submission" / "release" / "sbom.cdx.json").read_text(encoding="utf-8"))
    submission_license = json.loads(
        (ROOT / "submission" / "release" / "license-report.json").read_text(encoding="utf-8")
    )
    return {
        "sbom": len(sbom["components"]),
        "license_report": int(license_report["component_count"]),
        "submission_sbom": len(submission_sbom["components"]),
        "submission_license": int(submission_license["component_count"]),
    }


def test_claim_surfaces_agree_with_declared_sbom_and_license_component_counts() -> None:
    counts = _live_declared_component_counts()
    expected = contract.DECLARED_SBOM_COMPONENT_COUNT
    assert set(counts.values()) == {expected}
    stale = 40 if expected != 40 else 42
    for path in CLAIM_FILES:
        text = path.read_text(encoding="utf-8")
        assert contract.claimed_component_counts(text) == {expected}, path.as_posix()
        assert f"component {stale}개" not in text
        assert f"{stale}개 component" not in text
        assert f"closure {stale}개" not in text
        assert contract.component_count_claim_errors(text, expected) == []
        assert contract.component_count_claim_errors(text, stale) != []


def test_claim_contract_rejects_sbom_component_count_40_41_split() -> None:
    split = HONEST.replace("component 41개", "component 40개").replace("closure 41개", "closure 40개")
    errors = contract.claim_surface_errors(split)
    assert "missing_claim:sbom_or_closure_count" in errors
    assert "stale_claim:sbom_or_closure_40" in errors
    assert contract.component_count_claim_errors(HONEST, 41) == []
    assert "stale_claim:sbom_or_closure_40" in contract.component_count_claim_errors(
        HONEST.replace("41개", "40개"), 41
    )
