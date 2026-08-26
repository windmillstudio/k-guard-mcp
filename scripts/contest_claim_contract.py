from __future__ import annotations

import re
from typing import Any


HISTORICAL_PUBLIC_APP_COUNT = 12
HISTORICAL_CANDIDATE_COUNT = 31
HISTORICAL_REVIEWER_COUNT = 3
HISTORICAL_TRUE_POSITIVE_PROBE_COUNT = 11
CURRENT_PUBLIC_APP_COUNT = 12
CURRENT_PUBLIC_RUNS_PER_APP = 2
CURRENT_RELEASE_BLOCKING_CANDIDATE_COUNT = 14
CURRENT_TRUE_POSITIVE_PROBE_COUNT = 11
CURRENT_BENIGN_PROBE_COUNT = 1
CURRENT_PRODUCT_SOURCE_REVISION_SHORT = "72e2aea"
JULIET_FIRST_TRUE_POSITIVE = 180
JULIET_FIRST_FALSE_NEGATIVE = 30
JULIET_FIRST_FALSE_POSITIVE = 0
JULIET_FIRST_TRUE_NEGATIVE = 210
JULIET_REPLAY_TRUE_POSITIVE = 210
JULIET_REPLAY_FALSE_NEGATIVE = 0
DECLARED_SBOM_COMPONENT_COUNT = 41

REQUIRED_CLAIM_GROUPS: dict[str, tuple[str, ...]] = {
    "public_apps_12": ("12개", "12 apps"),
    "historical_candidates_31": ("후보 31", "31 candidates", "candidate 31건"),
    "historical_revision_9488898": ("9488898",),
    "public_reviewers_3": ("3명", "3 reviewers", "reviewer 3", "reviewer 3개"),
    "public_probes_11_of_11": ("11 / 11", "11/11"),
    "benign_probe_1_of_1": ("1 / 1", "1/1"),
    "current_candidates_14": ("후보 14", "candidate 14"),
    "current_replay_repeats": ("24회", "× 2", "x 2", "×2"),
    "same_model_family_boundary": ("동일 모델 계열", "same-model-family", "same model family"),
    "not_human_adjudication": (
        "사람 수동 판정이 아님",
        "인간 판정이 아님",
        "인간 판정이 아니",
        "not human adjudication",
    ),
    "juliet_first_tp180": ("TP 180", "TP180"),
    "juliet_first_fn30": ("FN 30", "FN30"),
    "juliet_replay_tp210": ("TP 210", "TP210"),
    "juliet_replay_fn0": ("FN 0", "FN0"),
    "post_tuning_boundary": ("post-tuning", "수정 후 재생", "수정 후 회귀"),
    "not_new_holdout": ("독립 holdout이 아님", "새 독립 holdout이 아님", "not an independent holdout"),
    "product_regression_current_source": ("72e2aea",),
    "product_regression_tested_revision": ("add8fe38",),
    "product_regression_receipt": ("full-regression receipt",),
    "product_regression_collected_3265": ("3,265 collected", "3265 collected"),
    "product_regression_passed_3261": ("3,261 passed", "3261 passed"),
    "product_regression_skipped_4": ("4 skipped",),
    "product_regression_zero_failures": (
        "0 failed / 0 errors",
        "0 failed·errors",
        "0 failed, 0 errors",
    ),
    "korean_privacy_separate_lanes_185": (
        "185회 separate-lane execution",
        "185 separate-lane executions",
    ),
    "korean_privacy_holdout_68": ("68건", "68/68", "68 / 68", "68-case"),
    "holdout_evaluator_authored": (
        "evaluator-authored",
        "평가자 작성",
        "평가자가 작성",
    ),
    "holdout_post_implementation": ("post-implementation", "구현 후"),
    "holdout_synthetic_inspection": (
        "합성 점검",
        "합성 oracle 점검",
        "synthetic inspection",
        "inspection of synthetic",
    ),
    "holdout_not_blind_field_registry": (
        "blind/field accuracy·실시간 등록 검증 아님",
        "blind/field accuracy·등록 검증 아님",
        "not a blind field-accuracy or registry-validation",
        "not blind evaluation, field accuracy, or live registry validation",
    ),
    "product_regression_boundary": ("bounded product regression", "제품 회귀"),
    "not_detector_accuracy": (
        "detector accuracy가 아님",
        "detector accuracy 아님",
        "detector accuracy가 아니",
        "not detector accuracy",
        "탐지 정확도가 아님",
    ),
    "field_pending": ("field evidence pending", "field 실증 미완료", "현장 실증 미완료"),
    "field_0_of_12": ("0/12", "0 / 12"),
    "demo_narration_audio": (
        "VoxCPM2 한국어 나레이션",
        "오디오 스트림 1",
        "오디오 스트림을 검증",
        "VoxCPM2 narration",
        "audio stream 1",
    ),
    "benchmark_java_hold": (
        "BenchmarkJava 최초 HOLD",
        "BenchmarkJava 성능은 HOLD",
        "BenchmarkJava 최초 성능 verdict HOLD",
        "BenchmarkJava 최초 recall verdict HOLD",
        "BenchmarkJava 최초 결과. 성능 verdict HOLD",
    ),
    "juliet_first_result": (
        "Juliet 최초",
        "Juliet 첫 결과",
        "Juliet Java CWE-89 첫 결과",
    ),
    "historical_owasp_python_inadmissible": (
        "역사적 OWASP Python은 integrity FAIL",
        "역사적 OWASP Python·Juliet replay가 integrity FAIL",
        "OWASP BenchmarkPython 역사 결과 내부 artifact digest·size mismatch integrity FAIL",
        "OWASP BenchmarkPython artifact digest·size mismatch",
    ),
    "historical_juliet_replay_inadmissible": (
        "Juliet replay는 integrity FAIL로 제외",
        "Juliet replay가 integrity FAIL",
        "Juliet post-tuning replay는 integrity FAIL",
        "Juliet post-tuning replay는 제출 정확도 근거에서 제외",
        "Juliet 튜닝 후 회귀 기록상 TP 210/FN 0/FP 0/TN 210이나 first-result digest binding 불일치 integrity FAIL",
        "NIST Juliet 수정 후 재생 기록상 같은 420 unit, TP 210/FN 0/FP 0/TN 210 first-result digest binding 불일치로 integrity FAIL",
    ),
}

_COMPONENT_COUNT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"dependency\s+closure\s+(\d+)\s*개", re.I),
    re.compile(r"component\s+(\d+)\s*개", re.I),
    re.compile(r"(\d+)\s*개\s*component", re.I),
    re.compile(r"\b(\d+)\s+components\b", re.I),
)


def claimed_component_counts(text: str) -> set[int]:
    found: set[int] = set()
    for pattern in _COMPONENT_COUNT_PATTERNS:
        for match in pattern.finditer(text):
            found.add(int(match.group(1)))
    return found


def component_count_claim_errors(text: str, expected_count: int) -> list[str]:
    expected_tokens = (
        f"component {expected_count}개",
        f"{expected_count}개 component",
        f"closure {expected_count}개",
        f"{expected_count} components",
    )
    errors: list[str] = []
    folded = text.casefold()
    if not any(token.casefold() in folded for token in expected_tokens):
        errors.append("missing_claim:sbom_or_closure_count")
    for count in sorted(claimed_component_counts(text) - {expected_count}):
        errors.append(f"stale_claim:sbom_or_closure_{count}")
    return errors


STALE_CLAIM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stale_pytest_1317", re.compile(r"1\s*,\s*317\s+passed", re.I)),
    ("stale_pytest_2819", re.compile(r"2\s*,\s*819\s+passed", re.I)),
    ("stale_pytest_3101", re.compile(r"3\s*,\s*101\s+passed", re.I)),
    ("stale_pytest_3191", re.compile(r"3\s*,\s*191\s+passed", re.I)),
    ("stale_pytest_3220", re.compile(r"3\s*,\s*220\s+passed", re.I)),
    ("stale_pytest_skipped_6", re.compile(r"(?<!\d)6\s+skipped(?![A-Za-z])", re.I)),
    ("stale_current_revision_9f2fd7e", re.compile(r"9f2fd7e", re.I)),
    ("stale_actionable_rate_44_44", re.compile(r"44\.44\s*%")),
    ("stale_tp16", re.compile(r"\bTP\s*[:=/]?\s*16\b", re.I)),
    ("stale_fp17", re.compile(r"\bFP\s*[:=/]?\s*17\b", re.I)),
    ("stale_detection_0_12", re.compile(r"대표\s*취약점\s*탐지\s*0\s*/\s*12")),
    (
        "stale_current_candidates_31",
        re.compile(
            r"현재\s*코드[^\n.!?。]{0,120}후보\s*31"
            r"|현재\s*코드[^\n.!?。]{0,120}candidate\s*31"
            r"|revision\s*9f2fd7e[^\n.!?。]{0,120}후보\s*31"
            r"|current-source\s*9f2fd7e",
            re.I,
        ),
    ),
)


def _exact_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def source_metrics_match_contract(
    historical: dict[str, Any],
    current: dict[str, Any],
    juliet_first: dict[str, Any],
    juliet_replay: dict[str, Any],
) -> bool:
    replay_boundary = (
        juliet_replay.get("claim_boundary")
        if isinstance(juliet_replay.get("claim_boundary"), dict)
        else {}
    )
    return (
        _exact_int(historical.get("app_count")) == HISTORICAL_PUBLIC_APP_COUNT
        and _exact_int(historical.get("candidate_count")) == HISTORICAL_CANDIDATE_COUNT
        and _exact_int(historical.get("reviewer_count")) == HISTORICAL_REVIEWER_COUNT
        and _exact_int(historical.get("true_positive_probe_detected"))
        == HISTORICAL_TRUE_POSITIVE_PROBE_COUNT
        and _exact_int(historical.get("true_positive_probe_count"))
        == HISTORICAL_TRUE_POSITIVE_PROBE_COUNT
        and _exact_int(current.get("app_count")) == CURRENT_PUBLIC_APP_COUNT
        and _exact_int(current.get("candidate_count"))
        == CURRENT_RELEASE_BLOCKING_CANDIDATE_COUNT
        and _exact_int(current.get("true_positive_probe_count"))
        == CURRENT_TRUE_POSITIVE_PROBE_COUNT
        and _exact_int(current.get("true_positive_probe_detected"))
        == CURRENT_TRUE_POSITIVE_PROBE_COUNT
        and _exact_int(current.get("benign_probe_count")) == CURRENT_BENIGN_PROBE_COUNT
        and _exact_int(current.get("benign_probe_detected")) == CURRENT_BENIGN_PROBE_COUNT
        and _exact_int(juliet_first.get("true_positive")) == JULIET_FIRST_TRUE_POSITIVE
        and _exact_int(juliet_first.get("false_negative")) == JULIET_FIRST_FALSE_NEGATIVE
        and _exact_int(juliet_first.get("false_positive")) == JULIET_FIRST_FALSE_POSITIVE
        and _exact_int(juliet_first.get("true_negative")) == JULIET_FIRST_TRUE_NEGATIVE
        and _exact_int(juliet_replay.get("true_positive")) == JULIET_REPLAY_TRUE_POSITIVE
        and _exact_int(juliet_replay.get("false_negative")) == JULIET_REPLAY_FALSE_NEGATIVE
        and replay_boundary.get("not_an_independent_holdout") is True
    )


def claim_surface_errors(text: str) -> list[str]:
    errors: list[str] = []
    folded = text.casefold()
    for name, alternatives in REQUIRED_CLAIM_GROUPS.items():
        if not any(token.casefold() in folded for token in alternatives):
            errors.append(f"missing_claim:{name}")
    for label, pattern in STALE_CLAIM_PATTERNS:
        if pattern.search(text):
            errors.append(f"stale_claim:{label}")
    errors.extend(component_count_claim_errors(text, DECLARED_SBOM_COMPONENT_COUNT))
    return errors
