from __future__ import annotations

import base64
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "contest-2026-result-report.html"
SUBMISSION_REPORT = ROOT / "submission" / "report" / "k-guard-contest-result-report.html"


def test_contest_report_has_required_submission_content() -> None:
    html = REPORT.read_text(encoding="utf-8")
    submission_html = SUBMISSION_REPORT.read_text(encoding="utf-8")

    required = (
        '<html lang="ko">',
        "K-Guard MCP",
        "안경선배",
        "이풍현",
        "공무원",
        "40세",
        "check_my_app",
        "continue_review",
        "start_review_before_ship",
        "Guardian high",
        "사이트",
        "API",
        "데이터",
        "운영",
        "OWASP BenchmarkPython",
        "NIST Juliet 최초 결과",
        "공개 개발 앱 12개",
        "fresh-process 24회",
        "high·critical candidate 31건",
        "동일 모델 계열 fresh AI reviewer 3개",
        "31/31 만장일치 TP",
        "자동 release-blocking 후보 14건",
        "vulnerable probe 11/11",
        "benign probe 1/1",
        "TP 180/FN 30/FP 0/TN 210",
        "TP 210/FN 0/FP 0/TN 210",
        "새 독립 holdout이 아님",
        "72e2aea",
        "full-regression receipt",
        "bounded product regression",
        "평가자 작성",
        "구현 후",
        "합성 점검",
        "blind/field accuracy·실시간 등록 검증 아님",
        "detector accuracy가 아니",
        "VALID LANES MIXED",
        "EXTERNAL URLS PENDING",
        "package final pending",
        "FIELD EVIDENCE PENDING",
        "인간 판정이 아님",
        "field recall",
        "release authority",
        "0/12",
        "오디오 스트림 없음",
        "수상 근거 미입증",
        "active dependency closure 41개",
        "SBOM 41개 component",
    )

    for text in required:
        assert text in html
        assert text in submission_html


def test_contest_report_rejects_stale_or_overstated_claims() -> None:
    reports = (
        REPORT.read_text(encoding="utf-8"),
        SUBMISSION_REPORT.read_text(encoding="utf-8"),
    )

    stale_patterns = (
        r"44\.44\s*%",
        r"\bTP\s*[:=/]?\s*16\b",
        r"\bFP\s*[:=/]?\s*17\b",
        r"대표\s*취약점\s*탐지\s*0\s*/\s*12",
        r"9f2fd7e",
        r"1\s*,\s*317\s+passed",
        r"3\s*,\s*101\s+passed",
        r"3\s*,\s*191\s+passed",
        r"3\s*,\s*220\s+passed",
        r"\b6\s+skipped\b",
        r"현재\s*코드[^\n]{0,180}후보\s*31",
    )
    for html in reports:
        for pattern in stale_patterns:
            assert re.search(pattern, html, re.IGNORECASE) is None

        assert "결과보고서 제출 후보" not in html
        assert "공개 저장소 URL은 제출 전 확정" not in html
        assert "vulnerable-apps-12-20260713" not in html
        assert "EFFECTIVENESS HOLD" not in html
        assert "후보 14" in html
        assert "9488898" in html
        assert "후보 31" in html or "candidate 31건" in html
        assert "component 40개" not in html
        assert "SBOM 40개" not in html
        assert "closure 40개" not in html
        assert "active dependency closure 41개" in html
        assert "SBOM 41개 component" in html
        assert "PACKAGE READY" not in html
        assert "current verdict: package ready" not in html.casefold()
        assert "PACKAGE VERIFICATION BLOCKED" not in html
        assert "PUBLIC DEV PASS" not in html
        assert "VALID LANES MIXED" in html
        assert "EXTERNAL URLS PENDING" in html
        assert "package final pending" in html


def test_contest_report_preserves_korean_word_boundaries() -> None:
    html = REPORT.read_text(encoding="utf-8")
    lowered = html.lower()

    assert "word-break: keep-all" in html
    assert "line-break: strict" in html
    assert "letter-spacing: 0" in html
    assert "hyphens: none" in html
    assert "<br" not in lowered
    assert "<wbr" not in lowered


def test_contest_report_is_exactly_ten_fixed_a4_sheets() -> None:
    html = REPORT.read_text(encoding="utf-8")

    assert html.count('<section class="sheet') == 10
    assert "@page" in html
    assert "size: A4" in html
    assert "@media print" in html
    assert "height: 297mm" in html
    assert "max-height: 297mm" in html
    assert "page-break-inside: avoid" in html
    legacy_brand = "체크" + "남방"
    assert legacy_brand not in html


def test_contest_report_mobile_body_copy_has_14px_floor() -> None:
    html = REPORT.read_text(encoding="utf-8")

    mobile = html.split("@media (max-width: 480px)", 1)[1].split("@page", 1)[0]
    assert "font-size: 16px" in mobile
    assert "font-size: 14px !important" in mobile
    assert ".sheet p" in mobile
    assert ".sheet li" in mobile
    assert ".sheet td" in mobile
    assert ".sheet code" in mobile


def test_contest_report_embeds_a_valid_standalone_hero() -> None:
    html = REPORT.read_text(encoding="utf-8")
    match = re.search(
        r'<img class="cover-image" src="data:image/webp;base64,([^"]+)"', html
    )

    assert match is not None
    image = base64.b64decode(match.group(1), validate=True)
    assert len(image) > 50_000
    assert image.startswith(b"RIFF")
    assert image[8:12] == b"WEBP"
    assert "../src/k_guard_mcp/assets" not in html
