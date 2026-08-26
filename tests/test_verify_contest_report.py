from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_contest_report as verifier


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "contest-2026-result-report.html"


def test_content_verifier_accepts_current_report() -> None:
    html = REPORT.read_text(encoding="utf-8")

    assert verifier.validate_content(html) == []


@pytest.mark.parametrize(
    "stale_claim",
    (
        "엄격한 조치 가능률 44.44%",
        "TP16 / FP17",
        "대표 취약점 탐지 0/12",
        "1,317 passed",
        "9f2fd7e",
        "component 40개",
        "active dependency closure 40개",
    ),
)
def test_content_verifier_fails_on_named_stale_claims(stale_claim: str) -> None:
    html = REPORT.read_text(encoding="utf-8")

    errors = verifier.validate_content(f"{html}<p>{stale_claim}</p>")

    assert any("stale claim is present" in error for error in errors)


def test_juliet_first_result_precedes_same_corpus_regression() -> None:
    html = REPORT.read_text(encoding="utf-8")
    first = "TP 180/FN 30/FP 0/TN 210"
    regression = "TP 210/FN 0/FP 0/TN 210"

    assert html.index(first) < html.index(regression)
    assert "Juliet replay는 integrity FAIL로 제외" in html
    assert "새 독립 holdout이 아님" in html


def test_contest_report_renders_as_exactly_ten_a4_pages(tmp_path: Path) -> None:
    pdf = tmp_path / "contest-2026-result-report.pdf"

    result = verifier.verify_report(REPORT, pdf_path=pdf)

    assert result.renderer in {"Playwright Chromium", "headless Chromium"}
    assert result.sheet_count == 10
    assert result.page_count == 10
    assert len(result.page_sizes) == 10
    assert all(abs(width - 595.0) <= 2 for width, _ in result.page_sizes)
    assert all(abs(height - 842.0) <= 2 for _, height in result.page_sizes)
    if result.min_mobile_body_font_px is not None:
        assert result.min_mobile_body_font_px >= 14
    assert pdf.stat().st_size > 100_000
