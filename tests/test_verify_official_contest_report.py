from __future__ import annotations

import builtins
import hashlib
from pathlib import Path

import pytest

from scripts import verify_official_contest_report as verifier


ROOT = Path(__file__).resolve().parents[1]

HONEST_KOREAN_CLAIMS = (
    "평가자 작성 68건 한국 개인정보 holdout은 구현 후 합성 점검이며 "
    "고정 시험 조건에서 재현했다. "
    "취약 probe 11/11, benign training fixture 1/1."
)
HONEST_ENGLISH_CLAIMS = (
    "The evaluator-authored 68-case Korean privacy holdout is a "
    "post-implementation synthetic inspection under fixed test conditions. Public replay results "
    "are 11/11 vulnerable probes detected plus 1/1 benign training fixture."
)


@pytest.fixture
def allow_layout_without_award_claims(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(verifier, "claim_boundary_errors", lambda _text: [])


@pytest.mark.usefixtures("allow_layout_without_award_claims")
def test_current_official_report_pair_has_valid_layout_and_honest_url_hold() -> None:
    result = verifier.verify_official_report()

    assert result.page_count == 6
    assert result.body_page_count == 3
    assert result.appendix_page_count == 3
    assert result.docx_section_count == 2
    assert result.repository_url == verifier.REPOSITORY_URL
    assert result.youtube_url == ""
    assert result.placeholder_count == 3
    assert result.external_urls_complete is False


@pytest.mark.usefixtures("allow_layout_without_award_claims")
def test_current_official_report_rejects_final_mode_until_urls_exist() -> None:
    with pytest.raises(verifier.OfficialReportVerificationError, match="URLs are not complete"):
        verifier.verify_official_report(require_external_urls=True)


@pytest.mark.usefixtures("allow_layout_without_award_claims")
def test_official_report_verifies_without_optional_pypdf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "pypdf":
            raise ImportError("pypdf deliberately unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    result = verifier.verify_official_report()

    assert result.body_page_count == 3
    assert result.appendix_page_count == 3


@pytest.mark.parametrize(
    ("page_count", "page_sizes", "message"),
    (
        (5, ((595.0, 842.0),) * 5, "expected 6 PDF pages"),
        (
            6,
            ((595.0, 842.0),) * 4 + ((842.0, 595.0),) * 2,
            "body/appendix page contract failed",
        ),
        (
            6,
            ((600.0, 842.0),) * 3 + ((842.0, 595.0),) * 3,
            "every PDF page must be A4",
        ),
    ),
)
@pytest.mark.usefixtures("allow_layout_without_award_claims")
def test_official_report_rejects_invalid_pdf_layout(
    monkeypatch: pytest.MonkeyPatch,
    page_count: int,
    page_sizes: tuple[tuple[float, float], ...],
    message: str,
) -> None:
    monkeypatch.setattr(verifier, "_pdf_metadata", lambda _pdf: (page_count, page_sizes))

    with pytest.raises(verifier.OfficialReportVerificationError, match=message):
        verifier.verify_official_report()


@pytest.mark.usefixtures("allow_layout_without_award_claims")
def test_official_report_attestation_binds_both_files() -> None:
    result = verifier.verify_official_report()
    payload = verifier.build_attestation(
        verifier.DEFAULT_DOCX,
        verifier.DEFAULT_PDF,
        result,
        visual_reviewed_all_pages=True,
    )

    assert payload["schema"] == "k_guard_official_contest_report_verification.v1"
    assert payload["docx_sha256"] == hashlib.sha256(verifier.DEFAULT_DOCX.read_bytes()).hexdigest()
    assert payload["pdf_sha256"] == hashlib.sha256(verifier.DEFAULT_PDF.read_bytes()).hexdigest()
    assert payload["external_urls_complete"] is False
    assert payload["visual_reviewed_all_pages"] is True


@pytest.mark.usefixtures("allow_layout_without_award_claims")
def test_official_report_attestation_does_not_invent_visual_review() -> None:
    result = verifier.verify_official_report()
    payload = verifier.build_attestation(
        verifier.DEFAULT_DOCX,
        verifier.DEFAULT_PDF,
        result,
        visual_reviewed_all_pages=False,
    )

    assert payload["visual_reviewed_all_pages"] is False


def test_claim_boundary_errors_accept_korean_and_english_award_wording() -> None:
    assert verifier.claim_boundary_errors(HONEST_KOREAN_CLAIMS) == []
    assert verifier.claim_boundary_errors(HONEST_ENGLISH_CLAIMS) == []


@pytest.mark.parametrize(
    ("removed", "code"),
    (
        ("평가자 작성", "missing_claim:holdout_evaluator_authored"),
        ("구현 후", "missing_claim:holdout_post_implementation"),
        ("합성 점검", "missing_claim:holdout_synthetic_inspection"),
        (
            "고정 시험 조건",
            "missing_claim:holdout_fixed_scope",
        ),
        ("취약 probe 11/11", "missing_claim:public_replay_vulnerable_11_of_11"),
        (
            "benign training fixture 1/1",
            "missing_claim:public_replay_benign_1_of_1",
        ),
        ("68건", "missing_claim:korean_privacy_holdout_68"),
    ),
)
def test_claim_boundary_errors_require_holdout_and_split_probe_claims(
    removed: str,
    code: str,
) -> None:
    errors = verifier.claim_boundary_errors(HONEST_KOREAN_CLAIMS.replace(removed, "omitted"))

    assert code in errors


def test_claim_boundary_errors_reject_undifferentiated_12_of_12_probe_claim() -> None:
    errors = verifier.claim_boundary_errors(
        HONEST_KOREAN_CLAIMS + " 표적 probe 12/12 탐지"
    )

    assert "stale_claim:undifferentiated_probe_12_of_12" in errors
    assert verifier.claim_boundary_errors(HONEST_KOREAN_CLAIMS + " field 0/12") == []


def test_integrity_reference_requires_manifest_and_rejects_embedded_wheel_digest() -> None:
    assert verifier.integrity_reference_errors(
        "두 clean build 바이트 동일, 상세 SHA-256은 submission/SHA256SUMS와 일치"
    ) == []
    assert verifier.integrity_reference_errors("두 clean build 바이트 동일") == [
        "missing_claim:submission_sha256sums_reference"
    ]
    assert verifier.integrity_reference_errors(
        "submission/SHA256SUMS와 일치, wheel SHA-256 c22e19f4f1c6…3aaf97"
    ) == ["stale_claim:embedded_mutable_wheel_sha256"]


def test_current_official_report_satisfies_award_claim_boundaries() -> None:
    result = verifier.verify_official_report()

    assert result.body_page_count == 3
    assert result.appendix_page_count == 3


def test_official_report_required_text_binds_final_rc_claims() -> None:
    required = set(verifier.REQUIRED_TEXT)

    assert "72e2aea" in required
    assert "full-regression receipt" in required
    assert "185회 separate-lane" in required
    assert "실제 MCP 클라이언트 3종" in required
    assert "168초" in required
    assert "BenchmarkJava 504건" not in required
    assert "integrity FAIL" not in required
    assert "3,191 passed" not in required
    assert "3,220 passed / 6 skipped / 0 failed" not in required
    assert "TP 45, FN 0, FP 0, TN 45" not in required


def test_official_report_surfaces_claim_boundary_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        verifier,
        "claim_boundary_errors",
        lambda _text: ["missing_claim:holdout_evaluator_authored"],
    )

    with pytest.raises(
        verifier.OfficialReportVerificationError,
        match="missing_claim:holdout_evaluator_authored",
    ):
        verifier.verify_official_report()
