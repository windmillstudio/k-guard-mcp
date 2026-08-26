from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256
from verify_contest_report import _pdf_metadata


REPORT_STEM = "2026 오픈소스 개발자대회 결과보고서_1123(AI쀼)"
DEFAULT_DOCX = ROOT / "submission" / "report" / f"{REPORT_STEM}.docx"
DEFAULT_PDF = ROOT / "submission" / "report" / f"{REPORT_STEM}.pdf"
EXPECTED_TOTAL_PAGES = 6
MAX_BODY_PAGES = 5
EXPECTED_APPENDIX_PAGES = 3
A4_SHORT_POINTS = 595.0
A4_LONG_POINTS = 842.0
WORD_NAMESPACE = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NAMESPACES = {"w": WORD_NAMESPACE}
REQUIRED_TEXT = (
    "2026년 오픈소스 개발자대회 결과보고서",
    "AI쀼",
    "안경선배",
    "72e2aea",
    "full-regression receipt",
    "28 tools",
    "185회 separate-lane",
    "실제 MCP 클라이언트 3종",
    "168초",
    "41 components",
    "MIT License",
    "Grok 4.6",
    "Claude Opus 5",
    "GPT-5.6 Sol/Codex",
    "붙임1",
    "붙임2",
)
PLACEHOLDER_MARKERS = ("제출 전 URL 입력 필요", "공개 승인 대기")
REPOSITORY_URL = "https://github.com/windmillstudio/k-guard-mcp"
YOUTUBE_URL_PATTERN = re.compile(
    r"https://(?:www\.)?(?:youtube\.com/watch\?v=[A-Za-z0-9_-]+|youtu\.be/[A-Za-z0-9_-]+)"
)
REQUIRED_CLAIM_GROUPS: dict[str, tuple[str, ...]] = {
    "korean_privacy_holdout_68": (
        "68건",
        "holdout 68회",
        "68/68",
        "68 / 68",
        "68-case",
    ),
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
    "holdout_fixed_scope": (
        "고정 시험 조건",
        "fixed test conditions",
        "fixed synthetic test scope",
    ),
    "public_replay_vulnerable_11_of_11": (
        "취약 probe 11 / 11",
        "취약 probe 11/11",
        "vulnerable probe 11/11",
        "vulnerable probes 11/11",
        "11/11 vulnerable probe",
        "11 / 11 vulnerable probe",
    ),
    "public_replay_benign_1_of_1": (
        "benign training fixture 1 / 1",
        "benign training fixture 1/1",
        "1/1 benign training fixture",
        "1 / 1 benign training fixture",
        "benign probe 1/1",
        "benign probe 1 / 1",
        "benign fixture 1/1",
        "benign fixture 1 / 1",
    ),
}
STALE_CLAIM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "undifferentiated_probe_12_of_12",
        re.compile(
            r"probe[s]?\s*12\s*/\s*12"
            r"|12\s*/\s*12\s*(?:탐지|detected|취약|vulnerab)",
            re.I,
        ),
    ),
)
OFFICIAL_REPORT_INTEGRITY_REFERENCE = "submission/SHA256SUMS"
EMBEDDED_WHEEL_DIGEST_PATTERN = re.compile(
    r"\bwheel\s+SHA-256\s+[0-9a-f]{8}",
    re.I,
)


class OfficialReportVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class OfficialReportResult:
    page_count: int
    body_page_count: int
    appendix_page_count: int
    page_sizes: tuple[tuple[float, float], ...]
    docx_section_count: int
    repository_url: str
    youtube_url: str
    placeholder_count: int
    external_urls_complete: bool


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def claim_boundary_errors(text: str) -> list[str]:
    errors: list[str] = []
    folded = text.casefold()
    for name, alternatives in REQUIRED_CLAIM_GROUPS.items():
        if not any(token.casefold() in folded for token in alternatives):
            errors.append(f"missing_claim:{name}")
    for label, pattern in STALE_CLAIM_PATTERNS:
        if pattern.search(text):
            errors.append(f"stale_claim:{label}")
    return errors


def integrity_reference_errors(text: str) -> list[str]:
    errors: list[str] = []
    if OFFICIAL_REPORT_INTEGRITY_REFERENCE not in text:
        errors.append("missing_claim:submission_sha256sums_reference")
    if EMBEDDED_WHEEL_DIGEST_PATTERN.search(text):
        errors.append("stale_claim:embedded_mutable_wheel_sha256")
    return errors


def _git_revision() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    revision = completed.stdout.strip()
    return revision if completed.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", revision) else ""


def _safe_docx_members(archive: zipfile.ZipFile) -> None:
    seen: set[str] = set()
    total = 0
    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        parts = Path(name).parts
        if (
            not name
            or name.startswith("/")
            or ".." in parts
            or re.match(r"^[A-Za-z]:", name)
            or name.casefold() in seen
        ):
            raise OfficialReportVerificationError("DOCX contains an unsafe or duplicate member")
        seen.add(name.casefold())
        total += info.file_size
        if total > 50_000_000:
            raise OfficialReportVerificationError("DOCX exceeds the verification budget")


def _docx_contract(docx: Path) -> tuple[str, int]:
    try:
        with zipfile.ZipFile(docx) as archive:
            _safe_docx_members(archive)
            document_xml = archive.read("word/document.xml")
    except (KeyError, OSError, zipfile.BadZipFile) as error:
        raise OfficialReportVerificationError(f"DOCX package is unreadable: {error}") from error

    try:
        root = ElementTree.fromstring(document_xml)
    except ElementTree.ParseError as error:
        raise OfficialReportVerificationError("DOCX document XML is malformed") from error

    paragraphs: list[str] = []
    for paragraph in root.findall(".//w:p", NAMESPACES):
        text = "".join(node.text or "" for node in paragraph.findall(".//w:t", NAMESPACES))
        if text.strip():
            paragraphs.append(text.strip())
    visible_text = "\n".join(paragraphs)

    missing = [claim for claim in REQUIRED_TEXT if claim not in visible_text]
    if missing:
        raise OfficialReportVerificationError(f"required report text is missing: {missing}")
    boundary_errors = claim_boundary_errors(visible_text)
    if boundary_errors:
        raise OfficialReportVerificationError(
            f"required claim boundary failed: {boundary_errors}"
        )
    integrity_errors = integrity_reference_errors(visible_text)
    if integrity_errors:
        raise OfficialReportVerificationError(
            f"release integrity reference failed: {integrity_errors}"
        )
    if visible_text.index("붙임1") >= visible_text.index("붙임2"):
        raise OfficialReportVerificationError("DOCX appendices are out of order")

    sections = root.findall(".//w:sectPr", NAMESPACES)
    if len(sections) != 2:
        raise OfficialReportVerificationError(f"expected two DOCX sections, found {len(sections)}")
    orientations: list[str] = []
    for section in sections:
        page_size = section.find("w:pgSz", NAMESPACES)
        if page_size is None:
            raise OfficialReportVerificationError("DOCX section page size is missing")
        width = int(page_size.get(f"{{{WORD_NAMESPACE}}}w", "0"))
        height = int(page_size.get(f"{{{WORD_NAMESPACE}}}h", "0"))
        orientation = page_size.get(f"{{{WORD_NAMESPACE}}}orient", "portrait")
        if not (11_850 <= min(width, height) <= 11_950 and 16_750 <= max(width, height) <= 16_950):
            raise OfficialReportVerificationError("DOCX section is not A4")
        orientations.append(orientation)
    if orientations != ["portrait", "landscape"]:
        raise OfficialReportVerificationError(f"unexpected DOCX section orientations: {orientations}")
    return visible_text, len(sections)


def _is_a4(width: float, height: float) -> bool:
    return abs(min(width, height) - A4_SHORT_POINTS) <= 2 and abs(max(width, height) - A4_LONG_POINTS) <= 2


def verify_official_report(
    docx: Path = DEFAULT_DOCX,
    pdf: Path = DEFAULT_PDF,
    *,
    require_external_urls: bool = False,
) -> OfficialReportResult:
    docx = docx.resolve()
    pdf = pdf.resolve()
    if not docx.is_file() or not pdf.is_file():
        raise OfficialReportVerificationError("official DOCX and PDF are both required")

    visible_text, section_count = _docx_contract(docx)
    page_count, page_sizes = _pdf_metadata(pdf)
    if page_count != EXPECTED_TOTAL_PAGES or len(page_sizes) != EXPECTED_TOTAL_PAGES:
        raise OfficialReportVerificationError(
            f"expected {EXPECTED_TOTAL_PAGES} PDF pages, found {page_count}"
        )
    if any(not _is_a4(width, height) for width, height in page_sizes):
        raise OfficialReportVerificationError("every PDF page must be A4")
    body_page_count = 0
    for width, height in page_sizes:
        if width >= height:
            break
        body_page_count += 1
    appendix_page_count = page_count - body_page_count
    if (
        body_page_count == 0
        or body_page_count > MAX_BODY_PAGES
        or appendix_page_count != EXPECTED_APPENDIX_PAGES
        or any(width <= height for width, height in page_sizes[body_page_count:])
    ):
        raise OfficialReportVerificationError("official report body/appendix page contract failed")

    placeholder_count = sum(visible_text.count(marker) for marker in PLACEHOLDER_MARKERS)
    repository_url = REPOSITORY_URL if REPOSITORY_URL in visible_text else ""
    youtube_match = YOUTUBE_URL_PATTERN.search(visible_text)
    youtube_url = youtube_match.group(0) if youtube_match else ""
    external_urls_complete = bool(repository_url and youtube_url and placeholder_count == 0)
    if require_external_urls and not external_urls_complete:
        raise OfficialReportVerificationError("public repository and YouTube URLs are not complete")

    return OfficialReportResult(
        page_count=page_count,
        body_page_count=body_page_count,
        appendix_page_count=appendix_page_count,
        page_sizes=tuple(page_sizes),
        docx_section_count=section_count,
        repository_url=repository_url,
        youtube_url=youtube_url,
        placeholder_count=placeholder_count,
        external_urls_complete=external_urls_complete,
    )


def build_attestation(
    docx: Path,
    pdf: Path,
    result: OfficialReportResult,
    *,
    visual_reviewed_all_pages: bool,
) -> dict[str, object]:
    return {
        "schema": "k_guard_official_contest_report_verification.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_revision": _git_revision(),
        "package_tree_hash_schema": TREE_HASH_SCHEMA,
        "analyzer_package_tree_sha256": package_tree_sha256(ROOT / "src" / "k_guard_mcp"),
        "docx_sha256": _sha256(docx.resolve()),
        "pdf_sha256": _sha256(pdf.resolve()),
        "page_count": result.page_count,
        "body_page_count": result.body_page_count,
        "body_page_limit": MAX_BODY_PAGES,
        "appendix_page_count": result.appendix_page_count,
        "page_sizes_points": [
            [round(width, 3), round(height, 3)] for width, height in result.page_sizes
        ],
        "docx_section_count": result.docx_section_count,
        "a4_mixed_orientation_verified": True,
        "repository_url": result.repository_url,
        "youtube_url": result.youtube_url,
        "placeholder_count": result.placeholder_count,
        "external_urls_complete": result.external_urls_complete,
        "visual_reviewed_all_pages": visual_reviewed_all_pages,
        "raw_returned": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the official contest DOCX/PDF pair.")
    parser.add_argument("--docx", type=Path, default=DEFAULT_DOCX)
    parser.add_argument("--pdf", type=Path, default=DEFAULT_PDF)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--require-external-urls", action="store_true")
    parser.add_argument(
        "--visual-review-confirmed",
        action="store_true",
        help="Record that a human or reviewing agent visually inspected every rendered PDF page.",
    )
    args = parser.parse_args(argv)
    try:
        result = verify_official_report(
            args.docx,
            args.pdf,
            require_external_urls=args.require_external_urls,
        )
    except (OSError, OfficialReportVerificationError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print(
        f"PASS: {result.body_page_count}-page body + {result.appendix_page_count}-page appendices; "
        f"external_urls_complete={result.external_urls_complete}"
    )
    if args.attestation is not None:
        payload = build_attestation(
            args.docx,
            args.pdf,
            result,
            visual_reviewed_all_pages=args.visual_review_confirmed,
        )
        args.attestation.parent.mkdir(parents=True, exist_ok=True)
        args.attestation.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
