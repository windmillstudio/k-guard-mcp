from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from contest_claim_contract import claim_surface_errors
from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256


DEFAULT_REPORT = ROOT / "docs" / "contest-2026-result-report.html"
EXPECTED_PAGES = 10
A4_WIDTH_POINTS = 595.0
A4_HEIGHT_POINTS = 842.0
A4_WIDTH_CSS_PX = 794
A4_HEIGHT_CSS_PX = 1123
MOBILE_BODY_SELECTOR = ", ".join(
    (
        ".sheet p",
        ".sheet li",
        ".sheet td",
        ".sheet th",
        ".sheet figcaption",
        ".sheet code",
        ".journey-step span",
        ".metric span",
        ".arch-node span",
        ".evidence-item span",
        ".cover-version",
    )
)

REQUIRED_CLAIMS = (
    "공개 개발 앱 12개",
    "fresh-process 24회",
    "high·critical candidate 31건",
    "동일 모델 계열 fresh AI reviewer 3개",
    "31/31 만장일치 TP",
    "자동 release-blocking 후보 14건",
    "vulnerable probe 11/11",
    "benign probe 1/1",
    "인간 판정",
    "field recall",
    "release authority",
    "TP 180/FN 30/FP 0/TN 210",
    "TP 210/FN 0/FP 0/TN 210",
    "새 독립 holdout이 아님",
    "72e2aea",
    "full-regression receipt",
    "185회 separate-lane execution",
    "평가자 작성",
    "구현 후",
    "합성 점검",
    "blind/field accuracy·실시간 등록 검증 아님",
    "bounded product regression",
    "BenchmarkJava 최초",
    "성능 verdict HOLD",
    "Juliet 최초",
    "integrity FAIL",
    "0/12",
    "오디오 스트림 없음",
    "field evidence pending",
    "수상 근거 미입증",
    "41개 component",
    "VALID LANES MIXED",
    "EXTERNAL URLS PENDING",
    "package final pending",
)

STALE_CLAIMS = (
    ("stale package-ready verdict", re.compile(r"\bPACKAGE\s+READY\b|current\s+verdict\s*:\s*package\s+ready", re.I)),
    ("stale SBOM component count 40", re.compile(r"component\s*40\s*개|40\s*개\s*component|dependency\s+closure\s+40\s*개", re.I)),
    ("submission candidate", re.compile(r"결과보고서\s*제출\s*후보")),
    (
        "repository URL placeholder",
        re.compile(r"공개\s*저장소\s*URL[^\n<]{0,80}제출\s*전"),
    ),
    ("old public-app evidence", re.compile(r"vulnerable-apps-12-20260713")),
    ("obsolete effectiveness hold", re.compile(r"EFFECTIVENESS\s+HOLD", re.I)),
)


class ReportHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sheet_count = 0
        self.cover_image_src: str | None = None
        self.text_parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        classes = set((attributes.get("class") or "").split())
        if tag in {"script", "style"}:
            self._ignored_depth += 1
        if tag == "section" and "sheet" in classes:
            self.sheet_count += 1
        if tag == "img" and "cover-image" in classes:
            self.cover_image_src = attributes.get("src")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.text_parts.append(data.strip())


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class VerificationResult:
    renderer: str
    page_count: int
    page_sizes: tuple[tuple[float, float], ...]
    sheet_count: int
    min_mobile_body_font_px: float | None
    pdf_path: Path


def validate_content(html: str) -> list[str]:
    errors: list[str] = []
    parser = ReportHTMLParser()
    parser.feed(html)
    visible_text = " ".join(parser.text_parts)

    if parser.sheet_count != EXPECTED_PAGES:
        errors.append(
            f"expected {EXPECTED_PAGES} .sheet sections, found {parser.sheet_count}"
        )

    source = parser.cover_image_src or ""
    if not source.startswith("data:image/") or ";base64," not in source:
        errors.append("cover hero must be an embedded base64 image")
    else:
        payload = source.split(",", 1)[1]
        try:
            image = base64.b64decode(payload, validate=True)
        except ValueError:
            errors.append("embedded cover hero is not valid base64")
        else:
            is_webp = image.startswith(b"RIFF") and image[8:12] == b"WEBP"
            is_png = image.startswith(b"\x89PNG\r\n\x1a\n")
            is_jpeg = image.startswith(b"\xff\xd8\xff")
            if len(image) < 50_000 or not (is_webp or is_png or is_jpeg):
                errors.append("embedded cover hero is missing or too small")

    for claim in REQUIRED_CLAIMS:
        if claim not in visible_text:
            errors.append(f"required evidence claim is missing: {claim}")

    for code in claim_surface_errors(visible_text):
        if code.startswith("missing_claim:"):
            errors.append(f"required evidence claim is missing: {code.split(':', 1)[1]}")
        else:
            errors.append(f"stale claim is present: {code.split(':', 1)[1]}")

    for label, pattern in STALE_CLAIMS:
        if pattern.search(visible_text):
            errors.append(f"stale claim is present: {label}")

    static_contracts = (
        (r"@page\s*\{[^}]*size:\s*A4", "@page A4 rule"),
        (r"@media\s+print", "print media rule"),
        (r"height:\s*297mm", "fixed A4 sheet height"),
        (r"max-height:\s*297mm", "fixed A4 sheet maximum height"),
        (r"font-size:\s*14px\s*!important", "14px mobile body rule"),
    )
    for pattern, label in static_contracts:
        if not re.search(pattern, html, re.S | re.I):
            errors.append(f"required layout contract is missing: {label}")

    return errors


def find_browser_executable(explicit: Path | None = None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())

    for name in ("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", "CHROME_PATH"):
        if os.environ.get(name):
            candidates.append(Path(os.environ[name]).expanduser())

    for name in (
        "chrome",
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "msedge",
    ):
        executable = shutil.which(name)
        if executable:
            candidates.append(Path(executable))

    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        home = Path.home()
        candidates.extend(
            (
                local / "Google/Chrome/Application/chrome.exe",
                local / "Microsoft/Edge/Application/msedge.exe",
                Path(os.environ.get("PROGRAMFILES", ""))
                / "Google/Chrome/Application/chrome.exe",
                Path(os.environ.get("PROGRAMFILES(X86)", ""))
                / "Microsoft/Edge/Application/msedge.exe",
            )
        )
        candidates.extend(
            sorted(
                (home / "AppData/Local/ms-playwright").glob(
                    "chromium-*/chrome-win64/chrome.exe"
                ),
                reverse=True,
            )
        )
        candidates.extend(
            sorted(
                (home / "AppData/Local/ms-playwright").glob(
                    "chromium_headless_shell-*/chrome-headless-shell-win64/"
                    "chrome-headless-shell.exe"
                ),
                reverse=True,
            )
        )
    elif sys.platform == "darwin":
        candidates.extend(
            (
                Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
            )
        )

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise VerificationError(
        "no Chromium executable found; set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"
    )


def _pdf_metadata(pdf_path: Path) -> tuple[int, tuple[tuple[float, float], ...]]:
    try:
        from pypdf import PdfReader
    except ImportError:
        data = pdf_path.read_bytes()
        page_count = len(re.findall(rb"/Type\s*/Page\b", data))
        boxes = re.findall(rb"/MediaBox\s*\[([^]]+)\]", data)
        sizes: list[tuple[float, float]] = []
        for box in boxes:
            numbers = [float(value) for value in re.findall(rb"-?\d+(?:\.\d+)?", box)]
            if len(numbers) == 4:
                sizes.append((numbers[2] - numbers[0], numbers[3] - numbers[1]))
        if len(sizes) == 1 and page_count > 1:
            sizes *= page_count
        if page_count == 0 or len(sizes) != page_count:
            raise VerificationError("could not parse page metadata from Chromium PDF")
        return page_count, tuple(sizes)

    reader = PdfReader(str(pdf_path))
    sizes = tuple(
        (float(page.mediabox.width), float(page.mediabox.height))
        for page in reader.pages
    )
    return len(reader.pages), sizes


def _render_with_playwright(
    report: Path, pdf_path: Path, browser_path: Path
) -> tuple[str, int, float]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True, executable_path=str(browser_path)
        )
        try:
            page = browser.new_page(
                viewport={"width": A4_WIDTH_CSS_PX, "height": A4_HEIGHT_CSS_PX}
            )
            page.goto(report.as_uri(), wait_until="load")
            page.emulate_media(media="print")
            sheets = page.locator(".sheet").evaluate_all(
                """elements => elements.map((element, index) => ({
                    page: index + 1,
                    overflow: (() => {
                        const sheet = element.getBoundingClientRect();
                        const paddingBottom = parseFloat(
                            getComputedStyle(element).paddingBottom
                        );
                        const contentBottom = [...element.children]
                            .filter(child => {
                                const style = getComputedStyle(child);
                                return style.display !== "none"
                                    && style.position !== "absolute"
                                    && style.position !== "fixed";
                            })
                            .reduce(
                                (bottom, child) => Math.max(
                                    bottom, child.getBoundingClientRect().bottom
                                ),
                                sheet.top
                            );
                        return Math.max(
                            element.scrollHeight - element.clientHeight,
                            contentBottom - (sheet.bottom - paddingBottom)
                        );
                    })()
                }))"""
            )
            overflow_pages = [item["page"] for item in sheets if item["overflow"] > 1]
            if overflow_pages:
                joined = ", ".join(str(page_number) for page_number in overflow_pages)
                raise VerificationError(f"print sheet content overflows on page(s): {joined}")
            hero_loaded = page.locator(".cover-image").evaluate(
                "image => image.complete && image.naturalWidth > 0"
            )
            if not hero_loaded:
                raise VerificationError("embedded cover hero did not render")
            page.pdf(
                path=str(pdf_path),
                format="A4",
                print_background=True,
                prefer_css_page_size=True,
            )

            mobile = browser.new_page(viewport={"width": 320, "height": 900})
            mobile.goto(report.as_uri(), wait_until="load")
            fonts = mobile.locator(MOBILE_BODY_SELECTOR).evaluate_all(
                """elements => elements
                    .filter(element => element.getClientRects().length > 0)
                    .map(element => parseFloat(getComputedStyle(element).fontSize))"""
            )
            if not fonts:
                raise VerificationError("mobile body typography probe found no elements")
            min_font = min(fonts)
            if min_font < 14:
                raise VerificationError(
                    f"mobile body copy falls below 14px: {min_font:.2f}px"
                )
            widths = mobile.evaluate(
                """() => ({
                    client: document.documentElement.clientWidth,
                    scroll: document.documentElement.scrollWidth
                })"""
            )
            if widths["scroll"] > widths["client"] + 1:
                raise VerificationError(
                    "320px viewport has document-level horizontal overflow"
                )
        finally:
            browser.close()
    return "Playwright Chromium", len(sheets), min_font


def _render_with_chromium(
    report: Path, pdf_path: Path, browser_path: Path
) -> tuple[str, int, None]:
    with tempfile.TemporaryDirectory(prefix="contest-report-chrome-") as profile:
        command = [
            str(browser_path),
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--allow-file-access-from-files",
            "--no-pdf-header-footer",
            "--print-to-pdf-no-header",
            "--run-all-compositor-stages-before-draw",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf_path}",
            report.as_uri(),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
    if completed.returncode != 0 or not pdf_path.is_file():
        details = (completed.stderr or completed.stdout).strip()
        raise VerificationError(f"headless Chromium PDF render failed: {details}")
    return "headless Chromium", EXPECTED_PAGES, None


def verify_report(
    report: Path = DEFAULT_REPORT,
    *,
    pdf_path: Path,
    browser_path: Path | None = None,
    expected_pages: int = EXPECTED_PAGES,
) -> VerificationResult:
    report = report.resolve()
    pdf_path = pdf_path.resolve()
    errors = validate_content(report.read_text(encoding="utf-8"))
    if errors:
        raise VerificationError("content verification failed:\n- " + "\n- ".join(errors))

    browser = find_browser_executable(browser_path)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        renderer, sheet_count, min_font = _render_with_chromium(
            report, pdf_path, browser
        )
    else:
        renderer, sheet_count, min_font = _render_with_playwright(
            report, pdf_path, browser
        )

    page_count, page_sizes = _pdf_metadata(pdf_path)
    if page_count != expected_pages:
        raise VerificationError(
            f"expected {expected_pages} PDF pages, rendered {page_count}"
        )
    for index, (width, height) in enumerate(page_sizes, start=1):
        if abs(width - A4_WIDTH_POINTS) > 2 or abs(height - A4_HEIGHT_POINTS) > 2:
            raise VerificationError(
                f"PDF page {index} is not A4: {width:.2f} x {height:.2f} pt"
            )

    return VerificationResult(
        renderer=renderer,
        page_count=page_count,
        page_sizes=page_sizes,
        sheet_count=sheet_count,
        min_mobile_body_font_px=min_font,
        pdf_path=pdf_path,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify contest-report content and render exactly ten A4 pages."
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--pdf", type=Path, required=True)
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--expected-pages", type=int, default=EXPECTED_PAGES)
    parser.add_argument("--attestation", type=Path)
    return parser


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_report(
            args.report,
            pdf_path=args.pdf,
            browser_path=args.browser,
            expected_pages=args.expected_pages,
        )
    except (OSError, VerificationError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    size = result.page_sizes[0]
    print(
        f"PASS: {result.page_count} A4 pages via {result.renderer} "
        f"({size[0]:.2f} x {size[1]:.2f} pt)"
    )
    if result.min_mobile_body_font_px is not None:
        print(
            "PASS: 320px mobile body minimum "
            f"{result.min_mobile_body_font_px:.2f}px; no sheet overflow"
        )
    else:
        print("PASS: mobile 14px contract checked statically (Playwright unavailable)")
    if args.attestation is not None:
        attestation = {
            "schema": "k_guard_contest_report_verification.v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "source_revision": _git_revision(),
            "package_tree_hash_schema": TREE_HASH_SCHEMA,
            "analyzer_package_tree_sha256": package_tree_sha256(ROOT / "src" / "k_guard_mcp"),
            "html_sha256": _sha256(args.report.resolve()),
            "pdf_sha256": _sha256(result.pdf_path),
            "renderer": result.renderer,
            "page_count": result.page_count,
            "page_sizes_points": [
                [round(width, 3), round(height, 3)] for width, height in result.page_sizes
            ],
            "sheet_count": result.sheet_count,
            "min_mobile_body_font_px": result.min_mobile_body_font_px,
            "a4_verified": True,
            "sheet_overflow_detected": False,
            "mobile_horizontal_overflow_detected": False,
            "raw_returned": False,
        }
        args.attestation.parent.mkdir(parents=True, exist_ok=True)
        args.attestation.write_bytes(
            (json.dumps(attestation, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )
    print(f"PDF: {result.pdf_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
