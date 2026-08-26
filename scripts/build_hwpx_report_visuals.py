#!/usr/bin/env python3
"""Build compact HWPX-ready K-Guard report figures from the actual source tree."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import tomllib
from collections import Counter
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "k_guard_mcp"
PYPROJECT = ROOT / "pyproject.toml"

BG = "#F4F6F1"
DARK = "#07150F"
INK = "#102019"
MUTED = "#5D6B64"
LINE = "#C9D4CD"
WHITE = "#FFFFFF"
GREEN = "#78D83A"
GREEN_SOFT = "#E5F5DA"
TEAL = "#2FAF9E"
TEAL_SOFT = "#DDF3EF"
BLUE = "#4E7FE8"
BLUE_SOFT = "#E5ECFB"
AMBER = "#EAA62A"
AMBER_SOFT = "#FBEDCE"
RED = "#D9534F"
RED_SOFT = "#F9E0DE"

FONT_REGULAR = Path(r"C:\Windows\Fonts\malgun.ttf")
FONT_BOLD = Path(r"C:\Windows\Fonts\malgunbd.ttf")


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_BOLD if bold else FONT_REGULAR), size)


def rounded(draw: ImageDraw.ImageDraw, box, fill, outline=LINE, radius=24, width=2):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def arrow(draw: ImageDraw.ImageDraw, start, end, color=TEAL, width=6):
    draw.line((start, end), fill=color, width=width)
    x2, y2 = end
    x1, y1 = start
    if abs(x2 - x1) >= abs(y2 - y1):
        direction = 1 if x2 > x1 else -1
        pts = [(x2, y2), (x2 - direction * 18, y2 - 11), (x2 - direction * 18, y2 + 11)]
    else:
        direction = 1 if y2 > y1 else -1
        pts = [(x2, y2), (x2 - 11, y2 - direction * 18), (x2 + 11, y2 - direction * 18)]
    draw.polygon(pts, fill=color)


def draw_glasses(draw: ImageDraw.ImageDraw, x: int, y: int, scale: float = 1.0, color=GREEN):
    r = int(22 * scale)
    gap = int(14 * scale)
    width = max(3, int(5 * scale))
    draw.ellipse((x, y, x + 2 * r, y + 2 * r), outline=color, width=width)
    x2 = x + 2 * r + gap
    draw.ellipse((x2, y, x2 + 2 * r, y + 2 * r), outline=color, width=width)
    draw.line((x + 2 * r, y + r, x2, y + r), fill=color, width=width)
    draw.line((x - int(12 * scale), y + int(4 * scale), x, y + int(8 * scale)), fill=color, width=width)
    draw.line((x2 + 2 * r, y + int(8 * scale), x2 + 2 * r + int(12 * scale), y + int(4 * scale)), fill=color, width=width)


def header(draw: ImageDraw.ImageDraw, width: int, title: str, subtitle: str):
    draw.rectangle((0, 0, width, 126), fill=DARK)
    draw_glasses(draw, 54, 35, 0.75)
    draw.text((155, 28), title, font=font(36, True), fill=WHITE)
    draw.text((158, 78), subtitle, font=font(21), fill="#9CB0A5")
    draw.text((width - 42, 42), "K-GUARD MCP · 안경선배", font=font(17, True), fill=GREEN, anchor="ra")


def footer(draw: ImageDraw.ImageDraw, width: int, height: int, text: str):
    draw.line((55, height - 58, width - 55, height - 58), fill=LINE, width=2)
    draw.text((62, height - 42), text, font=font(14), fill=MUTED)


def wrap_lines(draw: ImageDraw.ImageDraw, text: str, face, max_width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else current + " " + word
        if draw.textlength(candidate, font=face) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def text_block(draw: ImageDraw.ImageDraw, xy, text: str, face, fill, max_width: int, line_gap: int = 8):
    x, y = xy
    for line in wrap_lines(draw, text, face, max_width):
        draw.text((x, y), line, font=face, fill=fill)
        y += face.size + line_gap
    return y


def module_name(path: Path) -> str:
    relative = path.relative_to(PACKAGE).with_suffix("")
    return ".".join(relative.parts).replace(".__init__", "")


def group_for(module: str) -> str:
    first = module.split(".")[0]
    if first in {"server", "mcp_runtime", "cli", "session", "experience", "recipes", "installer"}:
        return "interface"
    if first in {"review_jobs", "guardian", "composite", "collector", "release_qualification", "release_policy", "supervisor_reviews"}:
        return "orchestration"
    if first in {"scanner", "analyzers", "flow", "taint", "java_flow", "detectors", "privacy_taxonomy", "sensitive_vocabulary", "database_gate", "database_policy"}:
        return "analysis"
    if first in {"mcp_proxy", "mcp_http_proxy", "mcp_normalization", "runtime_validation", "runtime_mediation_receipts", "access_policy", "cross_plane"}:
        return "runtime"
    if first in {"raw_free_evidence", "hashing", "provenance", "reports", "dashboard", "dashboard_ui", "sca", "dependency_evidence", "retention", "redaction"}:
        return "evidence"
    if first in {"validation", "language_validation", "field_validation", "benchmarking", "benchmark_adapters", "mutation_harness", "control_validation", "scoreboard", "validation_packs"}:
        return "validation"
    return "support"


def analyze_source() -> dict[str, object]:
    files = sorted(PACKAGE.rglob("*.py"))
    groups: Counter[str] = Counter()
    edges: Counter[tuple[str, str]] = Counter()
    for path in files:
        source_module = module_name(path)
        source_group = group_for(source_module)
        groups[source_group] += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                targets.append(node.module)
            for target in targets:
                if target.startswith("k_guard_mcp."):
                    target = target.removeprefix("k_guard_mcp.")
                elif target != "k_guard_mcp":
                    continue
                target_group = group_for(target)
                if source_group != target_group:
                    edges[(source_group, target_group)] += 1
    pyproject = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    dependencies = pyproject["project"]["dependencies"]
    return {
        "python_modules": len(files),
        "group_counts": dict(groups),
        "group_edges": {f"{a}->{b}": count for (a, b), count in sorted(edges.items())},
        "declared_dependencies": dependencies,
    }


def layer_box(draw, box, number, title, lines, fill, accent):
    x1, y1, x2, y2 = box
    rounded(draw, box, fill=fill, outline=LINE, radius=22)
    draw.rectangle((x1, y1, x1 + 10, y2), fill=accent)
    draw.text((x1 + 22, y1 + 18), number, font=font(18, True), fill=accent)
    draw.text((x1 + 62, y1 + 14), title, font=font(25, True), fill=INK)
    y = y1 + 62
    for line in lines:
        draw.ellipse((x1 + 28, y + 9, x1 + 40, y + 21), fill=accent)
        draw.text((x1 + 52, y), line, font=font(20), fill=MUTED)
        y += 38


def draw_structure(path: Path, analysis: dict[str, object]):
    width, height = 1400, 760
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    header(draw, width, "실제 소스 기반 프로젝트 구조·의존성", "Python import 관계와 pyproject.toml을 자동 분석한 뒤 핵심 실행 경로 중심으로 재구성")

    boxes = [
        ((35, 150, 255, 365), "01", "진입", ["MCP 클라이언트", "CLI·대시보드", "FastMCP 서버"], BLUE_SOFT, BLUE),
        ((295, 150, 515, 365), "02", "작업 관리", ["check_my_app", "continue_review", "출하 전 검수"], TEAL_SOFT, TEAL),
        ((555, 150, 775, 365), "03", "소스 결속", ["허용 작업공간", "후보 파일 수집", "SHA-256 스냅샷"], AMBER_SOFT, AMBER),
        ((815, 150, 1035, 365), "04", "통합 분석", ["사이트·API", "개인정보·데이터", "운영·정적 흐름"], GREEN_SOFT, GREEN),
        ((1075, 150, 1365, 365), "05", "증거·판정", ["raw-free 증거", "Guardian 네 영역", "HOLD 또는 SHIP"], RED_SOFT, RED),
    ]
    for args in boxes:
        layer_box(draw, *args)
    for idx in range(len(boxes) - 1):
        left = boxes[idx][0]
        right = boxes[idx + 1][0]
        arrow(draw, (left[2] + 5, 258), (right[0] - 5, 258), TEAL, 5)

    # Runtime mediation is a parallel lane connected to the same evidence contract.
    rounded(draw, (55, 400, 1345, 505), TEAL_SOFT, outline=TEAL, radius=24)
    draw.text((82, 432), "런타임 중재", font=font(23, True), fill=INK)
    lane = ["stdio / 검증된 Streamable HTTP", "접근정책·콘텐츠 검사", "allow · redact · block", "403 차단·transaction 영수증"]
    x = 255
    for idx, label in enumerate(lane):
        rounded(draw, (x, 418, x + 245, 488), WHITE, outline=LINE, radius=15)
        draw.text((x + 123, 453), label, font=font(17, True), fill=INK, anchor="mm")
        if idx < len(lane) - 1:
            arrow(draw, (x + 248, 453), (x + 270, 453), TEAL, 3)
        x += 270

    draw.text((55, 532), "의존성 경계", font=font(25, True), fill=INK)
    dep_cards = [
        (55, "제품 직접 의존성", "mcp · Pydantic · PyYAML · PyJWT\nSQLGlot · Tree-sitter", BLUE_SOFT, BLUE),
        (500, "선택적 분석 실행기", "Semgrep CE · pip-audit\nnpm audit · govulncheck", AMBER_SOFT, AMBER),
        (945, "증거·출력 표준", "JSON · HTML · SARIF\nCycloneDX SBOM", GREEN_SOFT, GREEN),
    ]
    for x, title, text, fill, accent in dep_cards:
        rounded(draw, (x, 570, x + 400, 690), fill, outline=LINE, radius=18)
        draw.rectangle((x, 570, x + 400, 580), fill=accent)
        draw.text((x + 22, 594), title, font=font(20, True), fill=INK)
        y = 630
        for line in text.splitlines():
            draw.text((x + 22, y), line, font=font(17), fill=MUTED)
            y += 28

    footer(draw, width, height, "pydeps·pyan·madge·CodeCharta 등은 제품 의존성이 아닙니다. 전체 import 그래프는 가독성을 위해 계층과 핵심 경로로 축약했습니다.")
    image.save(path, quality=96)


def draw_impact(path: Path):
    width, height = 1400, 440
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    header(draw, width, "기대효과와 활용 분야", "배포 뒤 발견하던 문제를 AI 코딩 흐름 안의 사전 검수와 재검수로 전환")

    items = [
        (45, BLUE_SOFT, BLUE, "개인·소규모 팀", "출하 전 점검\n수정 우선순위"),
        (385, TEAL_SOFT, TEAL, "개인정보 서비스", "한국 개인정보 신호\nraw-free 근거"),
        (725, AMBER_SOFT, AMBER, "오픈소스·CI/CD", "SARIF·SBOM\n릴리스 게이트"),
        (1065, GREEN_SOFT, GREEN, "AI·MCP 운영", "정책 중재\ntransaction 영수증"),
    ]
    for x, fill, accent, title, body in items:
        rounded(draw, (x, 150, x + 300, 355), fill, outline=LINE, radius=22)
        draw.ellipse((x + 24, 178, x + 66, 220), fill=accent)
        draw.text((x + 82, 181), title, font=font(22, True), fill=INK)
        y = 252
        for line in body.splitlines():
            draw.text((x + 30, y), line, font=font(20), fill=MUTED)
            y += 38
    footer(draw, width, height, "법률·전문가 검토를 대체하지 않고, 개발자가 배포 전에 확인할 범위와 다음 행동을 구조화합니다.")
    image.save(path, quality=96)


def draw_roadmap(path: Path):
    width, height = 1400, 440
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    header(draw, width, "지속 가능한 발전 로드맵", "현재 RC의 검증 범위를 고정하고 현장 데이터와 공개 생태계로 단계적으로 확장")

    stages = [
        (50, GREEN_SOFT, GREEN, "현재 · 공모전 RC", ["로컬 네 영역 게이트", "한국 개인정보·재현", "stdio·검증된 HTTP"]),
        (500, AMBER_SOFT, AMBER, "다음 · 현장 검증", ["owned/partner 12~20앱", "역할 분리 인간 라벨", "holdout·process 성능"]),
        (950, BLUE_SOFT, BLUE, "확장 · 생태계", ["원격 read-only 연결", "추가 전송·공개키 증거", "CI·SIEM 정책팩"]),
    ]
    for idx, (x, fill, accent, title, bullets) in enumerate(stages):
        rounded(draw, (x, 150, x + 400, 360), fill, outline=LINE, radius=22)
        draw.rectangle((x, 150, x + 400, 161), fill=accent)
        draw.text((x + 26, 184), title, font=font(23, True), fill=INK)
        y = 240
        for bullet in bullets:
            draw.ellipse((x + 30, y + 8, x + 42, y + 20), fill=accent)
            draw.text((x + 60, y), bullet, font=font(19), fill=MUTED)
            y += 39
        if idx < 2:
            arrow(draw, (x + 412, 255), (stages[idx + 1][0] - 12, 255), MUTED, 5)
    footer(draw, width, height, "현장 정확도와 운영 SLO는 다음 검증 단계입니다. 원격 커넥터·추가 전송·공개키 증거는 확장 계획입니다.")
    image.save(path, quality=96)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    analysis = analyze_source()
    specs = [
        ("01-codebase-structure-and-dependencies.png", lambda path: draw_structure(path, analysis), 1400, 760),
        ("02-expected-impact-strip.png", draw_impact, 1400, 440),
        ("03-roadmap-strip.png", draw_roadmap, 1400, 440),
    ]
    figures = []
    for name, renderer, width, height in specs:
        path = output / name
        renderer(path)
        figures.append({"path": name, "bytes": path.stat().st_size, "width": width, "height": height, "sha256": sha256(path)})
    manifest = {"schema": "k_guard_hwpx_report_visuals.v1", "analysis": analysis, "count": len(figures), "figures": figures}
    (output / "visuals-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "submission" / "report" / "hwpx-visuals")
    args = parser.parse_args()
    print(json.dumps(build(args.output.resolve()), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
