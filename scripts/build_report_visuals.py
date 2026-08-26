#!/usr/bin/env python3
"""Build high-resolution Korean report figures for the K-Guard contest report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


W, H = 1800, 1000
BG = "#F4F6F1"
INK = "#102019"
MUTED = "#5E6D64"
DARK = "#07150F"
GREEN = "#7AD63A"
GREEN_SOFT = "#E6F5DA"
TEAL = "#2FAF9E"
TEAL_SOFT = "#DDF3EF"
BLUE = "#4E7FE8"
BLUE_SOFT = "#E4EBFB"
AMBER = "#E9A72C"
AMBER_SOFT = "#FAEED2"
RED = "#D9534F"
RED_SOFT = "#FAE1DF"
WHITE = "#FFFFFF"
LINE = "#CDD6CF"

FONT_REGULAR = Path(r"C:\Windows\Fonts\malgun.ttf")
FONT_BOLD = Path(r"C:\Windows\Fonts\malgunbd.ttf")


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_BOLD if bold else FONT_REGULAR), size=size)


def text_width(draw: ImageDraw.ImageDraw, value: str, fnt: ImageFont.FreeTypeFont) -> float:
    return draw.textlength(value, font=fnt)


def wrap_lines(draw: ImageDraw.ImageDraw, text: str, fnt: ImageFont.FreeTypeFont, max_width: int) -> list[str]:
    lines: list[str] = []
    for paragraph in text.split("\n"):
        if not paragraph:
            lines.append("")
            continue
        current = ""
        for token in paragraph.split(" "):
            candidate = token if not current else f"{current} {token}"
            if text_width(draw, candidate, fnt) <= max_width:
                current = candidate
                continue
            if current:
                lines.append(current)
            if text_width(draw, token, fnt) <= max_width:
                current = token
                continue
            chunk = ""
            for char in token:
                if chunk and text_width(draw, chunk + char, fnt) > max_width:
                    lines.append(chunk)
                    chunk = char
                else:
                    chunk += char
            current = chunk
        if current:
            lines.append(current)
    return lines


def draw_wrapped(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    text: str,
    fnt: ImageFont.FreeTypeFont,
    fill: str,
    max_width: int,
    line_gap: int = 10,
    anchor: str = "la",
) -> int:
    x, y = xy
    line_h = fnt.size + line_gap
    for line in wrap_lines(draw, text, fnt, max_width):
        draw.text((x, y), line, font=fnt, fill=fill, anchor=anchor)
        y += line_h
    return y


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], fill: str, radius: int = 28, outline: str | None = None, width: int = 2) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def glasses(draw: ImageDraw.ImageDraw, x: int, y: int, scale: float = 1.0, color: str = GREEN) -> None:
    r = int(22 * scale)
    gap = int(12 * scale)
    width = max(3, int(5 * scale))
    draw.ellipse((x, y, x + 2 * r, y + 2 * r), outline=color, width=width)
    x2 = x + 2 * r + gap
    draw.ellipse((x2, y, x2 + 2 * r, y + 2 * r), outline=color, width=width)
    draw.line((x + 2 * r, y + r, x2, y + r), fill=color, width=width)
    draw.line((x - int(12 * scale), y + int(6 * scale), x, y + int(10 * scale)), fill=color, width=width)
    draw.line((x2 + 2 * r, y + int(10 * scale), x2 + 2 * r + int(12 * scale), y + int(6 * scale)), fill=color, width=width)


def header(draw: ImageDraw.ImageDraw, title: str, kicker: str) -> None:
    draw.rectangle((0, 0, W, 142), fill=DARK)
    glasses(draw, 72, 45, 1.0)
    draw.text((182, 52), title, font=font(44, True), fill=WHITE)
    draw.text((W - 72, 57), "K-GUARD MCP · 안경선배", font=font(22, True), fill=GREEN, anchor="ra")
    draw.text((182, 106), kicker, font=font(20), fill="#B8C8BE")


def footer(draw: ImageDraw.ImageDraw, text: str) -> None:
    draw.line((70, 920, W - 70, 920), fill=LINE, width=2)
    draw_wrapped(draw, (86, 944), text, font(18), MUTED, W - 172, line_gap=5)


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int], color: str = MUTED, width: int = 5) -> None:
    draw.line((*start, *end), fill=color, width=width)
    x1, y1 = start
    x2, y2 = end
    dx, dy = x2 - x1, y2 - y1
    length = max((dx * dx + dy * dy) ** 0.5, 1)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    size = 16
    p1 = (x2, y2)
    p2 = (int(x2 - ux * size + px * size * 0.6), int(y2 - uy * size + py * size * 0.6))
    p3 = (int(x2 - ux * size - px * size * 0.6), int(y2 - uy * size - py * size * 0.6))
    draw.polygon((p1, p2, p3), fill=color)


def card_title(draw: ImageDraw.ImageDraw, xy: tuple[int, int], label: str, color: str = INK) -> None:
    draw.text(xy, label, font=font(28, True), fill=color)


def draw_architecture(path: Path) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    header(d, "AI 코딩 흐름에 붙는 로컬 보안 검수·출하 게이트", "시스템 구성 및 핵심 데이터 흐름")

    blocks = [
        (60, 250, 280, 540, BLUE_SOFT, "개발자", "문제 정의\n실행 승인\n최종 책임"),
        (335, 220, 610, 570, WHITE, "MCP 지원 AI", "Grok\nCodex\nAntigravity"),
        (665, 190, 1005, 600, DARK, "K-Guard MCP", "워크스페이스 결속\n검수 작업 큐\n정책·한도 확인"),
        (1060, 205, 1390, 585, GREEN_SOFT, "네 영역 분석", "사이트 · API\n데이터 · 운영\n정적·제한적 동적 검사"),
        (1445, 220, 1740, 570, WHITE, "Guardian high", "증거 계약 확인\n소스 스냅샷 결속"),
    ]
    for x1, y1, x2, y2, fill, title, body in blocks:
        rounded(d, (x1, y1, x2, y2), fill, outline=LINE if fill != DARK else None)
        title_color = WHITE if fill == DARK else INK
        body_color = "#D5E0D8" if fill == DARK else MUTED
        d.text(((x1 + x2) // 2, y1 + 52), title, font=font(30, True), fill=title_color, anchor="ma")
        draw_wrapped(d, ((x1 + x2) // 2, y1 + 122), body, font(22), body_color, x2 - x1 - 44, 14, "ma")
    for x in (280, 610, 1005, 1390):
        arrow(d, (x + 12, 395), (x + 43, 395), TEAL)

    rounded(d, (75, 660, 1130, 855), TEAL_SOFT, outline="#AEDCD4")
    d.text((112, 695), "실시간 중재 레인", font=font(28, True), fill=INK)
    d.text((112, 747), "line-delimited stdio JSON-RPC", font=font(23), fill=MUTED)
    d.text((560, 747), "/", font=font(23, True), fill=TEAL)
    d.text((602, 747), "검증된 Streamable HTTP 수명주기", font=font(23), fill=MUTED)
    d.text((112, 806), "요청·응답을 전달 전에 allow / redact / block", font=font(24, True), fill=TEAL)
    arrow(d, (1135, 758), (1430, 758), TEAL, 6)

    rounded(d, (1450, 650, 1730, 855), WHITE, outline=LINE)
    d.text((1590, 695), "판정", font=font(26, True), fill=INK, anchor="ma")
    rounded(d, (1485, 747, 1585, 815), GREEN_SOFT, radius=18)
    d.text((1535, 781), "SHIP", font=font(24, True), fill="#397B18", anchor="mm")
    rounded(d, (1600, 747, 1698, 815), RED_SOFT, radius=18)
    d.text((1649, 781), "HOLD", font=font(24, True), fill=RED, anchor="mm")

    footer(d, "설정된 범위·고위험 finding·증거 계약 중 하나라도 충족되지 않으면 HOLD합니다. SHIP은 해당 소스 스냅샷과 설정 범위에 대한 판정입니다.")
    img.save(path, quality=96)


def draw_four_domains(path: Path) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    header(d, "출하 전에 함께 보는 네 가지 영역", "한 영역이라도 미완료면 HOLD_COVERAGE")
    items = [
        (70, 205, 760, 500, BLUE_SOFT, BLUE, "01  사이트", "배포 산출물 · 보안 헤더\n공개 노출 · 제한된 읽기 전용 probe"),
        (1040, 205, 1730, 500, AMBER_SOFT, AMBER, "02  API", "route · 인증/인가 경계\nIDOR 후보 · 서버/클라이언트 신뢰 경계"),
        (70, 590, 760, 880, TEAL_SOFT, TEAL, "03  데이터", "한국 개인정보 신호 · source→sink 흐름\nSQL AST · RBAC/RLS · 보유·파기 증거"),
        (1040, 590, 1730, 880, GREEN_SOFT, GREEN, "04  운영", "설정/secret · 의존성/라이선스/SBOM\nCI · suppression · 출하 증거"),
    ]
    for x1, y1, x2, y2, fill, accent, title, body in items:
        rounded(d, (x1, y1, x2, y2), fill, outline=LINE)
        d.rectangle((x1, y1, x1 + 16, y2), fill=accent)
        d.text((x1 + 48, y1 + 52), title, font=font(32, True), fill=INK)
        draw_wrapped(d, (x1 + 48, y1 + 124), body, font(24), MUTED, x2 - x1 - 92, 14)

    d.ellipse((720, 350, 1080, 730), fill=DARK)
    glasses(d, 822, 410, 1.35)
    d.text((900, 535), "Guardian high", font=font(31, True), fill=WHITE, anchor="mm")
    d.text((900, 594), "범위 + finding + 증거", font=font(21), fill="#C9D6CE", anchor="mm")
    rounded(d, (780, 645, 1020, 705), RED_SOFT, radius=18)
    d.text((900, 675), "미완료 → HOLD", font=font(22, True), fill=RED, anchor="mm")
    for start, end in [((760, 350), (780, 440)), ((1040, 350), (1020, 440)), ((760, 735), (790, 670)), ((1040, 735), (1010, 670))]:
        arrow(d, start, end, MUTED, 4)

    footer(d, "정적 분석, 명시적으로 허용된 제한적 동적 점검, 구성·증거 검사를 묶습니다. 완전한 침투시험이나 모든 배포 정책의 실효성 증명은 아닙니다.")
    img.save(path, quality=96)


def draw_review_lifecycle(path: Path) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    header(d, "발견 → 수정 → 같은 범위 재검수 → 출하 판정", "검수 영수증을 변경된 코드에 재사용하지 않는 흐름")
    steps = [
        (150, 320, "1", "워크스페이스\n결속", BLUE),
        (410, 320, "2", "check_my_app\n검수 접수", TEAL),
        (670, 320, "3", "완료까지\ncontinue_review", TEAL),
        (930, 320, "4", "finding 또는\n범위 누락 → HOLD", RED),
        (1190, 320, "5", "suggest_fix 참고\n사용자·AI 수정", AMBER),
        (1450, 320, "6", "새 review_id로\nGuardian 판정", GREEN),
    ]
    for idx in range(len(steps) - 1):
        arrow(d, (steps[idx][0] + 75, 365), (steps[idx + 1][0] - 75, 365), LINE, 6)
    for x, y, number, label, accent in steps:
        d.ellipse((x - 70, y - 70, x + 70, y + 70), fill=accent)
        d.text((x, y), number, font=font(42, True), fill=WHITE, anchor="mm")
        draw_wrapped(d, (x, y + 108), label, font(22, True), INK, 220, 10, "ma")

    arrow(d, (1260, 560), (930, 610), AMBER, 5)
    arrow(d, (930, 610), (410, 540), AMBER, 5)
    d.text((930, 640), "소스 변경 → 이전 review_id 무효 → 같은 워크스페이스 재검수", font=font(23, True), fill=AMBER, anchor="ma")

    rounded(d, (110, 735, 1690, 875), WHITE, outline=LINE)
    d.text((145, 770), "런타임 차단 영수증", font=font(25, True), fill=INK)
    tokens = [
        (430, "유출 요청", RED_SOFT, RED),
        (745, "K-Guard 검사", TEAL_SOFT, TEAL),
        (1060, "403 차단", RED_SOFT, RED),
        (1350, "upstream 0회", GREEN_SOFT, "#397B18"),
        (1580, "transaction 영수증", BLUE_SOFT, BLUE),
    ]
    for idx, (x, label, fill, color) in enumerate(tokens):
        rounded(d, (x - 118, 798, x + 118, 850), fill, radius=16)
        d.text((x, 824), label, font=font(19, True), fill=color, anchor="mm")
        if idx < len(tokens) - 1:
            arrow(d, (x + 123, 824), (tokens[idx + 1][0] - 123, 824), MUTED, 3)

    footer(d, "suggest_fix는 수정 안내이며 자동 해결 보증이 아닙니다. 코드가 바뀌면 이전 영수증을 폐기하고 동일 범위를 다시 검사합니다.")
    img.save(path, quality=96)


def draw_ai_roles(path: Path) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    header(d, "1인 개발자가 AI 역할을 분리한 검증 루프", "구현·검토·통합 검증을 분리하고 사람에게 최종 책임을 둡니다")

    rounded(d, (70, 220, 440, 780), DARK)
    glasses(d, 180, 285, 1.25)
    d.text((255, 430), "사람 개발자", font=font(31, True), fill=WHITE, anchor="ma")
    draw_wrapped(d, (255, 510), "문제 정의\n요구사항·위험 수용 결정\n실행 승인\n최종 책임", font(23), "#D5E0D8", 300, 18, "ma")

    roles = [
        (520, 215, 880, 470, GREEN_SOFT, "Grok", "구현·리팩터링 보조", GREEN),
        (930, 215, 1290, 470, BLUE_SOFT, "Claude", "설계·보안 관점\n읽기 전용 검토", BLUE),
        (1340, 215, 1730, 470, TEAL_SOFT, "GPT / Codex", "오케스트레이션\n통합 검증·릴리스 점검", TEAL),
    ]
    for x1, y1, x2, y2, fill, title, body, accent in roles:
        rounded(d, (x1, y1, x2, y2), fill, outline=LINE)
        d.text(((x1 + x2) // 2, y1 + 65), title, font=font(31, True), fill=INK, anchor="ma")
        draw_wrapped(d, ((x1 + x2) // 2, y1 + 135), body, font(22), MUTED, x2 - x1 - 60, 12, "ma")
        d.rectangle((x1, y2 - 13, x2, y2), fill=accent)

    for start, end in [((440, 360), (520, 340)), ((880, 340), (930, 340)), ((1290, 340), (1340, 340))]:
        arrow(d, start, end, MUTED, 4)

    rounded(d, (520, 560, 1730, 790), WHITE, outline=LINE)
    d.text((570, 605), "자동 검증 레이어", font=font(29, True), fill=INK)
    checks = ["회귀 테스트", "소스·결과 해시", "차단 영수증", "재현 패키지"]
    for idx, label in enumerate(checks):
        x = 590 + idx * 280
        rounded(d, (x, 675, x + 225, 742), TEAL_SOFT if idx % 2 else GREEN_SOFT, radius=18)
        d.text((x + 112, 708), label, font=font(21, True), fill=INK, anchor="mm")
    arrow(d, (1125, 795), (460, 805), AMBER, 5)
    d.text((780, 835), "검증 실패 → 수정 루프", font=font(22, True), fill=AMBER, anchor="ma")

    footer(d, "역할 분리는 개발 방법론이며 외부 독립감사·보안 인증을 뜻하지 않습니다. AI 판단은 테스트와 결속 증거로 다시 확인합니다.")
    img.save(path, quality=96)


def draw_impact(path: Path) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    header(d, "누가, 어디에서, 무엇을 개선하는가", "기대효과 및 활용 분야")

    d.text((85, 205), "개발 흐름의 변화", font=font(30, True), fill=INK)
    shifts = [
        ("사후 발견", "개발 단계 점검"),
        ("finding 나열", "HOLD와 다음 행동"),
        ("일회성 결과", "소스 결속 재검수"),
        ("클라이언트별 도구", "MCP 공통 인터페이스"),
    ]
    for idx, (before, after) in enumerate(shifts):
        y = 285 + idx * 140
        rounded(d, (85, y, 355, y + 86), RED_SOFT, radius=20)
        d.text((220, y + 43), before, font=font(22, True), fill=RED, anchor="mm")
        arrow(d, (375, y + 43), (495, y + 43), MUTED, 4)
        rounded(d, (515, y, 855, y + 86), GREEN_SOFT, radius=20)
        d.text((685, y + 43), after, font=font(22, True), fill="#397B18", anchor="mm")

    d.line((930, 205, 930, 855), fill=LINE, width=3)
    d.text((1000, 205), "주요 활용처", font=font(30, True), fill=INK)
    uses = [
        (985, 285, BLUE_SOFT, BLUE, "개인·소규모팀", "출하 전 점검 루틴과\n수정 우선순위"),
        (1365, 285, TEAL_SOFT, TEAL, "개인정보 서비스", "한국 개인정보 구현 신호와\n감사 근거"),
        (985, 565, AMBER_SOFT, AMBER, "오픈소스·CI/CD", "SARIF·보고서·SBOM과\n릴리스 게이트"),
        (1365, 565, GREEN_SOFT, GREEN, "AI·MCP 운영", "요청/응답 정책 중재와\ntransaction 영수증"),
    ]
    for x, y, fill, accent, title, body in uses:
        rounded(d, (x, y, x + 330, y + 220), fill, outline=LINE)
        d.ellipse((x + 28, y + 28, x + 76, y + 76), fill=accent)
        d.text((x + 100, y + 31), title, font=font(25, True), fill=INK)
        draw_wrapped(d, (x + 36, y + 106), body, font(21), MUTED, 266, 12)

    footer(d, "전문가·법률 검토를 대체하는 기능이 아니라 개발자가 출하 전에 확인할 범위와 다음 행동을 구조화하는 도구입니다.")
    img.save(path, quality=96)


def draw_roadmap(path: Path) -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    header(d, "현재 검증 범위에서 현장 신뢰로", "한계점과 지속 가능한 발전 로드맵")

    stages = [
        (90, 220, 560, 830, GREEN_SOFT, GREEN, "현재 · 공모전 RC", [
            "로컬 우선 네 영역 게이트",
            "한국 개인정보 규칙·합성 검증",
            "stdio / 검증된 HTTP 프록시",
            "공개 소스 회귀·재현 패키지",
        ]),
        (665, 220, 1135, 830, AMBER_SOFT, AMBER, "다음 · 현장 검증", [
            "owned/partner 12~20앱",
            "사전등록·역할 분리 인간 라벨",
            "독립 holdout과 오탐 관리",
            "대형 저장소·process 성능",
        ]),
        (1240, 220, 1710, 830, BLUE_SOFT, BLUE, "확장 · 생태계", [
            "JS/TS 의미 분석 고도화",
            "원격 read-only 커넥터",
            "추가 MCP 전송·공개키 증거",
            "SIEM·CI 정책팩·플러그인",
        ]),
    ]
    for idx, (x1, y1, x2, y2, fill, accent, title, bullets) in enumerate(stages):
        rounded(d, (x1, y1, x2, y2), fill, outline=LINE)
        d.rectangle((x1, y1, x2, y1 + 16), fill=accent)
        d.text((x1 + 40, y1 + 62), title, font=font(31, True), fill=INK)
        y = y1 + 160
        for bullet in bullets:
            d.ellipse((x1 + 42, y + 8, x1 + 58, y + 24), fill=accent)
            y = draw_wrapped(d, (x1 + 78, y), bullet, font(22), MUTED, x2 - x1 - 120, 10) + 35
        if idx < len(stages) - 1:
            arrow(d, (x2 + 18, 525), (stages[idx + 1][0] - 18, 525), MUTED, 5)

    footer(d, "실제 현장 정확도와 운영 SLO는 다음 검증 단계입니다. 원격 커넥터·추가 전송·공개키 증거는 현재 기능이 아닌 확장 계획입니다.")
    img.save(path, quality=96)


def build(output: Path) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    figures = [
        ("01-system-architecture.png", draw_architecture),
        ("02-four-domain-feature-map.png", draw_four_domains),
        ("03-review-lifecycle-and-runtime-block.png", draw_review_lifecycle),
        ("04-ai-development-roles.png", draw_ai_roles),
        ("05-expected-impact-and-use-cases.png", draw_impact),
        ("06-roadmap.png", draw_roadmap),
    ]
    rows: list[dict[str, object]] = []
    for name, renderer in figures:
        path = output / name
        renderer(path)
        rows.append({
            "path": name,
            "bytes": path.stat().st_size,
            "width": W,
            "height": H,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
    manifest = {"schema": "k_guard_report_visuals.v1", "count": len(rows), "figures": rows}
    (output / "visuals-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("submission/report/visuals"))
    args = parser.parse_args()
    print(json.dumps(build(args.output.resolve()), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
