from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(
    r"<LOCAL_USER_HOME>\Desktop\mcp\제출양식\2026 오픈소스 개발자대회 결과보고서_접수번호(팀명)"
    r"\쀼2026 오픈소스 개발자대회 결과보고서_1123(AI).hwpx"
)
SKILL_DIR = Path(r"<LOCAL_USER_HOME>\.codex\skills\hwpx")
FILL_PATH = SKILL_DIR / "scripts" / "fill_hwpx.py"
WORK_DIR = ROOT / "tmp" / "hwpx-report-work" / "completed-report"
OUTPUT_DIR = ROOT / "submission" / "report"
OUTPUT = OUTPUT_DIR / "2026 오픈소스 개발자대회 결과보고서_1123(AI쀼)_시각화완성본.hwpx"
VISUAL_DIR = OUTPUT_DIR / "hwpx-visuals"


def load_fill_module():
    spec = importlib.util.spec_from_file_location("kguard_hwpx_fill", FILL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"HWPX helper를 불러올 수 없습니다: {FILL_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FILL = load_fill_module()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Pipeline:
    def __init__(self, source: Path):
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        self.step = 0
        self.current = WORK_DIR / "00-source-copy.hwpx"
        shutil.copy2(source, self.current)

    def next_path(self, label: str) -> Path:
        self.step += 1
        return WORK_DIR / f"{self.step:02d}-{label}.hwpx"

    def apply(self, label: str, func, *args, **kwargs):
        target = self.next_path(label)
        result = func(self.current, target, *args, **kwargs)
        self.current = target
        return result


def paragraph_text(xml: str, para) -> str:
    registry = FILL.Registry(xml)
    return "".join(node.text for node in FILL.own_tnodes(para, registry))


def insert_paragraph_after_any(src: Path, dst: Path, after: str, text: str, section_idx: int = 0):
    """표 안 문단도 허용하면서 기준 문단의 서식을 복제해 새 문단을 삽입한다."""
    buf = src.read_bytes()
    with zipfile.ZipFile(src) as archive:
        names = FILL.section_names(archive)
        if section_idx >= len(names):
            raise ValueError(f"섹션 인덱스 초과: {section_idx}")
        name = names[section_idx]
        xml = archive.read(name).decode("utf-8")

    root = FILL.scan_xml(xml)
    registry = FILL.Registry(xml)
    target = None
    for para in FILL.descendants(root, "p"):
        full = "".join(node.text for node in FILL.own_tnodes(para, registry))
        if after in full:
            target = para
            break
    if target is None:
        raise ValueError(f"기준 문구를 찾을 수 없습니다: {after!r}")

    fragment = xml[target.start : target.end]
    if re.search(r"<\w+:(secPr|tbl|pic|ole|container)\b", fragment):
        raise ValueError(f"복제할 수 없는 개체가 포함된 문단입니다: {after!r}")
    max_id = max((int(value) for value in re.findall(r'\bid="(\d+)"', xml)), default=0)
    cloned = FILL._clone_para(fragment, text, [max_id + 1])
    new_xml = FILL.apply_splices(xml, [(target.end, target.end, cloned)])
    dst.write_bytes(FILL.patch_zip_entries(buf, {name: new_xml.encode("utf-8")}))
    return {"section": name, "after": after, "text": text}


def resolve_target_para_any(names, xmls, after, para, section_idx):
    """fill_hwpx의 보존형 편집을 그대로 쓰되 표 내부 문단도 탐색한다."""
    if after is not None:
        for name in names:
            xml = xmls[name]
            root = FILL.scan_xml(xml)
            registry = FILL.Registry(xml)
            for candidate in FILL.descendants(root, "p"):
                full = "".join(
                    node.text for node in FILL.own_tnodes(candidate, registry)
                )
                if after in full:
                    return name, xml, candidate
        raise ValueError(f"기준 문구를 찾을 수 없음: {after!r}")
    return ORIGINAL_RESOLVER(names, xmls, after, para, section_idx)


ORIGINAL_RESOLVER = FILL._resolve_target_para


def with_table_target(func):
    def wrapped(*args, **kwargs):
        original = FILL._resolve_target_para
        FILL._resolve_target_para = resolve_target_para_any
        try:
            return func(*args, **kwargs)
        finally:
            FILL._resolve_target_para = original

    return wrapped


set_text_style_any = with_table_target(FILL.set_text_style_hwpx)
insert_image_any = with_table_target(FILL.insert_image_hwpx)


def remove_guide_page(src: Path, dst: Path):
    """섹션 설정은 보존하고 작성 안내 표·강제 쪽나눔만 제거한다."""
    buf = src.read_bytes()
    with zipfile.ZipFile(src) as archive:
        name = "Contents/section0.xml"
        xml = archive.read(name).decode("utf-8")

    start = xml.find('<hp:tbl id="1075989302"')
    if start < 0:
        raise ValueError("작성 안내 표를 찾을 수 없습니다")
    token_re = re.compile(r"<hp:tbl\b|</hp:tbl>")
    depth = 0
    end = None
    for match in token_re.finditer(xml, start):
        if match.group(0).startswith("<hp:tbl"):
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                end = match.end()
                break
    if end is None:
        raise ValueError("작성 안내 표의 닫는 태그를 찾을 수 없습니다")
    xml = xml[:start] + xml[end:]

    main_table = xml.find('<hp:tbl id="1085359374"')
    if main_table < 0:
        raise ValueError("결과보고서 시작 표를 찾을 수 없습니다")
    para_start = xml.rfind("<hp:p", 0, main_table)
    para_open_end = xml.find(">", para_start)
    opening = xml[para_start : para_open_end + 1]
    if 'pageBreak="1"' not in opening:
        raise ValueError("결과보고서 시작 쪽나눔을 찾을 수 없습니다")
    opening = opening.replace('pageBreak="1"', 'pageBreak="0"', 1)
    xml = xml[:para_start] + opening + xml[para_open_end + 1 :]

    dst.write_bytes(FILL.patch_zip_entries(buf, {name: xml.encode("utf-8")}))
    return {"removed_table_id": "1075989302", "cleared_page_break_table_id": "1085359374"}


def normalize_inserted_image_geometry(src: Path, dst: Path):
    """한컴 2022가 자연 크기 대비 이중 축소하지 않도록 그림 좌표계를 표시 크기에 결속한다."""
    buf = src.read_bytes()
    with zipfile.ZipFile(src) as archive:
        name = "Contents/section0.xml"
        xml = archive.read(name).decode("utf-8")

    pic_re = re.compile(r"<hp:pic\b.*?</hp:pic>")
    changed = 0

    def normalize(match: re.Match[str]) -> str:
        nonlocal changed
        block = match.group(0)
        if "<hp:shapeComment>inserted image</hp:shapeComment>" not in block:
            return block
        size = re.search(r'<hp:curSz width="(\d+)" height="(\d+)"/>', block)
        if not size:
            return block
        width, height = size.groups()
        block = re.sub(
            r'<hp:orgSz width="\d+" height="\d+"/>',
            f'<hp:orgSz width="{width}" height="{height}"/>',
            block,
            count=1,
        )
        block = re.sub(
            r'<hp:imgClip left="0" right="\d+" top="0" bottom="\d+"/>',
            f'<hp:imgClip left="0" right="{width}" top="0" bottom="{height}"/>',
            block,
            count=1,
        )
        block = re.sub(
            r'<hp:imgDim dimwidth="\d+" dimheight="\d+"/>',
            f'<hp:imgDim dimwidth="{width}" dimheight="{height}"/>',
            block,
            count=1,
        )
        changed += 1
        return block

    new_xml = pic_re.sub(normalize, xml)
    if changed == 0:
        raise ValueError("정상화할 삽입 그림을 찾을 수 없습니다")
    dst.write_bytes(FILL.patch_zip_entries(buf, {name: new_xml.encode("utf-8")}))
    return {"normalized_images": changed}


def add_sequence(pipe: Pipeline, anchor: str, paragraphs: list[str], label: str):
    current_anchor = anchor
    for index, text in enumerate(paragraphs, start=1):
        pipe.apply(
            f"{label}-{index:02d}",
            insert_paragraph_after_any,
            current_anchor,
            text,
        )
        current_anchor = text
    return current_anchor


def style(pipe: Pipeline, anchor: str, *, bold: bool = False, size: float = 9.0):
    safe_label = re.sub(r"[^0-9A-Za-z가-힣]+", "-", anchor[:18]).strip("-") or "text"
    pipe.apply(
        f"style-{safe_label}",
        set_text_style_any,
        after=anchor,
        bold=bold,
        color="000000",
        size_pt=size,
        section_idx=0,
    )


def main() -> None:
    if not SOURCE.exists():
        raise FileNotFoundError(SOURCE)
    for required in (
        VISUAL_DIR / "01-codebase-structure-and-dependencies.png",
        VISUAL_DIR / "02-expected-impact-strip.png",
        VISUAL_DIR / "03-roadmap-strip.png",
    ):
        if not required.exists():
            raise FileNotFoundError(required)

    pipe = Pipeline(SOURCE)

    filled, _, _, cell_errors = pipe.apply(
        "project-url",
        FILL.fill_hwpx,
        cells=[
            {
                "section": 0,
                "table": 4,
                "row": 2,
                "col": 1,
                "value": "https://github.com/windmillstudio/k-guard-mcp",
            }
        ],
    )
    if cell_errors or not filled:
        raise RuntimeError(f"프로젝트 URL 입력 실패: filled={filled}, errors={cell_errors}")

    replacements = {
        "< 결과보고서 작성 안내 >": "",
        "온라인 개인정보 노출사고 대응 업무": "개인정보 유출사고 대응 업무",
        "개인정보유출 사고": "개인정보 유출 사고",
        "(소프트웨어 환경)": "(하드웨어·소프트웨어 환경)",
        "-운영체제: Microsoft Windows 11 Pro 64비트": "- 개발·검증 장비: AMD Ryzen 9 9950X, RAM 96GB, NVIDIA GeForce RTX 5090",
        "Semgrep: 다중 언어 심층 정적 분석": "Semgrep CE: 선택적 파일 단위 심층 정적 분석",
        "-차단 시 HTTP 403 수준의 명확한 거부 결과 제공": "- Streamable HTTP에서는 정책 위반 요청을 HTTP 403으로 차단하고, stdio에서는 JSON-RPC 오류로 거부",
        "-발견 → HOLD → 수정 → 재검수 → 출하 판정”의 전체 과정을": "-발견 → HOLD → 수정 → 재검수 → 출하 판정의 전체 과정을",
        "41components": "41개",
        "[시스템 구성도, 기술 스택 및 역할, 핵심 데이터 흐름 등을 개조식으로 작성]": "(기술 스택과 역할)",
        "[프로젝트의 발전 방향 및 타 분야로의 적용·확장 가능성, 시장성 서술]": "- 개인·소규모 팀: 배포 전 점검과 수정 우선순위를 제공해 사후 대응 비용 축소",
        "[다른 프로젝트와의 차별화 포인트 및 우리만의 독창적인 아이디어·기술적 강점 등]": "- 전체 워크스페이스 검수부터 수정·재검수·출하 판정까지 하나의 MCP 경험으로 연결",
        "[현재 프로젝트의 아쉬운 점 및 보완 방안을 바탕으로, 기능 고도화·서비스 확장·유지보수 등 프로젝트의 지속가능한 발전을 위한 향후 로드맵 기술]": "- 현재 한계: 실제 현장 정확도와 운영 SLO는 미확립이며 전문가·법률 검토를 대체하지 않음",
        "[팀워크, 기술적 한계 극복 사례 등 프로젝트 개발을 통해 느낀점]": "- 개발 동기: 개인정보 유출사고 대응 경험을 배포 전 예방 도구로 전환",
    }
    counts, _ = pipe.apply("text-corrections", FILL.replace_hwpx, replacements)
    missed = [key for key, count in counts.items() if count == 0]
    if missed:
        raise RuntimeError(f"교체 대상 누락: {missed}")

    last = add_sequence(
        pipe,
        "- 개발·검증 장비:",
        [
            "- 제품 실행 요건: 일반 PC, GPU 및 외부 AI API 불필요",
            "- 운영체제: Microsoft Windows 11 Pro 64비트",
        ],
        "environment",
    )

    architecture = [
        "- MCP 서버: AI 코딩 도구에 K-Guard 보안 기능을 표준 MCP 도구로 제공",
        "- 정적·흐름 분석: 소스·설정·배포 산출물과 Python AST, Java Tree-sitter, 제한적 JS/TS 흐름 분석",
        "- 한국 개인정보 엔진: 국내 개인정보 표현, 처리 신호, source-to-sink 전달 경로 분석",
        "- 런타임 프록시: stdio와 검증된 Streamable HTTP에서 요청·응답을 전달 전에 검사",
        "- Guardian: 사이트·API·데이터·운영의 검수 범위와 증거를 종합해 HOLD 또는 SHIP 판정",
        "- 증거 계층: 원문 대신 규칙·위치·지문·해시·HMAC 체인 중심의 raw-free 감사 근거 생성",
        "- 보고서·CI: JSON·Markdown·HTML·SARIF·SBOM 출력과 릴리스 게이트 연동",
        "(핵심 데이터 흐름)",
        "- 검수 요청: AI 코딩 도구에서 check_my_app 호출",
        "- 소스 결속: 허용 워크스페이스 확인, 후보 파일 수집, SHA-256 스냅샷 생성",
        "- 통합 분석: 사이트·API·데이터·운영 영역의 정적·흐름·의존성 검사",
        "- 증거 변환: 개인정보 원문을 제외하고 마스킹된 finding과 해시 증거 생성",
        "- 재검수: 코드 변경 시 기존 review_id를 무효화하고 동일 범위를 다시 검사",
        "- 출하 판정: 최신 review_id와 현재 소스가 일치하고 필수 조건을 충족할 때만 SHIP, 그 외 HOLD",
    ]
    architecture_last = add_sequence(pipe, "(기술 스택과 역할)", architecture, "architecture")

    impact = [
        "- 개인정보 서비스: 한국 개인정보 구현 신호와 raw-free 감사 근거를 개발 단계에서 확인",
        "- 오픈소스·CI/CD: SARIF·SBOM·체크섬과 릴리스 게이트를 재현 가능한 제출물로 연결",
        "- AI·MCP 운영: 요청·응답 정책 중재와 transaction 영수증으로 차단 근거 추적",
    ]
    impact_last = add_sequence(pipe, "- 개인·소규모 팀:", impact, "impact")

    innovation = [
        "- 한국 개인정보 분류와 처리 흐름을 일반 보안·공급망 검사와 같은 검수 계약으로 결합",
        "- finding·차단 행동·transaction ID·결과 해시를 raw-free 감사 영수증으로 연결",
    ]
    innovation_last = add_sequence(pipe, "- 전체 워크스페이스 검수부터", innovation, "innovation")

    roadmap = [
        "- 다음 검증: owned/partner 12~20앱에서 사전등록·역할 분리 인간 라벨과 독립 holdout 수행",
        "- 확장 단계: 원격 read-only 커넥터, 추가 MCP 전송, 공개키 증거, CI·SIEM 정책팩",
    ]
    roadmap_last = add_sequence(pipe, "- 현재 한계:", roadmap, "roadmap")

    reflection = [
        "- 협업·검증: 구현·읽기 전용 감사·통합 검증을 분리하고 로컬 테스트와 재현 자료로 확인",
    ]
    reflection_last = add_sequence(pipe, "- 개발 동기:", reflection, "reflection")

    headings = [
        "(기술 스택과 역할)",
        "(핵심 데이터 흐름)",
        "향후 확장성 및 기대효과",
        "프로젝트의 혁신성 및 차별성",
        "한계점 및 향후 발전 로드맵",
        "소감 및 후기",
    ]
    for heading in headings:
        style(pipe, heading, bold=True, size=10.0)

    pipe.apply(
        "style-project-url",
        set_text_style_any,
        after="https://github.com/windmillstudio/k-guard-mcp",
        underline=True,
        color="1F4E79",
        size_pt=8.5,
        section_idx=0,
    )

    body_anchors = [
        *architecture[:-1],
        architecture_last,
        "- 개인·소규모 팀:",
        *impact,
        "- 전체 워크스페이스 검수부터",
        *innovation,
        "- 현재 한계:",
        *roadmap,
        "- 개발 동기:",
        *reflection,
    ]
    for anchor in body_anchors:
        if anchor == "(핵심 데이터 흐름)":
            continue
        style(pipe, anchor, size=9.0)

    pipe.apply(
        "structure-image",
        insert_image_any,
        str(VISUAL_DIR / "01-codebase-structure-and-dependencies.png"),
        after=architecture_last,
        width_mm=108.0,
        section_idx=0,
    )
    pipe.apply(
        "impact-image",
        insert_image_any,
        str(VISUAL_DIR / "02-expected-impact-strip.png"),
        after=impact_last,
        width_mm=108.0,
        section_idx=0,
    )
    pipe.apply("normalize-image-geometry", normalize_inserted_image_geometry)

    pipe.apply("remove-guide", remove_guide_page)
    shutil.copy2(pipe.current, OUTPUT)

    manifest = {
        "schema": "k_guard_contest_hwpx_report.v1",
        "source": str(SOURCE),
        "source_sha256": sha256(SOURCE),
        "output": str(OUTPUT),
        "output_sha256_before_finalize": sha256(OUTPUT),
        "source_preserved": sha256(SOURCE) == "fed89188a5c976522c39566cccb402e86c80396d4bed030441493e729e7a3497",
        "project_url": "https://github.com/windmillstudio/k-guard-mcp",
        "visuals": [
            str(VISUAL_DIR / "01-codebase-structure-and-dependencies.png"),
            str(VISUAL_DIR / "02-expected-impact-strip.png"),
            str(VISUAL_DIR / "03-roadmap-strip.png"),
        ],
        "embedded_visuals": [
            "01-codebase-structure-and-dependencies.png",
            "02-expected-impact-strip.png",
        ],
        "notes": [
            "pydeps·pyan·madge·CodeCharta 등은 제품 의존성이 아니며 그림에도 그 경계를 명시함",
            "실제 Python import 관계와 pyproject.toml 선언을 자동 분석해 구조도를 생성함",
            "작성 안내 페이지는 제거하되 섹션 설정은 보존함",
        ],
    }
    manifest_path = OUTPUT_DIR / "completed-hwpx-report-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
