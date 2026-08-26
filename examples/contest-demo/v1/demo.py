from __future__ import annotations

import argparse
import csv
import difflib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
from typing import Callable, TextIO
import urllib.parse


DEMO_ROOT = Path(__file__).resolve().parent
REPO_ROOT = DEMO_ROOT.parents[2]
DEFAULT_WORK_DIR = REPO_ROOT / "tmp" / "contest-demo-v1"
STATE_FILES = ("app.py", "response.json")
RUNTIME_BUDGET_SECONDS = 180
GUARDIAN_STEP_TIMEOUT_SECONDS = 75
SHUTDOWN_RESERVE_SECONDS = 10
STAGE_ORDER = (
    "vulnerable_fixture",
    "first_review_hold",
    "first_actionable_blocker",
    "visible_safe_patch",
    "guardian_rerun",
    "bounded_result",
)
STAGE_TITLES = {
    "vulnerable_fixture": "취약 합성 fixture 공개",
    "first_review_hold": "첫 Guardian 검수와 HOLD",
    "first_actionable_blocker": "첫 조치 대상 확인",
    "visible_safe_patch": "안전 patch 공개 및 적용",
    "guardian_rerun": "같은 범위로 재검수",
    "bounded_result": "앱 위험 CLEAR와 출시 권한 경계",
}
CLAIM_BOUNDARY = (
    "로컬 합성 fixture에서 앱 위험 탐지와 수정 후 재검수만 확인합니다. "
    "실제 field accuracy, MCP client 상호운용, 수상 실적, SHIP 또는 canonical release authority의 증거가 아닙니다."
)
BLOCKER_GUIDANCE = {
    "DYN_UNAUTH_API_JSON": {
        "title": "인증 없는 JSON 응답의 개인 레코드 노출",
        "action": "개인 레코드 배열을 제거하고 공개 가능한 서비스 상태만 반환합니다.",
    },
    "SECRET_OPENAI_STYLE_KEY": {
        "title": "소스에 포함된 합성 API key 형태 문자열",
        "action": "소스의 key 문자열을 제거하고 실제 비밀은 런타임 secret store로 주입합니다.",
    },
    "WEB_UNTRUSTED_INPUT_TO_SQL": {
        "title": "요청 입력이 문자열 보간으로 SQL에 연결됨",
        "action": "SQL placeholder와 별도 parameter tuple을 사용합니다.",
    },
}


class JourneyConsole:
    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream or sys.stdout
        self.lines: list[str] = []
        self.stage_ids: list[str] = []

    def emit(self, message: str = "", *, record: bool = True) -> None:
        print(message, file=self.stream, flush=True)
        if record:
            self.lines.append(message)

    def stage(self, stage_id: str) -> None:
        if stage_id not in STAGE_ORDER:
            raise ValueError(f"Unknown contest-demo stage: {stage_id}")
        self.stage_ids.append(stage_id)
        number = STAGE_ORDER.index(stage_id) + 1
        self.emit()
        self.emit(f"[{number}/{len(STAGE_ORDER)}] {STAGE_TITLES[stage_id]}")

    def transcript(self) -> str:
        return "\n".join(self.lines).rstrip() + "\n"


def prepare(state: str, work_dir: Path = DEFAULT_WORK_DIR) -> Path:
    if state not in {"hold", "fixed"}:
        raise ValueError(f"Unsupported demo state: {state}")
    source = DEMO_ROOT / "states" / state
    destination = work_dir / "app"
    destination.mkdir(parents=True, exist_ok=True)
    (work_dir / "evidence").mkdir(parents=True, exist_ok=True)
    for name in STATE_FILES:
        shutil.copyfile(source / name, destination / name)
    (work_dir / "state.txt").write_text(state + "\n", encoding="utf-8")
    return destination


def build_server(work_dir: Path = DEFAULT_WORK_DIR, port: int = 0) -> ThreadingHTTPServer:
    response_path = work_dir / "app" / "response.json"
    if not response_path.is_file():
        raise FileNotFoundError("Prepare the hold or fixed state before starting the server.")

    class DemoHandler(BaseHTTPRequestHandler):
        server_version = "KGuardContestDemo/2.0"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            path = urllib.parse.urlsplit(self.path).path
            if path not in {"/", "/health"}:
                self._write_json(404, {"status": "not_found"})
                return
            payload = json.loads(response_path.read_text(encoding="utf-8"))
            self._write_json(200, payload)

        def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self.send_response(204)
            self.send_header("Allow", "GET, OPTIONS")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _write_json(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer(("127.0.0.1", port), DemoHandler)


def serve(work_dir: Path = DEFAULT_WORK_DIR, port: int = 8877) -> None:
    server = build_server(work_dir, port)
    print(f"로컬 합성 데모 서버: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def summarize(report_path: Path, *, emit: bool = True) -> dict[str, object]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    experience = payload.get("experience", {}) if isinstance(payload.get("experience"), dict) else {}
    contract = payload.get("review_contract", {}) if isinstance(payload.get("review_contract"), dict) else {}
    gate = payload.get("guardian_gate", {}) if isinstance(payload.get("guardian_gate"), dict) else {}
    domains = contract.get("domains", {}) if isinstance(contract.get("domains"), dict) else {}
    summary = {
        "verdict_code": experience.get("verdict_code", "unknown"),
        "verdict_message": experience.get("verdict", ""),
        "next_actions": experience.get("next_actions", []),
        "guardian_gate_passed": gate.get("passed"),
        "release_qualification_passed": gate.get("release_qualification_passed"),
        "canonical_release_authority": gate.get("canonical_release_authority"),
        "failed_qualification_gates": gate.get("failed_qualification_gates", []),
        "application_assurance": payload.get("application_assurance", {}),
        "domain_passed": {
            name: details.get("passed")
            for name, details in domains.items()
            if isinstance(details, dict)
        },
        "top_rules": [item.get("rule_id") for item in payload.get("top_rules", [])[:3] if isinstance(item, dict)],
        "top_rule_counts": {
            str(item.get("rule_id")): item.get("count")
            for item in payload.get("top_rules", [])
            if isinstance(item, dict) and item.get("rule_id")
        },
        "claim_boundary": experience.get("claim_boundary", contract.get("claim_boundary", "")),
        "raw_returned": False,
    }
    if emit:
        print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return summary


def write_runtime_manifest(work_dir: Path, port: int) -> Path:
    source = DEMO_ROOT / "guardian-targets.csv"
    output = work_dir / "guardian-targets.runtime.csv"
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    if len(rows) != 2 or not fieldnames or {row.get("kind") for row in rows} != {"workspace", "http"}:
        raise ValueError("Contest demo manifest must contain exactly one workspace and one HTTP target.")
    for row in rows:
        if row["kind"] == "workspace":
            row["locator"] = str((work_dir / "app").resolve())
        else:
            row["locator"] = f"http://127.0.0.1:{port}"
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    if not runtime_manifest_is_local_only(output, work_dir):
        raise ValueError("Contest demo refused a non-local target.")
    return output


def runtime_manifest_is_local_only(manifest: Path, work_dir: Path) -> bool:
    with manifest.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    expected_workspace = (work_dir / "app").resolve()
    if len(rows) != 2:
        return False
    for row in rows:
        if row.get("authorized", "").lower() != "true":
            return False
        if row.get("kind") == "workspace":
            if Path(row.get("locator", "")).resolve() != expected_workspace:
                return False
        elif row.get("kind") == "http":
            parsed = urllib.parse.urlsplit(row.get("locator", ""))
            if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
                return False
        else:
            return False
    return True


def build_safe_patch(work_dir: Path) -> str:
    chunks: list[str] = []
    for name in STATE_FILES:
        current = (work_dir / "app" / name).read_text(encoding="utf-8").splitlines()
        fixed = (DEMO_ROOT / "states" / "fixed" / name).read_text(encoding="utf-8").splitlines()
        chunks.extend(
            difflib.unified_diff(
                current,
                fixed,
                fromfile=f"a/{name}",
                tofile=f"b/{name}",
                lineterm="",
            )
        )
    return "\n".join(chunks) + "\n"


def dry_run_scorecard() -> dict[str, object]:
    return {
        "schema": "k_guard_contest_demo_dry_run_scorecard.v1",
        "demo_version": "2.0.0",
        "mode": "dry_run_contract",
        "contract_valid": True,
        "scan_executed": False,
        "http_requests_sent": False,
        "patch_applied": False,
        "stage_order": list(STAGE_ORDER),
        "expected_transition": ["hold_fix", "hold_qualification"],
        "expected_application_transition": ["risk_blocked", "clear_in_reviewed_scope"],
        "runtime_budget_seconds": RUNTIME_BUDGET_SECONDS,
        "safety_contract": {
            "targets": "local_workspace_and_127.0.0.1_only",
            "public_targets_allowed": False,
            "execution_surface": "local_cli",
            "mcp_client_exercised": False,
            "award_evidence_claimed": False,
            "release_authority_claimed": False,
        },
        "claim_boundary": CLAIM_BOUNDARY,
        "raw_returned": False,
    }


def build_dry_run_transcript() -> str:
    lines = [
        "=== K-Guard Contest Demo v2: DRY-RUN ===",
        "주의: 계획과 기대 계약만 표시합니다. Guardian 검사, HTTP 요청, 파일 patch를 실행하지 않습니다.",
        "실행 표면: 로컬 제품 CLI 계획 (MCP client 실행 아님)",
        "증거 경계: 실제 field accuracy, 수상 실적, SHIP 증거가 아닙니다.",
        "",
        "[1/6] 취약 합성 fixture 공개",
        "  계획: 합성 key, 문자열 보간 SQL, 개인 레코드 JSON이 있는 로컬 fixture를 표시합니다.",
        "  대상 계약: 로컬 workspace + 127.0.0.1 동적 포트만 허용합니다.",
        "",
        "[2/6] 첫 Guardian 검수와 HOLD",
        "  [DRY-RUN 예상] 앱 위험=risk_blocked, 제품 verdict=hold_fix",
        "",
        "[3/6] 첫 조치 대상 확인",
        "  [DRY-RUN 예상] 첫 blocker=DYN_UNAUTH_API_JSON",
        "  조치 계획: 개인 레코드 배열을 제거하고 공개 가능한 서비스 상태만 반환합니다.",
        "",
        "[4/6] 안전 patch 공개 및 적용",
        "  계획: 응답 최소화, 합성 key 제거, SQL parameterization diff를 화면에 표시합니다.",
        "  DRY-RUN이므로 파일은 바꾸지 않습니다.",
        "",
        "[5/6] 같은 범위로 재검수",
        "  [DRY-RUN 예상] 앱 위험=clear_in_reviewed_scope, 제품 verdict=hold_qualification",
        "",
        "[6/6] 앱 위험 CLEAR와 출시 권한 경계",
        "  [DRY-RUN 예상] 애플리케이션 위험: CLEAR (검수 범위 한정)",
        "  [DRY-RUN 예상] 제품 qualification: HOLD",
        "  [DRY-RUN 예상] canonical release authority: 부여되지 않음",
        "  결론: 실행 결과를 주장하지 않습니다. 실제 run의 두 Guardian report로만 판정합니다.",
    ]
    return "\n".join(lines) + "\n"


def run_dry_run(stream: TextIO | None = None) -> dict[str, object]:
    output = stream or sys.stdout
    for line in build_dry_run_transcript().splitlines():
        print(line, file=output, flush=True)
    return dry_run_scorecard()


def run_demo(work_dir: Path = DEFAULT_WORK_DIR, *, stream: TextIO | None = None) -> dict[str, object]:
    started = time.monotonic()
    console = JourneyConsole(stream)
    console.emit("=== K-Guard Contest Demo v2: 로컬 합성 실행 ===")
    console.emit("실행 표면: K-Guard 로컬 제품 CLI (MCP client 실행 아님)")
    console.emit("대상 범위: 로컬 workspace + 127.0.0.1 동적 포트 (공개 대상 호출 없음)")
    console.emit(f"주장 경계: {CLAIM_BOUNDARY}")

    console.stage("vulnerable_fixture")
    application_dir = prepare("hold", work_dir)
    console.emit("  fixture 상태: vulnerable (합성 데이터이며 실제 사용자 데이터가 아님)")
    _emit_file(console, "app.py", application_dir / "app.py")
    _emit_file(console, "response.json", application_dir / "response.json")

    server = build_server(work_dir, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    evidence_dir = work_dir / "evidence"
    manifest = write_runtime_manifest(work_dir, server.server_port)
    local_targets_only = runtime_manifest_is_local_only(manifest, work_dir)
    console.emit("  로컬 대상 준비: workspace 1개, loopback HTTP 1개")
    console.emit(f"  공개 대상 호출 차단 확인: {str(local_targets_only).lower()}")

    env = dict(os.environ)
    env.setdefault("K_GUARD_EVIDENCE_HMAC_KEY", secrets.token_hex(32))
    env.setdefault("PYTHONIOENCODING", "utf-8")
    hold_path = evidence_dir / "hold.json"
    fixed_path = evidence_dir / "fixed.json"
    blocker_rule = ""
    blocker_visible = False
    patch_visible = False
    safe_patch_applied = False
    try:
        console.stage("first_review_hold")
        console.emit("  제품 CLI 실행: guardian --run-probes --fail-on high (로컬 target만 사용)")
        hold_code = _run_guardian(
            manifest,
            hold_path,
            env=env,
            timeout=_remaining_step_timeout(started),
            on_output=console.emit,
        )
        hold = summarize(hold_path, emit=False)
        hold_assurance = _application_assurance(hold)
        console.emit(f"  첫 검수 verdict: {hold['verdict_code']} -> HOLD")
        console.emit(
            "  애플리케이션 위험: "
            f"{hold_assurance.get('status')} (차단 finding {hold_assurance.get('blocking_finding_count')}건)"
        )
        console.emit(f"  차단 규칙: {', '.join(_blocking_rule_ids(hold_assurance))}")

        console.stage("first_actionable_blocker")
        blocker_rule, guidance = _first_actionable_blocker(hold_assurance)
        count = _top_rule_counts(hold).get(blocker_rule, "확인됨")
        console.emit(f"  보고서 순서상 첫 blocker: {blocker_rule} ({count}건)")
        console.emit(f"  의미: {guidance['title']}")
        console.emit(f"  첫 조치: {guidance['action']}")
        console.emit("  근거 위치: hold.json > application_assurance > blocking_rule_ids[0]")
        blocker_visible = True

        console.stage("visible_safe_patch")
        patch = build_safe_patch(work_dir)
        if not patch.strip():
            raise RuntimeError("Safe demo patch is unexpectedly empty.")
        console.emit("  아래 diff는 취약 fixture와 저장소의 검토된 fixed fixture 사이의 실제 차이입니다.")
        for line in patch.rstrip().splitlines():
            console.emit(f"  {line}")
        patch_visible = True
        prepare("fixed", work_dir)
        safe_patch_applied = all(
            (work_dir / "app" / name).read_bytes() == (DEMO_ROOT / "states" / "fixed" / name).read_bytes()
            for name in STATE_FILES
        )
        console.emit(f"  patch 적용 확인: {str(safe_patch_applied).lower()}")

        console.stage("guardian_rerun")
        console.emit("  제품 CLI 재실행: 동일 manifest + 이전 hold report 비교")
        fixed_code = _run_guardian(
            manifest,
            fixed_path,
            previous=hold_path,
            env=env,
            timeout=_remaining_step_timeout(started),
            on_output=console.emit,
        )
        fixed = summarize(fixed_path, emit=False)
        fixed_assurance = _application_assurance(fixed)
        console.emit(f"  재검수 verdict: {fixed['verdict_code']} -> 제품 qualification HOLD")
        console.emit(f"  애플리케이션 위험: {fixed_assurance.get('status')}")
        console.emit(f"  앱 차단 finding: {fixed_assurance.get('blocking_finding_count')}건")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    elapsed = time.monotonic() - started
    console.stage("bounded_result")
    domain_passed = fixed.get("domain_passed", {}) if isinstance(fixed.get("domain_passed"), dict) else {}
    all_domains_passed = bool(domain_passed) and all(value is True for value in domain_passed.values())
    runtime_within_budget = elapsed <= RUNTIME_BUDGET_SECONDS
    console.emit("  애플리케이션 위험: CLEAR (clear_in_reviewed_scope, 검수 범위 한정)")
    console.emit("  제품 qualification: HOLD (hold_qualification)")
    console.emit("  canonical release authority: 부여되지 않음")
    console.emit(f"  4개 검수 domain 완료: {str(all_domains_passed).lower()}")
    console.emit(f"  180초 실행 예산 준수: {str(runtime_within_budget).lower()}")
    console.emit("  SHIP/field accuracy/MCP client/수상 증거 주장: 하지 않음")

    hold_assurance = _application_assurance(hold)
    fixed_assurance = _application_assurance(fixed)
    checks = {
        "stage_order_is_scripted": console.stage_ids == list(STAGE_ORDER),
        "targets_are_local_only": local_targets_only,
        "hold_blocks_app_risk": hold.get("verdict_code") == "hold_fix"
        and hold_assurance.get("status") == "risk_blocked",
        "first_actionable_blocker_is_report_derived": blocker_visible
        and blocker_rule in _blocking_rule_ids(hold_assurance),
        "safe_patch_is_visible_and_applied": patch_visible and safe_patch_applied,
        "fix_clears_app_risk": fixed_assurance.get("passed") is True
        and fixed_assurance.get("status") == "clear_in_reviewed_scope",
        "qualification_remains_fail_closed": fixed.get("verdict_code") == "hold_qualification"
        and fixed.get("guardian_gate_passed") is False
        and fixed.get("release_qualification_passed") is False,
        "canonical_release_authority_not_granted": fixed.get("canonical_release_authority") is False,
        "four_review_domains_complete": all_domains_passed,
        "expected_cli_gate_codes": hold_code == 3 and fixed_code == 3,
        "runtime_within_180_seconds": runtime_within_budget,
    }
    scorecard: dict[str, object] = {
        "schema": "k_guard_contest_demo_scorecard.v2",
        "demo_version": "2.0.0",
        "mode": "executed_local_cli",
        "passed": all(checks.values()),
        "stage_order": list(console.stage_ids),
        "transition": [str(hold.get("verdict_code")), str(fixed.get("verdict_code"))],
        "application_transition": [str(hold_assurance.get("status")), str(fixed_assurance.get("status"))],
        "application_result": "clear_in_reviewed_scope",
        "product_qualification_result": "hold_qualification",
        "canonical_release_authority": False,
        "runtime_budget_seconds": RUNTIME_BUDGET_SECONDS,
        "first_actionable_blocker": blocker_rule,
        "checks": checks,
        "public_targets_called": False,
        "mcp_client_exercised": False,
        "award_evidence_claimed": False,
        "release_authority_claimed": False,
        "claim_boundary": CLAIM_BOUNDARY,
        "raw_returned": False,
    }
    console.emit(f"  deterministic scorecard: {'PASS' if scorecard['passed'] else 'FAIL'}")
    console.emit(f"  최종 주장 경계: {CLAIM_BOUNDARY}")

    score_path = evidence_dir / "demo-scorecard.json"
    transcript_path = evidence_dir / "demo-transcript.txt"
    score_path.write_text(json.dumps(scorecard, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    transcript_path.write_text(console.transcript(), encoding="utf-8")
    console.emit("실행 산출물: evidence/demo-transcript.txt, evidence/demo-scorecard.json", record=False)
    return scorecard


def _emit_file(console: JourneyConsole, label: str, path: Path) -> None:
    console.emit(f"  --- {label} ---")
    for line in path.read_text(encoding="utf-8").rstrip().splitlines():
        console.emit(f"  {line}")


def _application_assurance(summary: dict[str, object]) -> dict[str, object]:
    assurance = summary.get("application_assurance", {})
    return assurance if isinstance(assurance, dict) else {}


def _blocking_rule_ids(assurance: dict[str, object]) -> list[str]:
    values = assurance.get("blocking_rule_ids", [])
    return [str(value) for value in values] if isinstance(values, list) else []


def _top_rule_counts(summary: dict[str, object]) -> dict[str, object]:
    counts = summary.get("top_rule_counts", {})
    return counts if isinstance(counts, dict) else {}


def _first_actionable_blocker(assurance: dict[str, object]) -> tuple[str, dict[str, str]]:
    for rule_id in _blocking_rule_ids(assurance):
        guidance = BLOCKER_GUIDANCE.get(rule_id)
        if guidance is not None:
            return rule_id, guidance
    raise RuntimeError("Guardian HOLD did not contain a supported actionable demo blocker.")


def _remaining_step_timeout(started: float) -> float:
    remaining = RUNTIME_BUDGET_SECONDS - SHUTDOWN_RESERVE_SECONDS - (time.monotonic() - started)
    if remaining <= 0:
        raise TimeoutError("Contest demo exhausted its 180-second runtime budget.")
    return min(float(GUARDIAN_STEP_TIMEOUT_SECONDS), remaining)


def _format_guardian_cli_line(line: str) -> str:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return f"  [제품 CLI] {line}"
    gate = payload.get("guardian_gate", {}) if isinstance(payload.get("guardian_gate"), dict) else {}
    experience = payload.get("experience", {}) if isinstance(payload.get("experience"), dict) else {}
    verdict = experience.get("verdict", {}) if isinstance(experience.get("verdict"), dict) else {}
    verdict_code = verdict.get("code", "unknown")
    gate_label = "PASS" if gate.get("passed") is True else "HOLD"
    return f"  [제품 CLI] 출력 수신: verdict={verdict_code}, 전체 gate={gate_label}"


def _run_guardian(
    manifest: Path,
    output: Path,
    *,
    previous: Path | None = None,
    env: dict[str, str],
    timeout: float = GUARDIAN_STEP_TIMEOUT_SECONDS,
    on_output: Callable[[str], None] | None = None,
) -> int:
    arguments = [
        sys.executable,
        "-m",
        "k_guard_mcp.cli",
        "guardian",
        "--manifest",
        str(manifest),
        "--run-probes",
        "--fail-on",
        "high",
        "--output",
        str(output),
        "--markdown",
        str(output.with_suffix(".md")),
        "--html",
        str(output.with_suffix(".html")),
    ]
    if previous is not None:
        arguments.extend(["--previous", str(previous)])
    process = subprocess.Popen(
        arguments,
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    timed_out = threading.Event()

    def terminate_on_timeout() -> None:
        if process.poll() is None:
            timed_out.set()
            process.kill()

    timer = threading.Timer(timeout, terminate_on_timeout)
    timer.daemon = True
    timer.start()
    emit = on_output or (lambda message: print(message, flush=True))
    try:
        if process.stdout is None:
            raise RuntimeError("Guardian CLI stdout stream was not created.")
        for raw_line in process.stdout:
            line = raw_line.rstrip()
            if line:
                emit(_format_guardian_cli_line(line))
        return_code = process.wait()
    finally:
        timer.cancel()
        if process.stdout is not None:
            process.stdout.close()
    if timed_out.is_set():
        raise TimeoutError(f"Guardian demo step exceeded its {timeout:.0f}-second limit.")
    if return_code not in {0, 3} or not output.is_file():
        raise RuntimeError(f"Guardian demo execution failed with code {return_code}.")
    return return_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the versioned local synthetic K-Guard contest demo.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("state", choices=("hold", "fixed"))
    prepare_parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    serve_parser.add_argument("--port", type=int, default=8877)

    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("report", type=Path)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)

    subparsers.add_parser("dry-run")

    args = parser.parse_args(argv)
    if args.command == "prepare":
        destination = prepare(args.state, args.work_dir)
        print(f"fixture 준비 완료: state={args.state}, workspace={destination}", flush=True)
        return 0
    if args.command == "serve":
        serve(args.work_dir, args.port)
        return 0
    if args.command == "run":
        return 0 if run_demo(args.work_dir)["passed"] else 1
    if args.command == "dry-run":
        run_dry_run()
        return 0
    summarize(args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
