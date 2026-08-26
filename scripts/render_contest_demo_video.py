#!/usr/bin/env python3
"""Render and verify the deterministic K-Guard contest demo video."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
PLAYER = ROOT / "submission" / "demo" / "player.html"
OUTPUT = ROOT / "submission" / "demo" / "k-guard-contest-demo.mp4"
TRANSCRIPT = ROOT / "evidence" / "demo" / "contest-demo-transcript.txt"
SCORECARD = ROOT / "evidence" / "demo" / "contest-demo-scorecard.json"
SOL_ATTESTATION = ROOT / "evidence" / "qualification" / "three-ai-audit-r1" / "sol-final-attestation.json"
KOREAN_QUALIFICATION = ROOT / "evidence" / "qualification" / "korean-privacy-ai-only-v1.json"
REGRESSION_SUMMARY = ROOT / "evidence" / "release" / "final-regression-summary.json"
FRESH_WHEEL_SMOKE = ROOT / "evidence" / "release" / "fresh-wheel-stdio-smoke.json"
INTEROP_STATUS = ROOT / "evidence" / "clients" / "interop-status.json"
RUNTIME_ATTACK_SCORECARD = ROOT / "evidence" / "runtime" / "runtime-attack-demo-v1" / "demo-scorecard.json"
LICENSE_REPORT = ROOT / "submission" / "release" / "license-report.json"
AUDIT_REPORT = ROOT / "submission" / "release" / "audit-report.json"

WIDTH = 1920
HEIGHT = 1080
DURATION_SECONDS = 180
CAPTURE_FPS = 5
OUTPUT_FPS = 30
SAMPLE_TIMESTAMPS = (2, 7, 20, 38, 57, 77, 94, 112, 130, 154, 177)
MEDIA_BIN_DIRECTORY: Path | None = None

REQUIRED_TRANSCRIPT_LINES = (
    "실행 표면: K-Guard 로컬 제품 CLI (MCP client 실행 아님)",
    "첫 검수 verdict: hold_fix -> HOLD",
    "보고서 순서상 첫 blocker: DYN_UNAUTH_API_JSON (2건)",
    "patch 적용 확인: true",
    "재검수 verdict: hold_qualification -> 제품 qualification HOLD",
    "애플리케이션 위험: CLEAR (clear_in_reviewed_scope, 검수 범위 한정)",
    "SHIP/field accuracy/MCP client/수상 증거 주장: 하지 않음",
    "공식 MCP client 공격 호출 관찰: true",
    "공격 upstream 실행: 0회",
    "finding-action-transaction receipt 결속: true",
    "operator-key HMAC 검증 및 변조 거부: true",
)

class _EvidenceSnapshotParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "script" and attributes.get("id") == "evidence-snapshot":
            self._inside = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inside:
            self._inside = False

    def handle_data(self, data: str) -> None:
        if self._inside:
            self.parts.append(data)


def _run(command: list[str], *, capture_output: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
    )


def _load_player_snapshot() -> dict[str, Any]:
    parser = _EvidenceSnapshotParser()
    parser.feed(PLAYER.read_text(encoding="utf-8"))
    if not parser.parts:
        raise RuntimeError(f"Missing evidence-snapshot in {PLAYER}")
    return json.loads("".join(parser.parts))


def validate_sources() -> dict[str, Any]:
    """Fail before rendering if the player drifts from the checked evidence."""
    transcript = TRANSCRIPT.read_text(encoding="utf-8")
    scorecard = json.loads(SCORECARD.read_text(encoding="utf-8"))
    sol = json.loads(SOL_ATTESTATION.read_text(encoding="utf-8"))
    korean = json.loads(KOREAN_QUALIFICATION.read_text(encoding="utf-8"))
    if not REGRESSION_SUMMARY.is_file():
        raise RuntimeError("Current product-source full regression receipt is required before render/verify")
    regression = json.loads(REGRESSION_SUMMARY.read_text(encoding="utf-8"))
    fresh_wheel = json.loads(FRESH_WHEEL_SMOKE.read_text(encoding="utf-8"))
    interop = json.loads(INTEROP_STATUS.read_text(encoding="utf-8"))
    runtime_attack = json.loads(RUNTIME_ATTACK_SCORECARD.read_text(encoding="utf-8"))
    license_report = json.loads(LICENSE_REPORT.read_text(encoding="utf-8"))
    audit_report = json.loads(AUDIT_REPORT.read_text(encoding="utf-8"))
    player_html = PLAYER.read_text(encoding="utf-8")
    snapshot = _load_player_snapshot()

    missing_lines = [line for line in REQUIRED_TRANSCRIPT_LINES if line not in transcript]
    if missing_lines:
        raise RuntimeError(f"Transcript contract drifted; missing: {missing_lines}")

    product_source_revision = regression.get("product_source_revision")
    historical_interop_source_revision = interop.get("product_source_revision")
    result = regression.get("result") if isinstance(regression.get("result"), dict) else {}
    junit = regression.get("junit") if isinstance(regression.get("junit"), dict) else {}
    tested_revision = regression.get("tested_revision")
    integer_fields = (
        "tests_collected",
        "passed_count",
        "skipped_count",
        "failure_count",
        "error_count",
    )
    if regression.get("schema") != "k_guard_final_regression_summary.v1":
        raise RuntimeError("Current regression receipt schema is invalid")
    if not isinstance(product_source_revision, str) or re.fullmatch(r"[0-9a-f]{40}", product_source_revision) is None:
        raise RuntimeError("Current regression receipt product revision is invalid")
    if (
        not isinstance(historical_interop_source_revision, str)
        or re.fullmatch(r"[0-9a-f]{40}", historical_interop_source_revision) is None
    ):
        raise RuntimeError("Historical client-interoperability product revision is invalid")
    if not isinstance(tested_revision, str) or re.fullmatch(r"[0-9a-f]{40}", tested_revision) is None:
        raise RuntimeError("Current regression tested revision is invalid")
    if result.get("passed") is not True or any(type(result.get(key)) is not int for key in integer_fields):
        raise RuntimeError("Current regression receipt result types are invalid")
    if result["failure_count"] != 0 or result["error_count"] != 0:
        raise RuntimeError("Current regression receipt is not a completed zero-failure result")
    if result["tests_collected"] != sum(result[key] for key in integer_fields[1:]):
        raise RuntimeError("Current regression receipt accounting is inconsistent")
    duration_seconds = result.get("duration_seconds")
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)) or duration_seconds <= 0:
        raise RuntimeError("Current regression duration is invalid")
    if junit.get("path") != "evidence/release/final-regression-junit.xml":
        raise RuntimeError("Current regression JUnit locator is invalid")
    junit_path = ROOT / junit["path"]
    if not junit_path.is_file():
        raise RuntimeError("Current regression JUnit is missing")
    junit_bytes = junit_path.read_bytes()
    if type(junit.get("byte_count")) is not int or junit["byte_count"] != len(junit_bytes):
        raise RuntimeError("Current regression JUnit byte count drifted")
    if junit.get("sha256") != hashlib.sha256(junit_bytes).hexdigest():
        raise RuntimeError("Current regression JUnit digest drifted")
    regression_story = {
        "status": "completed_current_source_receipt",
        "tested_revision": tested_revision,
        "product_source_revision": product_source_revision,
        "tests_collected": result["tests_collected"],
        "passed": result["passed_count"],
        "skipped": result["skipped_count"],
        "failed": result["failure_count"],
        "errors": result["error_count"],
        "duration_seconds": duration_seconds,
        "junit_size_bytes": junit["byte_count"],
        "junit_sha256": junit["sha256"],
    }
    expected = {
        "schema": "k_guard_contest_video_story.v5",
        "duration_seconds": DURATION_SECONDS,
        "demo": {
            "transition": scorecard["transition"],
            "application_transition": scorecard["application_transition"],
            "first_actionable_blocker": scorecard["first_actionable_blocker"],
            "application_result": scorecard["application_result"],
            "initial_blocking_findings": 4,
            "mcp_client_exercised_in_demo_fixture": scorecard["mcp_client_exercised"],
        },
        "client_interop": {
            "verified_process_recordings": interop["verified_clients"],
            "historical_product_source_revision": historical_interop_source_revision,
            "recording_mode": "sanitized_process_log_replay_not_vendor_ui_certification",
            "claim_boundary": "historical_fixed_revision_not_current_runtime_revision",
        },
        "runtime_attack": {
            "mode": runtime_attack["mode"],
            "mcp_client": runtime_attack["mcp_client"],
            "attack_invoked_via_official_client": runtime_attack["checks"]["attack_invoked_via_official_client"],
            "block_observed_by_official_client": runtime_attack["checks"]["block_observed_by_official_client"],
            "upstream_attack_calls": runtime_attack["upstream_steal_calls"],
            "finding_action_transaction_linked": runtime_attack["checks"]["finding_action_transaction_linked"],
            "operator_keyed_hmac_verified": runtime_attack["checks"]["receipts_verified_with_operator_key"],
            "tampered_receipt_rejected": runtime_attack["checks"]["tampered_receipt_rejected"],
            "rule_ids": runtime_attack["attack_rule_ids"],
            "receipt_count": runtime_attack["receipt_count"],
            "claim_boundary": "local_synthetic_official_python_client_one",
        },
        "korean_privacy": {
            "fixture_evaluations": korean["case_accounting"]["fixture_case_count"],
            "fixture_tp": korean["lanes"]["current_fixture"]["category_confusion"]["positive_detection_cases"]["tp"],
            "fixture_fn": korean["lanes"]["current_fixture"]["category_confusion"]["positive_detection_cases"]["fn"],
            "fixture_fp": korean["lanes"]["current_fixture"]["category_confusion"]["clean_negative_cases"]["fp"],
            "fixture_tn": korean["lanes"]["current_fixture"]["category_confusion"]["clean_negative_cases"]["tn"],
            "fixture_targeted_absence": korean["lanes"]["current_fixture"]["targeted_absence_case_count"],
            "holdout_evaluations": korean["case_accounting"]["holdout_case_count"],
            "holdout_tp": korean["lanes"]["frozen_evaluator_holdout"]["tp"],
            "holdout_fn": korean["lanes"]["frozen_evaluator_holdout"]["fn"],
            "holdout_fp": korean["lanes"]["frozen_evaluator_holdout"]["fp"],
            "holdout_tn": korean["lanes"]["frozen_evaluator_holdout"]["tn"],
            "synthetic_separate_lanes": korean["claim_boundary"]["synthetic"]
            and not korean["case_accounting"]["cross_lane_deduplication_claimed"],
        },
        "regression": regression_story,
        "fresh_wheel": {
            "passed": fresh_wheel["passed"],
            "tool_count": fresh_wheel["contract"]["tool_count"],
            "tool_call_count": fresh_wheel["contract"]["tool_call_count"],
            "two_clean_builds_byte_identical": sol["reproducible_release"]["two_clean_builds_byte_identical"],
        },
        "open_source": {
            "license": "MIT",
            "sbom_component_count": license_report["component_count"],
            "known_dependency_vulnerabilities": audit_report["vulnerability_count"],
            "license_unknown": license_report["unknown_license_count"],
            "license_review_required": license_report["review_required_count"],
        },
    }
    if snapshot != expected:
        raise RuntimeError("Player story snapshot drifted from the fixed evidence")

    required_player_copy = (
        "DYN_UNAUTH_API_JSON",
        "앱 위험이 CLEAR로 바뀌었는지 이전 보고서와 비교합니다",
        "AI 코딩 앞에 놓는",
        "실제 MCP 공격",
        "공식 MCP 호출",
        "UPSTREAM 0회",
        "HMAC CHAIN",
        "한국 개인정보",
        "런타임 중재",
        "Claude · Codex · Grok · Antigravity",
        "K-Guard MCP 안경선배는 AI코딩 흐름 안에 검수와 재검수를 붙입니다",
        "MIT License",
        "assets/glasses-senpai-round-hero.png",
    )
    missing_copy = [item for item in required_player_copy if item not in player_html]
    if missing_copy:
        raise RuntimeError(f"Player contract drifted; missing: {missing_copy}")

    if scorecard.get("passed") is not True or not all(scorecard.get("checks", {}).values()):
        raise RuntimeError("Contest demo scorecard is not fully passing")
    if interop.get("ready") is not True or interop.get("verified_client_count") != 3:
        raise RuntimeError("Three-client interoperability evidence is not ready")
    if runtime_attack.get("passed") is not True or not all(runtime_attack.get("checks", {}).values()):
        raise RuntimeError("Official MCP runtime attack evidence is not fully passing")
    if runtime_attack.get("upstream_steal_calls") != 0:
        raise RuntimeError("Runtime attack reached the synthetic malicious upstream")
    for client in expected["client_interop"]["verified_process_recordings"]:
        record = interop["clients"][client]
        recording = ROOT / record["published_locator"]
        if recording.stat().st_size != record["recording_size_bytes"]:
            raise RuntimeError(f"Interop recording size drifted: {client}")
        if hashlib.sha256(recording.read_bytes()).hexdigest() != record["recording_sha256"]:
            raise RuntimeError(f"Interop recording digest drifted: {client}")
    return {
        "transcript": transcript,
        "scorecard": scorecard,
        "snapshot": snapshot,
        "regression": regression,
        "korean": korean,
        "fresh_wheel": fresh_wheel,
        "interop": interop,
        "runtime_attack": runtime_attack,
    }


def _browser_candidates(playwright_executable: str | None = None) -> list[Path]:
    candidates: list[Path] = []
    if os.environ.get("K_GUARD_CHROMIUM"):
        candidates.append(Path(os.environ["K_GUARD_CHROMIUM"]))
    if playwright_executable:
        candidates.append(Path(playwright_executable))

    program_files = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
    program_files_x86 = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"))
    local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    candidates.extend(
        (
            program_files / "Google" / "Chrome" / "Application" / "chrome.exe",
            program_files_x86 / "Google" / "Chrome" / "Application" / "chrome.exe",
            local_app_data / "Google" / "Chrome" / "Application" / "chrome.exe",
            program_files / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            program_files_x86 / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            local_app_data / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        )
    )
    playwright_home = local_app_data / "ms-playwright"
    if playwright_home.is_dir():
        candidates.extend(sorted(playwright_home.glob("chromium-*/chrome-win64/chrome.exe"), reverse=True))
        candidates.extend(
            sorted(
                playwright_home.glob("chromium_headless_shell-*/chrome-headless-shell-win64/chrome-headless-shell.exe"),
                reverse=True,
            )
        )

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = str(candidate.resolve()) if candidate.exists() else str(candidate)
        if normalized not in seen:
            unique.append(candidate)
            seen.add(normalized)
    return unique


def find_chromium(playwright_executable: str | None = None, explicit: Path | None = None) -> Path:
    if explicit is not None:
        if not explicit.is_file():
            raise RuntimeError(f"Chromium executable does not exist: {explicit}")
        return explicit.resolve()
    for candidate in _browser_candidates(playwright_executable):
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError(
        "No Chromium-family executable found. Set K_GUARD_CHROMIUM or pass --browser."
    )


def _open_player(page: Any, *, render_mode: bool = True) -> None:
    query = f"?{urlencode({'render': '1'})}" if render_mode else ""
    page.goto(f"{PLAYER.as_uri()}{query}", wait_until="load")
    page.wait_for_function("document.documentElement.dataset.ready === 'true'", timeout=30_000)
    dimensions = page.evaluate(
        "() => ({width: document.getElementById('stage').offsetWidth, "
        "height: document.getElementById('stage').offsetHeight, "
        "duration: window.DEMO_DURATION_SECONDS})"
    )
    if dimensions != {"width": WIDTH, "height": HEIGHT, "duration": DURATION_SECONDS}:
        raise RuntimeError(f"Unexpected player contract: {dimensions}")


def _audit_page(page: Any) -> list[str]:
    errors: list[str] = []
    midpoints = page.evaluate("window.DEMO_SCENE_MIDPOINTS")
    for midpoint in midpoints:
        page.evaluate("seconds => window.renderAt(seconds)", midpoint)
        scene_errors = page.evaluate("window.auditLayout()")
        errors.extend(f"t={midpoint}: {message}" for message in scene_errors)
    return errors


def _audit_interactive_controls(page: Any) -> list[str]:
    _open_player(page, render_mode=False)
    return page.evaluate(
        """() => {
          const controls = document.querySelector('.player-controls').getBoundingClientRect();
          const footer = document.querySelector('.footer').getBoundingClientRect();
          const copy = getComputedStyle(document.querySelector('.footer-copy')).visibility;
          const errors = [];
          if (controls.left < footer.left || controls.right > footer.right ||
              controls.top < footer.top || controls.bottom > footer.bottom) {
            errors.push('controls-outside-footer');
          }
          if (copy !== 'hidden') {
            errors.push('footer-copy-visible-behind-controls');
          }
          return errors;
        }"""
    )


def audit_player_layout(browser_path: Path | None = None) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - exercised only on missing render dependency
        raise RuntimeError("Playwright is required to audit or render the demo") from exc

    with sync_playwright() as playwright:
        browser_executable = find_chromium(playwright.chromium.executable_path, browser_path)
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=str(browser_executable),
            args=("--allow-file-access-from-files", "--hide-scrollbars", "--force-device-scale-factor=1"),
        )
        try:
            context = browser.new_context(
                viewport={"width": WIDTH, "height": HEIGHT},
                device_scale_factor=1,
                reduced_motion="reduce",
            )
            page = context.new_page()
            _open_player(page)
            errors = _audit_page(page)
            interactive_page = context.new_page()
            errors.extend(_audit_interactive_controls(interactive_page))
            if errors:
                raise RuntimeError("Player layout audit failed: " + "; ".join(errors))
            return {"browser": str(browser_executable), "scene_count": 11, "errors": errors}
        finally:
            browser.close()


def _render_frames(frame_dir: Path, capture_fps: int, browser_path: Path | None) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - exercised only on missing render dependency
        raise RuntimeError("Playwright is required to render the demo") from exc

    frame_count = DURATION_SECONDS * capture_fps
    with sync_playwright() as playwright:
        browser_executable = find_chromium(playwright.chromium.executable_path, browser_path)
        browser = playwright.chromium.launch(
            headless=True,
            executable_path=str(browser_executable),
            args=("--allow-file-access-from-files", "--hide-scrollbars", "--force-device-scale-factor=1"),
        )
        try:
            context = browser.new_context(
                viewport={"width": WIDTH, "height": HEIGHT},
                device_scale_factor=1,
                reduced_motion="reduce",
            )
            page = context.new_page()
            _open_player(page)
            layout_errors = _audit_page(page)
            if layout_errors:
                raise RuntimeError("Player layout audit failed: " + "; ".join(layout_errors))

            for frame_index in range(frame_count):
                timestamp = frame_index / capture_fps
                page.evaluate("seconds => window.renderAt(seconds)", timestamp)
                page.screenshot(
                    path=str(frame_dir / f"frame-{frame_index:05d}.png"),
                    type="png",
                    animations="disabled",
                    scale="css",
                )
                if frame_index and frame_index % 100 == 0:
                    print(f"rendered {frame_index}/{frame_count} frames", flush=True)
            return {
                "browser": str(browser_executable),
                "frame_count": frame_count,
                "capture_fps": capture_fps,
            }
        finally:
            browser.close()


def _require_tool(name: str) -> str:
    if MEDIA_BIN_DIRECTORY is not None:
        candidate = MEDIA_BIN_DIRECTORY / f"{name}.exe"
        if candidate.is_file():
            return str(candidate)
        raise RuntimeError(f"Required executable is missing from --media-bin: {candidate}")
    executable = shutil.which(name)
    if not executable:
        raise RuntimeError(f"Required executable is not on PATH: {name}")
    return executable


def _encode_frames(frame_dir: Path, output: Path, capture_fps: int) -> None:
    ffmpeg = _require_tool("ffmpeg")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_name(f".{output.stem}.rendering{output.suffix}")
    temporary_output.unlink(missing_ok=True)
    command = [
        ffmpeg,
        "-y",
        "-hide_banner",
        "-loglevel",
        "error",
        "-fflags",
        "+bitexact",
        "-framerate",
        str(capture_fps),
        "-start_number",
        "0",
        "-i",
        str(frame_dir / "frame-%05d.png"),
        "-vf",
        f"fps={OUTPUT_FPS}:round=near,format=yuv420p",
        "-r",
        str(OUTPUT_FPS),
        "-fps_mode",
        "cfr",
        "-frames:v",
        str(DURATION_SECONDS * OUTPUT_FPS),
        "-c:v",
        "libx264",
        "-preset",
        "slow",
        "-crf",
        "18",
        "-profile:v",
        "high",
        "-level:v",
        "4.2",
        "-g",
        str(OUTPUT_FPS * 2),
        "-keyint_min",
        str(OUTPUT_FPS * 2),
        "-sc_threshold",
        "0",
        "-threads",
        "1",
        "-an",
        "-map_metadata",
        "-1",
        "-movflags",
        "+faststart",
        str(temporary_output),
    ]
    try:
        _run(command)
        os.replace(temporary_output, output)
    finally:
        temporary_output.unlink(missing_ok=True)


def probe_video(video: Path) -> dict[str, Any]:
    ffprobe = _require_tool("ffprobe")
    completed = _run(
        [
            ffprobe,
            "-v",
            "error",
            "-show_streams",
            "-show_format",
            "-of",
            "json",
            str(video),
        ]
    )
    payload = json.loads(completed.stdout.decode("utf-8"))
    video_streams = [stream for stream in payload.get("streams", []) if stream.get("codec_type") == "video"]
    if len(video_streams) != 1:
        raise RuntimeError(f"Expected exactly one video stream, found {len(video_streams)}")
    stream = video_streams[0]
    duration = float(payload.get("format", {}).get("duration") or stream.get("duration") or 0)
    return {
        "duration": duration,
        "codec": stream.get("codec_name"),
        "width": int(stream.get("width", 0)),
        "height": int(stream.get("height", 0)),
        "pixel_format": stream.get("pix_fmt"),
        "frame_rate": stream.get("avg_frame_rate"),
        "audio_streams": sum(1 for item in payload.get("streams", []) if item.get("codec_type") == "audio"),
    }


def _sample_frame(video: Path, timestamp: float) -> dict[str, float]:
    ffmpeg = _require_tool("ffmpeg")
    completed = _run(
        [
            ffmpeg,
            "-v",
            "error",
            "-ss",
            f"{timestamp:.3f}",
            "-i",
            str(video),
            "-frames:v",
            "1",
            "-vf",
            "scale=64:36:flags=area,format=gray",
            "-f",
            "rawvideo",
            "-",
        ]
    )
    pixels = completed.stdout
    expected = 64 * 36
    if len(pixels) != expected:
        raise RuntimeError(f"Could not decode frame at {timestamp}s: {len(pixels)} bytes")
    return {
        "timestamp": timestamp,
        "range": float(max(pixels) - min(pixels)),
        "stddev": statistics.pstdev(pixels),
        "mean": statistics.fmean(pixels),
    }


def verify_video(video: Path) -> dict[str, Any]:
    if not video.is_file():
        raise RuntimeError(f"Video does not exist: {video}")
    media = probe_video(video)
    if not 60 <= media["duration"] <= 180.15:
        raise RuntimeError(f"Video duration is outside the contest range: {media['duration']}")
    if not math.isclose(media["duration"], DURATION_SECONDS, abs_tol=0.15):
        raise RuntimeError(f"Unexpected deterministic duration: {media['duration']}")
    if media["codec"] != "h264":
        raise RuntimeError(f"Expected H.264, found {media['codec']}")
    if (media["width"], media["height"]) != (WIDTH, HEIGHT):
        raise RuntimeError(f"Expected {WIDTH}x{HEIGHT}, found {media['width']}x{media['height']}")
    if media["pixel_format"] != "yuv420p":
        raise RuntimeError(f"Expected yuv420p, found {media['pixel_format']}")
    if media["frame_rate"] != f"{OUTPUT_FPS}/1":
        raise RuntimeError(f"Expected constant {OUTPUT_FPS} fps, found {media['frame_rate']}")

    samples = [_sample_frame(video, timestamp) for timestamp in SAMPLE_TIMESTAMPS]
    blank = [sample for sample in samples if sample["range"] < 35 or sample["stddev"] < 10]
    if blank:
        raise RuntimeError(f"Blank or near-blank sampled frames: {blank}")
    return {"media": media, "samples": samples, "size_bytes": video.stat().st_size}


def render_video(output: Path, capture_fps: int, browser_path: Path | None = None) -> dict[str, Any]:
    if not 1 <= capture_fps <= 12:
        raise RuntimeError("Capture FPS must be between 1 and 12")
    validate_sources()
    with tempfile.TemporaryDirectory(prefix="k-guard-contest-demo-") as temporary_directory:
        frame_dir = Path(temporary_directory)
        render = _render_frames(frame_dir, capture_fps, browser_path)
        _encode_frames(frame_dir, output, capture_fps)
    verification = verify_video(output)
    return {"output": str(output), "render": render, "verification": verification}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--browser", type=Path, help="Explicit Chromium, Chrome, or Edge executable")
    parser.add_argument(
        "--media-bin",
        type=Path,
        help="Directory containing explicit ffmpeg.exe and ffprobe.exe binaries",
    )
    parser.add_argument("--capture-fps", type=int, default=CAPTURE_FPS)
    parser.add_argument("--verify-only", action="store_true", help="Verify the existing output without rendering")
    parser.add_argument("--audit-only", action="store_true", help="Validate evidence and browser layout without rendering")
    return parser.parse_args()


def main() -> int:
    global MEDIA_BIN_DIRECTORY
    args = _arguments()
    output = args.output.resolve()
    browser = args.browser.resolve() if args.browser else None
    MEDIA_BIN_DIRECTORY = args.media_bin.resolve() if args.media_bin else None
    validate_sources()
    if args.audit_only:
        result: dict[str, Any] = {"sources": "validated", "layout": audit_player_layout(browser)}
    elif args.verify_only:
        result = {"sources": "validated", "output": str(output), "verification": verify_video(output)}
    else:
        result = render_video(output, args.capture_fps, browser)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
