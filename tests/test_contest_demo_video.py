from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
PLAYER = ROOT / "submission" / "demo" / "player.html"
VIDEO = ROOT / "submission" / "demo" / "k-guard-contest-demo.mp4"
VERIFICATION = ROOT / "submission" / "demo" / "video-verification.json"
TRANSCRIPT = ROOT / "evidence" / "demo" / "contest-demo-transcript.txt"
NARRATION_MANIFEST = (
    ROOT
    / "evidence"
    / "demo"
    / "actual-cli-final-r8"
    / "narration-corrected-manifest.json"
)
CAPTIONS = (
    ROOT / "evidence" / "demo" / "actual-cli-final-r8" / "narration-corrected.ass"
)
ACTUAL_CAPTURES = [
    ROOT / "submission" / "demo" / "actual-cli-project-overview-r4.mp4",
    ROOT / "submission" / "demo" / "runtime-attack-live-capture.mp4",
    ROOT / "submission" / "demo" / "actual-cli-product-walkthrough-r4.mp4",
    ROOT / "submission" / "demo" / "actual-cli-release-checks-r1.mp4",
]

pytestmark = pytest.mark.skipif(
    not VIDEO.is_file(),
    reason="the contest video is distributed separately from the public source repository",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_player_is_only_an_offline_player_for_the_actual_cli_video() -> None:
    source = PLAYER.read_text(encoding="utf-8")
    assert '<video controls preload="metadata" src="k-guard-contest-demo.mp4">' in source
    assert "가상 패널 없이 실제 PowerShell·MCP 클라이언트·제품 검사 실행만" in source
    assert "http://" not in source
    assert "https://" not in source
    assert "data-start=" not in source
    assert "evidence-snapshot" not in source
    assert "glasses-senpai-round-hero.png" not in source


def test_final_video_attestation_is_bound_and_full_hd_with_audio() -> None:
    attestation = json.loads(VERIFICATION.read_text(encoding="utf-8"))
    assert VIDEO.stat().st_size > 1_000_000
    assert attestation["video_sha256"] == _sha256(VIDEO)
    assert attestation["byte_count"] == VIDEO.stat().st_size
    assert attestation["duration_seconds"] == 180.0
    assert attestation["codec_name"] == "h264"
    assert (attestation["width"], attestation["height"]) == (1920, 1080)
    assert attestation["frame_count"] == 5400
    assert attestation["video_stream_count"] == 1
    assert attestation["audio_stream_count"] == 1
    assert attestation["fully_decoded"] is True
    assert attestation["valid"] is True
    assert attestation["raw_returned"] is False


def test_final_video_is_composed_from_actual_cli_capture_files() -> None:
    for capture in ACTUAL_CAPTURES:
        assert capture.is_file(), capture
        assert capture.stat().st_size > 100_000, capture
    transcript = TRANSCRIPT.read_text(encoding="utf-8")
    assert "180초 실제 CLI 최종본" in transcript
    assert "실제 Windows 콘솔·MCP 클라이언트·제품 CLI 실행만 사용" in transcript
    assert "가상 UI·AI 생성 이미지·클라이언트 스틸 없음" in transcript


def test_narration_uses_one_local_synthetic_voice_and_covers_all_180_seconds() -> None:
    manifest = json.loads(NARRATION_MANIFEST.read_text(encoding="utf-8"))
    captions = CAPTIONS.read_text(encoding="utf-8")
    script = " ".join(cue["text"] for cue in manifest["cues"])

    assert 179.9 <= manifest["final_duration_seconds"] <= 180.0
    assert manifest["target_speech_end_seconds"] == 176.8
    assert manifest["human_reference_audio_used"] is False
    assert manifest["same_synthetic_voice_anchor"] is True
    assert len(manifest["synthetic_voice_anchor_sha256"]) == 64
    assert manifest["sentence_unit_count"] == 39
    assert manifest["cues"][0]["start"] == 0.0
    assert manifest["cues"][-1]["speech_end"] == 176.8
    assert manifest["cues"][-1]["end"] == 177.05

    assert "개인정보 유출사고" in script
    assert "K-Guard MCP 안경선배는 AI 코딩 흐름 안에 검수와 재검수를 붙입니다" in script
    assert "가상 대시보드가 아닙니다" in script
    assert "Dialogue: 0,0:00:00.00" in captions
    assert "0:02:57.05" in captions
