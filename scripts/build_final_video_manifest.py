#!/usr/bin/env python3
"""Bind the final 180-second narrated contest video to its local source recordings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "evidence" / "demo" / "final-180s-r1" / "capture-manifest.json"

FILES = {
    "final_video": "submission/demo/k-guard-contest-demo.mp4",
    "video_verification": "submission/demo/video-verification.json",
    "player": "submission/demo/player.html",
    "runtime_attack": "submission/demo/runtime-attack-live-capture.mp4",
    "product_walkthrough": "submission/demo/product-walkthrough-180s-r3-live-capture.mp4",
    "claude_readonly_audit": "submission/demo/claude-readonly-audit-receipt.mp4",
    "codex_process": "submission/client-interop/codex-interop.mp4",
    "grok_process": "submission/client-interop/grok-interop.mp4",
    "antigravity_process": "submission/client-interop/antigravity-interop.mp4",
    "narration": "evidence/demo/final-180s-r1/voxcpm2-narration-source-180.wav",
    "narration_manifest": "evidence/demo/final-180s-r1/voxcpm2-narration-manifest-v3.json",
    "product_events": "evidence/demo/final-180s-r1/product-events-r3.jsonl",
    "claude_events": "evidence/demo/final-180s-r1/claude-audit-events.jsonl",
    "claude_source_receipt": "evidence/qualification/three-ai-audit-r1/claude-opus-5-max-followup-review.json",
}


def bind(relative: str) -> dict[str, object]:
    path = ROOT / relative
    data = path.read_bytes()
    return {
        "path": relative,
        "byte_count": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit(f"Refusing to overwrite: {OUTPUT}")
    verification = json.loads((ROOT / FILES["video_verification"]).read_text(encoding="utf-8"))
    if (
        verification.get("valid") is not True
        or verification.get("fully_decoded") is not True
        or verification.get("duration_seconds") != 180.0
        or verification.get("video_stream_count") != 1
        or verification.get("audio_stream_count") != 1
    ):
        raise RuntimeError("Final video verification is not the fixed 180-second audio/video contract")
    claude = json.loads((ROOT / FILES["claude_source_receipt"]).read_text(encoding="utf-8"))
    if claude.get("provider") != "Anthropic" or claude.get("observed_model") != "claude-opus-5":
        raise RuntimeError("Claude audit receipt binding drifted")
    payload = {
        "schema": "k_guard_contest_video_capture_manifest.v2",
        "duration_seconds": 180.0,
        "dimensions": {"width": 1920, "height": 1080},
        "video": {"codec": "h264", "frame_rate": 30, "pixel_format": "yuv420p"},
        "audio": {
            "codec_in_final": "aac",
            "source_model": "OpenBMB VoxCPM2 local snapshot",
            "voice_design": "generic trustworthy Korean male in his thirties; low pitch; brisk delivery",
            "reference_audio_used": False,
            "music_used": False,
        },
        "timeline": {
            "motivation": [0, 5],
            "product_definition": [5, 10],
            "runtime_attack_actual": [10, 30],
            "product_walkthrough_actual": [30, 130],
            "test_summary": [130, 138],
            "four_ai_sequential": [138, 158],
            "four_ai_mosaic": [158, 175],
            "expected_impact": [175, 180],
        },
        "playback_speed": {
            "runtime_attack": 1.04833335,
            "product_walkthrough": 1.064,
            "four_ai_sequential": 3.526,
        },
        "actual_recording_seconds": 157,
        "html_explanation_seconds": 23,
        "claim_boundaries": [
            "Claude panel is a historical fixed-bundle read-only audit receipt, not current Claude MCP-client interoperability.",
            "Codex, Grok, and Antigravity panels are sanitized historical process recordings, not vendor certification.",
            "Korean identifiers and credentials shown in detector executions are synthetic and raw values are not returned.",
        ],
        "verification": verification,
        "files": {name: bind(relative) for name, relative in FILES.items()},
    }
    OUTPUT.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps({"output": str(OUTPUT), "files": len(FILES)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
