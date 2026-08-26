from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


VIDEO_SCHEMA = "k_guard_submission_video_verification.v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tool(name: str) -> str:
    executable = shutil.which(name)
    if not executable:
        raise RuntimeError(f"{name} is required")
    return executable


def _run(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def probe_video(
    path: Path,
    *,
    ffprobe_executable: Path | str | None = None,
    ffmpeg_executable: Path | str | None = None,
) -> dict[str, Any]:
    video = path.resolve(strict=True)
    ffprobe = str(Path(ffprobe_executable).resolve(strict=True)) if ffprobe_executable else _tool("ffprobe")
    ffmpeg = str(Path(ffmpeg_executable).resolve(strict=True)) if ffmpeg_executable else _tool("ffmpeg")
    probe = _run(
        [
            ffprobe,
            "-v",
            "error",
            "-count_frames",
            "-show_entries",
            "format=format_name,duration,size:stream=index,codec_type,codec_name,width,height,duration,nb_read_frames",
            "-of",
            "json",
            str(video),
        ],
        timeout=90,
    )
    if probe.returncode != 0:
        raise RuntimeError("ffprobe could not parse the submission video")
    payload = json.loads(probe.stdout)
    streams = payload.get("streams") if isinstance(payload.get("streams"), list) else []
    video_streams = [row for row in streams if isinstance(row, dict) and row.get("codec_type") == "video"]
    audio_streams = [row for row in streams if isinstance(row, dict) and row.get("codec_type") == "audio"]
    if len(video_streams) != 1:
        raise RuntimeError("submission video must contain exactly one video stream")
    stream = video_streams[0]
    format_row = payload.get("format") if isinstance(payload.get("format"), dict) else {}
    duration = float(format_row.get("duration") or stream.get("duration") or 0)
    width = int(stream.get("width") or 0)
    height = int(stream.get("height") or 0)
    frame_count = int(stream.get("nb_read_frames") or 0)
    byte_count = video.stat().st_size
    codec_name = str(stream.get("codec_name") or "")
    format_name = str(format_row.get("format_name") or "")

    decoded = _run(
        [ffmpeg, "-v", "error", "-i", str(video), "-map", "0", "-f", "null", "-"],
        timeout=180,
    )
    fully_decoded = decoded.returncode == 0
    valid = (
        10.0 <= duration <= 180.0
        and width >= 1280
        and height >= 720
        and frame_count >= int(duration)
        and byte_count >= 100_000
        and codec_name == "h264"
        and ("mp4" in format_name or "mov" in format_name)
        and fully_decoded
    )
    return {
        "schema": VIDEO_SCHEMA,
        "video_sha256": _sha256(video),
        "byte_count": byte_count,
        "format_name": format_name,
        "codec_name": codec_name,
        "duration_seconds": round(duration, 3),
        "width": width,
        "height": height,
        "frame_count": frame_count,
        "video_stream_count": len(video_streams),
        "audio_stream_count": len(audio_streams),
        "fully_decoded": fully_decoded,
        "valid": valid,
        "verification_tools": ["ffprobe", "ffmpeg full-stream decode"],
        "raw_returned": False,
    }


def validate_attestation(path: Path, attestation_path: Path, *, live_probe: bool) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    try:
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, ["video_attestation_unreadable"]
    if not isinstance(attestation, dict) or attestation.get("schema") != VIDEO_SCHEMA:
        return {}, ["video_attestation_schema_invalid"]
    if not path.is_file():
        return attestation, ["submission_video_missing"]
    if attestation.get("video_sha256") != _sha256(path):
        errors.append("video_attestation_digest_mismatch")
    if attestation.get("byte_count") != path.stat().st_size:
        errors.append("video_attestation_size_mismatch")
    for name, expected in (
        ("valid", True),
        ("fully_decoded", True),
        ("video_stream_count", 1),
        ("audio_stream_count", 1),
        ("raw_returned", False),
    ):
        if attestation.get(name) != expected:
            errors.append(f"video_attestation_{name}_invalid")
    if attestation.get("codec_name") != "h264":
        errors.append("video_attestation_codec_invalid")
    if not any(token in str(attestation.get("format_name") or "") for token in ("mp4", "mov")):
        errors.append("video_attestation_container_invalid")
    if live_probe:
        try:
            current = probe_video(path)
        except Exception:
            errors.append("video_live_reverification_failed")
        else:
            if current != attestation:
                errors.append("video_attestation_not_reproducible")
    return attestation, sorted(set(errors))
