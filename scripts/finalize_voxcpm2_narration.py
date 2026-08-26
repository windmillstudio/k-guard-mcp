#!/usr/bin/env python3
"""Pad the completed VoxCPM2 scene concatenation to exactly 180 seconds and bind it."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import wave
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def duration(path: Path) -> float:
    with wave.open(str(path), "rb") as stream:
        return stream.getnframes() / stream.getframerate()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repair-intro", action="store_true")
    parser.add_argument("--addendum", type=Path)
    args = parser.parse_args()
    source = args.input.resolve()
    work_dir = args.work_dir.resolve()
    ffmpeg = args.ffmpeg.resolve()
    output = args.output.resolve()
    manifest_path = args.manifest.resolve()
    for path in (output, manifest_path):
        if path.exists():
            raise SystemExit(f"Refusing to overwrite: {path}")
    processed = sorted(work_dir.glob("scene-*-fixed.wav"))
    raw = sorted(work_dir.glob("scene-*-raw.wav"))
    if len(processed) != 11 or len(raw) != 11:
        raise RuntimeError("Expected eleven completed raw and fixed scene files")
    padded = work_dir / "narration-padded-180.wav"
    subprocess.run(
        [
            str(ffmpeg),
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-i",
            str(source),
            "-af",
            "apad,atrim=duration=180",
            "-t",
            "180",
            "-ar",
            "48000",
            "-ac",
            "1",
            "-c:a",
            "pcm_s16le",
            str(padded if args.repair_intro else output),
        ],
        check=True,
    )
    intro_repair: Path | None = None
    if args.repair_intro:
        intro_repair = work_dir / "scene-00-intro-repair.wav"
        intro_output = work_dir / "narration-intro-repaired.wav" if args.addendum else output
        intro_ratio = duration(raw[0]) / 4.72
        subprocess.run(
            [
                str(ffmpeg), "-hide_banner", "-loglevel", "error", "-y",
                "-i", str(raw[0]),
                "-af", f"atempo={intro_ratio:.8f},adelay=120,apad,atrim=duration=5",
                "-t", "5", "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(intro_repair),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(ffmpeg), "-hide_banner", "-loglevel", "error", "-y",
                "-i", str(padded), "-i", str(intro_repair),
                "-filter_complex", "[0:a][1:a]amix=inputs=2:duration=first:normalize=0,alimiter=limit=0.95[a]",
                "-map", "[a]", "-t", "180", "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(intro_output),
            ],
            check=True,
        )
    if args.addendum:
        addendum = args.addendum.resolve()
        if not addendum.is_file():
            raise RuntimeError(f"Addendum not found: {addendum}")
        base = intro_output if args.repair_intro else padded
        subprocess.run(
            [
                str(ffmpeg), "-hide_banner", "-loglevel", "error", "-y",
                "-i", str(base), "-i", str(addendum),
                "-filter_complex", "[1:a]volume=2.2,adelay=159000[add];[0:a][add]amix=inputs=2:duration=first:normalize=0,alimiter=limit=0.95[a]",
                "-map", "[a]", "-t", "180", "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(output),
            ],
            check=True,
        )
    final_duration = duration(output)
    if abs(final_duration - 180.0) > 0.01:
        raise RuntimeError(f"Narration duration drifted: {final_duration}")
    manifest = {
        "schema": "k_guard_voxcpm2_narration.v1",
        "model": "openbmb/VoxCPM2 local snapshot",
        "voice_design": "trusted Korean male in his thirties; calm low pitch; brisk delivery",
        "reference_audio_used": False,
        "source_concat_duration_seconds": duration(source),
        "duration_seconds": final_duration,
        "sample_rate": 48000,
        "channel_count": 1,
        "output_sha256": digest(output),
        "generator": "scripts/generate_voxcpm2_narration.py",
        "intro_repaired_from_raw": args.repair_intro,
        "intro_repair_sha256": digest(intro_repair) if intro_repair is not None else None,
        "ai_addendum_sha256": digest(args.addendum.resolve()) if args.addendum else None,
        "ai_addendum_start_seconds": 159.0 if args.addendum else None,
        "scenes": [
            {
                "index": index,
                "raw_duration_seconds": duration(raw_path),
                "fixed_duration_seconds": duration(fixed_path),
                "raw_sha256": digest(raw_path),
                "fixed_sha256": digest(fixed_path),
            }
            for index, (raw_path, fixed_path) in enumerate(zip(raw, processed, strict=True))
        ],
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
