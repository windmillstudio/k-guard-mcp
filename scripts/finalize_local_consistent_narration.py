#!/usr/bin/env python3
"""Finalize already generated local VoxCPM2 scenes to exact aligned durations."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import soundfile as sf


SCENE_DURATIONS = (22.0, 27.0, 29.0, 34.0, 22.0, 21.0, 25.0)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atempo_chain(ratio: float) -> str:
    factors: list[float] = []
    while ratio > 2.0:
        factors.append(2.0)
        ratio /= 2.0
    while ratio < 0.5:
        factors.append(0.5)
        ratio /= 0.5
    factors.append(ratio)
    return ",".join(f"atempo={factor:.8f}" for factor in factors)


def ass_time(seconds: float) -> str:
    units = max(0, round(seconds * 100))
    hours, units = divmod(units, 360000)
    minutes, units = divmod(units, 6000)
    secs, centis = divmod(units, 100)
    return f"{hours}:{minutes:02d}:{secs:02d}.{centis:02d}"


def write_ass(paragraphs: list[str], path: Path) -> list[dict[str, object]]:
    header = """[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
WrapStyle: 0
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name,Fontname,Fontsize,PrimaryColour,SecondaryColour,OutlineColour,BackColour,Bold,Italic,Underline,StrikeOut,ScaleX,ScaleY,Spacing,Angle,BorderStyle,Outline,Shadow,Alignment,MarginL,MarginR,MarginV,Encoding
Style: Default,Malgun Gothic,36,&H00FFFFFF,&H00FFFFFF,&H00101010,&HC0000000,-1,0,0,0,100,100,0,0,3,1,0,2,80,80,18,1

[Events]
Format: Layer,Start,End,Style,Name,MarginL,MarginR,MarginV,Effect,Text
"""
    rows = [header]
    cues: list[dict[str, object]] = []
    scene_start = 0.0
    for paragraph, duration in zip(paragraphs, SCENE_DURATIONS, strict=True):
        sentences = [item.strip() for item in re.split(r"(?<=다\.)\s+|(?<=[!?])\s+", paragraph) if item.strip()]
        if not sentences:
            sentences = [paragraph]
        weights = [max(1, len(re.sub(r"\s", "", item))) for item in sentences]
        total = sum(weights)
        cursor = scene_start
        for index, (sentence, weight) in enumerate(zip(sentences, weights, strict=True)):
            end = scene_start + duration if index == len(sentences) - 1 else cursor + duration * weight / total
            safe = sentence.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}")
            rows.append(f"Dialogue: 0,{ass_time(cursor)},{ass_time(end)},Default,,0,0,0,,{safe}\n")
            cues.append({"start": round(cursor, 3), "end": round(end, 3), "text": sentence})
            cursor = end
        scene_start += duration
    path.write_text("".join(rows), encoding="utf-8-sig", newline="\n")
    return cues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--text", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--subtitles", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    work = args.work_dir.resolve()
    ffmpeg = args.ffmpeg.resolve()
    output = args.output.resolve()
    subtitles = args.subtitles.resolve()
    manifest_path = args.manifest.resolve()
    for path in (output, subtitles, manifest_path):
        if path.exists():
            raise SystemExit(f"Refusing to overwrite: {path}")
    fixed = sorted(work.glob("scene-*-fixed.wav"))
    raw = sorted(work.glob("scene-*-raw.wav"))
    if len(fixed) != 7 or len(raw) != 7:
        raise RuntimeError("Expected seven generated raw and fixed scene files")
    aligned: list[Path] = []
    scene_records: list[dict[str, object]] = []
    for index, (source, raw_path, target) in enumerate(zip(fixed, raw, SCENE_DURATIONS, strict=True)):
        info = sf.info(source)
        source_duration = info.frames / info.samplerate
        ratio = source_duration / target
        destination = work / f"scene-{index:02d}-aligned.wav"
        if destination.exists():
            raise RuntimeError(f"Refusing to overwrite aligned scene: {destination}")
        subprocess.run(
            [str(ffmpeg), "-hide_banner", "-loglevel", "error", "-y", "-i", str(source),
             "-af", f"{atempo_chain(ratio)},apad,atrim=duration={target:.3f}",
             "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", "-t", f"{target:.3f}", str(destination)],
            check=True,
        )
        result = sf.info(destination)
        actual = result.frames / result.samplerate
        if abs(actual - target) > 0.01:
            raise RuntimeError(f"Aligned scene {index} duration drifted: {actual}")
        aligned.append(destination)
        scene_records.append({
            "index": index, "target_duration_seconds": target,
            "raw_sha256": digest(raw_path), "generated_fixed_sha256": digest(source),
            "generated_fixed_duration_seconds": round(source_duration, 6),
            "final_speed_factor": round(ratio, 8), "aligned_sha256": digest(destination),
        })

    command = [str(ffmpeg), "-hide_banner", "-loglevel", "error", "-y"]
    for path in aligned:
        command += ["-i", str(path)]
    inputs = "".join(f"[{index}:a]" for index in range(len(aligned)))
    command += ["-filter_complex", f"{inputs}concat=n={len(aligned)}:v=0:a=1[a]", "-map", "[a]",
                "-t", "180", "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(output)]
    subprocess.run(command, check=True)
    final = sf.info(output)
    duration = final.frames / final.samplerate
    if abs(duration - 180.0) > 0.01:
        raise RuntimeError(f"Final narration duration drifted: {duration}")
    paragraphs = [item.strip() for item in re.split(r"(?:\r?\n){2,}", args.text.read_text(encoding="utf-8")) if item.strip()]
    if len(paragraphs) != 7:
        raise RuntimeError("Narration text must contain seven paragraphs")
    cues = write_ass(paragraphs, subtitles)
    anchor = work / "synthetic-voice-anchor.wav"
    manifest = {
        "schema": "k_guard_local_consistent_narration.v1",
        "model": "openbmb/VoxCPM2 local snapshot",
        "voice_design": "one synthetic Korean male anchor; calm low pitch; brisk professional delivery",
        "human_reference_audio_used": False,
        "synthetic_voice_anchor_used": True,
        "synthetic_voice_anchor_sha256": digest(anchor),
        "duration_seconds": duration,
        "sample_rate": final.samplerate,
        "channel_count": final.channels,
        "output_sha256": digest(output),
        "subtitle_sha256": digest(subtitles),
        "caption_cues": cues,
        "scenes": scene_records,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
