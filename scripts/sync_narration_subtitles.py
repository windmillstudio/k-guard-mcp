#!/usr/bin/env python3
"""Fit existing local narration inside 177 seconds and align captions to audible pauses."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
from pathlib import Path

import numpy as np
import soundfile as sf


TARGET_SPEECH_SECONDS = 177.0
FINAL_SECONDS = 180.0
SCENE_DURATIONS = (22.0, 27.0, 29.0, 34.0, 22.0, 21.0, 25.0)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ass_time(seconds: float) -> str:
    cs = max(0, round(seconds * 100))
    hours, remainder = divmod(cs, 360000)
    minutes, remainder = divmod(remainder, 6000)
    secs, hundredths = divmod(remainder, 100)
    return f"{hours}:{minutes:02d}:{secs:02d}.{hundredths:02d}"


def ass_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}").replace("\n", " ")


def silent_intervals(audio: np.ndarray, sample_rate: int) -> list[tuple[float, float]]:
    frame_samples = max(1, round(sample_rate * 0.01))
    usable = len(audio) - (len(audio) % frame_samples)
    frames = audio[:usable].reshape(-1, frame_samples)
    rms = np.sqrt(np.mean(np.square(frames, dtype=np.float64), axis=1))
    silent = rms < (10 ** (-43.0 / 20.0))
    minimum_frames = 9
    intervals: list[tuple[float, float]] = []
    start: int | None = None
    for index, value in enumerate(silent):
        if value and start is None:
            start = index
        elif not value and start is not None:
            if index - start >= minimum_frames:
                intervals.append((start * 0.01, index * 0.01))
            start = None
    if start is not None and len(silent) - start >= minimum_frames:
        intervals.append((start * 0.01, len(silent) * 0.01))
    return intervals


def choose_boundaries(
    expected: list[float],
    candidates: list[tuple[float, float]],
    scene_start: float,
    scene_end: float,
) -> list[float]:
    if not expected:
        return []
    usable = [
        ((start + end) / 2.0, end - start)
        for start, end in candidates
        if scene_start + 0.35 < (start + end) / 2.0 < scene_end - 0.35
    ]
    if len(usable) < len(expected):
        return expected

    count = len(expected)
    inf = float("inf")
    costs = [[inf] * len(usable) for _ in range(count)]
    previous = [[-1] * len(usable) for _ in range(count)]
    span = max(1.0, scene_end - scene_start)
    for j, (point, duration) in enumerate(usable):
        costs[0][j] = abs(point - expected[0]) / span - min(duration, 0.5) * 0.10
    for i in range(1, count):
        for j, (point, duration) in enumerate(usable):
            local = abs(point - expected[i]) / span - min(duration, 0.5) * 0.10
            best_cost = inf
            best_index = -1
            for k in range(j):
                if point - usable[k][0] < 0.45:
                    continue
                value = costs[i - 1][k] + local
                if value < best_cost:
                    best_cost = value
                    best_index = k
            costs[i][j] = best_cost
            previous[i][j] = best_index
    end_index = min(range(len(usable)), key=lambda j: costs[-1][j])
    if not math.isfinite(costs[-1][end_index]):
        return expected
    selected = [end_index]
    for i in range(count - 1, 0, -1):
        selected.append(previous[i][selected[-1]])
    selected.reverse()
    points = [usable[index][0] for index in selected]
    if any(abs(point - target) > 2.8 for point, target in zip(points, expected, strict=True)):
        return expected
    return points


def write_ass(cues: list[dict[str, object]], path: Path) -> None:
    header = """[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
WrapStyle: 0
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name,Fontname,Fontsize,PrimaryColour,SecondaryColour,OutlineColour,BackColour,Bold,Italic,Underline,StrikeOut,ScaleX,ScaleY,Spacing,Angle,BorderStyle,Outline,Shadow,Alignment,MarginL,MarginR,MarginV,Encoding
Style: Default,Malgun Gothic,35,&H00FFFFFF,&H00FFFFFF,&H00101010,&HC8000000,-1,0,0,0,100,100,0,0,3,1,0,2,70,70,16,1

[Events]
Format: Layer,Start,End,Style,Name,MarginL,MarginR,MarginV,Effect,Text
"""
    lines = [header]
    for cue in cues:
        lines.append(
            f"Dialogue: 0,{ass_time(float(cue['start']))},{ass_time(float(cue['end']))},"
            f"Default,,0,0,0,,{ass_escape(str(cue['text']))}\n"
        )
    path.write_text("".join(lines), encoding="utf-8-sig", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audio", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--output-audio", type=Path, required=True)
    parser.add_argument("--output-subtitles", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()

    for path in (args.output_audio, args.output_subtitles, args.output_manifest):
        if path.exists():
            raise SystemExit(f"Refusing to overwrite: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)

    speed = FINAL_SECONDS / TARGET_SPEECH_SECONDS
    subprocess.run(
        [
            str(args.ffmpeg.resolve()), "-hide_banner", "-loglevel", "error", "-y",
            "-i", str(args.audio.resolve()), "-af",
            f"atempo={speed:.10f},apad,atrim=duration={FINAL_SECONDS:.3f}",
            "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(args.output_audio.resolve()),
        ],
        check=True,
    )

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    source_cues = manifest["caption_cues"]
    scale = TARGET_SPEECH_SECONDS / FINAL_SECONDS
    audio, sample_rate = sf.read(args.output_audio, dtype="float32")
    if audio.ndim > 1:
        audio = audio[:, 0]
    silences = silent_intervals(audio, sample_rate)

    scaled_scene_ends = np.cumsum(np.asarray(SCENE_DURATIONS) * scale).tolist()
    scaled_scene_starts = [0.0, *scaled_scene_ends[:-1]]
    aligned: list[dict[str, object]] = []
    changes: list[dict[str, float]] = []
    for scene_start, scene_end in zip(scaled_scene_starts, scaled_scene_ends, strict=True):
        scene_cues = [
            cue for cue in source_cues
            if scene_start / scale - 0.001 <= float(cue["start"]) < scene_end / scale - 0.001
        ]
        expected = [float(cue["end"]) * scale for cue in scene_cues[:-1]]
        boundaries = choose_boundaries(expected, silences, scene_start, scene_end)
        points = [scene_start, *boundaries, scene_end]
        for index, cue in enumerate(scene_cues):
            end = points[index + 1]
            if scene_end == scaled_scene_ends[-1] and index == len(scene_cues) - 1:
                final_silences = [start for start, stop in silences if 170.0 < start < 179.5 and stop >= 179.5]
                if final_silences:
                    end = min(178.0, final_silences[-1] + 0.35)
            aligned.append({"start": round(points[index], 3), "end": round(end, 3), "text": cue["text"]})
        changes.extend(
            {"estimated": round(old, 3), "aligned": round(new, 3), "delta": round(new - old, 3)}
            for old, new in zip(expected, boundaries, strict=True)
        )

    write_ass(aligned, args.output_subtitles)
    last_non_silent = max(
        (start for start, end in silences if end >= 179.5),
        default=TARGET_SPEECH_SECONDS,
    )
    result = {
        "schema": "k_guard_audio_aligned_subtitles.v1",
        "source_audio_sha256": sha256(args.audio),
        "output_audio_sha256": sha256(args.output_audio),
        "output_subtitle_sha256": sha256(args.output_subtitles),
        "same_synthetic_voice_preserved": True,
        "speed_factor": round(speed, 10),
        "target_speech_window_seconds": TARGET_SPEECH_SECONDS,
        "final_duration_seconds": FINAL_SECONDS,
        "detected_final_silence_start": round(last_non_silent, 3),
        "subtitle_cues": aligned,
        "boundary_adjustments": changes,
        "raw_returned": False,
    }
    args.output_manifest.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({"cues": len(aligned), "final_silence_start": last_non_silent}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
