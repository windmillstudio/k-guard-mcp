#!/usr/bin/env python3
"""Generate one synthetic male voice anchor, seven aligned narration scenes, and ASS captions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import soundfile as sf
import torch
from voxcpm import VoxCPM


VOICE_DESIGN = (
    "(A trustworthy Korean man in his thirties, calm low-pitched voice, clear diction, "
    "brisk professional narration, steady identity, no exaggerated emotion)"
)
SCENE_DURATIONS = (22.0, 27.0, 29.0, 34.0, 22.0, 21.0, 25.0)


def sha256(path: Path) -> str:
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
    centiseconds = max(0, round(seconds * 100))
    hours, remainder = divmod(centiseconds, 360000)
    minutes, remainder = divmod(remainder, 6000)
    secs, cs = divmod(remainder, 100)
    return f"{hours}:{minutes:02d}:{secs:02d}.{cs:02d}"


def ass_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}").replace("\n", " ")


def write_ass(paragraphs: list[str], output: Path) -> list[dict[str, object]]:
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
    lines = [header]
    cues: list[dict[str, object]] = []
    scene_start = 0.0
    for paragraph, duration in zip(paragraphs, SCENE_DURATIONS, strict=True):
        sentences = [piece.strip() for piece in re.split(r"(?<=[.!?。])\s+|(?<=다\.)\s+", paragraph) if piece.strip()]
        if not sentences:
            sentences = [paragraph]
        weights = [max(1, len(re.sub(r"\s", "", sentence))) for sentence in sentences]
        weight_sum = sum(weights)
        cursor = scene_start
        for index, (sentence, weight) in enumerate(zip(sentences, weights, strict=True)):
            end = scene_start + duration if index == len(sentences) - 1 else cursor + duration * weight / weight_sum
            caption = ass_escape(sentence)
            lines.append(f"Dialogue: 0,{ass_time(cursor)},{ass_time(end)},Default,,0,0,0,,{caption}\n")
            cues.append({"start": round(cursor, 3), "end": round(end, 3), "text": sentence})
            cursor = end
        scene_start += duration
    output.write_text("".join(lines), encoding="utf-8-sig", newline="\n")
    return cues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--text", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--subtitles", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    work_dir = args.work_dir.resolve()
    output = args.output.resolve()
    subtitles = args.subtitles.resolve()
    manifest_path = args.manifest.resolve()
    for path in (work_dir, output, subtitles, manifest_path):
        if path.exists():
            raise SystemExit(f"Refusing to overwrite: {path}")
    work_dir.mkdir(parents=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    paragraphs = [piece.strip() for piece in re.split(r"(?:\r?\n){2,}", args.text.read_text(encoding="utf-8")) if piece.strip()]
    if len(paragraphs) != len(SCENE_DURATIONS):
        raise RuntimeError(f"Expected {len(SCENE_DURATIONS)} narration paragraphs; got {len(paragraphs)}")

    torch.manual_seed(20260826)
    model = VoxCPM.from_pretrained(
        str(args.model.resolve()), load_denoiser=False, local_files_only=True, device="cuda", optimize=False
    )
    sample_rate = int(model.tts_model.sample_rate)
    anchor_text = "안녕하세요. 안경선배가 실제 실행 화면을 빠르고 차분하게 설명하겠습니다."
    anchor_path = work_dir / "synthetic-voice-anchor.wav"
    anchor = model.generate(
        text=VOICE_DESIGN + anchor_text,
        cfg_value=2.0,
        inference_timesteps=10,
        max_len=4096,
        normalize=False,
        retry_badcase=True,
    )
    sf.write(anchor_path, anchor, sample_rate, subtype="PCM_16")

    processed: list[Path] = []
    scenes: list[dict[str, object]] = []
    for index, (paragraph, duration) in enumerate(zip(paragraphs, SCENE_DURATIONS, strict=True)):
        torch.manual_seed(20260827 + index)
        raw_path = work_dir / f"scene-{index:02d}-raw.wav"
        fixed_path = work_dir / f"scene-{index:02d}-fixed.wav"
        wav = model.generate(
            text=paragraph,
            reference_wav_path=str(anchor_path),
            cfg_value=2.0,
            inference_timesteps=10,
            max_len=12288,
            normalize=False,
            retry_badcase=True,
        )
        sf.write(raw_path, wav, sample_rate, subtype="PCM_16")
        raw_info = sf.info(raw_path)
        raw_duration = raw_info.frames / raw_info.samplerate
        speech_window = max(0.5, duration - 0.18)
        speed = raw_duration / speech_window
        filters = [atempo_chain(speed), "adelay=70", "loudnorm=I=-18:TP=-2:LRA=7", "apad", f"atrim=duration={duration:.3f}"]
        subprocess.run(
            [str(args.ffmpeg.resolve()), "-hide_banner", "-loglevel", "error", "-y", "-i", str(raw_path),
             "-af", ",".join(filters), "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", "-t", f"{duration:.3f}", str(fixed_path)],
            check=True,
        )
        processed.append(fixed_path)
        scenes.append({
            "index": index, "start": sum(SCENE_DURATIONS[:index]), "end": sum(SCENE_DURATIONS[: index + 1]),
            "text": paragraph, "raw_duration_seconds": round(raw_duration, 6), "speed_factor": round(speed, 8),
            "raw_sha256": sha256(raw_path), "fixed_sha256": sha256(fixed_path),
        })

    concat_path = work_dir / "concat.txt"
    concat_path.write_text("".join(f"file '{path.as_posix()}'\n" for path in processed), encoding="utf-8", newline="\n")
    subprocess.run(
        [str(args.ffmpeg.resolve()), "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(concat_path),
         "-t", "180", "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(output)],
        check=True,
    )
    cues = write_ass(paragraphs, subtitles)
    final_info = sf.info(output)
    final_duration = final_info.frames / final_info.samplerate
    if abs(final_duration - 180.0) > 0.01:
        raise RuntimeError(f"Narration duration drifted: {final_duration}")
    manifest = {
        "schema": "k_guard_local_consistent_narration.v1",
        "model": "openbmb/VoxCPM2 local snapshot",
        "voice_design": "one synthetic Korean male anchor; calm low pitch; brisk professional delivery",
        "human_reference_audio_used": False,
        "synthetic_voice_anchor_used": True,
        "synthetic_voice_anchor_sha256": sha256(anchor_path),
        "duration_seconds": final_duration,
        "sample_rate": final_info.samplerate,
        "channel_count": final_info.channels,
        "output_sha256": sha256(output),
        "subtitle_sha256": sha256(subtitles),
        "caption_cues": cues,
        "scenes": scenes,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
