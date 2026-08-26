#!/usr/bin/env python3
"""Generate every narration sentence separately with one local synthetic voice anchor."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import soundfile as sf
import torch
from voxcpm import VoxCPM


FINAL_DURATION = 180.0
TARGET_SPEECH_END = 176.8


@dataclass
class SentenceAudio:
    index: int
    paragraph: int
    text: str
    path: Path
    start: float
    end: float


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
    return ",".join(f"atempo={factor:.10f}" for factor in factors)


def ass_time(seconds: float) -> str:
    cs = max(0, round(seconds * 100))
    hours, remainder = divmod(cs, 360000)
    minutes, remainder = divmod(remainder, 6000)
    secs, hundredths = divmod(remainder, 100)
    return f"{hours}:{minutes:02d}:{secs:02d}.{hundredths:02d}"


def ass_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}")


def split_text(text: str) -> list[list[str]]:
    paragraphs = [piece.strip() for piece in re.split(r"(?:\r?\n){2,}", text) if piece.strip()]
    result: list[list[str]] = []
    for paragraph in paragraphs:
        sentences = [piece.strip() for piece in re.split(r"(?<=[.!?。])\s+|(?<=다\.)\s+", paragraph) if piece.strip()]
        result.append(sentences)
    return result


def trim_speech(audio: np.ndarray, sample_rate: int) -> np.ndarray:
    frame = max(1, round(sample_rate * 0.01))
    usable = len(audio) - len(audio) % frame
    if usable <= 0:
        return audio
    rms = np.sqrt(np.mean(np.square(audio[:usable].reshape(-1, frame), dtype=np.float64), axis=1))
    active = np.flatnonzero(rms > 10 ** (-48.0 / 20.0))
    if not len(active):
        raise RuntimeError("Generated sentence contains no audible speech")
    lead = max(0, int(active[0] * frame - sample_rate * 0.06))
    tail = min(len(audio), int((active[-1] + 1) * frame + sample_rate * 0.10))
    return audio[lead:tail]


def write_ass(records: list[SentenceAudio], speed: float, output: Path) -> list[dict[str, object]]:
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
    cues: list[dict[str, object]] = []
    for index, record in enumerate(records):
        start = record.start / speed
        speech_end = record.end / speed
        if index + 1 < len(records):
            next_start = records[index + 1].start / speed
            end = min(next_start - 0.02, speech_end + 0.10)
        else:
            end = min(177.2, speech_end + 0.25)
        end = max(start + 0.2, end)
        lines.append(
            f"Dialogue: 0,{ass_time(start)},{ass_time(end)},Default,,0,0,0,,{ass_escape(record.text)}\n"
        )
        cues.append(
            {
                "index": record.index,
                "paragraph": record.paragraph,
                "start": round(start, 3),
                "speech_end": round(speech_end, 3),
                "end": round(end, 3),
                "text": record.text,
            }
        )
    output.write_text("".join(lines), encoding="utf-8-sig", newline="\n")
    return cues


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--text", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--subtitles", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    for path in (args.work_dir, args.output, args.subtitles, args.manifest):
        if path.exists():
            raise SystemExit(f"Refusing to overwrite: {path}")
    args.work_dir.mkdir(parents=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.subtitles.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)

    paragraphs = split_text(args.text.read_text(encoding="utf-8"))
    if len(paragraphs) != 7:
        raise RuntimeError(f"Expected seven paragraphs, got {len(paragraphs)}")
    flattened = [(p_index, sentence) for p_index, sentences in enumerate(paragraphs) for sentence in sentences]
    if len(flattened) != 38:
        raise RuntimeError(f"Expected 38 sentences, got {len(flattened)}")

    torch.manual_seed(20260830)
    model = VoxCPM.from_pretrained(
        str(args.model.resolve()), load_denoiser=False, local_files_only=True, device="cuda", optimize=False
    )
    sample_rate = int(model.tts_model.sample_rate)
    pieces: list[np.ndarray] = []
    records: list[SentenceAudio] = []
    cursor_samples = 0
    for index, (paragraph_index, sentence) in enumerate(flattened):
        torch.manual_seed(20260900 + index)
        raw_path = args.work_dir / f"sentence-{index:02d}-raw.wav"
        trimmed_path = args.work_dir / f"sentence-{index:02d}-trimmed.wav"
        generated = model.generate(
            text=sentence,
            reference_wav_path=str(args.anchor.resolve()),
            cfg_value=2.0,
            inference_timesteps=10,
            max_len=4096,
            normalize=False,
            retry_badcase=True,
        )
        sf.write(raw_path, generated, sample_rate, subtype="PCM_16")
        trimmed = trim_speech(np.asarray(generated, dtype=np.float32), sample_rate)
        sf.write(trimmed_path, trimmed, sample_rate, subtype="PCM_16")
        start = cursor_samples / sample_rate
        pieces.append(trimmed)
        cursor_samples += len(trimmed)
        end = cursor_samples / sample_rate
        records.append(SentenceAudio(index, paragraph_index, sentence, trimmed_path, start, end))
        if index + 1 < len(flattened):
            next_paragraph = flattened[index + 1][0]
            gap_seconds = 0.18 if next_paragraph != paragraph_index else 0.09
            gap = np.zeros(round(sample_rate * gap_seconds), dtype=np.float32)
            pieces.append(gap)
            cursor_samples += len(gap)
        print(f"[{index + 1:02d}/38] {sentence[:42]}", flush=True)

    combined = np.concatenate(pieces)
    combined_path = args.work_dir / "sentences-combined-raw.wav"
    sf.write(combined_path, combined, sample_rate, subtype="PCM_16")
    raw_duration = len(combined) / sample_rate
    speed = raw_duration / TARGET_SPEECH_END
    if not 0.78 <= speed <= 1.35:
        raise RuntimeError(f"Unsafe narration speed factor: {speed}")
    subprocess.run(
        [
            str(args.ffmpeg.resolve()), "-hide_banner", "-loglevel", "error", "-y",
            "-i", str(combined_path), "-af",
            f"{atempo_chain(speed)},loudnorm=I=-18:TP=-2:LRA=7,apad,atrim=duration={FINAL_DURATION}",
            "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", str(args.output.resolve()),
        ],
        check=True,
    )
    cues = write_ass(records, speed, args.subtitles)
    info = sf.info(args.output)
    result = {
        "schema": "k_guard_sentence_narration.v1",
        "model": "openbmb/VoxCPM2 local snapshot",
        "same_synthetic_voice_anchor": True,
        "human_reference_audio_used": False,
        "synthetic_voice_anchor_sha256": sha256(args.anchor),
        "sentence_count": len(records),
        "paragraph_count": len(paragraphs),
        "raw_combined_duration_seconds": round(raw_duration, 6),
        "speed_factor": round(speed, 10),
        "target_speech_end_seconds": TARGET_SPEECH_END,
        "final_duration_seconds": info.frames / info.samplerate,
        "output_audio_sha256": sha256(args.output),
        "subtitle_sha256": sha256(args.subtitles),
        "cues": cues,
        "sentences": [
            {
                "index": record.index,
                "paragraph": record.paragraph,
                "text": record.text,
                "trimmed_sha256": sha256(record.path),
                "raw_start": round(record.start, 6),
                "raw_end": round(record.end, 6),
            }
            for record in records
        ],
        "raw_returned": False,
    }
    args.manifest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"sentences": len(records), "raw_seconds": raw_duration, "speed": speed}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
