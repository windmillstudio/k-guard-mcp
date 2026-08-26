#!/usr/bin/env python3
"""Regenerate only ASR-flagged narration sentences and rebuild exact captions."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import numpy as np
import soundfile as sf
import torch
from voxcpm import VoxCPM

from generate_sentence_narration import (
    FINAL_DURATION,
    TARGET_SPEECH_END,
    SentenceAudio,
    atempo_chain,
    sha256,
    trim_speech,
    write_ass,
)


CORRECTIONS: dict[int, list[tuple[str, str]]] = {
    2: [("케이 가드 엠씨피 안경선배는 AI 코딩 흐름 안에 검수와 재검수를 붙입니다.",
         "K-Guard MCP 안경선배는 AI 코딩 흐름 안에 검수와 재검수를 붙입니다.")],
    4: [("이 저장소의 코드를 전용 파워셸 콘솔에서 직접 실행하고, 기다리는 시간만 편집해서 줄인 실제 기록입니다.",
         "이 저장소의 코드를 전용 파워셸 콘솔에서 직접 실행하고, 기다리는 시간만 편집해서 줄인 실제 기록입니다.")],
    5: [("먼저 공식 파이썬 엠씨피 클라이언트를 로컬 테스트 서버에 연결합니다.",
         "먼저 공식 파이썬 MCP 클라이언트를 로컬 테스트 서버에 연결합니다.")],
    6: [("정상 에코 요청은 그대로 통과하지만, 비밀 키 형태가 들어간 유출 요청은 프록시에서 즉시 멈춥니다.",
         "정상 에코 요청은 그대로 통과하지만, 비밀키 형태가 들어간 유출 요청은 프록시에서 즉시 멈춥니다.")],
    12: [("에이치티티피 프록시는 요청마다 새 트랜잭션을 만들고, 전달 전에 정책을 적용한 다음, 탐지와 차단 여부를 같은 감사 기록에 묶습니다.",
          "HTTP 프록시는 요청마다 새 트랜잭션을 만들고, 전달 전에 정책을 적용한 다음, 탐지와 차단 여부를 같은 감사 기록에 묶습니다.")],
    18: [("코드 안에 있는 데모 비밀키, 사용자 입력이 그대로 이어진 SQL, 인증 없이 노출되는 개인 데이터 응답을 같은 작업 범위에서 검사합니다.",
          "코드 안에 있는 데모 비밀키, 사용자 입력이 그대로 이어진 SQL, 인증 없이 노출되는 개인 데이터 응답을 같은 작업 범위에서 검사합니다.")],
    22: [("코드를 수정한 뒤에는 새 대상을 검사하는 척하지 않습니다.",
          "코드를 수정한 뒤에는 새 대상을 검사하는 척하지 않습니다.")],
    24: [("그 결과, 검토한 앱 범위의 차단 항목이 사라진 것을 확인합니다.",
          "그 결과 검토한 앱 범위의 차단 항목이 사라진 것을 확인합니다."),
         ("하지만 제품 전체 출시는 별도 검증이 끝날 때까지 계속 차단합니다.",
          "하지만 제품 전체 출시는 별도 검증이 끝날 때까지 계속 차단합니다.")],
    27: [("고정 픽스처와 독립 홀드 아웃, 계층 간 용어 일치도도 같은 실행에서 확인합니다.",
          "고정 픽스처와 독립 홀드아웃, 계층 간 용어 일치도도 같은 실행에서 확인합니다.")],
    34: [("케이 가드의 핵심은 점수를 많이 보여 주는 것이 아닙니다.",
          "K-Guard의 핵심은 점수를 많이 보여 주는 것이 아닙니다.")],
    36: [("바이브 코딩 결과물을 올리지 못하게 만드는 가장 큰 걱정이 보안과 개인정보라면, 안경선배가 그 사이에 놓인 실용적인 안전장치가 될 수 있습니다.",
          "바이브 코딩 결과물을 올리지 못하게 만드는 가장 큰 걱정이 보안과 개인정보라면, 안경선배가 그 사이에 놓인 실용적인 안전장치가 될 수 있습니다.")],
}

DISPLAY_OVERRIDES: dict[int, str] = {
    7: "클라이언트는 403 차단을 받고, 위험한 호출은 업스트림 도구에 한 번도 도달하지 않습니다.",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--base-sentence-dir", type=Path, required=True)
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

    base = json.loads(args.base_manifest.read_text(encoding="utf-8"))
    torch.manual_seed(20260940)
    model = VoxCPM.from_pretrained(
        str(args.model.resolve()), load_denoiser=False, local_files_only=True, device="cuda", optimize=False
    )
    sample_rate = int(model.tts_model.sample_rate)
    replacement_audio: dict[int, list[tuple[np.ndarray, str, str]]] = {}
    correction_counter = 0
    for index, units in CORRECTIONS.items():
        generated_units = []
        for unit_number, (tts_text, display_text) in enumerate(units):
            torch.manual_seed(20261000 + correction_counter)
            raw_path = args.work_dir / f"index-{index:02d}-{unit_number}-raw.wav"
            trimmed_path = args.work_dir / f"index-{index:02d}-{unit_number}-trimmed.wav"
            audio = model.generate(
                text=tts_text,
                reference_wav_path=str(args.anchor.resolve()),
                cfg_value=2.0,
                inference_timesteps=10,
                max_len=4096,
                normalize=False,
                retry_badcase=True,
            )
            sf.write(raw_path, audio, sample_rate, subtype="PCM_16")
            trimmed = trim_speech(np.asarray(audio, dtype=np.float32), sample_rate)
            sf.write(trimmed_path, trimmed, sample_rate, subtype="PCM_16")
            generated_units.append((trimmed, tts_text, display_text))
            correction_counter += 1
            total_units = sum(len(correction_units) for correction_units in CORRECTIONS.values())
            print(f"[{correction_counter:02d}/{total_units:02d}] index={index} unit={unit_number}", flush=True)
        replacement_audio[index] = generated_units

    pieces: list[np.ndarray] = []
    records: list[SentenceAudio] = []
    cursor = 0
    sequence_index = 0
    sequence_rows: list[dict[str, object]] = []
    base_rows = base["sentences"]
    for base_position, base_row in enumerate(base_rows):
        original_index = int(base_row["index"])
        paragraph = int(base_row["paragraph"])
        if original_index in replacement_audio:
            units = replacement_audio[original_index]
        else:
            path = args.base_sentence_dir / f"sentence-{original_index:02d}-trimmed.wav"
            audio, rate = sf.read(path, dtype="float32")
            if rate != sample_rate:
                raise RuntimeError(f"Sample-rate mismatch: {path}")
            spoken_text = str(base_row["text"])
            units = [(audio, spoken_text, DISPLAY_OVERRIDES.get(original_index, spoken_text))]
        for unit_position, (audio, spoken_text, display_text) in enumerate(units):
            start = cursor / sample_rate
            pieces.append(np.asarray(audio, dtype=np.float32))
            cursor += len(audio)
            end = cursor / sample_rate
            record = SentenceAudio(sequence_index, paragraph, display_text, args.work_dir, start, end)
            records.append(record)
            sequence_rows.append(
                {
                    "sequence_index": sequence_index,
                    "source_index": original_index,
                    "unit": unit_position,
                    "spoken_text": spoken_text,
                    "display_text": display_text,
                    "raw_start": round(start, 6),
                    "raw_end": round(end, 6),
                }
            )
            sequence_index += 1
            is_last_unit = unit_position == len(units) - 1
            is_last_sentence = base_position == len(base_rows) - 1 and is_last_unit
            if not is_last_sentence:
                next_paragraph = paragraph
                if is_last_unit and base_position + 1 < len(base_rows):
                    next_paragraph = int(base_rows[base_position + 1]["paragraph"])
                gap_seconds = 0.18 if is_last_unit and next_paragraph != paragraph else 0.09
                gap = np.zeros(round(sample_rate * gap_seconds), dtype=np.float32)
                pieces.append(gap)
                cursor += len(gap)

    combined = np.concatenate(pieces)
    combined_path = args.work_dir / "corrected-combined-raw.wav"
    sf.write(combined_path, combined, sample_rate, subtype="PCM_16")
    raw_duration = len(combined) / sample_rate
    speed = raw_duration / TARGET_SPEECH_END
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
    result = {
        "schema": "k_guard_corrected_sentence_narration.v1",
        "same_synthetic_voice_anchor": True,
        "human_reference_audio_used": False,
        "synthetic_voice_anchor_sha256": sha256(args.anchor),
        "correction_source_indices": sorted(CORRECTIONS),
        "sentence_unit_count": len(records),
        "raw_duration_seconds": round(raw_duration, 6),
        "speed_factor": round(speed, 10),
        "target_speech_end_seconds": TARGET_SPEECH_END,
        "final_duration_seconds": sf.info(args.output).frames / sf.info(args.output).samplerate,
        "output_audio_sha256": sha256(args.output),
        "subtitle_sha256": sha256(args.subtitles),
        "cues": cues,
        "sequence": sequence_rows,
        "raw_returned": False,
    }
    args.manifest.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"units": len(records), "raw_seconds": raw_duration, "speed": speed}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
