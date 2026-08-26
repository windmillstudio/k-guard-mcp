#!/usr/bin/env python3
"""Generate the second half of the four-AI narration scene with local VoxCPM2."""

from __future__ import annotations

import argparse
from pathlib import Path

import soundfile as sf
import torch
from voxcpm import VoxCPM


VOICE = (
    "(A trustworthy Korean man in his thirties, calm low-pitched voice, clear diction, "
    "brisk professional delivery, no exaggerated emotion)"
)
TEXT = (
    "네 분할 비교에서는 감사 결과와 세 프로세스 기록을 동시에 확인합니다. "
    "읽기 전용 감사, 도구 검색, 대표 호출, 마스킹된 결과가 각각 어떻게 남는지 한 화면에서 비교합니다."
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"Refusing to overwrite: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.manual_seed(20260899)
    model = VoxCPM.from_pretrained(
        str(args.model.resolve()),
        load_denoiser=False,
        local_files_only=True,
        device="cuda",
        optimize=False,
    )
    wav = model.generate(
        text=VOICE + TEXT,
        cfg_value=2.0,
        inference_timesteps=10,
        max_len=4096,
        normalize=False,
        retry_badcase=True,
    )
    sf.write(output, wav, int(model.tts_model.sample_rate), subtype="PCM_16")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
