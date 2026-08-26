#!/usr/bin/env python3
"""Generate the fixed 180-second Korean contest narration with local VoxCPM2."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import soundfile as sf
import torch
from voxcpm import VoxCPM


VOICE = (
    "(A trustworthy Korean man in his thirties, calm low-pitched voice, clear diction, "
    "brisk professional delivery, no exaggerated emotion)"
)

SCENES = (
    (0, 5, "개인정보 사고와 개보위 조사 경험이, 이 프로젝트의 출발점이었습니다."),
    (5, 10, "K-Guard MCP 안경선배는 AI코딩 흐름 안에 검수와 재검수를 붙입니다."),
    (10, 30, "먼저 실제 MCP 공격입니다. 공식 파이썬 클라이언트의 정상 요청은 통과합니다. 비밀값 유출 요청은 전달 전에 차단되고 업스트림 호출은 발생하지 않습니다. 탐지 규칙과 차단 결과는 같은 트랜잭션 영수증으로 남고, 변조된 영수증은 거부됩니다."),
    (30, 46, "핵심 로직은 요청을 먼저 검사하고 정책을 적용한 뒤, 판단 근거를 영수증으로 묶습니다. 비밀키와 웹 공격, 한국 식별번호와 민감정보를 실제 규칙으로 빠르게 분류합니다."),
    (46, 68, "취약한 앱을 실제로 검사합니다. 사이트, API, 개인정보와 배포 준비를 함께 확인하고, 인증 없는 개인정보 응답과 비밀값, SQL 위험을 찾으면 가장 먼저 고칠 항목과 함께 보류합니다."),
    (68, 86, "검출 결과를 따라 코드를 고칩니다. 하드코딩된 비밀값을 제거하고, SQL 입력은 바인딩하며, 공개 응답에서 개인 레코드를 없앱니다. 화면은 취약본과 수정본의 실제 차이입니다."),
    (86, 102, "수정 뒤에는 같은 대상과 같은 범위를 다시 검사합니다. 이전 보고서를 연결해 위험이 코드 변화 때문에 사라졌는지 비교하고, 확인되지 않은 조건은 계속 닫힌 상태로 둡니다."),
    (102, 122, "한국 환경에서 자주 다루는 주민번호와 외국인번호, 여권과 면허, 사업자와 법인번호, 의료와 장애, 생체정보를 유형별로 검출합니다. 원문 값은 화면이나 결과에 돌려주지 않습니다."),
    (122, 138, "차단, 양방향 마스킹, 공식 SDK 상호운용, 한국 개인정보 분류, 수정 후 재검수 경로를 실제 테스트로 확인합니다. 새로 설치한 패키지에서도 도구 검색과 대표 호출을 다시 검증합니다."),
    (138, 175, "Claude Opus 장면은 고정 증거 묶음과 감사 영수증을 읽기만 한 기록입니다. Codex, Grok, Antigravity 장면은 각각 같은 제품 도구의 검색과 대표 호출을 실제 프로세스 기록으로 보여줍니다. 서로 다른 개발 도구에서도 검수 흐름이 유지되는지 확인했고, 어느 공개 화면에도 API 키나 원문 개인정보를 남기지 않았습니다."),
    (175, 180, "바이브 코딩 결과물을 안전하게 공개하고, 더 믿을 수 있는 생태계에 기여하겠습니다."),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atempo_chain(ratio: float) -> str:
    factors: list[float] = []
    while ratio > 2.0:
        factors.append(2.0)
        ratio /= 2.0
    factors.append(max(0.5, ratio))
    return ",".join(f"atempo={factor:.8f}" for factor in factors)


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    model_path = args.model.resolve()
    ffmpeg = args.ffmpeg.resolve()
    work_dir = args.work_dir.resolve()
    output = args.output.resolve()
    manifest_path = args.manifest.resolve()
    for path in (output, manifest_path):
        if path.exists():
            raise SystemExit(f"Refusing to overwrite: {path}")
    work_dir.mkdir(parents=True, exist_ok=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(20260826)
    model = VoxCPM.from_pretrained(
        str(model_path),
        load_denoiser=False,
        local_files_only=True,
        device="cuda",
        optimize=False,
    )
    sample_rate = int(model.tts_model.sample_rate)
    manifest_scenes: list[dict[str, object]] = []
    processed_paths: list[Path] = []

    for index, (start, end, text) in enumerate(SCENES):
        torch.manual_seed(20260826 + index)
        raw = work_dir / f"scene-{index:02d}-raw.wav"
        processed = work_dir / f"scene-{index:02d}-fixed.wav"
        wav = model.generate(
            text=VOICE + text,
            cfg_value=2.0,
            inference_timesteps=10,
            max_len=4096,
            normalize=False,
            retry_badcase=True,
        )
        sf.write(raw, wav, sample_rate, subtype="PCM_16")
        raw_info = sf.info(raw)
        raw_duration = raw_info.frames / raw_info.samplerate
        scene_duration = float(end - start)
        speech_window = max(0.5, scene_duration - 0.28)
        speed = max(1.0, raw_duration / speech_window)
        filters: list[str] = []
        if speed > 1.000001:
            filters.append(atempo_chain(speed))
        filters.extend(
            [
                "adelay=120",
                "loudnorm=I=-18:TP=-2:LRA=7",
                "apad",
                f"atrim=duration={scene_duration:.3f}",
            ]
        )
        run(
            [
                str(ffmpeg),
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(raw),
                "-af",
                ",".join(filters),
                "-ar",
                "48000",
                "-ac",
                "1",
                "-c:a",
                "pcm_s16le",
                "-t",
                f"{scene_duration:.3f}",
                str(processed),
            ]
        )
        processed_paths.append(processed)
        manifest_scenes.append(
            {
                "index": index,
                "start": start,
                "end": end,
                "text": text,
                "raw_duration_seconds": round(raw_duration, 6),
                "speed_factor": round(speed, 8),
                "raw_sha256": sha256(raw),
                "processed_sha256": sha256(processed),
            }
        )

    concat = work_dir / "concat.txt"
    concat.write_text(
        "".join(f"file '{path.as_posix()}'\n" for path in processed_paths),
        encoding="utf-8",
        newline="\n",
    )
    run(
        [
            str(ffmpeg),
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat),
            "-t",
            "180",
            "-ar",
            "48000",
            "-ac",
            "1",
            "-c:a",
            "pcm_s16le",
            str(output),
        ]
    )
    final_info = sf.info(output)
    final_duration = final_info.frames / final_info.samplerate
    if abs(final_duration - 180.0) > 0.01:
        raise RuntimeError(f"Narration duration drifted: {final_duration}")
    manifest = {
        "schema": "k_guard_voxcpm2_narration.v1",
        "model": "openbmb/VoxCPM2 local snapshot",
        "model_path_name": model_path.name,
        "voice_design": "trusted Korean male in his thirties; calm low pitch; brisk delivery",
        "reference_audio_used": False,
        "sample_rate": final_info.samplerate,
        "channel_count": final_info.channels,
        "duration_seconds": final_duration,
        "output_sha256": sha256(output),
        "scenes": manifest_scenes,
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
