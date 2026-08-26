#!/usr/bin/env python3
"""Create an unbiased local Whisper transcript for narration review."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from faster_whisper import WhisperModel


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--audio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"Refusing to overwrite: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    model = WhisperModel(
        str(args.model.resolve()), device="cuda", compute_type="float16", local_files_only=True
    )
    segments, info = model.transcribe(
        str(args.audio.resolve()),
        language="ko",
        beam_size=5,
        word_timestamps=True,
        vad_filter=False,
        condition_on_previous_text=True,
    )
    rows = []
    for segment in segments:
        rows.append(
            {
                "start": segment.start,
                "end": segment.end,
                "text": segment.text,
                "words": [
                    {
                        "start": word.start,
                        "end": word.end,
                        "word": word.word,
                        "probability": word.probability,
                    }
                    for word in (segment.words or [])
                ],
            }
        )
    payload = {
        "schema": "k_guard_local_whisper_transcript.v1",
        "model": args.model.name,
        "language": info.language,
        "duration": info.duration,
        "segments": rows,
        "full_text": "".join(row["text"] for row in rows),
        "initial_prompt_used": False,
        "vad_filter": False,
        "raw_returned": False,
    }
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"segments": len(rows), "duration": info.duration}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
