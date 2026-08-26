#!/usr/bin/env python3
"""Audit every generated sentence independently with local Whisper."""

from __future__ import annotations

import argparse
import difflib
import json
import re
from pathlib import Path

from faster_whisper import WhisperModel


def normalized(text: str) -> str:
    return re.sub(r"[^0-9a-z가-힣]", "", text.casefold())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sentence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"Refusing to overwrite: {args.output}")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    model = WhisperModel(str(args.model.resolve()), device="cuda", compute_type="float16", local_files_only=True)
    rows = []
    for row in manifest["sentences"]:
        index = int(row["index"])
        path = args.sentence_dir / f"sentence-{index:02d}-trimmed.wav"
        segments, _ = model.transcribe(
            str(path.resolve()), language="ko", beam_size=5, word_timestamps=True,
            vad_filter=False, condition_on_previous_text=False,
        )
        segments = list(segments)
        transcript = "".join(segment.text for segment in segments).strip()
        expected_norm = normalized(row["text"])
        actual_norm = normalized(transcript)
        ratio = difflib.SequenceMatcher(None, expected_norm, actual_norm).ratio()
        prefix = expected_norm[: min(10, len(expected_norm))]
        prefix_present = prefix in actual_norm if prefix else True
        rows.append(
            {
                "index": index,
                "expected": row["text"],
                "transcript": transcript,
                "similarity": round(ratio, 4),
                "expected_prefix_present": prefix_present,
                "first_word_start": next(
                    (word.start for segment in segments for word in (segment.words or []) if word.start is not None),
                    None,
                ),
            }
        )
        print(f"[{index + 1:02d}/38] similarity={ratio:.3f} prefix={prefix_present}", flush=True)
    failures = [row for row in rows if row["similarity"] < 0.70 or not row["expected_prefix_present"]]
    payload = {
        "schema": "k_guard_sentence_asr_audit.v1",
        "sentence_count": len(rows),
        "failure_count": len(failures),
        "minimum_similarity": min(row["similarity"] for row in rows),
        "rows": rows,
        "failures": failures,
        "raw_returned": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sentences": len(rows), "failures": len(failures)}, ensure_ascii=False))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
