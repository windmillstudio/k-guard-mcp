from __future__ import annotations

import argparse
import json
from pathlib import Path

from media_evidence import probe_video


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode and attest the contest submission video.")
    parser.add_argument("--video", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--media-bin", type=Path)
    args = parser.parse_args()
    try:
        media_bin = args.media_bin.resolve(strict=True) if args.media_bin else None
        report = probe_video(
            args.video,
            ffprobe_executable=(media_bin / "ffprobe.exe") if media_bin else None,
            ffmpeg_executable=(media_bin / "ffmpeg.exe") if media_bin else None,
        )
    except Exception as exc:
        print(json.dumps({"valid": False, "error_type": type(exc).__name__}, ensure_ascii=False))
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"valid": report["valid"], "duration_seconds": report["duration_seconds"]}))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
