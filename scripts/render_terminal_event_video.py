from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


COLORS = {
    "default": "#d6dfd8",
    "green": "#8be85f",
    "cyan": "#5ec8d8",
    "red": "#f06b63",
    "yellow": "#e5be63",
    "dim": "#78867d",
}


def font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        Path("C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf"),
        Path("C:/Windows/Fonts/CascadiaMono.ttf"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return ImageFont.truetype(str(candidate), size=size)
    return ImageFont.load_default()


def load_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        event = json.loads(raw)
        if not isinstance(event.get("t"), (int, float)) or not isinstance(event.get("text"), str):
            raise SystemExit(f"Invalid event at line {line_number}")
        if events and float(event["t"]) < float(events[-1]["t"]):
            raise SystemExit("Event timestamps are not monotonic")
        events.append(event)
    if not events or not any("K-GUARD WALKTHROUGH PASS" in str(item["text"]) for item in events):
        raise SystemExit("The actual-run completion marker is missing")
    visible = "\n".join(str(item["text"]) for item in events)
    if "sk-[redacted-demo]" not in visible or "sk-demo-" in visible:
        raise SystemExit("Expected masking contract was not satisfied")
    return events


def wrapped_lines(events: list[dict[str, object]], index: int, *, width: int, limit: int) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for event in events[: index + 1]:
        text = str(event["text"])
        color = str(event.get("color", "default"))
        if not text:
            lines.append(("", color))
            continue
        parts = textwrap.wrap(text, width=width, replace_whitespace=False, drop_whitespace=False) or [""]
        lines.extend((part, color) for part in parts)
    return lines[-limit:]


def render_frame(
    events: list[dict[str, object]],
    index: int,
    *,
    width: int,
    height: int,
    duration: float,
) -> Image.Image:
    image = Image.new("RGB", (width, height), "#070a09")
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, width, 52), fill="#0d1411")
    draw.line((0, 52, width, 52), fill="#2a3a31", width=1)
    draw.ellipse((20, 18, 32, 30), fill="#8be85f")
    draw.ellipse((40, 18, 52, 30), fill="#5ec8d8")
    draw.ellipse((60, 18, 72, 30), fill="#e05650")
    draw.text((92, 14), "K-GUARD ACTUAL LOCAL RUN", font=font(20, bold=True), fill="#edf5ef")
    now = float(events[index]["t"])
    clock = f"{now:05.1f}s / {duration:05.1f}s"
    draw.text((width - 245, 15), clock, font=font(18, bold=True), fill="#8be85f")

    body_font = font(20)
    body_bold = font(20, bold=True)
    y = 72
    for line, color_name in wrapped_lines(events, index, width=126, limit=21):
        color = COLORS.get(color_name, COLORS["default"])
        active_font = body_bold if color_name in {"green", "yellow"} else body_font
        draw.text((28, y), line, font=active_font, fill=color)
        y += 28

    draw.rectangle((0, height - 40, width, height), fill="#0b100e")
    draw.line((0, height - 40, width, height - 40), fill="#24342c", width=1)
    draw.text(
        (24, height - 31),
        "RECORDED FROM ACTUAL EXECUTION  |  synthetic fixtures  |  secrets masked",
        font=font(15, bold=True),
        fill="#9aa89f",
    )
    progress = max(0.0, min(1.0, now / duration))
    draw.rectangle((0, height - 4, int(width * progress), height), fill="#8be85f")
    return image


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--width", type=int, default=1808)
    parser.add_argument("--height", type=int, default=698)
    args = parser.parse_args()

    event_log = args.event_log.resolve()
    output = args.output.resolve()
    ffmpeg = args.ffmpeg.resolve()
    if output.exists():
        raise SystemExit("Refusing to overwrite output")
    if not event_log.is_file() or not ffmpeg.is_file():
        raise SystemExit("Missing event log or FFmpeg")
    events = load_events(event_log)
    duration = float(events[-1]["t"])
    if duration < 30 or duration > 180:
        raise SystemExit(f"Unexpected actual-run duration: {duration}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kguard-terminal-", dir=output.parent) as temp_name:
        temp = Path(temp_name)
        concat_lines: list[str] = []
        for index, event in enumerate(events):
            frame = temp / f"frame-{index:04d}.png"
            render_frame(events, index, width=args.width, height=args.height, duration=duration).save(frame)
            next_time = float(events[index + 1]["t"]) if index + 1 < len(events) else duration + 0.05
            frame_duration = max(0.04, next_time - float(event["t"]))
            concat_lines.append(f"file '{frame.as_posix()}'")
            concat_lines.append(f"duration {frame_duration:.6f}")
        concat_lines.append(f"file '{frame.as_posix()}'")
        concat = temp / "frames.concat.txt"
        concat.write_text("\n".join(concat_lines) + "\n", encoding="utf-8")
        command = [
            str(ffmpeg), "-hide_banner", "-loglevel", "error", "-y",
            "-f", "concat", "-safe", "0", "-i", str(concat),
            "-vf", "fps=30,format=yuv420p", "-t", f"{duration:.6f}",
            "-c:v", "libx264", "-preset", "medium", "-crf", "18",
            "-movflags", "+faststart", "-an", str(output),
        ]
        completed = subprocess.run(command, check=False)
        if completed.returncode != 0 or not output.is_file():
            raise SystemExit("FFmpeg terminal rendering failed")
    print(json.dumps({"output": str(output), "duration": duration, "events": len(events)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
