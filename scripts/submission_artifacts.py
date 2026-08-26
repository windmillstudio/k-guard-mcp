from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


MANIFEST_NAME = "SHA256SUMS"
TEXT_SUFFIXES = {".csv", ".html", ".json", ".jsonl", ".md", ".txt", ".yaml", ".yml"}
EXTRA_ARTIFACTS = ("src/k_guard_mcp/assets/glasses-senpai-hero.png",)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_paths(root: Path) -> list[Path]:
    submission = root / "submission"
    paths = {
        path
        for path in submission.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    }
    paths.update(path for relative in EXTRA_ARTIFACTS if (path := root / relative).is_file())
    return sorted(paths)


def normalize_text_artifacts(root: Path) -> int:
    changed = 0
    for path in artifact_paths(root):
        if path.suffix.casefold() not in TEXT_SUFFIXES:
            continue
        content = path.read_bytes()
        normalized = content.replace(b"\r\n", b"\n")
        if normalized != content:
            path.write_bytes(normalized)
            changed += 1
    return changed


def build_manifest(root: Path) -> str:
    return "".join(
        f"{_sha256(path)}  {path.relative_to(root).as_posix()}\n"
        for path in artifact_paths(root)
    )


def validate_manifest(root: Path) -> list[str]:
    manifest = root / "submission" / MANIFEST_NAME
    if not manifest.is_file():
        return ["submission_manifest_missing"]
    expected = build_manifest(root)
    try:
        actual = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ["submission_manifest_unreadable"]
    return [] if actual == expected else ["submission_manifest_content_mismatch"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the exact submission artifact SHA-256 manifest.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    normalize_text_artifacts(root)
    manifest = root / "submission" / MANIFEST_NAME
    manifest.write_bytes(build_manifest(root).encode("utf-8"))
    print(f"PASS: {len(artifact_paths(root))} submission artifacts bound in {manifest.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
