from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


MANIFEST_NAME = "SHA256SUMS"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_paths(root: Path) -> list[Path]:
    evidence = root / "evidence"
    manifest = evidence / MANIFEST_NAME
    paths: list[Path] = []
    for path in evidence.rglob("*"):
        if path == manifest:
            continue
        if path.is_symlink():
            raise ValueError(f"evidence symlink is not allowed: {path.relative_to(root).as_posix()}")
        if path.is_file():
            paths.append(path)
    return sorted(paths)


def build_manifest(root: Path) -> str:
    return "".join(
        f"{_sha256(path)}  {path.relative_to(root).as_posix()}\n"
        for path in artifact_paths(root)
    )


def validate_manifest(root: Path) -> list[str]:
    manifest = root / "evidence" / MANIFEST_NAME
    if not manifest.is_file():
        return ["evidence_manifest_missing"]
    try:
        expected = build_manifest(root)
    except ValueError:
        return ["evidence_symlink_not_allowed"]
    try:
        actual = manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ["evidence_manifest_unreadable"]
    return [] if actual == expected else ["evidence_manifest_content_mismatch"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the exact evidence artifact SHA-256 manifest without rewriting evidence bytes."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    manifest = root / "evidence" / MANIFEST_NAME
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_bytes(build_manifest(root).encode("utf-8"))
    print(f"PASS: {len(artifact_paths(root))} evidence artifacts bound in {manifest.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
