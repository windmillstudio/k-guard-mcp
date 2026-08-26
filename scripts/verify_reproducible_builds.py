from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


class ReproducibleBuildError(RuntimeError):
    pass


def _artifact_hashes(directory: Path) -> dict[str, str]:
    artifacts = sorted(
        [*directory.glob("*.whl"), *directory.glob("*.tar.gz"), *directory.glob("*-source.zip")]
    )
    wheel_count = sum(path.suffix == ".whl" for path in artifacts)
    sdist_count = sum(path.name.endswith(".tar.gz") for path in artifacts)
    source_zip_count = sum(path.name.endswith("-source.zip") for path in artifacts)
    if wheel_count != 1 or sdist_count != 1 or source_zip_count != 1 or len(artifacts) != 3:
        raise ReproducibleBuildError(
            f"expected one wheel, one sdist, and one source ZIP in {directory}, "
            f"found wheels={wheel_count} sdists={sdist_count} source_zips={source_zip_count} total={len(artifacts)}"
        )
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts}


def verify_reproducible_builds(first: Path, second: Path) -> dict[str, object]:
    first_hashes = _artifact_hashes(first)
    second_hashes = _artifact_hashes(second)
    if first_hashes != second_hashes:
        raise ReproducibleBuildError(
            f"clean repeated build hashes differ: first={first_hashes} second={second_hashes}"
        )
    return {"ok": True, "artifact_count": len(first_hashes), "sha256": first_hashes}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Require two clean repeated K-Guard builds to be byte-for-byte reproducible.")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify_reproducible_builds(args.first, args.second)
    except (OSError, ReproducibleBuildError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
