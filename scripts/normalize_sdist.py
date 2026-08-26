from __future__ import annotations

import argparse
import copy
import gzip
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


class SdistNormalizationError(RuntimeError):
    pass


def _validated_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    names = [member.name for member in members]
    if len(names) != len(set(names)):
        raise SdistNormalizationError("sdist contains duplicate member paths")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or ".." in path.parts:
            raise SdistNormalizationError(f"sdist contains an unsafe member path: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise SdistNormalizationError(f"sdist contains a non-regular member: {member.name}")
    roots = {PurePosixPath(name).parts[0] for name in names}
    if len(roots) != 1:
        raise SdistNormalizationError(f"sdist must contain one top-level directory, found {sorted(roots)}")
    return sorted(members, key=lambda member: member.name)


def _normalized_info(member: tarfile.TarInfo, *, epoch: int) -> tarfile.TarInfo:
    normalized = copy.copy(member)
    normalized.mtime = epoch
    normalized.uid = 0
    normalized.gid = 0
    normalized.uname = ""
    normalized.gname = ""
    normalized.pax_headers = {}
    normalized.devmajor = 0
    normalized.devminor = 0
    normalized.linkname = ""
    if normalized.isdir():
        normalized.mode = 0o755
        normalized.size = 0
    else:
        normalized.mode = 0o755 if member.mode & 0o111 else 0o644
        normalized.type = tarfile.REGTYPE
    return normalized


def normalize_sdist(path: Path, *, epoch: int) -> dict[str, object]:
    if epoch < 0:
        raise SdistNormalizationError("SOURCE_DATE_EPOCH must be non-negative")
    path = path.resolve()
    if not path.is_file() or not path.name.endswith(".tar.gz"):
        raise SdistNormalizationError(f"sdist is missing or has an unexpected name: {path}")

    temporary: Path | None = None
    try:
        with tarfile.open(path, "r:gz") as source:
            members = _validated_members(source)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as raw_output:
                temporary = Path(raw_output.name)
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=epoch) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target:
                        for member in members:
                            normalized = _normalized_info(member, epoch=epoch)
                            payload = source.extractfile(member) if member.isfile() else None
                            if member.isfile() and payload is None:
                                raise SdistNormalizationError(f"sdist member could not be read: {member.name}")
                            try:
                                target.addfile(normalized, payload)
                            finally:
                                if payload is not None:
                                    payload.close()
        if temporary is None:
            raise SdistNormalizationError("normalized sdist was not created")
        with tarfile.open(temporary, "r:gz") as verification:
            verified_members = _validated_members(verification)
            if len(verified_members) != len(members):
                raise SdistNormalizationError("normalized sdist member count changed")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return {"ok": True, "sdist": path.name, "source_date_epoch": epoch, "member_count": len(members)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize a K-Guard sdist for byte-for-byte reproducible releases.")
    parser.add_argument("sdist", type=Path)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "-1")),
        help="Fixed Unix timestamp; defaults to SOURCE_DATE_EPOCH.",
    )
    args = parser.parse_args(argv)
    try:
        report = normalize_sdist(args.sdist, epoch=args.epoch)
    except (OSError, tarfile.TarError, SdistNormalizationError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
