from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tarfile
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath


MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
ZIP_MIN_EPOCH = 315_532_800  # 1980-01-01T00:00:00Z
ZIP_MAX_EPOCH = 4_354_819_198  # 2107-12-31T23:59:58Z


class SourceZipError(RuntimeError):
    pass


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    if not ZIP_MIN_EPOCH <= epoch <= ZIP_MAX_EPOCH:
        raise SourceZipError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    value = datetime.fromtimestamp(epoch, tz=UTC)
    return (value.year, value.month, value.day, value.hour, value.minute, value.second - value.second % 2)


def _member_name(name: str, *, is_directory: bool) -> str:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts:
        raise SourceZipError(f"source archive contains an unsafe member path: {name}")
    normalized = path.as_posix().rstrip("/")
    if not normalized or normalized == ".":
        raise SourceZipError(f"source archive contains an unsafe member path: {name}")
    return f"{normalized}/" if is_directory else normalized


def _validated_sdist_members(archive: tarfile.TarFile) -> list[tuple[str, tarfile.TarInfo]]:
    members = archive.getmembers()
    if not members or len(members) > MAX_MEMBERS:
        raise SourceZipError("sdist member count is outside the verification budget")
    validated: list[tuple[str, tarfile.TarInfo]] = []
    seen: set[str] = set()
    total_bytes = 0
    for member in members:
        if not (member.isfile() or member.isdir()):
            raise SourceZipError(f"sdist contains a non-regular member: {member.name}")
        name = _member_name(member.name, is_directory=member.isdir())
        folded = name.casefold()
        if folded in seen:
            raise SourceZipError(f"sdist contains a duplicate or case-colliding member: {name}")
        seen.add(folded)
        if member.isfile():
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise SourceZipError(f"sdist member exceeds the verification budget: {name}")
            total_bytes += member.size
            if total_bytes > MAX_TOTAL_BYTES:
                raise SourceZipError("sdist exceeds the verification budget")
        validated.append((name, member))
    roots = {PurePosixPath(name.rstrip("/")).parts[0] for name, _ in validated}
    if len(roots) != 1:
        raise SourceZipError(f"sdist must contain one top-level directory, found {sorted(roots)}")
    # Normalized sdists are tar-name ordered. ZIP directories add a trailing
    # slash, so sibling pairs such as package.py vs package/ (and docs name.md
    # vs name/) change order. Emit ZIP-name order here; do not require tar order.
    return sorted(validated, key=lambda item: item[0])


def _normalized_sdist_epoch(
    members: list[tuple[str, tarfile.TarInfo]],
    *,
    expected_epoch: int | None,
) -> int:
    timestamps = {member.mtime for _, member in members}
    if len(timestamps) != 1:
        raise SourceZipError("sdist members do not share one normalized timestamp")
    value = next(iter(timestamps))
    if not isinstance(value, (int, float)) or value < 0 or int(value) != value:
        raise SourceZipError("sdist timestamp is not a non-negative integer")
    epoch = int(value)
    _zip_datetime(epoch)
    if expected_epoch is not None and epoch != expected_epoch:
        raise SourceZipError("sdist timestamp differs from SOURCE_DATE_EPOCH")
    for name, member in members:
        expected_mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
        # normalize_sdist writes PAX_FORMAT with empty headers; tarfile then
        # restores only path for names longer than the ustar 100-byte field.
        canonical_pax_headers = not member.pax_headers or member.pax_headers == {
            "path": member.name
        }
        if (
            member.uid != 0
            or member.gid != 0
            or member.uname
            or member.gname
            or not canonical_pax_headers
            or member.mode & 0o777 != expected_mode
        ):
            raise SourceZipError(f"sdist member metadata is not normalized: {name}")
    return epoch


def _zip_info(name: str, member: tarfile.TarInfo, *, epoch: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(filename=name, date_time=_zip_datetime(epoch))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED if member.isdir() else zipfile.ZIP_DEFLATED
    permissions = member.mode & 0o777
    file_type = stat.S_IFDIR if member.isdir() else stat.S_IFREG
    info.external_attr = (file_type | permissions) << 16
    if member.isdir():
        info.external_attr |= 0x10
    info.extra = b""
    info.comment = b""
    return info


def _content_digest(entries: dict[str, bytes | None]) -> str:
    digest = hashlib.sha256()
    for name, payload in sorted(entries.items()):
        encoded_name = name.encode("utf-8")
        content = payload or b""
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(b"D" if payload is None else b"F")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _sdist_entries(
    archive: tarfile.TarFile,
    members: list[tuple[str, tarfile.TarInfo]],
) -> dict[str, bytes | None]:
    entries: dict[str, bytes | None] = {}
    for name, member in members:
        if member.isdir():
            entries[name] = None
            continue
        handle = archive.extractfile(member)
        if handle is None:
            raise SourceZipError(f"sdist member could not be read: {name}")
        with handle:
            payload = handle.read()
        if len(payload) != member.size:
            raise SourceZipError(f"sdist member size does not match its payload: {name}")
        entries[name] = payload
    return entries


def _zip_entries(
    archive: zipfile.ZipFile,
    *,
    expected_epoch: int | None,
) -> dict[str, bytes | None]:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_MEMBERS:
        raise SourceZipError("source ZIP member count is outside the verification budget")
    expected_time = _zip_datetime(expected_epoch) if expected_epoch is not None else None
    entries: dict[str, bytes | None] = {}
    seen: set[str] = set()
    total_bytes = 0
    ordered_names: list[str] = []
    for info in infos:
        name = _member_name(info.filename, is_directory=info.is_dir())
        folded = name.casefold()
        if folded in seen:
            raise SourceZipError(f"source ZIP contains a duplicate or case-colliding member: {name}")
        seen.add(folded)
        ordered_names.append(name)
        if info.flag_bits & 0x1:
            raise SourceZipError(f"source ZIP contains an encrypted member: {name}")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
        if info.create_system != 3 or file_type != expected_type:
            raise SourceZipError(f"source ZIP member type is not canonical: {name}")
        expected_compression = zipfile.ZIP_STORED if info.is_dir() else zipfile.ZIP_DEFLATED
        if info.compress_type != expected_compression or info.extra or info.comment:
            raise SourceZipError(f"source ZIP member metadata is not canonical: {name}")
        if expected_time is not None and info.date_time != expected_time:
            raise SourceZipError(f"source ZIP member timestamp differs from SOURCE_DATE_EPOCH: {name}")
        if info.is_dir():
            if info.file_size != 0:
                raise SourceZipError(f"source ZIP directory is not empty: {name}")
            entries[name] = None
            continue
        if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
            raise SourceZipError(f"source ZIP member exceeds the verification budget: {name}")
        total_bytes += info.file_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise SourceZipError("source ZIP exceeds the verification budget")
        payload = archive.read(info)
        if len(payload) != info.file_size:
            raise SourceZipError(f"source ZIP member size does not match its payload: {name}")
        entries[name] = payload
    if ordered_names != sorted(ordered_names):
        raise SourceZipError("source ZIP member order is not canonical")
    return entries


def verify_source_zip(
    sdist: Path,
    source_zip: Path,
    *,
    expected_epoch: int | None = None,
) -> dict[str, object]:
    sdist = sdist.resolve()
    source_zip = source_zip.resolve()
    if not sdist.is_file() or not sdist.name.endswith(".tar.gz"):
        raise SourceZipError(f"sdist is missing or has an unexpected name: {sdist}")
    if not source_zip.is_file() or source_zip.suffix.casefold() != ".zip":
        raise SourceZipError(f"source ZIP is missing or has an unexpected name: {source_zip}")
    try:
        with tarfile.open(sdist, "r:gz") as tar_archive:
            tar_members = _validated_sdist_members(tar_archive)
            normalized_epoch = _normalized_sdist_epoch(
                tar_members,
                expected_epoch=expected_epoch,
            )
            tar_entries = _sdist_entries(tar_archive, tar_members)
        with zipfile.ZipFile(source_zip) as zip_archive:
            if zip_archive.comment:
                raise SourceZipError("source ZIP archive comment is not canonical")
            zip_entries = _zip_entries(zip_archive, expected_epoch=normalized_epoch)
    except (tarfile.TarError, zipfile.BadZipFile) as error:
        raise SourceZipError(f"source archive is unreadable: {error}") from error
    if set(zip_entries) != set(tar_entries):
        raise SourceZipError(
            "source ZIP member set differs from sdist: "
            f"zip_only={sorted(set(zip_entries) - set(tar_entries))} "
            f"sdist_only={sorted(set(tar_entries) - set(zip_entries))}"
        )
    mismatches = [name for name in sorted(tar_entries) if zip_entries[name] != tar_entries[name]]
    if mismatches:
        raise SourceZipError(f"source ZIP member bytes differ from sdist: {mismatches}")
    return {
        "ok": True,
        "sdist": sdist.name,
        "source_zip": source_zip.name,
        "member_count": len(tar_entries),
        "file_count": sum(payload is not None for payload in tar_entries.values()),
        "content_sha256": _content_digest(tar_entries),
    }


def build_source_zip(
    sdist: Path,
    source_zip: Path,
    *,
    epoch: int,
) -> dict[str, object]:
    _zip_datetime(epoch)
    sdist = sdist.resolve()
    source_zip = source_zip.resolve()
    if sdist == source_zip:
        raise SourceZipError("source ZIP output must differ from the sdist input")
    if source_zip.suffix.casefold() != ".zip":
        raise SourceZipError("source ZIP output must use the .zip extension")
    source_zip.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tarfile.open(sdist, "r:gz") as source:
            members = _validated_sdist_members(source)
            _normalized_sdist_epoch(members, expected_epoch=epoch)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{source_zip.name}.",
                suffix=".zip",
                dir=source_zip.parent,
                delete=False,
            ) as raw_output:
                temporary = Path(raw_output.name)
            with zipfile.ZipFile(temporary, mode="w", allowZip64=True) as target:
                target.comment = b""
                for name, member in members:
                    info = _zip_info(name, member, epoch=epoch)
                    if member.isdir():
                        target.writestr(info, b"")
                        continue
                    handle = source.extractfile(member)
                    if handle is None:
                        raise SourceZipError(f"sdist member could not be read: {name}")
                    with handle:
                        payload = handle.read()
                    if len(payload) != member.size:
                        raise SourceZipError(f"sdist member size does not match its payload: {name}")
                    target.writestr(
                        info,
                        payload,
                        compress_type=zipfile.ZIP_DEFLATED,
                        compresslevel=9,
                    )
        if temporary is None:
            raise SourceZipError("source ZIP was not created")
        report = verify_source_zip(sdist, temporary, expected_epoch=epoch)
        os.replace(temporary, source_zip)
        temporary = None
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise SourceZipError(f"source ZIP creation failed: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {**report, "source_zip": source_zip.name, "source_date_epoch": epoch}


def _default_output(sdist: Path) -> Path:
    if not sdist.name.endswith(".tar.gz"):
        raise SourceZipError("sdist filename must end with .tar.gz")
    return sdist.with_name(f"{sdist.name.removesuffix('.tar.gz')}-source.zip")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic source ZIP whose members and bytes exactly match a normalized sdist."
    )
    parser.add_argument("sdist", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "-1")),
        help="Fixed Unix timestamp; defaults to SOURCE_DATE_EPOCH.",
    )
    args = parser.parse_args(argv)
    try:
        output = args.output or _default_output(args.sdist)
        report = build_source_zip(args.sdist, output, epoch=args.epoch)
    except SourceZipError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
