from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import build_source_zip, normalize_sdist


def _write_sdist(path: Path, *, mtime: int, payload: bytes = b"release payload\n") -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename=path.name, mode="wb", fileobj=raw, mtime=mtime) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo("k_guard_mcp-0.1.0")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o777
                directory.mtime = mtime
                archive.addfile(directory)
                member = tarfile.TarInfo("k_guard_mcp-0.1.0/README.md")
                member.size = len(payload)
                member.mode = 0o666
                member.mtime = mtime
                archive.addfile(member, io.BytesIO(payload))


def test_source_zip_is_deterministic_and_exactly_matches_normalized_sdist(tmp_path: Path) -> None:
    epoch = 1_600_000_000
    first_sdist = tmp_path / "first.tar.gz"
    second_sdist = tmp_path / "second.tar.gz"
    first_zip = tmp_path / "first-source.zip"
    second_zip = tmp_path / "second-source.zip"
    _write_sdist(first_sdist, mtime=1_700_000_001)
    _write_sdist(second_sdist, mtime=1_800_000_002)
    normalize_sdist.normalize_sdist(first_sdist, epoch=epoch)
    normalize_sdist.normalize_sdist(second_sdist, epoch=epoch)

    first = build_source_zip.build_source_zip(first_sdist, first_zip, epoch=epoch)
    second = build_source_zip.build_source_zip(second_sdist, second_zip, epoch=epoch)

    assert first_zip.read_bytes() == second_zip.read_bytes()
    assert first["content_sha256"] == second["content_sha256"]
    assert first["member_count"] == 2
    assert first["file_count"] == 1
    assert build_source_zip.verify_source_zip(first_sdist, first_zip, expected_epoch=epoch)["ok"] is True
    with zipfile.ZipFile(first_zip) as archive:
        assert archive.namelist() == ["k_guard_mcp-0.1.0/", "k_guard_mcp-0.1.0/README.md"]
        assert archive.read("k_guard_mcp-0.1.0/README.md") == b"release payload\n"


def test_source_zip_accepts_normalized_tree_order_and_emits_canonical_zip_order(
    tmp_path: Path,
) -> None:
    epoch = 1_600_000_000
    sdist = tmp_path / "tree-order.tar.gz"
    source_zip = tmp_path / "tree-order-source.zip"
    payloads = {
        "k_guard_mcp-0.1.0/package.py": b"module = True\n",
        "k_guard_mcp-0.1.0/package/__init__.py": b"package = True\n",
    }
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo("k_guard_mcp-0.1.0")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        package = tarfile.TarInfo("k_guard_mcp-0.1.0/package")
        package.type = tarfile.DIRTYPE
        archive.addfile(package)
        for name, payload in payloads.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

    normalize_sdist.normalize_sdist(sdist, epoch=epoch)
    with tarfile.open(sdist, "r:gz") as archive:
        assert archive.getnames() == [
            "k_guard_mcp-0.1.0",
            "k_guard_mcp-0.1.0/package",
            "k_guard_mcp-0.1.0/package.py",
            "k_guard_mcp-0.1.0/package/__init__.py",
        ]

    report = build_source_zip.build_source_zip(sdist, source_zip, epoch=epoch)

    assert report["ok"] is True
    assert report["member_count"] == 4
    assert build_source_zip.verify_source_zip(sdist, source_zip, expected_epoch=epoch)["ok"] is True
    with zipfile.ZipFile(source_zip) as archive:
        assert archive.namelist() == [
            "k_guard_mcp-0.1.0/",
            "k_guard_mcp-0.1.0/package.py",
            "k_guard_mcp-0.1.0/package/",
            "k_guard_mcp-0.1.0/package/__init__.py",
        ]
        for name, payload in payloads.items():
            assert archive.read(name) == payload


def test_source_zip_accepts_normalizer_generated_pax_path_for_long_member(
    tmp_path: Path,
) -> None:
    epoch = 1_600_000_000
    sdist = tmp_path / "long-path.tar.gz"
    source_zip = tmp_path / "long-path-source.zip"
    long_name = f"k_guard_mcp-0.1.0/{'nested-' * 14}payload.txt"
    payload = b"long path payload\n"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo("k_guard_mcp-0.1.0")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        member = tarfile.TarInfo(long_name)
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    normalize_sdist.normalize_sdist(sdist, epoch=epoch)
    with tarfile.open(sdist, "r:gz") as archive:
        assert archive.getmember(long_name).pax_headers == {"path": long_name}

    report = build_source_zip.build_source_zip(sdist, source_zip, epoch=epoch)

    assert report["ok"] is True
    assert build_source_zip.verify_source_zip(sdist, source_zip, expected_epoch=epoch)["ok"] is True
    with zipfile.ZipFile(source_zip) as archive:
        assert archive.read(long_name) == payload


def test_source_zip_rejects_noncanonical_pax_metadata(tmp_path: Path) -> None:
    epoch = 1_600_000_000
    sdist = tmp_path / "noncanonical-pax.tar.gz"
    output = tmp_path / "noncanonical-pax-source.zip"
    with tarfile.open(sdist, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        root = tarfile.TarInfo("k_guard_mcp-0.1.0")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        root.mtime = epoch
        root.pax_headers = {"comment": "not normalized"}
        archive.addfile(root)

    with pytest.raises(build_source_zip.SourceZipError, match="metadata is not normalized"):
        build_source_zip.build_source_zip(sdist, output, epoch=epoch)


def test_source_zip_verifier_rejects_member_byte_mismatch(tmp_path: Path) -> None:
    epoch = 1_600_000_000
    sdist = tmp_path / "release.tar.gz"
    source_zip = tmp_path / "release-source.zip"
    _write_sdist(sdist, mtime=epoch)
    normalize_sdist.normalize_sdist(sdist, epoch=epoch)
    build_source_zip.build_source_zip(sdist, source_zip, epoch=epoch)
    with zipfile.ZipFile(source_zip, mode="w") as archive:
        directory = zipfile.ZipInfo(
            "k_guard_mcp-0.1.0/",
            date_time=build_source_zip._zip_datetime(epoch),
        )
        directory.external_attr = (0o40755 << 16) | 0x10
        directory.create_system = 3
        archive.writestr(directory, b"")
        member = zipfile.ZipInfo(
            "k_guard_mcp-0.1.0/README.md",
            date_time=build_source_zip._zip_datetime(epoch),
        )
        member.external_attr = 0o100644 << 16
        member.create_system = 3
        member.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(member, b"tampered\n")

    with pytest.raises(build_source_zip.SourceZipError, match="member bytes differ"):
        build_source_zip.verify_source_zip(sdist, source_zip)


def test_source_zip_verifier_rejects_member_set_mismatch(tmp_path: Path) -> None:
    epoch = 1_600_000_000
    sdist = tmp_path / "release.tar.gz"
    source_zip = tmp_path / "release-source.zip"
    _write_sdist(sdist, mtime=epoch)
    normalize_sdist.normalize_sdist(sdist, epoch=epoch)
    build_source_zip.build_source_zip(sdist, source_zip, epoch=epoch)
    with zipfile.ZipFile(source_zip, mode="a") as archive:
        extra = zipfile.ZipInfo(
            "k_guard_mcp-0.1.0/extra.txt",
            date_time=build_source_zip._zip_datetime(epoch),
        )
        extra.create_system = 3
        extra.external_attr = 0o100644 << 16
        extra.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(extra, b"extra\n")

    with pytest.raises(build_source_zip.SourceZipError, match="member set differs"):
        build_source_zip.verify_source_zip(sdist, source_zip, expected_epoch=epoch)


def test_source_zip_builder_rejects_links_without_replacing_output(tmp_path: Path) -> None:
    sdist = tmp_path / "unsafe.tar.gz"
    output = tmp_path / "unsafe-source.zip"
    output.write_bytes(b"preserve me")
    with tarfile.open(sdist, "w:gz") as archive:
        root = tarfile.TarInfo("k_guard_mcp-0.1.0")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        link = tarfile.TarInfo("k_guard_mcp-0.1.0/outside")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    with pytest.raises(build_source_zip.SourceZipError, match="non-regular"):
        build_source_zip.build_source_zip(sdist, output, epoch=1_600_000_000)

    assert output.read_bytes() == b"preserve me"
