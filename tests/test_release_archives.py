from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import io
import shutil
import subprocess
import tarfile
import tomllib
import zipfile
import zlib
from pathlib import Path

import pytest

from scripts import build_source_zip, normalize_sdist, verify_release_archives, verify_reproducible_builds

ROOT = Path(__file__).resolve().parents[1]
_LIVE_ARCHIVE_STALE_SKIP = (
    "git reports tracked source/artifact changes that make pre-freeze archives stale"
)


_RELEASE_REQUIREMENTS_FILES = {
    "requirements-build.lock",
    "requirements-evidence.in",
    "requirements-evidence.lock",
    "requirements-pip-audit.in",
    "requirements-pip-audit.lock",
    "requirements-semgrep.in",
    "requirements-semgrep.lock",
}


def test_release_workflow_requires_signed_provenance_and_sbom_bundles() -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )

    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    attest_ref = "actions/attest@a1948c3f048ba23858d222213b7c278aabede763"
    assert workflow.count(attest_ref) == 2
    assert "uses: actions/attest@v" not in workflow
    assert "subject-path: dist/*" in workflow
    assert "sbom-path: dist/sbom.cdx.json" in workflow
    assert "release-provenance.sigstore.json" in workflow
    assert "release-sbom.sigstore.json" in workflow
    assert workflow.count("python scripts/build_source_zip.py") == 2
    assert "dist/*-source.zip" in workflow


def _write_archives(
    dist: Path,
    *,
    repo_root: Path,
    sdist_files: set[str],
    content_overrides: dict[str, bytes] | None = None,
    wheel_overrides: dict[str, bytes] | None = None,
    release_requirements_files: set[str] | None = None,
) -> None:
    defaults = {
        "LICENSE": b"MIT\n",
        "requirements-evidence.in": b"mcp==1.28.1\n",
        "requirements-evidence.lock": b"mcp==1.28.1\n",
        "requirements-build.lock": b"build==1.5.1\n",
        "requirements-semgrep.in": b"semgrep==1.174.0\n",
        "requirements-semgrep.lock": b"semgrep==1.174.0\n",
        "requirements-pip-audit.in": b"pip-audit==2.10.1\n",
        "requirements-pip-audit.lock": b"pip-audit==2.10.1\n",
        "pyproject.toml": b"[project]\nname='k-guard-mcp'\nversion='0.1.0'\n",
        "src/k_guard_mcp/__init__.py": b"__version__ = '0.1.0'\n",
        "src/k_guard_mcp/scanner.py": b"def scan():\n    return True\n",
    }
    for relative, payload in defaults.items():
        path = repo_root / relative
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
    dist.mkdir(parents=True, exist_ok=True)
    wheel_payloads = {
        "k_guard_mcp/__init__.py": (repo_root / "src/k_guard_mcp/__init__.py").read_bytes(),
        "k_guard_mcp/scanner.py": (repo_root / "src/k_guard_mcp/scanner.py").read_bytes(),
        "k_guard_mcp-0.1.0.dist-info/licenses/LICENSE": (repo_root / "LICENSE").read_bytes(),
        "k_guard_mcp-0.1.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: k-guard-mcp\nVersion: 0.1.0\n\n",
        "k_guard_mcp-0.1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    wheel_payloads.update(wheel_overrides or {})
    record_rows: list[list[str]] = []
    for relative, payload in sorted(wheel_payloads.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        record_rows.append([relative, f"sha256={digest}", str(len(payload))])
    record_name = "k_guard_mcp-0.1.0.dist-info/RECORD"
    record_rows.append([record_name, "", ""])
    record_buffer = io.StringIO(newline="")
    csv.writer(record_buffer, lineterminator="\n").writerows(record_rows)
    wheel_payloads[record_name] = record_buffer.getvalue().encode("utf-8")
    with zipfile.ZipFile(dist / "k_guard_mcp-0.1.0-py3-none-any.whl", "w") as archive:
        for relative, payload in sorted(wheel_payloads.items()):
            archive.writestr(relative, payload)
    with tarfile.open(dist / "k_guard_mcp-0.1.0.tar.gz", "w:gz") as archive:
        package_files = {"src/k_guard_mcp/__init__.py", "src/k_guard_mcp/scanner.py"}
        packaged_requirements = (
            _RELEASE_REQUIREMENTS_FILES
            if release_requirements_files is None
            else release_requirements_files
        )
        for relative in sorted({"LICENSE", *packaged_requirements, "pyproject.toml", "PKG-INFO", *package_files, *sdist_files}):
            source = repo_root / relative
            payload = (content_overrides or {}).get(
                relative,
                (
                    b"Metadata-Version: 2.4\nName: k-guard-mcp\nVersion: 0.1.0\n\n"
                    if relative == "PKG-INFO"
                    else source.read_bytes() if source.is_file() else relative.encode("utf-8")
                ),
            )
            info = tarfile.TarInfo(f"k_guard_mcp-0.1.0/{relative}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    normalize_sdist.normalize_sdist(
        dist / "k_guard_mcp-0.1.0.tar.gz",
        epoch=1_600_000_000,
    )
    build_source_zip.build_source_zip(
        dist / "k_guard_mcp-0.1.0.tar.gz",
        dist / "k_guard_mcp-0.1.0-source.zip",
        epoch=1_600_000_000,
    )


def _write_readme_fixture(root: Path) -> set[str]:
    documents = {
        "docs/a.md",
        "docs/space name.md",
        "docs/reference.md",
        "docs/html.md",
        "examples/demo/README.md",
    }
    for relative in documents:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {relative}\n", encoding="utf-8")
    (root / "docs" / "a.md").write_text("# A\n\n[demo](../examples/demo/README.md)\n", encoding="utf-8")
    (root / "README.md").write_text(
        "[A](docs/a.md#section)\n"
        "[space](<docs/space%20name.md>)\n"
        "[reference][guide]\n"
        "[guide]: docs/reference.md\n"
        "<a href=\"docs/html.md?view=1\">HTML</a>\n"
        "[external](https://example.com/external.md)\n",
        encoding="utf-8",
    )
    return documents


def test_release_archive_verification_tracks_all_readme_linked_markdown(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})

    report = verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)

    assert report["ok"] is True
    assert set(report["readme_linked_documents"]) == documents


def test_release_archive_verification_fails_when_new_readme_document_is_not_shipped(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    missing = "docs/html.md"
    _write_archives(
        tmp_path / "dist",
        repo_root=tmp_path,
        sdist_files={"README.md", *(documents - {missing})},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="docs/html.md"):
        verify_release_archives.verify_release_archives(dist=tmp_path / "dist", repo_root=tmp_path)


def test_readme_link_parser_rejects_repository_escape() -> None:
    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="escapes repository root"):
        verify_release_archives.readme_linked_markdown("[outside](../outside.md)")


def test_readme_link_parser_handles_parentheses_in_local_filename() -> None:
    assert verify_release_archives.readme_linked_markdown("[nested](docs/a(1).md)") == {"docs/a(1).md"}


def test_release_archive_verification_rejects_stale_markdown_content(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(
        dist,
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
        content_overrides={"docs/a.md": b"# stale packaged document\n"},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="docs/a.md"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)


def test_release_archive_verification_rejects_wheel_code_that_differs_from_sdist(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(
        dist,
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
        wheel_overrides={"k_guard_mcp/scanner.py": b"def scan():\n    return 'tampered'\n"},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="package content differs"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)


def test_release_archive_verification_rejects_stale_evidence_lock(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(
        dist,
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
        content_overrides={"requirements-evidence.lock": b"mcp==0.0.0\n"},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="requirements-evidence.lock"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)


def test_release_archive_verification_requires_source_zip(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})
    (dist / "k_guard_mcp-0.1.0-source.zip").unlink()

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="source ZIP"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)


@pytest.mark.parametrize(
    "missing",
    [
        "requirements-semgrep.in",
        "requirements-semgrep.lock",
        "requirements-pip-audit.in",
        "requirements-pip-audit.lock",
    ],
)
def test_release_archive_verification_requires_tool_lock_inputs(tmp_path: Path, missing: str) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(
        dist,
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
        release_requirements_files=_RELEASE_REQUIREMENTS_FILES - {missing},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match=missing):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)


def test_reproducible_build_verifier_requires_identical_artifacts(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    for directory in (first, second):
        (directory / "k_guard_mcp-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
        (directory / "k_guard_mcp-0.1.0.tar.gz").write_bytes(b"sdist")
        (directory / "k_guard_mcp-0.1.0-source.zip").write_bytes(b"source zip")

    assert verify_reproducible_builds.verify_reproducible_builds(first, second)["ok"] is True
    (second / "k_guard_mcp-0.1.0-source.zip").write_bytes(b"different")
    with pytest.raises(verify_reproducible_builds.ReproducibleBuildError, match="hashes differ"):
        verify_reproducible_builds.verify_reproducible_builds(first, second)


def _write_nondeterministic_sdist(path: Path, *, mtime: int) -> None:
    with path.open("wb") as raw:
        with gzip.GzipFile(filename=path.name, mode="wb", fileobj=raw, mtime=mtime) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo("k_guard_mcp-0.1.0")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o777
                directory.mtime = mtime
                archive.addfile(directory)
                payload = b"release payload\n"
                member = tarfile.TarInfo("k_guard_mcp-0.1.0/README.md")
                member.size = len(payload)
                member.mode = 0o666
                member.mtime = mtime
                member.uid = mtime
                archive.addfile(member, io.BytesIO(payload))


def test_sdist_normalizer_produces_identical_safe_archives(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_nondeterministic_sdist(first, mtime=1_700_000_001)
    _write_nondeterministic_sdist(second, mtime=1_800_000_002)

    normalize_sdist.normalize_sdist(first, epoch=1_600_000_000)
    normalize_sdist.normalize_sdist(second, epoch=1_600_000_000)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, "r:gz") as archive:
        assert all(member.mtime == 1_600_000_000 for member in archive.getmembers())
        assert all(member.uid == member.gid == 0 for member in archive.getmembers())


def test_sdist_normalizer_rejects_links_without_replacing_original(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        root = tarfile.TarInfo("k_guard_mcp-0.1.0")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        link = tarfile.TarInfo("k_guard_mcp-0.1.0/outside")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)
    original = path.read_bytes()

    with pytest.raises(normalize_sdist.SdistNormalizationError, match="non-regular"):
        normalize_sdist.normalize_sdist(path, epoch=1_600_000_000)

    assert path.read_bytes() == original


def test_release_archive_verification_rejects_stale_package_source_even_when_wheel_matches_sdist(
    tmp_path: Path,
) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    stale = b"def scan():\n    return 'stale'\n"
    _write_archives(
        dist,
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
        content_overrides={"src/k_guard_mcp/scanner.py": stale},
        wheel_overrides={"k_guard_mcp/scanner.py": stale},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="src/k_guard_mcp/scanner.py"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)


def test_release_archive_verification_rejects_package_file_missing_from_sdist(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    extra = tmp_path / "src" / "k_guard_mcp" / "extra.py"
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_text("extra = True\n", encoding="utf-8")
    _write_archives(
        tmp_path / "dist",
        repo_root=tmp_path,
        sdist_files={"README.md", *documents},
    )

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="src/k_guard_mcp/extra.py"):
        verify_release_archives.verify_release_archives(dist=tmp_path / "dist", repo_root=tmp_path)


def test_committed_release_archive_errors_pass_for_matching_synthetic_archives(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})

    assert verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path) == []


def test_committed_release_archive_errors_fail_closed_on_tampered_source_zip(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})
    with zipfile.ZipFile(dist / "k_guard_mcp-0.1.0-source.zip", "a") as archive:
        archive.writestr("k_guard_mcp-0.1.0/extra.txt", b"tampered")

    errors = verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path)

    assert errors
    assert any("member set differs" in error or "source ZIP" in error for error in errors)


def test_committed_release_archive_errors_fail_closed_on_wrong_sdist_identity(tmp_path: Path) -> None:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})
    sdist = dist / "k_guard_mcp-0.1.0.tar.gz"
    sdist.rename(dist / "wrong_package-9.9.9.tar.gz")

    errors = verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path)

    assert errors
    assert any("sdist filename" in error or "committed_release_archives:" in error for error in errors)


def test_committed_release_archive_errors_fail_closed_when_archives_are_missing(tmp_path: Path) -> None:
    errors = verify_release_archives.committed_release_archive_errors(
        dist=tmp_path / "submission" / "release",
        repo_root=tmp_path,
    )

    assert errors
    assert any("committed_release_archives:" in error for error in errors)


def _rewrite_wheel_deflated(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as source:
        members = [(info.filename, source.read(info)) for info in source.infolist() if not info.is_dir()]
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as dest:
        for name, payload in members:
            dest.writestr(name, payload)


def _flip_first_deflated_payload_byte(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        info = next(
            item
            for item in archive.infolist()
            if not item.is_dir() and item.compress_type == zipfile.ZIP_DEFLATED and item.compress_size
        )
        data_start = info.header_offset + 30 + len(info.filename.encode("utf-8")) + len(info.extra)
    payload = bytearray(path.read_bytes())
    payload[data_start] ^= 0xFF
    path.write_bytes(payload)


def _matching_archives(tmp_path: Path) -> Path:
    documents = _write_readme_fixture(tmp_path)
    dist = tmp_path / "dist"
    _write_archives(dist, repo_root=tmp_path, sdist_files={"README.md", *documents})
    return dist


class _NoReadZipFile(zipfile.ZipFile):
    def read(self, member, pwd=None):
        raise AssertionError("wheel member read before size budget")


def _assert_unreadable(errors: list[str], label: str) -> None:
    assert errors == [f"committed_release_archives_unreadable:{label}"]


@pytest.mark.parametrize(
    ("exc", "label"),
    [
        (zlib.error("Error -3 while decompressing data"), "zlib.error"),
        (EOFError("Compressed file ended before the end-of-stream marker was reached"), "EOFError"),
        (zipfile.LargeZipFile("Filesize would require ZIP64 extensions"), "zipfile.LargeZipFile"),
        (tomllib.TOMLDecodeError("Invalid statement"), "tomllib.TOMLDecodeError"),
        (KeyError("project"), "KeyError"),
        (TypeError("string indices must be integers"), "TypeError"),
    ],
)
def test_committed_release_archive_errors_map_corrupt_and_malformed_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exc: BaseException,
    label: str,
) -> None:
    def boom(*, dist: Path, repo_root: Path):
        raise exc

    monkeypatch.setattr(verify_release_archives, "verify_release_archives", boom)
    _assert_unreadable(
        verify_release_archives.committed_release_archive_errors(dist=tmp_path, repo_root=tmp_path),
        label,
    )


def test_committed_release_archive_errors_do_not_catch_memoryerror_or_baseexception(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class OperatorInterrupt(BaseException):
        pass

    def raise_memory(*, dist: Path, repo_root: Path) -> dict[str, object]:
        raise MemoryError("zip bomb")

    monkeypatch.setattr(verify_release_archives, "verify_release_archives", raise_memory)
    with pytest.raises(MemoryError, match="zip bomb"):
        verify_release_archives.committed_release_archive_errors(dist=tmp_path, repo_root=tmp_path)

    def raise_base(*, dist: Path, repo_root: Path) -> dict[str, object]:
        raise OperatorInterrupt

    monkeypatch.setattr(verify_release_archives, "verify_release_archives", raise_base)
    with pytest.raises(OperatorInterrupt):
        verify_release_archives.committed_release_archive_errors(dist=tmp_path, repo_root=tmp_path)


def test_committed_release_archive_errors_map_zlib_error_from_corrupt_wheel(tmp_path: Path) -> None:
    dist = _matching_archives(tmp_path)
    wheel = dist / "k_guard_mcp-0.1.0-py3-none-any.whl"
    _rewrite_wheel_deflated(wheel)
    _flip_first_deflated_payload_byte(wheel)

    _assert_unreadable(
        verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path),
        "zlib.error",
    )


def test_committed_release_archive_errors_map_eoferror_from_truncated_sdist(tmp_path: Path) -> None:
    dist = _matching_archives(tmp_path)
    sdist = dist / "k_guard_mcp-0.1.0.tar.gz"
    sdist.write_bytes(sdist.read_bytes()[:25])

    _assert_unreadable(
        verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path),
        "EOFError",
    )


def test_committed_release_archive_errors_map_toml_decode_error(tmp_path: Path) -> None:
    dist = _matching_archives(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project\nname = 'k-guard-mcp'\n", encoding="utf-8")

    _assert_unreadable(
        verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path),
        "tomllib.TOMLDecodeError",
    )


def test_committed_release_archive_errors_map_keyerror_for_missing_pyproject_project(tmp_path: Path) -> None:
    dist = _matching_archives(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[tool.setuptools]\n", encoding="utf-8")

    _assert_unreadable(
        verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path),
        "KeyError",
    )


def test_committed_release_archive_errors_map_typeerror_for_non_table_project(tmp_path: Path) -> None:
    dist = _matching_archives(tmp_path)
    (tmp_path / "pyproject.toml").write_text("project = []\n", encoding="utf-8")

    _assert_unreadable(
        verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path),
        "TypeError",
    )


@pytest.mark.parametrize(
    ("attribute", "value", "match"),
    [
        ("WHEEL_MAX_MEMBER_COMPRESSED_BYTES", 1, "compressed member"),
        ("WHEEL_MAX_MEMBER_UNCOMPRESSED_BYTES", 1, "uncompressed member"),
        ("WHEEL_MAX_TOTAL_COMPRESSED_BYTES", 1, "compressed total"),
        ("WHEEL_MAX_TOTAL_UNCOMPRESSED_BYTES", 1, "uncompressed total"),
    ],
)
def test_wheel_size_budgets_are_enforced_before_read_all(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
    value: int,
    match: str,
) -> None:
    dist = _matching_archives(tmp_path)
    monkeypatch.setattr(verify_release_archives, attribute, value)
    monkeypatch.setattr(verify_release_archives.zipfile, "ZipFile", _NoReadZipFile)

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match=match):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)

    monkeypatch.setattr(verify_release_archives.zipfile, "ZipFile", zipfile.ZipFile)
    errors = verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path)
    assert errors
    assert any(match in error for error in errors)
    assert all(error.startswith("committed_release_archives:") for error in errors)


def test_release_archive_verification_rejects_missing_package_before_empty_set_comparison(
    tmp_path: Path,
) -> None:
    dist = _matching_archives(tmp_path)
    shutil.rmtree(tmp_path / "src" / "k_guard_mcp")

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="src/k_guard_mcp is missing"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)

    errors = verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path)
    assert errors == ["committed_release_archives:src/k_guard_mcp is missing"]
    assert all("sdist package file set differs" not in error for error in errors)


def test_release_archive_verification_rejects_empty_package_before_empty_set_comparison(
    tmp_path: Path,
) -> None:
    dist = _matching_archives(tmp_path)
    package = tmp_path / "src" / "k_guard_mcp"
    for path in package.rglob("*"):
        if path.is_file():
            path.unlink()
    pycache = package / "__pycache__"
    pycache.mkdir(parents=True, exist_ok=True)
    (pycache / "scanner.cpython-311.pyc").write_bytes(b"\0pyc")

    with pytest.raises(verify_release_archives.ArchiveVerificationError, match="src/k_guard_mcp is empty"):
        verify_release_archives.verify_release_archives(dist=dist, repo_root=tmp_path)

    errors = verify_release_archives.committed_release_archive_errors(dist=dist, repo_root=tmp_path)
    assert errors == ["committed_release_archives:src/k_guard_mcp is empty"]
    assert all("sdist package file set differs" not in error for error in errors)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def _tracked_pre_freeze_archive_changes(repo_root: Path) -> list[str]:
    completed = subprocess.run(
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=no",
            "--",
            *verify_release_archives.pre_freeze_archive_pathspecs(repo_root),
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in completed.stdout.splitlines() if line.strip()]


def test_pre_freeze_archive_pathspecs_cover_bound_source_and_artifacts(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("[guide](docs/a.md)\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("# A\n", encoding="utf-8")

    specs = verify_release_archives.pre_freeze_archive_pathspecs(tmp_path)

    assert "src/k_guard_mcp" in specs
    assert "scripts/*.py" in specs
    assert "pyproject.toml" in specs
    assert "LICENSE" in specs
    assert "README.md" in specs
    assert "requirements-evidence.lock" in specs
    assert "submission/release/*.whl" in specs
    assert "submission/release/*.tar.gz" in specs
    assert "submission/release/*-source.zip" in specs
    assert "docs/a.md" in specs


def test_tracked_pre_freeze_archive_changes_skip_only_bound_source_or_artifacts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "K-Guard Tests")
    _git(repo, "config", "core.autocrlf", "false")
    (repo / "src" / "k_guard_mcp").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "docs").mkdir()
    (repo / "tests").mkdir()
    (repo / "submission" / "release").mkdir(parents=True)
    (repo / "src" / "k_guard_mcp" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "scripts" / "runner.py").write_text("print('run')\n", encoding="utf-8")
    (repo / "docs" / "a.md").write_text("# A\n", encoding="utf-8")
    (repo / "README.md").write_text("[guide](docs/a.md)\n", encoding="utf-8")
    (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text("[project]\nname = 'k-guard-mcp'\nversion = '0.1.0'\n", encoding="utf-8")
    (repo / "tests" / "unrelated.py").write_text("assert True\n", encoding="utf-8")
    (repo / "submission" / "release" / "k_guard_mcp-0.1.0-py3-none-any.whl").write_bytes(b"wheel")
    _git(repo, "add", "--all")
    _git(repo, "commit", "--quiet", "-m", "baseline")

    assert _tracked_pre_freeze_archive_changes(repo) == []

    (repo / "tests" / "unrelated.py").write_text("assert False\n", encoding="utf-8")
    assert _tracked_pre_freeze_archive_changes(repo) == []

    (repo / "src" / "k_guard_mcp" / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")
    source_changes = _tracked_pre_freeze_archive_changes(repo)
    assert source_changes
    assert any("src/k_guard_mcp/__init__.py" in line for line in source_changes)
    _git(repo, "checkout", "--", "src/k_guard_mcp/__init__.py")

    (repo / "submission" / "release" / "k_guard_mcp-0.1.0-py3-none-any.whl").write_bytes(b"stale")
    artifact_changes = _tracked_pre_freeze_archive_changes(repo)
    assert artifact_changes
    assert any("k_guard_mcp-0.1.0-py3-none-any.whl" in line for line in artifact_changes)
    _git(repo, "checkout", "--", "submission/release/k_guard_mcp-0.1.0-py3-none-any.whl")

    (repo / "docs" / "a.md").write_text("# stale\n", encoding="utf-8")
    doc_changes = _tracked_pre_freeze_archive_changes(repo)
    assert doc_changes
    assert any("docs/a.md" in line for line in doc_changes)
    _git(repo, "checkout", "--", "docs/a.md")

    assert _tracked_pre_freeze_archive_changes(repo) == []


def test_live_committed_submission_release_archives_match_current_source() -> None:
    stale = _tracked_pre_freeze_archive_changes(ROOT)
    if stale:
        pytest.skip(f"{_LIVE_ARCHIVE_STALE_SKIP}: {'; '.join(stale)}")
    errors = verify_release_archives.committed_release_archive_errors(
        dist=ROOT / "submission" / "release",
        repo_root=ROOT,
    )
    assert errors == []
