from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import json
import re
import sys
import tarfile
import tomllib
import zipfile
import zlib
from email.parser import Parser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

try:
    from .build_source_zip import SourceZipError, verify_source_zip
except ImportError:
    from build_source_zip import SourceZipError, verify_source_zip


_REFERENCE_LINK = re.compile(r"(?m)^\s*\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|([^\s\n]+))")
_HTML_LINK = re.compile(r"(?i)\bhref\s*=\s*(['\"])(.*?)\1")
_REQUIRED_REQUIREMENTS_FILES = (
    "requirements-build.lock",
    "requirements-evidence.in",
    "requirements-evidence.lock",
    "requirements-pip-audit.in",
    "requirements-pip-audit.lock",
    "requirements-semgrep.in",
    "requirements-semgrep.lock",
)
WHEEL_MAX_MEMBER_COMPRESSED_BYTES = 20 * 1024 * 1024
WHEEL_MAX_MEMBER_UNCOMPRESSED_BYTES = 20 * 1024 * 1024
WHEEL_MAX_TOTAL_COMPRESSED_BYTES = 100 * 1024 * 1024
WHEEL_MAX_TOTAL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
_COMMITTED_RELEASE_ARCHIVE_UNREADABLE = (
    OSError,
    UnicodeError,
    tarfile.TarError,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    SourceZipError,
    zlib.error,
    EOFError,
    tomllib.TOMLDecodeError,
    KeyError,
    TypeError,
)


class ArchiveVerificationError(RuntimeError):
    pass


def _normalize_local_markdown_target(target: str, *, source: PurePosixPath) -> str | None:
    value = html.unescape(target).strip()
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ArchiveVerificationError(f"invalid Markdown link target: {target}") from exc
    if not value or value.startswith(("#", "/")) or parsed.scheme or parsed.netloc:
        return None
    path = unquote(parsed.path).replace("\\", "/")
    if not path or path.endswith("/"):
        return None

    normalized_parts: list[str] = []
    for part in (*source.parent.parts, *PurePosixPath(path).parts):
        if part in ("", "."):
            continue
        if part == "..":
            if not normalized_parts:
                raise ArchiveVerificationError(f"Markdown link escapes repository root: {target}")
            normalized_parts.pop()
            continue
        normalized_parts.append(part)
    normalized = PurePosixPath(*normalized_parts)
    return normalized.as_posix() if normalized.suffix.lower() == ".md" else None


def readme_linked_markdown(markdown: str, *, source: str = "README.md") -> set[str]:
    targets = _inline_link_targets(markdown)
    for match in _REFERENCE_LINK.finditer(markdown):
        targets.append(match.group(1) or match.group(2))
    targets.extend(match.group(2) for match in _HTML_LINK.finditer(markdown))
    source_path = PurePosixPath(source)
    return {
        normalized
        for target in targets
        if (normalized := _normalize_local_markdown_target(target, source=source_path)) is not None
    }


def _inline_link_targets(markdown: str) -> list[str]:
    targets: list[str] = []
    cursor = 0
    while True:
        marker = markdown.find("](", cursor)
        if marker < 0:
            return targets
        index = marker + 2
        while index < len(markdown) and markdown[index].isspace() and markdown[index] != "\n":
            index += 1
        if index < len(markdown) and markdown[index] == "<":
            closing = markdown.find(">", index + 1)
            if closing >= 0:
                targets.append(markdown[index + 1 : closing])
                cursor = closing + 1
                continue
        start = index
        depth = 0
        escaped = False
        while index < len(markdown):
            character = markdown[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "(":
                depth += 1
            elif character == ")":
                if depth == 0:
                    targets.append(markdown[start:index].strip())
                    index += 1
                    break
                depth -= 1
            elif character == "\n" or (character.isspace() and depth == 0):
                if index > start:
                    targets.append(markdown[start:index].strip())
                break
            index += 1
        cursor = max(index, marker + 2)


def required_readme_documents(repo_root: Path) -> set[str]:
    root = repo_root.resolve()
    pending = ["README.md"]
    visited: set[str] = set()
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        candidate = root / Path(*PurePosixPath(relative).parts)
        try:
            candidate.resolve().relative_to(root)
        except ValueError as exc:
            raise ArchiveVerificationError(f"Markdown link resolves outside repository: {relative}") from exc
        if not candidate.is_file() or candidate.is_symlink():
            raise ArchiveVerificationError(f"linked Markdown document is missing or not a regular file: {relative}")
        visited.add(relative)
        linked = readme_linked_markdown(candidate.read_text(encoding="utf-8"), source=relative)
        pending.extend(sorted(linked - visited))
    return visited - {"README.md"}


def _single_artifact(dist: Path, pattern: str, label: str) -> Path:
    matches = sorted(dist.glob(pattern))
    if len(matches) != 1:
        raise ArchiveVerificationError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def _sdist_index(names: list[str]) -> tuple[str, set[str]]:
    roots = {PurePosixPath(name).parts[0] for name in names if PurePosixPath(name).parts}
    if len(roots) != 1:
        raise ArchiveVerificationError(f"sdist must contain exactly one top-level directory, found {sorted(roots)}")
    root = next(iter(roots))
    relative_names = [
        PurePosixPath(*PurePosixPath(name).parts[1:]).as_posix()
        for name in names
        if len(PurePosixPath(name).parts) > 1
    ]
    if any(".." in PurePosixPath(name).parts or PurePosixPath(name).is_absolute() for name in names):
        raise ArchiveVerificationError("sdist contains an unsafe member path")
    duplicates = sorted({name for name in relative_names if relative_names.count(name) > 1})
    if duplicates:
        raise ArchiveVerificationError(f"sdist contains duplicate member paths: {duplicates}")
    return root, set(relative_names)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    if not member.isfile() or member.issym() or member.islnk():
        raise ArchiveVerificationError(f"sdist member must be a regular file: {member.name}")
    handle = archive.extractfile(member)
    if handle is None:
        raise ArchiveVerificationError(f"sdist member could not be read: {member.name}")
    digest = hashlib.sha256()
    with handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _zip_index(names: list[str]) -> set[str]:
    normalized = [PurePosixPath(name).as_posix() for name in names]
    if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in normalized):
        raise ArchiveVerificationError("wheel contains an unsafe member path")
    duplicates = sorted({name for name in normalized if normalized.count(name) > 1})
    if duplicates:
        raise ArchiveVerificationError(f"wheel contains duplicate member paths: {duplicates}")
    return set(normalized)


def _exception_type_label(exc: BaseException) -> str:
    cls = type(exc)
    module = cls.__module__
    if not module or module == "builtins":
        return cls.__name__
    return f"{module}.{cls.__name__}"


def _read_bounded_wheel_files(archive: zipfile.ZipFile) -> dict[str, bytes]:
    infos = [info for info in archive.infolist() if not info.is_dir()]
    total_compressed = 0
    total_uncompressed = 0
    for info in infos:
        compressed = info.compress_size
        uncompressed = info.file_size
        if compressed < 0 or uncompressed < 0:
            raise ArchiveVerificationError(f"wheel member size is invalid: {info.filename}")
        if compressed > WHEEL_MAX_MEMBER_COMPRESSED_BYTES:
            raise ArchiveVerificationError(
                f"wheel compressed member exceeds the verification budget: {info.filename}"
            )
        if uncompressed > WHEEL_MAX_MEMBER_UNCOMPRESSED_BYTES:
            raise ArchiveVerificationError(
                f"wheel uncompressed member exceeds the verification budget: {info.filename}"
            )
        total_compressed += compressed
        total_uncompressed += uncompressed
        if total_compressed > WHEEL_MAX_TOTAL_COMPRESSED_BYTES:
            raise ArchiveVerificationError("wheel compressed total exceeds the verification budget")
        if total_uncompressed > WHEEL_MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ArchiveVerificationError("wheel uncompressed total exceeds the verification budget")
    files: dict[str, bytes] = {}
    for info in infos:
        payload = archive.read(info)
        if len(payload) != info.file_size:
            raise ArchiveVerificationError(
                f"wheel member size does not match the archive directory: {info.filename}"
            )
        files[info.filename] = payload
    return files


def _verify_wheel_record(files: dict[str, bytes]) -> None:
    record_names = [name for name in files if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        raise ArchiveVerificationError(f"wheel must contain exactly one RECORD, found {record_names}")
    record_name = record_names[0]
    try:
        rows = list(csv.reader(files[record_name].decode("utf-8").splitlines()))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ArchiveVerificationError("wheel RECORD is not parseable UTF-8 CSV") from exc
    recorded_paths: set[str] = set()
    for row in rows:
        if len(row) != 3 or not row[0] or row[0] in recorded_paths:
            raise ArchiveVerificationError("wheel RECORD contains an invalid or duplicate row")
        path, hash_spec, size_text = row
        recorded_paths.add(path)
        if path not in files:
            raise ArchiveVerificationError(f"wheel RECORD references a missing file: {path}")
        if path == record_name:
            if hash_spec or size_text:
                raise ArchiveVerificationError("wheel RECORD self-row must not contain hash or size")
            continue
        if not hash_spec.startswith("sha256="):
            raise ArchiveVerificationError(f"wheel RECORD entry is not sha256-bound: {path}")
        expected_hash = base64.urlsafe_b64encode(hashlib.sha256(files[path]).digest()).rstrip(b"=").decode("ascii")
        if hash_spec.removeprefix("sha256=") != expected_hash:
            raise ArchiveVerificationError(f"wheel RECORD hash mismatch: {path}")
        if not size_text.isdigit() or int(size_text) != len(files[path]):
            raise ArchiveVerificationError(f"wheel RECORD size mismatch: {path}")
    if recorded_paths != set(files):
        missing = sorted(set(files) - recorded_paths)
        raise ArchiveVerificationError(f"wheel RECORD does not cover every file: {missing}")


def _metadata_identity(payload: bytes, label: str) -> tuple[str, str]:
    try:
        metadata = Parser().parsestr(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ArchiveVerificationError(f"{label} metadata is not UTF-8") from exc
    name = str(metadata.get("Name") or "").strip()
    version = str(metadata.get("Version") or "").strip()
    if not name or not version:
        raise ArchiveVerificationError(f"{label} metadata is missing Name or Version")
    return name, version


def _package_source_relatives(repo_root: Path) -> set[str]:
    package_root = repo_root / "src" / "k_guard_mcp"
    if not package_root.is_dir():
        raise ArchiveVerificationError("src/k_guard_mcp is missing")
    relatives: set[str] = set()
    for path in package_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(repo_root)
        if "__pycache__" in relative.parts or relative.suffix.casefold() in {".pyc", ".pyo"}:
            continue
        relatives.add(relative.as_posix())
    if not relatives:
        raise ArchiveVerificationError("src/k_guard_mcp is empty")
    return relatives


def pre_freeze_archive_pathspecs(repo_root: Path) -> list[str]:
    pathspecs = [
        "src/k_guard_mcp",
        "scripts/*.py",
        "pyproject.toml",
        "LICENSE",
        "README.md",
        *_REQUIRED_REQUIREMENTS_FILES,
        "submission/release/*.whl",
        "submission/release/*.tar.gz",
        "submission/release/*-source.zip",
    ]
    try:
        pathspecs.extend(sorted(required_readme_documents(repo_root)))
    except (ArchiveVerificationError, OSError, UnicodeError):
        pass
    return pathspecs


def committed_release_archive_errors(*, dist: Path, repo_root: Path) -> list[str]:
    try:
        report = verify_release_archives(dist=dist, repo_root=repo_root)
    except ArchiveVerificationError as exc:
        message = str(exc).strip() or "verification_failed"
        return [f"committed_release_archives:{message}"]
    except _COMMITTED_RELEASE_ARCHIVE_UNREADABLE as exc:
        return [f"committed_release_archives_unreadable:{_exception_type_label(exc)}"]
    if report.get("ok") is not True:
        return ["committed_release_archives_not_ok"]
    return []


def verify_release_archives(*, dist: Path, repo_root: Path) -> dict[str, object]:
    repo_root = repo_root.resolve()
    wheel = _single_artifact(dist, "*.whl", "wheel")
    sdist = _single_artifact(dist, "*.tar.gz", "source distribution")
    source_zip = _single_artifact(dist, "*-source.zip", "source ZIP")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
        _zip_index(wheel_names)
        wheel_files = _read_bounded_wheel_files(archive)
    _verify_wheel_record(wheel_files)
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_members = archive.getmembers()
        sdist_names = [member.name for member in sdist_members]

    sdist_root, archived = _sdist_index(sdist_names)
    member_by_relative = {
        PurePosixPath(*PurePosixPath(member.name).parts[1:]).as_posix(): member
        for member in sdist_members
        if len(PurePosixPath(member.name).parts) > 1
    }

    for label, names in (("wheel", wheel_names), ("sdist", sdist_names)):
        if any(PurePosixPath(name).name == "license-report.json" for name in names):
            raise ArchiveVerificationError(f"{label} contains internal license-report.json")
        license_files = [name for name in names if PurePosixPath(name).name == "LICENSE"]
        if len(license_files) != 1:
            raise ArchiveVerificationError(f"{label} must contain exactly one LICENSE, found {license_files}")

    for requirements_file in _REQUIRED_REQUIREMENTS_FILES:
        matches = [name for name in sdist_names if PurePosixPath(name).name == requirements_file]
        if len(matches) != 1:
            raise ArchiveVerificationError(
                f"sdist must contain exactly one {requirements_file}, found {matches}"
            )

    project = tomllib.loads((repo_root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    expected_name = str(project["name"])
    expected_version = str(project["version"])
    normalized_name = expected_name.replace("-", "_")
    if not wheel.name.startswith(f"{normalized_name}-{expected_version}-"):
        raise ArchiveVerificationError("wheel filename does not match pyproject name/version")
    if sdist.name != f"{normalized_name}-{expected_version}.tar.gz":
        raise ArchiveVerificationError("sdist filename does not match pyproject name/version")
    if source_zip.name != f"{normalized_name}-{expected_version}-source.zip":
        raise ArchiveVerificationError("source ZIP filename does not match pyproject name/version")
    try:
        source_zip_report = verify_source_zip(sdist, source_zip)
    except SourceZipError as error:
        raise ArchiveVerificationError(str(error)) from error
    wheel_metadata_names = [name for name in wheel_files if name.endswith(".dist-info/METADATA")]
    if len(wheel_metadata_names) != 1:
        raise ArchiveVerificationError(f"wheel must contain exactly one METADATA, found {wheel_metadata_names}")
    sdist_metadata = member_by_relative.get("PKG-INFO")
    if sdist_metadata is None:
        raise ArchiveVerificationError("sdist is missing PKG-INFO")
    with tarfile.open(sdist, "r:gz") as archive:
        wheel_identity = _metadata_identity(wheel_files[wheel_metadata_names[0]], "wheel")
        sdist_handle = archive.extractfile(sdist_metadata)
        if sdist_handle is None:
            raise ArchiveVerificationError("sdist PKG-INFO could not be read")
        with sdist_handle:
            sdist_identity = _metadata_identity(sdist_handle.read(), "sdist")
    if wheel_identity != (expected_name, expected_version) or sdist_identity != (expected_name, expected_version):
        raise ArchiveVerificationError("archive project identity differs from pyproject")

    wheel_package = {name for name in wheel_files if name.startswith("k_guard_mcp/")}
    sdist_package = {
        relative.removeprefix("src/")
        for relative, member in member_by_relative.items()
        if relative.startswith("src/k_guard_mcp/") and member.isfile()
    }
    if wheel_package != sdist_package:
        raise ArchiveVerificationError(
            f"wheel/sdist package file sets differ: wheel_only={sorted(wheel_package - sdist_package)} sdist_only={sorted(sdist_package - wheel_package)}"
        )
    package_mismatches: list[str] = []
    with tarfile.open(sdist, "r:gz") as archive:
        for package_path in sorted(wheel_package):
            member = member_by_relative[f"src/{package_path}"]
            if _sha256_bytes(wheel_files[package_path]) != _sha256_member(archive, member):
                package_mismatches.append(package_path)
    if package_mismatches:
        raise ArchiveVerificationError(f"wheel/sdist package content differs: {package_mismatches}")

    package_source_files = _package_source_relatives(repo_root)
    archived_package_files = {
        relative
        for relative, member in member_by_relative.items()
        if relative.startswith("src/k_guard_mcp/") and member.isfile()
    }
    if archived_package_files != package_source_files:
        raise ArchiveVerificationError(
            "sdist package file set differs from current source: "
            f"sdist_only={sorted(archived_package_files - package_source_files)} "
            f"source_only={sorted(package_source_files - archived_package_files)}"
        )
    source_bound_files = {
        "LICENSE",
        *_REQUIRED_REQUIREMENTS_FILES,
        "pyproject.toml",
        *(path.relative_to(repo_root).as_posix() for path in (repo_root / "scripts").glob("*.py")),
        *package_source_files,
    }
    source_mismatches: list[str] = []
    with tarfile.open(sdist, "r:gz") as archive:
        for relative in sorted(source_bound_files):
            member = member_by_relative.get(relative)
            if member is None or _sha256_path(repo_root / relative) != _sha256_member(archive, member):
                source_mismatches.append(relative)
    wheel_license_names = [name for name in wheel_files if PurePosixPath(name).name == "LICENSE"]
    if len(wheel_license_names) != 1 or _sha256_bytes(wheel_files[wheel_license_names[0]]) != _sha256_path(repo_root / "LICENSE"):
        source_mismatches.append("wheel:LICENSE")
    if source_mismatches:
        raise ArchiveVerificationError(f"archive release inputs differ from source: {sorted(source_mismatches)}")

    required_docs = required_readme_documents(repo_root)
    missing_docs = sorted(required_docs - archived)
    if missing_docs:
        raise ArchiveVerificationError(f"sdist is missing README-linked documents: {missing_docs}")
    verified_sources = {"README.md", *required_docs}
    mismatched: list[str] = []
    with tarfile.open(sdist, "r:gz") as archive:
        for relative in sorted(verified_sources):
            source = repo_root / Path(*PurePosixPath(relative).parts)
            try:
                member = archive.getmember(f"{sdist_root}/{relative}")
            except KeyError as exc:
                raise ArchiveVerificationError(f"sdist is missing release Markdown source: {relative}") from exc
            if _sha256_path(source) != _sha256_member(archive, member):
                mismatched.append(relative)
    if mismatched:
        raise ArchiveVerificationError(f"sdist Markdown content differs from release source: {mismatched}")
    return {
        "ok": True,
        "wheel": wheel.name,
        "sdist": sdist.name,
        "source_zip": source_zip.name,
        "source_zip_member_count": source_zip_report["member_count"],
        "source_zip_content_sha256": source_zip_report["content_sha256"],
        "readme_linked_documents": sorted(required_docs),
        "readme_linked_document_count": len(required_docs),
        "verified_markdown_content_count": len(verified_sources),
        "verified_package_content_count": len(wheel_package),
        "wheel_record_verified": True,
        "release_input_content_verified": sorted(source_bound_files),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify K-Guard wheel and sdist release contracts.")
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = verify_release_archives(dist=args.dist, repo_root=args.repo_root)
    except (ArchiveVerificationError, *_COMMITTED_RELEASE_ARCHIVE_UNREADABLE) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
