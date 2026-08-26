from __future__ import annotations

import hashlib
import re
import subprocess
import zipfile
from email.parser import BytesParser
from pathlib import Path
from pathlib import PurePosixPath
from typing import Iterable


TREE_HASH_SCHEMA = "k_guard_package_tree_sha256.v2"
TEXT_SUFFIXES = {
    ".cs",
    ".go",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}


def _canonical_content(path: Path, content: bytes | None = None) -> bytes:
    payload = path.read_bytes() if content is None else content
    if path.suffix.casefold() in TEXT_SUFFIXES:
        return payload.replace(b"\r\n", b"\n")
    return payload


def _hash_entries(entries: Iterable[tuple[str, bytes]]) -> str:
    ordered = sorted(entries, key=lambda item: item[0])
    if not ordered:
        raise ValueError("package tree contains no files")

    digest = hashlib.sha256()
    digest.update((TREE_HASH_SCHEMA + "\0").encode("ascii"))
    for relative_text, content in ordered:
        relative = relative_text.encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _included(relative: Path) -> bool:
    return "__pycache__" not in relative.parts and relative.suffix.casefold() not in {".pyc", ".pyo"}


def package_tree_sha256(package_root: Path) -> str:
    root = package_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("package root must be a directory")

    entries = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if _included(relative):
            entries.append((relative.as_posix(), _canonical_content(path)))
    return _hash_entries(entries)


def package_tree_sha256_at_revision(
    repo_root: Path,
    revision: str,
    package_path: str = "src/k_guard_mcp",
) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("revision must be a full lowercase Git commit SHA")
    root = repo_root.resolve(strict=True)
    prefix = package_path.strip("/").replace("\\", "/")
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "-z", revision, "--", prefix],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if listing.returncode != 0:
        raise ValueError("revision cannot be resolved")

    entries: list[tuple[str, bytes]] = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            _mode, object_type, object_id = metadata.split(b" ", 2)
            tracked = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("unexpected git tree record") from exc
        if object_type != b"blob" or not tracked.startswith(prefix + "/"):
            continue
        relative = Path(tracked[len(prefix) + 1 :])
        if not _included(relative):
            continue
        blob = subprocess.run(
            ["git", "cat-file", "blob", object_id.decode("ascii")],
            cwd=root,
            capture_output=True,
            check=False,
        )
        if blob.returncode != 0:
            raise ValueError(f"package blob cannot be read: {tracked}")
        entries.append((relative.as_posix(), _canonical_content(relative, blob.stdout)))
    return _hash_entries(entries)


def wheel_package_contract(wheel: Path) -> dict[str, str | int]:
    if not wheel.is_file() or wheel.suffix.casefold() != ".whl":
        raise ValueError("wheel must be an existing .whl file")
    entries: list[tuple[str, bytes]] = []
    metadata_payloads: list[bytes] = []
    seen: set[str] = set()
    total_uncompressed = 0
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            name = info.filename
            pure = PurePosixPath(name)
            if (
                not name
                or "\\" in name
                or pure.is_absolute()
                or ".." in pure.parts
                or name in seen
                or info.flag_bits & 0x1
                or ((info.external_attr >> 16) & 0o170000) == 0o120000
            ):
                raise ValueError("wheel contains an unsafe or duplicate archive member")
            seen.add(name)
            if info.is_dir():
                continue
            if info.file_size < 0 or info.file_size > 20 * 1024 * 1024:
                raise ValueError("wheel member exceeds the verification budget")
            total_uncompressed += info.file_size
            if total_uncompressed > 100 * 1024 * 1024 or len(seen) > 10_000:
                raise ValueError("wheel archive exceeds the verification budget")
            payload = archive.read(info)
            if len(payload) != info.file_size:
                raise ValueError("wheel member size does not match the archive directory")
            if name.startswith("k_guard_mcp/"):
                relative = Path(name[len("k_guard_mcp/") :])
                if relative.name and _included(relative):
                    entries.append((relative.as_posix(), _canonical_content(relative, payload)))
            if re.fullmatch(r"k_guard_mcp-[^/]+\.dist-info/METADATA", name):
                metadata_payloads.append(payload)
    if len(metadata_payloads) != 1:
        raise ValueError("wheel must contain exactly one k_guard_mcp METADATA record")
    metadata = BytesParser().parsebytes(metadata_payloads[0])
    distribution = str(metadata.get("Name") or "")
    version = str(metadata.get("Version") or "")
    if distribution.casefold().replace("_", "-") != "k-guard-mcp" or not version:
        raise ValueError("wheel distribution metadata is invalid")
    return {
        "package_tree_sha256": _hash_entries(entries),
        "distribution": distribution,
        "version": version,
        "package_file_count": len(entries),
    }
