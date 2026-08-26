from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    "coverage",
    ".cache",
    "tmp",
    "terminals",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".nox",
    ".tox",
    ".turbo",
    "venv",
    ".venv",
    "env",
    "site-packages",
    "temp",
    "__pycache__",
}
CANDIDATE_FINGERPRINT_MAX_FILE_BYTES = 20 * 1024 * 1024
FULL_TEXT_SCAN_MAX_FILE_BYTES = 5 * 1024 * 1024
BOUNDED_SECRET_SCAN_MAX_FILE_BYTES = CANDIDATE_FINGERPRINT_MAX_FILE_BYTES
SEMANTIC_ANALYSIS_MAX_FILE_BYTES = 512 * 1024
SEMANTIC_ANALYSIS_MAX_AVERAGE_LINE_BYTES = 4096

_BINARY_MAGIC_PREFIXES = (
    b"\x7fELF",
    b"%PDF-",
    b"MZ",
    b"PK\x03\x04",
    b"Rar!\x1a\x07",
    b"wOFF",
    b"wOF2",
    b"\x1f\x8b",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
)
_LARGE_NONEXECUTABLE_SUFFIXES = {".css", ".csv", ".html", ".htm", ".json", ".log", ".map", ".md", ".txt", ".tsv"}
_LARGE_NONEXECUTABLE_PARTS = {"asset", "assets", "fixture", "fixtures", "test", "tests", "testdata"}

GENERATED_CACHE_PARENTS = {".next", ".nuxt", ".svelte-kit"}

LOCKFILE_NAMES = {
    "bun.lock",
    "bun.lockb",
    "cargo.lock",
    "composer.lock",
    "gemfile.lock",
    "go.sum",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "yarn.lock",
}

SEMANTIC_NOISE_PARTS = {
    "bower_components",
    "bootstrap",
    "dist",
    "generated",
    "jquery",
    "syntax-highlighter",
    "syntaxhighlighter",
    "third-party",
    "third_party",
    "vendor",
    "vendors",
}
SEMANTIC_NOISE_PREFIXES = (
    "bootstrap.",
    "jquery.",
    "jquery-",
    "shbrush",
    "shcore",
    "syntaxhighlighter",
    "three.",
)
SEMANTIC_NOISE_PART_PREFIXES = (
    "bootstrap",
    "codemirror",
    "jquery",
    "syntaxhighlighter",
    "wysihtml5",
)
KNOWN_SEMANTIC_VENDOR_PARTS = {
    "ace",
    "doctrine",
    "nusoap",
    "prettify",
    "src-min-noconflict",
}

DEFAULT_EXTENSIONS = {
    ".env",
    ".txt",
    ".log",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".tsv",
    ".md",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".js",
    ".cjs",
    ".cs",
    ".jsx",
    ".mjs",
    ".ts",
    ".cts",
    ".mts",
    ".tsx",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".map",
    ".vue",
    ".svelte",
    ".sql",
    ".prisma",
    ".py",
    ".go",
    ".java",
    ".kt",
    ".php",
    ".rb",
    ".toml",
    ".ini",
    ".conf",
    ".dockerfile",
}


def collect_candidate_files(root: str | Path, max_files: int | None = None) -> list[Path]:
    """Collect every supported semantic candidate without hiding oversized files."""

    requested = Path(root).absolute()
    if max_files is not None and max_files <= 0:
        return []
    if is_unsafe_link(requested):
        return [requested]
    base = requested.resolve()
    if base.is_file():
        return [base] if _is_supported_file(base) else []

    files: list[Path] = []
    for current_root, directory_names, file_names in os.walk(base, topdown=True, followlinks=False):
        current = Path(current_root)
        eligible_directories = sorted(name for name in directory_names if not is_excluded_scan_directory(base, current, name))
        unsafe_directories = [current / name for name in eligible_directories if is_unsafe_link(current / name)]
        directory_names[:] = [name for name in eligible_directories if not is_unsafe_link(current / name)]
        for path in unsafe_directories:
            files.append(path)
            if max_files is not None and len(files) >= max_files:
                return files
        for file_name in sorted(file_names):
            path = current / file_name
            if is_unsafe_link(path) or _is_supported_file(path):
                files.append(path)
                if max_files is not None and len(files) >= max_files:
                    return files
    return files


def collect_files(root: str | Path, max_file_mb: int = 5, max_files: int | None = None) -> list[Path]:
    """Collect supported candidates that fit the bounded text-read limit."""

    if max_files is not None and max_files <= 0:
        return []
    files: list[Path] = []
    for path in collect_candidate_files(root):
        if _is_allowed_file(path, max_file_mb):
            files.append(path)
            if max_files is not None and len(files) >= max_files:
                break
    return files


def file_inventory_fingerprint(root: str | Path, files: list[Path]) -> dict[str, object]:
    """Return a raw-free path and content identity for the semantic candidate set."""

    base = Path(root).resolve()
    relative_to = base if base.is_dir() else base.parent
    normalized: list[tuple[str, Path]] = []
    for path in files:
        try:
            relative = path.absolute().relative_to(relative_to)
        except (OSError, ValueError):
            relative = Path(path.name)
        normalized.append((relative.as_posix(), path))
    path_digest = hashlib.sha256()
    content_digest = hashlib.sha256()
    unreadable = 0
    oversized = 0
    for value, path in sorted(normalized, key=lambda item: item[0].casefold()):
        encoded = value.encode("utf-8", errors="surrogatepass")
        path_digest.update(len(encoded).to_bytes(8, "big"))
        path_digest.update(encoded)
        content_digest.update(len(encoded).to_bytes(8, "big"))
        content_digest.update(encoded)
        try:
            if is_unsafe_link(path) or not path.is_file():
                raise OSError("candidate is not a regular readable file")
            with path.open("rb") as handle:
                content = handle.read(CANDIDATE_FINGERPRINT_MAX_FILE_BYTES + 1)
            if len(content) > CANDIDATE_FINGERPRINT_MAX_FILE_BYTES:
                oversized += 1
                content_digest.update(b"oversized")
                continue
        except OSError:
            unreadable += 1
            content_digest.update(b"unreadable")
            continue
        content_digest.update(len(content).to_bytes(8, "big"))
        content_digest.update(content)
    return {
        "candidate_count": len(normalized),
        "candidate_path_set_sha256": path_digest.hexdigest(),
        "candidate_content_set_sha256": content_digest.hexdigest(),
        "content_fingerprint_complete": unreadable == 0 and oversized == 0,
        "content_unreadable_count": unreadable,
        "content_oversized_count": oversized,
        "max_content_fingerprint_bytes": CANDIDATE_FINGERPRINT_MAX_FILE_BYTES,
        "raw_returned": False,
    }


def read_text(path: Path, max_bytes: int | None = None) -> str | None:
    if max_bytes is None:
        data = path.read_bytes()
    else:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    inferred_utf16 = _utf16_without_bom_encoding(data)
    if inferred_utf16 is not None:
        try:
            return data.decode(inferred_utf16)
        except UnicodeDecodeError:
            return None
    if _has_binary_magic(data):
        return None
    try:
        decoded = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        pass
    else:
        return None if _looks_like_binary_payload(data) else decoded
    if _looks_like_binary_payload(data):
        return None
    for encoding in ("cp949", "euc-kr", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def read_binary_for_secret_scan(path: Path, max_bytes: int) -> str | None:
    """Return a byte-preserving text view only for bounded payloads classified as binary."""

    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes or not (_has_binary_magic(data) or _looks_like_binary_payload(data)):
        return None
    return data.decode("latin-1")


def is_bounded_large_nonsemantic_asset(path: Path, size: int) -> bool:
    """Allow a bounded, full-byte secret pass only for non-executable large assets."""

    if not FULL_TEXT_SCAN_MAX_FILE_BYTES < size <= BOUNDED_SECRET_SCAN_MAX_FILE_BYTES:
        return False
    candidate = Path(str(path).replace("\\", "/"))
    name = candidate.name.casefold()
    suffix = candidate.suffix.casefold()
    parts = {part.casefold() for part in candidate.parts}
    if suffix not in _LARGE_NONEXECUTABLE_SUFFIXES:
        return False
    return bool(
        parts & _LARGE_NONEXECUTABLE_PARTS
        or "report" in name
        or "snapshot" in name
        or "test_suite" in name
        or "testing_framework" in name
        or name.startswith(("license.", "licenses."))
    )


def _has_binary_magic(data: bytes) -> bool:
    return any(data.startswith(prefix) for prefix in _BINARY_MAGIC_PREFIXES) or _looks_like_mpeg_transport_stream(data)


def _looks_like_mpeg_transport_stream(data: bytes) -> bool:
    sample = data[:4096]
    packet_size = 188
    required_packets = 4
    if len(sample) < packet_size * required_packets:
        return False
    for offset in range(min(packet_size, len(sample))):
        if all(sample[offset + packet_size * index] == 0x47 for index in range(required_packets)):
            return True
    return False


def _utf16_without_bom_encoding(data: bytes) -> str | None:
    sample = data[:4096]
    pair_count = len(sample) // 2
    if pair_count < 8:
        return None
    even_nuls = sample[0 : pair_count * 2 : 2].count(b"\x00") / pair_count
    odd_nuls = sample[1 : pair_count * 2 : 2].count(b"\x00") / pair_count
    if odd_nuls >= 0.40 and even_nuls <= 0.05:
        return "utf-16-le"
    if even_nuls >= 0.40 and odd_nuls <= 0.05:
        return "utf-16-be"
    return None


def _looks_like_binary_payload(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return False
    nul_ratio = sample.count(b"\x00") / len(sample)
    control_count = sum(byte < 32 and byte not in {9, 10, 13} for byte in sample)
    return nul_ratio > 0.01 or control_count / len(sample) > 0.10


def is_semantic_noise_asset(path: str | Path | None, text: str | None = None) -> bool:
    """Identify bundled/generated assets that should not drive semantic risk claims."""

    if not path:
        return False
    candidate = Path(str(path).replace("\\", "/"))
    name = candidate.name.casefold()
    suffix = candidate.suffix.casefold()
    parts = {part.casefold() for part in candidate.parts}
    if name in LOCKFILE_NAMES:
        return True
    if suffix in {".map", ".css", ".scss"}:
        return True
    if ".min." in name or name.endswith(
        (".bundle.js", ".bundle.mjs", "-bundle.js", "-bundle.mjs", ".chunk.js", "-chunk.js")
    ):
        return True
    if suffix in {".js", ".mjs", ".cjs"} and name.startswith(("swagger-ui", "redoc.standalone")):
        return True
    if parts & KNOWN_SEMANTIC_VENDOR_PARTS and suffix in {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".php",
    }:
        return True
    if parts & SEMANTIC_NOISE_PARTS and suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return True
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} and any(
        part.startswith(SEMANTIC_NOISE_PART_PREFIXES) for part in parts
    ):
        return True
    if suffix in {".js", ".mjs", ".cjs"} and name.startswith(SEMANTIC_NOISE_PREFIXES):
        return True
    if text is not None and suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        byte_count = len(text.encode("utf-8", errors="ignore"))
        line_count = text.count("\n") + 1
        if (
            byte_count > SEMANTIC_ANALYSIS_MAX_FILE_BYTES
            and byte_count / line_count > SEMANTIC_ANALYSIS_MAX_AVERAGE_LINE_BYTES
        ):
            return True
    return False


def _is_allowed_file(path: Path, max_file_mb: int) -> bool:
    if is_unsafe_link(path):
        return False
    try:
        if path.stat().st_size > max_file_mb * 1024 * 1024:
            return False
    except OSError:
        return False
    return _is_supported_file(path)


def _is_supported_file(path: Path) -> bool:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if lower_name.startswith(".env"):
        return True
    if lower_name in LOCKFILE_NAMES:
        return True
    if lower_name in {"dockerfile", "compose.yaml", "compose.yml"}:
        return True
    return suffix in DEFAULT_EXTENSIONS


def is_unsafe_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return False
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def is_excluded_scan_directory(base: Path, current: Path, name: str) -> bool:
    return name.casefold() in {item.casefold() for item in DEFAULT_EXCLUDES} or _is_generated_cache_directory(base, current, name)


def _is_generated_cache_directory(base: Path, current: Path, name: str) -> bool:
    if name.casefold() != "cache":
        return False
    try:
        relative_parts = {part.casefold() for part in current.relative_to(base).parts}
    except ValueError:
        return False
    return bool(relative_parts & GENERATED_CACHE_PARENTS)
