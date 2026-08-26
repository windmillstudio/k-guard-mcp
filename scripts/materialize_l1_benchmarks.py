from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "k_guard_l1_corpus_manifest.v1"
SOURCE_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"
CASE_SET_SCHEMA = "k_guard_l1_case_set.v1"
CASE_ID_RE = re.compile(r"BenchmarkTest\d{5}")
SHA1_RE = re.compile(r"[0-9a-f]{40}")
BLOB_EXACT_CLEAN_METHOD = "git_blob_sha256_file_set_plus_index_tree_v2"


@dataclass(frozen=True)
class CorpusSpec:
    corpus_id: str
    language: str
    repository_origin: str
    revision_sha1: str
    commit_tree_sha1: str
    expected_results_path: str
    expected_results_sha256: str
    license_path: str
    license_spdx: str
    license_sha256: str
    expected_case_count: int
    source_prefix: str
    source_suffix: str
    category_cwe: tuple[tuple[str, str], ...]


JAVA_CATEGORIES = (
    ("cmdi", "78"),
    ("crypto", "327"),
    ("hash", "328"),
    ("ldapi", "90"),
    ("pathtraver", "22"),
    ("securecookie", "614"),
    ("sqli", "89"),
    ("trustbound", "501"),
    ("weakrand", "330"),
    ("xpathi", "643"),
    ("xss", "79"),
)
PYTHON_CATEGORIES = (
    ("cmdi", "78"),
    ("codeinj", "94"),
    ("deserialization", "502"),
    ("hash", "328"),
    ("ldapi", "90"),
    ("pathtraver", "22"),
    ("redirect", "601"),
    ("securecookie", "614"),
    ("sqli", "89"),
    ("trustbound", "501"),
    ("weakrand", "330"),
    ("xpathi", "643"),
    ("xss", "79"),
    ("xxe", "611"),
)

L1_CORPORA = (
    CorpusSpec(
        corpus_id="owasp-benchmarkjava-1.2",
        language="java",
        repository_origin="https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        revision_sha1="79b9bd6177e07991a9c11dc19e457c840e229931",
        commit_tree_sha1="717509a4aeaf3cfacb8b1d8dec2c61ed9f88451a",
        expected_results_path="expectedresults-1.2.csv",
        expected_results_sha256="1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1",
        license_path="LICENSE",
        license_spdx="GPL-2.0-only",
        license_sha256="c03cea027b4b40e4402fabd08557736727ec3d5bc54ad64ab6472de432198cad",
        expected_case_count=2740,
        source_prefix="src/main/java/org/owasp/benchmark/testcode",
        source_suffix=".java",
        category_cwe=JAVA_CATEGORIES,
    ),
    CorpusSpec(
        corpus_id="owasp-benchmarkpython-0.1",
        language="python",
        repository_origin="https://github.com/OWASP-Benchmark/BenchmarkPython.git",
        revision_sha1="f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
        commit_tree_sha1="52367e858afa7841580a006e665c706b67874c4f",
        expected_results_path="expectedresults-0.1.csv",
        expected_results_sha256="6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c",
        license_path="LICENSE",
        license_spdx="GPL-3.0-only",
        license_sha256="3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
        expected_case_count=1230,
        source_prefix="testcode",
        source_suffix=".py",
        category_cwe=PYTHON_CATEGORIES,
    ),
)


def canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            byte_count += len(chunk)
    return digest.hexdigest(), byte_count


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        check=False,
        env=_git_environment(),
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise ValueError(f"git integrity check failed: {detail or arguments[0]}")
    return completed.stdout.rstrip("\r\n")


def _safe_root(value: str | Path) -> Path:
    root = Path(value)
    if root.is_symlink():
        raise ValueError("corpus root must not be a symlink")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("corpus checkout does not exist") from exc
    if not resolved.is_dir() or not (resolved / ".git").exists():
        raise ValueError("corpus checkout must be a Git worktree")
    return resolved


def _has_reparse_point(metadata: os.stat_result) -> bool:
    attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attribute and getattr(metadata, "st_file_attributes", 0) & attribute)


def _regular_file(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe corpus path: {relative}")
    path = root.joinpath(*pure.parts)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"required corpus file is missing: {relative}") from exc
    if path.is_symlink() or _has_reparse_point(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"corpus file must be a regular non-link file: {relative}")
    return path


def _index_entries(root: Path) -> list[dict[str, str]]:
    raw = _git(root, "ls-files", "--stage", "-z")
    if not raw:
        raise ValueError("corpus checkout contains no tracked files")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw.split("\0"):
        if not item:
            continue
        try:
            metadata, relative = item.split("\t", 1)
            mode, blob_sha1, stage = metadata.split(" ", 2)
        except ValueError as exc:
            raise ValueError("malformed Git index entry") from exc
        if stage != "0" or mode not in {"100644", "100755"} or not SHA1_RE.fullmatch(blob_sha1):
            raise ValueError(f"unsupported or linked Git index entry: {relative}")
        if relative in seen:
            raise ValueError(f"duplicate Git index path: {relative}")
        seen.add(relative)
        rows.append(
            {
                "path": relative,
                "mode": mode,
                "git_blob_sha1": blob_sha1,
            }
        )
    rows.sort(key=lambda row: str(row["path"]).encode("utf-8"))
    return rows


def _head_tree_entries(root: Path, revision: str) -> list[dict[str, str]]:
    raw = _git(root, "ls-tree", "-r", "-z", "--full-tree", revision)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw.split("\0"):
        if not item:
            continue
        try:
            metadata, relative = item.split("\t", 1)
            mode, object_type, blob_sha1 = metadata.split(" ", 2)
        except ValueError as exc:
            raise ValueError("malformed Git tree entry") from exc
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or not SHA1_RE.fullmatch(blob_sha1)
        ):
            raise ValueError(f"unsupported or linked Git tree entry: {relative}")
        if relative in seen:
            raise ValueError(f"duplicate Git tree path: {relative}")
        seen.add(relative)
        rows.append(
            {
                "path": relative,
                "mode": mode,
                "git_blob_sha1": blob_sha1,
            }
        )
    rows.sort(key=lambda row: str(row["path"]).encode("utf-8"))
    if not rows:
        raise ValueError("corpus commit contains no files")
    return rows


def _read_exact(stream: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ValueError("Git blob stream ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _git_blob_receipts(root: Path, object_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    ordered = sorted(set(object_ids))
    if not ordered or any(SHA1_RE.fullmatch(value) is None for value in ordered):
        raise ValueError("Git blob request contains an invalid object id")
    process = subprocess.Popen(
        ["git", "-C", str(root), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_git_environment(),
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise ValueError("Git blob verifier could not open its pipes")
    receipts: dict[str, dict[str, Any]] = {}
    try:
        for expected_oid in ordered:
            process.stdin.write(expected_oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(256)
            parts = header.rstrip(b"\n").split(b" ")
            if len(parts) != 3:
                raise ValueError("Git blob response header is malformed")
            try:
                actual_oid = parts[0].decode("ascii")
                object_type = parts[1].decode("ascii")
                byte_count = int(parts[2].decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("Git blob response header is malformed") from exc
            if actual_oid != expected_oid or object_type != "blob" or byte_count < 0:
                raise ValueError("Git blob response does not match the index")
            raw = _read_exact(process.stdout, byte_count)
            if process.stdout.read(1) != b"\n":
                raise ValueError("Git blob response terminator is missing")
            git_digest = hashlib.sha1(usedforsecurity=False)
            git_digest.update(f"blob {byte_count}\0".encode("ascii"))
            git_digest.update(raw)
            if git_digest.hexdigest() != expected_oid:
                raise ValueError("Git blob failed independent SHA-1 verification")
            receipts[expected_oid] = {
                "sha256": _sha256_bytes(raw),
                "byte_count": byte_count,
            }
        process.stdin.close()
        if process.wait(timeout=30) != 0:
            detail = process.stderr.read().decode("utf-8", errors="replace").strip()
            raise ValueError(f"Git blob verification failed: {detail or 'cat-file'}")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    return receipts


def _tracked_files(root: Path, revision: str) -> list[dict[str, Any]]:
    index_rows = _index_entries(root)
    tree_rows = _head_tree_entries(root, revision)
    if index_rows != tree_rows:
        raise ValueError("corpus index tree differs from the pinned HEAD tree")
    blobs = _git_blob_receipts(
        root,
        (str(row["git_blob_sha1"]) for row in index_rows),
    )
    rows: list[dict[str, Any]] = []
    for row in index_rows:
        relative = str(row["path"])
        path = _regular_file(root, relative)
        digest, byte_count = _sha256_file(path)
        blob = blobs[str(row["git_blob_sha1"])]
        if digest != blob["sha256"] or byte_count != blob["byte_count"]:
            raise ValueError(f"physical bytes differ from the indexed Git blob: {relative}")
        rows.append(
            {
                **row,
                "sha256": digest,
                "byte_count": byte_count,
            }
        )
    return rows


def _reject_untracked_or_linked_tree(root: Path, tracked_paths: set[str]) -> None:
    physical_paths: set[str] = set()
    for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
        relative_directory = Path(directory).relative_to(root)
        if relative_directory == Path("."):
            directories[:] = [name for name in directories if name != ".git"]
        for name in directories:
            path = Path(directory) / name
            metadata = path.stat(follow_symlinks=False)
            if path.is_symlink() or _has_reparse_point(metadata):
                raise ValueError("corpus checkout contains a symlink or reparse point")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("corpus checkout contains an unsupported directory entry")
        for name in files:
            path = Path(directory) / name
            metadata = path.stat(follow_symlinks=False)
            if (
                path.is_symlink()
                or _has_reparse_point(metadata)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise ValueError("corpus checkout contains a link or unsupported file entry")
            relative = path.relative_to(root).as_posix()
            if relative not in tracked_paths:
                raise ValueError(f"corpus checkout contains an untracked or ignored file: {relative}")
            physical_paths.add(relative)
    if physical_paths != tracked_paths:
        raise ValueError("corpus checkout has missing indexed paths")


def _read_expected_rows(path: Path, spec: CorpusSpec) -> list[dict[str, Any]]:
    expected_mapping = dict(spec.category_cwe)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        stream = path.open("r", encoding="utf-8-sig", newline="")
    except (OSError, UnicodeError) as exc:
        raise ValueError("expected-results CSV could not be opened") from exc
    try:
        with stream:
            reader = csv.reader(stream, strict=True)
            for line_number, row in enumerate(reader, start=1):
                if not row or (row[0].lstrip().startswith("#") and len(row) >= 1):
                    continue
                if len(row) != 4:
                    raise ValueError(f"malformed expected-results row at line {line_number}")
                case_id, category, truth_value, cwe = (value.strip() for value in row)
                category = category.lower()
                truth_value = truth_value.lower()
                if CASE_ID_RE.fullmatch(case_id) is None:
                    raise ValueError(f"invalid case identifier at line {line_number}")
                if case_id in seen:
                    raise ValueError(f"duplicate expected-results case: {case_id}")
                if truth_value not in {"true", "false"}:
                    raise ValueError(f"invalid truth value for case: {case_id}")
                if category not in expected_mapping or expected_mapping[category] != cwe:
                    raise ValueError(f"unsupported category/CWE mapping: {category}/{cwe}")
                seen.add(case_id)
                rows.append(
                    {
                        "case_id": case_id,
                        "truth": "present" if truth_value == "true" else "absent",
                        "category": category,
                        "cwe": f"CWE-{cwe}",
                    }
                )
    except (csv.Error, UnicodeError) as exc:
        raise ValueError("malformed expected-results CSV") from exc
    if len(rows) != spec.expected_case_count:
        raise ValueError(
            f"expected exactly {spec.expected_case_count} unique cases; found {len(rows)}"
        )
    return rows


def _normalized_source_tree_rows(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "git_blob_sha1": row["git_blob_sha1"],
            "byte_count": row["byte_count"],
        }
        for row in files
    ]
    rows.sort(key=lambda row: str(row["path"]))
    return rows


def _source_tree_sha256(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        (SOURCE_TREE_SCHEMA + "\0").encode("ascii")
        + json.dumps(
            rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _tree_receipt(files: list[dict[str, Any]]) -> dict[str, Any]:
    normalized_rows = _normalized_source_tree_rows(files)
    return {
        "schema": SOURCE_TREE_SCHEMA,
        "source_worktree_clean": True,
        "source_worktree_clean_method": BLOB_EXACT_CLEAN_METHOD,
        "index_tree_match": True,
        "physical_bytes_match_git_blobs": True,
        "no_untracked_or_ignored_physical_files": True,
        "source_tree_sha256": _source_tree_sha256(normalized_rows),
        "file_count": len(files),
        "total_bytes": sum(int(row["byte_count"]) for row in files),
        "files": files,
    }


def _materialize_corpus(root_value: str | Path, spec: CorpusSpec) -> dict[str, Any]:
    root = _safe_root(root_value)
    revision = _git(root, "rev-parse", "--verify", "HEAD")
    tree = _git(root, "rev-parse", "--verify", "HEAD^{tree}")
    origin = _git(root, "remote", "get-url", "origin")
    if revision != spec.revision_sha1:
        raise ValueError(f"revision mismatch for {spec.corpus_id}")
    if tree != spec.commit_tree_sha1:
        raise ValueError(f"commit tree mismatch for {spec.corpus_id}")
    if origin != spec.repository_origin:
        raise ValueError(f"origin mismatch for {spec.corpus_id}")

    files = _tracked_files(root, revision)
    _reject_untracked_or_linked_tree(
        root,
        {str(row["path"]) for row in files},
    )
    by_path = {str(row["path"]): row for row in files}
    license_file = _regular_file(root, spec.license_path)
    expected_file = _regular_file(root, spec.expected_results_path)
    license_sha256, license_bytes = _sha256_file(license_file)
    expected_sha256, expected_bytes = _sha256_file(expected_file)
    if license_sha256 != spec.license_sha256:
        raise ValueError(f"license content mismatch for {spec.corpus_id}")
    if expected_sha256 != spec.expected_results_sha256:
        raise ValueError(f"expected-results content mismatch for {spec.corpus_id}")
    if spec.license_path not in by_path or spec.expected_results_path not in by_path:
        raise ValueError("license and expected-results files must be tracked")

    expected_rows = _read_expected_rows(expected_file, spec)
    cases: list[dict[str, Any]] = []
    for row in expected_rows:
        source_path = f"{spec.source_prefix}/{row['case_id']}{spec.source_suffix}"
        source = by_path.get(source_path)
        if source is None:
            raise ValueError(f"case source is missing or untracked: {source_path}")
        _regular_file(root, source_path)
        cases.append(
            {
                **row,
                "source_path": source_path,
                "source_sha256": source["sha256"],
                "source_bytes": source["byte_count"],
            }
        )
    cases.sort(key=lambda row: str(row["case_id"]))
    case_projection = [
        {
            "case_id": row["case_id"],
            "truth": row["truth"],
            "category": row["category"],
            "cwe": row["cwe"],
            "source_path": row["source_path"],
            "source_sha256": row["source_sha256"],
        }
        for row in cases
    ]
    return {
        "corpus_id": spec.corpus_id,
        "language": spec.language,
        "repository_origin": origin,
        "revision_sha1": revision,
        "commit_tree_sha1": tree,
        "source_tree": _tree_receipt(files),
        "license": {
            "path": spec.license_path,
            "spdx": spec.license_spdx,
            "sha256": license_sha256,
            "byte_count": license_bytes,
        },
        "expected_results": {
            "path": spec.expected_results_path,
            "sha256": expected_sha256,
            "byte_count": expected_bytes,
            "row_count": len(cases),
            "unique_case_count": len(cases),
        },
        "case_set_sha256": _sha256_bytes(canonical_json_bytes(case_projection)),
        "case_set_schema": CASE_SET_SCHEMA,
        "cases": cases,
    }


def build_manifest(
    benchmark_java: str | Path,
    benchmark_python: str | Path,
    *,
    specs: Iterable[CorpusSpec] = L1_CORPORA,
) -> dict[str, Any]:
    locked_specs = tuple(specs)
    if len(locked_specs) != 2 or {spec.language for spec in locked_specs} != {"java", "python"}:
        raise ValueError("L1 materialization requires exactly Java and Python corpus specifications")
    paths = {"java": benchmark_java, "python": benchmark_python}
    corpora = [_materialize_corpus(paths[spec.language], spec) for spec in locked_specs]
    corpora.sort(key=lambda row: str(row["corpus_id"]))
    return {
        "schema": SCHEMA,
        "lane": "L1",
        "status": "locked_before_scan",
        "scanner_output_observed": False,
        "coverage_policy": "all_official_rows_exactly_once",
        "unsupported_detector_category_policy": "retain_in_denominator",
        "corpus_count": len(corpora),
        "total_case_count": sum(len(row["cases"]) for row in corpora),
        "corpora": corpora,
    }


def write_manifest(
    benchmark_java: str | Path,
    benchmark_python: str | Path,
    output: str | Path,
) -> dict[str, Any]:
    output_path = Path(output)
    if output_path.exists():
        raise ValueError("refusing to overwrite an existing L1 manifest")
    if output_path.is_symlink():
        raise ValueError("output path must not be a symlink")
    manifest = build_manifest(benchmark_java, benchmark_python)
    payload = canonical_json_bytes(manifest)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing to overwrite an existing L1 manifest") from exc
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bind the complete pinned OWASP BenchmarkJava and BenchmarkPython L1 corpus before scanning."
    )
    parser.add_argument("--benchmark-java", type=Path, required=True)
    parser.add_argument("--benchmark-python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = write_manifest(args.benchmark_java, args.benchmark_python, args.output)
    print(
        json.dumps(
            {
                "schema": manifest["schema"],
                "status": manifest["status"],
                "total_case_count": manifest["total_case_count"],
                "output": str(args.output.resolve()),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
