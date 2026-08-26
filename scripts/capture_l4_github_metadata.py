from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from k_guard_mcp.public_lineage import (
    GITHUB_METADATA_API,
    GITHUB_METADATA_QUERY_BYTES,
    SOURCE_RECEIPT_SCHEMA,
    canonical_json_bytes,
)


CAPTURE_SCHEMA = "k_guard_l4_github_metadata_capture.v1"
MAX_RECEIPT_BYTES = 256 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")


class GitHubCaptureError(RuntimeError):
    pass


def _decode_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GitHubCaptureError(f"{label} contains duplicate JSON key")
            result[key] = value
        return result

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                GitHubCaptureError(f"{label} contains non-finite JSON")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GitHubCaptureError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise GitHubCaptureError(f"{label} must be a JSON object")
    return payload


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _read_regular_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise GitHubCaptureError(f"{label} is unavailable") from exc
    if (
        _is_link_or_reparse(path, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > maximum_bytes
    ):
        raise GitHubCaptureError(f"{label} must be a bounded regular file")
    raw = path.read_bytes()
    after = os.lstat(path)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field, None) != getattr(after, field, None) for field in stable):
        raise GitHubCaptureError(f"{label} changed during read")
    if len(raw) != before.st_size:
        raise GitHubCaptureError(f"{label} changed during read")
    return raw


def load_repository_ids(source_receipts: Path) -> list[str]:
    try:
        metadata = os.lstat(source_receipts)
    except OSError as exc:
        raise GitHubCaptureError("source receipt directory is unavailable") from exc
    if _is_link_or_reparse(source_receipts, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise GitHubCaptureError("source receipt directory must be a real directory")
    repository_ids: list[str] = []
    for path in sorted(source_receipts.glob("*.json"), key=lambda value: value.name):
        receipt = _decode_json_object(
            _read_regular_file(
                path,
                maximum_bytes=MAX_RECEIPT_BYTES,
                label="source receipt",
            ),
            label="source receipt",
        )
        repository_id = receipt.get("repository_id")
        if (
            receipt.get("schema") != SOURCE_RECEIPT_SCHEMA
            or receipt.get("passed") is not True
            or not isinstance(repository_id, str)
            or _REPOSITORY_RE.fullmatch(repository_id) is None
        ):
            raise GitHubCaptureError("source receipt admission fields are invalid")
        repository_ids.append(repository_id)
    if not repository_ids or len(repository_ids) != len(set(repository_ids)):
        raise GitHubCaptureError("source receipt repository set is empty or duplicated")
    return sorted(repository_ids)


def _capture_one(
    repository_id: str,
    *,
    gh_executable: str,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> bytes:
    owner, name = repository_id.split("/", 1)
    command = [
        gh_executable,
        "api",
        "graphql",
        "-f",
        f"query={GITHUB_METADATA_QUERY_BYTES.decode('ascii')}",
        "-F",
        f"owner={owner}",
        "-F",
        f"name={name}",
    ]
    try:
        completed = runner(
            command,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GitHubCaptureError(f"GitHub metadata request failed: {repository_id}") from exc
    raw = completed.stdout
    if completed.returncode != 0 or not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise GitHubCaptureError(f"GitHub metadata request failed: {repository_id}")
    response = _decode_json_object(raw, label="GitHub metadata response")
    data = response.get("data")
    repository = data.get("repository") if isinstance(data, dict) else None
    name_with_owner = (
        repository.get("nameWithOwner") if isinstance(repository, dict) else None
    )
    if not isinstance(name_with_owner, str) or name_with_owner.casefold() != repository_id:
        raise GitHubCaptureError(f"GitHub metadata identity mismatch: {repository_id}")
    return raw


def _repository_set_sha256(repository_ids: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(repository_ids), separators=(",", ":")).encode("ascii")
    ).hexdigest()


def capture_github_metadata(
    *,
    source_receipts: Path,
    output: Path,
    gh_executable: str,
    captured_at_utc: str,
    workers: int = 4,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite GitHub capture: {output}")
    if workers < 1 or workers > 8:
        raise GitHubCaptureError("workers must be between 1 and 8")
    try:
        parsed_time = datetime.strptime(captured_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GitHubCaptureError("capture time must be canonical UTC") from exc
    if parsed_time.tzinfo is not None:
        raise GitHubCaptureError("capture time must be canonical UTC")
    repository_ids = load_repository_ids(source_receipts)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=str(output.parent))
    )
    try:
        query_path = staging / "query.graphql"
        query_path.write_bytes(GITHUB_METADATA_QUERY_BYTES)
        response_root = staging / "responses"
        response_root.mkdir()
        captured: dict[str, bytes] = {}
        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = {
                executor.submit(
                    _capture_one,
                    repository_id,
                    gh_executable=gh_executable,
                    runner=runner,
                ): repository_id
                for repository_id in repository_ids
            }
            for future in as_completed(pending):
                repository_id = pending[future]
                captured[repository_id] = future.result()
        rows: list[dict[str, Any]] = []
        for repository_id in repository_ids:
            relative = f"responses/{repository_id.replace('/', '--')}.json"
            raw = captured[repository_id]
            (staging / relative).write_bytes(raw)
            rows.append(
                {
                    "repository_id": repository_id,
                    "response_path": relative,
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        manifest: dict[str, Any] = {
            "schema": CAPTURE_SCHEMA,
            "capture_implementation_sha256": hashlib.sha256(
                _read_regular_file(
                    Path(__file__),
                    maximum_bytes=MAX_RESPONSE_BYTES,
                    label="capture implementation",
                )
            ).hexdigest(),
            "api": GITHUB_METADATA_API,
            "captured_at_utc": captured_at_utc,
            "query_path": "query.graphql",
            "query_sha256": hashlib.sha256(GITHUB_METADATA_QUERY_BYTES).hexdigest(),
            "repository_count": len(repository_ids),
            "repository_set_sha256": _repository_set_sha256(repository_ids),
            "responses": rows,
            "network_accessed_during_capture": True,
            "network_accessed_during_selection": False,
            "scanner_imported": False,
            "scanner_output_observed": False,
            "raw_returned": False,
        }
        (staging / "capture-manifest.json").write_bytes(canonical_json_bytes(manifest))
        os.replace(staging, output)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture primary GitHub metadata before offline L4 selection."
    )
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gh-executable", default=shutil.which("gh") or "gh")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    captured_at = datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    result = capture_github_metadata(
        source_receipts=args.source_receipts,
        output=args.output,
        gh_executable=args.gh_executable,
        captured_at_utc=captured_at,
        workers=args.workers,
    )
    print(
        json.dumps(
            {
                "schema": result["schema"],
                "repository_count": result["repository_count"],
                "query_sha256": result["query_sha256"],
                "network_accessed_during_capture": True,
                "scanner_output_observed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
