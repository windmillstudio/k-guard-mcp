from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from k_guard_mcp.public_lineage import (
    GITHUB_METADATA_QUERY_BYTES,
    SOURCE_RECEIPT_SCHEMA,
    canonical_json_bytes,
)
from scripts.capture_l4_github_metadata import (
    GitHubCaptureError,
    capture_github_metadata,
    load_repository_ids,
)
import scripts.capture_l4_github_metadata as capture_module


CAPTURED_AT = "2026-07-19T12:00:00Z"


def _write_receipt(root: Path, name: str, repository_id: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_bytes(
        canonical_json_bytes(
            {
                "schema": SOURCE_RECEIPT_SCHEMA,
                "passed": True,
                "repository_id": repository_id,
            }
        )
    )


def _runner(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
    owner = next(value.split("=", 1)[1] for value in command if value.startswith("owner="))
    name = next(value.split("=", 1)[1] for value in command if value.startswith("name="))
    repository_id = f"{owner}/{name}"
    raw = json.dumps(
        {
            "data": {
                "repository": {
                    "id": f"NODE-{owner}-{name}=",
                    "nameWithOwner": repository_id,
                }
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return subprocess.CompletedProcess(command, 0, raw, b"")


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_capture_is_repeatable_and_contains_only_prefetched_primary_data(
    tmp_path: Path,
) -> None:
    receipts = tmp_path / "receipts"
    _write_receipt(receipts, "b.json", "owner-b/app-b")
    _write_receipt(receipts, "a.json", "owner-a/app-a")

    first = capture_github_metadata(
        source_receipts=receipts,
        output=tmp_path / "first",
        gh_executable="gh-fixture",
        captured_at_utc=CAPTURED_AT,
        workers=2,
        runner=_runner,
    )
    second = capture_github_metadata(
        source_receipts=receipts,
        output=tmp_path / "second",
        gh_executable="gh-fixture",
        captured_at_utc=CAPTURED_AT,
        workers=1,
        runner=_runner,
    )

    assert _tree_bytes(tmp_path / "first") == _tree_bytes(tmp_path / "second")
    assert first == second
    assert first["repository_count"] == 2
    assert first["network_accessed_during_capture"] is True
    assert first["network_accessed_during_selection"] is False
    assert first["scanner_imported"] is False
    assert first["scanner_output_observed"] is False
    assert (tmp_path / "first" / "query.graphql").read_bytes() == GITHUB_METADATA_QUERY_BYTES
    assert first["query_sha256"] == hashlib.sha256(GITHUB_METADATA_QUERY_BYTES).hexdigest()
    assert first["capture_implementation_sha256"] == hashlib.sha256(
        Path(capture_module.__file__).read_bytes()
    ).hexdigest()
    assert (tmp_path / "first" / "capture-manifest.json").read_bytes() == canonical_json_bytes(first)


def test_source_receipt_repository_set_must_be_unique_and_valid(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts"
    _write_receipt(receipts, "a.json", "owner/app")
    _write_receipt(receipts, "b.json", "owner/app")
    with pytest.raises(GitHubCaptureError, match="empty or duplicated"):
        load_repository_ids(receipts)

    (receipts / "b.json").write_bytes(
        canonical_json_bytes(
            {
                "schema": SOURCE_RECEIPT_SCHEMA,
                "passed": False,
                "repository_id": "owner/other",
            }
        )
    )
    with pytest.raises(GitHubCaptureError, match="admission fields"):
        load_repository_ids(receipts)


def test_identity_mismatch_or_command_failure_leaves_no_final_output(
    tmp_path: Path,
) -> None:
    receipts = tmp_path / "receipts"
    _write_receipt(receipts, "a.json", "owner/app")

    def wrong_identity(
        command: list[str], **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            command,
            0,
            b'{"data":{"repository":{"nameWithOwner":"other/app"}}}',
            b"",
        )

    output = tmp_path / "capture"
    with pytest.raises(GitHubCaptureError, match="identity mismatch"):
        capture_github_metadata(
            source_receipts=receipts,
            output=output,
            gh_executable="gh-fixture",
            captured_at_utc=CAPTURED_AT,
            runner=wrong_identity,
        )
    assert not output.exists()

    def failed(command: list[str], **_: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 1, b"", b"secret stderr")

    with pytest.raises(GitHubCaptureError, match="request failed"):
        capture_github_metadata(
            source_receipts=receipts,
            output=output,
            gh_executable="gh-fixture",
            captured_at_utc=CAPTURED_AT,
            runner=failed,
        )
    assert not output.exists()


def test_capture_refuses_overwrite_and_invalid_time(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts"
    _write_receipt(receipts, "a.json", "owner/app")
    output = tmp_path / "capture"
    capture_github_metadata(
        source_receipts=receipts,
        output=output,
        gh_executable="gh-fixture",
        captured_at_utc=CAPTURED_AT,
        runner=_runner,
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        capture_github_metadata(
            source_receipts=receipts,
            output=output,
            gh_executable="gh-fixture",
            captured_at_utc=CAPTURED_AT,
            runner=_runner,
        )
    with pytest.raises(GitHubCaptureError, match="canonical UTC"):
        capture_github_metadata(
            source_receipts=receipts,
            output=tmp_path / "other",
            gh_executable="gh-fixture",
            captured_at_utc="2026-19-39T25:61:61Z",
            runner=_runner,
        )


def test_symlink_receipt_directory_is_rejected(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts"
    _write_receipt(receipts, "a.json", "owner/app")
    link = tmp_path / "linked"
    try:
        link.symlink_to(receipts, target_is_directory=True)
    except OSError as exc:
        pytest.fail(f"test environment could not create symlink fixture: {exc}")
    with pytest.raises(GitHubCaptureError, match="real directory"):
        load_repository_ids(link)
