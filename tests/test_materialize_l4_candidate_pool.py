from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest

from k_guard_mcp.public_lineage import (
    GITHUB_METADATA_API,
    GITHUB_METADATA_QUERY_BYTES,
    QUOTAS,
    SOURCE_RECEIPT_SCHEMA,
    candidate_record_sha256,
    canonical_json_bytes,
    seal_candidate_pool_bytes,
)
from scripts.capture_l4_github_metadata import CAPTURE_SCHEMA
from scripts.materialize_l4_candidate_pool import (
    CandidatePoolMaterializationError,
    materialize_candidate_pool,
    write_candidate_pool,
)


CAPTURED_AT = "2026-07-19T12:00:00Z"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _repository_set_sha256(repository_ids: list[str]) -> str:
    return _sha256(
        json.dumps(sorted(repository_ids), separators=(",", ":")).encode("ascii")
    )


def _stars(stratum: str, index: int) -> int:
    if stratum == "top":
        return 1000 + index
    if stratum == "mid":
        return 50 + index
    return index


def _response(repository_id: str, stratum: str, index: int) -> dict:
    return {
        "data": {
            "repository": {
                "id": f"NODE-{stratum}-{index:03d}=",
                "nameWithOwner": repository_id,
                "url": f"https://github.com/{repository_id}",
                "isFork": False,
                "isTemplate": False,
                "isArchived": False,
                "stargazerCount": _stars(stratum, index),
                "description": "Deployable self-hosted app",
                "licenseInfo": {"spdxId": "MIT"},
                "repositoryTopics": {"nodes": []},
                "parent": None,
            }
        }
    }


def _receipt(repository_id: str, stratum: str, index: int) -> dict:
    license_raw = b"MIT fixture\n"
    package_raw = b'{"scripts":{"start":"node app.js"}}\n'
    return {
        "schema": SOURCE_RECEIPT_SCHEMA,
        "passed": True,
        "repository_id": repository_id,
        "commit": f"{index + 1:040x}"[-40:],
        "commit_tree": hashlib.sha1(
            f"{repository_id}-tree".encode(), usedforsecurity=False
        ).hexdigest(),
        "source_tree_sha256": _sha256(repository_id.encode()),
        "files": [
            {
                "path": "LICENSE",
                "sha256": _sha256(license_raw),
            },
            {
                "path": "package.json",
                "sha256": _sha256(package_raw),
            },
        ],
    }


def _fixture(
    tmp_path: Path, *, reserve_per_stratum: int = 2
) -> dict[str, Path | str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    receipts = tmp_path / "receipts"
    sources = tmp_path / "sources"
    capture = tmp_path / "capture"
    responses = capture / "responses"
    receipts.mkdir()
    sources.mkdir()
    responses.mkdir(parents=True)
    (capture / "query.graphql").write_bytes(GITHUB_METADATA_QUERY_BYTES)
    capture_rows = []
    repository_ids = []
    for stratum, quota in QUOTAS.items():
        for index in range(quota + reserve_per_stratum):
            repository_id = f"owner-{stratum}/app-{index:03d}"
            slug = repository_id.replace("/", "--")
            repository_ids.append(repository_id)
            (receipts / f"{slug}.json").write_bytes(
                canonical_json_bytes(_receipt(repository_id, stratum, index))
            )
            (sources / slug).mkdir()
            response_path = responses / f"{slug}.json"
            response_raw = canonical_json_bytes(
                _response(repository_id, stratum, index)
            )
            response_path.write_bytes(response_raw)
            capture_rows.append(
                {
                    "repository_id": repository_id,
                    "response_path": f"responses/{slug}.json",
                    "response_sha256": _sha256(response_raw),
                }
            )
    capture_rows.sort(key=lambda row: row["repository_id"])
    manifest = {
        "schema": CAPTURE_SCHEMA,
        "capture_implementation_sha256": "d" * 64,
        "api": GITHUB_METADATA_API,
        "captured_at_utc": CAPTURED_AT,
        "query_path": "query.graphql",
        "query_sha256": _sha256(GITHUB_METADATA_QUERY_BYTES),
        "repository_count": len(repository_ids),
        "repository_set_sha256": _repository_set_sha256(repository_ids),
        "responses": capture_rows,
        "network_accessed_during_capture": True,
        "network_accessed_during_selection": False,
        "scanner_imported": False,
        "scanner_output_observed": False,
        "raw_returned": False,
    }
    manifest_raw = canonical_json_bytes(manifest)
    (capture / "capture-manifest.json").write_bytes(manifest_raw)
    existing = tmp_path / "existing.json"
    prior = tmp_path / "prior.json"
    existing.write_bytes(b'{"fixture":"existing"}\n')
    prior.write_bytes(b'{"fixture":"prior"}\n')
    return {
        "receipts": receipts,
        "sources": sources,
        "capture": capture,
        "capture_sha256": _sha256(manifest_raw),
        "existing": existing,
        "prior": prior,
    }


def _materialize(tmp_path: Path, fixture: dict[str, Path | str]) -> dict:
    return materialize_candidate_pool(
        artifact_root=tmp_path,
        source_receipts=fixture["receipts"],  # type: ignore[arg-type]
        source_checkouts=fixture["sources"],  # type: ignore[arg-type]
        capture_root=fixture["capture"],  # type: ignore[arg-type]
        expected_capture_manifest_sha256=str(fixture["capture_sha256"]),
        existing_41=fixture["existing"],  # type: ignore[arg-type]
        prior_evidence_105=fixture["prior"],  # type: ignore[arg-type]
    )


def test_materializer_builds_offline_pool_with_reserve_in_every_stratum(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    first = _materialize(tmp_path, fixture)
    second = _materialize(tmp_path, fixture)

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert first["source_population_count"] == 65
    assert first["candidate_count"] == 65
    assert Counter(row["star_stratum"] for row in first["candidates"]) == {
        stratum: quota + 2 for stratum, quota in QUOTAS.items()
    }
    assert first["materialization_rejection_ledger"] == []
    assert first["selection_boundary"]["network_accessed"] is False
    assert first["selection_boundary"]["scanner_output_observed"] is False
    assert first["provenance"]["capture_implementation_sha256"] == "d" * 64
    assert len(first["provenance"]["candidate_materializer_sha256"]) == 64
    assert all(
        row["candidate_sha256"] == candidate_record_sha256(row)
        for row in first["candidates"]
    )
    raw = canonical_json_bytes(first)
    seal_candidate_pool_bytes(raw, expected_manifest_sha256=_sha256(raw))

    output = tmp_path / "candidate-pool.json"
    write_candidate_pool(output, first)
    assert output.read_bytes() == raw
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_candidate_pool(output, first)


def test_capture_or_response_tamper_fails_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    with pytest.raises(CandidatePoolMaterializationError, match="manifest SHA-256"):
        materialize_candidate_pool(
            artifact_root=tmp_path,
            source_receipts=fixture["receipts"],  # type: ignore[arg-type]
            source_checkouts=fixture["sources"],  # type: ignore[arg-type]
            capture_root=fixture["capture"],  # type: ignore[arg-type]
            expected_capture_manifest_sha256="0" * 64,
            existing_41=fixture["existing"],  # type: ignore[arg-type]
            prior_evidence_105=fixture["prior"],  # type: ignore[arg-type]
        )

    response = next((fixture["capture"] / "responses").glob("*.json"))  # type: ignore[operator]
    response.write_bytes(response.read_bytes() + b" ")
    with pytest.raises(CandidatePoolMaterializationError, match="GitHub response SHA-256"):
        _materialize(tmp_path, fixture)


def test_missing_license_is_accounted_and_wrong_reserve_strata_fails_closed(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    receipt_path = next((fixture["receipts"]).glob("*.json"))  # type: ignore[union-attr]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["files"] = [
        row for row in receipt["files"] if row["path"] != "LICENSE"
    ]
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    result = _materialize(tmp_path, fixture)
    assert result["source_population_count"] == 65
    assert result["candidate_count"] == 64
    assert result["materialization_rejection_ledger"] == [
        {
            "repository_id": receipt["repository_id"],
            "source_receipt_sha256": _sha256(receipt_path.read_bytes()),
            "github_metadata_sha256": next(
                row["response_sha256"]
                for row in json.loads(
                    (fixture["capture"] / "capture-manifest.json").read_text(  # type: ignore[operator]
                        encoding="utf-8"
                    )
                )["responses"]
                if row["repository_id"] == receipt["repository_id"]
            ),
            "reasons": ["root_license_file_missing"],
        }
    ]

    fixture = _fixture(tmp_path / "strata", reserve_per_stratum=1)
    response_path = next((fixture["capture"] / "responses").glob("owner-top*.json"))  # type: ignore[operator]
    response = json.loads(response_path.read_text(encoding="utf-8"))
    response["data"]["repository"]["stargazerCount"] = 999
    raw = canonical_json_bytes(response)
    response_path.write_bytes(raw)
    manifest_path = fixture["capture"] / "capture-manifest.json"  # type: ignore[operator]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    row = next(
        value
        for value in manifest["responses"]
        if value["response_path"] == f"responses/{response_path.name}"
    )
    row["response_sha256"] = _sha256(raw)
    manifest_raw = canonical_json_bytes(manifest)
    manifest_path.write_bytes(manifest_raw)
    fixture["capture_sha256"] = _sha256(manifest_raw)
    with pytest.raises(
        CandidatePoolMaterializationError, match="stratum reserve contract"
    ):
        _materialize(tmp_path / "strata", fixture)


@pytest.mark.parametrize("drift", ["missing_receipt", "extra_receipt"])
def test_receipt_and_github_repository_set_drift_fails_closed(
    tmp_path: Path, drift: str
) -> None:
    fixture = _fixture(tmp_path)
    receipts = fixture["receipts"]
    assert isinstance(receipts, Path)
    receipt_path = next(receipts.glob("*.json"))

    if drift == "missing_receipt":
        receipt_path.unlink()
    else:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["repository_id"] = "extra-owner/extra-app"
        (receipts / "extra-owner--extra-app.json").write_bytes(
            canonical_json_bytes(receipt)
        )

    with pytest.raises(
        CandidatePoolMaterializationError,
        match="source receipt and GitHub response repository sets differ",
    ):
        _materialize(tmp_path, fixture)


def test_missing_source_checkout_fails_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    sources = fixture["sources"]
    assert isinstance(sources, Path)
    next(sources.iterdir()).rmdir()

    with pytest.raises(
        CandidatePoolMaterializationError, match="source checkout is missing"
    ):
        _materialize(tmp_path, fixture)
