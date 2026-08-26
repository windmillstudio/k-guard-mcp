from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validate_raw_free_candidate_queue import build_receipt, write_receipt


def _candidate(*, kind: str = "source", response_hash: str | None = None) -> dict[str, object]:
    source = "src/app.ts:3" if kind == "source" else "response-ref-0123456789abcdef"
    return {
        "candidate_id": "0123456789abcdef0123",
        "redacted_fingerprint": "sha256-truncated:0123456789abcdef0123",
        "app": "example-app",
        "severity": "high",
        "confidence": "high",
        "rule_id": "WEB_EXAMPLE_RISK",
        "detector_subtype": "example_detector",
        "source_location": source,
        "location": {
            "kind": kind,
            "source": source,
            "body_or_header": None if kind == "source" else "body",
        },
        "response_hash": response_hash,
        "artifact_scope": "runtime_source",
        "scan_report_sha256": "a" * 64,
        "raw_returned": False,
    }


def _queue(candidate: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "k_guard_public_candidate_queue.v2",
        "candidates": [candidate],
        "raw_returned": False,
    }


def test_build_receipt_summarizes_source_and_response_contracts(tmp_path: Path) -> None:
    queue = _queue(_candidate(kind="response", response_hash="b" * 64))
    queue["candidates"].append(_candidate())
    queue["candidates"][1]["candidate_id"] = "fedcba9876543210fedc"
    queue["candidates"][1]["redacted_fingerprint"] = "sha256-truncated:fedcba9876543210fedc"
    path = tmp_path / "queue.json"
    path.write_text(json.dumps(queue), encoding="utf-8")

    receipt = build_receipt(path)

    assert receipt["summary"]["candidate_count"] == 2
    assert receipt["summary"]["response_hashed_count"] == 1
    assert receipt["summary"]["source_null_response_hash_count"] == 1
    assert receipt["raw_returned"] is False


@pytest.mark.parametrize(
    ("kind", "response_hash"),
    (("source", "a" * 64), ("response", None)),
)
def test_build_receipt_rejects_invalid_response_hash_relation(
    tmp_path: Path, kind: str, response_hash: str | None
) -> None:
    path = tmp_path / "queue.json"
    path.write_text(json.dumps(_queue(_candidate(kind=kind, response_hash=response_hash))), encoding="utf-8")

    with pytest.raises(ValueError, match="evidence shape"):
        build_receipt(path)


def test_write_receipt_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "queue.json"
    path.write_text(json.dumps(_queue(_candidate())), encoding="utf-8")
    receipt = build_receipt(path)
    output = tmp_path / "receipt.json"

    write_receipt(output, receipt)

    with pytest.raises(FileExistsError):
        write_receipt(output, receipt)
