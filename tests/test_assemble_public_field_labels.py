from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.assemble_public_field_labels import build_labels, candidate_bindings_sha256


def _write(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _queue() -> dict[str, object]:
    return {
        "schema": "k_guard_public_field_candidate_queue.v1",
        "campaign_id": "campaign",
        "source_revision": "a" * 40,
        "analyzer_package_tree_sha256": "b" * 64,
        "holdout_protocol_manifest_sha256": "d" * 64,
        "candidates": [
            {
                "candidate_id": "0123456789abcdef0123",
                "redacted_fingerprint": "sha256-truncated:0123456789abcdef0123",
                "app": "app",
                "severity": "high",
                "confidence": "high",
                "rule_id": "RULE",
                "detector_subtype": "subtype",
                "source_location": "app.py:1",
                "artifact_scope": "runtime_source",
                "scan_report_sha256": "c" * 64,
                "response_hash": None,
                "location": {
                    "kind": "source",
                    "source": "app.py:1",
                    "body_or_header": None,
                },
                "raw_returned": False,
            }
        ],
        "raw_returned": False,
    }


def _review(
    root: Path,
    queue_path: Path,
    alias: str,
    vendor: str,
    label: str,
) -> dict[str, object]:
    queue_payload = json.loads(queue_path.read_text(encoding="utf-8"))
    queue_rows = queue_payload["candidates"]
    binding_hash = candidate_bindings_sha256(queue_rows)
    candidate_id = queue_rows[0]["candidate_id"]
    prompt = root / "review-prompt.txt"
    prompt.write_text("Review every bound candidate.", encoding="utf-8")
    response = root / f"{alias}-response.json"
    response.write_text(
        json.dumps({"session_id": f"session-{alias}", "response_id": f"response-{alias}"}),
        encoding="utf-8",
    )
    return {
        "schema": "k_guard_public_field_independent_review.v2",
        "campaign_id": "campaign",
        "source_revision": "a" * 40,
        "analyzer_package_tree_sha256": "b" * 64,
        "holdout_protocol_manifest_sha256": "d" * 64,
        "reviewer_alias": alias,
        "reviewer_kind": "external_ai_source_context_review",
        "vendor": vendor,
        "model": f"{vendor}-test-model",
        "session_id": f"session-{alias}",
        "response_id": f"response-{alias}",
        "prompt_artifact_path": prompt.name,
        "prompt_sha256": hashlib.sha256(prompt.read_bytes()).hexdigest(),
        "response_artifact_path": response.name,
        "response_sha256": hashlib.sha256(response.read_bytes()).hexdigest(),
        "candidate_queue_sha256": hashlib.sha256(queue_path.read_bytes()).hexdigest(),
        "candidate_bindings_sha256": binding_hash,
        "candidates": [{"candidate_id": candidate_id, "label": label, "rationale": f"reason-{alias}"}],
        "raw_returned": False,
    }


def test_build_labels_binds_queue_fields_and_majority(tmp_path: Path) -> None:
    queue = _write(tmp_path / "queue.json", _queue())
    reviews = [
        _write(tmp_path / f"{alias}.json", _review(tmp_path, queue, alias, vendor, label))
        for alias, vendor, label in (
            ("a", "openai", "true_positive"),
            ("b", "anthropic", "true_positive"),
            ("c", "xai", "false_positive"),
        )
    ]

    payload = build_labels(queue, reviews)

    assert payload["candidates"][0]["label"] == "true_positive"
    assert payload["candidates"][0]["agreement"] == "majority"
    assert payload["candidates"][0]["rule_id"] == "RULE"
    assert len({row["reviewer_ref"] for row in payload["reviewers"]}) == 3
    assert payload["review_provenance"]["not_human_review"] is True
    assert payload["review_provenance"]["required_vendors"] == ["anthropic", "openai", "xai"]
    assert payload["review_provenance"]["cross_vendor_review"] is True


def test_build_labels_rejects_incomplete_review(tmp_path: Path) -> None:
    queue = _write(tmp_path / "queue.json", _queue())
    review = _review(tmp_path, queue, "a", "openai", "true_positive")
    review["candidates"] = []
    reviews = [
        _write(tmp_path / "a.json", review),
        _write(tmp_path / "b.json", _review(tmp_path, queue, "b", "anthropic", "true_positive")),
        _write(tmp_path / "c.json", _review(tmp_path, queue, "c", "xai", "true_positive")),
    ]

    with pytest.raises(ValueError, match="coverage"):
        build_labels(queue, reviews)


def test_build_labels_rejects_review_from_different_candidate_binding(tmp_path: Path) -> None:
    queue = _write(tmp_path / "queue.json", _queue())
    mismatched = _review(tmp_path, queue, "a", "openai", "true_positive")
    mismatched["candidate_bindings_sha256"] = "0" * 64
    reviews = [
        _write(tmp_path / "a.json", mismatched),
        _write(tmp_path / "b.json", _review(tmp_path, queue, "b", "anthropic", "true_positive")),
        _write(tmp_path / "c.json", _review(tmp_path, queue, "c", "xai", "true_positive")),
    ]

    with pytest.raises(ValueError, match="candidate binding"):
        build_labels(queue, reviews)


def test_build_labels_rejects_review_from_a_different_campaign(tmp_path: Path) -> None:
    queue = _write(tmp_path / "queue.json", _queue())
    mismatched = _review(tmp_path, queue, "a", "openai", "true_positive")
    mismatched["campaign_id"] = "other-campaign"
    reviews = [
        _write(tmp_path / "a.json", mismatched),
        _write(tmp_path / "b.json", _review(tmp_path, queue, "b", "anthropic", "true_positive")),
        _write(tmp_path / "c.json", _review(tmp_path, queue, "c", "xai", "true_positive")),
    ]

    with pytest.raises(ValueError, match="campaign binding"):
        build_labels(queue, reviews)


def test_build_labels_rejects_duplicate_vendor_or_tampered_response(tmp_path: Path) -> None:
    queue = _write(tmp_path / "queue.json", _queue())
    reviews = [
        _write(tmp_path / "a.json", _review(tmp_path, queue, "a", "openai", "true_positive")),
        _write(tmp_path / "b.json", _review(tmp_path, queue, "b", "openai", "true_positive")),
        _write(tmp_path / "c.json", _review(tmp_path, queue, "c", "xai", "true_positive")),
    ]
    with pytest.raises(ValueError, match="reviewer identity"):
        build_labels(queue, reviews)

    reviews[1] = _write(
        tmp_path / "b.json",
        _review(tmp_path, queue, "b", "anthropic", "true_positive"),
    )
    (tmp_path / "b-response.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact hash"):
        build_labels(queue, reviews)


def test_candidate_bindings_include_response_evidence() -> None:
    source_candidate = _queue()["candidates"]
    response_candidate = json.loads(json.dumps(source_candidate))
    response_candidate[0]["location"] = {
        "kind": "response",
        "source": "response-ref-0123456789abcdef",
        "body_or_header": "body",
    }
    response_candidate[0]["response_hash"] = "a" * 64

    assert candidate_bindings_sha256(source_candidate) != candidate_bindings_sha256(response_candidate)


def test_build_labels_rejects_response_candidate_without_hash(tmp_path: Path) -> None:
    queue_payload = _queue()
    queue_payload["candidates"][0]["location"] = {
        "kind": "response",
        "source": "response-ref-0123456789abcdef",
        "body_or_header": "header",
    }
    queue = _write(tmp_path / "queue.json", queue_payload)
    with pytest.raises(ValueError, match="response hash"):
        build_labels(queue, [tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"])
