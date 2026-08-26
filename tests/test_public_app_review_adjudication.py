from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "adjudicate_public_app_reviews",
    ROOT / "scripts" / "adjudicate_public_app_reviews.py",
)
assert SPEC and SPEC.loader
adjudicator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adjudicator)


def _queue() -> dict:
    return {
        "schema": adjudicator.QUEUE_SCHEMA,
        "campaign_id": "campaign",
        "source_revision": "a" * 40,
        "candidates": [
            {
                "candidate_id": candidate_id,
                "redacted_fingerprint": f"sha256-truncated:{candidate_id}",
                "app": "demo",
                "severity": "high",
                "confidence": "high",
                "rule_id": "RULE",
                "detector_subtype": "test",
                "source_location": f"app.py:{line}",
                "artifact_scope": "runtime_source",
                "scan_report_sha256": "b" * 64,
                "raw_returned": False,
            }
            for candidate_id, line in (("1" * 20, 10), ("2" * 20, 20))
        ],
    }


def _review(alias: str, first: str, second: str) -> dict:
    return {
        "reviewer_alias": alias,
        "method": "independent_source_context_review",
        "labels": [
            {"candidate_id": "1" * 20, "label": first, "rationale": f"{alias} inspected candidate one."},
            {"candidate_id": "2" * 20, "label": second, "rationale": f"{alias} inspected candidate two."},
        ],
        "systemic_findings": [],
        "verdict": "NO_GO",
    }


def test_three_reviews_are_preserved_and_majority_adjudicated() -> None:
    labels = adjudicator.build_labels(
        _queue(),
        [
            _review("atlas", "true_positive", "false_positive"),
            _review("borealis", "true_positive", "benign"),
            _review("curie", "false_positive", "inconclusive"),
        ],
    )

    assert labels["metrics"] == {
        "candidate_count": 2,
        "label_counts": {"inconclusive": 1, "true_positive": 1},
        "agreement_counts": {"majority": 1, "no_consensus": 1},
    }
    first, second = labels["candidates"]
    assert first["label"] == "true_positive"
    assert first["agreement"] == "majority"
    assert len(first["reviews"]) == 3
    assert second["label"] == "inconclusive"
    assert labels["claim_boundary"]["not_cross_vendor_validation"] is True


def test_review_missing_a_candidate_fails_closed() -> None:
    incomplete = _review("atlas", "true_positive", "false_positive")
    incomplete["labels"].pop()

    with pytest.raises(ValueError, match="review candidates missing"):
        adjudicator.build_labels(
            _queue(),
            [incomplete, _review("borealis", "true_positive", "benign"), _review("curie", "true_positive", "benign")],
        )


def test_duplicate_reviewer_alias_fails_closed() -> None:
    with pytest.raises(ValueError, match="reviewer alias invalid"):
        adjudicator.build_labels(
            _queue(),
            [
                _review("atlas", "true_positive", "benign"),
                _review("atlas", "true_positive", "benign"),
                _review("curie", "true_positive", "benign"),
            ],
        )
