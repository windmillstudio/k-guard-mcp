from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.project_release_actionability import project_labels


def test_projection_selects_only_current_automatic_rules_and_keeps_benign_in_denominator(
    tmp_path: Path,
) -> None:
    labels = tmp_path / "candidate-labels.json"
    labels.write_text(
        json.dumps(
            {
                "source_revision": "a" * 40,
                "candidates": [
                    {
                        "candidate_id": "tp",
                        "app": "one",
                        "rule_id": "CONFIG_DOCKER_SOCK",
                        "label": "true_positive",
                    },
                    {
                        "candidate_id": "benign",
                        "app": "two",
                        "rule_id": "CONFIG_CSP_UNSAFE_EVAL",
                        "label": "benign",
                    },
                    {
                        "candidate_id": "automatic-tp",
                        "app": "four",
                            "rule_id": "AUTH_JWT_DECODE_WITHOUT_VERIFY",
                        "label": "true_positive",
                    },
                    {
                        "candidate_id": "manual",
                        "app": "three",
                        "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                        "label": "true_positive",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    result = project_labels(labels)

    assert result["population"]["candidate_count"] == 2
    assert result["population"]["candidate_label_counts"] == {
        "true_positive": 1,
        "false_positive": 0,
        "benign": 1,
        "inconclusive": 0,
    }
    assert result["metrics"]["automatic_block_actionability"] == 0.5
    assert result["metrics"]["automatic_block_actionability_wilson_95_lower"] == 0.094531
    assert result["claim_boundary"]["independent_post_fix_holdout"] is False


def test_projection_fails_closed_on_unknown_label(tmp_path: Path) -> None:
    labels = tmp_path / "candidate-labels.json"
    labels.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "unknown",
                        "app": "one",
                        "rule_id": "CONFIG_DOCKER_SOCK",
                        "label": "maybe",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported candidate label"):
        project_labels(labels)
