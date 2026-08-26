from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.project_mutable_action_shadow import build_projection, write_projection

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_projection_keeps_prior_labels_separate_from_new_shadow_candidates(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "campaign"
    source_root = tmp_path / "sources"
    workflow = source_root / "demo" / ".github" / "workflows" / "ci.yml"
    campaign.mkdir()
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@master\n"
        "  release:\n"
        "    steps:\n"
        "      - uses: pypa/gh-action-pypi-publish@master\n"
        "  quoted:\n"
        "    steps:\n"
        "      - uses: \"example/action@main\"\n",
        encoding="utf-8",
    )
    queue_candidates = [
        {
            "app": "demo",
            "artifact_scope": "configuration",
            "candidate_id": "benign-1",
            "rule_id": "CONFIG_GHA_MUTABLE_ACTION_REF",
            "source_location": ".github/workflows/ci.yml:4",
        },
        {
            "app": "demo",
            "artifact_scope": "configuration",
            "candidate_id": "positive-1",
            "rule_id": "CONFIG_GHA_MUTABLE_ACTION_REF",
            "source_location": ".github/workflows/ci.yml:7",
        },
    ]
    _write_json(
        campaign / "candidate-queue.json",
        {"campaign_id": "fixture", "candidates": queue_candidates},
    )
    _write_json(
        campaign / "candidate-labels.json",
        {
            "candidates": [
                {"candidate_id": "benign-1", "label": "benign"},
                {"candidate_id": "positive-1", "label": "true_positive"},
            ]
        },
    )

    payload = build_projection(
        repo_root=ROOT,
        campaign_dir=campaign,
        source_root=source_root,
    )

    assert payload["shadow_confusion_on_prior_labels"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 1,
    }
    assert payload["new_unlabeled_candidate_count"] == 1
    assert payload["new_unlabeled_candidates"][0]["label"] == "unreviewed"
    assert payload["current_release_lane_contract"]["automatic_release_blocking"] is False
    assert payload["promotion_allowed"] is False
    assert all(
        row["default_release_lane"] != "release_blocking"
        for row in payload["rows"]
    )


def test_projection_refuses_to_overwrite_evidence(tmp_path: Path) -> None:
    output = tmp_path / "projection.json"
    output.write_text("{}\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_projection(output, {"schema": "fixture"})
