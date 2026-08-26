from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.replay_docker_lane import replay_docker_lane


def _labels(path: Path, candidates: list[dict]) -> Path:
    path.write_text(
        json.dumps(
            {
                "campaign_id": "fixture-campaign",
                "source_revision": "a" * 40,
                "candidates": candidates,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_docker_lane_replay_content_binds_and_holds_every_candidate(tmp_path: Path) -> None:
    apps = tmp_path / "apps"
    app_a = apps / "app-a"
    app_b = apps / "app-b"
    app_a.mkdir(parents=True)
    (app_b / "src").mkdir(parents=True)
    (app_a / "compose.yml").write_text(
        "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock:ro\nendpoint: unix:///var/run/docker.sock\n",
        encoding="utf-8",
    )
    (app_b / "src" / "DocumentationMarkdown.ts").write_text(
        "const guide = `Mount /var/run/docker.sock`;\n",
        encoding="utf-8",
    )
    labels = _labels(
        tmp_path / "labels.json",
        [
            {
                "app": "app-a",
                "candidate_id": "mount",
                "label": "true_positive",
                "rule_id": "CONFIG_DOCKER_SOCK",
                "source_location": "compose.yml:2",
            },
            {
                "app": "app-a",
                "candidate_id": "endpoint",
                "label": "benign",
                "rule_id": "CONFIG_DOCKER_SOCK",
                "source_location": "compose.yml:3",
            },
            {
                "app": "app-b",
                "candidate_id": "docs",
                "label": "inconclusive",
                "rule_id": "CONFIG_DOCKER_SOCK",
                "source_location": "src/DocumentationMarkdown.ts:1",
            },
        ],
    )

    result = replay_docker_lane(labels, apps)

    assert result["population"] == {
        "candidate_count": 3,
        "current_lane_counts": {"manual_review_hold": 3},
        "current_subtype_counts": {
            "docker_socket_api_endpoint": 1,
            "docker_socket_bind_mount": 1,
            "docker_socket_documentation": 1,
        },
        "frozen_label_counts": {
            "benign": 1,
            "inconclusive": 1,
            "true_positive": 1,
        },
    }
    assert all(result["checks"].values())
    assert result["claim_boundary"]["independent_post_fix_holdout"] is False
    assert result["claim_boundary"]["qualifies_release_blocking_policy"] is False
    assert all(row["current_release_blocks"] for row in result["rows"])
    assert "Mount /var/run/docker.sock" not in json.dumps(result)


def test_docker_lane_replay_fails_closed_when_frozen_location_disappears(tmp_path: Path) -> None:
    apps = tmp_path / "apps"
    app = apps / "app"
    app.mkdir(parents=True)
    (app / "compose.yml").write_text("services: {}\n", encoding="utf-8")
    labels = _labels(
        tmp_path / "labels.json",
        [
            {
                "app": "app",
                "candidate_id": "missing",
                "label": "true_positive",
                "rule_id": "CONFIG_DOCKER_SOCK",
                "source_location": "compose.yml:1",
            }
        ],
    )

    with pytest.raises(ValueError, match="expected one current Docker finding"):
        replay_docker_lane(labels, apps)
