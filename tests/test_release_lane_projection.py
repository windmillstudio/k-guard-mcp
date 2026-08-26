from __future__ import annotations

import json
from pathlib import Path

from scripts.project_release_lanes import project_reports


def _finding(rule_id: str, confidence: str = "high") -> dict:
    return {
        "rule_id": rule_id,
        "severity": "high",
        "confidence": confidence,
        "artifact_scope": "runtime_source",
    }


def test_projection_preserves_legacy_holds_and_separates_actionability(tmp_path: Path) -> None:
    reports = tmp_path / "campaign" / "reports"
    reports.mkdir(parents=True)
    payload = {
        "findings": [
            _finding("WEB_UNTRUSTED_INPUT_TO_COMMAND"),
            _finding("WEB_UNTRUSTED_INPUT_TO_FILE_PATH", "medium"),
            _finding("STATIC_ANALYSIS_LIMIT_REACHED"),
            {
                **_finding("MCP_EXFILTRATION_INTENT"),
                "artifact_scope": "documentation",
            },
        ]
    }
    (reports / "demo-run1.json").write_text(json.dumps(payload), encoding="utf-8")

    result = project_reports(reports)

    assert result["population"]["high_critical_finding_count"] == 4
    assert result["population"]["lane_counts"] == {
        "manual_review_hold": 1,
        "policy_integrity_hold": 1,
        "release_blocking": 1,
        "supporting_review": 1,
    }
    assert result["legacy_comparison"] == {
        "legacy_blocking_count": 3,
        "current_hold_count": 3,
        "legacy_blockers_lost_count": 0,
        "legacy_blockers_lost_rule_counts": {},
        "newly_held_count": 0,
        "newly_held_rule_counts": {},
    }
    assert result["checks"] == {
        "every_high_critical_finding_assigned_once": True,
        "no_legacy_blocker_dropped": True,
    }
    assert result["claim_boundary"]["proves_detection_precision"] is False
