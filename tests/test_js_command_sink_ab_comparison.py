from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.compare_js_command_sink_resolution_ab import (
    EMPTY_SHA256,
    build_comparison,
    write_comparison,
)


def _app(app: str, count: int) -> dict:
    return {
        "app": app,
        "candidate_content_set_sha256": f"content-{app}",
        "candidate_path_set_sha256": f"paths-{app}",
        "supported_file_count": 3,
        "current_command_finding_count": count,
    }


def _row(
    candidate_id: str,
    label: str,
    detected: bool,
) -> dict:
    return {
        "candidate_id": candidate_id,
        "adjudicated_actionability_label": label,
        "detected": detected,
    }


def _projection(*, treatment: bool) -> dict:
    common = {
        "schema": "k_guard_js_command_sink_resolution_projection.v3",
        "raw_returned": False,
        "qualification_eligible": False,
        "release_gate_passed": False,
        "release_claim_allowed": False,
        "campaign_id": "fixture",
        "campaign_app_count": 2,
        "campaign_manifest_sha256": "campaign",
        "campaign_source_revision": "revision",
        "campaign_analyzer_package_tree_sha256": "baseline-package",
        "baseline_report_set_sha256": "baseline-reports",
        "source_queue_sha256": "queue",
        "source_labels_sha256": "labels",
        "target_source_set_sha256": "sources",
        "source_receipt_set_sha256": "receipts",
        "source_binding_count": 2,
        "projector_sha256": "projector",
        "pyproject_sha256": "pyproject",
        "evidence_hash_scheme": "scheme",
        "git_head": "head",
        "git_head_tree": "tree",
        "source_materialization": [{"app": "a"}, {"app": "b"}],
        "source_binding_contract_passed": True,
        "full_app_coverage_contract_passed": True,
        "exact_repeat_app_count": 2,
        "complete_coverage_app_count": 2,
        "exact_repeat": True,
        "current_analysis_limit_count": 0,
        "current_analysis_limit_contract_passed": True,
        "unmatched_current_candidate_count": 0,
        "rows": [
            _row("fp", "false_positive", not treatment),
            _row("tp", "true_positive", True),
        ],
    }
    if treatment:
        common.update(
            {
                "working_tree_package_sha256": "treatment-package",
                "working_tree_diff_sha256": "changed",
                "regression_probe_contract_passed": True,
                "current_full_universe_command_finding_count": 1,
                "app_scans": [_app("a", 1), _app("b", 0)],
                "unadjudicated_removed_baseline_count": 1,
                "unadjudicated_removed_baseline": [
                    {
                        "semantic_key": "a" * 64,
                        "raw_returned": False,
                    }
                ],
            }
        )
    else:
        common.update(
            {
                "working_tree_package_sha256": "control-package",
                "working_tree_diff_sha256": EMPTY_SHA256,
                "regression_probe_contract_passed": False,
                "current_full_universe_command_finding_count": 3,
                "app_scans": [_app("a", 3), _app("b", 0)],
                "unadjudicated_removed_baseline_count": 0,
                "unadjudicated_removed_baseline": [],
            }
        )
    return common


def _labels(label: str = "false_positive") -> dict:
    reviews = [
        {
            "reviewer": reviewer,
            "label": label,
            "raw_returned": False,
        }
        for reviewer in ("claude", "grok", "glm")
    ]
    return {
        "schema": "k_guard_js_command_supplemental_candidate_labels.v1",
        "raw_returned": False,
        "product_release_decision": "HOLD",
        "qualification_eligible": False,
        "release_gate_passed": False,
        "candidates": [
            {
                "semantic_key": "a" * 64,
                "label": label,
                "agreement": "unanimous",
                "reviews": reviews,
                "raw_returned": False,
            }
        ],
    }


def _write(path: Path, value: dict) -> Path:
    path.write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def test_same_head_ab_accepts_only_accounted_false_positive_removals(
    tmp_path: Path,
) -> None:
    payload = build_comparison(
        control_path=_write(
            tmp_path / "control.json",
            _projection(treatment=False),
        ),
        treatment_path=_write(
            tmp_path / "treatment.json",
            _projection(treatment=True),
        ),
        supplemental_labels_path=_write(
            tmp_path / "labels.json",
            _labels(),
        ),
    )

    assert payload["hypothesis_passed"] is True
    assert payload["removed_command_finding_count"] == 2
    assert payload["removed_false_positive_count"] == 2
    assert payload["known_true_positive_removed_count"] == 0
    assert payload["release_gate_passed"] is False
    assert payload["qualification_eligible"] is False


def test_same_head_ab_rejects_supplemental_true_positive_loss(
    tmp_path: Path,
) -> None:
    payload = build_comparison(
        control_path=_write(
            tmp_path / "control.json",
            _projection(treatment=False),
        ),
        treatment_path=_write(
            tmp_path / "treatment.json",
            _projection(treatment=True),
        ),
        supplemental_labels_path=_write(
            tmp_path / "labels.json",
            _labels("true_positive"),
        ),
    )

    assert payload["hypothesis_passed"] is False
    assert payload["known_true_positive_removed_count"] == 1
    assert payload["removed_non_false_positive_count"] == 1
    assert payload["supplemental_label_delta"][
        "all_removed_candidates_false_positive"
    ] is False


def test_same_head_ab_rejects_context_drift(tmp_path: Path) -> None:
    treatment = deepcopy(_projection(treatment=True))
    treatment["source_queue_sha256"] = "different"

    payload = build_comparison(
        control_path=_write(
            tmp_path / "control.json",
            _projection(treatment=False),
        ),
        treatment_path=_write(
            tmp_path / "treatment.json",
            treatment,
        ),
        supplemental_labels_path=_write(
            tmp_path / "labels.json",
            _labels(),
        ),
    )

    assert payload["hypothesis_passed"] is False
    assert payload["context_mismatches"] == ["source_queue_sha256"]


def test_same_head_ab_refuses_to_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "comparison.json"
    output.write_text("{}\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_comparison(output, {"schema": "fixture"})
