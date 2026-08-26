from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "public" / "vulnerable-apps-12-20260713"
SPEC = importlib.util.spec_from_file_location(
    "public_app_effectiveness",
    ROOT / "scripts" / "public_app_effectiveness.py",
)
assert SPEC and SPEC.loader
public_app_effectiveness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_app_effectiveness)


def test_public_app_campaign_is_reproducible_but_not_effectiveness_qualified() -> None:
    status = public_app_effectiveness.build_status(EVIDENCE)

    assert status["integrity_passed"] is True
    assert status["qualified"] is False
    assert status["verdict"] == "hold"
    assert status["validation_errors"] == []
    assert status["metrics"] == {
        "app_count": 12,
        "exact_repeat_app_count": 12,
        "stratum_counts": {"long_tail": 4, "mid": 4, "top": 4},
        "candidate_count": 36,
        "candidate_label_counts": {"benign": 3, "false_positive": 17, "true_positive": 16},
        "strict_actionable_candidate_rate": 0.444444,
        "adjudicated_precision_tp_fp_only": 0.484848,
        "candidate_reviewer_count": 3,
        "reference_probe_count": 12,
        "reference_probe_detected": 0,
        "reference_probe_false_negative": 12,
        "reference_probe_detection_rate": 0.0,
        "reference_probe_reviewer_count": 3,
    }
    assert status["blockers"] == [
        "candidate_actionable_rate_below_0_80",
        "reference_probe_detection_rate_below_0_80",
    ]
    assert status["claim_boundary"]["not_owned_or_partner_field_evidence"] is True
    assert status["claim_boundary"]["independent_reviewers_are_ai_not_human"] is True


def test_public_app_campaign_fails_closed_when_a_label_loses_report_binding(tmp_path: Path) -> None:
    copied = tmp_path / "campaign"
    shutil.copytree(EVIDENCE, copied)
    labels_path = copied / "candidate-labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    labels["candidates"][0]["scan_report_sha256"] = "0" * 64
    labels_path.write_text(json.dumps(labels, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    status = public_app_effectiveness.build_status(copied)

    assert status["integrity_passed"] is False
    assert status["qualified"] is False
    assert "candidate_report_binding_invalid:3ad722c02a4338f5c9b6" in status["validation_errors"]
    assert "public_campaign_contract_invalid" in status["blockers"]
