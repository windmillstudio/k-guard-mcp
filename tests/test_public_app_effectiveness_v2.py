from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "public_app_effectiveness_v2",
    ROOT / "scripts" / "public_app_effectiveness_v2.py",
)
assert SPEC and SPEC.loader
effectiveness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(effectiveness)


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _evidence(root: Path) -> None:
    revision = "a" * 40
    reviewer_refs = [f"sha256:{digit * 64}" for digit in "123"]
    apps = []
    candidates = []
    labeled = []
    probes = []
    available = {}
    sampled = {}
    for index in range(12):
        app = f"app-{index}"
        report_hash = f"{index + 4:x}" * 64
        candidate_id = f"{index + 1:020x}"
        stratum = ("top", "mid", "long_tail")[index % 3]
        apps.append(
            {
                "app": app,
                "stratum": stratum,
                "commit": "b" * 40,
                "runs": [
                    {"run": 1, "exit_code": 0, "report_sha256": report_hash},
                    {"run": 2, "exit_code": 0, "report_sha256": report_hash},
                ],
                "exact_repeat": True,
            }
        )
        candidate = {
            "candidate_id": candidate_id,
            "redacted_fingerprint": f"sha256-truncated:{candidate_id}",
            "app": app,
            "severity": "high",
            "confidence": "high",
            "rule_id": "RULE",
            "detector_subtype": "test",
            "source_location": "app.py:10",
            "artifact_scope": "runtime_source",
            "scan_report_sha256": report_hash,
            "raw_returned": False,
        }
        candidates.append(candidate)
        labeled.append(
            {
                **candidate,
                "response_location": "not_applicable_static_source_scan",
                "http_response_sha256": None,
                "reviews": [
                    {
                        "reviewer_alias": f"reviewer-{review_index}",
                        "reviewer_ref": reviewer_ref,
                        "label": "true_positive",
                        "rationale": "Source and sink are directly connected.",
                    }
                    for review_index, reviewer_ref in enumerate(reviewer_refs)
                ],
                "label": "true_positive",
                "agreement": "unanimous",
            }
        )
        probes.append(
            {
                "probe_id": f"probe-{index}",
                "app": app,
                "oracle_classification": "true_positive",
                "detected": True,
                "result": "detected",
                "scan_report_sha256": report_hash,
                "raw_returned": False,
            }
        )
        available[app] = 1
        sampled[app] = 1

    _write(
        root / "campaign.json",
        {
            "schema": effectiveness.CAMPAIGN_SCHEMA,
            "campaign_id": "campaign",
            "source_revision": revision,
            "apps": apps,
            "raw_returned": False,
        },
    )
    _write(
        root / "candidate-queue.json",
        {
            "schema": effectiveness.QUEUE_SCHEMA,
            "campaign_id": "campaign",
            "source_revision": revision,
            "sampling": {"target_per_app": 3, "available_by_app": available, "sampled_by_app": sampled},
            "candidates": candidates,
            "raw_returned": False,
        },
    )
    _write(
        root / "candidate-labels.json",
        {
            "schema": effectiveness.LABEL_SCHEMA,
            "campaign_id": "campaign",
            "source_revision": revision,
            "reviewers": [
                {
                    "reviewer_alias": f"reviewer-{index}",
                    "reviewer_ref": reviewer_ref,
                    "reviewer_kind": "independent_codex_subagent",
                }
                for index, reviewer_ref in enumerate(reviewer_refs)
            ],
            "candidates": labeled,
            "raw_returned": False,
        },
    )
    _write(
        root / "reference-probes.json",
        {
            "schema": effectiveness.PROBE_SCHEMA,
            "campaign_id": "campaign",
            "source_revision": revision,
            "probes": probes,
            "raw_returned": False,
        },
    )


def test_v2_effectiveness_contract_passes_complete_reproducible_evidence(tmp_path: Path) -> None:
    _evidence(tmp_path)

    status = effectiveness.build_status(tmp_path)

    assert status["integrity_passed"] is True
    assert status["qualified"] is True
    assert status["metrics"]["candidate_actionable_rate"] == 1.0
    assert status["metrics"]["true_positive_probe_rate"] == 1.0


def test_v2_effectiveness_contract_fails_closed_on_report_rebinding(tmp_path: Path) -> None:
    _evidence(tmp_path)
    labels_path = tmp_path / "candidate-labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    labels["candidates"][0]["scan_report_sha256"] = "0" * 64
    _write(labels_path, labels)

    status = effectiveness.build_status(tmp_path)

    assert status["integrity_passed"] is False
    assert status["qualified"] is False
    assert "public_development_contract_invalid" in status["blockers"]
    assert any(error.startswith("candidate_label_binding_invalid:") for error in status["validation_errors"])
