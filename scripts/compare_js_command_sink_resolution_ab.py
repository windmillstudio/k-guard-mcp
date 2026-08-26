from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


PROJECTION_SCHEMA = "k_guard_js_command_sink_resolution_projection.v3"
LABEL_SCHEMA = "k_guard_js_command_supplemental_candidate_labels.v1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
CONTEXT_FIELDS = (
    "campaign_id",
    "campaign_app_count",
    "campaign_manifest_sha256",
    "campaign_source_revision",
    "campaign_analyzer_package_tree_sha256",
    "baseline_report_set_sha256",
    "source_queue_sha256",
    "source_labels_sha256",
    "target_source_set_sha256",
    "source_receipt_set_sha256",
    "source_binding_count",
    "projector_sha256",
    "pyproject_sha256",
    "evidence_hash_scheme",
    "git_head",
    "git_head_tree",
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _wilson_lower(
    successes: int,
    total: int,
    z: float = 1.959963984540054,
) -> float:
    if total <= 0:
        return 0.0
    proportion = successes / total
    denominator = 1 + z * z / total
    center = proportion + z * z / (2 * total)
    margin = z * math.sqrt(
        (
            proportion * (1 - proportion)
            + z * z / (4 * total)
        )
        / total
    )
    return (center - margin) / denominator


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return payload


def _unique_rows(
    rows: list[dict[str, Any]],
    key: str,
    *,
    label: str,
) -> dict[str, dict[str, Any]]:
    values = [str(row.get(key) or "") for row in rows]
    if not values or not all(values) or len(values) != len(set(values)):
        raise ValueError(f"{label} contains missing or duplicate {key}")
    return {
        value: row
        for value, row in zip(values, rows, strict=True)
    }


def _validate_projection(
    payload: dict[str, Any],
    *,
    label: str,
) -> None:
    if payload.get("schema") != PROJECTION_SCHEMA:
        raise ValueError(f"{label} projection schema invalid")
    if payload.get("raw_returned") is not False:
        raise ValueError(f"{label} projection redaction contract invalid")
    if payload.get("qualification_eligible") is not False:
        raise ValueError(f"{label} projection overclaims qualification")
    if payload.get("release_gate_passed") is not False:
        raise ValueError(f"{label} projection overclaims release")
    if payload.get("release_claim_allowed") is not False:
        raise ValueError(f"{label} projection overclaims release authority")


def _validate_labels(payload: dict[str, Any]) -> None:
    if payload.get("schema") != LABEL_SCHEMA:
        raise ValueError("supplemental label schema invalid")
    if payload.get("raw_returned") is not False:
        raise ValueError("supplemental label redaction contract invalid")
    if payload.get("product_release_decision") != "HOLD":
        raise ValueError("supplemental labels must keep product HOLD")
    if payload.get("qualification_eligible") is not False:
        raise ValueError("supplemental labels overclaim qualification")
    if payload.get("release_gate_passed") is not False:
        raise ValueError("supplemental labels overclaim release")


def _app_contract(
    control: dict[str, Any],
    treatment: dict[str, Any],
) -> tuple[bool, list[dict[str, Any]], int, int]:
    control_apps = _unique_rows(
        list(control.get("app_scans", [])),
        "app",
        label="control app scans",
    )
    treatment_apps = _unique_rows(
        list(treatment.get("app_scans", [])),
        "app",
        label="treatment app scans",
    )
    if set(control_apps) != set(treatment_apps):
        raise ValueError("control/treatment app sets differ")

    deltas: list[dict[str, Any]] = []
    source_identity_passed = True
    removed = 0
    added = 0
    for app in sorted(control_apps):
        control_row = control_apps[app]
        treatment_row = treatment_apps[app]
        source_identity_passed = source_identity_passed and all(
            control_row.get(field) == treatment_row.get(field)
            for field in (
                "candidate_content_set_sha256",
                "candidate_path_set_sha256",
                "supported_file_count",
            )
        )
        control_count = int(
            control_row.get("current_command_finding_count") or 0
        )
        treatment_count = int(
            treatment_row.get("current_command_finding_count") or 0
        )
        delta = treatment_count - control_count
        if delta:
            deltas.append(
                {
                    "app": app,
                    "control_command_finding_count": control_count,
                    "treatment_command_finding_count": treatment_count,
                    "delta": delta,
                    "raw_returned": False,
                }
            )
        removed += max(0, -delta)
        added += max(0, delta)
    return source_identity_passed, deltas, removed, added


def _existing_label_delta(
    control: dict[str, Any],
    treatment: dict[str, Any],
) -> dict[str, Any]:
    control_rows = _unique_rows(
        list(control.get("rows", [])),
        "candidate_id",
        label="control candidate rows",
    )
    treatment_rows = _unique_rows(
        list(treatment.get("rows", [])),
        "candidate_id",
        label="treatment candidate rows",
    )
    if set(control_rows) != set(treatment_rows):
        raise ValueError("control/treatment adjudicated candidate sets differ")

    outcome_counts: Counter[str] = Counter()
    removed_false_positive_ids: list[str] = []
    removed_non_false_positive_ids: list[str] = []
    retained_true_positive_ids: list[str] = []
    control_all_detected = True
    for candidate_id in sorted(control_rows):
        control_row = control_rows[candidate_id]
        treatment_row = treatment_rows[candidate_id]
        if (
            control_row.get("adjudicated_actionability_label")
            != treatment_row.get("adjudicated_actionability_label")
        ):
            raise ValueError(
                f"candidate label changed between arms: {candidate_id}"
            )
        control_detected = control_row.get("detected") is True
        treatment_detected = treatment_row.get("detected") is True
        control_all_detected = control_all_detected and control_detected
        label = str(
            treatment_row.get("adjudicated_actionability_label") or ""
        )
        if control_detected and not treatment_detected:
            if label == "false_positive":
                removed_false_positive_ids.append(candidate_id)
                outcome_counts["false_positive_removed"] += 1
            else:
                removed_non_false_positive_ids.append(candidate_id)
                outcome_counts[f"{label or 'missing'}_removed"] += 1
        elif control_detected and treatment_detected:
            outcome_counts[f"{label}_retained"] += 1
            if label == "true_positive":
                retained_true_positive_ids.append(candidate_id)
        elif treatment_detected:
            outcome_counts[f"{label}_added"] += 1

    return {
        "control_all_prior_candidates_detected": control_all_detected,
        "candidate_count": len(control_rows),
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "removed_false_positive_candidate_ids": (
            removed_false_positive_ids
        ),
        "removed_non_false_positive_candidate_ids": (
            removed_non_false_positive_ids
        ),
        "retained_true_positive_candidate_ids": (
            retained_true_positive_ids
        ),
        "raw_returned": False,
    }


def _supplemental_label_delta(
    treatment: dict[str, Any],
    labels: dict[str, Any],
) -> dict[str, Any]:
    removed_rows = _unique_rows(
        list(treatment.get("unadjudicated_removed_baseline", [])),
        "semantic_key",
        label="treatment supplemental removals",
    )
    label_rows = _unique_rows(
        list(labels.get("candidates", [])),
        "semantic_key",
        label="supplemental labels",
    )
    if set(removed_rows) != set(label_rows):
        raise ValueError(
            "supplemental labels do not match treatment removals"
        )

    label_counts = Counter(
        str(row.get("label") or "")
        for row in label_rows.values()
    )
    all_unanimous = all(
        row.get("agreement") == "unanimous"
        and len(row.get("reviews", [])) == 3
        and len(
            {
                str(review.get("label") or "")
                for review in row.get("reviews", [])
            }
        )
        == 1
        and str(row.get("label") or "")
        == str(row.get("reviews", [{}])[0].get("label") or "")
        for row in label_rows.values()
    )
    all_false_positive = (
        label_counts == Counter({"false_positive": len(label_rows)})
    )
    return {
        "candidate_count": len(label_rows),
        "label_counts": dict(sorted(label_counts.items())),
        "all_reviewer_labels_unanimous": all_unanimous,
        "all_removed_candidates_false_positive": all_false_positive,
        "candidate_set_sha256": _canonical_sha256(
            sorted(label_rows)
        ),
        "raw_returned": False,
    }


def build_comparison(
    *,
    control_path: Path,
    treatment_path: Path,
    supplemental_labels_path: Path,
) -> dict[str, Any]:
    control = _load_json(control_path)
    treatment = _load_json(treatment_path)
    labels = _load_json(supplemental_labels_path)
    _validate_projection(control, label="control")
    _validate_projection(treatment, label="treatment")
    _validate_labels(labels)

    context_mismatches = [
        field
        for field in CONTEXT_FIELDS
        if control.get(field) != treatment.get(field)
    ]
    same_context = not context_mismatches
    source_materialization_same = (
        _canonical_sha256(control.get("source_materialization"))
        == _canonical_sha256(treatment.get("source_materialization"))
    )
    source_identity_passed, app_deltas, removed_count, added_count = (
        _app_contract(control, treatment)
    )
    existing = _existing_label_delta(control, treatment)
    supplemental = _supplemental_label_delta(treatment, labels)

    campaign_app_count = int(control.get("campaign_app_count") or 0)
    coverage_contract = all(
        projection.get("source_binding_contract_passed") is True
        and projection.get("full_app_coverage_contract_passed") is True
        and int(projection.get("exact_repeat_app_count") or 0)
        == campaign_app_count
        and int(projection.get("complete_coverage_app_count") or 0)
        == campaign_app_count
        and projection.get("exact_repeat") is True
        and int(projection.get("current_analysis_limit_count") or 0)
        == 0
        and projection.get("current_analysis_limit_contract_passed")
        is True
        and int(projection.get("unmatched_current_candidate_count") or 0)
        == 0
        for projection in (control, treatment)
    )
    control_count = int(
        control.get("current_full_universe_command_finding_count") or 0
    )
    treatment_count = int(
        treatment.get("current_full_universe_command_finding_count") or 0
    )
    total_delta = control_count - treatment_count
    existing_removed = len(
        existing["removed_false_positive_candidate_ids"]
    )
    existing_removed_non_false_positive = len(
        existing["removed_non_false_positive_candidate_ids"]
    )
    supplemental_removed = int(supplemental["candidate_count"])
    supplemental_false_positive = int(
        supplemental["label_counts"].get("false_positive", 0)
    )
    supplemental_non_false_positive = (
        supplemental_removed - supplemental_false_positive
    )
    delta_accounted = bool(
        added_count == 0
        and removed_count == total_delta
        and total_delta
        == (
            existing_removed
            + existing_removed_non_false_positive
            + supplemental_removed
        )
    )
    package_delta_present = bool(
        control.get("working_tree_package_sha256")
        != treatment.get("working_tree_package_sha256")
        and control.get("working_tree_diff_sha256") == EMPTY_SHA256
        and treatment.get("working_tree_diff_sha256") != EMPTY_SHA256
    )
    probe_contract = bool(
        control.get("regression_probe_contract_passed") is False
        and treatment.get("regression_probe_contract_passed") is True
    )
    known_tp_retained = len(
        existing["retained_true_positive_candidate_ids"]
    )
    known_tp_removed = sum(
        count
        for outcome, count in existing["outcome_counts"].items()
        if outcome == "true_positive_removed"
    ) + int(
        supplemental["label_counts"].get("true_positive", 0)
    )
    known_tp_total = known_tp_retained + known_tp_removed
    removal_correctness = (
        (existing_removed + supplemental_false_positive) / total_delta
        if total_delta > 0
        else 0.0
    )
    removal_wilson = _wilson_lower(
        existing_removed + supplemental_false_positive,
        total_delta,
    )
    known_tp_retention = (
        known_tp_retained / known_tp_total
        if known_tp_total > 0
        else 0.0
    )
    known_tp_wilson = _wilson_lower(
        known_tp_retained,
        known_tp_total,
    )

    hypothesis_passed = bool(
        same_context
        and source_materialization_same
        and source_identity_passed
        and coverage_contract
        and package_delta_present
        and probe_contract
        and existing["control_all_prior_candidates_detected"]
        and not existing["removed_non_false_positive_candidate_ids"]
        and supplemental["all_reviewer_labels_unanimous"]
        and supplemental["all_removed_candidates_false_positive"]
        and int(control.get("unadjudicated_removed_baseline_count") or 0)
        == 0
        and int(treatment.get("unadjudicated_removed_baseline_count") or 0)
        == supplemental_removed
        and delta_accounted
        and known_tp_retained > 0
        and known_tp_removed == 0
    )

    return {
        "schema": "k_guard_js_command_sink_same_head_ab.v1",
        "evidence_use": "same_head_exposed_development_ab",
        "hypothesis": (
            "Import-aware JS/TS command receiver resolution removes only "
            "non-process .exec false positives while retaining known process "
            "command findings."
        ),
        "control_projection_sha256": _sha256_file(control_path),
        "treatment_projection_sha256": _sha256_file(treatment_path),
        "supplemental_labels_sha256": _sha256_file(
            supplemental_labels_path
        ),
        "comparator_sha256": _sha256_file(Path(__file__).resolve()),
        "shared_git_head": control.get("git_head"),
        "shared_git_head_tree": control.get("git_head_tree"),
        "control_working_tree_package_sha256": control.get(
            "working_tree_package_sha256"
        ),
        "treatment_working_tree_package_sha256": treatment.get(
            "working_tree_package_sha256"
        ),
        "context_fields_checked": list(CONTEXT_FIELDS),
        "context_mismatches": context_mismatches,
        "same_context_contract_passed": same_context,
        "source_materialization_same": source_materialization_same,
        "source_inventory_contract_passed": source_identity_passed,
        "coverage_repeat_limit_contract_passed": coverage_contract,
        "package_delta_contract_passed": package_delta_present,
        "regression_probe_discrimination_passed": probe_contract,
        "campaign_app_count": campaign_app_count,
        "control_command_finding_count": control_count,
        "treatment_command_finding_count": treatment_count,
        "removed_command_finding_count": removed_count,
        "added_command_finding_count": added_count,
        "app_deltas": app_deltas,
        "existing_label_delta": existing,
        "supplemental_label_delta": supplemental,
        "delta_fully_accounted": delta_accounted,
        "removed_false_positive_count": (
            existing_removed + supplemental_false_positive
        ),
        "removed_non_false_positive_count": (
            existing_removed_non_false_positive
            + supplemental_non_false_positive
        ),
        "known_true_positive_retained_count": known_tp_retained,
        "known_true_positive_removed_count": known_tp_removed,
        "removed_candidate_correctness": round(
            removal_correctness,
            6,
        ),
        "removed_candidate_correctness_wilson_95_lower": round(
            removal_wilson,
            6,
        ),
        "known_true_positive_retention": round(
            known_tp_retention,
            6,
        ),
        "known_true_positive_retention_wilson_95_lower": round(
            known_tp_wilson,
            6,
        ),
        "hypothesis_passed": hypothesis_passed,
        "qualification_eligible": False,
        "release_gate_passed": False,
        "release_claim_allowed": False,
        "release_gate_blockers": [
            (
                "The 41-app corpus and all candidate labels are exposed "
                "development evidence, not a fresh unseen holdout."
            ),
            (
                "Seven correct removals have a Wilson 95% lower bound below "
                "the locked 80% promotion floor."
            ),
            (
                "Only one known true-positive command candidate is present, "
                "which cannot qualify product recall."
            ),
            (
                "Product-wide precision, High/Critical recall, specificity, "
                "runtime, and independent holdout thresholds remain open."
            ),
        ],
        "raw_returned": False,
    }


def write_comparison(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite comparison: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--treatment", type=Path, required=True)
    parser.add_argument(
        "--supplemental-labels",
        type=Path,
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    payload = build_comparison(
        control_path=arguments.control.resolve(),
        treatment_path=arguments.treatment.resolve(),
        supplemental_labels_path=(
            arguments.supplemental_labels.resolve()
        ),
    )
    write_comparison(arguments.output.resolve(), payload)
    print(
        json.dumps(
            {
                "output": str(arguments.output.resolve()),
                "removed_command_finding_count": payload[
                    "removed_command_finding_count"
                ],
                "removed_false_positive_count": payload[
                    "removed_false_positive_count"
                ],
                "known_true_positive_removed_count": payload[
                    "known_true_positive_removed_count"
                ],
                "hypothesis_passed": payload["hypothesis_passed"],
                "qualification_eligible": payload[
                    "qualification_eligible"
                ],
                "release_gate_passed": payload[
                    "release_gate_passed"
                ],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
