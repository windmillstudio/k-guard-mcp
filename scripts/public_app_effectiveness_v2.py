from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


CAMPAIGN_SCHEMA = "k_guard_public_app_campaign.v2"
QUEUE_SCHEMA = "k_guard_public_candidate_queue.v2"
LABEL_SCHEMA = "k_guard_public_candidate_labels.v2"
PROBE_SCHEMA = "k_guard_public_reference_probe_run.v2"
STATUS_SCHEMA = "k_guard_public_effectiveness_status.v2"
ALLOWED_LABELS = {"true_positive", "false_positive", "benign", "inconclusive"}
ALLOWED_AGREEMENTS = {"unanimous", "majority", "no_consensus"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REVIEWER_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^sha256-truncated:[0-9a-f]{20}$")

MIN_APP_COUNT = 12
MIN_REVIEWERS = 3
MIN_ACTIONABLE_RATE = 0.80
MIN_ADJUDICATED_PRECISION = 0.90
MIN_UNANIMOUS_RATE = 0.75
MIN_TRUE_POSITIVE_PROBE_RATE = 0.90


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _majority(reviews: list[dict[str, Any]]) -> tuple[str, str]:
    counts = Counter(str(row.get("label") or "") for row in reviews)
    if not counts:
        return "inconclusive", "no_consensus"
    label, votes = counts.most_common(1)[0]
    if votes < 2 or list(counts.values()).count(votes) > 1:
        return "inconclusive", "no_consensus"
    return label, "unanimous" if votes == len(reviews) else "majority"


def build_status(evidence_dir: Path) -> dict[str, Any]:
    campaign = _read_json(evidence_dir / "campaign.json")
    queue = _read_json(evidence_dir / "candidate-queue.json")
    labels = _read_json(evidence_dir / "candidate-labels.json")
    probes = _read_json(evidence_dir / "reference-probes.json")
    errors: list[str] = []

    expected_schemas = (
        (campaign, CAMPAIGN_SCHEMA, "campaign"),
        (queue, QUEUE_SCHEMA, "candidate_queue"),
        (labels, LABEL_SCHEMA, "candidate_labels"),
        (probes, PROBE_SCHEMA, "reference_probes"),
    )
    for payload, schema, label in expected_schemas:
        if payload.get("schema") != schema:
            errors.append(f"{label}_schema_invalid")
        if payload.get("raw_returned") is not False:
            errors.append(f"{label}_raw_boundary_invalid")

    campaign_ids = {str(payload.get("campaign_id") or "") for payload, _, _ in expected_schemas}
    if len(campaign_ids) != 1 or not next(iter(campaign_ids), ""):
        errors.append("campaign_binding_invalid")
    revisions = {str(payload.get("source_revision") or "") for payload, _, _ in expected_schemas}
    if len(revisions) != 1 or REVISION_RE.fullmatch(next(iter(revisions), "")) is None:
        errors.append("source_revision_binding_invalid")
    source_revision = next(iter(revisions), "")

    app_rows = campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    if not app_rows:
        errors.append("apps_invalid")
    app_names: set[str] = set()
    report_hashes: dict[str, str] = {}
    strata = Counter()
    exact_repeat_count = 0
    for row in app_rows:
        if not isinstance(row, dict):
            errors.append("app_row_invalid")
            continue
        app = str(row.get("app") or "")
        if not app or app in app_names:
            errors.append(f"app_identity_invalid:{app or 'missing'}")
            continue
        app_names.add(app)
        stratum = str(row.get("stratum") or "")
        if stratum not in {"top", "mid", "long_tail"}:
            errors.append(f"app_stratum_invalid:{app}")
        else:
            strata[stratum] += 1
        if REVISION_RE.fullmatch(str(row.get("commit") or "")) is None:
            errors.append(f"app_commit_invalid:{app}")
        runs = row.get("runs") if isinstance(row.get("runs"), list) else []
        run_hashes = [str(run.get("report_sha256") or "") for run in runs if isinstance(run, dict)]
        run_exits = [run.get("exit_code") for run in runs if isinstance(run, dict)]
        if len(runs) < 2 or len(run_hashes) != len(runs):
            errors.append(f"repeat_run_missing:{app}")
        elif any(SHA256_RE.fullmatch(value) is None for value in run_hashes):
            errors.append(f"repeat_hash_invalid:{app}")
        elif len(set(run_hashes)) != 1:
            errors.append(f"repeat_hash_mismatch:{app}")
        else:
            report_hashes[app] = run_hashes[0]
        if len(run_exits) != len(runs) or any(value != 0 for value in run_exits):
            errors.append(f"repeat_execution_failed:{app}")
        if row.get("exact_repeat") is True and len(set(run_hashes)) == 1 and run_hashes:
            exact_repeat_count += 1
        else:
            errors.append(f"exact_repeat_invalid:{app}")
    if len(app_names) < MIN_APP_COUNT:
        errors.append("app_count_below_minimum")
    for required in ("top", "mid", "long_tail"):
        if not strata[required]:
            errors.append(f"stratum_missing:{required}")

    queue_rows = queue.get("candidates") if isinstance(queue.get("candidates"), list) else []
    queue_by_id: dict[str, dict[str, Any]] = {}
    sampled_actual = Counter()
    for row in queue_rows:
        if not isinstance(row, dict):
            errors.append("candidate_queue_row_invalid")
            continue
        candidate_id = str(row.get("candidate_id") or "")
        app = str(row.get("app") or "")
        if not candidate_id or candidate_id in queue_by_id:
            errors.append(f"candidate_queue_identity_invalid:{candidate_id or 'missing'}")
            continue
        queue_by_id[candidate_id] = row
        sampled_actual[app] += 1
        if app not in app_names:
            errors.append(f"candidate_queue_app_unknown:{candidate_id}")
        if row.get("severity") not in {"high", "critical"}:
            errors.append(f"candidate_queue_severity_invalid:{candidate_id}")
        if FINGERPRINT_RE.fullmatch(str(row.get("redacted_fingerprint") or "")) is None:
            errors.append(f"candidate_queue_fingerprint_invalid:{candidate_id}")
        if row.get("scan_report_sha256") != report_hashes.get(app):
            errors.append(f"candidate_queue_report_binding_invalid:{candidate_id}")
        if row.get("raw_returned") is not False:
            errors.append(f"candidate_queue_raw_boundary_invalid:{candidate_id}")

    sampling = queue.get("sampling") if isinstance(queue.get("sampling"), dict) else {}
    target = int(sampling.get("target_per_app") or 0)
    available_by_app = sampling.get("available_by_app") if isinstance(sampling.get("available_by_app"), dict) else {}
    sampled_by_app = sampling.get("sampled_by_app") if isinstance(sampling.get("sampled_by_app"), dict) else {}
    fully_sampled_apps = 0
    for app in app_names:
        available = int(available_by_app.get(app, -1))
        sampled = int(sampled_by_app.get(app, -1))
        expected = min(target, available) if target > 0 and available >= 0 else -1
        if sampled != expected or sampled_actual[app] != expected:
            errors.append(f"candidate_sampling_invalid:{app}")
        else:
            fully_sampled_apps += 1
    sample_coverage = _ratio(fully_sampled_apps, len(app_names))

    reviewer_rows = labels.get("reviewers") if isinstance(labels.get("reviewers"), list) else []
    reviewer_refs: set[str] = set()
    reviewer_aliases: set[str] = set()
    for row in reviewer_rows:
        if not isinstance(row, dict):
            errors.append("reviewer_row_invalid")
            continue
        alias = str(row.get("reviewer_alias") or "")
        reviewer_ref = str(row.get("reviewer_ref") or "")
        if not alias or alias in reviewer_aliases or REVIEWER_RE.fullmatch(reviewer_ref) is None:
            errors.append(f"reviewer_identity_invalid:{alias or 'missing'}")
            continue
        reviewer_aliases.add(alias)
        reviewer_refs.add(reviewer_ref)
        if row.get("reviewer_kind") != "independent_codex_subagent":
            errors.append(f"reviewer_kind_invalid:{alias}")
    if len(reviewer_refs) < MIN_REVIEWERS:
        errors.append("reviewer_count_below_minimum")

    label_rows = labels.get("candidates") if isinstance(labels.get("candidates"), list) else []
    labeled_ids: set[str] = set()
    label_counts = Counter()
    agreement_counts = Counter()
    for row in label_rows:
        if not isinstance(row, dict):
            errors.append("candidate_label_row_invalid")
            continue
        candidate_id = str(row.get("candidate_id") or "")
        queued = queue_by_id.get(candidate_id)
        if queued is None or candidate_id in labeled_ids:
            errors.append(f"candidate_label_identity_invalid:{candidate_id or 'missing'}")
            continue
        labeled_ids.add(candidate_id)
        for field in (
            "redacted_fingerprint",
            "app",
            "severity",
            "confidence",
            "rule_id",
            "detector_subtype",
            "source_location",
            "artifact_scope",
            "scan_report_sha256",
        ):
            if row.get(field) != queued.get(field):
                errors.append(f"candidate_label_binding_invalid:{candidate_id}:{field}")
        candidate_reviews = row.get("reviews") if isinstance(row.get("reviews"), list) else []
        if len(candidate_reviews) != MIN_REVIEWERS:
            errors.append(f"candidate_review_count_invalid:{candidate_id}")
        seen_reviewers: set[str] = set()
        for review in candidate_reviews:
            if not isinstance(review, dict):
                errors.append(f"candidate_review_row_invalid:{candidate_id}")
                continue
            reviewer_ref = str(review.get("reviewer_ref") or "")
            label = str(review.get("label") or "")
            if reviewer_ref not in reviewer_refs or reviewer_ref in seen_reviewers:
                errors.append(f"candidate_reviewer_binding_invalid:{candidate_id}")
            seen_reviewers.add(reviewer_ref)
            if label not in ALLOWED_LABELS or not str(review.get("rationale") or "").strip():
                errors.append(f"candidate_review_invalid:{candidate_id}:{reviewer_ref}")
        expected_label, expected_agreement = _majority(candidate_reviews)
        label = str(row.get("label") or "")
        agreement = str(row.get("agreement") or "")
        if label != expected_label or agreement != expected_agreement or agreement not in ALLOWED_AGREEMENTS:
            errors.append(f"candidate_adjudication_invalid:{candidate_id}")
        else:
            label_counts[label] += 1
            agreement_counts[agreement] += 1
        if row.get("raw_returned") is not False:
            errors.append(f"candidate_label_raw_boundary_invalid:{candidate_id}")
    if labeled_ids != set(queue_by_id):
        errors.append("candidate_label_coverage_invalid")

    probe_rows = probes.get("probes") if isinstance(probes.get("probes"), list) else []
    probe_apps = Counter()
    true_positive_probes = 0
    true_positive_detected = 0
    benign_probes = 0
    benign_detected = 0
    for row in probe_rows:
        if not isinstance(row, dict):
            errors.append("reference_probe_row_invalid")
            continue
        probe_id = str(row.get("probe_id") or "missing")
        app = str(row.get("app") or "")
        probe_apps[app] += 1
        if app not in app_names or row.get("scan_report_sha256") != report_hashes.get(app):
            errors.append(f"reference_probe_binding_invalid:{probe_id}")
        detected = row.get("detected") is True and row.get("result") == "detected"
        missed = row.get("detected") is False and row.get("result") == "false_negative"
        if not detected and not missed:
            errors.append(f"reference_probe_result_invalid:{probe_id}")
        classification = row.get("oracle_classification")
        if classification == "true_positive":
            true_positive_probes += 1
            true_positive_detected += int(detected)
        elif classification == "benign_training_fixture":
            benign_probes += 1
            benign_detected += int(detected)
        else:
            errors.append(f"reference_probe_classification_invalid:{probe_id}")
        if row.get("raw_returned") is not False:
            errors.append(f"reference_probe_raw_boundary_invalid:{probe_id}")
    for app in app_names:
        if probe_apps[app] != 1:
            errors.append(f"reference_probe_count_invalid:{app}")

    candidate_count = len(label_rows)
    true_positive_count = label_counts["true_positive"]
    false_positive_count = label_counts["false_positive"]
    actionable_rate = _ratio(true_positive_count, candidate_count)
    adjudicated_precision = _ratio(true_positive_count, true_positive_count + false_positive_count)
    unanimous_rate = _ratio(agreement_counts["unanimous"], candidate_count)
    true_positive_probe_rate = _ratio(true_positive_detected, true_positive_probes)
    integrity_passed = not errors
    blockers: list[str] = []
    if not integrity_passed:
        blockers.append("public_development_contract_invalid")
    if exact_repeat_count != len(app_names):
        blockers.append("repeatability_incomplete")
    if sample_coverage != 1.0:
        blockers.append("candidate_sampling_incomplete")
    if actionable_rate < MIN_ACTIONABLE_RATE:
        blockers.append("candidate_actionable_rate_below_0_80")
    if adjudicated_precision < MIN_ADJUDICATED_PRECISION:
        blockers.append("candidate_precision_below_0_90")
    if unanimous_rate < MIN_UNANIMOUS_RATE:
        blockers.append("reviewer_unanimity_below_0_75")
    if label_counts["inconclusive"]:
        blockers.append("candidate_inconclusive_present")
    if true_positive_probe_rate < MIN_TRUE_POSITIVE_PROBE_RATE:
        blockers.append("true_positive_probe_rate_below_0_90")
    qualified = not blockers

    return {
        "schema": STATUS_SCHEMA,
        "campaign_id": next(iter(campaign_ids), ""),
        "source_revision": source_revision,
        "integrity_passed": integrity_passed,
        "qualified": qualified,
        "verdict": "pass" if qualified else "hold",
        "metrics": {
            "app_count": len(app_names),
            "exact_repeat_app_count": exact_repeat_count,
            "stratum_counts": dict(sorted(strata.items())),
            "candidate_count": candidate_count,
            "candidate_label_counts": dict(sorted(label_counts.items())),
            "candidate_actionable_rate": actionable_rate,
            "adjudicated_precision_tp_fp_only": adjudicated_precision,
            "reviewer_count": len(reviewer_refs),
            "reviewer_agreement_counts": dict(sorted(agreement_counts.items())),
            "reviewer_unanimous_rate": unanimous_rate,
            "candidate_sample_coverage": sample_coverage,
            "true_positive_probe_count": true_positive_probes,
            "true_positive_probe_detected": true_positive_detected,
            "true_positive_probe_rate": true_positive_probe_rate,
            "benign_classifier_probe_count": benign_probes,
            "benign_classifier_probe_detected": benign_detected,
        },
        "thresholds": {
            "minimum_app_count": MIN_APP_COUNT,
            "minimum_reviewers": MIN_REVIEWERS,
            "minimum_candidate_actionable_rate": MIN_ACTIONABLE_RATE,
            "minimum_adjudicated_precision": MIN_ADJUDICATED_PRECISION,
            "minimum_reviewer_unanimous_rate": MIN_UNANIMOUS_RATE,
            "minimum_true_positive_probe_rate": MIN_TRUE_POSITIVE_PROBE_RATE,
            "required_candidate_sample_coverage": 1.0,
        },
        "blockers": blockers,
        "validation_errors": sorted(set(errors)),
        "claim_boundary": {
            "public_development_benchmark_only": True,
            "not_owned_or_partner_field_evidence": True,
            "not_blind_holdout": True,
            "targeted_probe_rate_is_not_full_app_recall": True,
            "same_model_family_review_only": True,
            "not_cross_vendor_validation": True,
            "not_human_adjudication": True,
            "does_not_grant_release_authority": True,
        },
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute the v2 public development-app effectiveness gate.")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    status = build_status(args.evidence_dir)
    output = args.output or args.evidence_dir / "effectiveness-status.json"
    output.write_text(json.dumps(status, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: status[key] for key in ("integrity_passed", "qualified", "verdict", "blockers")}, ensure_ascii=False))
    required = status["qualified"] if args.require_qualified else status["integrity_passed"]
    return 0 if required else 1


if __name__ == "__main__":
    raise SystemExit(main())
