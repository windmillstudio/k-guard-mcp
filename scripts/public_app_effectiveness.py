from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE_DIR = ROOT / "evidence" / "public" / "vulnerable-apps-12-20260713"
CAMPAIGN_SCHEMA = "k_guard_public_app_campaign.v1"
LABEL_SCHEMA = "k_guard_public_candidate_labels.v1"
PROBE_SCHEMA = "k_guard_public_reference_probes.v1"
STATUS_SCHEMA = "k_guard_public_effectiveness_status.v1"
ALLOWED_LABELS = {"true_positive", "false_positive", "benign", "inconclusive"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REVIEWER_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^sha256-truncated:[0-9a-f]{20}$")
MIN_APP_COUNT = 12
MIN_CANDIDATES_PER_APP = 3
MIN_REFERENCE_PROBES = 12
MIN_INDEPENDENT_REVIEWERS = 3
MIN_ACTIONABLE_CANDIDATE_RATE = 0.80
MIN_REFERENCE_PROBE_DETECTION_RATE = 0.80


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _valid_hash(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def build_status(evidence_dir: Path = DEFAULT_EVIDENCE_DIR) -> dict[str, Any]:
    campaign = _read_json(evidence_dir / "campaign.json")
    label_bundle = _read_json(evidence_dir / "candidate-labels.json")
    probe_bundle = _read_json(evidence_dir / "reference-probes.json")
    errors: list[str] = []

    if campaign.get("schema") != CAMPAIGN_SCHEMA:
        errors.append("campaign_schema_invalid")
    if label_bundle.get("schema") != LABEL_SCHEMA:
        errors.append("candidate_label_schema_invalid")
    if probe_bundle.get("schema") != PROBE_SCHEMA:
        errors.append("reference_probe_schema_invalid")

    revisions = {
        str(payload.get("source_revision") or "")
        for payload in (campaign, label_bundle, probe_bundle)
    }
    if len(revisions) != 1 or not REVISION_RE.fullmatch(next(iter(revisions), "")):
        errors.append("source_revision_binding_invalid")
    source_revision = next(iter(revisions), "")

    if campaign.get("campaign_kind") != "public_intentionally_vulnerable_development_benchmark":
        errors.append("campaign_kind_invalid")
    if campaign.get("tracked_worktree_clean") is not True:
        errors.append("tracked_worktree_not_clean")
    if any(payload.get("raw_returned") is not False for payload in (campaign, label_bundle, probe_bundle)):
        errors.append("raw_boundary_invalid")

    apps = campaign.get("apps")
    if not isinstance(apps, list):
        apps = []
        errors.append("apps_invalid")
    app_names: list[str] = []
    report_hashes: dict[str, str] = {}
    exact_repeat_count = 0
    strata = Counter()
    for row in apps:
        if not isinstance(row, dict):
            errors.append("app_row_invalid")
            continue
        name = str(row.get("app") or "")
        if not name or name in app_names:
            errors.append(f"app_identity_invalid:{name or 'missing'}")
            continue
        app_names.append(name)
        if not REVISION_RE.fullmatch(str(row.get("commit") or "")):
            errors.append(f"app_commit_invalid:{name}")
        stratum = str(row.get("stratum") or "")
        if stratum not in {"top", "mid", "long_tail"}:
            errors.append(f"app_stratum_invalid:{name}")
        else:
            strata[stratum] += 1
        runs = row.get("runs")
        if not isinstance(runs, list) or len(runs) < 2:
            errors.append(f"repeat_run_missing:{name}")
            continue
        hashes = [str(run.get("report_sha256") or "") for run in runs if isinstance(run, dict)]
        exits = [run.get("exit_code") for run in runs if isinstance(run, dict)]
        run_numbers = [run.get("run") for run in runs if isinstance(run, dict)]
        if len(run_numbers) != len(runs) or len(set(run_numbers)) != len(runs):
            errors.append(f"repeat_run_identity_invalid:{name}")
        if len(hashes) != len(runs) or any(not _valid_hash(value) for value in hashes):
            errors.append(f"repeat_hash_invalid:{name}")
        elif len(set(hashes)) != 1:
            errors.append(f"repeat_hash_mismatch:{name}")
        else:
            report_hashes[name] = hashes[0]
        if len(exits) != len(runs) or any(value != 0 for value in exits):
            errors.append(f"repeat_execution_failed:{name}")
        if row.get("exact_repeat") is not True:
            errors.append(f"exact_repeat_not_asserted:{name}")
        elif len(set(hashes)) == 1 and all(value == 0 for value in exits):
            exact_repeat_count += 1

    if len(app_names) < MIN_APP_COUNT:
        errors.append("app_count_below_minimum")
    for required in ("top", "mid", "long_tail"):
        if strata[required] == 0:
            errors.append(f"stratum_missing:{required}")

    labels = label_bundle.get("candidates")
    if not isinstance(labels, list):
        labels = []
        errors.append("candidate_rows_invalid")
    candidate_ids: set[str] = set()
    label_counts = Counter()
    labels_per_app = Counter()
    reviewer_refs: set[str] = set()
    for row in labels:
        if not isinstance(row, dict):
            errors.append("candidate_row_invalid")
            continue
        candidate_id = str(row.get("candidate_id") or "")
        app = str(row.get("app") or "")
        label = str(row.get("label") or "")
        reviewer_ref = str(row.get("reviewer_ref") or "")
        if not candidate_id or candidate_id in candidate_ids:
            errors.append(f"candidate_id_invalid:{candidate_id or 'missing'}")
        candidate_ids.add(candidate_id)
        if app not in app_names:
            errors.append(f"candidate_app_unknown:{app or 'missing'}")
        if label not in ALLOWED_LABELS:
            errors.append(f"candidate_label_invalid:{candidate_id or 'missing'}")
        else:
            label_counts[label] += 1
        if not REVIEWER_RE.fullmatch(reviewer_ref):
            errors.append(f"candidate_reviewer_invalid:{candidate_id or 'missing'}")
        else:
            reviewer_refs.add(reviewer_ref)
        if row.get("reviewer_kind") != "independent_ai":
            errors.append(f"candidate_reviewer_kind_invalid:{candidate_id or 'missing'}")
        if row.get("severity") not in {"high", "critical"}:
            errors.append(f"candidate_severity_invalid:{candidate_id or 'missing'}")
        for field in ("rule_id", "detector_subtype", "source_location", "rationale"):
            if not isinstance(row.get(field), str) or not row.get(field).strip():
                errors.append(f"candidate_{field}_missing:{candidate_id or 'missing'}")
        if row.get("response_location") != "not_applicable_static_source_scan":
            errors.append(f"candidate_location_boundary_invalid:{candidate_id or 'missing'}")
        if row.get("raw_returned") is not False:
            errors.append(f"candidate_raw_boundary_invalid:{candidate_id or 'missing'}")
        if not FINGERPRINT_RE.fullmatch(str(row.get("redacted_fingerprint") or "")):
            errors.append(f"candidate_fingerprint_invalid:{candidate_id or 'missing'}")
        if row.get("scan_report_sha256") != report_hashes.get(app):
            errors.append(f"candidate_report_binding_invalid:{candidate_id or 'missing'}")
        labels_per_app[app] += 1
    for app in app_names:
        if labels_per_app[app] != MIN_CANDIDATES_PER_APP:
            errors.append(f"candidate_sample_count_invalid:{app}")
    if len(reviewer_refs) < MIN_INDEPENDENT_REVIEWERS:
        errors.append("candidate_reviewer_count_below_minimum")

    probes = probe_bundle.get("probes")
    if not isinstance(probes, list):
        probes = []
        errors.append("reference_probe_rows_invalid")
    detected_count = 0
    false_negative_count = 0
    probes_per_app = Counter()
    probe_reviewers: set[str] = set()
    probe_ids: set[str] = set()
    for row in probes:
        if not isinstance(row, dict):
            errors.append("reference_probe_row_invalid")
            continue
        probe_id = str(row.get("probe_id") or "")
        app = str(row.get("app") or "")
        reviewer_ref = str(row.get("reviewer_ref") or "")
        detected = row.get("detected")
        if not probe_id or probe_id in probe_ids:
            errors.append(f"reference_probe_id_invalid:{probe_id or 'missing'}")
        probe_ids.add(probe_id)
        if app not in app_names:
            errors.append(f"reference_probe_app_unknown:{app or 'missing'}")
        probes_per_app[app] += 1
        if not REVIEWER_RE.fullmatch(reviewer_ref):
            errors.append(f"reference_probe_reviewer_invalid:{probe_id or 'missing'}")
        else:
            probe_reviewers.add(reviewer_ref)
        if row.get("reviewer_kind") != "independent_ai":
            errors.append(f"reference_probe_reviewer_kind_invalid:{probe_id or 'missing'}")
        if row.get("entire_report_reviewed") is not True:
            errors.append(f"reference_probe_report_review_incomplete:{probe_id or 'missing'}")
        if not isinstance(row.get("oracle_refs"), list) or not row.get("oracle_refs"):
            errors.append(f"reference_probe_oracle_missing:{probe_id or 'missing'}")
        for field in ("risk_domain", "vulnerability", "rationale"):
            if not isinstance(row.get(field), str) or not row.get(field).strip():
                errors.append(f"reference_probe_{field}_missing:{probe_id or 'missing'}")
        if detected is True and row.get("result") == "detected":
            detected_count += 1
        elif detected is False and row.get("result") == "false_negative":
            false_negative_count += 1
        else:
            errors.append(f"reference_probe_result_invalid:{probe_id or 'missing'}")
        if row.get("scan_report_sha256") != report_hashes.get(app):
            errors.append(f"reference_probe_report_binding_invalid:{probe_id or 'missing'}")
        if row.get("raw_returned") is not False:
            errors.append(f"reference_probe_raw_boundary_invalid:{probe_id or 'missing'}")
    if len(probes) < MIN_REFERENCE_PROBES:
        errors.append("reference_probe_count_below_minimum")
    for app in app_names:
        if probes_per_app[app] != 1:
            errors.append(f"reference_probe_count_invalid:{app}")
    if len(probe_reviewers) < MIN_INDEPENDENT_REVIEWERS:
        errors.append("reference_probe_reviewer_count_below_minimum")

    candidate_count = len(labels)
    true_positive_count = label_counts["true_positive"]
    strict_actionable_rate = _ratio(true_positive_count, candidate_count)
    adjudicated_precision = _ratio(
        true_positive_count,
        true_positive_count + label_counts["false_positive"],
    )
    probe_detection_rate = _ratio(detected_count, len(probes))
    integrity_passed = not errors
    blockers: list[str] = []
    if not integrity_passed:
        blockers.append("public_campaign_contract_invalid")
    if strict_actionable_rate < MIN_ACTIONABLE_CANDIDATE_RATE:
        blockers.append("candidate_actionable_rate_below_0_80")
    if probe_detection_rate < MIN_REFERENCE_PROBE_DETECTION_RATE:
        blockers.append("reference_probe_detection_rate_below_0_80")
    qualified = integrity_passed and not blockers

    return {
        "schema": STATUS_SCHEMA,
        "source_revision": source_revision,
        "campaign_id": campaign.get("campaign_id"),
        "integrity_passed": integrity_passed,
        "qualified": qualified,
        "verdict": "pass" if qualified else "hold",
        "metrics": {
            "app_count": len(app_names),
            "exact_repeat_app_count": exact_repeat_count,
            "stratum_counts": dict(sorted(strata.items())),
            "candidate_count": candidate_count,
            "candidate_label_counts": dict(sorted(label_counts.items())),
            "strict_actionable_candidate_rate": strict_actionable_rate,
            "adjudicated_precision_tp_fp_only": adjudicated_precision,
            "candidate_reviewer_count": len(reviewer_refs),
            "reference_probe_count": len(probes),
            "reference_probe_detected": detected_count,
            "reference_probe_false_negative": false_negative_count,
            "reference_probe_detection_rate": probe_detection_rate,
            "reference_probe_reviewer_count": len(probe_reviewers),
        },
        "thresholds": {
            "minimum_app_count": MIN_APP_COUNT,
            "minimum_candidates_per_app": MIN_CANDIDATES_PER_APP,
            "minimum_reference_probes": MIN_REFERENCE_PROBES,
            "minimum_independent_reviewers": MIN_INDEPENDENT_REVIEWERS,
            "minimum_actionable_candidate_rate": MIN_ACTIONABLE_CANDIDATE_RATE,
            "minimum_reference_probe_detection_rate": MIN_REFERENCE_PROBE_DETECTION_RATE,
        },
        "blockers": blockers,
        "validation_errors": sorted(set(errors)),
        "claim_boundary": {
            "public_development_benchmark_only": True,
            "not_owned_or_partner_field_evidence": True,
            "not_blind_holdout": True,
            "targeted_probe_rate_is_not_full_app_recall": True,
            "independent_reviewers_are_ai_not_human": True,
            "does_not_grant_release_authority": True,
        },
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Recompute the public vulnerable-app effectiveness gate.")
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_DIR)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-qualified", action="store_true")
    args = parser.parse_args()
    status = build_status(args.evidence_dir)
    output = args.output or args.evidence_dir / "effectiveness-status.json"
    output.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "integrity_passed": status["integrity_passed"],
                "qualified": status["qualified"],
                "verdict": status["verdict"],
                "blockers": status["blockers"],
            },
            ensure_ascii=False,
        )
    )
    required = status["qualified"] if args.require_qualified else status["integrity_passed"]
    return 0 if required else 1


if __name__ == "__main__":
    raise SystemExit(main())
