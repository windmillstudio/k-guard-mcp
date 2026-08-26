from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV, evidence_hash, evidence_hash_scheme, uses_public_evidence_key
from k_guard_mcp.provenance import evidence_bundle, object_artifact, path_artifact
from k_guard_mcp.redaction import sanitize_any


VALIDATION_FIELDS = ["app_id", "target_id", "rule_id", "finding_fingerprint", "verdict", "reviewer", "notes"]
VALIDATION_VERDICTS = {"true_positive", "false_positive", "false_negative", "benign", "inconclusive"}


def write_validation_review_template(path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=VALIDATION_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "app_id": "owned-app-01",
                "target_id": "app-workspace",
                "rule_id": "JS_TS_EXPRESS_IDOR_ROUTE_PARAM",
                "finding_fingerprint": "paste-finding-fingerprint-from-guardian-report",
                "verdict": "true_positive",
                "reviewer": "senior-reviewer",
                "notes": "raw-free review note",
            }
        )


def run_validation_review(guardian_report_path: str | Path, review_path: str | Path) -> dict[str, Any]:
    if uses_public_evidence_key():
        raise RuntimeError(f"{EVIDENCE_HMAC_ENV} is required to generate signed manual-validation evidence.")
    guardian_report = json.loads(Path(guardian_report_path).read_text(encoding="utf-8"))
    findings = _guardian_findings(guardian_report)
    review_file = Path(review_path)
    reviews, invalid_reviews = _read_reviews(review_file)
    reviews, binding_errors = _bind_reviews_to_guardian(
        reviews,
        _guardian_target_apps(guardian_report),
    )
    invalid_reviews.extend(binding_errors)
    candidates = [finding for finding in findings if str(finding.get("severity") or "info") in {"critical", "high"}]
    candidate_app_ids = {
        str(finding.get("app_id") or "")
        for finding in candidates
        if str(finding.get("app_id") or "").strip()
    }
    candidate_target_ids = {str(finding.get("target_id") or "") for finding in candidates if str(finding.get("target_id") or "").strip()}
    reviewed_candidates = []
    verdict_counts: Counter[str] = Counter()
    for finding in candidates:
        fingerprint = finding_fingerprint(finding)
        review = reviews.get(
            (
                str(finding.get("app_id") or ""),
                str(finding.get("target_id") or ""),
                str(finding.get("rule_id") or ""),
                fingerprint,
            )
        )
        verdict = review.get("verdict", "inconclusive") if review else "inconclusive"
        verdict_counts[verdict] += 1
        reviewed_candidates.append(
            {
                "app_id_hash": evidence_hash(str(finding.get("app_id") or "")),
                "target_id": finding.get("target_id", ""),
                "rule_id": finding.get("rule_id", ""),
                "severity": finding.get("severity", ""),
                "finding_fingerprint": fingerprint,
                "verdict": verdict,
                "reviewed": bool(review),
            }
        )
    false_negative_reviews = [review for review in reviews.values() if review.get("verdict") == "false_negative"]
    verdict_counts["false_negative"] += len(false_negative_reviews)
    app_ids = {str(review.get("app_id") or "") for review in reviews.values() if str(review.get("app_id") or "").strip()}
    reviewed_count = sum(1 for item in reviewed_candidates if item["reviewed"])
    total_verdicts = sum(verdict_counts.values())
    generated_at = datetime.now(UTC).isoformat()
    review_artifact = path_artifact("validation_review_csv", review_file, role="manual_input")
    review_source = _review_source_contract(review_artifact, len(reviews) + len(invalid_reviews))
    reviewer_assertions = _reviewer_assertions(reviews, invalid_reviews)
    report = {
        "generated_at": generated_at,
        "method": "design_partner_validation",
        "raw_free": True,
        "guardian_report_ref": _path_ref(guardian_report_path),
        "guardian_report_content_ref": _content_ref(guardian_report_path),
        "guardian_report_bundle_ref": _bundle_ref(guardian_report.get("evidence_bundle")),
        "review_path_ref": _path_ref(review_path),
        "review_source": review_source,
        "reviewer_assertions": reviewer_assertions,
        "sample": {
            "app_count": len(candidate_app_ids),
            "minimum_app_count_for_claim": 5,
            "maximum_app_count_for_claim": 20,
            "review_app_id_count": len(app_ids),
            "candidate_app_count": len(candidate_app_ids),
            "candidate_target_count": len(candidate_target_ids),
            "candidate_count": len(candidates),
            "minimum_reviewed_candidate_count_for_claim": 5,
            "reviewed_candidate_count": reviewed_count,
            "invalid_review_count": len(invalid_reviews),
        },
        "verdict_counts": {verdict: verdict_counts.get(verdict, 0) for verdict in sorted(VALIDATION_VERDICTS)},
        "rates": _rates(verdict_counts, total_verdicts),
        "claim_status": _claim_status(len(candidate_app_ids), len(invalid_reviews), verdict_counts, len(candidates), reviewed_count),
        "candidate_app_refs": [_app_ref(app_id) for app_id in sorted(candidate_app_ids)],
        "candidate_target_refs": [_target_ref(target_id) for target_id in sorted(candidate_target_ids)],
        "candidate_finding_refs": [_finding_ref(finding) for finding in candidates],
        "candidate_reviews": reviewed_candidates[:200],
        "false_negative_reviews": [
            {
                "app_id_hash": evidence_hash(str(item.get("app_id") or "")),
                "target_id": item.get("target_id", ""),
                "rule_id": item.get("rule_id", ""),
                "finding_fingerprint": item.get("finding_fingerprint", ""),
                "raw_notes_returned": False,
            }
            for item in false_negative_reviews[:100]
        ],
        "invalid_reviews": invalid_reviews,
        "hash_scheme": evidence_hash_scheme(),
        "boundary": {
            "manual_labels_required": True,
            "pass_claim_requires_no_unresolved_high_critical": True,
            "not_a_certificate": True,
        },
    }
    report["validation_evidence_envelope"] = evidence_bundle(
        "manual_validation_review",
        "k_guard_mcp.validation",
        [
            review_artifact,
            object_artifact("review_source", review_source, role="manual_input"),
            object_artifact("reviewer_assertions", reviewer_assertions, role="assertion"),
            object_artifact("generated_at", {"generated_at": generated_at}, role="timestamp"),
            object_artifact("guardian_binding", _guardian_binding(report), role="input"),
            object_artifact("validation_projection", validation_evidence_projection(report), role="gate"),
        ],
    )
    return sanitize_any(report)


def validation_evidence_projection(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": report.get("method"),
        "raw_free": report.get("raw_free"),
        "sample": report.get("sample", {}),
        "verdict_counts": report.get("verdict_counts", {}),
        "rates": report.get("rates", {}),
        "claim_status": report.get("claim_status"),
        "candidate_app_refs": report.get("candidate_app_refs", []),
        "candidate_target_refs": report.get("candidate_target_refs", []),
        "candidate_finding_refs": report.get("candidate_finding_refs", []),
        "candidate_reviews": report.get("candidate_reviews", []),
        "false_negative_reviews": report.get("false_negative_reviews", []),
        "invalid_reviews": report.get("invalid_reviews", []),
        "boundary": report.get("boundary", {}),
        "hash_scheme": report.get("hash_scheme"),
    }


def finding_fingerprint(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("target_id") or ""),
        str(finding.get("rule_id") or ""),
        str(finding.get("source") or ""),
        str(finding.get("file") or finding.get("url") or ""),
        str(finding.get("line_start") or ""),
        str(finding.get("evidence") or ""),
    ]
    return evidence_hash("|".join(parts))


def _path_ref(path: str | Path) -> dict[str, Any]:
    text = str(path)
    return {"hash": evidence_hash(text), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _content_ref(path: str | Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except Exception:
        text = ""
    return {"hash": evidence_hash(text), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _bundle_ref(bundle: object) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        return {"bundle_sha256": "", "hash_scheme": evidence_hash_scheme(), "raw_returned": False}
    signature = bundle.get("signature", {}) if isinstance(bundle.get("signature"), dict) else {}
    return {
        "bundle_sha256": str(bundle.get("bundle_sha256") or ""),
        "signature_sha256_hash": evidence_hash(str(signature.get("signature_sha256") or "")),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _review_source_contract(artifact: dict[str, Any], row_count: int) -> dict[str, Any]:
    content_sha256 = str(artifact.get("content_sha256") or "")
    return {
        "schema": "k_guard_validation_review_source.v1",
        "content_sha256": content_sha256,
        "sha256_verified_at_generation": len(content_sha256) == hashlib.sha256().digest_size * 2,
        "byte_count": int(artifact.get("byte_count", 0)),
        "row_count": row_count,
        "exists_at_generation": artifact.get("exists_at_bundle_time") is True,
        "path_ref": {
            "hash": artifact.get("hash", ""),
            "hash_scheme": artifact.get("hash_scheme", evidence_hash_scheme()),
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _reviewer_assertions(
    reviews: dict[tuple[str, str, str, str], dict[str, str]],
    invalid_reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = list(reviews.values())
    reviewers = sorted({row["reviewer"] for row in rows if row.get("reviewer")})
    assertion_refs = []
    for row in sorted(rows, key=lambda item: (item["app_id"], item["target_id"], item["rule_id"], item["finding_fingerprint"])):
        assertion_refs.append(
            {
                "assertion_hash": evidence_hash(
                    "|".join(
                        (
                            row["app_id"],
                            row["target_id"],
                            row["rule_id"],
                            row["finding_fingerprint"],
                            row["verdict"],
                            row["reviewer"],
                        )
                    )
                ),
                "hash_scheme": evidence_hash_scheme(),
                "raw_returned": False,
            }
        )
    return {
        "schema": "k_guard_validation_reviewer_assertions.v1",
        "manual_labels_asserted": bool(rows),
        "exact_review_source_asserted": True,
        "named_reviewer_required": True,
        "all_valid_rows_have_named_reviewer": all(bool(row.get("reviewer")) for row in rows),
        "reviewed_row_count": len(rows),
        "invalid_row_count": len(invalid_reviews),
        "reviewer_count": len(reviewers),
        "reviewer_refs": [
            {"hash": evidence_hash(reviewer), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}
            for reviewer in reviewers
        ],
        "assertion_refs": assertion_refs,
        "raw_returned": False,
    }


def _guardian_binding(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "guardian_report_ref": report.get("guardian_report_ref", {}),
        "guardian_report_content_ref": report.get("guardian_report_content_ref", {}),
        "guardian_report_bundle_ref": report.get("guardian_report_bundle_ref", {}),
        "raw_returned": False,
    }


def _target_ref(target_id: str) -> dict[str, Any]:
    return {"hash": evidence_hash(target_id), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _app_ref(app_id: str) -> dict[str, Any]:
    return {"hash": evidence_hash(app_id), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _finding_ref(finding: dict[str, Any]) -> dict[str, Any]:
    return {"hash": finding_fingerprint(finding), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _guardian_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in report.get("targets", []):
        if not isinstance(row, dict):
            continue
        for finding in row.get("findings", []):
            if isinstance(finding, dict):
                item = dict(finding)
                item.setdefault("app_id", row.get("app_id", ""))
                item.setdefault("target_id", row.get("target_id", ""))
                findings.append(item)
    return findings


def _read_reviews(path: Path) -> tuple[dict[tuple[str, str, str, str], dict[str, str]], list[dict[str, Any]]]:
    reviews: dict[tuple[str, str, str, str], dict[str, str]] = {}
    invalid: list[dict[str, Any]] = []
    if not path.exists():
        return reviews, [{"row": 0, "error": "review_path_not_found", "path_hash": evidence_hash(str(path))}]
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for index, row in enumerate(rows, start=2):
        item = {field: str(row.get(field, "") or "").strip() for field in VALIDATION_FIELDS}
        error = _review_error(item)
        if error:
            invalid.append({"row": index, "error": error})
            continue
        key = (
            item["app_id"],
            item["target_id"],
            item["rule_id"],
            item["finding_fingerprint"],
        )
        if key in reviews:
            invalid.append({"row": index, "error": "duplicate_review_key"})
            continue
        reviews[key] = item
    return reviews, invalid


def _guardian_target_apps(report: dict[str, Any]) -> dict[str, str]:
    target_apps: dict[str, str] = {}
    ambiguous: set[str] = set()
    for row in report.get("targets", []):
        if not isinstance(row, dict):
            continue
        target_id = str(row.get("target_id") or "").strip()
        app_id = str(row.get("app_id") or "").strip()
        if not target_id or not app_id:
            continue
        if target_id in target_apps and target_apps[target_id] != app_id:
            ambiguous.add(target_id)
            continue
        target_apps[target_id] = app_id
    for target_id in ambiguous:
        target_apps.pop(target_id, None)
    return target_apps


def _bind_reviews_to_guardian(
    reviews: dict[tuple[str, str, str, str], dict[str, str]],
    target_apps: dict[str, str],
) -> tuple[dict[tuple[str, str, str, str], dict[str, str]], list[dict[str, Any]]]:
    bound: dict[tuple[str, str, str, str], dict[str, str]] = {}
    invalid: list[dict[str, Any]] = []
    for key, review in reviews.items():
        expected_app_id = target_apps.get(review["target_id"])
        if expected_app_id is None:
            invalid.append(
                {
                    "row_ref": evidence_hash("|".join(key)),
                    "error": "review_target_not_bound_to_guardian_app",
                }
            )
            continue
        if review["app_id"] != expected_app_id:
            invalid.append(
                {
                    "row_ref": evidence_hash("|".join(key)),
                    "error": "review_app_id_mismatch",
                }
            )
            continue
        bound[key] = review
    return bound, invalid


def _review_error(row: dict[str, str]) -> str:
    for field in ("app_id", "target_id", "rule_id", "verdict", "reviewer"):
        if not row.get(field):
            return f"missing_{field}"
    if row["verdict"] not in VALIDATION_VERDICTS:
        return "invalid_verdict"
    if row["verdict"] != "false_negative" and not row.get("finding_fingerprint"):
        return "missing_finding_fingerprint"
    return ""


def _rates(counts: Counter[str], total: int) -> dict[str, float]:
    denominator = total or 1
    return {
        "true_positive_rate": counts.get("true_positive", 0) / denominator,
        "false_positive_rate": counts.get("false_positive", 0) / denominator,
        "false_negative_rate": counts.get("false_negative", 0) / denominator,
        "inconclusive_rate": counts.get("inconclusive", 0) / denominator,
        "benign_rate": counts.get("benign", 0) / denominator,
    }


def _claim_status(app_count: int, invalid_review_count: int, counts: Counter[str], candidate_count: int, reviewed_candidate_count: int) -> str:
    if invalid_review_count:
        return "blocked_invalid_review_labels"
    if app_count < 5:
        return "insufficient_design_partner_sample"
    if app_count > 20:
        return "sample_scope_too_broad_for_manual_claim"
    if counts.get("false_negative", 0):
        return "blocked_false_negatives_need_rule_work"
    if counts.get("benign", 0):
        return "blocked_benign_high_critical_labels"
    if candidate_count < 5 or reviewed_candidate_count < 5:
        return "insufficient_candidate_review_coverage"
    if reviewed_candidate_count < candidate_count:
        return "manual_review_incomplete"
    if counts.get("inconclusive", 0):
        return "manual_review_incomplete"
    return "validation_sample_ready"
