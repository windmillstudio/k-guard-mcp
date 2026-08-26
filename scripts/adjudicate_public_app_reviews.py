from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


QUEUE_SCHEMA = "k_guard_public_candidate_queue.v2"
LABEL_SCHEMA = "k_guard_public_candidate_labels.v2"
ALLOWED_LABELS = {"true_positive", "false_positive", "benign", "inconclusive"}
REQUIRED_REVIEWERS = 3


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _review_ref(review: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(review)).hexdigest()


def _validate_queue(queue: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if queue.get("schema") != QUEUE_SCHEMA:
        raise ValueError(f"candidate queue schema must be {QUEUE_SCHEMA}")
    candidates = queue.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("candidate queue must not be empty")
    by_id: dict[str, dict[str, Any]] = {}
    for row in candidates:
        if not isinstance(row, dict):
            raise ValueError("candidate row must be an object")
        candidate_id = str(row.get("candidate_id") or "")
        if not candidate_id or candidate_id in by_id:
            raise ValueError(f"candidate identity invalid: {candidate_id or 'missing'}")
        if row.get("raw_returned") is not False:
            raise ValueError(f"candidate raw boundary invalid: {candidate_id}")
        by_id[candidate_id] = row
    return by_id


def _validate_review(
    review: dict[str, Any],
    expected_ids: set[str],
    seen_aliases: set[str],
) -> tuple[str, str, dict[str, dict[str, str]]]:
    alias = str(review.get("reviewer_alias") or "").strip().lower()
    if not alias or alias in seen_aliases:
        raise ValueError(f"reviewer alias invalid: {alias or 'missing'}")
    if review.get("method") != "independent_source_context_review":
        raise ValueError(f"reviewer method invalid: {alias}")
    rows = review.get("labels")
    if not isinstance(rows, list):
        raise ValueError(f"review labels invalid: {alias}")
    labels: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"review row invalid: {alias}")
        candidate_id = str(row.get("candidate_id") or "")
        label = str(row.get("label") or "")
        rationale = str(row.get("rationale") or "").strip()
        if candidate_id in labels or candidate_id not in expected_ids:
            raise ValueError(f"review candidate invalid: {alias}:{candidate_id or 'missing'}")
        if label not in ALLOWED_LABELS:
            raise ValueError(f"review label invalid: {alias}:{candidate_id}")
        if not rationale:
            raise ValueError(f"review rationale missing: {alias}:{candidate_id}")
        labels[candidate_id] = {"label": label, "rationale": rationale}
    missing = expected_ids - set(labels)
    if missing:
        raise ValueError(f"review candidates missing: {alias}:{','.join(sorted(missing))}")
    seen_aliases.add(alias)
    return alias, _review_ref(review), labels


def _consensus(reviews: list[dict[str, str]]) -> tuple[str, str]:
    counts = Counter(row["label"] for row in reviews)
    label, votes = counts.most_common(1)[0]
    if votes < 2 or list(counts.values()).count(votes) > 1:
        return "inconclusive", "no_consensus"
    return label, "unanimous" if votes == len(reviews) else "majority"


def build_labels(queue: dict[str, Any], reviews: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = _validate_queue(queue)
    if len(reviews) != REQUIRED_REVIEWERS:
        raise ValueError(f"exactly {REQUIRED_REVIEWERS} independent reviews are required")
    reviewer_rows: list[dict[str, Any]] = []
    labels_by_reviewer: list[tuple[str, str, dict[str, dict[str, str]]]] = []
    aliases: set[str] = set()
    for review in reviews:
        alias, reviewer_ref, labels = _validate_review(review, set(candidates), aliases)
        labels_by_reviewer.append((alias, reviewer_ref, labels))
        reviewer_rows.append(
            {
                "reviewer_alias": alias,
                "reviewer_ref": reviewer_ref,
                "reviewer_kind": "independent_codex_subagent",
                "method": "independent_source_context_review",
                "candidate_count": len(labels),
            }
        )

    adjudicated: list[dict[str, Any]] = []
    agreement_counts = Counter()
    label_counts = Counter()
    for candidate_id, candidate in candidates.items():
        candidate_reviews = [
            {
                "reviewer_alias": alias,
                "reviewer_ref": reviewer_ref,
                **labels[candidate_id],
            }
            for alias, reviewer_ref, labels in labels_by_reviewer
        ]
        label, agreement = _consensus(candidate_reviews)
        agreement_counts[agreement] += 1
        label_counts[label] += 1
        adjudicated.append(
            {
                "candidate_id": candidate_id,
                "redacted_fingerprint": candidate.get("redacted_fingerprint"),
                "app": candidate.get("app"),
                "severity": candidate.get("severity"),
                "confidence": candidate.get("confidence"),
                "rule_id": candidate.get("rule_id"),
                "detector_subtype": candidate.get("detector_subtype"),
                "source_location": candidate.get("source_location"),
                "artifact_scope": candidate.get("artifact_scope"),
                "scan_report_sha256": candidate.get("scan_report_sha256"),
                "response_location": "not_applicable_static_source_scan",
                "http_response_sha256": None,
                "reviews": candidate_reviews,
                "label": label,
                "agreement": agreement,
                "raw_returned": False,
            }
        )

    return {
        "schema": LABEL_SCHEMA,
        "campaign_id": queue.get("campaign_id"),
        "source_revision": queue.get("source_revision"),
        "review_contract": {
            "required_reviewers_per_candidate": REQUIRED_REVIEWERS,
            "labels": sorted(ALLOWED_LABELS),
            "adjudication": "two-of-three majority; no majority becomes inconclusive",
            "review_boundary": "Three independent Codex subagents inspected source context. This is not human or cross-vendor review.",
            "static_location_boundary": "HTTP body/header position and response hash do not apply to local source scans.",
        },
        "reviewers": reviewer_rows,
        "candidates": adjudicated,
        "metrics": {
            "candidate_count": len(adjudicated),
            "label_counts": dict(sorted(label_counts.items())),
            "agreement_counts": dict(sorted(agreement_counts.items())),
        },
        "claim_boundary": {
            "independent_process_reviews": True,
            "same_model_family_review_only": True,
            "not_cross_vendor_validation": True,
            "not_human_adjudication": True,
            "not_owned_or_partner_field_evidence": True,
        },
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Adjudicate three independent public-app candidate reviews.")
    parser.add_argument("--candidate-queue", type=Path, required=True)
    parser.add_argument("--review", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    queue = _read_json(args.candidate_queue)
    reviews = [_read_json(path) for path in args.review]
    labels = build_labels(queue, reviews)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(labels, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(labels["metrics"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
