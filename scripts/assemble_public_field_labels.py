from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


QUEUE_SCHEMA = "k_guard_public_field_candidate_queue.v1"
REVIEW_SCHEMA = "k_guard_public_field_independent_review.v2"
LABEL_SCHEMA = "k_guard_public_field_candidate_labels.v1"
ALLOWED_LABELS = {"true_positive", "false_positive", "benign", "inconclusive"}
REQUIRED_VENDORS = {"anthropic", "openai", "xai"}
BINDING_FIELDS = (
    "redacted_fingerprint",
    "app",
    "severity",
    "confidence",
    "rule_id",
    "detector_subtype",
    "source_location",
    "artifact_scope",
    "scan_report_sha256",
    "response_hash",
    "location",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CANDIDATE_ID_RE = re.compile(r"^[0-9a-f]{20}$")
APP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RULE_RE = re.compile(r"^[A-Z][A-Z0-9_.-]{2,127}$")
SUBTYPE_RE = re.compile(r"^[a-z0-9][a-z0-9_:-]{0,127}$")
SCOPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def _canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bound_artifact(root: Path, relative_value: Any, expected_sha256: Any) -> Path:
    relative = Path(str(relative_value or ""))
    candidate = (root / relative).resolve()
    resolved_root = root.resolve()
    if (
        not relative.name
        or relative.is_absolute()
        or ".." in relative.parts
        or not candidate.is_relative_to(resolved_root)
        or not candidate.is_file()
        or candidate.is_symlink()
    ):
        raise ValueError("review provenance artifact path is invalid")
    if _file_sha256(candidate) != expected_sha256:
        raise ValueError("review provenance artifact hash is invalid")
    return candidate


def _valid_location_ref(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 512:
        return False
    if any(character in value for character in "\x00\r\n\\"):
        return False
    if value.startswith(("/", "http://", "https://")):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def _validate_queue_candidate(row: Any) -> None:
    if not isinstance(row, dict):
        raise ValueError("candidate queue row is invalid")
    candidate_id = row.get("candidate_id")
    if not isinstance(candidate_id, str) or CANDIDATE_ID_RE.fullmatch(candidate_id) is None:
        raise ValueError("candidate id is not a canonical redacted identifier")
    if row.get("redacted_fingerprint") != f"sha256-truncated:{candidate_id}":
        raise ValueError("candidate redacted fingerprint is not bound to its identifier")
    if row.get("severity") not in {"high", "critical"}:
        raise ValueError("candidate severity must be high or critical")
    if row.get("confidence") not in {"low", "medium", "high"}:
        raise ValueError("candidate confidence is invalid")
    if not isinstance(row.get("app"), str) or APP_RE.fullmatch(row["app"]) is None:
        raise ValueError("candidate app identifier is invalid")
    if not isinstance(row.get("rule_id"), str) or RULE_RE.fullmatch(row["rule_id"]) is None:
        raise ValueError("candidate rule identifier is invalid")
    if not isinstance(row.get("detector_subtype"), str) or SUBTYPE_RE.fullmatch(row["detector_subtype"]) is None:
        raise ValueError("candidate detector subtype is invalid")
    if not isinstance(row.get("artifact_scope"), str) or SCOPE_RE.fullmatch(row["artifact_scope"]) is None:
        raise ValueError("candidate artifact scope is invalid")
    if not isinstance(row.get("scan_report_sha256"), str) or SHA256_RE.fullmatch(row["scan_report_sha256"]) is None:
        raise ValueError("candidate scan report hash is invalid")
    source_location = row.get("source_location")
    if not _valid_location_ref(source_location):
        raise ValueError("candidate source location is not raw-free")
    location = row.get("location")
    if not isinstance(location, dict) or set(location) != {"kind", "source", "body_or_header"}:
        raise ValueError("candidate location schema is invalid")
    kind = location.get("kind")
    body_or_header = location.get("body_or_header")
    response_hash = row.get("response_hash")
    if kind == "source":
        if location.get("source") != source_location or body_or_header is not None or response_hash is not None:
            raise ValueError("source candidate response evidence is invalid")
    elif kind == "response":
        if not _valid_location_ref(location.get("source")) or body_or_header not in {"body", "header"}:
            raise ValueError("response candidate location is invalid")
        if not isinstance(response_hash, str) or SHA256_RE.fullmatch(response_hash) is None:
            raise ValueError("response candidate response hash is invalid")
    else:
        raise ValueError("candidate location kind is invalid")
    if row.get("raw_returned") is not False:
        raise ValueError("candidate row must be raw-free")


def candidate_bindings_sha256(queue_rows: list[dict[str, Any]]) -> str:
    for row in queue_rows:
        _validate_queue_candidate(row)
    bindings = [
        {"candidate_id": row.get("candidate_id"), **{field: row.get(field) for field in BINDING_FIELDS}}
        for row in queue_rows
    ]
    encoded = json.dumps(bindings, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _majority(rows: list[dict[str, str]]) -> tuple[str, str]:
    counts = Counter(row["label"] for row in rows)
    label, votes = counts.most_common(1)[0]
    if votes < 2 or list(counts.values()).count(votes) > 1:
        return "inconclusive", "no_consensus"
    return label, "unanimous" if votes == len(rows) else "majority"


def build_labels(queue_path: Path, review_paths: list[Path]) -> dict[str, Any]:
    queue = _read_json(queue_path)
    if queue.get("schema") != QUEUE_SCHEMA or queue.get("raw_returned") is not False:
        raise ValueError("candidate queue contract is invalid")
    if len(review_paths) != 3:
        raise ValueError("exactly three review files are required")

    queue_rows = queue.get("candidates")
    if not isinstance(queue_rows, list):
        raise ValueError("candidate queue rows are missing")
    queued = {str(row.get("candidate_id") or ""): row for row in queue_rows if isinstance(row, dict)}
    if "" in queued or len(queued) != len(queue_rows):
        raise ValueError("candidate queue identities are invalid")
    binding_hash = candidate_bindings_sha256(queue_rows)
    queue_file_hash = _file_sha256(queue_path)
    evidence_root = queue_path.resolve().parent

    reviewers: list[dict[str, Any]] = []
    review_maps: list[tuple[dict[str, Any], dict[str, dict[str, str]]]] = []
    aliases: set[str] = set()
    refs: set[str] = set()
    vendors: set[str] = set()
    sessions: set[str] = set()
    responses: set[str] = set()
    response_artifacts: set[str] = set()
    for path in review_paths:
        resolved_review = path.resolve()
        if not resolved_review.is_relative_to(evidence_root) or resolved_review.is_symlink():
            raise ValueError("review file must be inside the candidate evidence directory")
        payload = _read_json(path)
        if payload.get("schema") != REVIEW_SCHEMA or payload.get("raw_returned") is not False:
            raise ValueError(f"review contract is invalid: {path}")
        for field in (
            "campaign_id",
            "source_revision",
            "analyzer_package_tree_sha256",
            "holdout_protocol_manifest_sha256",
        ):
            if payload.get(field) != queue.get(field):
                raise ValueError(f"review campaign binding is invalid: {path}:{field}")
        if payload.get("candidate_bindings_sha256") != binding_hash:
            raise ValueError(f"review candidate binding is invalid: {path}")
        if payload.get("candidate_queue_sha256") != queue_file_hash:
            raise ValueError(f"review queue artifact binding is invalid: {path}")
        alias = str(payload.get("reviewer_alias") or "").strip()
        reviewer_kind = str(payload.get("reviewer_kind") or "").strip()
        vendor = str(payload.get("vendor") or "").strip().casefold()
        model = str(payload.get("model") or "").strip()
        session_id = str(payload.get("session_id") or "").strip()
        response_id = str(payload.get("response_id") or "").strip()
        if (
            not alias
            or alias in aliases
            or reviewer_kind != "external_ai_source_context_review"
            or vendor not in REQUIRED_VENDORS
            or vendor in vendors
            or not model
            or not session_id
            or session_id in sessions
            or not response_id
            or response_id in responses
        ):
            raise ValueError("reviewer identity is invalid")
        aliases.add(alias)
        vendors.add(vendor)
        sessions.add(session_id)
        responses.add(response_id)
        prompt_path = _bound_artifact(
            evidence_root,
            payload.get("prompt_artifact_path"),
            payload.get("prompt_sha256"),
        )
        response_path = _bound_artifact(
            evidence_root,
            payload.get("response_artifact_path"),
            payload.get("response_sha256"),
        )
        response_relative = response_path.relative_to(evidence_root).as_posix()
        if response_path == prompt_path or response_path == resolved_review or response_relative in response_artifacts:
            raise ValueError("review response evidence must be distinct")
        response_artifacts.add(response_relative)
        reviewer_ref = "sha256:" + _canonical_sha256(payload)
        if reviewer_ref in refs:
            raise ValueError("reviewer evidence must be distinct")
        refs.add(reviewer_ref)
        review_rows = payload.get("candidates")
        if not isinstance(review_rows, list):
            raise ValueError(f"review rows are missing: {path}")
        review_map: dict[str, dict[str, str]] = {}
        for row in review_rows:
            if not isinstance(row, dict):
                raise ValueError(f"review row is invalid: {path}")
            candidate_id = str(row.get("candidate_id") or "")
            label = str(row.get("label") or "")
            rationale = str(row.get("rationale") or "").strip()
            if candidate_id in review_map or label not in ALLOWED_LABELS or not rationale:
                raise ValueError(f"review decision is invalid: {path}:{candidate_id}")
            review_map[candidate_id] = {"label": label, "rationale": rationale}
        if set(review_map) != set(queued):
            raise ValueError(f"review coverage does not match queue: {path}")
        reviewer = {
            "reviewer_alias": alias,
            "reviewer_kind": reviewer_kind,
            "vendor": vendor,
            "model": model,
            "session_id": session_id,
            "response_id": response_id,
            "reviewer_ref": reviewer_ref,
            "review_file_path": resolved_review.relative_to(evidence_root).as_posix(),
            "review_file_sha256": _file_sha256(resolved_review),
            "prompt_artifact_path": prompt_path.relative_to(evidence_root).as_posix(),
            "prompt_sha256": _file_sha256(prompt_path),
            "response_artifact_path": response_relative,
            "response_sha256": _file_sha256(response_path),
            "candidate_queue_sha256": queue_file_hash,
            "candidate_bindings_sha256": binding_hash,
        }
        reviewers.append(reviewer)
        review_maps.append((reviewer, review_map))

    labeled: list[dict[str, Any]] = []
    for queued_row in queue_rows:
        candidate_id = str(queued_row["candidate_id"])
        reviews = [
            {
                "reviewer_alias": reviewer["reviewer_alias"],
                "reviewer_vendor": reviewer["vendor"],
                "reviewer_ref": reviewer["reviewer_ref"],
                "label": decisions[candidate_id]["label"],
                "rationale": decisions[candidate_id]["rationale"],
            }
            for reviewer, decisions in review_maps
        ]
        label, agreement = _majority(reviews)
        row = {field: queued_row.get(field) for field in BINDING_FIELDS}
        location = queued_row.get("location") if isinstance(queued_row.get("location"), dict) else {}
        row.update(
            {
                "candidate_id": candidate_id,
                "http_response_sha256": queued_row.get("response_hash"),
                "response_location": location.get("body_or_header") or "not_applicable_static_source_scan",
                "label": label,
                "agreement": agreement,
                "reviews": reviews,
                "raw_returned": False,
            }
        )
        labeled.append(row)

    return {
        "schema": LABEL_SCHEMA,
        "campaign_id": queue.get("campaign_id"),
        "source_revision": queue.get("source_revision"),
        "analyzer_package_tree_sha256": queue.get("analyzer_package_tree_sha256"),
        "holdout_protocol_manifest_sha256": queue.get("holdout_protocol_manifest_sha256"),
        "reviewers": reviewers,
        "review_provenance": {
            "independent_sessions": True,
            "cross_vendor_review": True,
            "required_vendors": sorted(REQUIRED_VENDORS),
            "distinct_vendor_count": len(vendors),
            "same_provider_model_family_ai_only": False,
            "not_human_review": True,
            "not_cross_vendor_review": False,
            "reviewed_pinned_source_and_candidate_queue": True,
            "candidate_bindings_sha256": binding_hash,
            "candidate_queue_sha256": queue_file_hash,
            "provider_identity_boundary": "Vendor CLI response artifacts and identifiers are hash-bound; provider identity is not cryptographically attested by K-Guard.",
        },
        "candidates": labeled,
        "claim_boundary": queue.get("claim_boundary", {}),
        "qualification_boundary": queue.get("qualification_boundary", {}),
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble three independent public-field candidate reviews.")
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--review", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_labels(args.queue, args.review)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    counts = Counter(row["label"] for row in payload["candidates"])
    print(json.dumps({"candidates": len(payload["candidates"]), "labels": dict(sorted(counts.items()))}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
