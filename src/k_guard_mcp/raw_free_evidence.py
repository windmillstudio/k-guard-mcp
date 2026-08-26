from __future__ import annotations

import re
from collections import Counter
from typing import Any


PUBLIC_CANDIDATE_QUEUE_SCHEMA = "k_guard_public_candidate_queue.v2"
_CANDIDATE_ID_RE = re.compile(r"^[0-9a-f]{20}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SUBTYPE_RE = re.compile(r"^[a-z0-9][a-z0-9_:-]{0,127}$")
_SCOPE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _safe_location_ref(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > 512:
        return False
    if any(character in value for character in "\x00\r\n\\"):
        return False
    if value.startswith(("/", "http://", "https://")):
        return False
    return all(part not in {"", ".", ".."} for part in value.split("/"))


def public_candidate_evidence_shape_valid(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    candidate_id = str(row.get("candidate_id") or "")
    fingerprint = str(row.get("redacted_fingerprint") or "")
    source_location = str(row.get("source_location") or "")
    location = row.get("location")
    if (
        _CANDIDATE_ID_RE.fullmatch(candidate_id) is None
        or fingerprint != f"sha256-truncated:{candidate_id}"
        or row.get("severity") not in {"high", "critical"}
        or not isinstance(row.get("detector_subtype"), str)
        or _SUBTYPE_RE.fullmatch(row["detector_subtype"]) is None
        or not isinstance(row.get("artifact_scope"), str)
        or _SCOPE_RE.fullmatch(row["artifact_scope"]) is None
        or not isinstance(row.get("scan_report_sha256"), str)
        or _SHA256_RE.fullmatch(row["scan_report_sha256"]) is None
        or not _safe_location_ref(source_location)
        or not isinstance(location, dict)
        or set(location) != {"kind", "source", "body_or_header"}
        or row.get("raw_returned") is not False
    ):
        return False

    response_hash = row.get("response_hash")
    if location["kind"] == "source":
        return (
            location.get("source") == source_location
            and location.get("body_or_header") is None
            and response_hash is None
        )
    if location["kind"] == "response":
        return (
            _safe_location_ref(location.get("source"))
            and location.get("body_or_header") in {"body", "header"}
            and isinstance(response_hash, str)
            and _SHA256_RE.fullmatch(response_hash) is not None
        )
    return False


def summarize_public_candidate_queue(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != PUBLIC_CANDIDATE_QUEUE_SCHEMA:
        raise ValueError("public candidate queue schema is invalid")
    if payload.get("raw_returned") is not False:
        raise ValueError("public candidate queue must be raw-free")
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("public candidate queue is empty or invalid")
    if any(not public_candidate_evidence_shape_valid(row) for row in candidates):
        raise ValueError("public candidate evidence shape is invalid")

    locations = Counter(str(row["location"]["kind"]) for row in candidates)
    severities = Counter(str(row["severity"]) for row in candidates)
    source_rows = [row for row in candidates if row["location"]["kind"] == "source"]
    response_rows = [row for row in candidates if row["location"]["kind"] == "response"]
    return {
        "candidate_count": len(candidates),
        "location_kind_counts": dict(sorted(locations.items())),
        "response_candidate_count": len(response_rows),
        "response_hashed_count": sum(isinstance(row["response_hash"], str) for row in response_rows),
        "severity_counts": dict(sorted(severities.items())),
        "source_candidate_count": len(source_rows),
        "source_null_response_hash_count": sum(row["response_hash"] is None for row in source_rows),
        "raw_returned": False,
    }
