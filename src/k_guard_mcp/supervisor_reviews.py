from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any


SUPERVISOR_REVIEW_RECEIPTS_SCHEMA = "k_guard_supervisor_review_receipts.v5"
SUPERVISOR_REVIEW_DECISION_SCHEMA = "k_guard_supervisor_review_decision.v5"
PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA = "k_guard_supervisor_review_receipts.v4"
PREVIOUS_SUPERVISOR_REVIEW_DECISION_SCHEMA = "k_guard_supervisor_review_decision.v4"
LEGACY_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA = "k_guard_supervisor_review_receipts.v3"
LEGACY_SUPERVISOR_REVIEW_DECISION_SCHEMA = "k_guard_supervisor_review_decision.v3"
EARLIEST_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA = "k_guard_supervisor_review_receipts.v2"
EARLIEST_SUPERVISOR_REVIEW_DECISION_SCHEMA = "k_guard_supervisor_review_decision.v2"
DIRECT_FILE_ATTESTATION_SCHEMA = "k_guard_direct_file_tool_attestation.v1"
REQUIRED_MODELS = {
    "claude": "claude-opus-5",
    "grok": "grok-4.6",
}
PREVIOUS_REQUIRED_MODELS = {
    "claude": "claude-opus-4-8",
    "grok": "grok-4.5",
    "glm": "cline-pass/glm-5.2",
}
_SCHEMA_MODELS = {
    SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: REQUIRED_MODELS,
    PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: PREVIOUS_REQUIRED_MODELS,
    LEGACY_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: PREVIOUS_REQUIRED_MODELS,
    EARLIEST_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: PREVIOUS_REQUIRED_MODELS,
}
_CODED_SCHEMAS = frozenset(
    {
        SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        LEGACY_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
    }
)
_DIRECT_FILE_SCHEMAS = frozenset(
    {
        SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
    }
)
DIRECT_FILE_REVIEW_PROVIDERS = frozenset({"claude"})
REVIEW_SCOPES = {"direct-files", "sanitized-packet", "unavailable"}
VERDICTS = {"GO", "HOLD", "BLOCKED"}
BLOCKED_REASONS = {
    "BLOCKED_PROVIDER",
    "BLOCKED_AUTH",
    "BLOCKED_RATE_LIMIT",
    "BLOCKED_TIMEOUT",
}
REVIEW_CODES = frozenset(
    {
        "ARTIFACT_INTEGRITY_GAP",
        "CLAIM_BOUNDARY_GAP",
        "DIRECT_FILE_REVIEW_GAP",
        "EVIDENCE_BINDING_GAP",
        "MODEL_PINNING_GAP",
        "RAW_FREE_BOUNDARY_GAP",
        "RELEASE_NONPROMOTION_GAP",
        "REPEATABILITY_GAP",
        "TERMINAL_CONTRACT_GAP",
        "TEST_ATTESTATION_GAP",
    }
)
MAX_REVIEW_CODES = 100
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_FIELD_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


def validate_field_id(value: object) -> str:
    if not isinstance(value, str) or _FIELD_ID_RE.fullmatch(value) is None:
        raise ValueError("field_id is invalid")
    return value


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _required_models_for_schema(schema: str) -> dict[str, str]:
    try:
        return _SCHEMA_MODELS[schema]
    except KeyError as exc:
        raise ValueError("supervisor review receipt bundle schema is invalid") from exc


def evaluate_supervisor_review_receipts(payload: object) -> dict[str, Any]:
    """Fail closed when cross-provider review receipts cannot prove one shared target."""

    bundle = _validate_bundle(payload)
    receipts = bundle["receipts"]
    test_attestation = bundle["test_attestation"]
    required_models = _required_models_for_schema(bundle["schema"])
    verdicts = {receipt["provider"]: receipt["verdict"] for receipt in receipts}
    blocked = sorted(
        receipt["provider"]
        for receipt in receipts
        if receipt["verdict"] == "BLOCKED"
    )
    holds = sorted(
        receipt["provider"]
        for receipt in receipts
        if receipt["verdict"] == "HOLD"
    )
    tests_complete = all(test_attestation[name] is True for name in (
        "focused_passed",
        "full_regression_passed",
        "repeat_required",
        "repeat_exact",
    ))
    all_required_go = all(verdicts[provider] == "GO" for provider in required_models)
    direct_file_review_present = any(
        receipt["review_scope"] == "direct-files" and receipt["verdict"] == "GO"
        for receipt in receipts
    )
    claim_boundary_confirmed = all(
        receipt["claim_boundary_confirmed"] is True
        for receipt in receipts
        if receipt["verdict"] == "GO"
    )

    failure_reasons: list[str] = []
    if not tests_complete:
        failure_reasons.append("test_attestation_incomplete")
    if holds:
        failure_reasons.append("reviewer_hold")
    if not all_required_go:
        failure_reasons.append(
            "all_required_go_required"
            if bundle["schema"] == SUPERVISOR_REVIEW_RECEIPTS_SCHEMA
            else "all_three_go_required"
        )
    if not direct_file_review_present:
        failure_reasons.append("direct_file_review_required")
    if not claim_boundary_confirmed:
        failure_reasons.append("claim_boundary_unconfirmed")

    fixed = (
        tests_complete
        and not holds
        and all_required_go
        and direct_file_review_present
        and claim_boundary_confirmed
    )
    temporary = (
        tests_complete
        and not holds
        and bool(blocked)
        and any(receipt["verdict"] == "GO" for receipt in receipts)
        and claim_boundary_confirmed
    )
    status = "FIX" if fixed else "TEMPORARY_PENDING_REVIEW" if temporary else "HOLD"
    scope_counts = dict(sorted(Counter(receipt["review_scope"] for receipt in receipts).items()))
    blocked_reasons = {
        receipt["provider"]: receipt["blocked_reason"]
        for receipt in receipts
        if receipt["verdict"] == "BLOCKED"
    }

    decision_schema = {
        SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: SUPERVISOR_REVIEW_DECISION_SCHEMA,
        PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: PREVIOUS_SUPERVISOR_REVIEW_DECISION_SCHEMA,
        LEGACY_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: LEGACY_SUPERVISOR_REVIEW_DECISION_SCHEMA,
        EARLIEST_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA: EARLIEST_SUPERVISOR_REVIEW_DECISION_SCHEMA,
    }[bundle["schema"]]
    decision = {
        "schema": decision_schema,
        "field_id": bundle["field_id"],
        "target": bundle["target"],
        "evidence_manifest_sha256": bundle["evidence_manifest_sha256"],
        "review_packet_sha256": bundle["review_packet_sha256"],
        "review_count": len(receipts),
        "review_scope_counts": scope_counts,
        "verdicts": verdicts,
        "blocked_reasons": blocked_reasons,
        "status": status,
        "failure_reasons": failure_reasons,
        "authority": {
            "may_start_next_non_promoting_measurement": status in {"FIX", "TEMPORARY_PENDING_REVIEW"},
            "may_mark_field_fix": status == "FIX",
            "may_count_as_scorecard_achievement": status == "FIX",
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "raw_returned": False,
    }
    if bundle["schema"] in _CODED_SCHEMAS:
        decision["hold_codes"] = {
            receipt["provider"]: receipt["blocker_codes"]
            for receipt in receipts
            if receipt["verdict"] == "HOLD"
        }
        decision["nonblocking_codes"] = {
            receipt["provider"]: receipt["nonblocking_codes"]
            for receipt in receipts
            if receipt["nonblocking_codes"]
        }
    return decision


def _validate_bundle(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("supervisor review receipt bundle schema is invalid")
    schema = payload.get("schema")
    if schema not in {
        SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        LEGACY_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        EARLIEST_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
    }:
        raise ValueError("supervisor review receipt bundle schema is invalid")
    required = {
        "schema",
        "field_id",
        "target",
        "evidence_manifest_sha256",
        "review_packet_sha256",
        "test_attestation",
        "receipts",
        "raw_returned",
    }
    if schema in _DIRECT_FILE_SCHEMAS:
        required |= {"direct_file_count", "direct_file_set_sha256"}
    if set(payload) != required:
        raise ValueError("supervisor review receipt bundle schema is invalid")
    if payload.get("raw_returned") is not False:
        raise ValueError("supervisor review receipt bundle must be raw-free")
    field_id = validate_field_id(payload.get("field_id"))
    target = _validate_target(payload.get("target"), label="bundle target")
    evidence_manifest_sha256 = _require_sha256(
        payload.get("evidence_manifest_sha256"), "evidence_manifest_sha256"
    )
    review_packet_sha256 = _require_sha256(
        payload.get("review_packet_sha256"), "review_packet_sha256"
    )
    test_attestation = _validate_test_attestation(payload.get("test_attestation"))
    direct_file_binding = _validate_direct_file_binding(payload, schema=schema)
    receipts = payload.get("receipts")
    required_models = _required_models_for_schema(schema)
    if not isinstance(receipts, list) or len(receipts) != len(required_models):
        raise ValueError("the exact schema-bound supervisor receipt count is required")

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for receipt in receipts:
        normalized_receipt = _validate_receipt(
            receipt,
            schema=schema,
            target=target,
            evidence_manifest_sha256=evidence_manifest_sha256,
            review_packet_sha256=review_packet_sha256,
            direct_file_binding=direct_file_binding,
        )
        provider = normalized_receipt["provider"]
        if provider in seen:
            raise ValueError("supervisor provider is duplicated")
        seen.add(provider)
        normalized.append(normalized_receipt)
    if seen != set(required_models):
        raise ValueError("supervisor providers do not match the schema-bound model set")
    return {
        "schema": schema,
        "field_id": field_id,
        "target": target,
        "evidence_manifest_sha256": evidence_manifest_sha256,
        "review_packet_sha256": review_packet_sha256,
        "test_attestation": test_attestation,
        "direct_file_binding": direct_file_binding,
        "receipts": sorted(normalized, key=lambda item: item["provider"]),
    }


def _validate_target(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "head_git_oid", "dirty_path_set_sha256", "dirty_worktree_sha256"
    }:
        raise ValueError(f"{label} is invalid")
    head = value.get("head_git_oid")
    dirty_paths = value.get("dirty_path_set_sha256")
    dirty_worktree = value.get("dirty_worktree_sha256")
    if not isinstance(head, str) or _COMMIT_RE.fullmatch(head) is None:
        raise ValueError(f"{label} head_git_oid is invalid")
    if not isinstance(dirty_paths, str) or _SHA256_RE.fullmatch(dirty_paths) is None:
        raise ValueError(f"{label} dirty_path_set_sha256 is invalid")
    if not isinstance(dirty_worktree, str) or _SHA256_RE.fullmatch(dirty_worktree) is None:
        raise ValueError(f"{label} dirty_worktree_sha256 is invalid")
    return {
        "head_git_oid": head,
        "dirty_path_set_sha256": dirty_paths,
        "dirty_worktree_sha256": dirty_worktree,
    }


def _validate_test_attestation(value: object) -> dict[str, bool]:
    required = {
        "focused_passed",
        "full_regression_passed",
        "repeat_required",
        "repeat_exact",
        "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ValueError("test_attestation is invalid")
    result: dict[str, bool] = {"raw_returned": False}
    for name in required - {"raw_returned"}:
        observed = value.get(name)
        if not isinstance(observed, bool):
            raise ValueError("test_attestation is invalid")
        result[name] = observed
    return result


def _validate_receipt(
    value: object,
    *,
    schema: str,
    target: dict[str, str],
    evidence_manifest_sha256: str,
    review_packet_sha256: str,
    direct_file_binding: dict[str, Any] | None,
) -> dict[str, Any]:
    required = {
        "provider",
        "model",
        "review_scope",
        "target",
        "evidence_manifest_sha256",
        "review_packet_sha256",
        "verdict",
        "blocked_reason",
        "blocker_count",
        "nonblocking_count",
        "claim_boundary_confirmed",
        "raw_returned",
    }
    if schema in _CODED_SCHEMAS:
        required |= {"blocker_codes", "nonblocking_codes"}
    if schema in _DIRECT_FILE_SCHEMAS:
        required.add("direct_file_attestation")
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ValueError("supervisor receipt schema is invalid")
    provider = value.get("provider")
    required_models = _required_models_for_schema(schema)
    if provider not in required_models:
        raise ValueError("supervisor provider is invalid")
    if value.get("model") != required_models[provider]:
        raise ValueError("supervisor model identity is invalid")
    if _validate_target(value.get("target"), label="receipt target") != target:
        raise ValueError("supervisor receipt target does not match the shared target")
    if value.get("evidence_manifest_sha256") != evidence_manifest_sha256:
        raise ValueError("supervisor receipt evidence manifest does not match the shared packet")
    if value.get("review_packet_sha256") != review_packet_sha256:
        raise ValueError("supervisor receipt packet does not match the shared packet")
    verdict = value.get("verdict")
    review_scope = value.get("review_scope")
    if verdict not in VERDICTS or review_scope not in REVIEW_SCOPES:
        raise ValueError("supervisor receipt verdict or scope is invalid")
    if review_scope == "direct-files" and provider not in DIRECT_FILE_REVIEW_PROVIDERS:
        raise ValueError("direct-files review scope is not authorized for this provider")
    blocker_count = value.get("blocker_count")
    nonblocking_count = value.get("nonblocking_count")
    if (
        not isinstance(blocker_count, int)
        or isinstance(blocker_count, bool)
        or blocker_count < 0
        or not isinstance(nonblocking_count, int)
        or isinstance(nonblocking_count, bool)
        or nonblocking_count < 0
        or not isinstance(value.get("claim_boundary_confirmed"), bool)
    ):
        raise ValueError("supervisor receipt counts or claim boundary are invalid")
    blocked_reason = value.get("blocked_reason")
    blocker_codes: list[str] = []
    nonblocking_codes: list[str] = []
    if schema in _CODED_SCHEMAS:
        raw_blocker_codes = value.get("blocker_codes")
        raw_nonblocking_codes = value.get("nonblocking_codes")
        if (
            not isinstance(raw_blocker_codes, list)
            or not isinstance(raw_nonblocking_codes, list)
            or len(raw_blocker_codes) > MAX_REVIEW_CODES
            or len(raw_nonblocking_codes) > MAX_REVIEW_CODES
            or any(
                not isinstance(code, str) or code not in REVIEW_CODES
                for code in raw_blocker_codes + raw_nonblocking_codes
            )
            or len(raw_blocker_codes) != blocker_count
            or len(raw_nonblocking_codes) != nonblocking_count
        ):
            raise ValueError("supervisor receipt review codes are invalid")
        blocker_codes = sorted(raw_blocker_codes)
        nonblocking_codes = sorted(raw_nonblocking_codes)
    direct_file_attestation: dict[str, Any] | None = None
    if schema in _DIRECT_FILE_SCHEMAS:
        direct_file_attestation = _validate_direct_file_attestation(
            value.get("direct_file_attestation"),
            provider=provider,
            review_scope=review_scope,
            verdict=verdict,
            direct_file_binding=direct_file_binding,
        )
    if verdict == "GO":
        if (
            review_scope == "unavailable"
            or blocked_reason is not None
            or blocker_count != 0
            or value["claim_boundary_confirmed"] is not True
        ):
            raise ValueError("GO receipt is internally inconsistent")
    elif verdict == "HOLD":
        if review_scope == "unavailable" or blocked_reason is not None or blocker_count < 1:
            raise ValueError("HOLD receipt is internally inconsistent")
    else:
        if (
            review_scope != "unavailable"
            or blocked_reason not in BLOCKED_REASONS
            or blocker_count != 0
            or value["claim_boundary_confirmed"] is not False
        ):
            raise ValueError("BLOCKED receipt is internally inconsistent")
    normalized = {
        "provider": provider,
        "model": required_models[provider],
        "review_scope": review_scope,
        "target": target,
        "evidence_manifest_sha256": evidence_manifest_sha256,
        "review_packet_sha256": review_packet_sha256,
        "verdict": verdict,
        "blocked_reason": blocked_reason,
        "blocker_count": blocker_count,
        "nonblocking_count": nonblocking_count,
        "claim_boundary_confirmed": value["claim_boundary_confirmed"],
        "raw_returned": False,
    }
    if schema in _CODED_SCHEMAS:
        normalized["blocker_codes"] = blocker_codes
        normalized["nonblocking_codes"] = nonblocking_codes
    if schema in _DIRECT_FILE_SCHEMAS:
        normalized["direct_file_attestation"] = direct_file_attestation
    return normalized


def _validate_direct_file_binding(payload: dict[str, Any], *, schema: str) -> dict[str, Any] | None:
    if schema not in _DIRECT_FILE_SCHEMAS:
        return None
    required = {
        "schema",
        "field_id",
        "target",
        "evidence_manifest_sha256",
        "review_packet_sha256",
        "test_attestation",
        "direct_file_count",
        "direct_file_set_sha256",
        "receipts",
        "raw_returned",
    }
    if set(payload) != required:
        raise ValueError("supervisor review receipt bundle schema is invalid")
    count = payload.get("direct_file_count")
    digest = payload.get("direct_file_set_sha256")
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or count < 1
        or count > MAX_REVIEW_CODES
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
    ):
        raise ValueError("direct file binding is invalid")
    return {"count": count, "sha256": digest}


def _validate_direct_file_attestation(
    value: object,
    *,
    provider: str,
    review_scope: str,
    verdict: str,
    direct_file_binding: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if direct_file_binding is None:
        raise ValueError("direct file binding is invalid")
    if review_scope != "direct-files":
        if value is not None:
            raise ValueError("non-direct review must not claim direct file attestation")
        return None
    if provider not in DIRECT_FILE_REVIEW_PROVIDERS or verdict == "BLOCKED":
        raise ValueError("direct file attestation is invalid")
    required = {"schema", "file_count", "file_set_sha256", "raw_returned"}
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ValueError("direct file attestation is invalid")
    if (
        value.get("schema") != DIRECT_FILE_ATTESTATION_SCHEMA
        or value.get("file_count") != direct_file_binding["count"]
        or value.get("file_set_sha256") != direct_file_binding["sha256"]
    ):
        raise ValueError("direct file attestation does not match the bound file set")
    return {
        "schema": DIRECT_FILE_ATTESTATION_SCHEMA,
        "file_count": direct_file_binding["count"],
        "file_set_sha256": direct_file_binding["sha256"],
        "raw_returned": False,
    }


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


__all__ = [
    "DIRECT_FILE_REVIEW_PROVIDERS",
    "DIRECT_FILE_ATTESTATION_SCHEMA",
    "EARLIEST_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA",
    "LEGACY_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA",
    "MAX_REVIEW_CODES",
    "PREVIOUS_REQUIRED_MODELS",
    "REQUIRED_MODELS",
    "REVIEW_CODES",
    "PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA",
    "SUPERVISOR_REVIEW_DECISION_SCHEMA",
    "SUPERVISOR_REVIEW_RECEIPTS_SCHEMA",
    "canonical_json_bytes",
    "evaluate_supervisor_review_receipts",
    "sha256_bytes",
]
