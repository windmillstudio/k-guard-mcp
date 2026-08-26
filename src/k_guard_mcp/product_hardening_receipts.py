from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


CANONICAL_SUPERVISOR_RECEIPT_SCHEMA = "k_guard_product_supervisor_receipt.v1"
CANONICAL_SUPERVISOR_BUNDLE_SCHEMA = "k_guard_product_supervisor_bundle.v1"
CANONICAL_SUPERVISOR_DECISION_SCHEMA = "k_guard_product_supervisor_decision.v1"
QWEN_HEALTH_SCHEMA = "k_guard_qwen_parallel_health.v2"
CONTRACT_FREEZE_SCHEMA = "k-guard.contract-freeze-check.v1"

REQUIRED_REVIEWERS = ("sol", "opus", "grok")
MODEL_PINS = {
    "sol": {("gpt-5.6-sol", "gpt-5.6-sol")},
    "opus": {("claude-opus-5", "claude-opus-5")},
    "grok": {
        ("grok-4.5", "grok-4.5"),
        ("grok-4.5", "grok-4.5-build"),
    },
}
ATTESTATION_KINDS = {
    "sol": "deterministic",
    "opus": "source",
    "grok": "sanitized-packet",
}
VERDICTS = {"GO", "HOLD", "BLOCKED"}
HOLD_BLOCKER_CLASSES = {"code_change", "evidence_only"}
BLOCKED_BLOCKER_CLASSES = {"provider_failure"}

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_PHASE_RE = re.compile(r"phase-(?:[0-9]+|3c)\Z")

CANONICAL_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "receipt_context",
        "recorded_at",
        "phase_id",
        "attempt",
        "reviewer",
        "requested_model_id",
        "runtime_model_id",
        "session_id",
        "scope",
        "bindings",
        "usage",
        "independence",
        "decision",
        "evidence",
        "source",
        "validation",
        "raw_returned",
    }
)


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("receipt must be readable UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("receipt must be a JSON object")
    return value, raw


def canonicalize_actual_supervisor_receipt(
    source: Mapping[str, Any],
    *,
    source_path: str,
    source_sha256: str,
    source_canonical: bool,
) -> dict[str, Any]:
    """Project observed historical receipts into one loss-aware schema.

    Historical receipts remain ineligible for a product gate when the source
    did not record a required phase binding. Missing evidence is represented
    as null and never inferred from a neighboring artifact.
    """

    _require_sha256(source_sha256, "source_sha256")
    if source.get("schema") == "k_guard_sol_candidate_pre_gate.v1":
        receipt = _from_sol_pre_gate(source)
    elif source.get("schema") == "k_guard_retry_authority_supervisor_receipt.v1":
        receipt = _from_retry_authority(source)
    elif source.get("schema_version") == "1.0" and "contract_sha256" in source:
        receipt = _from_contract_review(source)
    else:
        raise ValueError("unsupported observed receipt schema")

    receipt["source"] = {
        "schema": _source_schema(source),
        "path": _require_nonempty(source_path, "source_path"),
        "sha256": source_sha256,
        "canonical": source_canonical,
    }
    receipt["validation"] = _validation_for(receipt)
    validate_canonical_supervisor_receipt(receipt, require_phase_review=False)
    return receipt


def canonicalize_actual_supervisor_receipt_file(path: Path, *, source_path: str | None = None) -> dict[str, Any]:
    source, raw = load_json_object(path)
    return canonicalize_actual_supervisor_receipt(
        source,
        source_path=source_path or path.as_posix(),
        source_sha256=sha256_bytes(raw),
        source_canonical=raw == canonical_json_bytes(source),
    )


def seal_product_phase_supervisor_receipt(
    *,
    recorded_at: str,
    phase_id: str,
    attempt: int,
    reviewer: str,
    requested_model_id: str,
    runtime_model_id: str,
    session_id: str,
    scope: str,
    contract_file_sha256: str,
    sealed_packet_sha256: str,
    candidate_commit: str | None,
    candidate_tree: str | None,
    usage: Mapping[str, int],
    peer_verdict_supplied: bool,
    verdict: str,
    source_verdict: str,
    product_approval: bool,
    blockers: Sequence[str],
    blocker_class: str | None,
    provider_envelope_path: str,
    provider_envelope_sha256: str,
    attestation_kind: str,
    attestation_path: str,
    attestation_sha256: str,
    source_schema: str,
    source_path: str,
    source_sha256: str,
) -> dict[str, Any]:
    """Seal a fully observed product-phase receipt into the canonical schema."""

    receipt = _receipt_base(
        context="phase_review",
        recorded_at=recorded_at,
        phase_id=phase_id,
        attempt=attempt,
        reviewer=reviewer,
        requested_model_id=requested_model_id,
        runtime_model_id=runtime_model_id,
        session_id=session_id,
        scope=scope,
        bindings={
            "contract_file_sha256": contract_file_sha256,
            "sealed_packet_sha256": sealed_packet_sha256,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
        },
        usage=dict(usage),
        peer_verdict_supplied=peer_verdict_supplied,
        verdict=verdict,
        source_verdict=source_verdict,
        product_approval=product_approval,
        blockers=list(blockers),
        blocker_class=blocker_class,
        provider_envelope_path=provider_envelope_path,
        provider_envelope_sha256=provider_envelope_sha256,
        attestation_kind=attestation_kind,
        attestation_path=attestation_path,
        attestation_sha256=attestation_sha256,
    )
    receipt["source"] = {
        "schema": source_schema,
        "path": source_path,
        "sha256": source_sha256,
        "canonical": True,
    }
    receipt["validation"] = _validation_for(receipt)
    return validate_canonical_supervisor_receipt(receipt)


def validate_canonical_supervisor_receipt(
    receipt: Mapping[str, Any],
    *,
    require_phase_review: bool = True,
) -> dict[str, Any]:
    if set(receipt) != CANONICAL_RECEIPT_FIELDS:
        raise ValueError("canonical supervisor receipt field set is invalid")
    if receipt.get("schema") != CANONICAL_SUPERVISOR_RECEIPT_SCHEMA:
        raise ValueError("canonical supervisor receipt schema is invalid")
    if receipt.get("raw_returned") is not False:
        raise ValueError("canonical supervisor receipt must be raw-free")

    context = receipt.get("receipt_context")
    if context not in {"phase_review", "contract_review", "retry_authority", "sol_pre_gate"}:
        raise ValueError("receipt_context is invalid")
    if require_phase_review and context != "phase_review":
        raise ValueError("historical receipt is not admissible for a product phase gate")

    reviewer = receipt.get("reviewer")
    if reviewer not in REQUIRED_REVIEWERS:
        raise ValueError("reviewer is invalid")
    _optional_nonempty(receipt.get("recorded_at"), "recorded_at")
    _optional_nonempty(receipt.get("requested_model_id"), "requested_model_id")
    _optional_nonempty(receipt.get("runtime_model_id"), "runtime_model_id")
    _optional_nonempty(receipt.get("session_id"), "session_id")
    _require_nonempty(receipt.get("scope"), "scope")
    _validate_bindings(receipt.get("bindings"))
    _validate_usage(receipt.get("usage"), optional=context != "phase_review")
    _validate_independence(receipt.get("independence"))
    _validate_decision(receipt.get("decision"))
    _validate_evidence(receipt.get("evidence"))
    _validate_source(receipt.get("source"))

    expected_validation = _validation_for(receipt)
    if receipt.get("validation") != expected_validation:
        raise ValueError("canonical supervisor receipt validation summary is stale or forged")
    if require_phase_review and not expected_validation["product_gate_admissible"]:
        raise ValueError(
            "product phase receipt is not admissible: "
            + ",".join(expected_validation["failure_reasons"])
        )
    return dict(receipt)


def evaluate_product_phase_receipts(bundle: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "phase_id",
        "attempt",
        "sealed_packet_sha256",
        "contract_file_sha256",
        "receipts",
        "raw_returned",
    }
    if set(bundle) != required or bundle.get("schema") != CANONICAL_SUPERVISOR_BUNDLE_SCHEMA:
        raise ValueError("product supervisor bundle schema is invalid")
    if bundle.get("raw_returned") is not False:
        raise ValueError("product supervisor bundle must be raw-free")
    phase_id = _require_phase(bundle.get("phase_id"))
    attempt = _require_positive_int(bundle.get("attempt"), "attempt")
    packet_sha = _require_sha256(bundle.get("sealed_packet_sha256"), "sealed_packet_sha256")
    contract_sha = _require_sha256(bundle.get("contract_file_sha256"), "contract_file_sha256")
    values = bundle.get("receipts")
    if not isinstance(values, list) or len(values) != 3:
        raise ValueError("exactly three product supervisor receipts are required")

    receipts: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("product supervisor receipt must be an object")
        normalized = validate_canonical_supervisor_receipt(value)
        reviewer = normalized["reviewer"]
        if reviewer in receipts:
            raise ValueError("product supervisor reviewer is duplicated")
        if (
            normalized["phase_id"] != phase_id
            or normalized["attempt"] != attempt
            or normalized["bindings"]["sealed_packet_sha256"] != packet_sha
            or normalized["bindings"]["contract_file_sha256"] != contract_sha
        ):
            raise ValueError("product supervisor receipts do not share one frozen target")
        receipts[reviewer] = normalized
    if set(receipts) != set(REQUIRED_REVIEWERS):
        raise ValueError("SOL, Opus, and Grok receipts are all required")
    sessions = [receipts[name]["session_id"] for name in REQUIRED_REVIEWERS]
    if len(set(sessions)) != 3:
        raise ValueError("product supervisor session IDs must be pairwise distinct")

    verdicts = {name: receipts[name]["decision"]["verdict"] for name in REQUIRED_REVIEWERS}
    all_go = all(verdicts[name] == "GO" for name in REQUIRED_REVIEWERS)
    return {
        "schema": CANONICAL_SUPERVISOR_DECISION_SCHEMA,
        "phase_id": phase_id,
        "attempt": attempt,
        "sealed_packet_sha256": packet_sha,
        "contract_file_sha256": contract_sha,
        "verdicts": verdicts,
        "status": "FIX" if all_go else "HOLD",
        "may_start_next_phase": all_go,
        "receipt_sha256": {
            name: sha256_bytes(canonical_json_bytes(receipts[name]))
            for name in REQUIRED_REVIEWERS
        },
        "raw_returned": False,
    }


def validate_qwen_parallel_health_v2(
    payload: Mapping[str, Any],
    *,
    expected_model_id: str = "qwen3.8-max-preview",
    expected_worker_count: int = 3,
) -> dict[str, Any]:
    required = {
        "all_exit_zero",
        "all_returned_healthy",
        "all_runtime_models_match",
        "all_usage_positive",
        "base_commit",
        "claim_boundary",
        "contract_file_sha256",
        "parallel_worker_count",
        "profile",
        "provider",
        "recorded_at_kst",
        "repo_clean_after",
        "repo_clean_before",
        "repository",
        "requested_model_id",
        "schema",
        "status",
        "tool",
        "workers",
    }
    if set(payload) != required or payload.get("schema") != QWEN_HEALTH_SCHEMA:
        raise ValueError("Qwen health v2 schema is invalid")
    if payload.get("requested_model_id") != expected_model_id:
        raise ValueError("Qwen requested model does not match the pin")
    if payload.get("parallel_worker_count") != expected_worker_count:
        raise ValueError("Qwen worker count does not match the contract")
    _require_commit(payload.get("base_commit"), "base_commit")
    _require_sha256(payload.get("contract_file_sha256"), "contract_file_sha256")
    if payload.get("repo_clean_before") is not True or payload.get("repo_clean_after") is not True:
        raise ValueError("Qwen health must not dirty the repository")
    workers = payload.get("workers")
    if not isinstance(workers, list) or len(workers) != expected_worker_count:
        raise ValueError("Qwen health worker list is invalid")
    for index, worker in enumerate(workers):
        if not isinstance(worker, dict):
            raise ValueError("Qwen health worker is invalid")
        if (
            worker.get("exit_code") != 0
            or worker.get("healthy") is not True
            or worker.get("runtime_model_id") != expected_model_id
            or worker.get("timed_out") is not False
        ):
            raise ValueError(f"Qwen health worker {index + 1} is not healthy")
        usage = worker.get("usage")
        if not isinstance(usage, dict) or not any(
            _is_positive_int(value) for key, value in usage.items() if key.endswith("_tokens")
        ):
            raise ValueError(f"Qwen health worker {index + 1} has no positive usage")
    aggregate_flags = (
        "all_exit_zero",
        "all_returned_healthy",
        "all_runtime_models_match",
        "all_usage_positive",
    )
    if any(payload.get(name) is not True for name in aggregate_flags) or payload.get("status") != "GO":
        raise ValueError("Qwen health aggregate is not GO")
    return {
        "schema": QWEN_HEALTH_SCHEMA,
        "status": "GO",
        "requested_model_id": expected_model_id,
        "worker_count": expected_worker_count,
        "base_commit": payload["base_commit"],
        "contract_file_sha256": payload["contract_file_sha256"],
    }


def validate_contract_freeze_receipt(
    payload: Mapping[str, Any],
    *,
    expected_phase_id: str,
    expected_event: str,
    expected_contract_sha256: str | None = None,
    expected_contract_byte_count: int | None = None,
) -> dict[str, Any]:
    required = {
        "checked_at",
        "checker_path",
        "checker_sha256",
        "contract_agreement_path",
        "contract_agreement_sha256",
        "contract_byte_count",
        "contract_file_sha256",
        "contract_path",
        "event",
        "phase_id",
        "schema_version",
        "status",
    }
    if set(payload) != required or payload.get("schema_version") != CONTRACT_FREEZE_SCHEMA:
        raise ValueError("contract freeze receipt schema is invalid")
    if payload.get("phase_id") != expected_phase_id or payload.get("event") != expected_event:
        raise ValueError("contract freeze receipt phase or event does not match")
    if payload.get("status") != "PASS":
        raise ValueError("contract freeze receipt is not PASS")
    contract_sha = _require_sha256(payload.get("contract_file_sha256"), "contract_file_sha256")
    contract_bytes = _require_positive_int(payload.get("contract_byte_count"), "contract_byte_count")
    _require_sha256(payload.get("checker_sha256"), "checker_sha256")
    _require_sha256(payload.get("contract_agreement_sha256"), "contract_agreement_sha256")
    if expected_contract_sha256 is not None and contract_sha != expected_contract_sha256:
        raise ValueError("contract freeze receipt hash does not match")
    if expected_contract_byte_count is not None and contract_bytes != expected_contract_byte_count:
        raise ValueError("contract freeze receipt byte count does not match")
    return {
        "schema": CONTRACT_FREEZE_SCHEMA,
        "status": "PASS",
        "phase_id": expected_phase_id,
        "event": expected_event,
        "contract_file_sha256": contract_sha,
        "contract_byte_count": contract_bytes,
    }


def _from_contract_review(source: Mapping[str, Any]) -> dict[str, Any]:
    reviewer = _reviewer_from_label(source.get("reviewer"))
    blockers = _string_list(source.get("blockers"), "blockers")
    verdict = source.get("verdict")
    if verdict not in {"GO", "HOLD", "BLOCKED"}:
        raise ValueError("contract review verdict is invalid")
    return _receipt_base(
        context="contract_review",
        recorded_at=source.get("recorded_at"),
        phase_id=None,
        attempt=None,
        reviewer=reviewer,
        requested_model_id=source.get("requested_model"),
        runtime_model_id=source.get("runtime_model"),
        session_id=source.get("session_id"),
        scope=source.get("scope"),
        bindings={
            "contract_file_sha256": source.get("contract_sha256"),
            "sealed_packet_sha256": None,
            "candidate_commit": None,
            "candidate_tree": None,
        },
        usage=_normalize_usage(source.get("usage")),
        peer_verdict_supplied=source.get("peer_verdict_supplied"),
        verdict=verdict,
        source_verdict=verdict,
        product_approval=source.get("product_approval") is True,
        blockers=blockers,
        blocker_class="code_change" if verdict == "HOLD" and blockers else None,
        provider_envelope_path=None,
        provider_envelope_sha256=source.get("provider_envelope_sha256"),
        attestation_kind="source" if source.get("direct_file_read") is True else None,
        attestation_path=None,
        attestation_sha256=None,
    )


def _from_retry_authority(source: Mapping[str, Any]) -> dict[str, Any]:
    reviewer = _reviewer_from_label(source.get("reviewer"))
    source_verdict = _require_nonempty(source.get("verdict"), "verdict")
    denied = source_verdict.startswith("DENY_")
    validation = source.get("validation")
    if not isinstance(validation, dict):
        raise ValueError("retry authority validation is invalid")
    return _receipt_base(
        context="retry_authority",
        recorded_at=source.get("recorded_at_kst"),
        phase_id=source.get("phase_id"),
        attempt=None,
        reviewer=reviewer,
        requested_model_id=source.get("requested_model_id"),
        runtime_model_id=source.get("runtime_model_id"),
        session_id=source.get("session_id"),
        scope=source.get("scope"),
        bindings={
            "contract_file_sha256": None,
            "sealed_packet_sha256": None,
            "candidate_commit": None,
            "candidate_tree": None,
        },
        usage=None,
        peer_verdict_supplied=validation.get("peer_verdict_supplied"),
        verdict="HOLD" if denied else "GO",
        source_verdict=source_verdict,
        product_approval=validation.get("product_approval") is True,
        blockers=["retry_authority_denied"] if denied else [],
        blocker_class="code_change" if denied else None,
        provider_envelope_path=source.get("provider_envelope_path"),
        provider_envelope_sha256=source.get("provider_envelope_sha256"),
        attestation_kind=None,
        attestation_path=None,
        attestation_sha256=source.get("review_result_sha256"),
    )


def _from_sol_pre_gate(source: Mapping[str, Any]) -> dict[str, Any]:
    verdict = source.get("verdict")
    if verdict not in VERDICTS:
        raise ValueError("SOL pre-gate verdict is invalid")
    blockers: list[str] = []
    probes = source.get("actual_artifact_probes")
    if isinstance(probes, list):
        blockers.extend(
            item["id"]
            for item in probes
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        )
    findings = source.get("direct_review_findings")
    if isinstance(findings, list):
        blockers.extend(
            f"direct-review-{index + 1}"
            for index, item in enumerate(findings)
            if isinstance(item, dict)
        )
    return _receipt_base(
        context="sol_pre_gate",
        recorded_at=source.get("recorded_at_kst"),
        phase_id=source.get("phase_id"),
        attempt=source.get("implementation_attempt"),
        reviewer="sol",
        requested_model_id=None,
        runtime_model_id=None,
        session_id=None,
        scope="candidate_pre_gate",
        bindings={
            "contract_file_sha256": source.get("contract_file_sha256"),
            "sealed_packet_sha256": None,
            "candidate_commit": source.get("candidate_commit"),
            "candidate_tree": source.get("candidate_tree"),
        },
        usage=None,
        peer_verdict_supplied=None,
        verdict=verdict,
        source_verdict=_require_nonempty(source.get("status"), "status"),
        product_approval=False,
        blockers=blockers,
        blocker_class=source.get("blocker_class"),
        provider_envelope_path=None,
        provider_envelope_sha256=None,
        attestation_kind="deterministic",
        attestation_path=source.get("qwen_run_validation_path"),
        attestation_sha256=None,
    )


def _receipt_base(
    *,
    context: str,
    recorded_at: object,
    phase_id: object,
    attempt: object,
    reviewer: str,
    requested_model_id: object,
    runtime_model_id: object,
    session_id: object,
    scope: object,
    bindings: dict[str, Any],
    usage: dict[str, int] | None,
    peer_verdict_supplied: object,
    verdict: str,
    source_verdict: str,
    product_approval: bool,
    blockers: list[str],
    blocker_class: object,
    provider_envelope_path: object,
    provider_envelope_sha256: object,
    attestation_kind: object,
    attestation_path: object,
    attestation_sha256: object,
) -> dict[str, Any]:
    return {
        "schema": CANONICAL_SUPERVISOR_RECEIPT_SCHEMA,
        "receipt_context": context,
        "recorded_at": recorded_at,
        "phase_id": phase_id,
        "attempt": attempt,
        "reviewer": reviewer,
        "requested_model_id": requested_model_id,
        "runtime_model_id": runtime_model_id,
        "session_id": session_id,
        "scope": scope,
        "bindings": bindings,
        "usage": usage,
        "independence": {"peer_verdict_supplied": peer_verdict_supplied},
        "decision": {
            "verdict": verdict,
            "source_verdict": source_verdict,
            "product_approval": product_approval,
            "blockers": blockers,
            "blocker_class": blocker_class,
        },
        "evidence": {
            "provider_envelope_path": provider_envelope_path,
            "provider_envelope_sha256": provider_envelope_sha256,
            "attestation_kind": attestation_kind,
            "attestation_path": attestation_path,
            "attestation_sha256": attestation_sha256,
            "raw_returned": False,
        },
        "source": {},
        "validation": {},
        "raw_returned": False,
    }


def _validation_for(receipt: Mapping[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    context = receipt.get("receipt_context")
    reviewer = receipt.get("reviewer")
    if context != "phase_review":
        reasons.append("not_phase_review")
    if not _nonempty(receipt.get("recorded_at")):
        reasons.append("recorded_at_missing")
    if not _nonempty(receipt.get("session_id")):
        reasons.append("session_id_missing")
    if not isinstance(receipt.get("phase_id"), str) or _PHASE_RE.fullmatch(receipt["phase_id"]) is None:
        reasons.append("phase_id_missing_or_invalid")
    if not _is_positive_int(receipt.get("attempt")):
        reasons.append("attempt_missing_or_invalid")
    bindings = receipt.get("bindings")
    if not isinstance(bindings, dict) or not _is_sha256(bindings.get("sealed_packet_sha256")):
        reasons.append("sealed_packet_binding_missing")
    if not isinstance(bindings, dict) or not _is_sha256(bindings.get("contract_file_sha256")):
        reasons.append("contract_binding_missing")
    model_pair = (receipt.get("requested_model_id"), receipt.get("runtime_model_id"))
    exact_model = reviewer in MODEL_PINS and model_pair in MODEL_PINS[reviewer]
    if not exact_model:
        reasons.append("model_binding_invalid")
    positive_usage = _usage_positive(receipt.get("usage"))
    if not positive_usage:
        reasons.append("positive_usage_missing")
    independence = receipt.get("independence")
    peer_independent = (
        isinstance(independence, dict)
        and independence.get("peer_verdict_supplied") is False
    )
    if not peer_independent:
        reasons.append("peer_independence_missing")
    evidence = receipt.get("evidence")
    expected_attestation = ATTESTATION_KINDS.get(reviewer)
    evidence_complete = (
        isinstance(evidence, dict)
        and _nonempty(evidence.get("provider_envelope_path"))
        and _is_sha256(evidence.get("provider_envelope_sha256"))
        and evidence.get("attestation_kind") == expected_attestation
        and _nonempty(evidence.get("attestation_path"))
        and _is_sha256(evidence.get("attestation_sha256"))
        and evidence.get("raw_returned") is False
    )
    if not evidence_complete:
        reasons.append("evidence_binding_incomplete")
    source = receipt.get("source")
    source_canonical = isinstance(source, dict) and source.get("canonical") is True
    if not source_canonical:
        reasons.append("source_not_canonical")
    decision_valid = _decision_is_internally_consistent(receipt.get("decision"))
    if not decision_valid:
        reasons.append("decision_inconsistent")
    return {
        "exact_model_binding": exact_model,
        "positive_usage": positive_usage,
        "peer_independent": peer_independent,
        "evidence_binding_complete": evidence_complete,
        "source_canonical": source_canonical,
        "decision_consistent": decision_valid,
        "product_gate_admissible": not reasons,
        "failure_reasons": sorted(reasons),
    }


def _validate_bindings(value: object) -> None:
    required = {
        "contract_file_sha256",
        "sealed_packet_sha256",
        "candidate_commit",
        "candidate_tree",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("receipt bindings are invalid")
    for name in ("contract_file_sha256", "sealed_packet_sha256"):
        if value[name] is not None:
            _require_sha256(value[name], name)
    for name in ("candidate_commit", "candidate_tree"):
        if value[name] is not None:
            _require_commit(value[name], name)


def _validate_usage(value: object, *, optional: bool) -> None:
    if value is None and optional:
        return
    if not _usage_positive(value):
        raise ValueError("receipt usage is invalid")


def _validate_independence(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"peer_verdict_supplied"}
        or value["peer_verdict_supplied"] not in {True, False, None}
    ):
        raise ValueError("receipt independence is invalid")


def _validate_decision(value: object) -> None:
    required = {
        "verdict",
        "source_verdict",
        "product_approval",
        "blockers",
        "blocker_class",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("receipt decision is invalid")
    if value.get("verdict") not in VERDICTS:
        raise ValueError("receipt verdict is invalid")
    _require_nonempty(value.get("source_verdict"), "source_verdict")
    if not isinstance(value.get("product_approval"), bool):
        raise ValueError("product_approval is invalid")
    _string_list(value.get("blockers"), "blockers")
    blocker_class = value.get("blocker_class")
    if blocker_class is not None and not isinstance(blocker_class, str):
        raise ValueError("blocker_class is invalid")


def _validate_evidence(value: object) -> None:
    required = {
        "provider_envelope_path",
        "provider_envelope_sha256",
        "attestation_kind",
        "attestation_path",
        "attestation_sha256",
        "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ValueError("receipt evidence is invalid")
    for name in ("provider_envelope_path", "attestation_path", "attestation_kind"):
        _optional_nonempty(value.get(name), name)
    for name in ("provider_envelope_sha256", "attestation_sha256"):
        if value.get(name) is not None:
            _require_sha256(value[name], name)


def _validate_source(value: object) -> None:
    required = {"schema", "path", "sha256", "canonical"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("receipt source is invalid")
    _require_nonempty(value.get("schema"), "source.schema")
    _require_nonempty(value.get("path"), "source.path")
    _require_sha256(value.get("sha256"), "source.sha256")
    if not isinstance(value.get("canonical"), bool):
        raise ValueError("source.canonical is invalid")


def _decision_is_internally_consistent(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    verdict = value.get("verdict")
    approval = value.get("product_approval")
    blockers = value.get("blockers")
    blocker_class = value.get("blocker_class")
    if not isinstance(blockers, list):
        return False
    if verdict == "GO":
        return approval is True and blockers == [] and blocker_class is None
    if verdict == "HOLD":
        return approval is False and bool(blockers) and blocker_class in HOLD_BLOCKER_CLASSES
    if verdict == "BLOCKED":
        return approval is False and bool(blockers) and blocker_class in BLOCKED_BLOCKER_CLASSES
    return False


def _normalize_usage(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    input_tokens = value.get("input_tokens")
    output_tokens = value.get("output_tokens")
    total_tokens = value.get("total_tokens", value.get("total_tokens_derived"))
    if not all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in (input_tokens, output_tokens)):
        return None
    if not _is_positive_int(total_tokens):
        return None
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _usage_positive(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"input_tokens", "output_tokens", "total_tokens"}
        and isinstance(value["input_tokens"], int)
        and not isinstance(value["input_tokens"], bool)
        and value["input_tokens"] >= 0
        and isinstance(value["output_tokens"], int)
        and not isinstance(value["output_tokens"], bool)
        and value["output_tokens"] >= 0
        and _is_positive_int(value["total_tokens"])
    )


def _reviewer_from_label(value: object) -> str:
    labels = {
        "Claude Opus 5": "opus",
        "Grok 4.5": "grok",
        "CODEX SOL": "sol",
    }
    if value not in labels:
        raise ValueError("observed reviewer label is unsupported")
    return labels[value]


def _source_schema(source: Mapping[str, Any]) -> str:
    value = source.get("schema")
    if isinstance(value, str) and value:
        return value
    value = source.get("schema_version")
    if isinstance(value, str) and value:
        return f"contract-review-receipt.{value}"
    raise ValueError("source receipt schema is missing")


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{label} must be a list of non-empty strings")
    return list(value)


def _require_nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is invalid")
    return value


def _optional_nonempty(value: object, label: str) -> None:
    if value is not None:
        _require_nonempty(value, label)


def _require_phase(value: object) -> str:
    if not isinstance(value, str) or _PHASE_RE.fullmatch(value) is None:
        raise ValueError("phase_id is invalid")
    return value


def _require_sha256(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{label} is invalid")
    return value


def _require_commit(value: object, label: str) -> str:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _require_positive_int(value: object, label: str) -> int:
    if not _is_positive_int(value):
        raise ValueError(f"{label} is invalid")
    return value


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonempty(value: object) -> bool:
    return isinstance(value, str) and bool(value)


__all__ = [
    "CANONICAL_RECEIPT_FIELDS",
    "CANONICAL_SUPERVISOR_BUNDLE_SCHEMA",
    "CANONICAL_SUPERVISOR_DECISION_SCHEMA",
    "CANONICAL_SUPERVISOR_RECEIPT_SCHEMA",
    "CONTRACT_FREEZE_SCHEMA",
    "MODEL_PINS",
    "QWEN_HEALTH_SCHEMA",
    "REQUIRED_REVIEWERS",
    "canonical_json_bytes",
    "canonicalize_actual_supervisor_receipt",
    "canonicalize_actual_supervisor_receipt_file",
    "evaluate_product_phase_receipts",
    "load_json_object",
    "seal_product_phase_supervisor_receipt",
    "sha256_bytes",
    "validate_canonical_supervisor_receipt",
    "validate_contract_freeze_receipt",
    "validate_qwen_parallel_health_v2",
]
