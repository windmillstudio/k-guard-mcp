from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
INPUT_SCHEMA = "k_guard_l3_source_flow_aggregate_input.v1"
AGGREGATE_SCHEMA = "k_guard_l3_source_flow_aggregate.v1"
AGGREGATE_HASH_SCHEMA = "k_guard_l3_source_flow_aggregate_sha256.v1"
SLOT_ORDER = (
    "site-01",
    "site-02",
    "site-03",
    "site-04",
    "site-05",
    "site-06",
    "site-07",
    "site-08",
    "site-09",
    "site-10",
    "site-11",
    "site-12",
    "site-13",
    "site-14",
    "site-15",
    "data-03",
    "data-07",
    "data-09",
    "data-14",
)
EXPECTED_COUNTS = {
    "slot_count": 19,
    "candidate_count": 38,
    "primary_candidate_count": 19,
    "reserve_candidate_count": 19,
    "source_triplet_count": 114,
    "source_file_count": 342,
}
SOURCE_SCHEMA_PREFIX = "k_guard_l3_source_flow_"
SUPERVISOR_SCHEMA = "k_guard_supervisor_repeat_comparison.v1"


class SourceFlowAggregateError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise SourceFlowAggregateError("aggregate_duplicate_json_key")
        result[key] = item
    return result


def _read_json(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceFlowAggregateError(f"aggregate_{label}_unreadable") from exc
    if not isinstance(value, dict):
        raise SourceFlowAggregateError(f"aggregate_{label}_invalid")
    return value, raw


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT)
        return True
    except ValueError:
        return False


def _external_regular_file(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or _is_within_repository(path):
        raise SourceFlowAggregateError(f"aggregate_{label}_must_be_external_regular_file")
    return path.resolve(strict=True)


def _external_new_output(path: Path) -> Path:
    if not path.is_absolute() or _is_within_repository(path) or path.exists() or path.is_symlink():
        raise SourceFlowAggregateError("aggregate_output_must_be_new_external_path")
    return path.resolve(strict=False)


def _require_exact_keys(value: object, expected: set[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise SourceFlowAggregateError(f"aggregate_{label}_keys_invalid")
    return value


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise SourceFlowAggregateError(f"aggregate_{label}_sha256_invalid")
    try:
        int(value, 16)
    except ValueError as exc:
        raise SourceFlowAggregateError(f"aggregate_{label}_sha256_invalid") from exc
    return value


def _slot_token(slot_id: str) -> str:
    return "".join(character for character in slot_id.lower() if character.isalnum())


def _validate_authority(value: object, *, label: str, require_slot_scope: bool = False) -> None:
    if not isinstance(value, dict) or value.get("may_mark_field_fix") is not True:
        raise SourceFlowAggregateError(f"aggregate_{label}_authority_invalid")
    for key in (
        "may_affect_h100_or_release",
        "may_affect_oracle_labels",
        "may_affect_performance_metrics",
    ):
        if value.get(key) is not False:
            raise SourceFlowAggregateError(f"aggregate_{label}_authority_scope_invalid")
    if require_slot_scope and value.get("may_affect_other_slots") is not False:
        raise SourceFlowAggregateError(f"aggregate_{label}_authority_slot_scope_invalid")


def _validate_source_comparison(value: object, *, slot_id: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise SourceFlowAggregateError("aggregate_source_comparison_invalid")
    schema = value.get("schema")
    if not isinstance(schema, str) or not schema.startswith(SOURCE_SCHEMA_PREFIX) or "repeat_comparison" not in schema:
        raise SourceFlowAggregateError("aggregate_source_comparison_schema_invalid")
    if value.get("slot_id") != slot_id or value.get("status") != "FIX" or value.get("repeat_exact") is not True:
        raise SourceFlowAggregateError("aggregate_source_comparison_status_invalid")
    if value.get("raw_source_returned") is not False:
        raise SourceFlowAggregateError("aggregate_source_comparison_raw_invalid")
    first = _require_sha256(value.get("first_semantic_fingerprint_sha256"), label="source_first_semantic")
    second = _require_sha256(value.get("second_semantic_fingerprint_sha256"), label="source_second_semantic")
    if first != second:
        raise SourceFlowAggregateError("aggregate_source_comparison_semantic_mismatch")
    _validate_authority(value.get("authority"), label="source_comparison", require_slot_scope=True)
    boundary = value.get("claim_boundary")
    if not isinstance(boundary, dict):
        raise SourceFlowAggregateError("aggregate_source_comparison_boundary_invalid")
    for key in ("detector_accuracy_proven", "execution_oracles_proved", "release_gate_admitted"):
        if boundary.get(key) is not False:
            raise SourceFlowAggregateError("aggregate_source_comparison_boundary_scope_invalid")
    if not any(
        key == "source_triplets_materialized" or key.endswith("_source_triplets_materialized")
        for key, item in boundary.items()
        if item is True
    ):
        raise SourceFlowAggregateError("aggregate_source_comparison_materialization_claim_missing")
    return {"schema": schema, "semantic_fingerprint_sha256": first}


def _validate_supervisor_comparison(value: object, *, slot_id: str) -> dict[str, str]:
    if not isinstance(value, dict) or value.get("schema") != SUPERVISOR_SCHEMA:
        raise SourceFlowAggregateError("aggregate_supervisor_comparison_schema_invalid")
    field_id = value.get("field_id")
    if not isinstance(field_id, str) or _slot_token(slot_id) not in _slot_token(field_id):
        raise SourceFlowAggregateError("aggregate_supervisor_comparison_field_invalid")
    if value.get("status") != "FIX" or value.get("repeat_exact") is not True or value.get("raw_returned") is not False:
        raise SourceFlowAggregateError("aggregate_supervisor_comparison_status_invalid")
    first = _require_sha256(value.get("first_semantic_fingerprint_sha256"), label="supervisor_first_semantic")
    second = _require_sha256(value.get("second_semantic_fingerprint_sha256"), label="supervisor_second_semantic")
    if first != second:
        raise SourceFlowAggregateError("aggregate_supervisor_comparison_semantic_mismatch")
    _validate_authority(value.get("authority"), label="supervisor_comparison")
    return {"field_id": field_id, "semantic_fingerprint_sha256": first}


def _parse_input(path: Path) -> list[dict[str, str]]:
    input_path = _external_regular_file(path, label="input")
    value, _ = _read_json(input_path, label="input")
    payload = _require_exact_keys(value, {"schema", "leaves", "raw_returned"}, label="input")
    if payload["schema"] != INPUT_SCHEMA or payload["raw_returned"] is not False or not isinstance(payload["leaves"], list):
        raise SourceFlowAggregateError("aggregate_input_contract_invalid")
    if len(payload["leaves"]) != len(SLOT_ORDER):
        raise SourceFlowAggregateError("aggregate_input_leaf_count_invalid")

    leaves: list[dict[str, str]] = []
    for item in payload["leaves"]:
        entry = _require_exact_keys(
            item,
            {"slot_id", "source_comparison_path", "supervisor_comparison_path"},
            label="input_leaf",
        )
        if not all(isinstance(entry[key], str) and entry[key] for key in entry):
            raise SourceFlowAggregateError("aggregate_input_leaf_value_invalid")
        leaves.append({key: str(entry[key]) for key in entry})
    if [entry["slot_id"] for entry in leaves] != list(SLOT_ORDER):
        raise SourceFlowAggregateError("aggregate_input_slot_order_invalid")
    if len({entry["source_comparison_path"] for entry in leaves}) != len(leaves):
        raise SourceFlowAggregateError("aggregate_input_source_path_duplicate")
    if len({entry["supervisor_comparison_path"] for entry in leaves}) != len(leaves):
        raise SourceFlowAggregateError("aggregate_input_supervisor_path_duplicate")
    return leaves


def build_aggregate(input_path: Path, output_path: Path) -> dict[str, Any]:
    leaves = _parse_input(input_path)
    resolved_paths: list[Path] = []
    resolved_leaves: list[tuple[str, Path, Path]] = []
    for entry in leaves:
        source_path = _external_regular_file(Path(entry["source_comparison_path"]), label="source_comparison")
        supervisor_path = _external_regular_file(Path(entry["supervisor_comparison_path"]), label="supervisor_comparison")
        if source_path == supervisor_path:
            raise SourceFlowAggregateError("aggregate_leaf_evidence_path_overlap")
        resolved_paths.extend((source_path, supervisor_path))
        resolved_leaves.append((entry["slot_id"], source_path, supervisor_path))
    if len(set(resolved_paths)) != len(resolved_paths):
        raise SourceFlowAggregateError("aggregate_evidence_path_overlap")

    evidence: list[dict[str, Any]] = []
    for slot_id, source_path, supervisor_path in resolved_leaves:
        source_value, source_raw = _read_json(source_path, label="source_comparison")
        supervisor_value, supervisor_raw = _read_json(supervisor_path, label="supervisor_comparison")
        source = _validate_source_comparison(source_value, slot_id=slot_id)
        supervisor = _validate_supervisor_comparison(supervisor_value, slot_id=slot_id)
        evidence.append(
            {
                "slot_id": slot_id,
                "source_comparison": {
                    **source,
                    "evidence_sha256": sha256_bytes(source_raw),
                },
                "supervisor_comparison": {
                    **supervisor,
                    "evidence_sha256": sha256_bytes(supervisor_raw),
                },
            }
        )

    result: dict[str, Any] = {
        "schema": AGGREGATE_SCHEMA,
        "aggregate_hash_schema": AGGREGATE_HASH_SCHEMA,
        "slot_order": list(SLOT_ORDER),
        "counts": dict(EXPECTED_COUNTS),
        "excluded_slot_ids": [],
        "leaf_evidence": evidence,
        "claim_boundary": {
            "source_triplet_inventory_complete": True,
            "execution_oracles_proved": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }
    result["aggregate_sha256"] = sha256_bytes(canonical_json_bytes(result))
    validate_aggregate(result)
    write_aggregate(output_path, result)
    return result


def validate_aggregate(value: object) -> dict[str, Any]:
    result = _require_exact_keys(
        value,
        {
            "schema",
            "aggregate_hash_schema",
            "slot_order",
            "counts",
            "excluded_slot_ids",
            "leaf_evidence",
            "claim_boundary",
            "raw_returned",
            "aggregate_sha256",
        },
        label="result",
    )
    if result["schema"] != AGGREGATE_SCHEMA or result["aggregate_hash_schema"] != AGGREGATE_HASH_SCHEMA:
        raise SourceFlowAggregateError("aggregate_result_schema_invalid")
    if result["slot_order"] != list(SLOT_ORDER) or result["counts"] != EXPECTED_COUNTS:
        raise SourceFlowAggregateError("aggregate_result_denominator_invalid")
    if result["excluded_slot_ids"] != [] or result["raw_returned"] is not False:
        raise SourceFlowAggregateError("aggregate_result_exclusion_or_raw_invalid")
    if not isinstance(result["leaf_evidence"], list) or len(result["leaf_evidence"]) != len(SLOT_ORDER):
        raise SourceFlowAggregateError("aggregate_result_leaf_count_invalid")
    expected_leaf_keys = {"slot_id", "source_comparison", "supervisor_comparison"}
    for slot_id, item in zip(SLOT_ORDER, result["leaf_evidence"], strict=True):
        leaf = _require_exact_keys(item, expected_leaf_keys, label="result_leaf")
        if leaf["slot_id"] != slot_id:
            raise SourceFlowAggregateError("aggregate_result_slot_order_invalid")
        source = _require_exact_keys(
            leaf["source_comparison"],
            {"schema", "semantic_fingerprint_sha256", "evidence_sha256"},
            label="result_source",
        )
        supervisor = _require_exact_keys(
            leaf["supervisor_comparison"],
            {"field_id", "semantic_fingerprint_sha256", "evidence_sha256"},
            label="result_supervisor",
        )
        if (
            not isinstance(source["schema"], str)
            or not source["schema"].startswith(SOURCE_SCHEMA_PREFIX)
            or "repeat_comparison" not in source["schema"]
        ):
            raise SourceFlowAggregateError("aggregate_result_source_schema_invalid")
        if not isinstance(supervisor["field_id"], str) or _slot_token(slot_id) not in _slot_token(supervisor["field_id"]):
            raise SourceFlowAggregateError("aggregate_result_supervisor_field_invalid")
        for digest in (
            source["semantic_fingerprint_sha256"],
            source["evidence_sha256"],
            supervisor["semantic_fingerprint_sha256"],
            supervisor["evidence_sha256"],
        ):
            _require_sha256(digest, label="result_evidence")
    boundary = _require_exact_keys(
        result["claim_boundary"],
        {
            "source_triplet_inventory_complete",
            "execution_oracles_proved",
            "detector_accuracy_proven",
            "release_gate_admitted",
            "raw_returned",
        },
        label="result_boundary",
    )
    if boundary != {
        "source_triplet_inventory_complete": True,
        "execution_oracles_proved": False,
        "detector_accuracy_proven": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }:
        raise SourceFlowAggregateError("aggregate_result_boundary_invalid")
    expected_hash = sha256_bytes(canonical_json_bytes({key: item for key, item in result.items() if key != "aggregate_sha256"}))
    if result["aggregate_sha256"] != expected_hash:
        raise SourceFlowAggregateError("aggregate_result_hash_invalid")
    return result


def load_aggregate(path: Path) -> dict[str, Any]:
    evidence_path = _external_regular_file(path, label="result")
    value, _ = _read_json(evidence_path, label="result")
    return validate_aggregate(value)


def write_aggregate(path: Path, value: Mapping[str, Any]) -> None:
    output = _external_new_output(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(value)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise SourceFlowAggregateError("aggregate_output_already_exists") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or validate a raw-free, fail-closed source-flow aggregate.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--input", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_aggregate(args.input, args.output)
        else:
            result = load_aggregate(args.input)
    except SourceFlowAggregateError as exc:
        print(f"HOLD: {exc}")
        return 1
    print(
        json.dumps(
            {
                "slot_count": result["counts"]["slot_count"],
                "excluded_slot_count": len(result["excluded_slot_ids"]),
                "raw_returned": False,
                "status": "FIX_NARROW",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
