from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
AGGREGATE_PATH = REPOSITORY_ROOT / "scripts" / "aggregate_l3_source_flow.py"
SCHEMA = "k_guard_l3_source_flow_aggregate_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT)
        return True
    except ValueError:
        return False


def _external_regular_file(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or _is_within_repository(path):
        raise ValueError(f"aggregate_repeat_{label}_must_be_external_regular_file")
    return path.resolve(strict=True)


def _external_new_output(path: Path) -> Path:
    if not path.is_absolute() or _is_within_repository(path) or path.exists() or path.is_symlink():
        raise ValueError("aggregate_repeat_output_must_be_new_external_path")
    return path.resolve(strict=False)


def _load_aggregate_module() -> Any:
    raw_before = AGGREGATE_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_source_flow_aggregate_for_comparison", AGGREGATE_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("aggregate_repeat_aggregate_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if AGGREGATE_PATH.read_bytes() != raw_before:
        raise ValueError("aggregate_repeat_aggregate_module_changed_while_loading")
    return module


def _projection(aggregate: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": aggregate["schema"],
        "aggregate_hash_schema": aggregate["aggregate_hash_schema"],
        "slot_order": aggregate["slot_order"],
        "counts": aggregate["counts"],
        "excluded_slot_ids": aggregate["excluded_slot_ids"],
        "leaf_evidence": aggregate["leaf_evidence"],
        "claim_boundary": aggregate["claim_boundary"],
        "raw_returned": aggregate["raw_returned"],
    }


def compare_aggregate_repeats(first_path: Path, second_path: Path) -> dict[str, Any]:
    first_input = _external_regular_file(first_path, label="first")
    second_input = _external_regular_file(second_path, label="second")
    if first_input == second_input:
        raise ValueError("aggregate_repeat_inputs_must_be_independent")
    aggregate = _load_aggregate_module()
    try:
        first = aggregate.load_aggregate(first_input)
        second = aggregate.load_aggregate(second_input)
    except aggregate.SourceFlowAggregateError as exc:
        raise ValueError(f"aggregate_repeat_input_invalid: {exc}") from exc
    first_projection = _projection(first)
    second_projection = _projection(second)
    first_fingerprint = hashlib.sha256(canonical_json_bytes(first_projection)).hexdigest()
    second_fingerprint = hashlib.sha256(canonical_json_bytes(second_projection)).hexdigest()
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_other_families": False,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "source_flow_inventory_complete": repeat_exact,
            "execution_oracles_proved": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def write_comparison(output: Path, comparison: Mapping[str, Any]) -> None:
    destination = _external_new_output(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(comparison)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("aggregate_repeat_output_must_be_new_external_path") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two raw-free source-flow aggregate manifests.")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        comparison = compare_aggregate_repeats(args.first, args.second)
        write_comparison(args.output, comparison)
    except (OSError, ValueError) as exc:
        print(f"compare_l3_source_flow_aggregate_repeats: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"raw_returned": False, "repeat_exact": comparison["repeat_exact"], "status": comparison["status"]},
            sort_keys=True,
        )
    )
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
