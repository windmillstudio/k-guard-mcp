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
AGGREGATOR_PATH = REPOSITORY_ROOT / "scripts" / "aggregate_l2_execution_oracles.py"
SCHEMA = "k_guard_l2_execution_oracle_aggregate_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _load_aggregator() -> tuple[Any, str]:
    raw_before = AGGREGATOR_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_execution_oracle_aggregate", AGGREGATOR_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("aggregate_materializer_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if AGGREGATOR_PATH.read_bytes() != raw_before:
        raise ValueError("aggregate_materializer_changed_while_loading")
    return module, hashlib.sha256(raw_before).hexdigest()


def _load_canonical(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label}_path_invalid")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_json_invalid") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label}_not_canonical")
    return payload, raw


def _semantic_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": payload["schema"],
        "status": payload["status"],
        "aggregate_ready": payload["aggregate_ready"],
        "source_registry": payload["source_registry"],
        "apps": payload["apps"],
        "coverage": payload["coverage"],
        "tool_provenance": payload["tool_provenance"],
        "claim_boundary": payload["claim_boundary"],
        "release_gate_passed": payload["release_gate_passed"],
        "raw_returned": payload["raw_returned"],
    }


def compare_measurements(first_path: Path, second_path: Path) -> dict[str, Any]:
    aggregate, current_materializer_sha256 = _load_aggregator()
    first, first_raw = _load_canonical(first_path, label="first_aggregate")
    second, second_raw = _load_canonical(second_path, label="second_aggregate")
    aggregate.validate_measurement(first)
    aggregate.validate_measurement(second)
    if (
        first["tool_provenance"].get("materializer_sha256") != current_materializer_sha256
        or second["tool_provenance"].get("materializer_sha256") != current_materializer_sha256
    ):
        raise ValueError("aggregate_materializer_target_binding_invalid")
    first_projection = _semantic_projection(first)
    second_projection = _semantic_projection(second)
    first_fingerprint = sha256_bytes(first_projection)
    second_fingerprint = sha256_bytes(second_projection)
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "source_registry_sha256": first["source_registry"]["sha256"],
        "expected_app_ids": first["coverage"]["expected_app_ids"],
        "first_receipt_sha256": hashlib.sha256(first_raw).hexdigest(),
        "second_receipt_sha256": hashlib.sha256(second_raw).hexdigest(),
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "historical_component_comparators_revalidated": True,
            "fresh_app_execution_proven": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def write_comparison(output: Path, comparison: Mapping[str, Any]) -> None:
    if not output.is_absolute() or _is_within(output, REPOSITORY_ROOT):
        raise ValueError("aggregate_comparison_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_aggregate_comparison")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(comparison)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_aggregate_comparison") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two raw-free six-app historical execution-oracle aggregates."
    )
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    comparison = compare_measurements(args.first, args.second)
    write_comparison(args.output, comparison)
    print(
        json.dumps(
            {
                "status": comparison["status"],
                "repeat_exact": comparison["repeat_exact"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
