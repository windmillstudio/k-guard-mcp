from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
MATERIALIZER_PATH = REPOSITORY_ROOT / "scripts" / "materialize_l2_sources.py"
SCHEMA = "k_guard_l2_source_registry_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _load_materializer_with_hash() -> tuple[Any, str]:
    raw_before = MATERIALIZER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location(
        "k_guard_l2_source_registry_comparator_materializer", MATERIALIZER_PATH
    )
    if spec is None or spec.loader is None:
        raise ValueError("source_registry_materializer_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if MATERIALIZER_PATH.read_bytes() != raw_before:
        raise ValueError("source_registry_materializer_changed_while_loading")
    return module, hashlib.sha256(raw_before).hexdigest()


def _load_canonical_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label}_invalid_path")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_not_json") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"{label}_not_canonical")
    return payload, raw


def _assert_raw_free(value: object) -> None:
    forbidden_keys = {"source_bytes", "file_contents", "raw_source", "scanner_output"}
    if isinstance(value, dict):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise ValueError("source_registry_raw_boundary_invalid")
        if forbidden_keys.intersection(value):
            raise ValueError("source_registry_contains_raw_content")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _validate_source_only_claims(receipt: Mapping[str, Any]) -> None:
    if (
        receipt.get("schema") != "k_guard_l2_source_materialization.v3"
        or receipt.get("expected_app_count") != 6
        or receipt.get("materialized_app_count") != 6
        or receipt.get("source_license_admission") != "PASS"
        or receipt.get("isolation_contract_declared") != "PASS"
        or receipt.get("runtime_isolation_gate") != "HOLD"
        or receipt.get("machine_oracle_gate") != "HOLD"
        or receipt.get("phase_2_status") != "HOLD"
        or receipt.get("release_gate_passed") is not False
        or receipt.get("scanner_output_observed") is not False
        or receipt.get("raw_returned") is not False
    ):
        raise ValueError("source_registry_claim_boundary_invalid")
    apps = receipt.get("apps")
    if not isinstance(apps, list) or len(apps) != 6:
        raise ValueError("source_registry_app_set_invalid")
    if any(
        not isinstance(app, Mapping)
        or app.get("source_license_admission") != "PASS"
        or app.get("scanner_output_observed") is not False
        or app.get("oracle_gate_status") != "HOLD"
        or app.get("machine_oracles") != []
        or app.get("raw_returned") is not None
        for app in apps
    ):
        raise ValueError("source_registry_per_app_claim_invalid")


def semantic_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    _assert_raw_free(receipt)
    _validate_source_only_claims(receipt)
    return {
        "schema": receipt["schema"],
        "seed_sha256": receipt["seed_sha256"],
        "tool_provenance": receipt["tool_provenance"],
        "expected_app_count": receipt["expected_app_count"],
        "materialized_app_count": receipt["materialized_app_count"],
        "source_license_admission": receipt["source_license_admission"],
        "isolation_contract_declared": receipt["isolation_contract_declared"],
        "runtime_isolation_gate": receipt["runtime_isolation_gate"],
        "runtime_isolation_gate_reason": receipt["runtime_isolation_gate_reason"],
        "machine_oracle_totals": receipt["machine_oracle_totals"],
        "machine_oracle_gate": receipt["machine_oracle_gate"],
        "machine_oracle_gate_reason": receipt["machine_oracle_gate_reason"],
        "phase_2_status": receipt["phase_2_status"],
        "release_gate_passed": receipt["release_gate_passed"],
        "scanner_output_observed": receipt["scanner_output_observed"],
        "apps": receipt["apps"],
        "raw_returned": False,
    }


def compare_receipts(seed_path: Path, first_path: Path, second_path: Path) -> dict[str, Any]:
    seed, seed_raw = _load_canonical_object(seed_path, label="source_registry_seed")
    materializer, materializer_sha256 = _load_materializer_with_hash()
    if seed.get("schema") != materializer.SEED_SCHEMA:
        raise ValueError("source_registry_seed_schema_invalid")
    expected = materializer.materialize_l2_sources(seed_path)
    _validate_source_only_claims(expected)
    expected_raw = materializer.canonical_json_bytes(expected)
    first, first_raw = _load_canonical_object(first_path, label="first_source_registry")
    second, second_raw = _load_canonical_object(second_path, label="second_source_registry")
    if first != expected or second != expected:
        raise ValueError("source_registry_output_differs_from_current_materialization")
    expected_seed_sha256 = hashlib.sha256(seed_raw).hexdigest()
    if (
        first.get("seed_sha256") != expected_seed_sha256
        or second.get("seed_sha256") != expected_seed_sha256
        or first.get("tool_provenance", {}).get("materializer_sha256")
        != materializer_sha256
        or second.get("tool_provenance", {}).get("materializer_sha256")
        != materializer_sha256
    ):
        raise ValueError("source_registry_target_binding_invalid")
    first_projection = semantic_projection(first)
    second_projection = semantic_projection(second)
    first_semantic_sha256 = sha256_bytes(first_projection)
    second_semantic_sha256 = sha256_bytes(second_projection)
    repeat_exact = first_semantic_sha256 == second_semantic_sha256
    return {
        "schema": SCHEMA,
        "seed_sha256": expected_seed_sha256,
        "current_materialization_sha256": hashlib.sha256(expected_raw).hexdigest(),
        "first_receipt_sha256": hashlib.sha256(first_raw).hexdigest(),
        "second_receipt_sha256": hashlib.sha256(second_raw).hexdigest(),
        "first_semantic_fingerprint_sha256": first_semantic_sha256,
        "second_semantic_fingerprint_sha256": second_semantic_sha256,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "source_provenance_and_declaration_only": True,
            "runtime_isolation_proven": False,
            "machine_oracle_proven": False,
            "scanner_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def write_comparison(path: Path, comparison: Mapping[str, Any]) -> None:
    if not path.is_absolute() or _is_within(path, REPOSITORY_ROOT):
        raise ValueError("comparison_output_must_be_external")
    if path.exists() or path.is_symlink():
        raise ValueError("refusing_to_overwrite_source_registry_comparison")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(comparison)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_source_registry_comparison") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two six-app L2 source-only materializations without release promotion."
    )
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    comparison = compare_receipts(args.seed, args.first, args.second)
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
