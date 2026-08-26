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
RUNNER_PATH = REPOSITORY_ROOT / "scripts" / "replay_l2_nodegoat_idor.py"
POSITIVE_SCHEMA = "k_guard_l2_nodegoat_allocations_idor_execution_repeat_comparison.v1"
NEGATIVE_SCHEMA = "k_guard_l2_nodegoat_allocations_idor_negative_control_repeat_comparison.v1"
SHA256_RE = __import__("re").compile(r"[0-9a-f]{64}\Z")
SCENARIO = "nodegoat-allocations-cross-user-read"


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_value(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _load_runner() -> Any:
    before = RUNNER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_nodegoat_idor_repeat_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("execution_runner_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if RUNNER_PATH.read_bytes() != before:
        raise ValueError("execution_runner_changed_while_loading")
    return module


def _assert_raw_free(value: object) -> None:
    if isinstance(value, Mapping):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise ValueError("receipt_raw_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _load_canonical_receipt(path: Path, runner: Any, *, negative: bool) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("execution_receipt_invalid_path")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("execution_receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise ValueError("execution_receipt_not_canonical")
    try:
        if negative:
            runner.validate_negative_control_receipt(receipt)
            passed = receipt.get("negative_control_status") == "NEGATIVE_CONTROL_PASS"
        else:
            runner.validate_receipt(receipt)
            passed = receipt.get("execution_contract_status") == "EXECUTION_CONTRACT_PASS"
    except Exception as exc:
        raise ValueError("execution_receipt_contract_invalid") from exc
    if not passed or receipt.get("release_gate_passed") is not False or receipt.get("raw_returned") is not False:
        raise ValueError("execution_receipt_claim_boundary_invalid")
    _assert_raw_free(receipt)
    return receipt, hashlib.sha256(raw).hexdigest()


def _fields(value: Mapping[str, Any], fields: tuple[str, ...], label: str) -> dict[str, Any]:
    if any(field not in value for field in fields):
        raise ValueError(f"{label}_projection_invalid")
    return {field: value[field] for field in fields}


def _isolation_projection(value: object) -> object:
    if not isinstance(value, Mapping):
        return value
    projected: dict[str, Any] = {
        "passed": value.get("passed"),
        "raw_returned": value.get("raw_returned"),
    }
    for key in (
        "network",
        "database",
        "seed",
        "application",
        "application_post_state",
        "network_post_state",
    ):
        nested = value.get(key)
        if not isinstance(nested, Mapping):
            projected[key] = nested
            continue
        projected[key] = {
            "checks": nested.get("checks"),
            "created_id_exact": nested.get("created_id_exact"),
            "passed": nested.get("passed"),
            "raw_returned": nested.get("raw_returned"),
        }
    return projected


def _normalized_run(run: Mapping[str, Any]) -> dict[str, Any]:
    return _fields(
        run,
        (
            "driver_sha256",
            "network_policy",
            "expected_status",
            "mode",
            "normalized_result",
            "passed",
        ),
        "run",
    ) | {"isolation": _isolation_projection(run.get("isolation"))}


def _base_projection(base: Mapping[str, Any]) -> dict[str, Any]:
    return _fields(
        base,
        (
            "source_image_id",
            "source_image_ref",
            "source_image_rootfs_layers_sha256",
            "source_image_commit_label",
            "mongo_image_id",
            "mongo_image_ref",
            "mongo_image_rootfs_layers_sha256",
            "source_dockerfile_sha256",
            "route_source_sha256",
            "seed_source_sha256",
            "source_image_current_source_provenance_only",
            "fresh_dependency_rebuild_proven",
            "mongo_runtime_supply_chain_proven",
            "raw_returned",
        ),
        "base_images",
    )


def _image_projection(image: Mapping[str, Any]) -> dict[str, Any]:
    return _fields(
        image,
        (
            "base_source_image_id",
            "contract_label",
            "dockerfile_sha256",
            "driver_sha256",
            "seed_wrapper_sha256",
            "build_contract_sha256",
            "route",
            "source_derived",
            "build_network",
            "fresh_dependency_rebuild_proven",
            "raw_returned",
        ),
        "image",
    )


def semantic_projection(
    receipt: Mapping[str, Any], *, negative: bool, positive_pair: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    source = receipt.get("source")
    tool = receipt.get("tool_provenance")
    base = receipt.get("base_images")
    image = receipt.get("image")
    runs = receipt.get("runs")
    if not all(isinstance(value, Mapping) for value in (source, tool, base, image)):
        raise ValueError("execution_receipt_projection_shape_invalid")
    if not isinstance(runs, list) or len(runs) != 2 or not all(isinstance(run, Mapping) for run in runs):
        raise ValueError("execution_receipt_projection_runs_invalid")
    projection = {
        "schema": receipt.get("schema"),
        "tool_provenance": _fields(
            tool,
            (
                "runner_sha256",
                "source_verifier_sha256",
                "driver_sha256",
                "seed_wrapper_sha256",
                "source_image_id",
                "mongo_image_id",
                "raw_returned",
            ),
            "tool",
        ),
        "source": _fields(
            source,
            (
                "repository_id",
                "commit",
                "commit_tree",
                "source_tree_sha256",
                "p23a_registry_sha256",
                "p23a_app_receipt_sha256",
                "p23a_app_receipt_semantic_sha256",
                "current_source_receipt_sha256",
                "file_count",
                "total_bytes",
                "raw_returned",
            ),
            "source",
        ),
        "base_images": _base_projection(base),
        "image_contract": _image_projection(image),
        "runs": [_normalized_run(run) for run in runs],
        "claim_boundary": receipt.get("claim_boundary"),
        "admission_blockers": receipt.get("admission_blockers"),
        "release_gate_passed": receipt.get("release_gate_passed"),
        "raw_returned": False,
    }
    if negative:
        control = receipt.get("negative_control")
        if not isinstance(control, Mapping) or positive_pair is None:
            raise ValueError("negative_control_projection_invalid")
        projection["positive_execution_pair"] = dict(positive_pair)
        projection["negative_control"] = _fields(
            control,
            (
                "patch_id",
                "source_path",
                "original_file_sha256",
                "patched_file_sha256",
                "patch_sha256",
                "marker_count",
                "replacement_count",
                "source_checkout_mutated",
                "raw_returned",
            ),
            "negative_control",
        )
        projection["negative_control_status"] = receipt.get("negative_control_status")
    else:
        projection["execution_contract_status"] = receipt.get("execution_contract_status")
    return projection


def compare_positive_receipts(first_path: Path, second_path: Path) -> dict[str, Any]:
    runner = _load_runner()
    first, first_receipt_sha256 = _load_canonical_receipt(first_path, runner, negative=False)
    second, second_receipt_sha256 = _load_canonical_receipt(second_path, runner, negative=False)
    first_fingerprint = sha256_value(semantic_projection(first, negative=False))
    second_fingerprint = sha256_value(semantic_projection(second, negative=False))
    repeat_exact = first_receipt_sha256 != second_receipt_sha256 and first_fingerprint == second_fingerprint
    return {
        "schema": POSITIVE_SCHEMA,
        "scenario": SCENARIO,
        "first_receipt_sha256": first_receipt_sha256,
        "second_receipt_sha256": second_receipt_sha256,
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
            "execution_repeatability_only": True,
            "source_mutated_negative_control_only": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def _load_positive_comparison(
    path: Path, *, first_positive_receipt_sha256: str, second_positive_receipt_sha256: str
) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("positive_comparison_invalid_path")
    raw = path.read_bytes()
    try:
        comparison = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("positive_comparison_not_json") from exc
    if not isinstance(comparison, dict) or canonical_json_bytes(comparison) != raw:
        raise ValueError("positive_comparison_not_canonical")
    required = {
        "schema",
        "scenario",
        "first_receipt_sha256",
        "second_receipt_sha256",
        "first_semantic_fingerprint_sha256",
        "second_semantic_fingerprint_sha256",
        "repeat_exact",
        "status",
        "authority",
        "claim_boundary",
        "raw_returned",
    }
    if set(comparison) != required or comparison.get("schema") != POSITIVE_SCHEMA:
        raise ValueError("positive_comparison_schema_invalid")
    hashes = (
        "first_receipt_sha256",
        "second_receipt_sha256",
        "first_semantic_fingerprint_sha256",
        "second_semantic_fingerprint_sha256",
    )
    if any(not isinstance(comparison.get(key), str) or SHA256_RE.fullmatch(comparison[key]) is None for key in hashes):
        raise ValueError("positive_comparison_hash_invalid")
    if (
        comparison.get("scenario") != SCENARIO
        or comparison.get("repeat_exact") is not True
        or comparison.get("status") != "FIX"
        or comparison.get("raw_returned") is not False
        or {comparison["first_receipt_sha256"], comparison["second_receipt_sha256"]}
        != {first_positive_receipt_sha256, second_positive_receipt_sha256}
        or comparison["first_receipt_sha256"] == comparison["second_receipt_sha256"]
        or comparison["first_semantic_fingerprint_sha256"] != comparison["second_semantic_fingerprint_sha256"]
    ):
        raise ValueError("positive_comparison_anchor_mismatch")
    if comparison.get("authority") != {
        "may_mark_field_fix": True,
        "may_affect_oracle_labels": False,
        "may_affect_performance_metrics": False,
        "may_affect_h100_or_release": False,
    }:
        raise ValueError("positive_comparison_authority_invalid")
    if comparison.get("claim_boundary") != {
        "execution_repeatability_only": True,
        "source_mutated_negative_control_only": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
    }:
        raise ValueError("positive_comparison_claim_boundary_invalid")
    return {
        "comparison_sha256": hashlib.sha256(raw).hexdigest(),
        "first_receipt_sha256": comparison["first_receipt_sha256"],
        "second_receipt_sha256": comparison["second_receipt_sha256"],
        "semantic_fingerprint_sha256": comparison["first_semantic_fingerprint_sha256"],
        "status": "FIX",
        "raw_returned": False,
    }


def compare_negative_receipts(
    first_path: Path, second_path: Path, positive_comparison_path: Path
) -> dict[str, Any]:
    runner = _load_runner()
    first, first_receipt_sha256 = _load_canonical_receipt(first_path, runner, negative=True)
    second, second_receipt_sha256 = _load_canonical_receipt(second_path, runner, negative=True)
    first_positive = first.get("positive_execution_contract")
    second_positive = second.get("positive_execution_contract")
    if not isinstance(first_positive, Mapping) or not isinstance(second_positive, Mapping):
        raise ValueError("negative_control_positive_reference_invalid")
    first_positive_sha256 = first_positive.get("receipt_sha256")
    second_positive_sha256 = second_positive.get("receipt_sha256")
    if (
        not isinstance(first_positive_sha256, str)
        or not isinstance(second_positive_sha256, str)
        or SHA256_RE.fullmatch(first_positive_sha256) is None
        or SHA256_RE.fullmatch(second_positive_sha256) is None
    ):
        raise ValueError("negative_control_positive_reference_invalid")
    positive_pair = _load_positive_comparison(
        positive_comparison_path,
        first_positive_receipt_sha256=first_positive_sha256,
        second_positive_receipt_sha256=second_positive_sha256,
    )
    first_fingerprint = sha256_value(semantic_projection(first, negative=True, positive_pair=positive_pair))
    second_fingerprint = sha256_value(semantic_projection(second, negative=True, positive_pair=positive_pair))
    repeat_exact = first_receipt_sha256 != second_receipt_sha256 and first_fingerprint == second_fingerprint
    return {
        "schema": NEGATIVE_SCHEMA,
        "scenario": f"{SCENARIO}-negative-control",
        "first_receipt_sha256": first_receipt_sha256,
        "second_receipt_sha256": second_receipt_sha256,
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "positive_execution_pair": positive_pair,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "execution_repeatability_only": True,
            "source_mutated_negative_control_only": True,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def write_comparison(path: Path, comparison: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("refusing_to_overwrite_execution_repeat_evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_json_bytes(dict(comparison)))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two NodeGoat allocations IDOR execution receipts without detector or release promotion."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    positive = subparsers.add_parser("positive")
    positive.add_argument("--first", type=Path, required=True)
    positive.add_argument("--second", type=Path, required=True)
    positive.add_argument("--output", type=Path, required=True)
    negative = subparsers.add_parser("negative-control")
    negative.add_argument("--first", type=Path, required=True)
    negative.add_argument("--second", type=Path, required=True)
    negative.add_argument("--positive-comparison", type=Path, required=True)
    negative.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "positive":
            comparison = compare_positive_receipts(args.first, args.second)
        else:
            comparison = compare_negative_receipts(args.first, args.second, args.positive_comparison)
        write_comparison(args.output, comparison)
        print(json.dumps({"status": comparison["status"], "repeat_exact": comparison["repeat_exact"], "raw_returned": False}, sort_keys=True))
        return 0 if comparison["status"] == "FIX" else 2
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "HOLD", "failure_code": str(exc), "raw_returned": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
