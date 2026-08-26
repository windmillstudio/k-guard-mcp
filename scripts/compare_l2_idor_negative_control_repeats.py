from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
RUNNER_PATH = REPOSITORY_ROOT / "scripts" / "replay_l2_webgoat_idor.py"
SCHEMA = "k_guard_l2_webgoat_idor_negative_control_repeat_comparison.v2"
POSITIVE_COMPARISON_SCHEMA = "k_guard_l2_execution_contract_repeat_comparison.v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _load_runner() -> Any:
    before = RUNNER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_webgoat_idor_negative_repeat_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("execution_runner_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if RUNNER_PATH.read_bytes() != before:
        raise ValueError("execution_runner_changed_while_loading")
    return module


def _assert_raw_free(value: object) -> None:
    if isinstance(value, dict):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise ValueError("negative_control_raw_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


def _load_canonical_receipt(path: Path, runner: Any) -> tuple[dict[str, Any], str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("negative_control_receipt_invalid_path")
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("negative_control_receipt_not_json") from exc
    if not isinstance(receipt, dict) or canonical_json_bytes(receipt) != raw:
        raise ValueError("negative_control_receipt_not_canonical")
    try:
        runner.validate_negative_control_receipt(receipt)
    except Exception as exc:  # The runner owns the exact negative-control contract.
        raise ValueError("negative_control_receipt_contract_invalid") from exc
    if receipt.get("negative_control_status") != "NEGATIVE_CONTROL_PASS":
        raise ValueError("negative_control_receipt_not_passed")
    if receipt.get("release_gate_passed") is not False or receipt.get("raw_returned") is not False:
        raise ValueError("negative_control_receipt_claim_boundary_invalid")
    _assert_raw_free(receipt)
    return receipt, hashlib.sha256(raw).hexdigest()


def _load_positive_comparison(
    path: Path,
    *,
    first_positive_receipt_sha256: str,
    second_positive_receipt_sha256: str,
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
    if set(comparison) != required or comparison.get("schema") != POSITIVE_COMPARISON_SCHEMA:
        raise ValueError("positive_comparison_schema_invalid")
    hash_fields = (
        "first_receipt_sha256",
        "second_receipt_sha256",
        "first_semantic_fingerprint_sha256",
        "second_semantic_fingerprint_sha256",
    )
    if any(not isinstance(comparison.get(field), str) or SHA256_RE.fullmatch(comparison[field]) is None for field in hash_fields):
        raise ValueError("positive_comparison_hash_invalid")
    if (
        comparison.get("scenario") != "webgoat-idor-upstream-integration-test"
        or comparison.get("repeat_exact") is not True
        or comparison.get("status") != "FIX"
        or comparison.get("raw_returned") is not False
        or comparison["first_receipt_sha256"] != first_positive_receipt_sha256
        or comparison["second_receipt_sha256"] != second_positive_receipt_sha256
        or comparison["first_receipt_sha256"] == comparison["second_receipt_sha256"]
        or comparison["first_semantic_fingerprint_sha256"] != comparison["second_semantic_fingerprint_sha256"]
    ):
        raise ValueError("positive_comparison_anchor_mismatch")
    authority = comparison.get("authority")
    if not isinstance(authority, Mapping) or authority != {
        "may_mark_field_fix": True,
        "may_affect_oracle_labels": False,
        "may_affect_performance_metrics": False,
        "may_affect_h100_or_release": False,
    }:
        raise ValueError("positive_comparison_authority_invalid")
    boundary = comparison.get("claim_boundary")
    if not isinstance(boundary, Mapping) or boundary != {
        "execution_repeatability_only": True,
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


def _normalized_run(run: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "maven_command_sha256",
        "runtime_command_sha256",
        "network_policy",
        "expected_exit_code",
        "isolation",
        "normalized_result",
        "passed",
    }
    if any(field not in run for field in required):
        raise ValueError("negative_control_run_projection_invalid")
    return {field: run[field] for field in sorted(required)}


def semantic_projection(receipt: Mapping[str, Any], *, positive_execution_pair: Mapping[str, Any]) -> dict[str, Any]:
    source = receipt.get("source")
    tool = receipt.get("tool_provenance")
    positive = receipt.get("positive_execution_contract")
    control = receipt.get("negative_control")
    image = receipt.get("image")
    runs = receipt.get("runs")
    if not all(isinstance(value, Mapping) for value in (source, tool, positive, control, image)):
        raise ValueError("negative_control_projection_shape_invalid")
    if not isinstance(runs, list) or len(runs) != 2 or not all(isinstance(run, Mapping) for run in runs):
        raise ValueError("negative_control_projection_runs_invalid")
    source_fields = (
        "repository_id",
        "commit",
        "commit_tree",
        "source_tree_sha256",
        "file_count",
        "total_bytes",
    )
    tool_fields = ("runner_sha256", "source_verifier_sha256", "base_image")
    image_fields = (
        "base_image",
        "build_contract_sha256",
        "dockerfile_sha256",
        "source_derived",
        "online_build_non_evidence",
    )
    positive_fields = ("source_receipt_sha256", "execution_contract_status", "raw_returned")
    control_fields = (
        "patch_id",
        "source_path",
        "original_file_sha256",
        "patched_file_sha256",
        "patch_sha256",
        "variant_tree_sha256",
        "source_checkout_mutated",
        "raw_returned",
    )
    if any(field not in source for field in source_fields):
        raise ValueError("negative_control_source_projection_invalid")
    if any(field not in tool for field in tool_fields):
        raise ValueError("negative_control_tool_projection_invalid")
    if any(field not in image for field in image_fields):
        raise ValueError("negative_control_image_projection_invalid")
    if any(field not in positive for field in positive_fields):
        raise ValueError("negative_control_positive_projection_invalid")
    if any(field not in control for field in control_fields):
        raise ValueError("negative_control_mutation_projection_invalid")
    return {
        "schema": receipt.get("schema"),
        "tool_provenance": {field: tool[field] for field in tool_fields},
        "source": {field: source[field] for field in source_fields},
        "positive_execution_contract": {field: positive[field] for field in positive_fields},
        "positive_execution_pair": dict(positive_execution_pair),
        "negative_control": {field: control[field] for field in control_fields},
        "image_contract": {field: image[field] for field in image_fields},
        "runs": [_normalized_run(run) for run in runs],
        "claim_boundary": receipt.get("claim_boundary"),
        "admission_blockers": receipt.get("admission_blockers"),
        "negative_control_status": receipt.get("negative_control_status"),
        "release_gate_passed": receipt.get("release_gate_passed"),
        "raw_returned": False,
    }


def compare_receipts(first_path: Path, second_path: Path, positive_comparison_path: Path) -> dict[str, Any]:
    runner = _load_runner()
    first, first_receipt_sha256 = _load_canonical_receipt(first_path, runner)
    second, second_receipt_sha256 = _load_canonical_receipt(second_path, runner)
    first_positive = first.get("positive_execution_contract")
    second_positive = second.get("positive_execution_contract")
    if not isinstance(first_positive, Mapping) or not isinstance(second_positive, Mapping):
        raise ValueError("negative_control_positive_reference_invalid")
    first_positive_receipt_sha256 = first_positive.get("receipt_sha256")
    second_positive_receipt_sha256 = second_positive.get("receipt_sha256")
    if (
        not isinstance(first_positive_receipt_sha256, str)
        or not isinstance(second_positive_receipt_sha256, str)
        or SHA256_RE.fullmatch(first_positive_receipt_sha256) is None
        or SHA256_RE.fullmatch(second_positive_receipt_sha256) is None
    ):
        raise ValueError("negative_control_positive_reference_invalid")
    positive_execution_pair = _load_positive_comparison(
        positive_comparison_path,
        first_positive_receipt_sha256=first_positive_receipt_sha256,
        second_positive_receipt_sha256=second_positive_receipt_sha256,
    )
    first_projection = semantic_projection(first, positive_execution_pair=positive_execution_pair)
    second_projection = semantic_projection(second, positive_execution_pair=positive_execution_pair)
    first_semantic_sha256 = sha256_bytes(first_projection)
    second_semantic_sha256 = sha256_bytes(second_projection)
    repeat_exact = first_semantic_sha256 == second_semantic_sha256
    return {
        "schema": SCHEMA,
        "scenario": "webgoat-idor-source-mutated-negative-control",
        "first_receipt_sha256": first_receipt_sha256,
        "second_receipt_sha256": second_receipt_sha256,
        "first_semantic_fingerprint_sha256": first_semantic_sha256,
        "second_semantic_fingerprint_sha256": second_semantic_sha256,
        "positive_execution_pair": positive_execution_pair,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "source_mutated_negative_control_only": True,
            "independent_upstream_fixed_revision_proven": False,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def write_comparison(path: Path, comparison: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("refusing_to_overwrite_negative_control_repeat_evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_json_bytes(dict(comparison)))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two canonical WebGoat IDOR negative-control receipts without release promotion."
    )
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--positive-comparison", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    comparison = compare_receipts(args.first, args.second, args.positive_comparison)
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
