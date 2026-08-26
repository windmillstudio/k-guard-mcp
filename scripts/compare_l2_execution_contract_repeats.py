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
RUNNER_PATH = REPOSITORY_ROOT / "scripts" / "replay_l2_webgoat_idor.py"
SCHEMA = "k_guard_l2_execution_contract_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _load_runner() -> Any:
    before = RUNNER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_webgoat_idor_repeat_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("execution_runner_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if RUNNER_PATH.read_bytes() != before:
        raise ValueError("execution_runner_changed_while_loading")
    return module


def _load_canonical_receipt(path: Path, runner: Any) -> tuple[dict[str, Any], str]:
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
        runner.validate_receipt(receipt)
    except Exception as exc:  # The runner owns the exact receipt contract.
        raise ValueError("execution_receipt_contract_invalid") from exc
    if receipt.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise ValueError("execution_receipt_not_passed")
    if receipt.get("release_gate_passed") is not False or receipt.get("raw_returned") is not False:
        raise ValueError("execution_receipt_claim_boundary_invalid")
    return receipt, hashlib.sha256(raw).hexdigest()


def _assert_raw_free(value: object) -> None:
    if isinstance(value, dict):
        if "raw_returned" in value and value["raw_returned"] is not False:
            raise ValueError("execution_receipt_raw_boundary_invalid")
        for nested in value.values():
            _assert_raw_free(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_raw_free(nested)


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
        raise ValueError("execution_run_projection_invalid")
    return {field: run[field] for field in sorted(required)}


def semantic_projection(receipt: Mapping[str, Any]) -> dict[str, Any]:
    _assert_raw_free(receipt)
    source = receipt.get("source")
    tool = receipt.get("tool_provenance")
    image = receipt.get("image")
    runs = receipt.get("runs")
    if not isinstance(source, Mapping) or not isinstance(tool, Mapping) or not isinstance(image, Mapping):
        raise ValueError("execution_receipt_projection_shape_invalid")
    if not isinstance(runs, list) or len(runs) != 2 or not all(isinstance(run, Mapping) for run in runs):
        raise ValueError("execution_receipt_projection_runs_invalid")
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
    if any(field not in source for field in source_fields):
        raise ValueError("execution_receipt_source_projection_invalid")
    if any(field not in tool for field in tool_fields):
        raise ValueError("execution_receipt_tool_projection_invalid")
    if any(field not in image for field in image_fields):
        raise ValueError("execution_receipt_image_projection_invalid")
    return {
        "schema": receipt.get("schema"),
        "tool_provenance": {field: tool[field] for field in tool_fields},
        "source": {field: source[field] for field in source_fields},
        "image_contract": {field: image[field] for field in image_fields},
        "runs": [_normalized_run(run) for run in runs],
        "claim_boundary": receipt.get("claim_boundary"),
        "admission_blockers": receipt.get("admission_blockers"),
        "execution_contract_status": receipt.get("execution_contract_status"),
        "release_gate_passed": receipt.get("release_gate_passed"),
        "raw_returned": False,
    }


def compare_receipts(first_path: Path, second_path: Path) -> dict[str, Any]:
    runner = _load_runner()
    first, first_receipt_sha256 = _load_canonical_receipt(first_path, runner)
    second, second_receipt_sha256 = _load_canonical_receipt(second_path, runner)
    first_projection = semantic_projection(first)
    second_projection = semantic_projection(second)
    first_semantic_sha256 = sha256_bytes(first_projection)
    second_semantic_sha256 = sha256_bytes(second_projection)
    repeat_exact = first_semantic_sha256 == second_semantic_sha256
    return {
        "schema": SCHEMA,
        "scenario": "webgoat-idor-upstream-integration-test",
        "first_receipt_sha256": first_receipt_sha256,
        "second_receipt_sha256": second_receipt_sha256,
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
            "execution_repeatability_only": True,
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
        description="Compare two canonical WebGoat IDOR execution-contract receipts without release promotion."
    )
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    comparison = compare_receipts(args.first, args.second)
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
