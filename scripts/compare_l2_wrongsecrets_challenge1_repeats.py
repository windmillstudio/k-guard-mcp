from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
RUNNER_PATH = REPOSITORY_ROOT / "scripts" / "replay_l2_wrongsecrets_challenge1.py"
POSITIVE_SCHEMA = "k_guard_l2_wrongsecrets_challenge1_execution_repeat_comparison.v1"
NEGATIVE_SCHEMA = "k_guard_l2_wrongsecrets_challenge1_negative_control_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_value(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _load_runner() -> Any:
    before = RUNNER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_wrongsecrets_repeat_runner", RUNNER_PATH)
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
    if not passed or receipt.get("release_gate_passed") is not False:
        raise ValueError("execution_receipt_claim_boundary_invalid")
    _assert_raw_free(receipt)
    return receipt, sha256_bytes(raw)


def _require_distinct_paths(first: Path, second: Path, label: str) -> None:
    if first.resolve() == second.resolve():
        raise ValueError(f"{label}_paths_not_distinct")


def _verify_negative_positive_anchors(
    *,
    runner: Any,
    first_negative: Mapping[str, Any],
    second_negative: Mapping[str, Any],
    first_positive: Path | None,
    second_positive: Path | None,
) -> dict[str, str]:
    if first_positive is None or second_positive is None:
        raise ValueError("negative_positive_anchors_missing")
    _require_distinct_paths(first_positive, second_positive, "positive_anchor")
    first_receipt, first_sha256 = _load_canonical_receipt(first_positive, runner, negative=False)
    second_receipt, second_sha256 = _load_canonical_receipt(second_positive, runner, negative=False)
    first_semantic = sha256_value(runner.semantic_projection(first_receipt, negative=False))
    second_semantic = sha256_value(runner.semantic_projection(second_receipt, negative=False))
    if (
        first_negative.get("positive_receipt_sha256") != first_sha256
        or second_negative.get("positive_receipt_sha256") != second_sha256
        or first_negative.get("positive_receipt_semantic_sha256") != first_semantic
        or second_negative.get("positive_receipt_semantic_sha256") != second_semantic
    ):
        raise ValueError("negative_positive_anchor_binding_invalid")
    return {
        "first_positive_receipt_sha256": first_sha256,
        "second_positive_receipt_sha256": second_sha256,
        "first_positive_semantic_sha256": first_semantic,
        "second_positive_semantic_sha256": second_semantic,
    }


def compare_receipts(
    first_path: Path,
    second_path: Path,
    *,
    negative: bool,
    first_positive: Path | None = None,
    second_positive: Path | None = None,
) -> dict[str, Any]:
    _require_distinct_paths(first_path, second_path, "execution_receipt")
    runner = _load_runner()
    first, first_sha256 = _load_canonical_receipt(first_path, runner, negative=negative)
    second, second_sha256 = _load_canonical_receipt(second_path, runner, negative=negative)
    first_projection = runner.semantic_projection(first, negative=negative)
    second_projection = runner.semantic_projection(second, negative=negative)
    first_semantic = sha256_value(first_projection)
    second_semantic = sha256_value(second_projection)
    anchors = (
        _verify_negative_positive_anchors(
            runner=runner,
            first_negative=first,
            second_negative=second,
            first_positive=first_positive,
            second_positive=second_positive,
        )
        if negative
        else None
    )
    exact = first_projection == second_projection
    return {
        "schema": NEGATIVE_SCHEMA if negative else POSITIVE_SCHEMA,
        "mode": "negative" if negative else "positive",
        "first_receipt_sha256": first_sha256,
        "second_receipt_sha256": second_sha256,
        "first_semantic_sha256": first_semantic,
        "second_semantic_sha256": second_semantic,
        "positive_anchors": anchors,
        "repeat_exact": exact,
        "status": "FIX" if exact else "HOLD",
        "authority": {
            "may_mark_field_fix": exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "reason": "semantic_projection_equal" if exact else "semantic_projection_mismatch",
        "release_gate_passed": False,
        "raw_returned": False,
    }


def _write_new_output(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("output_path_already_exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(dict(payload)))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare P2.3B.6 WrongSecrets execution receipts.")
    parser.add_argument("--first", required=True, type=Path)
    parser.add_argument("--second", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--negative", action="store_true")
    parser.add_argument("--first-positive", type=Path)
    parser.add_argument("--second-positive", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    has_any_positive_anchor = args.first_positive is not None or args.second_positive is not None
    if (args.negative and (args.first_positive is None or args.second_positive is None)) or (
        not args.negative and has_any_positive_anchor
    ):
        parser.error("negative comparisons require both positive anchors; positive comparisons accept neither")
    try:
        result = compare_receipts(
            args.first.resolve(),
            args.second.resolve(),
            negative=args.negative,
            first_positive=args.first_positive.resolve() if args.first_positive else None,
            second_positive=args.second_positive.resolve() if args.second_positive else None,
        )
        _write_new_output(args.output.resolve(), result)
    except ValueError as exc:
        print(f"HOLD:{exc}", file=sys.stderr)
        return 2
    return 0 if result["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
