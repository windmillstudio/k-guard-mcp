from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from capture_supervisor_target import capture_target
from run_regression_attestation import (
    RECEIPT_NAME,
    SCHEMA as ATTESTATION_SCHEMA,
    _receipt_hash,
    _outside_repository,
    prepare_run,
    run_worker,
    selector_binding,
)


SCHEMA = "k_guard_regression_shard_plan.v1"
AGGREGATE_SCHEMA = "k_guard_regression_shard_aggregate.v1"
DEFAULT_SHARD_COUNT = 12
MAX_SHARD_COUNT = 64
SHA256_RE = set("0123456789abcdef")


class RegressionShardError(ValueError):
    pass


TargetCapturer = Callable[[Path], Mapping[str, str]]


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _with_hash(payload: Mapping[str, Any], *, hash_key: str) -> dict[str, Any]:
    result = dict(payload)
    result[hash_key] = _sha256_bytes(_canonical_bytes(result))
    return result


def _validate_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in SHA256_RE for character in value):
        raise RegressionShardError(f"{label}_invalid")
    return value


def _test_files() -> tuple[Path, ...]:
    tests_directory = ROOT / "tests"
    files = tuple(sorted(path for path in tests_directory.glob("test_*.py") if path.is_file() and not path.is_symlink()))
    if not files:
        raise RegressionShardError("test_files_unavailable")
    return files


def _relative(path: Path) -> str:
    return path.resolve(strict=True).relative_to(ROOT.resolve(strict=True)).as_posix()


def _inventory_binding(files: Sequence[Path]) -> dict[str, Any]:
    rendered = tuple(_relative(path) for path in files)
    return {
        "test_file_count": len(rendered),
        "test_file_set_sha256": _sha256_bytes("\n".join(rendered).encode("utf-8")),
    }


def build_plan(shard_count: int = DEFAULT_SHARD_COUNT) -> dict[str, Any]:
    if not isinstance(shard_count, int) or not 1 <= shard_count <= MAX_SHARD_COUNT:
        raise RegressionShardError("shard_count_invalid")
    files = _test_files()
    if shard_count > len(files):
        raise RegressionShardError("shard_count_exceeds_test_files")

    buckets: list[list[Path]] = [[] for _ in range(shard_count)]
    bucket_sizes = [0 for _ in range(shard_count)]
    weighted = sorted(files, key=lambda path: (-path.stat().st_size, _relative(path)))
    for path in weighted:
        selected = min(range(shard_count), key=lambda index: (bucket_sizes[index], index))
        buckets[selected].append(path)
        bucket_sizes[selected] += path.stat().st_size

    shards = []
    for index, paths in enumerate(buckets, start=1):
        selectors = tuple(sorted(_relative(path) for path in paths))
        if not selectors:
            raise RegressionShardError("shard_empty")
        shards.append(
            {
                "id": f"shard-{index:02d}",
                "selectors": list(selectors),
                "source_byte_count": sum(path.stat().st_size for path in paths),
                "selector_binding": selector_binding(selectors),
            }
        )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "inventory": _inventory_binding(files),
        "shards": shards,
        "raw_returned": False,
    }
    payload["plan_sha256"] = _sha256_bytes(_canonical_bytes(payload))
    return payload


def _validate_binding(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"scope", "selector_count", "selector_sha256"}:
        raise RegressionShardError("selector_binding_invalid")
    if value["scope"] not in {"full", "focused"} or not isinstance(value["selector_count"], int):
        raise RegressionShardError("selector_binding_invalid")
    _validate_sha256(value["selector_sha256"], label="selector_binding")
    return dict(value)


def validate_plan(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "inventory", "shards", "raw_returned", "plan_sha256"}:
        raise RegressionShardError("plan_shape_invalid")
    if value["schema"] != SCHEMA or value["raw_returned"] is not False:
        raise RegressionShardError("plan_shape_invalid")
    without_hash = {key: item for key, item in value.items() if key != "plan_sha256"}
    if value["plan_sha256"] != _sha256_bytes(_canonical_bytes(without_hash)):
        raise RegressionShardError("plan_hash_invalid")
    inventory = value["inventory"]
    if not isinstance(inventory, dict) or set(inventory) != {"test_file_count", "test_file_set_sha256"}:
        raise RegressionShardError("plan_inventory_invalid")
    if not isinstance(inventory["test_file_count"], int) or inventory["test_file_count"] <= 0:
        raise RegressionShardError("plan_inventory_invalid")
    _validate_sha256(inventory["test_file_set_sha256"], label="test_file_set")
    if not isinstance(value["shards"], list) or not value["shards"]:
        raise RegressionShardError("plan_shards_invalid")
    selectors: list[str] = []
    normalized_shards: list[dict[str, Any]] = []
    for expected_index, shard in enumerate(value["shards"], start=1):
        if not isinstance(shard, dict) or set(shard) != {"id", "selectors", "source_byte_count", "selector_binding"}:
            raise RegressionShardError("plan_shards_invalid")
        if shard["id"] != f"shard-{expected_index:02d}":
            raise RegressionShardError("plan_shards_invalid")
        if not isinstance(shard["selectors"], list) or not shard["selectors"] or not all(isinstance(item, str) for item in shard["selectors"]):
            raise RegressionShardError("plan_shards_invalid")
        if not isinstance(shard["source_byte_count"], int) or shard["source_byte_count"] < 0:
            raise RegressionShardError("plan_shards_invalid")
        binding = _validate_binding(shard["selector_binding"])
        expected_binding = selector_binding(tuple(shard["selectors"]))
        if binding != expected_binding:
            raise RegressionShardError("plan_selector_binding_invalid")
        selectors.extend(shard["selectors"])
        normalized_shards.append(dict(shard))
    if len(selectors) != len(set(selectors)) or len(selectors) != inventory["test_file_count"]:
        raise RegressionShardError("plan_coverage_invalid")
    if _sha256_bytes("\n".join(sorted(selectors)).encode("utf-8")) != inventory["test_file_set_sha256"]:
        raise RegressionShardError("plan_coverage_invalid")
    return {
        "schema": SCHEMA,
        "inventory": dict(inventory),
        "shards": normalized_shards,
        "raw_returned": False,
        "plan_sha256": value["plan_sha256"],
    }


def _load_plan(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RegressionShardError("plan_unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegressionShardError("plan_unreadable") from exc
    return validate_plan(value)


def _write_new_json(path: Path, payload: Mapping[str, Any]) -> None:
    output = _outside_repository(path)
    if output.exists():
        raise RegressionShardError("output_already_exists")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("xb") as stream:
            stream.write(_canonical_bytes(payload))
    except OSError as exc:
        raise RegressionShardError("output_unavailable") from exc


def _current_plan_matches(plan: Mapping[str, Any]) -> bool:
    return _inventory_binding(_test_files()) == plan["inventory"]


def run_shard(plan_path: Path, shard_id: str, run_directory: Path) -> dict[str, Any]:
    plan = _load_plan(plan_path)
    if not _current_plan_matches(plan):
        raise RegressionShardError("test_inventory_changed_since_plan")
    selected = next((item for item in plan["shards"] if item["id"] == shard_id), None)
    if selected is None:
        raise RegressionShardError("shard_unknown")
    directory, _ = prepare_run(run_directory, tuple(selected["selectors"]))
    return run_worker(directory, tuple(selected["selectors"]))


def _load_receipt(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise RegressionShardError("receipt_unavailable")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegressionShardError("receipt_unreadable") from exc
    if not isinstance(value, dict) or value.get("schema") != ATTESTATION_SCHEMA:
        raise RegressionShardError("receipt_invalid")
    if value.get("receipt_sha256") != _receipt_hash(value):
        raise RegressionShardError("receipt_hash_invalid")
    return value


def aggregate(
    plan: Mapping[str, Any],
    receipt_paths: Sequence[Path],
    *,
    target_capturer: TargetCapturer = capture_target,
) -> dict[str, Any]:
    valid_plan = validate_plan(plan)
    errors: list[str] = []
    expected = {item["selector_binding"]["selector_sha256"]: item for item in valid_plan["shards"]}
    if len(receipt_paths) != len(expected):
        errors.append("receipt_count_mismatch")
    seen: set[str] = set()
    receipts: list[dict[str, Any]] = []
    baseline_target: Mapping[str, str] | None = None
    totals = {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "duration_ms": 0}
    for path in receipt_paths:
        try:
            receipt = _load_receipt(path)
        except RegressionShardError as exc:
            errors.append(str(exc))
            continue
        binding = receipt.get("selector_binding")
        if not isinstance(binding, dict):
            errors.append("receipt_selector_binding_invalid")
            continue
        binding_sha = binding.get("selector_sha256")
        expected_shard = expected.get(binding_sha)
        if expected_shard is None or binding != expected_shard["selector_binding"]:
            errors.append("receipt_selector_binding_mismatch")
            continue
        if binding_sha in seen:
            errors.append("receipt_shard_duplicate")
            continue
        seen.add(binding_sha)
        if receipt.get("status") != "COMPLETE" or receipt.get("complete") is not True:
            errors.append("receipt_not_complete")
            continue
        if receipt.get("target_before") != receipt.get("target_after"):
            errors.append("receipt_target_drift")
            continue
        if baseline_target is None:
            baseline_target = receipt.get("target_before")
        elif receipt.get("target_before") != baseline_target:
            errors.append("receipt_target_mismatch")
            continue
        test_run = receipt.get("test_run")
        summary = test_run.get("summary") if isinstance(test_run, dict) else None
        if not isinstance(summary, dict) or test_run.get("all_tests_passed") is not True:
            errors.append("receipt_test_summary_invalid")
            continue
        try:
            for key in ("total", "passed", "failed", "errors", "skipped"):
                value = summary[key]
                if not isinstance(value, int) or value < 0:
                    raise KeyError(key)
                totals[key] += value
            duration = test_run["duration_ms"]
            if not isinstance(duration, int) or duration < 0:
                raise KeyError("duration_ms")
            totals["duration_ms"] += duration
        except (KeyError, TypeError):
            errors.append("receipt_test_summary_invalid")
            continue
        receipts.append({"receipt_sha256": receipt["receipt_sha256"], "selector_sha256": binding_sha})
    if set(expected) != seen:
        errors.append("shard_coverage_incomplete")
    current_target = dict(target_capturer(ROOT))
    if baseline_target is None or current_target != baseline_target:
        errors.append("aggregate_target_mismatch")
    payload: dict[str, Any] = {
        "schema": AGGREGATE_SCHEMA,
        "status": "COMPLETE" if not errors else "CONTROL_HOLD",
        "complete": not errors,
        "plan_sha256": valid_plan["plan_sha256"],
        "target": baseline_target,
        "shard_count": len(valid_plan["shards"]),
        "completed_shard_count": len(receipts),
        "test_summary": totals,
        "receipt_bindings": sorted(receipts, key=lambda item: item["selector_sha256"]),
        "control_errors": sorted(set(errors)),
        "claim_boundary": {
            "product_accuracy_proven": False,
            "release_gate_passed": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }
    payload["aggregate_sha256"] = _sha256_bytes(_canonical_bytes(payload))
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan, run, and aggregate bounded pytest regression shards.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--output", required=True)
    plan_parser.add_argument("--shard-count", type=int, default=DEFAULT_SHARD_COUNT)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--plan", required=True)
    run_parser.add_argument("--shard", required=True)
    run_parser.add_argument("--run-dir", required=True)
    aggregate_parser = subparsers.add_parser("aggregate")
    aggregate_parser.add_argument("--plan", required=True)
    aggregate_parser.add_argument("--receipt", action="append", required=True)
    aggregate_parser.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "plan":
            payload = build_plan(args.shard_count)
            _write_new_json(Path(args.output), payload)
        elif args.command == "run":
            payload = run_shard(Path(args.plan), args.shard, Path(args.run_dir))
        else:
            plan = _load_plan(Path(args.plan))
            payload = aggregate(plan, [Path(item) for item in args.receipt])
            _write_new_json(Path(args.output), payload)
    except RegressionShardError as exc:
        print(json.dumps({"status": "CONTROL_HOLD", "control_errors": [str(exc)], "raw_returned": False}, sort_keys=True))
        return 2
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    if args.command == "plan" or payload.get("status") == "COMPLETE":
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
