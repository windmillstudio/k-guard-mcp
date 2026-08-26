from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "regression_shards.py"
SPEC = importlib.util.spec_from_file_location("regression_shards_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
shards = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shards
SPEC.loader.exec_module(shards)


def _target(_: Path) -> dict[str, str]:
    return {
        "head_git_oid": "a" * 40,
        "dirty_path_set_sha256": "b" * 64,
        "dirty_worktree_sha256": "c" * 64,
    }


def _receipt(binding: dict[str, object], *, target: dict[str, str]) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": shards.ATTESTATION_SCHEMA,
        "status": "COMPLETE",
        "complete": True,
        "selector_binding": binding,
        "target_before": target,
        "target_after": target,
        "test_run": {
            "duration_ms": 11,
            "summary": {"total": 2, "passed": 2, "failed": 0, "errors": 0, "skipped": 0},
            "all_tests_passed": True,
        },
        "raw_returned": False,
    }
    value["receipt_sha256"] = shards._receipt_hash(value)
    return value


def test_plan_is_deterministic_and_covers_each_test_file_once() -> None:
    first = shards.build_plan(12)
    second = shards.build_plan(12)

    assert first == second
    validated = shards.validate_plan(first)
    selectors = [selector for shard in validated["shards"] for selector in shard["selectors"]]
    assert len(selectors) == len(set(selectors)) == validated["inventory"]["test_file_count"]
    assert validated["inventory"] == shards._inventory_binding(shards._test_files())


def test_aggregate_requires_every_bound_shard_once(tmp_path: Path) -> None:
    plan = shards.build_plan(2)
    target = _target(ROOT)
    receipt_paths = []
    for index, shard in enumerate(plan["shards"], start=1):
        path = tmp_path / f"shard-{index}.json"
        path.write_text(json.dumps(_receipt(shard["selector_binding"], target=target)), encoding="utf-8")
        receipt_paths.append(path)

    aggregate = shards.aggregate(plan, receipt_paths, target_capturer=_target)

    assert aggregate["status"] == "COMPLETE"
    assert aggregate["completed_shard_count"] == 2
    assert aggregate["test_summary"]["passed"] == 4
    assert aggregate["claim_boundary"]["release_gate_passed"] is False


def test_aggregate_fails_closed_for_missing_shard(tmp_path: Path) -> None:
    plan = shards.build_plan(2)
    path = tmp_path / "one.json"
    path.write_text(json.dumps(_receipt(plan["shards"][0]["selector_binding"], target=_target(ROOT))), encoding="utf-8")

    aggregate = shards.aggregate(plan, [path], target_capturer=_target)

    assert aggregate["status"] == "CONTROL_HOLD"
    assert "receipt_count_mismatch" in aggregate["control_errors"]
    assert "shard_coverage_incomplete" in aggregate["control_errors"]


def test_cli_exposes_plan_run_and_aggregate() -> None:
    completed = __import__("subprocess").run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "plan" in completed.stdout
    assert "run" in completed.stdout
    assert "aggregate" in completed.stdout


def test_plan_command_returns_success_after_writing_a_plan(tmp_path: Path) -> None:
    output = tmp_path / "plan.json"

    exit_code = shards.main(("plan", "--output", str(output), "--shard-count", "2"))

    assert exit_code == 0
    assert shards.validate_plan(json.loads(output.read_text(encoding="utf-8")))["shards"]
