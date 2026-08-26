from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SCHEMA = "k_guard_release_program_goal_state_repeat_comparison.v1"
EXPECTED_SUMMARY_KEYS = {
    "active_card_id",
    "goal_count",
    "human_status_boards",
    "north_star",
    "paused_card_ids",
    "phase_count",
    "program_status",
    "product_work_card_active_id",
    "product_work_card_count",
    "product_work_card_open_count",
    "product_work_card_phase_exit_count",
    "review_providers",
    "review_runs",
    "schema",
    "target",
}


def _load_goal_control_module() -> Any:
    module_path = REPOSITORY_ROOT / "scripts" / "validate_release_program_goals.py"
    spec = importlib.util.spec_from_file_location("validate_release_program_goals", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("goal-state validator module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


goal_control = _load_goal_control_module()


def _load_canonical(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("goal-state repeat input is invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("goal-state repeat input must be canonical JSON") from exc
    if not isinstance(value, dict) or goal_control.canonical_json_bytes(value) != raw:
        raise ValueError("goal-state repeat input must be canonical JSON")
    if set(value) != EXPECTED_SUMMARY_KEYS or value.get("schema") != goal_control.SCHEMA:
        raise ValueError("goal-state repeat input schema is invalid")
    if not isinstance(value.get("target"), dict) or set(value["target"]) != {
        "head_git_oid",
        "dirty_path_set_sha256",
        "dirty_worktree_sha256",
    }:
        raise ValueError("goal-state repeat input target is invalid")
    if not isinstance(value.get("active_card_id"), str) or not value["active_card_id"] or value.get("program_status") != "ACTIVE":
        raise ValueError("goal-state repeat input active state is invalid")
    if value.get("product_work_card_active_id") != value["active_card_id"]:
        raise ValueError("goal-state repeat input product work-card active state is invalid")
    product_card_count = value.get("product_work_card_count")
    product_open_count = value.get("product_work_card_open_count")
    product_phase_exit_count = value.get("product_work_card_phase_exit_count")
    if (
        not isinstance(product_card_count, int)
        or not isinstance(product_open_count, int)
        or not isinstance(product_phase_exit_count, int)
        or product_card_count < 1
        or product_open_count < 0
        or product_open_count > product_card_count
        or product_phase_exit_count != value.get("phase_count")
    ):
        raise ValueError("goal-state repeat input product work-card summary is invalid")
    boards = value.get("human_status_boards")
    if not isinstance(boards, list) or boards != list(goal_control.HUMAN_STATUS_BOARDS):
        raise ValueError("goal-state repeat input human status boards are invalid")
    if value.get("review_providers") != sorted(goal_control.REQUIRED_MODELS) or value.get("review_runs") != 2:
        raise ValueError("goal-state repeat input review policy is invalid")
    return value


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(goal_control.canonical_json_bytes(dict(value))).hexdigest()


def compare_runs(first: Path, second: Path) -> dict[str, Any]:
    first_value = _load_canonical(first)
    second_value = _load_canonical(second)
    first_fingerprint = _sha256(first_value)
    second_fingerprint = _sha256(second_value)
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "active_card_id": first_value["active_card_id"],
        "target": first_value["target"],
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_count_as_scorecard_achievement": False,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "raw_returned": False,
    }


def _write_canonical_new(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or goal_control._is_within(path, REPOSITORY_ROOT):
        raise ValueError("goal-state repeat output must be new and outside the repository")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(goal_control.canonical_json_bytes(dict(payload)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("goal-state repeat output must be new and outside the repository") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two release-program goal-state validation outputs.")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_runs(args.first, args.second)
        _write_canonical_new(args.output.expanduser().resolve(strict=False), result)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"HOLD: {exc}") from exc
    print(
        json.dumps(
            {
                "active_card_id": result["active_card_id"],
                "repeat_exact": result["repeat_exact"],
                "status": result["status"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if result["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
