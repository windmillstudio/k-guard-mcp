from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_release_program_goal_state_repeats.py"
SPEC = importlib.util.spec_from_file_location("compare_release_program_goal_state_repeats_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)

STATE_PATH = Path(__file__).parents[1] / "docs" / "release-program-goal-state.json"


def _summary() -> dict[str, object]:
    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    summary = comparison.goal_control.validate_goal_state(state)
    summary["human_status_boards"] = comparison.goal_control.validate_current_status_boards(state)
    return summary


def _write(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(comparison.goal_control.canonical_json_bytes(value))


def test_repeat_comparator_accepts_same_goal_state_summary(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write(first, _summary())
    _write(second, _summary())

    result = comparison.compare_runs(first, second)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["active_card_id"] == "P2.4B.3.13"
    assert result["raw_returned"] is False


def test_repeat_comparator_rejects_changed_target_or_goal_state(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_value = _summary()
    second_value = copy.deepcopy(first_value)
    second_value["target"]["dirty_worktree_sha256"] = "0" * 64
    _write(first, first_value)
    _write(second, second_value)

    result = comparison.compare_runs(first, second)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False


def test_repeat_comparator_rejects_changed_human_status_board_set(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first_value = _summary()
    second_value = copy.deepcopy(first_value)
    second_value["human_status_boards"] = ["docs/stale-status-board.md"]
    _write(first, first_value)
    _write(second, second_value)

    with pytest.raises(ValueError, match="human status boards"):
        comparison.compare_runs(first, second)


def test_repeat_comparator_rejects_noncanonical_or_wrong_active_state(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema":"k_guard_release_program_goal_state.v1"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="canonical JSON"):
        comparison.compare_runs(bad, bad)
