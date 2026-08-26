from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "validate_release_program_goals.py"
SPEC = importlib.util.spec_from_file_location("validate_release_program_goals_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
goal_control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(goal_control)

STATE_PATH = Path(__file__).parents[1] / "docs" / "release-program-goal-state.json"
REGISTRY_PATH = Path(__file__).parents[1] / "docs" / "release-program-product-card-registry.json"


def _state() -> dict[str, object]:
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def _registry() -> dict[str, object]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def _validate_registry(registry: dict[str, object], state: dict[str, object] | None = None) -> dict[str, object]:
    payload = _state() if state is None else state
    goals = goal_control._index_records(payload["goals"], label="goals")
    phases = goal_control._index_records(payload["phases"], label="phases")
    return goal_control._validate_product_work_card_registry(
        registry,
        root=STATE_PATH.parents[1],
        goals=goals,
        phases=phases,
        active_card=payload["active_card"],
        paused_cards=payload["paused_cards"],
        review_policy=payload["review_policy"],
    )


def test_checked_in_goal_state_has_one_explicit_active_card() -> None:
    state = _state()
    registry = _registry()
    summary = goal_control.validate_goal_state(state)
    registry_active = next(card for card in registry["cards"] if card["id"] == state["active_card"]["id"])

    assert summary["active_card_id"] == "P2.4B.3.13"
    assert summary["paused_card_ids"] == []
    assert summary["review_providers"] == ["claude", "grok"]
    assert summary["review_runs"] == 2
    assert summary["product_work_card_count"] == 110
    assert summary["product_work_card_active_id"] == "P2.4B.3.13"
    assert summary["product_work_card_open_count"] == 83
    assert summary["product_work_card_phase_exit_count"] == 9
    assert state["active_card"]["completed_gates"] == registry_active["completed_gates"]
    assert state["active_card"]["next_gate"] == registry_active["next_gate"]


def test_human_status_boards_match_the_canonical_active_card() -> None:
    assert goal_control.validate_current_status_boards(_state()) == list(goal_control.HUMAN_STATUS_BOARDS)


def test_human_status_board_rejects_a_stale_marker(tmp_path: Path) -> None:
    payload = _state()
    marker = goal_control.current_status_marker(payload["active_card"])
    for reference in goal_control.HUMAN_STATUS_BOARDS:
        destination = tmp_path / reference
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(marker, encoding="utf-8")
    stale = tmp_path / goal_control.HUMAN_STATUS_BOARDS[0]
    stale.write_text("<!-- release-program-current-card: stale -->", encoding="utf-8")

    with pytest.raises(ValueError, match="marker is stale"):
        goal_control.validate_current_status_boards(payload, root=tmp_path)


def test_goal_state_rejects_non_prefix_completed_gates() -> None:
    payload = copy.deepcopy(_state())
    payload["active_card"]["completed_gates"] = ["A", "C"]

    with pytest.raises(ValueError, match="ordered gate prefix"):
        goal_control.validate_goal_state(payload)


def test_goal_state_rejects_second_active_card() -> None:
    payload = copy.deepcopy(_state())
    duplicate = copy.deepcopy(payload["active_card"])
    duplicate["status"] = "ACTIVE"
    payload["paused_cards"] = [duplicate]

    with pytest.raises(ValueError, match="paused_card status"):
        goal_control.validate_goal_state(payload)


def test_goal_state_rejects_an_active_card_that_drifts_from_registry() -> None:
    payload = copy.deepcopy(_state())
    payload["active_card"] = {
        "board_reference": "docs/release-program-goal-control-ko.md",
        "completed_gates": ["A"],
        "goal_id": "G7",
        "id": "P8.1",
        "next_gate": "B",
        "phase_id": "P8",
        "status": "ACTIVE",
        "title": "goal-control bootstrap",
    }

    with pytest.raises(ValueError, match="product work-card active card is invalid"):
        goal_control.validate_goal_state(payload)


def test_goal_state_rejects_a_deprecated_glm_review_lane() -> None:
    payload = copy.deepcopy(_state())
    payload["review_policy"]["required_models"]["glm"] = "cline-pass/glm-5.2"

    with pytest.raises(ValueError, match="supervisor requirement"):
        goal_control.validate_goal_state(payload)


def test_goal_state_rejects_release_when_work_is_incomplete() -> None:
    payload = copy.deepcopy(_state())
    payload["program_status"] = "GO_RELEASE"
    payload["north_star"]["status"] = "GO_RELEASE"

    with pytest.raises(ValueError, match="GO_RELEASE requires"):
        goal_control.validate_goal_state(payload)


def test_product_work_card_registry_rejects_duplicate_card_id() -> None:
    registry = _registry()
    registry["cards"].append(copy.deepcopy(registry["cards"][0]))

    with pytest.raises(ValueError, match="product work-card id is duplicated"):
        _validate_registry(registry)


def test_product_work_card_registry_rejects_unknown_dependency() -> None:
    registry = _registry()
    registry["cards"][0]["depends_on"] = ["does-not-exist"]

    with pytest.raises(ValueError, match="product work-card dependency is unknown"):
        _validate_registry(registry)


def test_product_work_card_registry_rejects_missing_phase_exit() -> None:
    registry = _registry()
    registry["cards"][0]["phase_exit"] = False

    with pytest.raises(ValueError, match="product work-card phase exit is invalid"):
        _validate_registry(registry)


def test_product_work_card_registry_rejects_fake_fix() -> None:
    registry = _registry()
    fixed = next(card for card in registry["cards"] if card["id"] == "P8.2D")
    fixed["completed_gates"] = ["A"]

    with pytest.raises(ValueError, match="FIX_NARROW requires every gate"):
        _validate_registry(registry)


def test_product_work_card_registry_rejects_stale_catalog_binding() -> None:
    registry = _registry()
    registry["catalog_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="catalog binding is stale"):
        _validate_registry(registry)
