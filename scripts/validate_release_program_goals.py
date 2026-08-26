from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SCHEMA = "k_guard_release_program_goal_state.v1"
PRODUCT_WORK_CARD_REGISTRY_SCHEMA = "k_guard_product_work_card_registry.v1"
CARD_GATES = ("A", "B", "C", "D", "E", "F1", "F2", "G")
REQUIRED_MODELS = {
    "claude": "claude-opus-5",
    "grok": "grok-4.6",
}
HUMAN_STATUS_BOARDS = (
    "docs/release-program-current-work-breakdown-ko.md",
    "docs/release-program-execution-map-ko.md",
    "docs/release-program-goal-register-ko.md",
)
PROGRAM_STATUSES = frozenset({"ACTIVE", "HOLD", "GO_RELEASE"})
GOAL_PHASE_STATUSES = frozenset(
    {"NOT_STARTED", "IN_PROGRESS", "FIX_NARROW", "MEASURED_HOLD", "BLOCKED"}
)
CARD_STATUSES = frozenset(
    {
        "NOT_STARTED",
        "ACTIVE",
        "PAUSED",
        "EVIDENCE_READY",
        "REVIEWING",
        "FIX_NARROW",
        "MEASURED_HOLD",
        "BLOCKED",
    }
)
PRODUCT_CARD_STATUSES = frozenset({"NOT_STARTED", "ACTIVE", "PAUSED", "FIX_NARROW", "MEASURED_HOLD", "BLOCKED"})


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except ValueError:
        return False


def _write_canonical_new(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink() or _is_within(path, REPOSITORY_ROOT):
        raise ValueError("goal-state evidence output must be new and outside the repository")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(payload)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("goal-state evidence output must be new and outside the repository") from exc


def _capture_target(root: Path) -> dict[str, str]:
    module_path = root / "scripts" / "capture_supervisor_target.py"
    spec = importlib.util.spec_from_file_location("capture_supervisor_target", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("target capture module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.capture_target(root)


def _load_canonical(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("goal state file is invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("goal state file must be UTF-8 JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ValueError("goal state file must use canonical JSON")
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is invalid")
    return value


def _require_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{label} is invalid")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} is duplicated")
    return list(value)


def _is_gate_prefix(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value) and tuple(value) == CARD_GATES[: len(value)]


def _reference_is_valid(root: Path, value: object, label: str) -> str:
    reference = _require_string(value, label)
    candidate = Path(reference)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"{label} is invalid")
    resolved = (root / candidate).resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"{label} is invalid")
    return reference


def _index_records(value: object, *, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} is invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for record in value:
        if not isinstance(record, dict):
            raise ValueError(f"{label} is invalid")
        identifier = _require_string(record.get("id"), f"{label} id")
        if identifier in indexed:
            raise ValueError(f"{label} id is duplicated")
        indexed[identifier] = record
    return indexed


def _validate_card(
    card: Mapping[str, Any],
    *,
    label: str,
    goal_ids: set[str],
    phase_ids: set[str],
    root: Path,
    expected_status: str | None = None,
) -> dict[str, Any]:
    allowed = {
        "board_reference",
        "completed_gates",
        "goal_id",
        "id",
        "next_gate",
        "phase_id",
        "resume_after",
        "status",
        "title",
    }
    if set(card) - allowed:
        raise ValueError(f"{label} fields are invalid")
    identifier = _require_string(card.get("id"), f"{label} id")
    title = _require_string(card.get("title"), f"{label} title")
    goal_id = _require_string(card.get("goal_id"), f"{label} goal_id")
    phase_id = _require_string(card.get("phase_id"), f"{label} phase_id")
    status = _require_string(card.get("status"), f"{label} status")
    if goal_id not in goal_ids or phase_id not in phase_ids or status not in CARD_STATUSES:
        raise ValueError(f"{label} relation is invalid")
    if expected_status is not None and status != expected_status:
        raise ValueError(f"{label} status is invalid")
    completed_gates = card.get("completed_gates")
    if not _is_gate_prefix(completed_gates):
        raise ValueError(f"{label} completed_gates must be an ordered gate prefix")
    if status == "FIX_NARROW" and tuple(completed_gates) != CARD_GATES:
        raise ValueError(f"{label} FIX_NARROW requires every gate")
    if status in {"ACTIVE", "PAUSED"} and not completed_gates:
        raise ValueError(f"{label} active or paused card requires a completed gate")
    if status in {"EVIDENCE_READY", "REVIEWING"} and tuple(completed_gates)[:5] != CARD_GATES[:5]:
        raise ValueError(f"{label} review state requires gates A through E")
    _reference_is_valid(root, card.get("board_reference"), f"{label} board_reference")
    next_gate = card.get("next_gate")
    if status == "ACTIVE":
        expected_next = CARD_GATES[len(completed_gates)] if len(completed_gates) < len(CARD_GATES) else None
        if next_gate != expected_next:
            raise ValueError(f"{label} next_gate is invalid")
    elif next_gate is not None:
        raise ValueError(f"{label} next_gate is invalid")
    if status == "PAUSED":
        _require_string(card.get("resume_after"), f"{label} resume_after")
    elif card.get("resume_after") is not None:
        raise ValueError(f"{label} resume_after is invalid")
    return {
        "completed_gates": list(completed_gates),
        "goal_id": goal_id,
        "id": identifier,
        "next_gate": next_gate,
        "phase_id": phase_id,
        "status": status,
        "title": title,
    }


def _require_optional_gate(value: object, *, status: str, completed_gates: list[str], label: str) -> str | None:
    if status == "NOT_STARTED":
        if completed_gates or value != "A":
            raise ValueError(f"{label} next_gate is invalid")
        return "A"
    if status == "ACTIVE":
        expected = CARD_GATES[len(completed_gates)] if len(completed_gates) < len(CARD_GATES) else None
        if value != expected:
            raise ValueError(f"{label} next_gate is invalid")
        return expected
    if value is not None:
        raise ValueError(f"{label} next_gate is invalid")
    return None


def _validate_product_work_card_registry(
    payload: object,
    *,
    root: Path,
    goals: Mapping[str, Mapping[str, Any]],
    phases: Mapping[str, Mapping[str, Any]],
    active_card: Mapping[str, Any],
    paused_cards: Sequence[Mapping[str, Any]],
    review_policy: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "as_of",
        "cards",
        "catalog_sha256",
        "catalog_reference",
        "default_claim_boundary",
        "review_profile",
        "schema",
    }:
        raise ValueError("product work-card registry schema is invalid")
    if payload.get("schema") != PRODUCT_WORK_CARD_REGISTRY_SCHEMA:
        raise ValueError("product work-card registry schema is invalid")
    _require_string(payload.get("as_of"), "product work-card registry as_of")
    _require_string(payload.get("default_claim_boundary"), "product work-card registry claim boundary")
    catalog_reference = _reference_is_valid(
        root,
        payload.get("catalog_reference"),
        "product work-card registry catalog_reference",
    )
    catalog_sha256 = _require_string(payload.get("catalog_sha256"), "product work-card registry catalog_sha256")
    if len(catalog_sha256) != 64 or any(character not in "0123456789abcdef" for character in catalog_sha256):
        raise ValueError("product work-card registry catalog_sha256 is invalid")
    if hashlib.sha256((root / catalog_reference).read_bytes()).hexdigest() != catalog_sha256:
        raise ValueError("product work-card registry catalog binding is stale")

    expected_profile = {
        "card_gates": list(CARD_GATES),
        "comparator_required_status": "FIX",
        "models": dict(REQUIRED_MODELS),
        "phase_review_required": True,
        "review_runs": 2,
    }
    if payload.get("review_profile") != expected_profile:
        raise ValueError("product work-card registry review profile is invalid")
    if review_policy.get("required_models") != expected_profile["models"]:
        raise ValueError("product work-card registry review policy drift")

    cards_payload = payload.get("cards")
    if not isinstance(cards_payload, list) or not cards_payload:
        raise ValueError("product work-card registry cards are invalid")
    cards: dict[str, dict[str, Any]] = {}
    for raw_card in cards_payload:
        if not isinstance(raw_card, dict) or set(raw_card) != {
            "completed_gates",
            "depends_on",
            "goal_id",
            "id",
            "next_gate",
            "phase_exit",
            "phase_id",
            "status",
            "title",
        }:
            raise ValueError("product work-card fields are invalid")
        identifier = _require_string(raw_card.get("id"), "product work-card id")
        if identifier in cards:
            raise ValueError("product work-card id is duplicated")
        goal_id = _require_string(raw_card.get("goal_id"), f"product work-card {identifier} goal_id")
        phase_id = _require_string(raw_card.get("phase_id"), f"product work-card {identifier} phase_id")
        if goal_id not in goals or phase_id not in phases or phases[phase_id]["goal_id"] != goal_id:
            raise ValueError("product work-card goal/phase relation is invalid")
        _require_string(raw_card.get("title"), f"product work-card {identifier} title")
        status = _require_string(raw_card.get("status"), f"product work-card {identifier} status")
        if status not in PRODUCT_CARD_STATUSES:
            raise ValueError("product work-card status is invalid")
        completed_gates = raw_card.get("completed_gates")
        if not _is_gate_prefix(completed_gates):
            raise ValueError("product work-card completed_gates must be an ordered gate prefix")
        if status == "FIX_NARROW" and tuple(completed_gates) != CARD_GATES:
            raise ValueError("product work-card FIX_NARROW requires every gate")
        _require_optional_gate(
            raw_card.get("next_gate"),
            status=status,
            completed_gates=list(completed_gates),
            label="product work-card",
        )
        dependencies = raw_card.get("depends_on")
        if not isinstance(dependencies, list) or any(not isinstance(item, str) or not item for item in dependencies):
            raise ValueError("product work-card dependencies are invalid")
        if len(dependencies) != len(set(dependencies)) or identifier in dependencies:
            raise ValueError("product work-card dependencies are invalid")
        if not isinstance(raw_card.get("phase_exit"), bool):
            raise ValueError("product work-card phase_exit is invalid")
        cards[identifier] = raw_card

    for identifier, card in cards.items():
        dependencies = card["depends_on"]
        if any(dependency not in cards for dependency in dependencies):
            raise ValueError("product work-card dependency is unknown")
        if card["status"] in {"ACTIVE", "FIX_NARROW"} and any(
            cards[dependency]["status"] != "FIX_NARROW" for dependency in dependencies
        ):
            raise ValueError("product work-card dependency is not closed")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise ValueError("product work-card dependency cycle is invalid")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in cards[identifier]["depends_on"]:
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in cards:
        visit(identifier)

    active_ids = [identifier for identifier, card in cards.items() if card["status"] == "ACTIVE"]
    if active_ids != [active_card["id"]]:
        raise ValueError("product work-card active card is invalid")
    registry_active = cards[active_card["id"]]
    for key in ("goal_id", "phase_id", "status", "completed_gates", "next_gate"):
        if registry_active[key] != active_card[key]:
            raise ValueError("product work-card active card drift")

    paused_by_id = {card["id"]: card for card in paused_cards}
    registry_paused = {identifier: card for identifier, card in cards.items() if card["status"] == "PAUSED"}
    if set(registry_paused) != set(paused_by_id):
        raise ValueError("product work-card paused set is invalid")
    for identifier, paused_card in paused_by_id.items():
        registry_card = registry_paused[identifier]
        for key in ("goal_id", "phase_id", "completed_gates"):
            if registry_card[key] != paused_card[key]:
                raise ValueError("product work-card paused card drift")

    phase_exits: dict[str, list[dict[str, Any]]] = {phase_id: [] for phase_id in phases}
    for card in cards.values():
        if card["phase_exit"]:
            phase_exits[card["phase_id"]].append(card)
    for phase_id, exits in phase_exits.items():
        if len(exits) != 1:
            raise ValueError("product work-card phase exit is invalid")
        phase_status = phases[phase_id]["status"]
        if phase_status == "FIX_NARROW" and exits[0]["status"] != "FIX_NARROW":
            raise ValueError("closed phase requires a closed product work-card phase exit")
        if phase_status != "FIX_NARROW" and exits[0]["status"] == "FIX_NARROW":
            raise ValueError("open phase cannot have a closed product work-card phase exit")

    open_cards = sorted(identifier for identifier, card in cards.items() if card["status"] != "FIX_NARROW")
    return {
        "product_work_card_count": len(cards),
        "product_work_card_active_id": active_card["id"],
        "product_work_card_open_count": len(open_cards),
        "product_work_card_phase_exit_count": sum(len(items) for items in phase_exits.values()),
    }


def current_status_marker(card: Mapping[str, Any]) -> str:
    completed_gates = card.get("completed_gates")
    if not isinstance(completed_gates, list):
        raise ValueError("active_card completed_gates is invalid")
    completed = ",".join(completed_gates)
    next_gate = card.get("next_gate") or "NONE"
    return (
        f"<!-- release-program-current-card: {card.get('id')}; status={card.get('status')}; "
        f"completed={completed}; next={next_gate} -->"
    )


def validate_current_status_boards(payload: Mapping[str, Any], *, root: Path = REPOSITORY_ROOT) -> list[str]:
    active_card = payload.get("active_card")
    if not isinstance(active_card, dict):
        raise ValueError("active_card is invalid")
    marker = current_status_marker(active_card)
    validated: list[str] = []
    for reference in HUMAN_STATUS_BOARDS:
        path = (root / reference).resolve(strict=True)
        try:
            path.relative_to(root.resolve(strict=True))
        except ValueError as exc:
            raise ValueError("human status board is invalid") from exc
        if not path.is_file() or path.is_symlink():
            raise ValueError("human status board is invalid")
        if path.read_text(encoding="utf-8").count(marker) != 1:
            raise ValueError(f"human status board marker is stale: {reference}")
        validated.append(reference)
    return validated


def validate_goal_state(payload: object, *, root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "active_card",
        "as_of",
        "goals",
        "north_star",
        "paused_cards",
        "phases",
        "program_status",
        "product_work_card_registry",
        "review_policy",
        "schema",
    }:
        raise ValueError("goal state schema is invalid")
    if payload.get("schema") != SCHEMA:
        raise ValueError("goal state schema is invalid")
    program_status = _require_string(payload.get("program_status"), "program_status")
    if program_status not in PROGRAM_STATUSES:
        raise ValueError("program_status is invalid")
    _require_string(payload.get("as_of"), "as_of")

    north_star = payload.get("north_star")
    if not isinstance(north_star, dict) or set(north_star) != {"id", "required_goal_ids", "status", "title"}:
        raise ValueError("north_star is invalid")
    if _require_string(north_star.get("id"), "north_star id") != "G0":
        raise ValueError("north_star id is invalid")
    if _require_string(north_star.get("title"), "north_star title") is None:
        raise ValueError("north_star title is invalid")
    if _require_string(north_star.get("status"), "north_star status") != program_status:
        raise ValueError("north_star status is invalid")

    goals = _index_records(payload.get("goals"), label="goals")
    goal_ids = set(goals)
    required_goal_ids = _require_string_list(north_star.get("required_goal_ids"), "north_star required_goal_ids")
    if set(required_goal_ids) != goal_ids:
        raise ValueError("north_star required_goal_ids must match goals")
    phases = _index_records(payload.get("phases"), label="phases")
    phase_ids = set(phases)
    for goal_id, goal in goals.items():
        if set(goal) != {"id", "phase_ids", "status", "title"}:
            raise ValueError("goal fields are invalid")
        if _require_string(goal.get("title"), f"goal {goal_id} title") is None:
            raise ValueError("goal title is invalid")
        if _require_string(goal.get("status"), f"goal {goal_id} status") not in GOAL_PHASE_STATUSES:
            raise ValueError("goal status is invalid")
        declared_phases = _require_string_list(goal.get("phase_ids"), f"goal {goal_id} phase_ids")
        if any(phase_id not in phase_ids for phase_id in declared_phases):
            raise ValueError("goal phase relation is invalid")
    for phase_id, phase in phases.items():
        if set(phase) != {"goal_id", "id", "phase_review_status", "status", "title", "work_board"}:
            raise ValueError("phase fields are invalid")
        goal_id = _require_string(phase.get("goal_id"), f"phase {phase_id} goal_id")
        if goal_id not in goal_ids or phase_id not in goals[goal_id]["phase_ids"]:
            raise ValueError("phase goal relation is invalid")
        if _require_string(phase.get("status"), f"phase {phase_id} status") not in GOAL_PHASE_STATUSES:
            raise ValueError("phase status is invalid")
        review_status = _require_string(phase.get("phase_review_status"), f"phase {phase_id} phase_review_status")
        if review_status not in GOAL_PHASE_STATUSES:
            raise ValueError("phase review status is invalid")
        if phase["status"] == "FIX_NARROW" and review_status != "FIX_NARROW":
            raise ValueError("FIX_NARROW phase requires its phase review")
        _require_string(phase.get("title"), f"phase {phase_id} title")
        _reference_is_valid(root, phase.get("work_board"), f"phase {phase_id} work_board")

    policy = payload.get("review_policy")
    if not isinstance(policy, dict) or set(policy) != {
        "card_gates",
        "card_review_required_after_gate",
        "phase_review_required",
        "required_models",
        "required_review_runs",
        "review_comparator_required_status",
    }:
        raise ValueError("review_policy is invalid")
    if tuple(policy.get("card_gates", [])) != CARD_GATES:
        raise ValueError("review_policy card_gates is invalid")
    if policy.get("card_review_required_after_gate") != "E" or policy.get("phase_review_required") is not True:
        raise ValueError("review_policy gate requirement is invalid")
    if policy.get("required_models") != REQUIRED_MODELS or policy.get("required_review_runs") != 2:
        raise ValueError("review_policy supervisor requirement is invalid")
    if policy.get("review_comparator_required_status") != "FIX":
        raise ValueError("review_policy comparator requirement is invalid")
    registry_reference = _reference_is_valid(
        root,
        payload.get("product_work_card_registry"),
        "product_work_card_registry",
    )

    active_card = payload.get("active_card")
    if not isinstance(active_card, dict):
        raise ValueError("active_card is invalid")
    active = _validate_card(
        active_card,
        label="active_card",
        goal_ids=goal_ids,
        phase_ids=phase_ids,
        root=root,
    )
    if active["status"] not in {"ACTIVE", "EVIDENCE_READY", "REVIEWING"}:
        raise ValueError("active_card status is invalid")
    paused_payload = payload.get("paused_cards")
    if not isinstance(paused_payload, list):
        raise ValueError("paused_cards is invalid")
    paused = [
        _validate_card(
            card,
            label="paused_card",
            goal_ids=goal_ids,
            phase_ids=phase_ids,
            root=root,
            expected_status="PAUSED",
        )
        for card in paused_payload
        if isinstance(card, dict)
    ]
    if len(paused) != len(paused_payload):
        raise ValueError("paused_cards is invalid")
    all_card_ids = [active["id"], *[card["id"] for card in paused]]
    if len(all_card_ids) != len(set(all_card_ids)):
        raise ValueError("active and paused cards are duplicated")
    product_summary = _validate_product_work_card_registry(
        _load_canonical(root / registry_reference),
        root=root,
        goals=goals,
        phases=phases,
        active_card=active,
        paused_cards=paused,
        review_policy=policy,
    )
    if program_status == "GO_RELEASE":
        if any(goal["status"] != "FIX_NARROW" for goal in goals.values()) or any(
            phase["status"] != "FIX_NARROW" for phase in phases.values()
        ):
            raise ValueError("GO_RELEASE requires every goal and phase to be FIX_NARROW")
        if paused:
            raise ValueError("GO_RELEASE cannot retain a paused card")
        if product_summary["product_work_card_open_count"]:
            raise ValueError("GO_RELEASE requires every product work-card to be FIX_NARROW")

    return {
        "schema": SCHEMA,
        "program_status": program_status,
        "north_star": north_star["id"],
        "goal_count": len(goals),
        "phase_count": len(phases),
        "active_card_id": active["id"],
        "paused_card_ids": sorted(card["id"] for card in paused),
        "review_providers": sorted(REQUIRED_MODELS),
        "review_runs": policy["required_review_runs"],
        **product_summary,
        "target": _capture_target(root),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the K-Guard release-program goal control contract.")
    parser.add_argument(
        "--state",
        type=Path,
        default=REPOSITORY_ROOT / "docs" / "release-program-goal-state.json",
        help="canonical goal-state JSON inside the repository",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="new canonical raw-free evidence file outside the repository",
    )
    args = parser.parse_args(argv)
    try:
        state_path = args.state.resolve(strict=True)
        state_path.relative_to(REPOSITORY_ROOT)
        payload = _load_canonical(state_path)
        result = validate_goal_state(payload, root=REPOSITORY_ROOT)
        result["human_status_boards"] = validate_current_status_boards(payload, root=REPOSITORY_ROOT)
        if args.output is not None:
            _write_canonical_new(args.output.expanduser().resolve(strict=False), result)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"HOLD: {exc}") from exc
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
