from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
STAGER_PATH = Path(__file__).resolve(strict=True)
BLUEPRINT_BUILDER_PATH = REPOSITORY_ROOT / "scripts" / "build_l3_generated_pair_blueprint.py"
SCHEMA = "k_guard_l3_generated_pair_staging.v1"
VERSION = "1.0.0"
MARKER_SCHEMA = "k_guard_l3_generated_pair_stage_marker.v1"
MARKER_FILENAME = "stage-marker.json"
EXPECTED_BLUEPRINT_SHA256 = "3489c9a802a960a1c31451cb12d3cd2976d8c87be0c4c37c7c9e7fcf8a05e2a6"
TRIPLET_STATES = ("vulnerable", "fixed", "negative")
CANDIDATE_RANKS = (0, 1)

CLAIM_BOUNDARY = {
    "source_triplet_paths_reserved": True,
    "source_triplets_materialized": False,
    "execution_oracles_proved": False,
    "scanner_output_observed": False,
    "eligible_for_tp_fp_fn": False,
    "eligible_for_h100": False,
    "release_gate_passed": False,
    "raw_source_returned": False,
}

STAGING_CONTRACT = {
    "slot_count": 60,
    "candidates_per_slot": 2,
    "primary_candidates_per_slot": 1,
    "reserve_candidates_per_slot": 1,
    "candidate_rank_order": [0, 1],
    "replacement_policy": "same_slot_fixed_reserve_order_only",
    "stage_layout": "slots/<slot_id>/candidate-<rank>/<vulnerable|fixed|negative>",
    "triplet_states": list(TRIPLET_STATES),
    "stage_marker_filename": MARKER_FILENAME,
    "empty_triplet_directories_required": True,
    "source_content_permitted": False,
}


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _domain_hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("staging_duplicate_json_key")
        result[key] = item
    return result


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve(strict=True))
        return True
    except ValueError:
        return False


def _require_external_path(path: Path, error: str) -> None:
    if not path.is_absolute() or _is_within_repository(path):
        raise ValueError(error)


def _paths_overlap(first: Path, second: Path) -> bool:
    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    try:
        first_resolved.relative_to(second_resolved)
        return True
    except ValueError:
        pass
    try:
        second_resolved.relative_to(first_resolved)
        return True
    except ValueError:
        return False


def _load_blueprint_builder() -> tuple[Any, str]:
    raw_before = BLUEPRINT_BUILDER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_generated_pair_blueprint_for_staging", BLUEPRINT_BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("blueprint_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if BLUEPRINT_BUILDER_PATH.read_bytes() != raw_before:
        raise ValueError("blueprint_builder_changed_while_loading")
    return module, _sha256_bytes(raw_before)


def load_external_blueprint(path: Path) -> tuple[dict[str, Any], str, str]:
    _require_external_path(path, "blueprint_input_must_be_external")
    if not path.is_file() or path.is_symlink():
        raise ValueError("blueprint_input_path_invalid")
    builder, builder_sha256 = _load_blueprint_builder()
    raw_before = path.read_bytes()
    blueprint = builder.load_blueprint(path)
    if path.read_bytes() != raw_before:
        raise ValueError("blueprint_changed_while_loading")
    if blueprint["blueprint_sha256"] != EXPECTED_BLUEPRINT_SHA256:
        raise ValueError("blueprint_content_sha256_not_preregistered")
    return blueprint, _sha256_bytes(raw_before), builder_sha256


def _candidate_role(rank: int) -> str:
    if rank == 0:
        return "primary"
    if rank == 1:
        return "reserve"
    raise ValueError("candidate_rank_invalid")


def _candidate_record(slot: Mapping[str, Any], rank: int, blueprint_sha256: str) -> dict[str, Any]:
    role = _candidate_role(rank)
    root = f"slots/{slot['slot_id']}/candidate-{rank}"
    triplet_relative_paths = {state: f"{root}/{state}" for state in TRIPLET_STATES}
    record: dict[str, Any] = {
        "slot_id": slot["slot_id"],
        "scenario_id": slot["scenario_id"],
        "oracle_id": slot["oracle_id"],
        "plane": slot["plane"],
        "family": slot["family"],
        "language": slot["language"],
        "framework": slot["framework"],
        "coverage_tags": list(slot["coverage_tags"]),
        "cwe": slot["cwe"],
        "severity": slot["severity"],
        "generator_profile": slot["generator_profile"],
        "candidate_rank": rank,
        "candidate_role": role,
        "candidate_relative_root": root,
        "triplet_relative_paths": triplet_relative_paths,
        "stage_marker_relative_path": f"{root}/{MARKER_FILENAME}",
    }
    record["stage_marker_sha256"] = _sha256_bytes(canonical_json_bytes(_marker_payload(record, blueprint_sha256)))
    return record


def _marker_payload(candidate: Mapping[str, Any], blueprint_sha256: str) -> dict[str, Any]:
    return {
        "schema": MARKER_SCHEMA,
        "version": VERSION,
        "blueprint_sha256": blueprint_sha256,
        "slot_id": candidate["slot_id"],
        "scenario_id": candidate["scenario_id"],
        "oracle_id": candidate["oracle_id"],
        "candidate_rank": candidate["candidate_rank"],
        "candidate_role": candidate["candidate_role"],
        "candidate_relative_root": candidate["candidate_relative_root"],
        "triplet_relative_paths": candidate["triplet_relative_paths"],
        "claim_boundary": {
            "source_triplets_materialized": False,
            "execution_oracles_proved": False,
            "raw_source_returned": False,
        },
        "raw_source_returned": False,
    }


def expected_candidates(blueprint: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for slot in blueprint["slots"]:
        for rank in CANDIDATE_RANKS:
            candidates.append(_candidate_record(slot, rank, blueprint["blueprint_sha256"]))
    return candidates


def _expected_counts(blueprint: Mapping[str, Any]) -> dict[str, Any]:
    candidates = expected_candidates(blueprint)
    return {
        "slot_count": len(blueprint["slots"]),
        "candidate_count": len(candidates),
        "primary_candidate_count": sum(candidate["candidate_role"] == "primary" for candidate in candidates),
        "reserve_candidate_count": sum(candidate["candidate_role"] == "reserve" for candidate in candidates),
        "triplet_directory_count": len(candidates) * len(TRIPLET_STATES),
        "plane_candidate_counts": dict(sorted(Counter(candidate["plane"] for candidate in candidates).items())),
        "family_candidate_counts": dict(sorted(Counter(candidate["family"] for candidate in candidates).items())),
    }


def _stage_tree_projection(candidates: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    directories: set[str] = {"slots"}
    markers: list[dict[str, str]] = []
    for candidate in candidates:
        root = candidate["candidate_relative_root"]
        directories.add(str(Path("slots") / str(candidate["slot_id"])))
        directories.add(str(root))
        directories.update(str(path) for path in candidate["triplet_relative_paths"].values())
        markers.append(
            {
                "relative_path": candidate["stage_marker_relative_path"],
                "sha256": candidate["stage_marker_sha256"],
            }
        )
    return {
        "directories": sorted(Path(path).as_posix() for path in directories),
        "markers": sorted(markers, key=lambda item: item["relative_path"]),
    }


def _stage_tree_identity(candidates: Iterable[Mapping[str, Any]]) -> str:
    return _domain_hash(b"k_guard_l3_generated_pair_staging_tree.v1\0", _stage_tree_projection(candidates))


def _stage_root_binding(stage_root: Path) -> str:
    return hashlib.sha256(
        b"k_guard_l3_generated_pair_stage_root.v1\0" + str(stage_root.resolve(strict=True)).encode("utf-8")
    ).hexdigest()


def _expected_directories(candidates: Iterable[Mapping[str, Any]]) -> set[str]:
    return set(_stage_tree_projection(candidates)["directories"])


def _expected_marker_paths(candidates: Iterable[Mapping[str, Any]]) -> set[str]:
    return {str(candidate["stage_marker_relative_path"]) for candidate in candidates}


def _validate_stage_tree(stage_root: Path, candidates: list[dict[str, Any]], blueprint_sha256: str) -> None:
    _require_external_path(stage_root, "stage_root_must_be_external")
    if not stage_root.is_dir() or stage_root.is_symlink():
        raise ValueError("stage_root_path_invalid")

    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    for path in stage_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("staging_tree_symlink_forbidden")
        relative = path.relative_to(stage_root).as_posix()
        if path.is_dir():
            actual_directories.add(relative)
        elif path.is_file():
            actual_files.add(relative)
        else:
            raise ValueError("staging_tree_entry_type_invalid")

    if actual_directories != _expected_directories(candidates):
        raise ValueError("staging_tree_directories_invalid")
    if actual_files != _expected_marker_paths(candidates):
        raise ValueError("staging_tree_files_invalid")

    for candidate in candidates:
        marker_path = stage_root / str(candidate["stage_marker_relative_path"])
        raw = marker_path.read_bytes()
        try:
            marker = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("staging_marker_json_invalid") from exc
        if canonical_json_bytes(marker) != raw:
            raise ValueError("staging_marker_not_canonical")
        if marker != _marker_payload(candidate, blueprint_sha256):
            raise ValueError("staging_marker_content_invalid")
        if _sha256_bytes(raw) != candidate["stage_marker_sha256"]:
            raise ValueError("staging_marker_hash_mismatch")


def _stager_sha256() -> str:
    return _sha256_bytes(STAGER_PATH.read_bytes())


def _build_receipt(
    blueprint: Mapping[str, Any],
    blueprint_artifact_sha256: str,
    blueprint_builder_sha256: str,
    stage_root: Path,
) -> dict[str, Any]:
    candidates = expected_candidates(blueprint)
    _validate_stage_tree(stage_root, candidates, blueprint["blueprint_sha256"])
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "blueprint": {
            "artifact_sha256": blueprint_artifact_sha256,
            "content_sha256": blueprint["blueprint_sha256"],
            "builder_sha256": blueprint_builder_sha256,
        },
        "staging_contract": STAGING_CONTRACT,
        "stage_root_binding_sha256": _stage_root_binding(stage_root),
        "stage_tree_identity_sha256": _stage_tree_identity(candidates),
        "counts": _expected_counts(blueprint),
        "candidates": candidates,
        "claim_boundary": CLAIM_BOUNDARY,
        "raw_source_returned": False,
        "stager_sha256": _stager_sha256(),
    }


def validate_staging_receipt(
    value: object,
    *,
    blueprint: Mapping[str, Any],
    blueprint_artifact_sha256: str,
    blueprint_builder_sha256: str,
    stage_root: Path,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("staging_receipt_not_object")
    expected_keys = {
        "schema",
        "version",
        "blueprint",
        "staging_contract",
        "stage_root_binding_sha256",
        "stage_tree_identity_sha256",
        "counts",
        "candidates",
        "claim_boundary",
        "raw_source_returned",
        "stager_sha256",
    }
    if set(value) != expected_keys:
        raise ValueError("staging_receipt_keys_invalid")
    if value["schema"] != SCHEMA or value["version"] != VERSION:
        raise ValueError("staging_receipt_schema_or_version_invalid")
    expected_blueprint = {
        "artifact_sha256": blueprint_artifact_sha256,
        "content_sha256": blueprint["blueprint_sha256"],
        "builder_sha256": blueprint_builder_sha256,
    }
    if value["blueprint"] != expected_blueprint:
        raise ValueError("staging_blueprint_binding_invalid")
    if value["staging_contract"] != STAGING_CONTRACT:
        raise ValueError("staging_contract_invalid")
    if value["stage_root_binding_sha256"] != _stage_root_binding(stage_root):
        raise ValueError("staging_stage_root_binding_mismatch")
    candidates = expected_candidates(blueprint)
    if value["candidates"] != candidates:
        raise ValueError("staging_candidates_invalid")
    if value["counts"] != _expected_counts(blueprint):
        raise ValueError("staging_counts_invalid")
    if value["claim_boundary"] != CLAIM_BOUNDARY or value["raw_source_returned"] is not False:
        raise ValueError("staging_claim_boundary_invalid")
    if value["stager_sha256"] != _stager_sha256():
        raise ValueError("staging_stager_sha256_mismatch")
    if value["stage_tree_identity_sha256"] != _stage_tree_identity(candidates):
        raise ValueError("staging_tree_identity_invalid")
    _validate_stage_tree(stage_root, candidates, blueprint["blueprint_sha256"])
    return dict(value)


def _write_receipt(output: Path, receipt: Mapping[str, Any]) -> None:
    _require_external_path(output, "staging_receipt_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_staging_receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_staging_receipt") from exc


def stage_source_triplets(blueprint_path: Path, stage_root: Path, output: Path) -> dict[str, Any]:
    _require_external_path(blueprint_path, "blueprint_input_must_be_external")
    _require_external_path(stage_root, "stage_root_must_be_external")
    _require_external_path(output, "staging_receipt_output_must_be_external")
    if stage_root.exists() or stage_root.is_symlink():
        raise ValueError("refusing_to_overwrite_staging_root")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_staging_receipt")
    if _paths_overlap(stage_root, output):
        raise ValueError("staging_root_and_receipt_must_not_overlap")

    blueprint, blueprint_artifact_sha256, blueprint_builder_sha256 = load_external_blueprint(blueprint_path)
    candidates = expected_candidates(blueprint)
    stage_root.mkdir(parents=True, exist_ok=False)
    for candidate in candidates:
        candidate_root = stage_root / str(candidate["candidate_relative_root"])
        candidate_root.mkdir(parents=True, exist_ok=False)
        for relative_path in candidate["triplet_relative_paths"].values():
            (stage_root / str(relative_path)).mkdir(exist_ok=False)
        marker_path = stage_root / str(candidate["stage_marker_relative_path"])
        with marker_path.open("xb") as stream:
            stream.write(canonical_json_bytes(_marker_payload(candidate, blueprint["blueprint_sha256"])))
            stream.flush()
            os.fsync(stream.fileno())

    receipt = _build_receipt(blueprint, blueprint_artifact_sha256, blueprint_builder_sha256, stage_root)
    _write_receipt(output, receipt)
    return receipt


def load_staging_receipt(receipt_path: Path, blueprint_path: Path, stage_root: Path) -> dict[str, Any]:
    _require_external_path(receipt_path, "staging_receipt_input_must_be_external")
    _require_external_path(blueprint_path, "blueprint_input_must_be_external")
    _require_external_path(stage_root, "stage_root_must_be_external")
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError("staging_receipt_input_path_invalid")
    raw = receipt_path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("staging_receipt_json_invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("staging_receipt_not_canonical")
    blueprint, blueprint_artifact_sha256, blueprint_builder_sha256 = load_external_blueprint(blueprint_path)
    return validate_staging_receipt(
        value,
        blueprint=blueprint,
        blueprint_artifact_sha256=blueprint_artifact_sha256,
        blueprint_builder_sha256=blueprint_builder_sha256,
        stage_root=stage_root,
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reserve P2.4B.1 external raw-free source-triplet staging paths without materializing source."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("stage")
    stage.add_argument("--blueprint", type=Path, required=True)
    stage.add_argument("--stage-root", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--blueprint", type=Path, required=True)
    validate.add_argument("--stage-root", type=Path, required=True)
    validate.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            receipt = stage_source_triplets(args.blueprint, args.stage_root, args.output)
        else:
            receipt = load_staging_receipt(args.input, args.blueprint, args.stage_root)
    except (OSError, ValueError) as exc:
        print(f"stage_l3_generated_pair_source_triplets: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "candidate_count": receipt["counts"]["candidate_count"],
                "raw_source_returned": False,
                "source_triplets_materialized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
