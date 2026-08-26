from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
BUILDER_PATH = REPOSITORY_ROOT / "scripts" / "build_l3_generated_pair_blueprint.py"
SCHEMA = "k_guard_l3_generated_pair_blueprint_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _load_builder() -> tuple[Any, str]:
    raw_before = BUILDER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_generated_pair_blueprint", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("blueprint_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if BUILDER_PATH.read_bytes() != raw_before:
        raise ValueError("blueprint_builder_changed_while_loading")
    return module, hashlib.sha256(raw_before).hexdigest()


def _projection(blueprint: Mapping[str, Any], builder_sha256: str) -> dict[str, Any]:
    return {
        "schema": blueprint["schema"],
        "version": blueprint["version"],
        "blueprint_sha256": blueprint["blueprint_sha256"],
        "candidate_materialization": blueprint["candidate_materialization"],
        "claim_boundary": blueprint["claim_boundary"],
        "generator_profiles": blueprint["generator_profiles"],
        "oracle_contract": blueprint["oracle_contract"],
        "required_evidence_keys": blueprint["required_evidence_keys"],
        "slot_count": blueprint["slot_count"],
        "plane_counts": blueprint["plane_counts"],
        "slots": blueprint["slots"],
        "builder_sha256": builder_sha256,
    }


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve(strict=True))
        return True
    except ValueError:
        return False


def compare_blueprints(first_path: Path, second_path: Path) -> dict[str, Any]:
    if (
        not first_path.is_absolute()
        or not second_path.is_absolute()
        or _is_within_repository(first_path)
        or _is_within_repository(second_path)
    ):
        raise ValueError("blueprint_comparison_inputs_must_be_external")
    builder, builder_sha256 = _load_builder()
    first = builder.load_blueprint(first_path)
    second = builder.load_blueprint(second_path)
    first_projection = _projection(first, builder_sha256)
    second_projection = _projection(second, builder_sha256)
    first_fingerprint = hashlib.sha256(canonical_json_bytes(first_projection)).hexdigest()
    second_fingerprint = hashlib.sha256(canonical_json_bytes(second_projection)).hexdigest()
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "first_blueprint_sha256": first["blueprint_sha256"],
        "second_blueprint_sha256": second["blueprint_sha256"],
        "builder_sha256": builder_sha256,
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "blueprint_repeatability_proven": repeat_exact,
            "source_triplets_materialized": False,
            "execution_oracles_proved": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
        },
        "raw_source_returned": False,
    }


def write_comparison(output: Path, comparison: Mapping[str, Any]) -> None:
    if not output.is_absolute() or _is_within_repository(output):
        raise ValueError("blueprint_comparison_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_blueprint_comparison")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(comparison)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_blueprint_comparison") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two P2.4A raw-free generated-pair blueprints.")
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        comparison = compare_blueprints(args.first, args.second)
        write_comparison(args.output, comparison)
    except (OSError, ValueError) as exc:
        print(f"compare_l3_generated_pair_blueprint_repeats: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": comparison["status"], "repeat_exact": comparison["repeat_exact"], "raw_source_returned": False}, sort_keys=True))
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
