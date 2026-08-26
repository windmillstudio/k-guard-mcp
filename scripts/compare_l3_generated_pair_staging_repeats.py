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
STAGER_PATH = REPOSITORY_ROOT / "scripts" / "stage_l3_generated_pair_source_triplets.py"
SCHEMA = "k_guard_l3_generated_pair_staging_repeat_comparison.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def _is_within_repository(path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve(strict=True))
        return True
    except ValueError:
        return False


def _require_external_path(path: Path, error: str) -> None:
    if not path.is_absolute() or _is_within_repository(path):
        raise ValueError(error)


def _load_stager() -> tuple[Any, str]:
    raw_before = STAGER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_generated_pair_staging_for_comparison", STAGER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("staging_builder_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if STAGER_PATH.read_bytes() != raw_before:
        raise ValueError("staging_builder_changed_while_loading")
    return module, hashlib.sha256(raw_before).hexdigest()


def _projection(receipt: Mapping[str, Any], stager_sha256: str) -> dict[str, Any]:
    return {
        "schema": receipt["schema"],
        "version": receipt["version"],
        "blueprint": receipt["blueprint"],
        "staging_contract": receipt["staging_contract"],
        "stage_tree_identity_sha256": receipt["stage_tree_identity_sha256"],
        "counts": receipt["counts"],
        "candidates": receipt["candidates"],
        "claim_boundary": receipt["claim_boundary"],
        "raw_source_returned": receipt["raw_source_returned"],
        "stager_sha256": stager_sha256,
    }


def compare_staging_repeats(
    *,
    first_receipt_path: Path,
    first_blueprint_path: Path,
    first_stage_root: Path,
    second_receipt_path: Path,
    second_blueprint_path: Path,
    second_stage_root: Path,
) -> dict[str, Any]:
    for path, error in (
        (first_receipt_path, "staging_comparison_inputs_must_be_external"),
        (first_blueprint_path, "staging_comparison_inputs_must_be_external"),
        (first_stage_root, "staging_comparison_inputs_must_be_external"),
        (second_receipt_path, "staging_comparison_inputs_must_be_external"),
        (second_blueprint_path, "staging_comparison_inputs_must_be_external"),
        (second_stage_root, "staging_comparison_inputs_must_be_external"),
    ):
        _require_external_path(path, error)
    stager, stager_sha256 = _load_stager()
    first = stager.load_staging_receipt(first_receipt_path, first_blueprint_path, first_stage_root)
    second = stager.load_staging_receipt(second_receipt_path, second_blueprint_path, second_stage_root)
    first_projection = _projection(first, stager_sha256)
    second_projection = _projection(second, stager_sha256)
    first_fingerprint = hashlib.sha256(canonical_json_bytes(first_projection)).hexdigest()
    second_fingerprint = hashlib.sha256(canonical_json_bytes(second_projection)).hexdigest()
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "first_blueprint_content_sha256": first["blueprint"]["content_sha256"],
        "second_blueprint_content_sha256": second["blueprint"]["content_sha256"],
        "stager_sha256": stager_sha256,
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
            "staging_layout_repeatability_proven": repeat_exact,
            "source_triplets_materialized": False,
            "execution_oracles_proved": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
        },
        "raw_source_returned": False,
    }


def write_comparison(output: Path, comparison: Mapping[str, Any]) -> None:
    _require_external_path(output, "staging_comparison_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_staging_comparison")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(comparison)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_staging_comparison") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two P2.4B.1 raw-free staging receipts and empty stage trees.")
    parser.add_argument("--first-receipt", type=Path, required=True)
    parser.add_argument("--first-blueprint", type=Path, required=True)
    parser.add_argument("--first-stage-root", type=Path, required=True)
    parser.add_argument("--second-receipt", type=Path, required=True)
    parser.add_argument("--second-blueprint", type=Path, required=True)
    parser.add_argument("--second-stage-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        comparison = compare_staging_repeats(
            first_receipt_path=args.first_receipt,
            first_blueprint_path=args.first_blueprint,
            first_stage_root=args.first_stage_root,
            second_receipt_path=args.second_receipt,
            second_blueprint_path=args.second_blueprint,
            second_stage_root=args.second_stage_root,
        )
        write_comparison(args.output, comparison)
    except (OSError, ValueError) as exc:
        print(f"compare_l3_generated_pair_staging_repeats: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": comparison["status"], "repeat_exact": comparison["repeat_exact"], "raw_source_returned": False}, sort_keys=True))
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
