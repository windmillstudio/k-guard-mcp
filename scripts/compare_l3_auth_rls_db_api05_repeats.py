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
MATERIALIZER_PATH = REPOSITORY_ROOT / "scripts" / "materialize_l3_auth_rls_db_api05.py"
SCHEMA = "k_guard_l3_auth_rls_db_api05_repeat_comparison.v1"


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


def _load_materializer() -> tuple[Any, str]:
    raw_before = MATERIALIZER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_auth_rls_db_api05_for_comparison", MATERIALIZER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("api05_materializer_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if MATERIALIZER_PATH.read_bytes() != raw_before:
        raise ValueError("api05_materializer_changed_while_loading")
    return module, hashlib.sha256(raw_before).hexdigest()


def _projection(receipt: Mapping[str, Any], materializer_sha256: str) -> dict[str, Any]:
    return {
        "schema": receipt["schema"],
        "version": receipt["version"],
        "blueprint": receipt["blueprint"],
        "staging_binding": {
            "stage_tree_identity_sha256": receipt["staging_binding"]["stage_tree_identity_sha256"],
            "stager_sha256": receipt["staging_binding"]["stager_sha256"],
        },
        "slot_id": receipt["slot_id"],
        "candidates": receipt["candidates"],
        "counts": receipt["counts"],
        "claim_boundary": receipt["claim_boundary"],
        "raw_source_returned": receipt["raw_source_returned"],
        "materializer_sha256": materializer_sha256,
    }


def compare_api05_repeats(
    *,
    first_blueprint_path: Path,
    first_staging_receipt_path: Path,
    first_staging_root: Path,
    first_materialization_root: Path,
    first_receipt_path: Path,
    second_blueprint_path: Path,
    second_staging_receipt_path: Path,
    second_staging_root: Path,
    second_materialization_root: Path,
    second_receipt_path: Path,
) -> dict[str, Any]:
    paths = (
        first_blueprint_path,
        first_staging_receipt_path,
        first_staging_root,
        first_materialization_root,
        first_receipt_path,
        second_blueprint_path,
        second_staging_receipt_path,
        second_staging_root,
        second_materialization_root,
        second_receipt_path,
    )
    for path in paths:
        _require_external_path(path, "api05_repeat_inputs_must_be_external")
    materializer, materializer_sha256 = _load_materializer()
    first = materializer.load_materialization_receipt(
        blueprint_path=first_blueprint_path,
        staging_receipt_path=first_staging_receipt_path,
        staging_root=first_staging_root,
        materialization_root=first_materialization_root,
        receipt_path=first_receipt_path,
    )
    second = materializer.load_materialization_receipt(
        blueprint_path=second_blueprint_path,
        staging_receipt_path=second_staging_receipt_path,
        staging_root=second_staging_root,
        materialization_root=second_materialization_root,
        receipt_path=second_receipt_path,
    )
    first_fingerprint = hashlib.sha256(canonical_json_bytes(_projection(first, materializer_sha256))).hexdigest()
    second_fingerprint = hashlib.sha256(canonical_json_bytes(_projection(second, materializer_sha256))).hexdigest()
    repeat_exact = first_fingerprint == second_fingerprint
    return {
        "schema": SCHEMA,
        "slot_id": first["slot_id"],
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "materializer_sha256": materializer_sha256,
        "repeat_exact": repeat_exact,
        "status": "FIX" if repeat_exact else "HOLD",
        "authority": {
            "may_mark_field_fix": repeat_exact,
            "may_affect_other_slots": False,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "api05_source_triplets_materialized": repeat_exact,
            "execution_oracles_proved": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
        },
        "raw_source_returned": False,
    }


def write_comparison(output: Path, comparison: Mapping[str, Any]) -> None:
    _require_external_path(output, "api05_repeat_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_api05_repeat_comparison")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(comparison)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_api05_repeat_comparison") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two P2.4B.3.05 api-05 Next.js admin-boundary source materializations.")
    for prefix in ("first", "second"):
        parser.add_argument(f"--{prefix}-blueprint", type=Path, required=True)
        parser.add_argument(f"--{prefix}-staging-receipt", type=Path, required=True)
        parser.add_argument(f"--{prefix}-staging-root", type=Path, required=True)
        parser.add_argument(f"--{prefix}-materialization-root", type=Path, required=True)
        parser.add_argument(f"--{prefix}-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        comparison = compare_api05_repeats(
            first_blueprint_path=args.first_blueprint,
            first_staging_receipt_path=args.first_staging_receipt,
            first_staging_root=args.first_staging_root,
            first_materialization_root=args.first_materialization_root,
            first_receipt_path=args.first_receipt,
            second_blueprint_path=args.second_blueprint,
            second_staging_receipt_path=args.second_staging_receipt,
            second_staging_root=args.second_staging_root,
            second_materialization_root=args.second_materialization_root,
            second_receipt_path=args.second_receipt,
        )
        write_comparison(args.output, comparison)
    except (OSError, ValueError) as exc:
        print(f"compare_l3_auth_rls_db_api05_repeats: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"raw_source_returned": False, "repeat_exact": comparison["repeat_exact"], "status": comparison["status"]}, sort_keys=True))
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
