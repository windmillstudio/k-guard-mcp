from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
SCRIPTS_ROOT = REPOSITORY_ROOT / "scripts"
SOURCE_ROOT = REPOSITORY_ROOT / "src"
MATERIALIZER_PATH = SCRIPTS_ROOT / "materialize_l1_benchmarks.py"
BLOB_WORKTREE_PATH = SCRIPTS_ROOT / "materialize_git_blob_worktree.py"
SCHEMA = "k_guard_benchmarkjava_denominator_repeat_comparison.v1"
DEFAULT_FIELD_ID = "p2.1a-benchmarkjava-current-denominator"
FIELD_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")

if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from capture_supervisor_target import capture_target  # noqa: E402
from k_guard_mcp.l1_benchmark import L1BenchmarkError, _validate_manifest  # noqa: E402


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _field_id(value: object) -> str:
    if not isinstance(value, str) or FIELD_ID_RE.fullmatch(value) is None:
        raise ValueError("comparison_field_id_invalid")
    return value


def _load_module(path: Path, name: str) -> Any:
    before = path.read_bytes()
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("comparison_dependency_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if path.read_bytes() != before:
        raise ValueError("comparison_dependency_changed_while_loading")
    return module


def _load_materializer() -> Any:
    return _load_module(MATERIALIZER_PATH, "k_guard_l1_denominator_materializer")


def _load_blob_worktree() -> Any:
    return _load_module(BLOB_WORKTREE_PATH, "k_guard_l1_denominator_blob_worktree")


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("comparison_input_duplicate_json_key")
        value[key] = item
    return value


def _load_json(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("comparison_input_path_invalid")
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("comparison_input_not_json") from exc
    if not isinstance(value, dict):
        raise ValueError("comparison_input_not_object")
    return value, raw


def _load_manifest(path: Path, materializer: Any) -> tuple[dict[str, Any], str, dict[str, Any]]:
    manifest, raw = _load_json(path)
    if materializer.canonical_json_bytes(manifest) != raw:
        raise ValueError("comparison_manifest_not_canonical")
    try:
        by_language = _validate_manifest(manifest)
    except L1BenchmarkError as exc:
        raise ValueError("comparison_manifest_contract_invalid") from exc
    java = by_language.get("java")
    if not isinstance(java, dict):
        raise ValueError("comparison_manifest_java_missing")
    return manifest, _sha256_bytes(raw), java


def _load_source_receipt(path: Path, blob_worktree: Any) -> tuple[dict[str, Any], str]:
    receipt, raw = _load_json(path)
    if blob_worktree.canonical_json_bytes(receipt) != raw:
        raise ValueError("comparison_source_receipt_not_canonical")
    required = {
        "schema",
        "revision",
        "tree",
        "origin",
        "file_count",
        "worktree_clean",
        "byte_source",
        "raw_returned",
    }
    if set(receipt) != required or receipt.get("schema") != blob_worktree.SCHEMA:
        raise ValueError("comparison_source_receipt_contract_invalid")
    if (
        receipt.get("worktree_clean") is not True
        or receipt.get("byte_source") != "git_cat_file_raw_blob"
        or receipt.get("raw_returned") is not False
        or not isinstance(receipt.get("file_count"), int)
        or receipt["file_count"] <= 0
    ):
        raise ValueError("comparison_source_receipt_contract_invalid")
    return receipt, _sha256_bytes(raw)


def _production_java_spec(materializer: Any) -> Any:
    matches = [spec for spec in materializer.L1_CORPORA if spec.language == "java"]
    if len(matches) != 1:
        raise ValueError("comparison_java_spec_invalid")
    return matches[0]


def _java_summary(corpus: Mapping[str, Any]) -> dict[str, Any]:
    expected = corpus["expected_results"]
    license_value = corpus["license"]
    tree = corpus["source_tree"]
    return {
        "corpus_id": corpus["corpus_id"],
        "language": corpus["language"],
        "repository_origin": corpus["repository_origin"],
        "revision_sha1": corpus["revision_sha1"],
        "commit_tree_sha1": corpus["commit_tree_sha1"],
        "expected_results": {
            "path": expected["path"],
            "sha256": expected["sha256"],
            "row_count": expected["row_count"],
            "unique_case_count": expected["unique_case_count"],
        },
        "license": {
            "path": license_value["path"],
            "spdx": license_value["spdx"],
            "sha256": license_value["sha256"],
        },
        "case_set_schema": corpus["case_set_schema"],
        "case_set_sha256": corpus["case_set_sha256"],
        "case_count": len(corpus["cases"]),
        "source_tree": {
            "source_tree_sha256": tree["source_tree_sha256"],
            "file_count": tree["file_count"],
            "total_bytes": tree["total_bytes"],
            "source_worktree_clean": tree["source_worktree_clean"],
            "index_tree_match": tree["index_tree_match"],
            "physical_bytes_match_git_blobs": tree["physical_bytes_match_git_blobs"],
            "no_untracked_or_ignored_physical_files": tree[
                "no_untracked_or_ignored_physical_files"
            ],
        },
        "raw_returned": False,
    }


def _source_receipt_matches(
    receipt: Mapping[str, Any], expected_java: Mapping[str, Any]
) -> bool:
    return (
        receipt.get("revision") == expected_java["revision_sha1"]
        and receipt.get("tree") == expected_java["commit_tree_sha1"]
        and receipt.get("origin") == expected_java["repository_origin"]
        and receipt.get("file_count") == expected_java["source_tree"]["file_count"]
        and receipt.get("worktree_clean") is True
        and receipt.get("byte_source") == "git_cat_file_raw_blob"
        and receipt.get("raw_returned") is False
    )


def _repeat_projection(
    manifest_sha256: str,
    manifest: Mapping[str, Any],
    java: Mapping[str, Any],
    expected_java: Mapping[str, Any],
    source_receipt_matches: bool,
) -> dict[str, Any]:
    return {
        "manifest_sha256": manifest_sha256,
        "manifest_contract": {
            "schema": manifest["schema"],
            "status": manifest["status"],
            "lane": manifest["lane"],
            "scanner_output_observed": manifest["scanner_output_observed"],
            "coverage_policy": manifest["coverage_policy"],
            "unsupported_detector_category_policy": manifest[
                "unsupported_detector_category_policy"
            ],
            "corpus_count": manifest["corpus_count"],
            "total_case_count": manifest["total_case_count"],
        },
        "benchmarkjava": _java_summary(java),
        "benchmarkjava_matches_clean_official_projection": java == expected_java,
        "java_source_receipt_matches_clean_projection": source_receipt_matches,
        "raw_returned": False,
    }


def compare_manifests(
    first_path: Path,
    second_path: Path,
    benchmark_java: Path,
    java_source_receipt_path: Path,
    *,
    materializer_module: Any | None = None,
    java_spec: Any | None = None,
    field_id: str = DEFAULT_FIELD_ID,
) -> dict[str, Any]:
    normalized_field_id = _field_id(field_id)
    target_before = capture_target(REPOSITORY_ROOT)
    materializer = materializer_module or _load_materializer()
    blob_worktree = _load_blob_worktree()
    spec = java_spec or _production_java_spec(materializer)
    expected_java = materializer._materialize_corpus(benchmark_java, spec)
    receipt, receipt_sha256 = _load_source_receipt(java_source_receipt_path, blob_worktree)
    source_receipt_matches = _source_receipt_matches(receipt, expected_java)
    first_manifest, first_manifest_sha256, first_java = _load_manifest(first_path, materializer)
    second_manifest, second_manifest_sha256, second_java = _load_manifest(second_path, materializer)
    first_projection = _repeat_projection(
        first_manifest_sha256,
        first_manifest,
        first_java,
        expected_java,
        source_receipt_matches,
    )
    second_projection = _repeat_projection(
        second_manifest_sha256,
        second_manifest,
        second_java,
        expected_java,
        source_receipt_matches,
    )
    first_fingerprint = _sha256_bytes(canonical_json_bytes(first_projection))
    second_fingerprint = _sha256_bytes(canonical_json_bytes(second_projection))
    repeat_exact = first_fingerprint == second_fingerprint
    official_binding_exact = (
        first_java == expected_java
        and second_java == expected_java
        and source_receipt_matches
        and first_manifest.get("scanner_output_observed") is False
        and second_manifest.get("scanner_output_observed") is False
    )
    target_after = capture_target(REPOSITORY_ROOT)
    if target_after != target_before:
        raise ValueError("comparison_target_changed_during_run")
    passed = repeat_exact and official_binding_exact
    return {
        "schema": SCHEMA,
        "field_id": normalized_field_id,
        "target": target_before,
        "tool_provenance": {
            "comparator_sha256": _sha256_file(Path(__file__).resolve(strict=True)),
            "materializer_sha256": _sha256_file(MATERIALIZER_PATH),
            "blob_worktree_sha256": _sha256_file(BLOB_WORKTREE_PATH),
        },
        "first_manifest_sha256": first_manifest_sha256,
        "second_manifest_sha256": second_manifest_sha256,
        "first_semantic_fingerprint_sha256": first_fingerprint,
        "second_semantic_fingerprint_sha256": second_fingerprint,
        "java_source_receipt_sha256": receipt_sha256,
        "repeat_exact": repeat_exact,
        "official_binding_exact": official_binding_exact,
        "status": "FIX" if passed else "HOLD",
        "benchmarkjava": _java_summary(expected_java),
        "carrier_manifest": {
            "schema": first_manifest["schema"],
            "total_case_count": first_manifest["total_case_count"],
            "contains_benchmarkpython": True,
            "benchmarkpython_claimed": False,
            "scanner_output_observed": False,
        },
        "authority": {
            "may_mark_field_fix": passed,
            "may_approve_benchmarkjava_denominator": passed,
            "may_approve_benchmarkpython_denominator": False,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "benchmarkjava_denominator_only": True,
            "scanner_executed": False,
            "detection_accuracy_proven": False,
            "tp_fp_fn_admitted": False,
            "warning_or_block_promoted": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def write_comparison(path: Path, comparison: Mapping[str, Any]) -> None:
    resolved = path.resolve()
    if resolved.is_relative_to(REPOSITORY_ROOT.resolve()):
        raise ValueError("comparison_output_must_be_external")
    if path.exists() or path.is_symlink():
        raise ValueError("refusing_to_overwrite_l1_denominator_comparison")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_json_bytes(dict(comparison)))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two raw-free BenchmarkJava denominator manifests without scanning or release promotion."
    )
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--benchmark-java", type=Path, required=True)
    parser.add_argument("--java-source-receipt", type=Path, required=True)
    parser.add_argument("--field-id", default=DEFAULT_FIELD_ID)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    comparison = compare_manifests(
        args.first,
        args.second,
        args.benchmark_java,
        args.java_source_receipt,
        field_id=args.field_id,
    )
    write_comparison(args.output, comparison)
    print(
        json.dumps(
            {
                "field_id": comparison["field_id"],
                "status": comparison["status"],
                "repeat_exact": comparison["repeat_exact"],
                "official_binding_exact": comparison["official_binding_exact"],
                "raw_returned": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if comparison["status"] == "FIX" else 2


if __name__ == "__main__":
    raise SystemExit(main())
