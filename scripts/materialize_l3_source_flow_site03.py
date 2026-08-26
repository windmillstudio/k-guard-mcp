from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve(strict=True).parents[1]
MATERIALIZER_PATH = Path(__file__).resolve(strict=True)
STAGER_PATH = REPOSITORY_ROOT / "scripts" / "stage_l3_generated_pair_source_triplets.py"
SCHEMA = "k_guard_l3_source_flow_site03_materialization.v1"
VERSION = "1.0.0"
SLOT_ID = "site-03"
TRIPLET_STATES = ("vulnerable", "fixed", "negative")
LICENSE_SPDX = "MIT"
LICENSE_TEXT = """MIT License

Copyright (c) 2026 K-Guard generated development corpus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

CLAIM_BOUNDARY = {
    "materialized_slot_count": 1,
    "materialized_candidate_count": 2,
    "source_triplets_materialized": True,
    "execution_oracles_proved": False,
    "scanner_output_observed": False,
    "eligible_for_tp_fp_fn": False,
    "eligible_for_h100": False,
    "release_gate_passed": False,
    "raw_source_returned": False,
}

EXPECTED_CANDIDATE_BINDING = {
    "slot_id": SLOT_ID,
    "scenario_id": "dev-site-03-command-exec",
    "oracle_id": "l3-gen-site-03-command-exec",
    "plane": "site",
    "family": "source-flow",
    "language": "javascript",
    "framework": "express",
    "coverage_tags": ["express"],
    "cwe": "CWE-78",
    "severity": "critical",
    "generator_profile": "deterministic-transform-v1",
}

TRANSFORM_SPECS: dict[int, dict[str, Any]] = {
    0: {
        "template_id": "source-flow-site-03-primary-transform-v1",
        "function_name": "archiveByTarget",
        "input_name": "target",
        "route_path": "routes/archive.js",
        "executable": "archive",
        "flag": "--target",
        "allowed_values": ("daily", "weekly"),
        "static_value": "daily",
    },
    1: {
        "template_id": "source-flow-site-03-reserve-transform-v1",
        "function_name": "exportByFormat",
        "input_name": "format",
        "route_path": "routes/export.js",
        "executable": "export",
        "flag": "--format",
        "allowed_values": ("json", "csv"),
        "static_value": "json",
    },
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
            raise ValueError("site03_duplicate_json_key")
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


def _load_stager() -> tuple[Any, str]:
    raw_before = STAGER_PATH.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l3_stager_for_site03", STAGER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("site03_stager_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if STAGER_PATH.read_bytes() != raw_before:
        raise ValueError("site03_stager_changed_while_loading")
    return module, _sha256_bytes(raw_before)


def _load_staging_inputs(
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
) -> tuple[dict[str, Any], str, str]:
    for path, error in (
        (blueprint_path, "site03_blueprint_must_be_external"),
        (staging_receipt_path, "site03_staging_receipt_must_be_external"),
        (staging_root, "site03_staging_root_must_be_external"),
    ):
        _require_external_path(path, error)
    if not staging_receipt_path.is_file() or staging_receipt_path.is_symlink():
        raise ValueError("site03_staging_receipt_path_invalid")
    stager, stager_sha256 = _load_stager()
    raw_before = staging_receipt_path.read_bytes()
    receipt = stager.load_staging_receipt(staging_receipt_path, blueprint_path, staging_root)
    if staging_receipt_path.read_bytes() != raw_before:
        raise ValueError("site03_staging_receipt_changed_while_loading")
    return receipt, _sha256_bytes(raw_before), stager_sha256


def _source_flow_candidates(staging_receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = [dict(candidate) for candidate in staging_receipt["candidates"] if candidate["slot_id"] == SLOT_ID]
    if len(candidates) != 2 or [candidate["candidate_rank"] for candidate in candidates] != [0, 1]:
        raise ValueError("site03_staging_candidate_set_invalid")
    for candidate in candidates:
        for key, expected in EXPECTED_CANDIDATE_BINDING.items():
            if candidate.get(key) != expected:
                raise ValueError("site03_staging_candidate_binding_invalid")
        rank = candidate["candidate_rank"]
        if candidate.get("candidate_role") != ("primary" if rank == 0 else "reserve"):
            raise ValueError("site03_staging_candidate_role_invalid")
        root = f"slots/{SLOT_ID}/candidate-{rank}"
        if candidate.get("candidate_relative_root") != root:
            raise ValueError("site03_staging_candidate_path_invalid")
        expected_triplets = {state: f"{root}/{state}" for state in TRIPLET_STATES}
        if candidate.get("triplet_relative_paths") != expected_triplets:
            raise ValueError("site03_staging_triplet_path_invalid")
    return candidates


def _transform_spec(candidate_rank: int) -> dict[str, Any]:
    try:
        value = TRANSFORM_SPECS[candidate_rank]
    except KeyError as exc:
        raise ValueError("site03_transform_candidate_rank_invalid") from exc
    expected_keys = {
        "template_id",
        "function_name",
        "input_name",
        "route_path",
        "executable",
        "flag",
        "allowed_values",
        "static_value",
    }
    if set(value) != expected_keys or not isinstance(value["allowed_values"], tuple):
        raise ValueError("site03_transform_spec_invalid")
    return dict(value)


def _route_source(spec: Mapping[str, Any], state: str) -> bytes:
    function_name = spec["function_name"]
    input_name = spec["input_name"]
    executable = spec["executable"]
    flag = spec["flag"]
    allowed_values = list(spec["allowed_values"])
    static_value = spec["static_value"]
    if state == "vulnerable":
        body = (
            f"  const command = \"{executable} {flag} \" + {input_name};\n"
            "  return runner.exec(command);"
        )
    elif state == "fixed":
        values = ", ".join(f"\"{value}\"" for value in allowed_values)
        body = (
            f"  const allowed = new Set([{values}]);\n"
            f"  if (!allowed.has({input_name})) {{\n"
            "    throw new Error(\"invalid argument\");\n"
            "  }\n"
            f"  return runner.execFile(\"{executable}\", [\"{flag}\", {input_name}]);"
        )
    elif state == "negative":
        body = f"  return runner.execFile(\"{executable}\", [\"{flag}\", \"{static_value}\"]);"
    else:
        raise ValueError("site03_tree_state_invalid")
    input_line = "" if state == "negative" else f"  const {input_name} = req.query.{input_name};\n"
    return (
        f"export function {function_name}(req, res, runner) {{\n"
        f"{input_line}"
        f"{body}\n"
        "}\n"
    ).encode("ascii")


def _tree_files(candidate_rank: int, state: str) -> dict[str, bytes]:
    spec = _transform_spec(candidate_rank)
    role = "primary" if candidate_rank == 0 else "reserve"
    package = {
        "name": f"k-guard-generated-{SLOT_ID}-{role}",
        "private": True,
        "type": "module",
        "version": "0.0.0",
    }
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "package.json": canonical_json_bytes(package),
        spec["route_path"]: _route_source(spec, state),
    }


def _tree_identity(files: Mapping[str, bytes]) -> str:
    projection = [{"path": path, "sha256": _sha256_bytes(content)} for path, content in sorted(files.items())]
    return _domain_hash(b"k_guard_l3_source_flow_site03_tree.v1\0", projection)


def _materialization_root_binding(materialization_root: Path) -> str:
    return hashlib.sha256(
        b"k_guard_l3_source_flow_site03_root.v1\0" + str(materialization_root.resolve(strict=True)).encode("utf-8")
    ).hexdigest()


def _candidate_receipt(candidate: Mapping[str, Any]) -> dict[str, Any]:
    rank = candidate["candidate_rank"]
    spec = _transform_spec(rank)
    trees = {state: _tree_files(rank, state) for state in TRIPLET_STATES}
    identities = {state: _tree_identity(files) for state, files in trees.items()}
    if len(set(identities.values())) != len(TRIPLET_STATES):
        raise ValueError("site03_source_tree_identity_not_differential")
    transform_projection = {
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "route_path": spec["route_path"],
        "function_name": spec["function_name"],
        "input_name": spec["input_name"],
        "executable": spec["executable"],
        "flag": spec["flag"],
        "allowed_values": list(spec["allowed_values"]),
    }
    return {
        "slot_id": candidate["slot_id"],
        "scenario_id": candidate["scenario_id"],
        "oracle_id": candidate["oracle_id"],
        "candidate_rank": rank,
        "candidate_role": candidate["candidate_role"],
        "candidate_relative_root": candidate["candidate_relative_root"],
        "triplet_relative_paths": candidate["triplet_relative_paths"],
        "generator_profile": candidate["generator_profile"],
        "transform_id": spec["template_id"],
        "transform_identity_sha256": _domain_hash(b"k_guard_l3_source_flow_site03_transform.v1\0", transform_projection),
        "license_spdx": LICENSE_SPDX,
        "license_content_sha256": _sha256_bytes(LICENSE_TEXT.encode("ascii")),
        "tree_file_counts": {state: len(files) for state, files in trees.items()},
        "tree_sha256": {state: identities[state] for state in TRIPLET_STATES},
    }


def _expected_candidates(staging_receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [_candidate_receipt(candidate) for candidate in _source_flow_candidates(staging_receipt)]


def _expected_counts(candidates: list[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "slot_count": 1,
        "candidate_count": len(candidates),
        "primary_candidate_count": sum(candidate["candidate_role"] == "primary" for candidate in candidates),
        "reserve_candidate_count": sum(candidate["candidate_role"] == "reserve" for candidate in candidates),
        "source_triplet_count": len(candidates) * len(TRIPLET_STATES),
        "source_file_count": sum(sum(candidate["tree_file_counts"].values()) for candidate in candidates),
    }


def _expected_files(staging_receipt: Mapping[str, Any]) -> dict[str, bytes]:
    expected: dict[str, bytes] = {}
    for candidate in _source_flow_candidates(staging_receipt):
        for state in TRIPLET_STATES:
            for relative_path, content in _tree_files(candidate["candidate_rank"], state).items():
                source_path = f"{candidate['triplet_relative_paths'][state]}/{relative_path}"
                if source_path in expected:
                    raise ValueError("site03_source_path_duplicate")
                expected[source_path] = content
    return expected


def _expected_directories(expected_files: Mapping[str, bytes]) -> set[str]:
    directories: set[str] = set()
    for raw_path in expected_files:
        current = PurePosixPath(raw_path).parent
        while str(current) != ".":
            directories.add(current.as_posix())
            current = current.parent
    return directories


def _validate_materialization_tree(materialization_root: Path, staging_receipt: Mapping[str, Any]) -> None:
    _require_external_path(materialization_root, "site03_materialization_root_must_be_external")
    if not materialization_root.is_dir() or materialization_root.is_symlink():
        raise ValueError("site03_materialization_root_path_invalid")
    expected_files = _expected_files(staging_receipt)
    actual_files: dict[str, Path] = {}
    actual_directories: set[str] = set()
    for path in materialization_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("site03_materialization_symlink_forbidden")
        relative = path.relative_to(materialization_root).as_posix()
        if path.is_dir():
            actual_directories.add(relative)
        elif path.is_file():
            actual_files[relative] = path
        else:
            raise ValueError("site03_materialization_entry_type_invalid")
    if set(actual_files) != set(expected_files):
        raise ValueError("site03_materialization_file_set_invalid")
    if actual_directories != _expected_directories(expected_files):
        raise ValueError("site03_materialization_directory_set_invalid")
    for relative_path, expected_content in expected_files.items():
        if actual_files[relative_path].read_bytes() != expected_content:
            raise ValueError("site03_materialization_source_content_invalid")


def _materializer_sha256() -> str:
    return _sha256_bytes(MATERIALIZER_PATH.read_bytes())


def _build_receipt(
    *,
    staging_receipt: Mapping[str, Any],
    staging_receipt_artifact_sha256: str,
    stager_sha256: str,
    materialization_root: Path,
) -> dict[str, Any]:
    candidates = _expected_candidates(staging_receipt)
    _validate_materialization_tree(materialization_root, staging_receipt)
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "blueprint": dict(staging_receipt["blueprint"]),
        "staging_binding": {
            "staging_receipt_artifact_sha256": staging_receipt_artifact_sha256,
            "stage_root_binding_sha256": staging_receipt["stage_root_binding_sha256"],
            "stage_tree_identity_sha256": staging_receipt["stage_tree_identity_sha256"],
            "stager_sha256": stager_sha256,
        },
        "materialization_root_binding_sha256": _materialization_root_binding(materialization_root),
        "slot_id": SLOT_ID,
        "candidates": candidates,
        "counts": _expected_counts(candidates),
        "claim_boundary": CLAIM_BOUNDARY,
        "raw_source_returned": False,
        "materializer_sha256": _materializer_sha256(),
    }


def validate_materialization_receipt(
    value: object,
    *,
    staging_receipt: Mapping[str, Any],
    staging_receipt_artifact_sha256: str,
    stager_sha256: str,
    materialization_root: Path,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("site03_materialization_receipt_not_object")
    expected_keys = {
        "schema",
        "version",
        "blueprint",
        "staging_binding",
        "materialization_root_binding_sha256",
        "slot_id",
        "candidates",
        "counts",
        "claim_boundary",
        "raw_source_returned",
        "materializer_sha256",
    }
    if set(value) != expected_keys:
        raise ValueError("site03_materialization_receipt_keys_invalid")
    if value["schema"] != SCHEMA or value["version"] != VERSION:
        raise ValueError("site03_materialization_receipt_schema_or_version_invalid")
    if value["blueprint"] != staging_receipt["blueprint"]:
        raise ValueError("site03_materialization_blueprint_binding_invalid")
    expected_staging_binding = {
        "staging_receipt_artifact_sha256": staging_receipt_artifact_sha256,
        "stage_root_binding_sha256": staging_receipt["stage_root_binding_sha256"],
        "stage_tree_identity_sha256": staging_receipt["stage_tree_identity_sha256"],
        "stager_sha256": stager_sha256,
    }
    if value["staging_binding"] != expected_staging_binding:
        raise ValueError("site03_materialization_staging_binding_invalid")
    if value["materialization_root_binding_sha256"] != _materialization_root_binding(materialization_root):
        raise ValueError("site03_materialization_root_binding_mismatch")
    if value["slot_id"] != SLOT_ID:
        raise ValueError("site03_materialization_slot_invalid")
    candidates = _expected_candidates(staging_receipt)
    if value["candidates"] != candidates:
        raise ValueError("site03_materialization_candidates_invalid")
    if value["counts"] != _expected_counts(candidates):
        raise ValueError("site03_materialization_counts_invalid")
    if value["claim_boundary"] != CLAIM_BOUNDARY or value["raw_source_returned"] is not False:
        raise ValueError("site03_materialization_claim_boundary_invalid")
    if value["materializer_sha256"] != _materializer_sha256():
        raise ValueError("site03_materializer_sha256_mismatch")
    _validate_materialization_tree(materialization_root, staging_receipt)
    return dict(value)


def _write_receipt(output: Path, receipt: Mapping[str, Any]) -> None:
    _require_external_path(output, "site03_materialization_receipt_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_site03_materialization_receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_site03_materialization_receipt") from exc


def materialize_site03(
    *,
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
    materialization_root: Path,
    output: Path,
) -> dict[str, Any]:
    for path, error in (
        (materialization_root, "site03_materialization_root_must_be_external"),
        (output, "site03_materialization_receipt_output_must_be_external"),
    ):
        _require_external_path(path, error)
    if materialization_root.exists() or materialization_root.is_symlink():
        raise ValueError("refusing_to_overwrite_site03_materialization_root")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_site03_materialization_receipt")
    if any(_paths_overlap(materialization_root, other) for other in (blueprint_path, staging_receipt_path, staging_root, output)):
        raise ValueError("site03_materialization_paths_must_not_overlap_inputs_or_receipt")
    staging_receipt, staging_receipt_sha256, stager_sha256 = _load_staging_inputs(
        blueprint_path, staging_receipt_path, staging_root
    )
    materialization_root.mkdir(parents=True, exist_ok=False)
    for relative_path, content in _expected_files(staging_receipt).items():
        destination = materialization_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    receipt = _build_receipt(
        staging_receipt=staging_receipt,
        staging_receipt_artifact_sha256=staging_receipt_sha256,
        stager_sha256=stager_sha256,
        materialization_root=materialization_root,
    )
    _write_receipt(output, receipt)
    return receipt


def load_materialization_receipt(
    *,
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
    materialization_root: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    _require_external_path(receipt_path, "site03_materialization_receipt_must_be_external")
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError("site03_materialization_receipt_path_invalid")
    raw = receipt_path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("site03_materialization_receipt_json_invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("site03_materialization_receipt_not_canonical")
    staging_receipt, staging_receipt_sha256, stager_sha256 = _load_staging_inputs(
        blueprint_path, staging_receipt_path, staging_root
    )
    return validate_materialization_receipt(
        value,
        staging_receipt=staging_receipt,
        staging_receipt_artifact_sha256=staging_receipt_sha256,
        stager_sha256=stager_sha256,
        materialization_root=materialization_root,
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize the preregistered site-03 source-flow triplet pair.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("materialize", "validate"):
        command = subparsers.add_parser(name)
        command.add_argument("--blueprint", type=Path, required=True)
        command.add_argument("--staging-receipt", type=Path, required=True)
        command.add_argument("--staging-root", type=Path, required=True)
        command.add_argument("--materialization-root", type=Path, required=True)
        command.add_argument("--output" if name == "materialize" else "--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            receipt = materialize_site03(
                blueprint_path=args.blueprint,
                staging_receipt_path=args.staging_receipt,
                staging_root=args.staging_root,
                materialization_root=args.materialization_root,
                output=args.output,
            )
        else:
            receipt = load_materialization_receipt(
                blueprint_path=args.blueprint,
                staging_receipt_path=args.staging_receipt,
                staging_root=args.staging_root,
                materialization_root=args.materialization_root,
                receipt_path=args.input,
            )
    except (OSError, ValueError) as exc:
        print(f"materialize_l3_source_flow_site03: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"materialized_candidate_count": receipt["counts"]["candidate_count"], "raw_source_returned": False, "source_triplets_materialized": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
