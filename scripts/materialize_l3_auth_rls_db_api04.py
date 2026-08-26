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
SCHEMA = "k_guard_l3_auth_rls_db_api04_materialization.v1"
VERSION = "1.0.0"
SLOT_ID = "api-04"
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
    "scenario_id": "dev-api-04-rule-open",
    "oracle_id": "l3-gen-api-04-rule-open",
    "plane": "api",
    "family": "auth-rls-db",
    "language": "typescript",
    "framework": "firebase",
    "coverage_tags": ["firebase"],
    "cwe": "CWE-284",
    "severity": "critical",
    "generator_profile": "deterministic-fixture-v1",
}

FIREBASE_RULE_SPECS: dict[int, dict[str, str]] = {
    0: {
        "fixture_id": "auth-rls-db-api-04-primary-v1",
        "rule_kind": "firestore",
        "rule_path": "firestore.rules",
        "match_path": "/teamNotes/{noteId}",
        "resource_name": "teamNotes",
        "owner_field": "ownerId",
        "repository_path": "src/lib/team-notes.ts",
    },
    1: {
        "fixture_id": "auth-rls-db-api-04-reserve-v1",
        "rule_kind": "storage",
        "rule_path": "storage.rules",
        "match_path": "/customerDocuments/{documentId}",
        "resource_name": "customerDocuments",
        "owner_field": "ownerId",
        "repository_path": "src/lib/customer-documents.ts",
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
            raise ValueError("api04_duplicate_json_key")
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
    spec = importlib.util.spec_from_file_location("k_guard_l3_stager_for_api04", STAGER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("api04_stager_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if STAGER_PATH.read_bytes() != raw_before:
        raise ValueError("api04_stager_changed_while_loading")
    return module, _sha256_bytes(raw_before)


def _load_staging_inputs(
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
) -> tuple[dict[str, Any], str, str]:
    for path, error in (
        (blueprint_path, "api04_blueprint_must_be_external"),
        (staging_receipt_path, "api04_staging_receipt_must_be_external"),
        (staging_root, "api04_staging_root_must_be_external"),
    ):
        _require_external_path(path, error)
    if not staging_receipt_path.is_file() or staging_receipt_path.is_symlink():
        raise ValueError("api04_staging_receipt_path_invalid")
    stager, stager_sha256 = _load_stager()
    raw_before = staging_receipt_path.read_bytes()
    receipt = stager.load_staging_receipt(staging_receipt_path, blueprint_path, staging_root)
    if staging_receipt_path.read_bytes() != raw_before:
        raise ValueError("api04_staging_receipt_changed_while_loading")
    return receipt, _sha256_bytes(raw_before), stager_sha256


def _api04_candidates(staging_receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = [dict(candidate) for candidate in staging_receipt["candidates"] if candidate["slot_id"] == SLOT_ID]
    if len(candidates) != 2 or [candidate["candidate_rank"] for candidate in candidates] != [0, 1]:
        raise ValueError("api04_staging_candidate_set_invalid")
    for candidate in candidates:
        for key, expected in EXPECTED_CANDIDATE_BINDING.items():
            if candidate.get(key) != expected:
                raise ValueError("api04_staging_candidate_binding_invalid")
        rank = candidate["candidate_rank"]
        if candidate.get("candidate_role") != ("primary" if rank == 0 else "reserve"):
            raise ValueError("api04_staging_candidate_role_invalid")
        root = f"slots/{SLOT_ID}/candidate-{rank}"
        if candidate.get("candidate_relative_root") != root:
            raise ValueError("api04_staging_candidate_path_invalid")
        if candidate.get("triplet_relative_paths") != {state: f"{root}/{state}" for state in TRIPLET_STATES}:
            raise ValueError("api04_staging_triplet_path_invalid")
    return candidates


def _firebase_rule_spec(candidate_rank: int) -> dict[str, str]:
    try:
        value = FIREBASE_RULE_SPECS[candidate_rank]
    except KeyError as exc:
        raise ValueError("api04_firebase_candidate_rank_invalid") from exc
    required = {
        "fixture_id",
        "rule_kind",
        "rule_path",
        "match_path",
        "resource_name",
        "owner_field",
        "repository_path",
    }
    if set(value) != required or not all(isinstance(item, str) and item for item in value.values()):
        raise ValueError("api04_firebase_rule_spec_invalid")
    if value["rule_kind"] not in {"firestore", "storage"}:
        raise ValueError("api04_firebase_rule_kind_invalid")
    return dict(value)


def _source_files(spec: Mapping[str, str], state: str) -> dict[str, bytes]:
    if state == "negative":
        return {"src/status.ts": b'export const status = "ok";\n'}
    if state not in {"vulnerable", "fixed"}:
        raise ValueError("api04_tree_state_invalid")

    rule_kind = spec["rule_kind"]
    match_path = spec["match_path"]
    resource = spec["resource_name"]
    owner = spec["owner_field"]
    if rule_kind == "firestore":
        service_header = "service cloud.firestore {\n  match /databases/{database}/documents {\n"
        owner_source = f"resource.data.{owner}"
        incoming_owner_source = f"request.resource.data.{owner}"
        repository = (
            "type FirestoreCollection = { doc(id: string): unknown };\n"
            "type FirestoreClient = { collection(path: string): FirestoreCollection };\n\n"
            f"export function {'teamNotesRepository' if state == 'vulnerable' else 'teamNotesRepositoryWithRule'}(client: FirestoreClient) {{\n"
            f'  return client.collection("{resource}");\n'
            "}\n"
        )
    else:
        service_header = "service firebase.storage {\n  match /b/{bucket}/o {\n"
        owner_source = f"resource.metadata.{owner}"
        incoming_owner_source = f"request.resource.metadata.{owner}"
        repository = (
            "type StorageReference = { child(path: string): StorageReference };\n"
            "type StorageClient = { ref(path?: string): StorageReference };\n\n"
            f"export function {'customerDocumentsRepository' if state == 'vulnerable' else 'customerDocumentsRepositoryWithRule'}(client: StorageClient) {{\n"
            f'  return client.ref("{resource}");\n'
            "}\n"
        )
    if state == "vulnerable":
        rules = service_header + f"    match {match_path} {{\n      allow read, write: if true;\n    }}\n  }}\n}}\n"
    else:
        rules = (
            service_header
            + "    function signedIn() { return request.auth != null; }\n"
            + f"    function ownsExisting() {{ return request.auth.uid == {owner_source}; }}\n"
            + f"    function ownsIncoming() {{ return request.auth.uid == {incoming_owner_source}; }}\n"
            + f"    match {match_path} {{\n"
            + "      allow read: if signedIn() && ownsExisting();\n"
            + "      allow create: if signedIn() && ownsIncoming();\n"
            + "      allow update, delete: if signedIn() && ownsExisting() && ownsIncoming();\n"
            + "    }\n  }\n}\n"
        )
    return {
        spec["rule_path"]: rules.encode("ascii"),
        spec["repository_path"]: repository.encode("ascii"),
    }


def _tree_files(candidate_rank: int, state: str) -> dict[str, bytes]:
    spec = _firebase_rule_spec(candidate_rank)
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
        **_source_files(spec, state),
    }


def _tree_identity(files: Mapping[str, bytes]) -> str:
    projection = [{"path": path, "sha256": _sha256_bytes(content)} for path, content in sorted(files.items())]
    return _domain_hash(b"k_guard_l3_auth_rls_db_api04_tree.v1\0", projection)


def _materialization_root_binding(materialization_root: Path) -> str:
    return hashlib.sha256(
        b"k_guard_l3_auth_rls_db_api04_root.v1\0" + str(materialization_root.resolve(strict=True)).encode("utf-8")
    ).hexdigest()


def _candidate_receipt(candidate: Mapping[str, Any]) -> dict[str, Any]:
    rank = candidate["candidate_rank"]
    spec = _firebase_rule_spec(rank)
    trees = {state: _tree_files(rank, state) for state in TRIPLET_STATES}
    identities = {state: _tree_identity(files) for state, files in trees.items()}
    if len(set(identities.values())) != len(TRIPLET_STATES):
        raise ValueError("api04_source_tree_identity_not_differential")
    fixture_projection = {"fixture_id": spec["fixture_id"], "candidate_rank": rank, "kind": "firebase-open-rule"}
    return {
        "slot_id": candidate["slot_id"],
        "scenario_id": candidate["scenario_id"],
        "oracle_id": candidate["oracle_id"],
        "candidate_rank": rank,
        "candidate_role": candidate["candidate_role"],
        "candidate_relative_root": candidate["candidate_relative_root"],
        "triplet_relative_paths": candidate["triplet_relative_paths"],
        "generator_profile": candidate["generator_profile"],
        "fixture_id": spec["fixture_id"],
        "fixture_identity_sha256": _domain_hash(b"k_guard_l3_auth_rls_db_api04_fixture.v1\0", fixture_projection),
        "license_spdx": LICENSE_SPDX,
        "license_content_sha256": _sha256_bytes(LICENSE_TEXT.encode("ascii")),
        "tree_file_counts": {state: len(files) for state, files in trees.items()},
        "tree_sha256": {state: identities[state] for state in TRIPLET_STATES},
    }


def _expected_candidates(staging_receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [_candidate_receipt(candidate) for candidate in _api04_candidates(staging_receipt)]


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
    for candidate in _api04_candidates(staging_receipt):
        for state in TRIPLET_STATES:
            for relative_path, content in _tree_files(candidate["candidate_rank"], state).items():
                source_path = f"{candidate['triplet_relative_paths'][state]}/{relative_path}"
                if source_path in expected:
                    raise ValueError("api04_source_path_duplicate")
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
    _require_external_path(materialization_root, "api04_materialization_root_must_be_external")
    if not materialization_root.is_dir() or materialization_root.is_symlink():
        raise ValueError("api04_materialization_root_path_invalid")
    expected_files = _expected_files(staging_receipt)
    actual_files: dict[str, Path] = {}
    actual_directories: set[str] = set()
    for path in materialization_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("api04_materialization_symlink_forbidden")
        relative = path.relative_to(materialization_root).as_posix()
        if path.is_dir():
            actual_directories.add(relative)
        elif path.is_file():
            actual_files[relative] = path
        else:
            raise ValueError("api04_materialization_entry_type_invalid")
    if set(actual_files) != set(expected_files):
        raise ValueError("api04_materialization_file_set_invalid")
    if actual_directories != _expected_directories(expected_files):
        raise ValueError("api04_materialization_directory_set_invalid")
    for relative_path, expected_content in expected_files.items():
        if actual_files[relative_path].read_bytes() != expected_content:
            raise ValueError("api04_materialization_source_content_invalid")


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
        raise ValueError("api04_materialization_receipt_not_object")
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
        raise ValueError("api04_materialization_receipt_keys_invalid")
    if value["schema"] != SCHEMA or value["version"] != VERSION:
        raise ValueError("api04_materialization_receipt_schema_or_version_invalid")
    if value["blueprint"] != staging_receipt["blueprint"]:
        raise ValueError("api04_materialization_blueprint_binding_invalid")
    expected_staging_binding = {
        "staging_receipt_artifact_sha256": staging_receipt_artifact_sha256,
        "stage_root_binding_sha256": staging_receipt["stage_root_binding_sha256"],
        "stage_tree_identity_sha256": staging_receipt["stage_tree_identity_sha256"],
        "stager_sha256": stager_sha256,
    }
    if value["staging_binding"] != expected_staging_binding:
        raise ValueError("api04_materialization_staging_binding_invalid")
    if value["materialization_root_binding_sha256"] != _materialization_root_binding(materialization_root):
        raise ValueError("api04_materialization_root_binding_mismatch")
    if value["slot_id"] != SLOT_ID:
        raise ValueError("api04_materialization_slot_invalid")
    candidates = _expected_candidates(staging_receipt)
    if value["candidates"] != candidates:
        raise ValueError("api04_materialization_candidates_invalid")
    if value["counts"] != _expected_counts(candidates):
        raise ValueError("api04_materialization_counts_invalid")
    if value["claim_boundary"] != CLAIM_BOUNDARY or value["raw_source_returned"] is not False:
        raise ValueError("api04_materialization_claim_boundary_invalid")
    if value["materializer_sha256"] != _materializer_sha256():
        raise ValueError("api04_materializer_sha256_mismatch")
    _validate_materialization_tree(materialization_root, staging_receipt)
    return dict(value)


def _write_receipt(output: Path, receipt: Mapping[str, Any]) -> None:
    _require_external_path(output, "api04_materialization_receipt_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_api04_materialization_receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_api04_materialization_receipt") from exc


def materialize_api04(
    *,
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
    materialization_root: Path,
    output: Path,
) -> dict[str, Any]:
    for path, error in (
        (materialization_root, "api04_materialization_root_must_be_external"),
        (output, "api04_materialization_receipt_output_must_be_external"),
    ):
        _require_external_path(path, error)
    if materialization_root.exists() or materialization_root.is_symlink():
        raise ValueError("refusing_to_overwrite_api04_materialization_root")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_api04_materialization_receipt")
    inputs = (blueprint_path, staging_receipt_path, staging_root)
    if any(_paths_overlap(materialization_root, other) for other in (*inputs, output)) or any(
        _paths_overlap(output, other) for other in inputs
    ):
        raise ValueError("api04_materialization_paths_must_not_overlap_inputs_or_receipt")

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
    _require_external_path(receipt_path, "api04_materialization_receipt_must_be_external")
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError("api04_materialization_receipt_path_invalid")
    raw = receipt_path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("api04_materialization_receipt_json_invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("api04_materialization_receipt_not_canonical")
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
    parser = argparse.ArgumentParser(
        description="Materialize only the P2.4B.3.04 api-04 Firebase open-rule primary/reserve source triplets."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--blueprint", type=Path, required=True)
    materialize.add_argument("--staging-receipt", type=Path, required=True)
    materialize.add_argument("--staging-root", type=Path, required=True)
    materialize.add_argument("--materialization-root", type=Path, required=True)
    materialize.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--blueprint", type=Path, required=True)
    validate.add_argument("--staging-receipt", type=Path, required=True)
    validate.add_argument("--staging-root", type=Path, required=True)
    validate.add_argument("--materialization-root", type=Path, required=True)
    validate.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            receipt = materialize_api04(
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
        print(f"materialize_l3_auth_rls_db_api04: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "materialized_candidate_count": receipt["counts"]["candidate_count"],
                "raw_source_returned": False,
                "source_triplets_materialized": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
