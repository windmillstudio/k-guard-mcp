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
SCHEMA = "k_guard_l3_source_flow_site13_materialization.v1"
VERSION = "1.0.0"
SLOT_ID = "site-13"
TRIPLET_STATES = ("vulnerable", "fixed", "negative")
LICENSE_SPDX = "MIT"
LICENSE_TEXT = """MIT License

Copyright (c) 2026 K-Guard generated development corpus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
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
    "scenario_id": "dev-site-13-jdbc-query",
    "oracle_id": "l3-gen-site-13-jdbc-query",
    "plane": "site",
    "family": "source-flow",
    "language": "java",
    "framework": "spring",
    "coverage_tags": ["express"],
    "cwe": "CWE-89",
    "severity": "high",
    "generator_profile": "deterministic-fixture-v1",
}

TEMPLATE_SPECS: dict[int, dict[str, str]] = {
    0: {
        "template_id": "source-flow-site-13-primary-jdbc-query-template-v1",
        "source_path": "src/main/java/dev/kguard/checkout/OrderLookupController.java",
        "package_name": "dev.kguard.checkout",
        "controller_name": "OrderLookupController",
        "handler_name": "findOrder",
        "request_path": "/orders",
        "parameter_name": "id",
        "table_name": "orders",
        "result_column": "status",
        "static_message": "orders-ready",
    },
    1: {
        "template_id": "source-flow-site-13-reserve-jdbc-query-template-v1",
        "source_path": "src/main/java/dev/kguard/integrations/IntegrationLookupController.java",
        "package_name": "dev.kguard.integrations",
        "controller_name": "IntegrationLookupController",
        "handler_name": "findIntegration",
        "request_path": "/integrations",
        "parameter_name": "provider",
        "table_name": "integrations",
        "result_column": "endpoint",
        "static_message": "integrations-ready",
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
            raise ValueError("site13_duplicate_json_key")
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
    spec = importlib.util.spec_from_file_location("k_guard_l3_stager_for_site13", STAGER_PATH)
    if spec is None or spec.loader is None:
        raise ValueError("site13_stager_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if STAGER_PATH.read_bytes() != raw_before:
        raise ValueError("site13_stager_changed_while_loading")
    return module, _sha256_bytes(raw_before)


def _load_staging_inputs(
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
) -> tuple[dict[str, Any], str, str]:
    for path, error in (
        (blueprint_path, "site13_blueprint_must_be_external"),
        (staging_receipt_path, "site13_staging_receipt_must_be_external"),
        (staging_root, "site13_staging_root_must_be_external"),
    ):
        _require_external_path(path, error)
    if not staging_receipt_path.is_file() or staging_receipt_path.is_symlink():
        raise ValueError("site13_staging_receipt_path_invalid")
    stager, stager_sha256 = _load_stager()
    raw_before = staging_receipt_path.read_bytes()
    receipt = stager.load_staging_receipt(staging_receipt_path, blueprint_path, staging_root)
    if staging_receipt_path.read_bytes() != raw_before:
        raise ValueError("site13_staging_receipt_changed_while_loading")
    return receipt, _sha256_bytes(raw_before), stager_sha256


def _source_flow_candidates(staging_receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = [dict(candidate) for candidate in staging_receipt["candidates"] if candidate["slot_id"] == SLOT_ID]
    if len(candidates) != 2 or [candidate["candidate_rank"] for candidate in candidates] != [0, 1]:
        raise ValueError("site13_staging_candidate_set_invalid")
    for candidate in candidates:
        for key, expected in EXPECTED_CANDIDATE_BINDING.items():
            if candidate.get(key) != expected:
                raise ValueError("site13_staging_candidate_binding_invalid")
        rank = candidate["candidate_rank"]
        if candidate.get("candidate_role") != ("primary" if rank == 0 else "reserve"):
            raise ValueError("site13_staging_candidate_role_invalid")
        root = f"slots/{SLOT_ID}/candidate-{rank}"
        if candidate.get("candidate_relative_root") != root:
            raise ValueError("site13_staging_candidate_path_invalid")
        if candidate.get("triplet_relative_paths") != {state: f"{root}/{state}" for state in TRIPLET_STATES}:
            raise ValueError("site13_staging_triplet_path_invalid")
    return candidates


def _template_spec(candidate_rank: int) -> dict[str, str]:
    try:
        spec = TEMPLATE_SPECS[candidate_rank]
    except KeyError as exc:
        raise ValueError("site13_template_candidate_rank_invalid") from exc
    expected_keys = {
        "template_id",
        "source_path",
        "package_name",
        "controller_name",
        "handler_name",
        "request_path",
        "parameter_name",
        "table_name",
        "result_column",
        "static_message",
    }
    if set(spec) != expected_keys:
        raise ValueError("site13_template_spec_invalid")
    return dict(spec)


def _java_source(spec: Mapping[str, str], state: str) -> bytes:
    package_name = spec["package_name"]
    controller_name = spec["controller_name"]
    handler_name = spec["handler_name"]
    request_path = spec["request_path"]
    parameter_name = spec["parameter_name"]
    table_name = spec["table_name"]
    result_column = spec["result_column"]
    static_message = spec["static_message"]
    if state == "vulnerable":
        body = (
            f"package {package_name};\n\n"
            "import java.sql.Connection;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n"
            "import java.sql.Statement;\n"
            "import javax.sql.DataSource;\n"
            "import org.springframework.http.ResponseEntity;\n"
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.springframework.web.bind.annotation.RestController;\n\n"
            "@RestController\n"
            f"public final class {controller_name} {{\n"
            "    private final DataSource dataSource;\n\n"
            f"    public {controller_name}(DataSource dataSource) {{\n"
            "        this.dataSource = dataSource;\n"
            "    }\n\n"
            f"    @GetMapping({json.dumps(request_path, ensure_ascii=True)})\n"
            f"    public ResponseEntity<String> {handler_name}(@RequestParam String {parameter_name}) throws SQLException {{\n"
            f"        String query = \"SELECT {result_column} FROM {table_name} WHERE {parameter_name} = '\" + {parameter_name} + \"'\";\n"
            "        try (Connection connection = dataSource.getConnection();\n"
            "             Statement statement = connection.createStatement();\n"
            "             ResultSet result = statement.executeQuery(query)) {\n"
            f"            return ResponseEntity.ok(result.next() ? result.getString({json.dumps(result_column, ensure_ascii=True)}) : \"missing\");\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
    elif state == "fixed":
        body = (
            f"package {package_name};\n\n"
            "import java.sql.Connection;\n"
            "import java.sql.PreparedStatement;\n"
            "import java.sql.ResultSet;\n"
            "import java.sql.SQLException;\n"
            "import javax.sql.DataSource;\n"
            "import org.springframework.http.ResponseEntity;\n"
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.springframework.web.bind.annotation.RestController;\n\n"
            "@RestController\n"
            f"public final class {controller_name} {{\n"
            "    private final DataSource dataSource;\n\n"
            f"    public {controller_name}(DataSource dataSource) {{\n"
            "        this.dataSource = dataSource;\n"
            "    }\n\n"
            f"    @GetMapping({json.dumps(request_path, ensure_ascii=True)})\n"
            f"    public ResponseEntity<String> {handler_name}(@RequestParam String {parameter_name}) throws SQLException {{\n"
            f"        String query = \"SELECT {result_column} FROM {table_name} WHERE {parameter_name} = ?\";\n"
            "        try (Connection connection = dataSource.getConnection();\n"
            "             PreparedStatement statement = connection.prepareStatement(query)) {\n"
            f"            statement.setString(1, {parameter_name});\n"
            "            try (ResultSet result = statement.executeQuery()) {\n"
            f"                return ResponseEntity.ok(result.next() ? result.getString({json.dumps(result_column, ensure_ascii=True)}) : \"missing\");\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
    elif state == "negative":
        body = (
            f"package {package_name};\n\n"
            "import org.springframework.http.ResponseEntity;\n"
            "import org.springframework.web.bind.annotation.GetMapping;\n"
            "import org.springframework.web.bind.annotation.RestController;\n\n"
            "@RestController\n"
            f"public final class {controller_name} {{\n"
            f"    @GetMapping({json.dumps(request_path, ensure_ascii=True)})\n"
            f"    public ResponseEntity<String> {handler_name}() {{\n"
            f"        return ResponseEntity.ok({json.dumps(static_message, ensure_ascii=True)});\n"
            "    }\n"
            "}\n"
        )
    else:
        raise ValueError("site13_tree_state_invalid")
    return body.encode("ascii")


def _tree_files(candidate_rank: int, state: str) -> dict[str, bytes]:
    spec = _template_spec(candidate_rank)
    role = "primary" if candidate_rank == 0 else "reserve"
    pom = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
        "  xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>dev.kguard</groupId>\n"
        f"  <artifactId>k-guard-generated-{SLOT_ID}-{role}</artifactId>\n"
        "  <version>0.0.0</version>\n"
        "  <properties>\n"
        "    <maven.compiler.release>21</maven.compiler.release>\n"
        "  </properties>\n"
        "  <dependencies>\n"
        "    <dependency>\n"
        "      <groupId>org.springframework.boot</groupId>\n"
        "      <artifactId>spring-boot-starter-web</artifactId>\n"
        "      <version>3.3.0</version>\n"
        "    </dependency>\n"
        "  </dependencies>\n"
        "</project>\n"
    )
    return {
        "LICENSE": LICENSE_TEXT.encode("ascii"),
        "pom.xml": pom.encode("ascii"),
        spec["source_path"]: _java_source(spec, state),
    }


def _tree_identity(files: Mapping[str, bytes]) -> str:
    projection = [{"path": path, "sha256": _sha256_bytes(content)} for path, content in sorted(files.items())]
    return _domain_hash(b"k_guard_l3_source_flow_site13_tree.v1\0", projection)


def _materialization_root_binding(materialization_root: Path) -> str:
    return hashlib.sha256(
        b"k_guard_l3_source_flow_site13_root.v1\0" + str(materialization_root.resolve(strict=True)).encode("utf-8")
    ).hexdigest()


def _candidate_receipt(candidate: Mapping[str, Any]) -> dict[str, Any]:
    rank = candidate["candidate_rank"]
    spec = _template_spec(rank)
    trees = {state: _tree_files(rank, state) for state in TRIPLET_STATES}
    identities = {state: _tree_identity(files) for state, files in trees.items()}
    if len(set(identities.values())) != len(TRIPLET_STATES):
        raise ValueError("site13_source_tree_identity_not_differential")
    template_projection = {
        "template_id": spec["template_id"],
        "candidate_rank": rank,
        "source_path": spec["source_path"],
        "package_name": spec["package_name"],
        "controller_name": spec["controller_name"],
        "handler_name": spec["handler_name"],
        "request_path": spec["request_path"],
        "parameter_name": spec["parameter_name"],
        "table_name": spec["table_name"],
        "result_column": spec["result_column"],
        "static_message": spec["static_message"],
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
        "template_id": spec["template_id"],
        "template_identity_sha256": _domain_hash(b"k_guard_l3_source_flow_site13_template.v1\0", template_projection),
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
                    raise ValueError("site13_source_path_duplicate")
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
    _require_external_path(materialization_root, "site13_materialization_root_must_be_external")
    if not materialization_root.is_dir() or materialization_root.is_symlink():
        raise ValueError("site13_materialization_root_path_invalid")
    expected_files = _expected_files(staging_receipt)
    actual_files: dict[str, Path] = {}
    actual_directories: set[str] = set()
    for path in materialization_root.rglob("*"):
        if path.is_symlink():
            raise ValueError("site13_materialization_symlink_forbidden")
        relative = path.relative_to(materialization_root).as_posix()
        if path.is_dir():
            actual_directories.add(relative)
        elif path.is_file():
            actual_files[relative] = path
        else:
            raise ValueError("site13_materialization_entry_type_invalid")
    if set(actual_files) != set(expected_files):
        raise ValueError("site13_materialization_file_set_invalid")
    if actual_directories != _expected_directories(expected_files):
        raise ValueError("site13_materialization_directory_set_invalid")
    for relative_path, expected_content in expected_files.items():
        if actual_files[relative_path].read_bytes() != expected_content:
            raise ValueError("site13_materialization_source_content_invalid")


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
        raise ValueError("site13_materialization_receipt_not_object")
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
        raise ValueError("site13_materialization_receipt_keys_invalid")
    if value["schema"] != SCHEMA or value["version"] != VERSION:
        raise ValueError("site13_materialization_receipt_schema_or_version_invalid")
    if value["blueprint"] != staging_receipt["blueprint"]:
        raise ValueError("site13_materialization_blueprint_binding_invalid")
    expected_staging_binding = {
        "staging_receipt_artifact_sha256": staging_receipt_artifact_sha256,
        "stage_root_binding_sha256": staging_receipt["stage_root_binding_sha256"],
        "stage_tree_identity_sha256": staging_receipt["stage_tree_identity_sha256"],
        "stager_sha256": stager_sha256,
    }
    if value["staging_binding"] != expected_staging_binding:
        raise ValueError("site13_materialization_staging_binding_invalid")
    if value["materialization_root_binding_sha256"] != _materialization_root_binding(materialization_root):
        raise ValueError("site13_materialization_root_binding_mismatch")
    if value["slot_id"] != SLOT_ID:
        raise ValueError("site13_materialization_slot_invalid")
    candidates = _expected_candidates(staging_receipt)
    if value["candidates"] != candidates:
        raise ValueError("site13_materialization_candidates_invalid")
    if value["counts"] != _expected_counts(candidates):
        raise ValueError("site13_materialization_counts_invalid")
    if value["claim_boundary"] != CLAIM_BOUNDARY or value["raw_source_returned"] is not False:
        raise ValueError("site13_materialization_claim_boundary_invalid")
    if value["materializer_sha256"] != _materializer_sha256():
        raise ValueError("site13_materializer_sha256_mismatch")
    _validate_materialization_tree(materialization_root, staging_receipt)
    return dict(value)


def _write_receipt(output: Path, receipt: Mapping[str, Any]) -> None:
    _require_external_path(output, "site13_materialization_receipt_output_must_be_external")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_site13_materialization_receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(canonical_json_bytes(dict(receipt)))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ValueError("refusing_to_overwrite_site13_materialization_receipt") from exc


def materialize_site13(
    *,
    blueprint_path: Path,
    staging_receipt_path: Path,
    staging_root: Path,
    materialization_root: Path,
    output: Path,
) -> dict[str, Any]:
    for path, error in (
        (materialization_root, "site13_materialization_root_must_be_external"),
        (output, "site13_materialization_receipt_output_must_be_external"),
    ):
        _require_external_path(path, error)
    if materialization_root.exists() or materialization_root.is_symlink():
        raise ValueError("refusing_to_overwrite_site13_materialization_root")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing_to_overwrite_site13_materialization_receipt")
    if any(_paths_overlap(materialization_root, other) for other in (blueprint_path, staging_receipt_path, staging_root, output)):
        raise ValueError("site13_materialization_paths_must_not_overlap_inputs_or_receipt")
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
    _require_external_path(receipt_path, "site13_materialization_receipt_must_be_external")
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError("site13_materialization_receipt_path_invalid")
    raw = receipt_path.read_bytes()
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("site13_materialization_receipt_json_invalid") from exc
    if canonical_json_bytes(value) != raw:
        raise ValueError("site13_materialization_receipt_not_canonical")
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
    parser = argparse.ArgumentParser(description="Materialize the preregistered site-13 source-flow triplet pair.")
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
            receipt = materialize_site13(
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
        print(f"materialize_l3_source_flow_site13: {exc}", file=sys.stderr)
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
