from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "k_guard_l2_webgoat_sql_injection_advanced_cwe_evidence.v1"
APP_ID = "webgoat"
REPOSITORY_ID = "webgoat/webgoat"
SOURCE_COMMIT = "5142935bf7c279882c3b0fc0ecec42c447de6fd5"
SOURCE_TREE = "6c45e60db0995416a5bbe5977657a78d5084dcf7"
SOURCE_TREE_SHA256 = "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c"
SOURCE_RECEIPT_RAW_SHA256 = "52ba9d0e5a85539790e9b68f82ad4d389847b4331354276e196af64367af7aaa"
SOURCE_RECEIPT_SHA256 = "4b518fc464fcbc9eed993895c3aa628958828a3c8a6f6733e24739c84628dded"
SOURCE_LINEAGE_ID = "57bdd9ad7f768090b3c1530f2e0bff3ffa1746befdbd09f8e8c0a5c2ef497c72"
TEST_PATH = "src/it/java/org/owasp/webgoat/integration/SqlInjectionAdvancedIntegrationTest.java"
TEST_LINE = 13
TEST_CONTENT_SHA256 = "2ef8a359befd66f5a75cc4d30ce0be573c762eaf2f6d3bd052509afad2d7633a"
TEST_BYTE_COUNT = 2440
IMPLEMENTATION_PATH = "src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java"
IMPLEMENTATION_CONTENT_SHA256 = "d9c9aad8e2e49b8e2192637aaf18f80b774b487b14983147b0207a3466459c02"
IMPLEMENTATION_BYTE_COUNT = 4435
ROOT_CAUSE = "upstream-test:org.owasp.webgoat.integration.SqlInjectionAdvancedIntegrationTest#runTests"
SOURCE_ROOT_CAUSE_IDENTITY = "d89982fbf77e55304de7e52f8164bad748cd497c156ebb416d92937e3d57d50e"
SCENARIO_ID = "webgoat:upstream-test-org-owasp-webgoat-integration-sqlinjectionadvancedintegrationtest-runtests:d89982fbf77e5530"
CWE_ID = "CWE-89"
CWE_REFERENCE = "https://cwe.mitre.org/data/definitions/89.html"
SHA256_LENGTH = 64

TEST_ANCHORS = {
    "advanced_lesson_selected": b'startLesson("SqlInjectionAdvanced");',
    "negative_registration_control": b'checkAssignmentWithPUT(webGoatUrlConfig.url("SqlInjectionAdvanced/register"), params, false);',
    "attack6a_endpoint": b'checkAssignment(webGoatUrlConfig.url("SqlInjectionAdvanced/attack6a"), params, true);',
    "data_exfiltration_test_vector": b'params.put("userid_6a", "\'; SELECT * FROM user_system_data;--");',
}
IMPLEMENTATION_ANCHORS = {
    "untrusted_value_in_sql_literal": b'"SELECT * FROM user_data WHERE last_name = \'" + accountName + "\'"',
    "raw_statement_creation": b'connection.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)',
    "constructed_query_execution": b'statement.executeQuery(query)',
    "sensitive_data_success_condition": b'output.toString().contains("dave") && output.toString().contains("passW0rD")',
}


class CweEvidenceError(RuntimeError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_canonical_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.resolve(strict=True).read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CweEvidenceError(f"{label}_unreadable") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise CweEvidenceError(f"{label}_not_canonical")
    return value, raw


def _source_selector() -> dict[str, Any]:
    identity_material = "\0".join(
        (SOURCE_LINEAGE_ID, TEST_PATH, str(TEST_LINE), TEST_CONTENT_SHA256)
    )
    identity = sha256_bytes(("k_guard_l2_source_root_cause.v1\0" + identity_material).encode("utf-8"))
    scenario_id = (
        "webgoat:upstream-test-org-owasp-webgoat-integration-"
        "sqlinjectionadvancedintegrationtest-runtests:"
        + identity[:16]
    )
    if identity != SOURCE_ROOT_CAUSE_IDENTITY or scenario_id != SCENARIO_ID:
        raise CweEvidenceError("source_selector_preregistration_mismatch")
    return {
        "root_cause": ROOT_CAUSE,
        "source_path": TEST_PATH,
        "source_line": TEST_LINE,
        "source_content_sha256": TEST_CONTENT_SHA256,
        "source_root_cause_identity": identity,
        "scenario_id": scenario_id,
        "raw_returned": False,
    }


def _validate_source_receipt(receipt: dict[str, Any], raw: bytes) -> None:
    if sha256_bytes(raw) != SOURCE_RECEIPT_RAW_SHA256:
        raise CweEvidenceError("source_receipt_identity_mismatch")
    expected_identity = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
    }
    if (
        receipt.get("schema") != "k_guard_git_source_materialization.v2"
        or receipt.get("passed") is not True
        or receipt.get("raw_returned") is not False
        or any(receipt.get(key) != value for key, value in expected_identity.items())
    ):
        raise CweEvidenceError("source_receipt_contract_invalid")
    required_truths = (
        "source_worktree_clean",
        "origin_repository_match",
        "commit_match",
        "commit_object_hash_match",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
    )
    if any(receipt.get(field) is not True for field in required_truths):
        raise CweEvidenceError("source_receipt_blob_truth_missing")
    files = receipt.get("files")
    if not isinstance(files, list):
        raise CweEvidenceError("source_receipt_file_manifest_invalid")
    expected_files = {
        TEST_PATH: {"sha256": TEST_CONTENT_SHA256, "byte_count": TEST_BYTE_COUNT},
        IMPLEMENTATION_PATH: {
            "sha256": IMPLEMENTATION_CONTENT_SHA256,
            "byte_count": IMPLEMENTATION_BYTE_COUNT,
        },
    }
    for path, expected in expected_files.items():
        rows = [row for row in files if isinstance(row, dict) and row.get("path") == path]
        if len(rows) != 1 or {"sha256": rows[0].get("sha256"), "byte_count": rows[0].get("byte_count")} != expected:
            raise CweEvidenceError("source_receipt_selector_not_bound")


def _git(source_root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *args],
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise CweEvidenceError("source_git_unavailable") from exc
    if result.returncode != 0:
        raise CweEvidenceError("source_git_command_failed")
    return result.stdout


def _verify_source_root(source_root: Path) -> Path:
    root = source_root.resolve(strict=True)
    top_level = _git(root, "rev-parse", "--show-toplevel").decode("utf-8", errors="strict").strip()
    if Path(top_level).resolve(strict=True) != root:
        raise CweEvidenceError("source_root_is_not_repository_root")
    commit = _git(root, "rev-parse", "HEAD").decode("ascii", errors="strict").strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode("ascii", errors="strict").strip()
    if commit != SOURCE_COMMIT or tree != SOURCE_TREE:
        raise CweEvidenceError("source_root_identity_mismatch")
    return root


def _read_source_blob(source_root: Path, path: str) -> bytes:
    return _git(source_root, "show", f"{SOURCE_COMMIT}:{path}")


def _validate_anchor_set(raw: bytes, anchors: dict[str, bytes], *, label: str) -> list[str]:
    missing = [anchor_id for anchor_id, needle in anchors.items() if needle not in raw]
    if missing:
        raise CweEvidenceError(f"{label}_source_anchor_missing")
    return sorted(anchors)


def _expected_source_evidence() -> dict[str, Any]:
    return {
        "test": {
            "path": TEST_PATH,
            "content_sha256": TEST_CONTENT_SHA256,
            "anchor_ids": sorted(TEST_ANCHORS),
            "raw_returned": False,
        },
        "implementation": {
            "path": IMPLEMENTATION_PATH,
            "content_sha256": IMPLEMENTATION_CONTENT_SHA256,
            "anchor_ids": sorted(IMPLEMENTATION_ANCHORS),
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _source_evidence(source_root: Path) -> dict[str, Any]:
    test_raw = _read_source_blob(source_root, TEST_PATH)
    implementation_raw = _read_source_blob(source_root, IMPLEMENTATION_PATH)
    if sha256_bytes(test_raw) != TEST_CONTENT_SHA256 or len(test_raw) != TEST_BYTE_COUNT:
        raise CweEvidenceError("test_source_blob_identity_mismatch")
    if (
        sha256_bytes(implementation_raw) != IMPLEMENTATION_CONTENT_SHA256
        or len(implementation_raw) != IMPLEMENTATION_BYTE_COUNT
    ):
        raise CweEvidenceError("implementation_source_blob_identity_mismatch")
    _validate_anchor_set(test_raw, TEST_ANCHORS, label="test")
    _validate_anchor_set(implementation_raw, IMPLEMENTATION_ANCHORS, label="implementation")
    return _expected_source_evidence()


def _classification() -> dict[str, Any]:
    return {
        "cwe": {
            "id": CWE_ID,
            "reference_url": CWE_REFERENCE,
            "mapping_scope": "pinned_webgoat_benchmark_scenario",
            "raw_returned": False,
        },
        "mechanism_truth": "present",
        "cvss_v4": None,
        "expected_disposition": None,
        "severity_status": "DEFERRED_NO_SOURCE_BOUND_CVSS_PROFILE",
        "source_evidence": _expected_source_evidence(),
        "raw_returned": False,
    }


def _claim_boundary() -> dict[str, bool]:
    return {
        "source_bound_cwe_mapping_supported": True,
        "source_bound_mechanism_truth_supported": True,
        "source_bound_cvss_profile_proven": False,
        "customer_deployment_severity_admitted": False,
        "scanner_accuracy_proven": False,
        "tp_fp_fn_admitted": False,
        "registry_evidence_integrated": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _admission_blockers() -> list[str]:
    return [
        "source_bound_cvss_profile_missing",
        "registry_evidence_integration_missing",
        "negative_control_missing",
        "state_reset_missing",
    ]


def derive_cwe_evidence(source_root: Path, source_receipt_path: Path) -> dict[str, Any]:
    receipt, raw = _load_canonical_object(source_receipt_path, label="source_receipt")
    _validate_source_receipt(receipt, raw)
    root = _verify_source_root(source_root)
    _source_evidence(root)
    payload = {
        "schema": SCHEMA,
        "tool_provenance": {
            "adapter_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "raw_returned": False,
        },
        "source": {
            "app_id": APP_ID,
            "repository_id": REPOSITORY_ID,
            "commit": SOURCE_COMMIT,
            "commit_tree": SOURCE_TREE,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "source_receipt_sha256": SOURCE_RECEIPT_RAW_SHA256,
            "source_receipt_semantic_sha256": SOURCE_RECEIPT_SHA256,
            "lineage_id": SOURCE_LINEAGE_ID,
            "selector": _source_selector(),
            "raw_returned": False,
        },
        "classification": _classification(),
        "claim_boundary": _claim_boundary(),
        "admission_blockers": _admission_blockers(),
        "adapter_status": "CWE_MECHANISM_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    validate_cwe_evidence(payload)
    return payload


def validate_cwe_evidence(payload: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "classification",
        "claim_boundary",
        "admission_blockers",
        "adapter_status",
        "release_gate_passed",
        "raw_returned",
    }
    if set(payload) != required or payload.get("schema") != SCHEMA or payload.get("raw_returned") is not False:
        raise CweEvidenceError("cwe_evidence_schema_invalid")
    provenance = payload.get("tool_provenance")
    if (
        not isinstance(provenance, dict)
        or set(provenance) != {"adapter_sha256", "raw_returned"}
        or provenance.get("adapter_sha256") != sha256_bytes(Path(__file__).read_bytes())
        or provenance.get("raw_returned") is not False
    ):
        raise CweEvidenceError("cwe_evidence_provenance_invalid")
    expected_source = {
        "app_id": APP_ID,
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "source_receipt_sha256": SOURCE_RECEIPT_RAW_SHA256,
        "source_receipt_semantic_sha256": SOURCE_RECEIPT_SHA256,
        "lineage_id": SOURCE_LINEAGE_ID,
        "selector": _source_selector(),
        "raw_returned": False,
    }
    if payload.get("source") != expected_source:
        raise CweEvidenceError("cwe_evidence_source_invalid")
    classification = payload.get("classification")
    if not isinstance(classification, dict):
        raise CweEvidenceError("cwe_evidence_classification_invalid")
    if classification != _classification():
        raise CweEvidenceError("cwe_evidence_classification_invalid")
    if (
        payload.get("claim_boundary") != _claim_boundary()
        or payload.get("admission_blockers") != _admission_blockers()
        or payload.get("adapter_status") != "CWE_MECHANISM_EVIDENCE_PASS"
        or payload.get("release_gate_passed") is not False
    ):
        raise CweEvidenceError("cwe_evidence_claim_boundary_invalid")


def write_new_output(path: Path, payload: dict[str, Any]) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite CWE evidence: {output}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=str(output.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise FileExistsError(f"refusing to overwrite CWE evidence: {output}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Derive source-bound WebGoat SQL Injection Advanced CWE evidence"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    derive = subparsers.add_parser("derive")
    derive.add_argument("--source-root", type=Path, required=True)
    derive.add_argument("--source-receipt", type=Path, required=True)
    derive.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    if args.command == "derive":
        payload = derive_cwe_evidence(args.source_root, args.source_receipt)
        output = write_new_output(args.output, payload)
    else:
        payload, _raw = _load_canonical_object(args.evidence, label="evidence")
        validate_cwe_evidence(payload)
        output = args.evidence.resolve(strict=True)
    print(
        json.dumps(
            {
                "adapter_status": payload["adapter_status"],
                "evidence_path": str(output.resolve(strict=True)),
                "evidence_sha256": sha256_bytes(output.read_bytes()),
                "release_gate_passed": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
