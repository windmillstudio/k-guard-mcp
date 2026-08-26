from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "k_guard_l2_webgoat_missing_function_ac_execution_evidence.v1"
APP_ID = "webgoat"
REPOSITORY_ID = "webgoat/webgoat"
SOURCE_COMMIT = "5142935bf7c279882c3b0fc0ecec42c447de6fd5"
SOURCE_TREE = "6c45e60db0995416a5bbe5977657a78d5084dcf7"
SOURCE_TREE_SHA256 = "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c"
SOURCE_RECEIPT_SHA256 = "52ba9d0e5a85539790e9b68f82ad4d389847b4331354276e196af64367af7aaa"
SOURCE_RECEIPT_SEMANTIC_SHA256 = "4b518fc464fcbc9eed993895c3aa628958828a3c8a6f6733e24739c84628dded"
SOURCE_LINEAGE_ID = "57bdd9ad7f768090b3c1530f2e0bff3ffa1746befdbd09f8e8c0a5c2ef497c72"
SOURCE_PATH = "src/it/java/org/owasp/webgoat/integration/AccessControlIntegrationTest.java"
SOURCE_LINE = 15
SOURCE_CONTENT_SHA256 = "29c6f550f55ece56cebe67e503c10feeaaa05fbe9cd4fd26921b168211bb3e36"
SOURCE_BYTE_COUNT = 2778
ROOT_CAUSE = "upstream-test:org.owasp.webgoat.integration.AccessControlIntegrationTest#testLesson"
SOURCE_ROOT_CAUSE_IDENTITY = "fbfda4592bc795b9ba7433758b6d4287e525c3a1f418b7c104c5cdf347f87e14"
SCENARIO_ID = "webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:fbfda4592bc795b9"
POSITIVE_EXECUTION_RECEIPT_SHA256 = "ef6ebea1b3db517f1d2f5823439d4b164febc44a2552c6fe2baf5b758f71d8cd"
NEGATIVE_CONTROL_RECEIPT_SHA256 = "ef4db0a19a190d0dd17e35e1f8f128a47abe3acf7504e9bb63852b6354a5430b"
POSITIVE_RESULT_SHA256 = "e0c771ee18c8d1143b6dae097cf32756c21852d1afa0ba39f0c991d6beb0f3c3"
NEGATIVE_RESULT_SHA256 = "299b4065f097d6a34bc8372faef4bf388454de4ad5184a158e2ea50d2aa468b2"
TEST_CLASS = "org.owasp.webgoat.integration.AccessControlIntegrationTest"
PROCESS_ARGV = (
    "./mvnw",
    "-o",
    "-B",
    "-Dstyle.color=never",
    "-Pcleanall,start-server",
    "-Dtest=__kguard_no_unit__",
    "-Dsurefire.failIfNoSpecifiedTests=false",
    f"-Dit.test={TEST_CLASS}",
    "verify",
)
ADMISSION_BLOCKERS = tuple(
    sorted(
        {
            "evidence_signature_missing",
            "independent_upstream_fixed_revision_missing",
            "registry_evidence_integration_missing",
            "scanner_finding_mapping_missing",
            "source_bound_severity_rubric_missing",
        }
    )
)
SHA256_LENGTH = 64


class ExecutionEvidenceError(RuntimeError):
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
        raise ExecutionEvidenceError(f"{label}_unreadable") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise ExecutionEvidenceError(f"{label}_not_canonical")
    return value, raw


def _load_replay_contract() -> tuple[Any, str]:
    path = Path(__file__).resolve(strict=True).with_name("replay_l2_webgoat_missing_function_ac.py")
    raw_before = path.read_bytes()
    name = "k_guard_l2_webgoat_missing_function_ac_execution_evidence_replay"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ExecutionEvidenceError("replay_contract_load_failed")
    previous = sys.modules.get(name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - protects standalone CLI use.
        raise ExecutionEvidenceError("replay_contract_load_failed") from exc
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    if path.read_bytes() != raw_before:
        raise ExecutionEvidenceError("replay_contract_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _source_selector() -> dict[str, Any]:
    identity_material = "\0".join(
        (SOURCE_LINEAGE_ID, SOURCE_PATH, str(SOURCE_LINE), SOURCE_CONTENT_SHA256)
    )
    identity = sha256_bytes(("k_guard_l2_source_root_cause.v1\0" + identity_material).encode("utf-8"))
    scenario_id = (
        "webgoat:upstream-test-org-owasp-webgoat-integration-accesscontrolintegrationtest-testlesson:"
        + identity[:16]
    )
    if identity != SOURCE_ROOT_CAUSE_IDENTITY or scenario_id != SCENARIO_ID:
        raise ExecutionEvidenceError("source_selector_preregistration_mismatch")
    return {
        "root_cause": ROOT_CAUSE,
        "source_path": SOURCE_PATH,
        "source_line": SOURCE_LINE,
        "source_content_sha256": SOURCE_CONTENT_SHA256,
        "source_root_cause_identity": identity,
        "scenario_id": scenario_id,
        "raw_returned": False,
    }


def _source_receipt_semantic_sha256(receipt: dict[str, Any]) -> str:
    porcelain_clean = receipt.get("git_porcelain_clean")
    if not isinstance(porcelain_clean, bool):
        raise ExecutionEvidenceError("source_receipt_porcelain_flag_invalid")
    semantic = dict(receipt)
    del semantic["git_porcelain_clean"]
    return sha256_bytes(canonical_json_bytes(semantic))


def _validate_source_receipt(receipt: dict[str, Any], raw: bytes) -> None:
    if sha256_bytes(raw) != SOURCE_RECEIPT_SHA256:
        raise ExecutionEvidenceError("source_receipt_identity_mismatch")
    if _source_receipt_semantic_sha256(receipt) != SOURCE_RECEIPT_SEMANTIC_SHA256:
        raise ExecutionEvidenceError("source_receipt_semantic_identity_mismatch")
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
        raise ExecutionEvidenceError("source_receipt_contract_invalid")
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
        raise ExecutionEvidenceError("source_receipt_blob_truth_missing")
    files = receipt.get("files")
    if not isinstance(files, list):
        raise ExecutionEvidenceError("source_receipt_file_manifest_invalid")
    rows = [row for row in files if isinstance(row, dict) and row.get("path") == SOURCE_PATH]
    if len(rows) != 1 or {
        "sha256": rows[0].get("sha256"),
        "byte_count": rows[0].get("byte_count"),
    } != {"sha256": SOURCE_CONTENT_SHA256, "byte_count": SOURCE_BYTE_COUNT}:
        raise ExecutionEvidenceError("source_receipt_selector_not_bound")


def _expected_process(*, expected_exit_code: int, expected_result_sha256: str) -> dict[str, Any]:
    return {
        "argv": list(PROCESS_ARGV),
        "cwd": ".",
        "kind": "process",
        "network_policy": "offline",
        "expected_exit_code": expected_exit_code,
        "expected_http_status": None,
        "expected_body_sha256": None,
        "expected_result_sha256": expected_result_sha256,
    }


def _validate_run_consensus(
    receipt: dict[str, Any],
    *,
    expected_exit_code: int,
    expected_result_schema: str,
    expect_cases_passed: bool,
    require_control_triggered: bool,
    label: str,
) -> tuple[str, int]:
    runs = receipt.get("runs")
    consensus = receipt.get("consensus")
    if not isinstance(runs, list) or len(runs) != 2 or not isinstance(consensus, dict):
        raise ExecutionEvidenceError(f"{label}_run_shape_invalid")
    result_hashes: list[str] = []
    nonces: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            raise ExecutionEvidenceError(f"{label}_run_shape_invalid")
        execution = run.get("execution")
        normalized = run.get("normalized_result")
        hashes = run.get("report_hashes")
        cleanup = run.get("cleanup")
        isolation = run.get("isolation")
        if (
            run.get("passed") is not True
            or run.get("raw_returned") is not False
            or run.get("expected_exit_code") != expected_exit_code
            or not _is_sha256(run.get("run_nonce_sha256"))
            or not isinstance(execution, dict)
            or execution.get("returncode") != expected_exit_code
            or execution.get("timed_out") is not False
            or execution.get("output_truncated") is not False
            or not isinstance(normalized, dict)
            or normalized.get("schema") != expected_result_schema
            or normalized.get("test_class") != TEST_CLASS
            or not isinstance(normalized.get("suite"), dict)
            or normalized["suite"].get("all_cases_passed") is not expect_cases_passed
            or not isinstance(hashes, dict)
            or not _is_sha256(hashes.get("summary_sha256"))
            or not _is_sha256(hashes.get("suite_sha256"))
            or not isinstance(cleanup, dict)
            or cleanup.get("passed") is not True
            or not isinstance(isolation, dict)
            or isolation.get("passed") is not True
            or run.get("observed_result") is not None
            or run.get("failure_code") is not None
        ):
            raise ExecutionEvidenceError(f"{label}_run_contract_invalid")
        if require_control_triggered and normalized.get("control_triggered") is not True:
            raise ExecutionEvidenceError(f"{label}_control_not_triggered")
        if not require_control_triggered and normalized.get("control_triggered") is not None:
            raise ExecutionEvidenceError(f"{label}_control_unexpected")
        result_hashes.append(hashes["summary_sha256"])
        nonces.append(run["run_nonce_sha256"])
    if (
        consensus.get("run_count") != 2
        or consensus.get("two_runs_byte_equivalent_after_normalization") is not True
        or consensus.get("raw_returned") is not False
        or len(set(result_hashes)) != 1
        or len(set(nonces)) != 2
    ):
        raise ExecutionEvidenceError(f"{label}_consensus_invalid")
    return result_hashes[0], len(runs)


def _validate_execution_pair(
    positive: dict[str, Any],
    positive_raw: bytes,
    negative: dict[str, Any],
    negative_raw: bytes,
    replay: Any,
) -> dict[str, Any]:
    positive_sha256 = sha256_bytes(positive_raw)
    negative_sha256 = sha256_bytes(negative_raw)
    if positive_sha256 != POSITIVE_EXECUTION_RECEIPT_SHA256:
        raise ExecutionEvidenceError("positive_execution_receipt_identity_mismatch")
    if negative_sha256 != NEGATIVE_CONTROL_RECEIPT_SHA256:
        raise ExecutionEvidenceError("negative_control_receipt_identity_mismatch")
    try:
        replay.validate_receipt(positive)
        replay.validate_negative_control_receipt(negative)
    except Exception as exc:
        raise ExecutionEvidenceError("replay_contract_validation_failed") from exc
    if positive.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS":
        raise ExecutionEvidenceError("positive_execution_contract_not_passed")
    if negative.get("negative_control_status") != "NEGATIVE_CONTROL_PASS":
        raise ExecutionEvidenceError("negative_control_contract_not_passed")
    expected_source = {
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "source_receipt_sha256": SOURCE_RECEIPT_SHA256,
    }
    for label, receipt in (("positive", positive), ("negative", negative)):
        source = receipt.get("source")
        if not isinstance(source, dict) or any(source.get(key) != value for key, value in expected_source.items()):
            raise ExecutionEvidenceError(f"{label}_execution_source_mismatch")
    reference = negative.get("positive_execution_contract")
    if (
        not isinstance(reference, dict)
        or reference.get("receipt_sha256") != positive_sha256
        or reference.get("source_receipt_sha256") != SOURCE_RECEIPT_SHA256
        or reference.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
        or reference.get("raw_returned") is not False
    ):
        raise ExecutionEvidenceError("negative_control_positive_reference_mismatch")
    positive_result, positive_count = _validate_run_consensus(
        positive,
        expected_exit_code=0,
        expected_result_schema=replay.RESULT_SCHEMA,
        expect_cases_passed=True,
        require_control_triggered=False,
        label="positive_execution",
    )
    negative_result, negative_count = _validate_run_consensus(
        negative,
        expected_exit_code=replay.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE,
        expected_result_schema=replay.NEGATIVE_CONTROL_RESULT_SCHEMA,
        expect_cases_passed=False,
        require_control_triggered=True,
        label="negative_control",
    )
    if positive_result != POSITIVE_RESULT_SHA256 or negative_result != NEGATIVE_RESULT_SHA256:
        raise ExecutionEvidenceError("execution_result_preregistration_mismatch")
    if positive_result == negative_result:
        raise ExecutionEvidenceError("negative_control_not_distinguishing")
    control = negative.get("negative_control")
    if (
        not isinstance(control, dict)
        or control.get("patch_id") != replay.NEGATIVE_CONTROL_PATCH_ID
        or control.get("source_checkout_mutated") is not False
        or control.get("raw_returned") is not False
    ):
        raise ExecutionEvidenceError("negative_control_source_variant_invalid")
    if (
        positive.get("image_cleanup", {}).get("passed") is not True
        or negative.get("image_cleanup", {}).get("passed") is not True
    ):
        raise ExecutionEvidenceError("execution_image_cleanup_missing")
    return {
        "positive_execution_receipt_sha256": positive_sha256,
        "negative_control_receipt_sha256": negative_sha256,
        "positive_result_sha256": positive_result,
        "negative_result_sha256": negative_result,
        "positive_run_count": positive_count,
        "negative_run_count": negative_count,
        "positive_per_run_cleanup_passed": True,
        "negative_per_run_cleanup_passed": True,
        "positive_image_cleanup_passed": True,
        "negative_image_cleanup_passed": True,
        "negative_control_patch_id": control["patch_id"],
        "negative_control_source_checkout_mutated": False,
        "raw_returned": False,
    }


def _claim_boundary() -> dict[str, bool]:
    return {
        "execution_result_pair_proven": True,
        "source_bound_execution_selector_proven": True,
        "process_oracle_contract_proven": True,
        "state_reset_cleanup_chain_proven": True,
        "generated_control_pair_only": True,
        "independent_upstream_fixed_revision_proven": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "registry_evidence_integrated": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _state_reset_evidence(pair: dict[str, Any]) -> dict[str, Any]:
    return {
        "positive_per_run_cleanup_passed": pair["positive_per_run_cleanup_passed"],
        "negative_per_run_cleanup_passed": pair["negative_per_run_cleanup_passed"],
        "positive_image_cleanup_passed": pair["positive_image_cleanup_passed"],
        "negative_image_cleanup_passed": pair["negative_image_cleanup_passed"],
        "negative_control_source_checkout_mutated": pair[
            "negative_control_source_checkout_mutated"
        ],
        "registry_state_reset_admitted": False,
        "raw_returned": False,
    }


def derive_execution_evidence(
    source_receipt_path: Path,
    positive_receipt_path: Path,
    negative_receipt_path: Path,
    *,
    replay_module: Any | None = None,
) -> dict[str, Any]:
    source_receipt, source_raw = _load_canonical_object(source_receipt_path, label="source_receipt")
    positive, positive_raw = _load_canonical_object(positive_receipt_path, label="positive_execution_receipt")
    negative, negative_raw = _load_canonical_object(negative_receipt_path, label="negative_control_receipt")
    _validate_source_receipt(source_receipt, source_raw)
    if replay_module is None:
        replay_module, replay_sha256 = _load_replay_contract()
    else:
        replay_path = Path(getattr(replay_module, "__file__", ""))
        replay_sha256 = sha256_bytes(replay_path.read_bytes()) if replay_path.is_file() else "0" * SHA256_LENGTH
    pair = _validate_execution_pair(positive, positive_raw, negative, negative_raw, replay_module)
    payload = {
        "schema": SCHEMA,
        "tool_provenance": {
            "adapter_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "replay_contract_sha256": replay_sha256,
            "raw_returned": False,
        },
        "source": {
            "app_id": APP_ID,
            "repository_id": REPOSITORY_ID,
            "commit": SOURCE_COMMIT,
            "commit_tree": SOURCE_TREE,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "source_receipt_sha256": SOURCE_RECEIPT_SHA256,
            "source_receipt_semantic_sha256": SOURCE_RECEIPT_SEMANTIC_SHA256,
            "lineage_id": SOURCE_LINEAGE_ID,
            "selector": _source_selector(),
            "raw_returned": False,
        },
        "execution_pair": pair,
        "oracle": _expected_process(
            expected_exit_code=0, expected_result_sha256=pair["positive_result_sha256"]
        ),
        "negative_control": _expected_process(
            expected_exit_code=replay_module.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE,
            expected_result_sha256=pair["negative_result_sha256"],
        ),
        "state_reset_evidence": _state_reset_evidence(pair),
        "claim_boundary": _claim_boundary(),
        "admission_blockers": list(ADMISSION_BLOCKERS),
        "adapter_status": "EXECUTION_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    validate_execution_evidence(payload)
    return payload


def _validate_process(value: Any, *, expected_exit_code: int, expected_result_sha256: str, label: str) -> None:
    if value != _expected_process(
        expected_exit_code=expected_exit_code, expected_result_sha256=expected_result_sha256
    ):
        raise ExecutionEvidenceError(f"{label}_process_contract_invalid")


def validate_execution_evidence(payload: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "execution_pair",
        "oracle",
        "negative_control",
        "state_reset_evidence",
        "claim_boundary",
        "admission_blockers",
        "adapter_status",
        "release_gate_passed",
        "raw_returned",
    }
    if set(payload) != required or payload.get("schema") != SCHEMA or payload.get("raw_returned") is not False:
        raise ExecutionEvidenceError("execution_evidence_schema_invalid")
    provenance = payload.get("tool_provenance")
    if (
        not isinstance(provenance, dict)
        or set(provenance) != {"adapter_sha256", "replay_contract_sha256", "raw_returned"}
        or not _is_sha256(provenance.get("adapter_sha256"))
        or not _is_sha256(provenance.get("replay_contract_sha256"))
        or provenance.get("raw_returned") is not False
    ):
        raise ExecutionEvidenceError("execution_evidence_provenance_invalid")
    expected_source = {
        "app_id": APP_ID,
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "source_receipt_sha256": SOURCE_RECEIPT_SHA256,
        "source_receipt_semantic_sha256": SOURCE_RECEIPT_SEMANTIC_SHA256,
        "lineage_id": SOURCE_LINEAGE_ID,
        "selector": _source_selector(),
        "raw_returned": False,
    }
    if payload.get("source") != expected_source:
        raise ExecutionEvidenceError("execution_evidence_source_invalid")
    pair = payload.get("execution_pair")
    required_pair = {
        "positive_execution_receipt_sha256",
        "negative_control_receipt_sha256",
        "positive_result_sha256",
        "negative_result_sha256",
        "positive_run_count",
        "negative_run_count",
        "positive_per_run_cleanup_passed",
        "negative_per_run_cleanup_passed",
        "positive_image_cleanup_passed",
        "negative_image_cleanup_passed",
        "negative_control_patch_id",
        "negative_control_source_checkout_mutated",
        "raw_returned",
    }
    if (
        not isinstance(pair, dict)
        or set(pair) != required_pair
        or pair.get("positive_execution_receipt_sha256") != POSITIVE_EXECUTION_RECEIPT_SHA256
        or pair.get("negative_control_receipt_sha256") != NEGATIVE_CONTROL_RECEIPT_SHA256
        or pair.get("positive_result_sha256") != POSITIVE_RESULT_SHA256
        or pair.get("negative_result_sha256") != NEGATIVE_RESULT_SHA256
        or pair["positive_result_sha256"] == pair["negative_result_sha256"]
        or pair.get("positive_run_count") != 2
        or pair.get("negative_run_count") != 2
        or any(
            pair.get(field) is not True
            for field in (
                "positive_per_run_cleanup_passed",
                "negative_per_run_cleanup_passed",
                "positive_image_cleanup_passed",
                "negative_image_cleanup_passed",
            )
        )
        or pair.get("negative_control_patch_id") != "force-created-user-nonadmin.v1"
        or pair.get("negative_control_source_checkout_mutated") is not False
        or pair.get("raw_returned") is not False
    ):
        raise ExecutionEvidenceError("execution_evidence_pair_invalid")
    _validate_process(
        payload.get("oracle"),
        expected_exit_code=0,
        expected_result_sha256=pair["positive_result_sha256"],
        label="oracle",
    )
    _validate_process(
        payload.get("negative_control"),
        expected_exit_code=1,
        expected_result_sha256=pair["negative_result_sha256"],
        label="negative_control",
    )
    if payload.get("state_reset_evidence") != _state_reset_evidence(pair):
        raise ExecutionEvidenceError("execution_evidence_state_reset_invalid")
    if (
        payload.get("claim_boundary") != _claim_boundary()
        or tuple(payload.get("admission_blockers", [])) != ADMISSION_BLOCKERS
        or payload.get("adapter_status") != "EXECUTION_EVIDENCE_PASS"
        or payload.get("release_gate_passed") is not False
    ):
        raise ExecutionEvidenceError("execution_evidence_claim_boundary_invalid")


def write_new_output(path: Path, payload: dict[str, Any]) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite execution evidence: {output}")
    output.write_bytes(canonical_json_bytes(payload))
    return output


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Derive raw-free WebGoat missing-function access-control execution evidence."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    derive = subparsers.add_parser("derive")
    derive.add_argument("--source-receipt", type=Path, required=True)
    derive.add_argument("--positive-receipt", type=Path, required=True)
    derive.add_argument("--negative-receipt", type=Path, required=True)
    derive.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "derive":
            payload = derive_execution_evidence(
                args.source_receipt, args.positive_receipt, args.negative_receipt
            )
            write_new_output(args.output, payload)
            return 0
        payload, _raw = _load_canonical_object(args.evidence, label="execution_evidence")
        validate_execution_evidence(payload)
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ExecutionEvidenceError, FileExistsError) as exc:
        raise SystemExit(f"HOLD: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
