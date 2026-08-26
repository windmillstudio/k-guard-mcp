from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "k_guard_l2_webgoat_idor_state_reset_evidence.v1"
VALIDATION_SCHEMA = "k_guard_l2_webgoat_idor_state_reset_validation.v1"
APP_ID = "webgoat"
REPOSITORY_ID = "webgoat/webgoat"
SOURCE_COMMIT = "5142935bf7c279882c3b0fc0ecec42c447de6fd5"
SOURCE_TREE = "6c45e60db0995416a5bbe5977657a78d5084dcf7"
SOURCE_TREE_SHA256 = "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c"
SOURCE_RECEIPT_SHA256 = "7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b"
SOURCE_LINEAGE_ID = "57bdd9ad7f768090b3c1530f2e0bff3ffa1746befdbd09f8e8c0a5c2ef497c72"
SOURCE_PATH = "src/it/java/org/owasp/webgoat/integration/IDORIntegrationTest.java"
SOURCE_LINE = 28
SOURCE_CONTENT_SHA256 = "bcf5db68da5b1574a4710a2cb087a4907ece95e4688310ef7213c957d2ddf6a9"
ROOT_CAUSE = "upstream-test:org.owasp.webgoat.integration.IDORIntegrationTest#testIDORLesson"
SOURCE_ROOT_CAUSE_IDENTITY = "2da84111e81ac5d492a9932982dde73fc513c8a0b14ed53abd3aa8cb95bc0166"
SCENARIO_ID = "webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:2da84111e81ac5d4"
POSITIVE_EXECUTION_RECEIPT_SHA256 = "3d1e162931ec875f1b9de8564ff08733677e7125347eb559c91318c67e86a874"
NEGATIVE_CONTROL_RECEIPT_SHA256 = "baee6c365c87526a5a7b00717c14616e7497eb55f804a9a0fdf9fe36160bddaa"
SHA256_LENGTH = 64
ADMISSION_BLOCKERS = tuple(
    sorted({"evidence_signature_missing", "registry_evidence_integration_missing"})
)


class StateResetEvidenceError(RuntimeError):
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
        raise StateResetEvidenceError(f"{label}_unreadable") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise StateResetEvidenceError(f"{label}_not_canonical")
    return value, raw


def _load_module(filename: str, module_name: str) -> tuple[Any, str]:
    path = Path(__file__).resolve(strict=True).with_name(filename)
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise StateResetEvidenceError(f"{module_name}_load_failed")
    previous = sys.modules.get(module_name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - protects standalone CLI use.
        raise StateResetEvidenceError(f"{module_name}_load_failed") from exc
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    if path.read_bytes() != raw_before:
        raise StateResetEvidenceError(f"{module_name}_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _load_execution_adapter() -> tuple[Any, str]:
    return _load_module(
        "derive_l2_webgoat_idor_execution_evidence.py",
        "k_guard_l2_webgoat_idor_state_reset_execution_adapter",
    )


def _load_registry_contract_sha256() -> str:
    path = Path(__file__).resolve(strict=True).with_name("materialize_l2_oracles.py")
    return sha256_bytes(path.read_bytes())


def _source_selector() -> dict[str, Any]:
    identity_material = "\0".join(
        (SOURCE_LINEAGE_ID, SOURCE_PATH, str(SOURCE_LINE), SOURCE_CONTENT_SHA256)
    )
    identity = sha256_bytes(("k_guard_l2_source_root_cause.v1\0" + identity_material).encode("utf-8"))
    scenario_id = (
        "webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:"
        + identity[:16]
    )
    if identity != SOURCE_ROOT_CAUSE_IDENTITY or scenario_id != SCENARIO_ID:
        raise StateResetEvidenceError("source_selector_preregistration_mismatch")
    return {
        "root_cause": ROOT_CAUSE,
        "source_path": SOURCE_PATH,
        "source_line": SOURCE_LINE,
        "source_content_sha256": SOURCE_CONTENT_SHA256,
        "source_root_cause_identity": identity,
        "scenario_id": scenario_id,
        "raw_returned": False,
    }


def _validation_projection() -> dict[str, Any]:
    return {
        "schema": VALIDATION_SCHEMA,
        "status": "STATE_RESET_EVIDENCE_PASS",
        "raw_returned": False,
    }


def _expected_state_reset_command() -> dict[str, Any]:
    return {
        "argv": [
            "python",
            "scripts/derive_l2_webgoat_idor_state_reset_evidence.py",
            "validate",
            "--evidence",
            "evidence/l2-webgoat-idor-state-reset.json",
        ],
        "cwd": ".",
        "kind": "process",
        "network_policy": "offline",
        "expected_exit_code": 0,
        "expected_http_status": None,
        "expected_body_sha256": None,
        "expected_result_sha256": sha256_bytes(canonical_json_bytes(_validation_projection())),
    }


def _validate_cleanup(receipt: dict[str, Any], *, label: str) -> tuple[list[str], str]:
    runs = receipt.get("runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise StateResetEvidenceError(f"{label}_run_shape_invalid")
    nonces: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            raise StateResetEvidenceError(f"{label}_run_shape_invalid")
        cleanup = run.get("cleanup")
        nonce = run.get("run_nonce_sha256")
        if (
            run.get("passed") is not True
            or run.get("raw_returned") is not False
            or not _is_sha256(nonce)
            or not isinstance(cleanup, dict)
            or cleanup.get("ownership_verified") is not True
            or cleanup.get("container_removed") is not True
            or cleanup.get("volume_count") != 2
            or cleanup.get("volumes_removed") is not True
            or cleanup.get("passed") is not True
            or cleanup.get("raw_returned") is not False
        ):
            raise StateResetEvidenceError(f"{label}_run_cleanup_invalid")
        nonces.append(nonce)
    image_cleanup = receipt.get("image_cleanup")
    if (
        not isinstance(image_cleanup, dict)
        or image_cleanup.get("ownership_verified") is not True
        or image_cleanup.get("removed") is not True
        or image_cleanup.get("absent_after") is not True
        or image_cleanup.get("passed") is not True
        or image_cleanup.get("raw_returned") is not False
    ):
        raise StateResetEvidenceError(f"{label}_image_cleanup_invalid")
    if len(set(nonces)) != 2:
        raise StateResetEvidenceError(f"{label}_run_nonce_not_unique")
    image = receipt.get("image")
    if not isinstance(image, dict) or not _is_sha256(str(image.get("image_id", "")).removeprefix("sha256:")):
        raise StateResetEvidenceError(f"{label}_image_identity_invalid")
    return nonces, sha256_bytes(str(image["image_id"]).encode("ascii"))


def _claim_boundary() -> dict[str, bool]:
    return {
        "state_reset_cleanup_chain_proven": True,
        "registry_state_reset_admitted": False,
        "registry_scenario_admitted": False,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def derive_state_reset_evidence(
    execution_evidence_path: Path,
    positive_receipt_path: Path,
    negative_receipt_path: Path,
    *,
    execution_adapter: Any | None = None,
) -> dict[str, Any]:
    execution, execution_raw = _load_canonical_object(
        execution_evidence_path, label="execution_evidence"
    )
    positive, positive_raw = _load_canonical_object(
        positive_receipt_path, label="positive_execution_receipt"
    )
    negative, negative_raw = _load_canonical_object(
        negative_receipt_path, label="negative_control_receipt"
    )
    if execution_adapter is None:
        execution_adapter, execution_adapter_sha256 = _load_execution_adapter()
    else:
        adapter_path = Path(getattr(execution_adapter, "__file__", ""))
        execution_adapter_sha256 = (
            sha256_bytes(adapter_path.read_bytes()) if adapter_path.is_file() else "0" * SHA256_LENGTH
        )
    try:
        execution_adapter.validate_execution_evidence(execution)
        replay, replay_sha256 = execution_adapter._load_replay_contract()
        pair = execution_adapter._validate_execution_pair(
            positive, positive_raw, negative, negative_raw, replay
        )
    except Exception as exc:
        raise StateResetEvidenceError("execution_evidence_input_invalid") from exc
    if sha256_bytes(positive_raw) != POSITIVE_EXECUTION_RECEIPT_SHA256:
        raise StateResetEvidenceError("positive_execution_receipt_identity_mismatch")
    if sha256_bytes(negative_raw) != NEGATIVE_CONTROL_RECEIPT_SHA256:
        raise StateResetEvidenceError("negative_control_receipt_identity_mismatch")
    if execution.get("execution_pair") != pair:
        raise StateResetEvidenceError("execution_pair_does_not_match_receipts")
    if execution.get("state_reset_evidence") != execution_adapter._state_reset_evidence(pair):
        raise StateResetEvidenceError("execution_cleanup_projection_invalid")
    if execution.get("claim_boundary", {}).get("registry_state_reset_admitted") is not False:
        raise StateResetEvidenceError("execution_evidence_cannot_self_admit_reset")
    source = execution.get("source")
    expected_source = {
        "app_id": APP_ID,
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "source_receipt_sha256": SOURCE_RECEIPT_SHA256,
        "lineage_id": SOURCE_LINEAGE_ID,
        "selector": _source_selector(),
        "raw_returned": False,
    }
    if source != expected_source:
        raise StateResetEvidenceError("execution_source_selector_invalid")
    positive_nonces, positive_image_id_sha256 = _validate_cleanup(positive, label="positive")
    negative_nonces, negative_image_id_sha256 = _validate_cleanup(negative, label="negative")
    all_nonces = positive_nonces + negative_nonces
    if len(set(all_nonces)) != 4:
        raise StateResetEvidenceError("cleanup_nonce_collision")
    payload = {
        "schema": SCHEMA,
        "tool_provenance": {
            "adapter_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "execution_adapter_sha256": execution_adapter_sha256,
            "replay_contract_sha256": replay_sha256,
            "registry_contract_sha256": _load_registry_contract_sha256(),
            "raw_returned": False,
        },
        "source": expected_source,
        "inputs": {
            "execution_evidence_sha256": sha256_bytes(execution_raw),
            "positive_execution_receipt_sha256": sha256_bytes(positive_raw),
            "negative_control_receipt_sha256": sha256_bytes(negative_raw),
            "raw_returned": False,
        },
        "reset_proof": {
            "positive_run_count": 2,
            "negative_run_count": 2,
            "unique_run_nonce_count": 4,
            "positive_per_run_cleanup_passed": True,
            "negative_per_run_cleanup_passed": True,
            "positive_image_absent_after": True,
            "negative_image_absent_after": True,
            "positive_image_id_sha256": positive_image_id_sha256,
            "negative_image_id_sha256": negative_image_id_sha256,
            "raw_returned": False,
        },
        "state_reset": _expected_state_reset_command(),
        "claim_boundary": _claim_boundary(),
        "admission_blockers": list(ADMISSION_BLOCKERS),
        "adapter_status": "STATE_RESET_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    validate_state_reset_evidence(payload)
    return payload


def validate_state_reset_evidence(payload: dict[str, Any]) -> None:
    required = {
        "schema",
        "tool_provenance",
        "source",
        "inputs",
        "reset_proof",
        "state_reset",
        "claim_boundary",
        "admission_blockers",
        "adapter_status",
        "release_gate_passed",
        "raw_returned",
    }
    if set(payload) != required or payload.get("schema") != SCHEMA or payload.get("raw_returned") is not False:
        raise StateResetEvidenceError("state_reset_evidence_schema_invalid")
    provenance = payload.get("tool_provenance")
    if (
        not isinstance(provenance, dict)
        or set(provenance) != {
            "adapter_sha256",
            "execution_adapter_sha256",
            "replay_contract_sha256",
            "registry_contract_sha256",
            "raw_returned",
        }
        or any(not _is_sha256(provenance.get(field)) for field in (
            "adapter_sha256",
            "execution_adapter_sha256",
            "replay_contract_sha256",
            "registry_contract_sha256",
        ))
        or provenance.get("raw_returned") is not False
    ):
        raise StateResetEvidenceError("state_reset_evidence_provenance_invalid")
    expected_source = {
        "app_id": APP_ID,
        "repository_id": REPOSITORY_ID,
        "commit": SOURCE_COMMIT,
        "commit_tree": SOURCE_TREE,
        "source_tree_sha256": SOURCE_TREE_SHA256,
        "source_receipt_sha256": SOURCE_RECEIPT_SHA256,
        "lineage_id": SOURCE_LINEAGE_ID,
        "selector": _source_selector(),
        "raw_returned": False,
    }
    if payload.get("source") != expected_source:
        raise StateResetEvidenceError("state_reset_evidence_source_invalid")
    inputs = payload.get("inputs")
    if (
        not isinstance(inputs, dict)
        or set(inputs) != {
            "execution_evidence_sha256",
            "positive_execution_receipt_sha256",
            "negative_control_receipt_sha256",
            "raw_returned",
        }
        or not _is_sha256(inputs.get("execution_evidence_sha256"))
        or inputs.get("positive_execution_receipt_sha256") != POSITIVE_EXECUTION_RECEIPT_SHA256
        or inputs.get("negative_control_receipt_sha256") != NEGATIVE_CONTROL_RECEIPT_SHA256
        or inputs.get("raw_returned") is not False
    ):
        raise StateResetEvidenceError("state_reset_evidence_inputs_invalid")
    proof = payload.get("reset_proof")
    if (
        not isinstance(proof, dict)
        or set(proof) != {
            "positive_run_count",
            "negative_run_count",
            "unique_run_nonce_count",
            "positive_per_run_cleanup_passed",
            "negative_per_run_cleanup_passed",
            "positive_image_absent_after",
            "negative_image_absent_after",
            "positive_image_id_sha256",
            "negative_image_id_sha256",
            "raw_returned",
        }
        or proof.get("positive_run_count") != 2
        or proof.get("negative_run_count") != 2
        or proof.get("unique_run_nonce_count") != 4
        or any(proof.get(field) is not True for field in (
            "positive_per_run_cleanup_passed",
            "negative_per_run_cleanup_passed",
            "positive_image_absent_after",
            "negative_image_absent_after",
        ))
        or not _is_sha256(proof.get("positive_image_id_sha256"))
        or not _is_sha256(proof.get("negative_image_id_sha256"))
        or proof.get("raw_returned") is not False
    ):
        raise StateResetEvidenceError("state_reset_evidence_proof_invalid")
    if payload.get("state_reset") != _expected_state_reset_command():
        raise StateResetEvidenceError("state_reset_command_invalid")
    if (
        payload.get("claim_boundary") != _claim_boundary()
        or tuple(payload.get("admission_blockers", [])) != ADMISSION_BLOCKERS
        or payload.get("adapter_status") != "STATE_RESET_EVIDENCE_PASS"
        or payload.get("release_gate_passed") is not False
    ):
        raise StateResetEvidenceError("state_reset_evidence_claim_boundary_invalid")


def write_new_output(path: Path, payload: dict[str, Any]) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite state reset evidence: {output}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_json_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise FileExistsError(f"refusing to overwrite state reset evidence: {output}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Derive raw-free WebGoat IDOR state-reset evidence without admitting registry or release status."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    derive = subparsers.add_parser("derive")
    derive.add_argument("--execution-evidence", type=Path, required=True)
    derive.add_argument("--positive-receipt", type=Path, required=True)
    derive.add_argument("--negative-receipt", type=Path, required=True)
    derive.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "derive":
            payload = derive_state_reset_evidence(
                args.execution_evidence, args.positive_receipt, args.negative_receipt
            )
            output = write_new_output(args.output, payload)
            print(
                json.dumps(
                    {
                        "adapter_status": payload["adapter_status"],
                        "evidence_sha256": sha256_bytes(output.read_bytes()),
                        "release_gate_passed": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0
        payload, _raw = _load_canonical_object(args.evidence, label="state_reset_evidence")
        validate_state_reset_evidence(payload)
        sys.stdout.buffer.write(canonical_json_bytes(_validation_projection()))
        return 0
    except (StateResetEvidenceError, FileExistsError) as exc:
        print(json.dumps({"error": str(exc), "release_gate_passed": False}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
