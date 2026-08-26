from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from k_guard_mcp.scanner import KGuardScanner


SCHEMA = "k_guard_l2_webgoat_idor_scanner_mapping.v1"
STATUS_PASS = "SCANNER_MAPPING_PASS"
STATUS_HOLD = "HOLD"
APP_ID = "webgoat"
REPOSITORY_ID = "webgoat/webgoat"
SOURCE_COMMIT = "5142935bf7c279882c3b0fc0ecec42c447de6fd5"
SOURCE_TREE = "6c45e60db0995416a5bbe5977657a78d5084dcf7"
SOURCE_TREE_SHA256 = "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c"
SOURCE_RECEIPT_SHA256 = "7755ce29a5450b9803f46effb6f42fe7624e39b317c99546eb74624a3380b83b"
ORACLE_SOURCE_PATH = Path("src/it/java/org/owasp/webgoat/integration/IDORIntegrationTest.java")
IMPLEMENTATION_SOURCE_PATH = Path("src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java")
EXPECTED_RULE_ID = "API_IDOR_ROUTE_PARAM_LOOKUP"
EXPECTED_SUBTYPE = "java_spring_cross_account_write_observe"
EXPECTED_SEVERITY = "high"
EXPECTED_CONFIDENCE = "medium"
EXPECTED_ARTIFACT_SCOPE = "runtime_source"
POSITIVE_EXECUTION_RECEIPT_SHA256 = "3d1e162931ec875f1b9de8564ff08733677e7125347eb559c91318c67e86a874"
NEGATIVE_CONTROL_RECEIPT_SHA256 = "baee6c365c87526a5a7b00717c14616e7497eb55f804a9a0fdf9fe36160bddaa"
ORACLE_ROUTE_LINE = 97
IMPLEMENTATION_ROUTE_LINE = 40
EXPECTED_FINDING_LINE = 53
EXPECTED_LINE_HASH = "03baf357e91b1c5d"
ORACLE_ROUTE_MARKER = '.put(webGoatUrlConfig.url("IDOR/profile/2342388"))'
IMPLEMENTATION_ROUTE_MARKER = '@PutMapping(path = "/IDOR/profile/{userId}"'
ROUTE_MAPPING_KIND = "upstream-integration-put-to-spring-path-variable"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LINE_HASH_RE = re.compile(r"\bline_hash=([0-9a-f]{16})\b")
ADMISSION_BLOCKERS = (
    "evidence_signature_missing",
    "independent_upstream_fixed_revision_missing",
    "source_bound_severity_rubric_missing",
)


class ObservationError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _load_runtime_contract() -> Any:
    path = Path(__file__).with_name("replay_l2_webgoat_idor.py")
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location("k_guard_l2_webgoat_idor_runtime_contract", path)
    if spec is None or spec.loader is None:
        raise ObservationError("runtime_contract_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    if path.read_bytes() != raw_before:
        raise ObservationError("runtime_contract_changed_while_loading")
    return module


def _load_canonical_receipt(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ObservationError(f"{label}_unreadable") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ObservationError(f"{label}_not_canonical")
    return payload, sha256_bytes(raw)


def _positive_reference(path: Path, runtime: Any) -> dict[str, str | bool]:
    payload, receipt_sha256 = _load_canonical_receipt(path, label="positive_execution_receipt")
    try:
        runtime.validate_receipt(payload)
    except Exception as exc:
        raise ObservationError("positive_execution_receipt_invalid") from exc
    if (
        receipt_sha256 != POSITIVE_EXECUTION_RECEIPT_SHA256
        or runtime.POSITIVE_EXECUTION_RECEIPT_SHA256 != POSITIVE_EXECUTION_RECEIPT_SHA256
        or payload.get("execution_contract_status") != "EXECUTION_CONTRACT_PASS"
    ):
        raise ObservationError("positive_execution_receipt_not_pinned_pass")
    source = payload.get("source")
    if not isinstance(source, dict):
        raise ObservationError("positive_execution_source_invalid")
    source_receipt_sha256 = source.get("source_receipt_sha256")
    if not isinstance(source_receipt_sha256, str) or SHA256_RE.fullmatch(source_receipt_sha256) is None:
        raise ObservationError("positive_execution_source_invalid")
    if source_receipt_sha256 != SOURCE_RECEIPT_SHA256:
        raise ObservationError("positive_execution_source_not_pinned")
    return {
        "positive_execution_receipt_sha256": receipt_sha256,
        "source_receipt_sha256": source_receipt_sha256,
        "raw_returned": False,
    }


def _negative_reference(path: Path, runtime: Any, positive: dict[str, str | bool]) -> dict[str, str | bool]:
    payload, receipt_sha256 = _load_canonical_receipt(path, label="negative_control_receipt")
    try:
        runtime.validate_negative_control_receipt(payload)
    except Exception as exc:
        raise ObservationError("negative_control_receipt_invalid") from exc
    positive_reference = payload.get("positive_execution_contract")
    source = payload.get("source")
    if (
        payload.get("negative_control_status") != "NEGATIVE_CONTROL_PASS"
        or receipt_sha256 != NEGATIVE_CONTROL_RECEIPT_SHA256
        or not isinstance(positive_reference, dict)
        or positive_reference.get("receipt_sha256") != positive["positive_execution_receipt_sha256"]
        or not isinstance(source, dict)
        or source.get("source_receipt_sha256") != positive["source_receipt_sha256"]
    ):
        raise ObservationError("negative_control_receipt_not_bound_to_positive")
    return {
        **positive,
        "negative_control_receipt_sha256": receipt_sha256,
        "both_statuses_passed": True,
        "raw_returned": False,
    }


def _bound_source_file(source_root: Path, relative: Path, *, label: str) -> tuple[str, bytes]:
    if relative.is_absolute() or ".." in relative.parts:
        raise ObservationError(f"{label}_path_invalid")
    root = source_root.resolve(strict=True)
    path = (root / relative).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ObservationError(f"{label}_path_escape") from exc
    if path.is_symlink() or not path.is_file():
        raise ObservationError(f"{label}_missing")
    try:
        raw = path.read_bytes()
        return raw.decode("utf-8"), raw
    except UnicodeDecodeError as exc:
        raise ObservationError(f"{label}_not_utf8") from exc


def _line_number(text: str, marker: str, *, label: str) -> int:
    index = text.find(marker)
    if index < 0:
        raise ObservationError(f"{label}_marker_missing")
    return text.count("\n", 0, index) + 1


def _source_mapping(source_root: Path) -> tuple[dict[str, Any], str]:
    oracle_text, oracle_raw = _bound_source_file(source_root, ORACLE_SOURCE_PATH, label="oracle_source")
    implementation_text, implementation_raw = _bound_source_file(
        source_root,
        IMPLEMENTATION_SOURCE_PATH,
        label="implementation_source",
    )
    mapping = {
        "oracle_source": {
            "path": ORACLE_SOURCE_PATH.as_posix(),
            "content_sha256": sha256_bytes(oracle_raw),
            "line": _line_number(oracle_text, ORACLE_ROUTE_MARKER, label="oracle_route"),
        },
        "implementation_source": {
            "path": IMPLEMENTATION_SOURCE_PATH.as_posix(),
            "content_sha256": sha256_bytes(implementation_raw),
            "line": _line_number(implementation_text, IMPLEMENTATION_ROUTE_MARKER, label="implementation_route"),
        },
        "mapping_kind": ROUTE_MAPPING_KIND,
        "raw_returned": False,
    }
    if (
        mapping["oracle_source"]["line"] != ORACLE_ROUTE_LINE
        or mapping["implementation_source"]["line"] != IMPLEMENTATION_ROUTE_LINE
    ):
        raise ObservationError("route_mapping_line_changed")
    return mapping, implementation_text


def _finding_projection(implementation_text: str) -> dict[str, Any]:
    findings = KGuardScanner().scan_text(implementation_text, IMPLEMENTATION_SOURCE_PATH.as_posix()).findings
    matching = [finding for finding in findings if finding.rule_id == EXPECTED_RULE_ID]
    if len(matching) != 1:
        raise ObservationError("expected_scanner_finding_count_invalid")
    finding = matching[0]
    subtype_match = re.search(r"\bdetector_subtype=([a-z0-9_]+)\b", finding.evidence)
    line_hash_match = LINE_HASH_RE.search(finding.evidence)
    if (
        subtype_match is None
        or line_hash_match is None
        or subtype_match.group(1) != EXPECTED_SUBTYPE
        or finding.severity != EXPECTED_SEVERITY
        or finding.confidence != EXPECTED_CONFIDENCE
        or finding.artifact_scope != EXPECTED_ARTIFACT_SCOPE
        or finding.line_start is None
        or finding.line_end != finding.line_start
        or finding.line_start != EXPECTED_FINDING_LINE
        or line_hash_match.group(1) != EXPECTED_LINE_HASH
    ):
        raise ObservationError("expected_scanner_finding_shape_invalid")
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "detector_subtype": subtype_match.group(1),
        "artifact_scope": finding.artifact_scope,
        "implementation_path": IMPLEMENTATION_SOURCE_PATH.as_posix(),
        "line": finding.line_start,
        "line_hash": line_hash_match.group(1),
        "raw_returned": False,
    }


def _claim_boundary() -> dict[str, bool]:
    return {
        "source_bound_scanner_mapping_proven": True,
        "scanner_accuracy_proven": False,
        "severity_or_cwe_admitted": False,
        "tp_fp_fn_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _tool_provenance(runtime: Any) -> dict[str, Any]:
    scanner_path = Path(__file__).parents[1] / "src" / "k_guard_mcp" / "scanner.py"
    polyglot_path = Path(__file__).parents[1] / "src" / "k_guard_mcp" / "detectors" / "polyglot.py"
    return {
        "observer_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "runtime_contract_sha256": sha256_bytes(Path(runtime.__file__).read_bytes()),
        "scanner_sha256": sha256_bytes(scanner_path.read_bytes()),
        "polyglot_detector_sha256": sha256_bytes(polyglot_path.read_bytes()),
        "raw_returned": False,
    }


def observe_mapping(
    source_root: Path,
    *,
    positive_receipt_path: Path,
    negative_receipt_path: Path,
) -> dict[str, Any]:
    runtime = _load_runtime_contract()
    provenance = _tool_provenance(runtime)
    source: dict[str, Any] | None = None
    execution_pair: dict[str, Any] | None = None
    mapping: dict[str, Any] | None = None
    runs: list[dict[str, Any]] = []
    failure_code: str | None = None
    try:
        source, _verifier, _verifier_sha256 = runtime.verify_source_workspace(source_root.resolve(strict=True))
        if source.get("repository_id") != REPOSITORY_ID or source.get("commit") != SOURCE_COMMIT or source.get("commit_tree") != SOURCE_TREE or source.get("source_tree_sha256") != SOURCE_TREE_SHA256 or source.get("source_receipt_sha256") != SOURCE_RECEIPT_SHA256:
            raise ObservationError("source_identity_mismatch")
        positive = _positive_reference(positive_receipt_path, runtime)
        execution_pair = _negative_reference(negative_receipt_path, runtime, positive)
        if source.get("source_receipt_sha256") != execution_pair["source_receipt_sha256"]:
            raise ObservationError("execution_pair_source_receipt_mismatch")
        mapping, implementation_text = _source_mapping(source_root)
        runs = [_finding_projection(implementation_text) for _ in range(2)]
    except (ObservationError, RuntimeError, OSError, ValueError) as exc:
        failure_code = str(exc)
    passed = (
        failure_code is None
        and source is not None
        and execution_pair is not None
        and mapping is not None
        and len(runs) == 2
        and runs[0] == runs[1]
    )
    receipt = {
        "schema": SCHEMA,
        "tool_provenance": provenance,
        "source": source,
        "execution_pair": execution_pair,
        "mapping": mapping,
        "runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": len(runs) == 2 and runs[0] == runs[1],
            "projection_sha256": _canonical_sha256(runs) if runs else None,
            "raw_returned": False,
        },
        "claim_boundary": _claim_boundary(),
        "admission_blockers": list(ADMISSION_BLOCKERS),
        "mapping_status": STATUS_PASS if passed else STATUS_HOLD,
        "release_gate_passed": False,
        "failure_code": failure_code,
        "raw_returned": False,
    }
    validate_receipt(receipt)
    return receipt


def _require_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ObservationError(f"{label}_invalid")
    return value


def _validate_source(value: Any, *, allow_none: bool) -> None:
    if value is None and allow_none:
        return
    required = {
        "repository_id", "commit", "commit_tree", "source_tree_sha256", "source_receipt_sha256",
        "file_count", "total_bytes", "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ObservationError("source_projection_invalid")
    if (
        value.get("repository_id") != REPOSITORY_ID
        or value.get("commit") != SOURCE_COMMIT
        or value.get("commit_tree") != SOURCE_TREE
        or value.get("source_tree_sha256") != SOURCE_TREE_SHA256
    ):
        raise ObservationError("source_projection_identity_invalid")
    _require_sha256(value.get("source_receipt_sha256"), label="source_receipt_sha256")
    if value["source_receipt_sha256"] != SOURCE_RECEIPT_SHA256:
        raise ObservationError("source_projection_receipt_identity_invalid")
    for name in ("file_count", "total_bytes"):
        if not isinstance(value.get(name), int) or isinstance(value[name], bool) or value[name] < 1:
            raise ObservationError("source_projection_shape_invalid")


def _validate_execution_pair(value: Any, source: Any, *, allow_none: bool) -> None:
    if value is None and allow_none:
        return
    required = {
        "positive_execution_receipt_sha256", "negative_control_receipt_sha256", "source_receipt_sha256",
        "both_statuses_passed", "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("both_statuses_passed") is not True or value.get("raw_returned") is not False:
        raise ObservationError("execution_pair_invalid")
    for name in ("positive_execution_receipt_sha256", "negative_control_receipt_sha256", "source_receipt_sha256"):
        _require_sha256(value.get(name), label=name)
    if (
        value["positive_execution_receipt_sha256"] != POSITIVE_EXECUTION_RECEIPT_SHA256
        or value["negative_control_receipt_sha256"] != NEGATIVE_CONTROL_RECEIPT_SHA256
    ):
        raise ObservationError("execution_pair_receipt_identity_invalid")
    if not isinstance(source, dict) or value["source_receipt_sha256"] != source["source_receipt_sha256"]:
        raise ObservationError("execution_pair_source_binding_invalid")


def _validate_source_binding(value: Any, *, path: Path, allow_none: bool) -> None:
    if value is None and allow_none:
        return
    required = {"path", "content_sha256", "line"}
    if not isinstance(value, dict) or set(value) != required or value.get("path") != path.as_posix():
        raise ObservationError("mapping_source_binding_invalid")
    _require_sha256(value.get("content_sha256"), label="mapping_source_content_sha256")
    if not isinstance(value.get("line"), int) or isinstance(value["line"], bool) or value["line"] < 1:
        raise ObservationError("mapping_source_line_invalid")


def _validate_mapping(value: Any, *, allow_none: bool) -> None:
    if value is None and allow_none:
        return
    required = {"oracle_source", "implementation_source", "mapping_kind", "raw_returned"}
    if not isinstance(value, dict) or set(value) != required or value.get("mapping_kind") != ROUTE_MAPPING_KIND or value.get("raw_returned") is not False:
        raise ObservationError("mapping_invalid")
    _validate_source_binding(value.get("oracle_source"), path=ORACLE_SOURCE_PATH, allow_none=False)
    _validate_source_binding(value.get("implementation_source"), path=IMPLEMENTATION_SOURCE_PATH, allow_none=False)
    if (
        value["oracle_source"]["line"] != ORACLE_ROUTE_LINE
        or value["implementation_source"]["line"] != IMPLEMENTATION_ROUTE_LINE
    ):
        raise ObservationError("mapping_source_line_invalid")


def _validate_run(value: Any) -> None:
    required = {
        "rule_id", "severity", "confidence", "detector_subtype", "artifact_scope", "implementation_path",
        "line", "line_hash", "raw_returned",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ObservationError("scanner_run_shape_invalid")
    expected = {
        "rule_id": EXPECTED_RULE_ID,
        "severity": EXPECTED_SEVERITY,
        "confidence": EXPECTED_CONFIDENCE,
        "detector_subtype": EXPECTED_SUBTYPE,
        "artifact_scope": EXPECTED_ARTIFACT_SCOPE,
        "implementation_path": IMPLEMENTATION_SOURCE_PATH.as_posix(),
    }
    if any(value.get(name) != expected_value for name, expected_value in expected.items()):
        raise ObservationError("scanner_run_finding_invalid")
    if not isinstance(value.get("line"), int) or isinstance(value["line"], bool) or value["line"] < 1:
        raise ObservationError("scanner_run_line_invalid")
    if value["line"] != EXPECTED_FINDING_LINE:
        raise ObservationError("scanner_run_line_invalid")
    line_hash = value.get("line_hash")
    if line_hash != EXPECTED_LINE_HASH:
        raise ObservationError("scanner_run_line_hash_invalid")


def _validate_provenance(value: Any) -> None:
    required = {"observer_sha256", "runtime_contract_sha256", "scanner_sha256", "polyglot_detector_sha256", "raw_returned"}
    if not isinstance(value, dict) or set(value) != required or value.get("raw_returned") is not False:
        raise ObservationError("tool_provenance_invalid")
    for name in required - {"raw_returned"}:
        _require_sha256(value.get(name), label=name)


def validate_receipt(receipt: Any) -> None:
    required = {
        "schema", "tool_provenance", "source", "execution_pair", "mapping", "runs", "consensus",
        "claim_boundary", "admission_blockers", "mapping_status", "release_gate_passed", "failure_code",
        "raw_returned",
    }
    if not isinstance(receipt, dict) or set(receipt) != required or receipt.get("schema") != SCHEMA or receipt.get("raw_returned") is not False:
        raise ObservationError("receipt_schema_invalid")
    if receipt.get("claim_boundary") != _claim_boundary() or receipt.get("release_gate_passed") is not False:
        raise ObservationError("receipt_claim_boundary_invalid")
    if receipt.get("admission_blockers") != list(ADMISSION_BLOCKERS):
        raise ObservationError("receipt_admission_blockers_invalid")
    _validate_provenance(receipt.get("tool_provenance"))
    status = receipt.get("mapping_status")
    if status not in {STATUS_PASS, STATUS_HOLD}:
        raise ObservationError("receipt_status_invalid")
    holding = status == STATUS_HOLD
    _validate_source(receipt.get("source"), allow_none=holding)
    _validate_execution_pair(receipt.get("execution_pair"), receipt.get("source"), allow_none=holding)
    _validate_mapping(receipt.get("mapping"), allow_none=holding)
    runs = receipt.get("runs")
    consensus = receipt.get("consensus")
    if not isinstance(runs, list) or not isinstance(consensus, dict):
        raise ObservationError("receipt_runs_invalid")
    for run in runs:
        _validate_run(run)
    expected_equal = len(runs) == 2 and runs[0] == runs[1]
    expected_consensus = {
        "run_count": len(runs),
        "two_runs_byte_equivalent_after_normalization": expected_equal,
        "projection_sha256": _canonical_sha256(runs) if runs else None,
        "raw_returned": False,
    }
    if consensus != expected_consensus:
        raise ObservationError("receipt_consensus_invalid")
    if status == STATUS_PASS:
        if receipt.get("failure_code") is not None or not expected_equal:
            raise ObservationError("receipt_pass_without_complete_evidence")
    elif receipt.get("failure_code") is None:
        raise ObservationError("receipt_hold_without_failure")


def write_new_output(path: Path, receipt: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite scanner mapping receipt: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as temporary:
        temporary.write(canonical_json_bytes(receipt))
        temporary_path = Path(temporary.name)
    try:
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind one WebGoat IDOR scanner observation to source and execution receipts.")
    commands = parser.add_subparsers(dest="command", required=True)
    observe = commands.add_parser("observe")
    observe.add_argument("--source-root", type=Path, required=True)
    observe.add_argument("--positive-receipt", type=Path, required=True)
    observe.add_argument("--negative-receipt", type=Path, required=True)
    observe.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "verify":
        payload, _digest = _load_canonical_receipt(args.receipt, label="receipt")
        validate_receipt(payload)
        print(json.dumps({"status": payload["mapping_status"], "raw_returned": False}, sort_keys=True))
        return 0 if payload["mapping_status"] == STATUS_PASS else 2
    receipt = observe_mapping(
        args.source_root,
        positive_receipt_path=args.positive_receipt,
        negative_receipt_path=args.negative_receipt,
    )
    write_new_output(args.output, receipt)
    print(json.dumps({"status": receipt["mapping_status"], "raw_returned": False}, sort_keys=True))
    return 0 if receipt["mapping_status"] == STATUS_PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
