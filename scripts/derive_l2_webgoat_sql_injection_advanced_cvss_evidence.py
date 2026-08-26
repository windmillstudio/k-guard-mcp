from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "k_guard_l2_webgoat_sql_injection_advanced_cvss_evidence.v1"
CWE_EVIDENCE_SCHEMA = "k_guard_l2_webgoat_sql_injection_advanced_cwe_evidence.v1"
EXECUTION_EVIDENCE_SCHEMA = "k_guard_l2_webgoat_sql_injection_advanced_execution_evidence.v1"
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
SCORE = "7.1"
SEVERITY = "high"
EXPECTED_DISPOSITION = "warn"
SHA256_LENGTH = 64
EXPECTED_CALCULATOR_ID = "FIRST-CVSS-v4.0-c5b0d409"
EXPECTED_ROOT_CAUSE = (
    "upstream-test:org.owasp.webgoat.integration.SqlInjectionAdvancedIntegrationTest#runTests"
)
EXPECTED_SOURCE_PATH = (
    "src/it/java/org/owasp/webgoat/integration/SqlInjectionAdvancedIntegrationTest.java"
)
EXPECTED_SCENARIO_PREFIX = (
    "webgoat:upstream-test-org-owasp-webgoat-integration-"
    "sqlinjectionadvancedintegrationtest-runtests:"
)
ADMISSION_BLOCKERS = ["registry_evidence_integration_missing"]


class CvssEvidenceError(RuntimeError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA256_LENGTH and all(char in "0123456789abcdef" for char in value)


def _load_canonical(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.resolve(strict=True).read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CvssEvidenceError(f"{label}_unreadable") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise CvssEvidenceError(f"{label}_not_canonical")
    return payload, raw


def _load_module(filename: str, name: str) -> tuple[Any, str]:
    path = Path(__file__).resolve(strict=True).with_name(filename)
    raw = path.read_bytes()
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise CvssEvidenceError("supporting_adapter_load_failed")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - standalone protection.
        raise CvssEvidenceError("supporting_adapter_load_failed") from exc
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    if path.read_bytes() != raw:
        raise CvssEvidenceError("supporting_adapter_changed_while_loading")
    return module, sha256_bytes(raw)


def _load_cwe_adapter() -> tuple[Any, str]:
    return _load_module("derive_l2_webgoat_sql_injection_advanced_cwe_evidence.py", "k_guard_l2_webgoat_sql_injection_advanced_cvss_cwe")


def _load_execution_adapter() -> tuple[Any, str]:
    return _load_module("derive_l2_webgoat_sql_injection_advanced_execution_evidence.py", "k_guard_l2_webgoat_sql_injection_advanced_cvss_execution")


def _load_registry_contract() -> tuple[Any, str]:
    return _load_module("materialize_l2_oracles.py", "k_guard_l2_webgoat_sql_injection_advanced_cvss_registry")


def _load_cwe_evidence(path: Path) -> tuple[dict[str, Any], str, str]:
    payload, raw = _load_canonical(path, label="cwe_evidence")
    adapter, adapter_sha256 = _load_cwe_adapter()
    try:
        adapter.validate_cwe_evidence(payload)
    except Exception as exc:
        raise CvssEvidenceError("cwe_evidence_contract_invalid") from exc
    provenance = payload.get("tool_provenance")
    if not isinstance(provenance, dict) or provenance.get("adapter_sha256") != adapter_sha256:
        raise CvssEvidenceError("cwe_evidence_tool_provenance_not_current")
    classification = payload.get("classification")
    boundary = payload.get("claim_boundary")
    if (
        not isinstance(classification, dict)
        or classification.get("cwe", {}).get("id") != "CWE-89"
        or classification.get("mechanism_truth") != "present"
        or classification.get("cvss_v4") is not None
        or classification.get("expected_disposition") is not None
        or not isinstance(boundary, dict)
        or boundary.get("source_bound_cwe_mapping_supported") is not True
        or boundary.get("source_bound_cvss_profile_proven") is not False
        or boundary.get("customer_deployment_severity_admitted") is not False
    ):
        raise CvssEvidenceError("cwe_evidence_claim_boundary_invalid")
    return payload, sha256_bytes(raw), adapter_sha256


def _load_execution_evidence(path: Path) -> tuple[dict[str, Any], str, str]:
    payload, raw = _load_canonical(path, label="execution_evidence")
    adapter, adapter_sha256 = _load_execution_adapter()
    try:
        adapter.validate_execution_evidence(payload)
    except Exception as exc:
        raise CvssEvidenceError("execution_evidence_contract_invalid") from exc
    provenance = payload.get("tool_provenance")
    if not isinstance(provenance, dict) or provenance.get("adapter_sha256") != adapter_sha256:
        raise CvssEvidenceError("execution_evidence_tool_provenance_not_current")
    boundary = payload.get("claim_boundary")
    if (
        not isinstance(boundary, dict)
        or boundary.get("execution_result_pair_proven") is not True
        or boundary.get("source_bound_execution_selector_proven") is not True
        or boundary.get("severity_or_cwe_admitted") is not False
        or boundary.get("registry_evidence_integrated") is not False
        or boundary.get("release_gate_admitted") is not False
    ):
        raise CvssEvidenceError("execution_evidence_claim_boundary_invalid")
    return payload, sha256_bytes(raw), adapter_sha256


def _same_selector(cwe: dict[str, Any], execution: dict[str, Any]) -> dict[str, Any]:
    cwe_source = cwe.get("source")
    execution_source = execution.get("source")
    if not isinstance(cwe_source, dict) or not isinstance(execution_source, dict):
        raise CvssEvidenceError("source_selector_missing")
    selector = cwe_source.get("selector")
    if selector != execution_source.get("selector") or not isinstance(selector, dict):
        raise CvssEvidenceError("source_selector_mismatch")
    return dict(selector)


def _selector_is_valid(selector: Any) -> bool:
    required = {
        "root_cause",
        "source_path",
        "source_line",
        "source_content_sha256",
        "source_root_cause_identity",
        "scenario_id",
        "raw_returned",
    }
    return (
        isinstance(selector, dict)
        and set(selector) == required
        and selector.get("root_cause") == EXPECTED_ROOT_CAUSE
        and selector.get("source_path") == EXPECTED_SOURCE_PATH
        and isinstance(selector.get("source_line"), int)
        and selector["source_line"] > 0
        and _is_sha256(selector.get("source_content_sha256"))
        and _is_sha256(selector.get("source_root_cause_identity"))
        and isinstance(selector.get("scenario_id"), str)
        and selector["scenario_id"].startswith(EXPECTED_SCENARIO_PREFIX)
        and selector.get("raw_returned") is False
    )


def _calculator_provenance(calculator_root: Path, calculator_receipt: Path) -> tuple[dict[str, Any], str]:
    registry, registry_sha256 = _load_registry_contract()
    try:
        calculator = registry._verify_calculator_source(calculator_root, calculator_receipt)
    except Exception as exc:
        raise CvssEvidenceError("calculator_source_contract_invalid") from exc
    binding = sha256_bytes(registry.canonical_json_bytes(calculator))
    if (
        calculator.get("id") != EXPECTED_CALCULATOR_ID
        or calculator.get("pin_verified") is not True
        or not _is_sha256(calculator.get("source_receipt_sha256"))
        or not _is_sha256(binding)
    ):
        raise CvssEvidenceError("calculator_binding_missing")
    calculator = {**calculator, "binding_sha256": binding}
    return calculator, registry_sha256


def _calculate_score(calculator_root: Path) -> str:
    runner = r'''
const fs = require("fs");
const vm = require("vm");
const root = process.argv[1];
for (const name of ["cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js"]) {
  vm.runInThisContext(fs.readFileSync(`${root}/${name}`, "utf8"), {filename: name});
}
const values = {AV:"N",AC:"L",AT:"N",PR:"L",UI:"N",VC:"H",VI:"N",VA:"N",SC:"N",SI:"N",SA:"N"};
for (const metric of "E CR IR AR MAV MAC MAT MPR MUI MVC MVI MVA MSC MSI MSA S AU R V RE U".split(" ")) values[metric] = "X";
const macro = macroVector(values);
process.stdout.write(JSON.stringify({macro, score:cvss_score(values, cvssLookup_global, maxSeverity, macro)}));
'''
    try:
        result = subprocess.run(
            ["node", "-e", runner, str(calculator_root.resolve(strict=True))],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CvssEvidenceError("calculator_execution_failed") from exc
    if result.returncode != 0 or result.stderr or len(result.stdout) > 256:
        raise CvssEvidenceError("calculator_execution_failed")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CvssEvidenceError("calculator_output_invalid") from exc
    if not isinstance(value, dict) or value.get("score") != 7.1 or value.get("macro") != "101200":
        raise CvssEvidenceError("calculator_score_mismatch")
    return SCORE


def _metric_evidence() -> dict[str, str]:
    return {
        "AV": "network_http_stateful_session_endpoint",
        "AC": "deterministic_source_bound_sql_injection_test",
        "AT": "no_preexisting_attack_condition_in_pinned_scenario",
        "PR": "authenticated_low_privilege_session_cookie",
        "UI": "no_victim_interaction_in_pinned_test",
        "VC": "database_query_returns_sensitive_user_system_data",
        "VI": "no_integrity_impact_in_pinned_test",
        "VA": "no_availability_impact_in_pinned_test",
        "SC_SI_SA": "no_subsequent_system_impact_in_pinned_test",
    }


def _cvss_profile(calculator: dict[str, Any], score: str) -> dict[str, Any]:
    return {
        "scope": "pinned_webgoat_benchmark_scenario",
        "vector": VECTOR,
        "score": score,
        "severity": SEVERITY,
        "expected_disposition": EXPECTED_DISPOSITION,
        "metric_evidence": _metric_evidence(),
        "calculator": {
            "id": calculator["id"],
            "binding_sha256": calculator["binding_sha256"],
            "source_receipt_sha256": calculator["source_receipt_sha256"],
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _claim_boundary() -> dict[str, bool]:
    return {
        "benchmark_cvss_profile_proven": True,
        "customer_deployment_severity_admitted": False,
        "registry_evidence_integrated": False,
        "scanner_accuracy_proven": False,
        "tp_fp_fn_admitted": False,
        "l2_gate_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def derive_cvss_evidence(
    cwe_evidence_path: Path,
    execution_evidence_path: Path,
    calculator_root: Path,
    calculator_receipt_path: Path,
) -> dict[str, Any]:
    cwe, cwe_sha256, cwe_adapter_sha256 = _load_cwe_evidence(cwe_evidence_path)
    execution, execution_sha256, execution_adapter_sha256 = _load_execution_evidence(execution_evidence_path)
    selector = _same_selector(cwe, execution)
    calculator, registry_contract_sha256 = _calculator_provenance(calculator_root, calculator_receipt_path)
    score = _calculate_score(calculator_root)
    if score != SCORE:
        raise CvssEvidenceError("calculator_score_mismatch")
    payload = {
        "schema": SCHEMA,
        "tool_provenance": {
            "adapter_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "registry_contract_sha256": registry_contract_sha256,
            "raw_returned": False,
        },
        "source": {
            "selector": selector,
            "cwe_evidence_sha256": cwe_sha256,
            "cwe_adapter_sha256": cwe_adapter_sha256,
            "execution_evidence_sha256": execution_sha256,
            "execution_adapter_sha256": execution_adapter_sha256,
            "raw_returned": False,
        },
        "cvss_profile": _cvss_profile(calculator, score),
        "claim_boundary": _claim_boundary(),
        "admission_blockers": ADMISSION_BLOCKERS,
        "adapter_status": "CVSS_PROFILE_EVIDENCE_PASS",
        "release_gate_passed": False,
        "raw_returned": False,
    }
    validate_cvss_evidence(payload)
    return payload


def validate_cvss_evidence(payload: dict[str, Any]) -> None:
    required = {"schema", "tool_provenance", "source", "cvss_profile", "claim_boundary", "admission_blockers", "adapter_status", "release_gate_passed", "raw_returned"}
    if set(payload) != required or payload.get("schema") != SCHEMA or payload.get("raw_returned") is not False:
        raise CvssEvidenceError("cvss_evidence_schema_invalid")
    provenance = payload.get("tool_provenance")
    if not isinstance(provenance, dict) or set(provenance) != {"adapter_sha256", "registry_contract_sha256", "raw_returned"} or provenance.get("adapter_sha256") != sha256_bytes(Path(__file__).read_bytes()) or not _is_sha256(provenance.get("registry_contract_sha256")) or provenance.get("raw_returned") is not False:
        raise CvssEvidenceError("cvss_evidence_provenance_invalid")
    source = payload.get("source")
    required_source = {"selector", "cwe_evidence_sha256", "cwe_adapter_sha256", "execution_evidence_sha256", "execution_adapter_sha256", "raw_returned"}
    if not isinstance(source, dict) or set(source) != required_source or source.get("raw_returned") is not False or not _selector_is_valid(source.get("selector")) or any(not _is_sha256(source.get(key)) for key in required_source - {"selector", "raw_returned"}):
        raise CvssEvidenceError("cvss_evidence_source_invalid")
    profile = payload.get("cvss_profile")
    required_profile = {"scope", "vector", "score", "severity", "expected_disposition", "metric_evidence", "calculator", "raw_returned"}
    if not isinstance(profile, dict) or set(profile) != required_profile or profile.get("scope") != "pinned_webgoat_benchmark_scenario" or profile.get("vector") != VECTOR or profile.get("score") != SCORE or profile.get("severity") != SEVERITY or profile.get("expected_disposition") != EXPECTED_DISPOSITION or profile.get("metric_evidence") != _metric_evidence() or profile.get("raw_returned") is not False:
        raise CvssEvidenceError("cvss_evidence_profile_invalid")
    calculator = profile.get("calculator")
    if not isinstance(calculator, dict) or set(calculator) != {"id", "binding_sha256", "source_receipt_sha256", "raw_returned"} or calculator.get("id") != EXPECTED_CALCULATOR_ID or not _is_sha256(calculator.get("binding_sha256")) or not _is_sha256(calculator.get("source_receipt_sha256")) or calculator.get("raw_returned") is not False:
        raise CvssEvidenceError("cvss_evidence_calculator_invalid")
    if payload.get("claim_boundary") != _claim_boundary() or payload.get("admission_blockers") != ADMISSION_BLOCKERS or payload.get("adapter_status") != "CVSS_PROFILE_EVIDENCE_PASS" or payload.get("release_gate_passed") is not False:
        raise CvssEvidenceError("cvss_evidence_claim_boundary_invalid")


def write_new_output(path: Path, payload: dict[str, Any]) -> Path:
    output = path.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite CVSS evidence: {output}")
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
            raise FileExistsError(f"refusing to overwrite CVSS evidence: {output}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Derive source-bound WebGoat SQL Injection Advanced benchmark CVSS evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)
    derive = subparsers.add_parser("derive")
    derive.add_argument("--cwe-evidence", type=Path, required=True)
    derive.add_argument("--execution-evidence", type=Path, required=True)
    derive.add_argument("--calculator-root", type=Path, required=True)
    derive.add_argument("--calculator-receipt", type=Path, required=True)
    derive.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(list(argv) if argv is not None else None)
    if args.command == "derive":
        payload = derive_cvss_evidence(args.cwe_evidence, args.execution_evidence, args.calculator_root, args.calculator_receipt)
        output = write_new_output(args.output, payload)
    else:
        payload, _raw = _load_canonical(args.evidence, label="evidence")
        validate_cvss_evidence(payload)
        output = args.evidence.resolve(strict=True)
    print(json.dumps({"adapter_status": payload["adapter_status"], "evidence_path": str(output.resolve(strict=True)), "evidence_sha256": sha256_bytes(output.read_bytes()), "release_gate_passed": False}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
