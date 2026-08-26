from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from k_guard_mcp import scanner as scanner_module
from k_guard_mcp.detectors import polyglot as polyglot_module


SCHEMA = "k_guard_l2_webgoat_missing_function_ac_scanner_differential.v1"
STATUS_PASS = "SCANNER_DIFFERENTIAL_PASS"
STATUS_HOLD = "HOLD"
APP_ID = "webgoat"
EXPECTED_RULE_ID = "API_PRIVILEGED_FIELD_MASS_ASSIGNMENT"
EXPECTED_SUBTYPE = "java_spring_privileged_field_mass_assignment_observe"
EXPECTED_SEVERITY = "high"
EXPECTED_CONFIDENCE = "medium"
EXPECTED_ARTIFACT_SCOPE = "runtime_source"
IMPLEMENTATION_PATH = Path(
    "src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java"
)
PERSISTENCE_MARKER = b"userRepository.save(newUser);"
BASELINE_VARIANT = "privileged_body_persistence_observer_disabled.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
LINE_HASH_RE = re.compile(r"\bline_hash=([0-9a-f]{16})\b")


class DifferentialError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _load_script(path: Path, *, module_name: str) -> tuple[Any, str]:
    raw_before = path.read_bytes()
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise DifferentialError(f"{module_name}_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    if path.read_bytes() != raw_before:
        sys.modules.pop(module_name, None)
        raise DifferentialError(f"{module_name}_changed_while_loading")
    return module, sha256_bytes(raw_before)


def _load_contracts() -> tuple[Any, str, Any, str, Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    runtime, runtime_sha256 = _load_script(
        directory / "replay_l2_webgoat_missing_function_ac.py",
        module_name="k_guard_l2_missing_function_ac_runtime",
    )
    execution, execution_sha256 = _load_script(
        directory / "derive_l2_webgoat_missing_function_ac_execution_evidence.py",
        module_name="k_guard_l2_missing_function_ac_execution_evidence",
    )
    cwe, cwe_sha256 = _load_script(
        directory / "derive_l2_webgoat_missing_function_ac_cwe_evidence.py",
        module_name="k_guard_l2_missing_function_ac_cwe_evidence",
    )
    return runtime, runtime_sha256, execution, execution_sha256, cwe, cwe_sha256


def _load_canonical(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.resolve(strict=True).read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DifferentialError(f"{label}_unreadable") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise DifferentialError(f"{label}_not_canonical")
    return value, raw


def _git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise DifferentialError("source_git_unavailable") from exc
    if result.returncode != 0:
        raise DifferentialError("source_git_command_failed")
    try:
        return result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise DifferentialError("source_git_output_invalid") from exc


def _source_binding(
    source_root: Path,
    *,
    execution_evidence_path: Path,
    cwe_evidence_path: Path,
    execution: Any,
    cwe: Any,
) -> tuple[dict[str, Any], dict[str, Any], bytes, dict[str, Any]]:
    execution_payload, execution_raw = _load_canonical(
        execution_evidence_path, label="execution_evidence"
    )
    cwe_payload, cwe_raw = _load_canonical(cwe_evidence_path, label="cwe_evidence")
    execution.validate_execution_evidence(execution_payload)
    cwe.validate_cwe_evidence(cwe_payload)

    execution_source = execution_payload.get("source")
    cwe_source = cwe_payload.get("source")
    if not isinstance(execution_source, dict) or execution_source != cwe_source:
        raise DifferentialError("source_evidence_identity_mismatch")
    source = execution_source
    expected_identity = {
        "app_id": APP_ID,
        "repository_id": "webgoat/webgoat",
        "commit": "5142935bf7c279882c3b0fc0ecec42c447de6fd5",
        "commit_tree": "6c45e60db0995416a5bbe5977657a78d5084dcf7",
        "source_tree_sha256": "0b2193e30038f4366715986e939645d7851e647c6188b992311639dd7564da3c",
    }
    if any(source.get(name) != value for name, value in expected_identity.items()):
        raise DifferentialError("source_evidence_identity_invalid")
    for name in ("source_receipt_sha256", "source_receipt_semantic_sha256", "lineage_id"):
        if not isinstance(source.get(name), str) or SHA256_RE.fullmatch(source[name]) is None:
            raise DifferentialError("source_evidence_hash_invalid")

    root = source_root.resolve(strict=True)
    try:
        discovered_root = Path(_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exc:
        raise DifferentialError("source_root_not_repository_root") from exc
    if discovered_root != root:
        raise DifferentialError("source_root_not_repository_root")
    if _git(root, "rev-parse", "HEAD") != source["commit"]:
        raise DifferentialError("source_commit_mismatch")
    if _git(root, "rev-parse", "HEAD^{tree}") != source["commit_tree"]:
        raise DifferentialError("source_tree_mismatch")

    source_evidence = cwe_payload.get("classification", {}).get("source_evidence")
    if not isinstance(source_evidence, dict):
        raise DifferentialError("cwe_source_evidence_missing")
    implementation = source_evidence.get("implementation")
    if not isinstance(implementation, dict) or implementation.get("path") != IMPLEMENTATION_PATH.as_posix():
        raise DifferentialError("implementation_evidence_invalid")
    expected_sha256 = implementation.get("content_sha256")
    if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
        raise DifferentialError("implementation_hash_invalid")
    implementation_path = root / IMPLEMENTATION_PATH
    try:
        implementation_raw = implementation_path.read_bytes()
    except OSError as exc:
        raise DifferentialError("implementation_source_unreadable") from exc
    if sha256_bytes(implementation_raw) != expected_sha256 or implementation_raw.count(PERSISTENCE_MARKER) != 1:
        raise DifferentialError("implementation_source_not_bound")

    persistence_line = implementation_raw.count(b"\n", 0, implementation_raw.index(PERSISTENCE_MARKER)) + 1
    projection = {
        "app_id": APP_ID,
        "repository_id": source["repository_id"],
        "commit": source["commit"],
        "commit_tree": source["commit_tree"],
        "source_tree_sha256": source["source_tree_sha256"],
        "source_receipt_sha256": source["source_receipt_sha256"],
        "source_receipt_semantic_sha256": source["source_receipt_semantic_sha256"],
        "lineage_id": source["lineage_id"],
        "scenario_id": source["selector"]["scenario_id"],
        "implementation_path": IMPLEMENTATION_PATH.as_posix(),
        "implementation_sha256": expected_sha256,
        "persistence_line": persistence_line,
        "raw_returned": False,
    }
    evidence = {
        "execution_evidence_sha256": sha256_bytes(execution_raw),
        "cwe_evidence_sha256": sha256_bytes(cwe_raw),
        "positive_execution_receipt_sha256": execution_payload["execution_pair"][
            "positive_execution_receipt_sha256"
        ],
        "negative_control_receipt_sha256": execution_payload["execution_pair"][
            "negative_control_receipt_sha256"
        ],
        "raw_returned": False,
    }
    for name in (
        "execution_evidence_sha256",
        "cwe_evidence_sha256",
        "positive_execution_receipt_sha256",
        "negative_control_receipt_sha256",
    ):
        if not isinstance(evidence[name], str) or SHA256_RE.fullmatch(evidence[name]) is None:
            raise DifferentialError("source_evidence_reference_invalid")
    return projection, evidence, implementation_raw, source


def _execution_pair(
    runtime: Any,
    *,
    positive_receipt_path: Path,
    negative_receipt_path: Path,
    evidence: dict[str, Any],
    source: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    positive, positive_raw = _load_canonical(positive_receipt_path, label="positive_execution_receipt")
    negative, negative_raw = _load_canonical(negative_receipt_path, label="negative_control_receipt")
    runtime.validate_receipt(positive)
    runtime.validate_negative_control_receipt(
        negative, positive_reference=negative.get("positive_execution_contract")
    )
    if (
        sha256_bytes(positive_raw) != evidence["positive_execution_receipt_sha256"]
        or sha256_bytes(negative_raw) != evidence["negative_control_receipt_sha256"]
    ):
        raise DifferentialError("execution_receipt_identity_mismatch")
    if positive.get("source") != negative.get("source") or positive.get("source", {}).get(
        "source_receipt_sha256"
    ) != source["source_receipt_sha256"]:
        raise DifferentialError("execution_source_binding_invalid")
    control = negative.get("negative_control")
    required = {
        "patch_id",
        "source_path",
        "original_file_sha256",
        "patched_file_sha256",
        "patch_sha256",
        "variant_tree_sha256",
        "source_checkout_mutated",
        "raw_returned",
    }
    if (
        not isinstance(control, dict)
        or set(control) != required
        or control.get("source_path") != IMPLEMENTATION_PATH.as_posix()
        or control.get("source_checkout_mutated") is not False
        or control.get("raw_returned") is not False
    ):
        raise DifferentialError("negative_control_projection_invalid")
    for name in ("original_file_sha256", "patched_file_sha256", "patch_sha256", "variant_tree_sha256"):
        if not isinstance(control.get(name), str) or SHA256_RE.fullmatch(control[name]) is None:
            raise DifferentialError("negative_control_hash_invalid")
    pair = {
        "positive_execution_receipt_sha256": sha256_bytes(positive_raw),
        "negative_control_receipt_sha256": sha256_bytes(negative_raw),
        "source_receipt_sha256": source["source_receipt_sha256"],
        "raw_returned": False,
    }
    return pair, dict(control)


def _copy_negative_variant(source_root: Path, runtime: Any) -> tuple[str, dict[str, Any]]:
    shared, _shared_sha256 = runtime._load_shared_runtime()
    verifier, _verifier_sha256 = shared._load_source_verifier()
    with tempfile.TemporaryDirectory(prefix="k-guard-l2-missing-ac-scan-") as temporary:
        variant_root = Path(temporary) / APP_ID
        shared._copy_verified_source(source_root, variant_root, verifier)
        control = runtime._apply_negative_control_patch(variant_root, verifier)
        target = variant_root / IMPLEMENTATION_PATH
        try:
            text = target.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DifferentialError("negative_variant_unreadable") from exc
    return text, control


def _pre_observer_baseline() -> dict[str, Any]:
    polyglot_path = Path(polyglot_module.__file__).resolve(strict=True)
    definition = {
        "base_candidate_polyglot_sha256": sha256_bytes(polyglot_path.read_bytes()),
        "variant": BASELINE_VARIANT,
        "override": "java_privileged_request_body_persistence_line=None",
        "raw_returned": False,
    }
    return {
        **definition,
        "counterfactual_definition_sha256": _canonical_sha256(definition),
        "raw_returned": False,
    }


def _finding_projection(text: str, path: str, *, disable_observer: bool = False) -> dict[str, Any]:
    original_detector = scanner_module.PolyglotRiskDetector
    original_observer = polyglot_module._java_privileged_request_body_persistence_line
    if disable_observer:
        polyglot_module._java_privileged_request_body_persistence_line = lambda *_args, **_kwargs: None
    try:
        findings = scanner_module.KGuardScanner().scan_text(text, path).findings
    finally:
        scanner_module.PolyglotRiskDetector = original_detector
        polyglot_module._java_privileged_request_body_persistence_line = original_observer
    relevant: list[dict[str, Any]] = []
    for finding in findings:
        if finding.rule_id != EXPECTED_RULE_ID:
            continue
        subtype = re.search(r"\bdetector_subtype=([a-z0-9_]+)\b", finding.evidence)
        line_hash = LINE_HASH_RE.search(finding.evidence)
        relevant.append(
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "detector_subtype": subtype.group(1) if subtype is not None else None,
                "artifact_scope": finding.artifact_scope,
                "path": path,
                "line": finding.line_start,
                "line_hash": line_hash.group(1) if line_hash is not None else None,
                "raw_returned": False,
            }
        )
    relevant.sort(key=canonical_json_bytes)
    return {
        "relevant_finding_count": len(relevant),
        "relevant_findings": relevant,
        "raw_returned": False,
    }


def _expected_positive(projection: dict[str, Any], *, persistence_line: int) -> bool:
    findings = projection.get("relevant_findings")
    if not isinstance(findings, list) or len(findings) != 1:
        return False
    finding = findings[0]
    return (
        isinstance(finding, dict)
        and finding.get("rule_id") == EXPECTED_RULE_ID
        and finding.get("severity") == EXPECTED_SEVERITY
        and finding.get("confidence") == EXPECTED_CONFIDENCE
        and finding.get("detector_subtype") == EXPECTED_SUBTYPE
        and finding.get("artifact_scope") == EXPECTED_ARTIFACT_SCOPE
        and finding.get("line") == persistence_line
        and isinstance(finding.get("line_hash"), str)
        and re.fullmatch(r"[0-9a-f]{16}", finding["line_hash"]) is not None
    )


def _empty_projection(projection: dict[str, Any]) -> bool:
    return projection.get("relevant_finding_count") == 0 and projection.get("relevant_findings") == []


def _pair(positive_text: str, negative_text: str, *, path: str, disable_observer: bool) -> dict[str, Any]:
    return {
        "positive_oracle": _finding_projection(positive_text, path, disable_observer=disable_observer),
        "negative_oracle": _finding_projection(negative_text, path, disable_observer=disable_observer),
        "raw_returned": False,
    }


def _candidate_outcome(pair: dict[str, Any], *, persistence_line: int) -> bool:
    return _expected_positive(pair.get("positive_oracle", {}), persistence_line=persistence_line) and _empty_projection(
        pair.get("negative_oracle", {})
    )


def _validate_prechange_baseline(
    path: Path,
    *,
    source: dict[str, Any],
    evidence: dict[str, Any],
) -> dict[str, Any]:
    baseline, raw = _load_canonical(path, label="prechange_baseline")
    required = {
        "schema",
        "target",
        "source",
        "dynamic_evidence",
        "baseline_scanner",
        "claim_boundary",
        "raw_returned",
    }
    if (
        set(baseline) != required
        or baseline.get("schema") != "k_guard_l2_webgoat_missing_function_ac_scanner_baseline.v1"
        or baseline.get("raw_returned") is not False
        or baseline.get("source", {}).get("source_receipt_sha256") != source["source_receipt_sha256"]
        or baseline.get("source", {}).get("source_receipt_semantic_sha256")
        != source["source_receipt_semantic_sha256"]
        or baseline.get("source", {}).get("implementation_sha256") != source["implementation_sha256"]
        or baseline.get("dynamic_evidence", {}).get("positive_execution_receipt_sha256")
        != evidence["positive_execution_receipt_sha256"]
        or baseline.get("dynamic_evidence", {}).get("negative_control_receipt_sha256")
        != evidence["negative_control_receipt_sha256"]
        or baseline.get("baseline_scanner", {}).get("expected_rule_id") != EXPECTED_RULE_ID
        or not _empty_projection(baseline.get("baseline_scanner", {}).get("positive_oracle", {}))
        or not _empty_projection(baseline.get("baseline_scanner", {}).get("negative_oracle", {}))
        or baseline.get("claim_boundary", {}).get("actual_prechange_baseline_recorded") is not True
    ):
        raise DifferentialError("prechange_baseline_invalid")
    target = baseline.get("target")
    if not isinstance(target, dict) or set(target) != {
        "head_git_oid",
        "dirty_path_set_sha256",
        "dirty_worktree_sha256",
    }:
        raise DifferentialError("prechange_baseline_target_invalid")
    return {
        "receipt_sha256": sha256_bytes(raw),
        "target": target,
        "scanner_sha256": baseline["baseline_scanner"]["scanner_sha256"],
        "polyglot_sha256": baseline["baseline_scanner"]["polyglot_sha256"],
        "actual_prechange_zero_findings": True,
        "raw_returned": False,
    }


def _claim_boundary() -> dict[str, bool]:
    return {
        "one_source_bound_generated_pair_only": True,
        "actual_prechange_baseline_proven": True,
        "counterfactual_baseline_is_not_shipped_history": True,
        "candidate_pair_tp_tn_proven": True,
        "product_accuracy_proven": False,
        "product_tp_fp_fn_tn_proven": False,
        "recall_or_specificity_proven": False,
        "severity_or_cwe_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _tool_provenance(
    *,
    runtime_sha256: str,
    execution_sha256: str,
    cwe_sha256: str,
    baseline: dict[str, Any],
) -> dict[str, Any]:
    root = Path(__file__).resolve(strict=True).parents[1]
    return {
        "measurement_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "runtime_contract_sha256": runtime_sha256,
        "execution_evidence_contract_sha256": execution_sha256,
        "cwe_evidence_contract_sha256": cwe_sha256,
        "scanner_sha256": sha256_bytes((root / "src" / "k_guard_mcp" / "scanner.py").read_bytes()),
        "candidate_polyglot_sha256": sha256_bytes(
            (root / "src" / "k_guard_mcp" / "detectors" / "polyglot.py").read_bytes()
        ),
        "prechange_baseline_receipt_sha256": baseline["receipt_sha256"],
        "raw_returned": False,
    }


def measure_differential(
    source_root: Path,
    *,
    execution_evidence_path: Path,
    cwe_evidence_path: Path,
    positive_receipt_path: Path,
    negative_receipt_path: Path,
    prechange_baseline_path: Path,
) -> dict[str, Any]:
    runtime, runtime_sha256, execution, execution_sha256, cwe, cwe_sha256 = _load_contracts()
    source: dict[str, Any] | None = None
    evidence: dict[str, Any] | None = None
    mapping: dict[str, Any] | None = None
    execution_pair: dict[str, Any] | None = None
    control: dict[str, Any] | None = None
    baseline: dict[str, Any] | None = None
    candidate_runs: list[dict[str, Any]] = []
    provenance: dict[str, Any] | None = None
    failure_code: str | None = None
    score: dict[str, int] | None = None
    try:
        mapping, evidence, positive_raw, source_raw = _source_binding(
            source_root,
            execution_evidence_path=execution_evidence_path,
            cwe_evidence_path=cwe_evidence_path,
            execution=execution,
            cwe=cwe,
        )
        source = {key: mapping[key] for key in (
            "app_id", "repository_id", "commit", "commit_tree", "source_tree_sha256",
            "source_receipt_sha256", "source_receipt_semantic_sha256", "lineage_id",
            "implementation_path", "implementation_sha256",
        )} | {"raw_returned": False}
        execution_pair, expected_control = _execution_pair(
            runtime,
            positive_receipt_path=positive_receipt_path,
            negative_receipt_path=negative_receipt_path,
            evidence=evidence,
            source=source,
        )
        negative_text, control = _copy_negative_variant(source_root, runtime)
        if control != expected_control:
            raise DifferentialError("negative_control_patch_not_equal_to_runtime_oracle")
        prechange = _validate_prechange_baseline(
            prechange_baseline_path, source=source, evidence=evidence
        )
        counterfactual = _pre_observer_baseline()
        baseline_pair = _pair(
            positive_raw.decode("utf-8"),
            negative_text,
            path=IMPLEMENTATION_PATH.as_posix(),
            disable_observer=True,
        )
        baseline = {
            "prechange_baseline": prechange,
            "counterfactual": counterfactual,
            "pair": baseline_pair,
            "actual_prechange_zero_findings": True,
            "counterfactual_baseline_is_not_shipped_history": True,
            "raw_returned": False,
        }
        if not _empty_projection(baseline_pair["positive_oracle"]) or not _empty_projection(
            baseline_pair["negative_oracle"]
        ):
            raise DifferentialError("counterfactual_baseline_invalid")
        candidate_runs = [
            _pair(
                positive_raw.decode("utf-8"),
                negative_text,
                path=IMPLEMENTATION_PATH.as_posix(),
                disable_observer=False,
            )
            for _ in range(2)
        ]
        if not all(_candidate_outcome(pair, persistence_line=mapping["persistence_line"]) for pair in candidate_runs):
            raise DifferentialError("candidate_pair_outcome_invalid")
        if candidate_runs[0] != candidate_runs[1]:
            raise DifferentialError("candidate_runs_not_repeatable")
        after_mapping, after_evidence, _after_raw, _after_source = _source_binding(
            source_root,
            execution_evidence_path=execution_evidence_path,
            cwe_evidence_path=cwe_evidence_path,
            execution=execution,
            cwe=cwe,
        )
        if after_mapping != mapping or after_evidence != evidence:
            raise DifferentialError("source_binding_changed_during_measurement")
        score = {"generated_pair_count": 1, "tp": 1, "fp": 0, "fn": 0, "tn": 1}
        provenance = _tool_provenance(
            runtime_sha256=runtime_sha256,
            execution_sha256=execution_sha256,
            cwe_sha256=cwe_sha256,
            baseline=prechange,
        )
    except (DifferentialError, OSError, RuntimeError, ValueError) as exc:
        failure_code = str(exc)
    passed = (
        failure_code is None
        and source is not None
        and evidence is not None
        and mapping is not None
        and execution_pair is not None
        and control is not None
        and baseline is not None
        and len(candidate_runs) == 2
        and score is not None
        and provenance is not None
    )
    receipt = {
        "schema": SCHEMA,
        "tool_provenance": provenance,
        "source": source,
        "evidence": evidence,
        "mapping": mapping,
        "execution_pair": execution_pair,
        "negative_control": control,
        "baseline": baseline,
        "candidate_runs": candidate_runs,
        "consensus": {
            "run_count": len(candidate_runs),
            "two_runs_byte_equivalent_after_normalization": len(candidate_runs) == 2 and candidate_runs[0] == candidate_runs[1],
            "projection_sha256": _canonical_sha256(candidate_runs) if candidate_runs else None,
            "raw_returned": False,
        },
        "score": score,
        "claim_boundary": _claim_boundary(),
        "differential_status": STATUS_PASS if passed else STATUS_HOLD,
        "release_gate_passed": False,
        "failure_code": failure_code,
        "raw_returned": False,
    }
    validate_receipt(receipt)
    return receipt


def _require_sha256(value: Any, *, label: str) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DifferentialError(f"{label}_invalid")


def _validate_projection(value: Any, *, allow_empty: bool, persistence_line: int) -> None:
    if not isinstance(value, dict) or set(value) != {
        "relevant_finding_count", "relevant_findings", "raw_returned"
    }:
        raise DifferentialError("finding_projection_invalid")
    if value.get("raw_returned") is not False or not isinstance(value.get("relevant_finding_count"), int):
        raise DifferentialError("finding_projection_shape_invalid")
    findings = value.get("relevant_findings")
    if not isinstance(findings, list) or len(findings) != value["relevant_finding_count"]:
        raise DifferentialError("finding_projection_count_invalid")
    if allow_empty and _empty_projection(value):
        return
    if not _expected_positive(value, persistence_line=persistence_line):
        raise DifferentialError("finding_projection_expected_shape_invalid")


def _validate_pair(value: Any, *, persistence_line: int, candidate: bool) -> None:
    if not isinstance(value, dict) or set(value) != {"positive_oracle", "negative_oracle", "raw_returned"}:
        raise DifferentialError("pair_invalid")
    if value.get("raw_returned") is not False:
        raise DifferentialError("pair_raw_boundary_invalid")
    _validate_projection(value.get("positive_oracle"), allow_empty=not candidate, persistence_line=persistence_line)
    _validate_projection(value.get("negative_oracle"), allow_empty=True, persistence_line=persistence_line)
    if candidate and not _candidate_outcome(value, persistence_line=persistence_line):
        raise DifferentialError("candidate_pair_outcome_invalid")


def validate_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema", "tool_provenance", "source", "evidence", "mapping", "execution_pair",
        "negative_control", "baseline", "candidate_runs", "consensus", "score", "claim_boundary",
        "differential_status", "release_gate_passed", "failure_code", "raw_returned",
    }
    if not isinstance(receipt, dict) or set(receipt) != required or receipt.get("schema") != SCHEMA:
        raise DifferentialError("receipt_schema_invalid")
    if receipt.get("raw_returned") is not False or receipt.get("release_gate_passed") is not False:
        raise DifferentialError("receipt_claim_boundary_invalid")
    if receipt.get("claim_boundary") != _claim_boundary():
        raise DifferentialError("claim_boundary_invalid")
    status = receipt.get("differential_status")
    if status not in {STATUS_PASS, STATUS_HOLD}:
        raise DifferentialError("receipt_status_invalid")
    if status == STATUS_HOLD:
        if not isinstance(receipt.get("failure_code"), str) or not receipt["failure_code"]:
            raise DifferentialError("hold_without_failure")
        return
    if receipt.get("failure_code") is not None:
        raise DifferentialError("pass_with_failure")
    source = receipt.get("source")
    mapping = receipt.get("mapping")
    if (
        not isinstance(source, dict)
        or source.get("raw_returned") is not False
        or not isinstance(mapping, dict)
        or mapping.get("raw_returned") is not False
        or mapping.get("implementation_path") != IMPLEMENTATION_PATH.as_posix()
        or not isinstance(mapping.get("persistence_line"), int)
    ):
        raise DifferentialError("source_or_mapping_invalid")
    for name in (
        "source_tree_sha256", "source_receipt_sha256", "source_receipt_semantic_sha256", "implementation_sha256"
    ):
        _require_sha256(source.get(name), label=name)
    for value in (receipt.get("tool_provenance"), receipt.get("evidence"), receipt.get("execution_pair"), receipt.get("negative_control")):
        if not isinstance(value, dict) or value.get("raw_returned") is not False:
            raise DifferentialError("evidence_projection_invalid")
    baseline = receipt.get("baseline")
    if (
        not isinstance(baseline, dict)
        or baseline.get("raw_returned") is not False
        or baseline.get("actual_prechange_zero_findings") is not True
        or baseline.get("counterfactual_baseline_is_not_shipped_history") is not True
        or not isinstance(baseline.get("prechange_baseline"), dict)
        or baseline["prechange_baseline"].get("actual_prechange_zero_findings") is not True
        or not isinstance(baseline.get("counterfactual"), dict)
        or baseline["counterfactual"].get("variant") != BASELINE_VARIANT
    ):
        raise DifferentialError("baseline_invalid")
    _validate_pair(baseline.get("pair"), persistence_line=mapping["persistence_line"], candidate=False)
    if not _empty_projection(baseline["pair"]["positive_oracle"]) or not _empty_projection(
        baseline["pair"]["negative_oracle"]
    ):
        raise DifferentialError("counterfactual_baseline_outcome_invalid")
    runs = receipt.get("candidate_runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise DifferentialError("candidate_runs_invalid")
    for run in runs:
        _validate_pair(run, persistence_line=mapping["persistence_line"], candidate=True)
    if runs[0] != runs[1]:
        raise DifferentialError("candidate_runs_not_repeatable")
    expected_consensus = {
        "run_count": 2,
        "two_runs_byte_equivalent_after_normalization": True,
        "projection_sha256": _canonical_sha256(runs),
        "raw_returned": False,
    }
    if receipt.get("consensus") != expected_consensus:
        raise DifferentialError("consensus_invalid")
    if receipt.get("score") != {"generated_pair_count": 1, "tp": 1, "fp": 0, "fn": 0, "tn": 1}:
        raise DifferentialError("score_invalid")


def write_new_output(path: Path, receipt: dict[str, Any]) -> None:
    path = path.resolve()
    if path.exists():
        raise DifferentialError("output_already_exists")
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
    parser = argparse.ArgumentParser(
        description="Measure one source-bound WebGoat privilege-persistence scanner differential."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    measure = commands.add_parser("measure")
    measure.add_argument("--source-root", type=Path, required=True)
    measure.add_argument("--execution-evidence", type=Path, required=True)
    measure.add_argument("--cwe-evidence", type=Path, required=True)
    measure.add_argument("--positive-receipt", type=Path, required=True)
    measure.add_argument("--negative-receipt", type=Path, required=True)
    measure.add_argument("--prechange-baseline", type=Path, required=True)
    measure.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "verify":
        payload = json.loads(args.receipt.read_text(encoding="utf-8"))
        validate_receipt(payload)
        print(json.dumps({"status": payload["differential_status"], "raw_returned": False}, sort_keys=True))
        return 0 if payload["differential_status"] == STATUS_PASS else 2
    receipt = measure_differential(
        args.source_root,
        execution_evidence_path=args.execution_evidence,
        cwe_evidence_path=args.cwe_evidence,
        positive_receipt_path=args.positive_receipt,
        negative_receipt_path=args.negative_receipt,
        prechange_baseline_path=args.prechange_baseline,
    )
    write_new_output(args.output, receipt)
    print(json.dumps({"status": receipt["differential_status"], "raw_returned": False}, sort_keys=True))
    return 0 if receipt["differential_status"] == STATUS_PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
