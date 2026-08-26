from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable

from k_guard_mcp import scanner as scanner_module
from k_guard_mcp.detectors import polyglot as polyglot_module


SCHEMA = "k_guard_l2_webgoat_idor_scanner_differential.v1"
STATUS_PASS = "SCANNER_DIFFERENTIAL_PASS"
STATUS_HOLD = "HOLD"
APP_ID = "webgoat"
BASELINE_VARIANT = "pre_suppression_rejection_override.v1"
EXPECTED_RULE_ID = "API_IDOR_ROUTE_PARAM_LOOKUP"
EXPECTED_SUBTYPE = "java_spring_cross_account_write_observe"
EXPECTED_SEVERITY = "high"
EXPECTED_CONFIDENCE = "medium"
EXPECTED_ARTIFACT_SCOPE = "runtime_source"
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


def _load_contracts() -> tuple[Any, str, Any, str]:
    directory = Path(__file__).resolve(strict=True).parent
    mapping, mapping_sha256 = _load_script(
        directory / "observe_l2_webgoat_idor_scanner.py",
        module_name="k_guard_l2_webgoat_idor_mapping_contract",
    )
    registry, registry_sha256 = _load_script(
        directory / "materialize_l2_oracles.py",
        module_name="k_guard_l2_webgoat_idor_registry_contract",
    )
    return mapping, mapping_sha256, registry, registry_sha256


def _source_binding(
    registry: Any,
    *,
    source_root: Path,
    sources_root: Path,
    source_admission_path: Path,
    source_receipts_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolved_source = source_root.resolve(strict=True)
    resolved_sources = sources_root.resolve(strict=True)
    expected_source = (resolved_sources / APP_ID).resolve(strict=True)
    if resolved_source != expected_source:
        raise DifferentialError("source_root_not_bound_to_sources_root")
    admission, receipts = registry._verify_source_receipts(
        resolved_sources, source_admission_path, source_receipts_dir
    )
    row = next((value for value in receipts if value.get("app_id") == APP_ID), None)
    if not isinstance(row, dict):
        raise DifferentialError("webgoat_source_receipt_missing")
    required = {
        "repository_id",
        "commit",
        "commit_tree",
        "source_tree_sha256",
        "receipt_sha256",
        "observed_receipt_sha256",
        "receipt_semantic_sha256",
        "receipt_equivalence",
        "lineage_id",
        "source_admission",
    }
    if any(name not in row for name in required):
        raise DifferentialError("webgoat_source_receipt_projection_invalid")
    if (
        row["source_admission"] != "PASS"
        or row["receipt_equivalence"] not in {"exact_raw_receipt", "informational_porcelain_variance"}
    ):
        raise DifferentialError("webgoat_source_receipt_not_admitted")
    for name in ("receipt_sha256", "observed_receipt_sha256", "receipt_semantic_sha256", "source_tree_sha256"):
        if not isinstance(row.get(name), str) or SHA256_RE.fullmatch(row[name]) is None:
            raise DifferentialError("webgoat_source_receipt_hash_invalid")
    projection = {
        "app_id": APP_ID,
        "repository_id": row["repository_id"],
        "commit": row["commit"],
        "commit_tree": row["commit_tree"],
        "source_tree_sha256": row["source_tree_sha256"],
        "lineage_id": row["lineage_id"],
        "preregistered_source_receipt_sha256": row["receipt_sha256"],
        "observed_source_receipt_sha256": row["observed_receipt_sha256"],
        "source_receipt_semantic_sha256": row["receipt_semantic_sha256"],
        "receipt_equivalence": row["receipt_equivalence"],
        "raw_returned": False,
    }
    admission_projection = {
        "schema": admission["schema"],
        "artifact_name": admission["artifact_name"],
        "artifact_sha256": admission["artifact_sha256"],
        "contract_artifact": admission["contract_artifact"],
        "contract_sha256": admission["contract_sha256"],
        "verifier_artifact": admission["verifier_artifact"],
        "verifier_sha256": admission["verifier_sha256"],
        "status": admission["status"],
        "raw_returned": False,
    }
    return projection, admission_projection


def _execution_pair(mapping: Any, *, positive_receipt: Path, negative_receipt: Path) -> tuple[dict[str, Any], dict[str, Any], Any]:
    runtime = mapping._load_runtime_contract()
    positive = mapping._positive_reference(positive_receipt, runtime)
    pair = mapping._negative_reference(negative_receipt, runtime, positive)
    negative_payload, negative_sha256 = mapping._load_canonical_receipt(
        negative_receipt, label="negative_control_receipt"
    )
    if negative_sha256 != pair["negative_control_receipt_sha256"]:
        raise DifferentialError("negative_control_receipt_digest_mismatch")
    control = negative_payload.get("negative_control")
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
    if not isinstance(control, dict) or set(control) != required:
        raise DifferentialError("negative_control_projection_invalid")
    if control["raw_returned"] is not False or control["source_checkout_mutated"] is not False:
        raise DifferentialError("negative_control_boundary_invalid")
    for name in ("original_file_sha256", "patched_file_sha256", "patch_sha256", "variant_tree_sha256"):
        if not isinstance(control.get(name), str) or SHA256_RE.fullmatch(control[name]) is None:
            raise DifferentialError("negative_control_hash_invalid")
    return pair, dict(control), runtime


def _pre_suppression_baseline() -> dict[str, str]:
    polyglot_path = Path(polyglot_module.__file__).resolve(strict=True)
    candidate_sha256 = sha256_bytes(polyglot_path.read_bytes())
    definition = {
        "base_candidate_polyglot_sha256": candidate_sha256,
        "variant": BASELINE_VARIANT,
        "override": "java_cross_account_mismatch_is_explicitly_rejected=false",
        "raw_returned": False,
    }
    return {
        **definition,
        "counterfactual_definition_sha256": _canonical_sha256(definition),
        "raw_returned": False,
    }


def _finding_projection(
    text: str,
    path: str,
    detector: type[Any],
    *,
    disable_explicit_rejection: bool = False,
) -> dict[str, Any]:
    original = scanner_module.PolyglotRiskDetector
    original_rejection = polyglot_module._java_cross_account_mismatch_is_explicitly_rejected
    scanner_module.PolyglotRiskDetector = detector
    if disable_explicit_rejection:
        polyglot_module._java_cross_account_mismatch_is_explicitly_rejected = lambda *_args, **_kwargs: False
    try:
        findings = scanner_module.KGuardScanner().scan_text(text, path).findings
    finally:
        scanner_module.PolyglotRiskDetector = original
        polyglot_module._java_cross_account_mismatch_is_explicitly_rejected = original_rejection
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


def _expected_positive(projection: dict[str, Any]) -> bool:
    findings = projection.get("relevant_findings")
    if not isinstance(findings, list) or len(findings) != 1:
        return False
    finding = findings[0]
    return (
        isinstance(finding, dict)
        and finding.get("severity") == EXPECTED_SEVERITY
        and finding.get("confidence") == EXPECTED_CONFIDENCE
        and finding.get("detector_subtype") == EXPECTED_SUBTYPE
        and finding.get("artifact_scope") == EXPECTED_ARTIFACT_SCOPE
        and isinstance(finding.get("line"), int)
        and isinstance(finding.get("line_hash"), str)
        and bool(re.fullmatch(r"[0-9a-f]{16}", finding["line_hash"]))
    )


def _copy_negative_variant(source_root: Path, runtime: Any) -> tuple[str, dict[str, Any]]:
    verifier, _verifier_sha256 = runtime._load_source_verifier()
    with tempfile.TemporaryDirectory(prefix="k-guard-l2-idorscan-") as temporary:
        variant_root = Path(temporary) / APP_ID
        runtime._copy_verified_source(source_root, variant_root, verifier)
        control = runtime._apply_negative_control_patch(variant_root, verifier)
        target = variant_root / runtime.NEGATIVE_CONTROL_SOURCE_PATH
        try:
            text = target.read_bytes().decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise DifferentialError("negative_control_variant_unreadable") from exc
    return text, control


def _candidate_pair(positive_text: str, negative_text: str, path: str) -> dict[str, Any]:
    current = scanner_module.PolyglotRiskDetector
    return {
        "positive_oracle": _finding_projection(positive_text, path, current),
        "negative_oracle": _finding_projection(negative_text, path, current),
        "raw_returned": False,
    }


def _candidate_outcome(pair: dict[str, Any]) -> bool:
    return (
        _expected_positive(pair.get("positive_oracle", {}))
        and pair.get("negative_oracle", {}).get("relevant_finding_count") == 0
    )


def _claim_boundary() -> dict[str, bool]:
    return {
        "one_source_bound_generated_pair_only": True,
        "historical_false_positive_reproduced": True,
        "candidate_pair_tp_tn_proven": True,
        "product_accuracy_proven": False,
        "product_tp_fp_fn_tn_proven": False,
        "recall_or_specificity_proven": False,
        "severity_or_cwe_admitted": False,
        "release_gate_admitted": False,
        "raw_returned": False,
    }


def _tool_provenance(
    *, mapping_sha256: str, registry_sha256: str, runtime: Any, baseline: dict[str, str]
) -> dict[str, Any]:
    root = Path(__file__).resolve(strict=True).parents[1]
    scanner_path = root / "src" / "k_guard_mcp" / "scanner.py"
    polyglot_path = root / "src" / "k_guard_mcp" / "detectors" / "polyglot.py"
    return {
        "measurement_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "mapping_contract_sha256": mapping_sha256,
        "registry_contract_sha256": registry_sha256,
        "runtime_contract_sha256": sha256_bytes(Path(runtime.__file__).read_bytes()),
        "scanner_sha256": sha256_bytes(scanner_path.read_bytes()),
        "candidate_polyglot_sha256": sha256_bytes(polyglot_path.read_bytes()),
        **baseline,
        "raw_returned": False,
    }


def measure_differential(
    source_root: Path,
    *,
    sources_root: Path,
    source_admission_path: Path,
    source_receipts_dir: Path,
    positive_receipt_path: Path,
    negative_receipt_path: Path,
) -> dict[str, Any]:
    mapping, mapping_sha256, registry, registry_sha256 = _load_contracts()
    source: dict[str, Any] | None = None
    admission: dict[str, Any] | None = None
    execution_pair: dict[str, Any] | None = None
    control: dict[str, Any] | None = None
    mapping_projection: dict[str, Any] | None = None
    baseline: dict[str, Any] | None = None
    candidate_runs: list[dict[str, Any]] = []
    score: dict[str, int] | None = None
    provenance: dict[str, Any] | None = None
    failure_code: str | None = None
    try:
        source, admission = _source_binding(
            registry,
            source_root=source_root,
            sources_root=sources_root,
            source_admission_path=source_admission_path,
            source_receipts_dir=source_receipts_dir,
        )
        execution_pair, expected_control, runtime = _execution_pair(
            mapping, positive_receipt=positive_receipt_path, negative_receipt=negative_receipt_path
        )
        if execution_pair["source_receipt_sha256"] != source["preregistered_source_receipt_sha256"]:
            raise DifferentialError("execution_pair_not_bound_to_preregistered_source")
        mapping_projection, positive_text = mapping._source_mapping(source_root)
        negative_text, control = _copy_negative_variant(source_root, runtime)
        if control != expected_control:
            raise DifferentialError("negative_control_patch_not_equal_to_runtime_oracle")
        baseline_provenance = _pre_suppression_baseline()
        baseline_pair = {
            "positive_oracle": _finding_projection(
                positive_text,
                mapping.IMPLEMENTATION_SOURCE_PATH.as_posix(),
                scanner_module.PolyglotRiskDetector,
                disable_explicit_rejection=True,
            ),
            "negative_oracle": _finding_projection(
                negative_text,
                mapping.IMPLEMENTATION_SOURCE_PATH.as_posix(),
                scanner_module.PolyglotRiskDetector,
                disable_explicit_rejection=True,
            ),
            "raw_returned": False,
        }
        baseline = {
            **baseline_provenance,
            "pair": baseline_pair,
            "historical_false_positive_reproduced": (
                _expected_positive(baseline_pair["positive_oracle"])
                and _expected_positive(baseline_pair["negative_oracle"])
            ),
            "raw_returned": False,
        }
        candidate_runs = [
            _candidate_pair(positive_text, negative_text, mapping.IMPLEMENTATION_SOURCE_PATH.as_posix())
            for _ in range(2)
        ]
        if source != _source_binding(
            registry,
            source_root=source_root,
            sources_root=sources_root,
            source_admission_path=source_admission_path,
            source_receipts_dir=source_receipts_dir,
        )[0]:
            raise DifferentialError("source_admission_changed_during_measurement")
        candidate_passed = len(candidate_runs) == 2 and candidate_runs[0] == candidate_runs[1] and _candidate_outcome(candidate_runs[0])
        if not baseline["historical_false_positive_reproduced"]:
            raise DifferentialError("historical_false_positive_not_reproduced")
        if not candidate_passed:
            raise DifferentialError("candidate_pair_outcome_invalid")
        score = {"generated_pair_count": 1, "tp": 1, "fp": 0, "fn": 0, "tn": 1}
        provenance = _tool_provenance(
            mapping_sha256=mapping_sha256,
            registry_sha256=registry_sha256,
            runtime=runtime,
            baseline=baseline_provenance,
        )
    except (DifferentialError, OSError, RuntimeError, ValueError) as exc:
        failure_code = str(exc)
    passed = (
        failure_code is None
        and source is not None
        and admission is not None
        and execution_pair is not None
        and control is not None
        and mapping_projection is not None
        and baseline is not None
        and len(candidate_runs) == 2
        and score is not None
        and provenance is not None
    )
    receipt = {
        "schema": SCHEMA,
        "tool_provenance": provenance,
        "source_admission": admission,
        "source": source,
        "execution_pair": execution_pair,
        "mapping": mapping_projection,
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


def _validate_finding_projection(value: Any, *, allow_empty: bool) -> None:
    if not isinstance(value, dict) or set(value) != {"relevant_finding_count", "relevant_findings", "raw_returned"}:
        raise DifferentialError("finding_projection_invalid")
    if value.get("raw_returned") is not False or not isinstance(value.get("relevant_finding_count"), int):
        raise DifferentialError("finding_projection_shape_invalid")
    findings = value.get("relevant_findings")
    if not isinstance(findings, list) or len(findings) != value["relevant_finding_count"]:
        raise DifferentialError("finding_projection_count_invalid")
    if not allow_empty and not _expected_positive(value):
        raise DifferentialError("positive_finding_projection_invalid")
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("raw_returned") is not False:
            raise DifferentialError("finding_projection_raw_boundary_invalid")


def _validate_candidate_pair(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"positive_oracle", "negative_oracle", "raw_returned"}:
        raise DifferentialError("candidate_pair_invalid")
    if value.get("raw_returned") is not False:
        raise DifferentialError("candidate_pair_raw_boundary_invalid")
    _validate_finding_projection(value.get("positive_oracle"), allow_empty=False)
    _validate_finding_projection(value.get("negative_oracle"), allow_empty=True)


def validate_receipt(receipt: dict[str, Any]) -> None:
    required = {
        "schema", "tool_provenance", "source_admission", "source", "execution_pair", "mapping", "negative_control",
        "baseline", "candidate_runs", "consensus", "score", "claim_boundary", "differential_status",
        "release_gate_passed", "failure_code", "raw_returned",
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
    if not isinstance(source, dict) or source.get("raw_returned") is not False:
        raise DifferentialError("source_invalid")
    for name in ("preregistered_source_receipt_sha256", "observed_source_receipt_sha256", "source_receipt_semantic_sha256"):
        _require_sha256(source.get(name), label=name)
    if source.get("receipt_equivalence") not in {"exact_raw_receipt", "informational_porcelain_variance"}:
        raise DifferentialError("source_equivalence_invalid")
    execution_pair = receipt.get("execution_pair")
    if not isinstance(execution_pair, dict) or execution_pair.get("raw_returned") is not False:
        raise DifferentialError("execution_pair_invalid")
    _require_sha256(execution_pair.get("source_receipt_sha256"), label="execution_source_receipt_sha256")
    if execution_pair["source_receipt_sha256"] != source["preregistered_source_receipt_sha256"]:
        raise DifferentialError("execution_pair_source_binding_invalid")
    baseline = receipt.get("baseline")
    if not isinstance(baseline, dict) or baseline.get("raw_returned") is not False:
        raise DifferentialError("baseline_invalid")
    if baseline.get("historical_false_positive_reproduced") is not True:
        raise DifferentialError("historical_false_positive_not_reproduced")
    _validate_candidate_pair(baseline.get("pair"))
    baseline_negative = baseline["pair"]["negative_oracle"]
    if not _expected_positive(baseline_negative):
        raise DifferentialError("baseline_false_positive_shape_invalid")
    runs = receipt.get("candidate_runs")
    if not isinstance(runs, list) or len(runs) != 2:
        raise DifferentialError("candidate_runs_invalid")
    for run in runs:
        _validate_candidate_pair(run)
        if not _candidate_outcome(run):
            raise DifferentialError("candidate_pair_outcome_invalid")
    if runs[0] != runs[1]:
        raise DifferentialError("candidate_runs_not_repeatable")
    consensus = receipt.get("consensus")
    expected_consensus = {
        "run_count": 2,
        "two_runs_byte_equivalent_after_normalization": True,
        "projection_sha256": _canonical_sha256(runs),
        "raw_returned": False,
    }
    if consensus != expected_consensus:
        raise DifferentialError("consensus_invalid")
    if receipt.get("score") != {"generated_pair_count": 1, "tp": 1, "fp": 0, "fn": 0, "tn": 1}:
        raise DifferentialError("score_invalid")
    for value in (receipt.get("tool_provenance"), receipt.get("source_admission"), receipt.get("mapping"), receipt.get("negative_control")):
        if not isinstance(value, dict) or value.get("raw_returned") is not False:
            raise DifferentialError("provenance_projection_invalid")


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
    parser = argparse.ArgumentParser(description="Measure one source-bound WebGoat IDOR scanner differential without promoting product accuracy.")
    commands = parser.add_subparsers(dest="command", required=True)
    measure = commands.add_parser("measure")
    measure.add_argument("--source-root", type=Path, required=True)
    measure.add_argument("--sources-root", type=Path, required=True)
    measure.add_argument("--source-admission", type=Path, required=True)
    measure.add_argument("--source-receipts-dir", type=Path, required=True)
    measure.add_argument("--positive-receipt", type=Path, required=True)
    measure.add_argument("--negative-receipt", type=Path, required=True)
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
        sources_root=args.sources_root,
        source_admission_path=args.source_admission,
        source_receipts_dir=args.source_receipts_dir,
        positive_receipt_path=args.positive_receipt,
        negative_receipt_path=args.negative_receipt,
    )
    write_new_output(args.output, receipt)
    print(json.dumps({"status": receipt["differential_status"], "raw_returned": False}, sort_keys=True))
    return 0 if receipt["differential_status"] == STATUS_PASS else 2


if __name__ == "__main__":
    raise SystemExit(main())
