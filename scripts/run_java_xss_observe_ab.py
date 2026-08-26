from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from capture_supervisor_target import capture_target
from seal_current_baseline import _load_canonical_receipt, validate_current_baseline

from k_guard_mcp.detectors.polyglot import PolyglotRiskDetector
from k_guard_mcp.l1_benchmark import (
    L1BenchmarkError,
    _read_manifest,
    _regular_file,
    _validate_manifest,
    _verify_corpus,
)


SCHEMA = "k_guard_java_servlet_xss_observe_ab.v1"
STATUS = "MEASURED_HOLD"
RULE_ID = "WEB_UNTRUSTED_INPUT_TO_HTML"
SUBTYPE = "java_servlet_bounded_html_response_observe"
EXPECTED_SEVERITY = "medium"
EXPECTED_CONFIDENCE = "medium"
LINE_HASH_RE = re.compile(r"\bline_hash=([0-9a-f]{16})\b")


class JavaXssObserveError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _outside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return True
    return False


def _case_ref(case_id: str) -> str:
    return _sha256_bytes(canonical_json_bytes({"case_id": case_id}))[:24]


def _candidate_ref(case_id: str, line: int, line_hash: str) -> str:
    return _sha256_bytes(
        canonical_json_bytes(
            {
                "case_id": case_id,
                "rule_id": RULE_ID,
                "subtype": SUBTYPE,
                "line": line,
                "line_hash": line_hash,
            }
        )
    )[:24]


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    observed = successes / total
    denominator = 1 + z * z / total
    centre = observed + z * z / (2 * total)
    margin = z * ((observed * (1 - observed) + z * z / (4 * total)) / total) ** 0.5
    return round((centre - margin) / denominator, 6)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _metrics(counts: Counter[str]) -> dict[str, Any]:
    tp = counts["tp"]
    fp = counts["fp"]
    fn = counts["fn"]
    tn = counts["tn"]
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": _ratio(tp, tp + fp),
        "precision_wilson_95_lower": _wilson_lower(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "recall_wilson_95_lower": _wilson_lower(tp, tp + fn),
        "specificity": _ratio(tn, tn + fp),
        "specificity_wilson_95_lower": _wilson_lower(tn, tn + fp),
    }


def _relevant_candidates(
    text: str,
    source_path: str,
    *,
    enabled: bool,
    html_encoder_suppression: bool,
    html_encoder_helper_suppression: bool,
    constant_ternary_suppression: bool,
    static_switch_suppression: bool,
    static_if_suppression: bool = False,
) -> list[dict[str, Any]]:
    findings = PolyglotRiskDetector(
        enable_java_servlet_xss_observe=enabled,
        enable_java_servlet_xss_html_encoder_suppression=html_encoder_suppression,
        enable_java_servlet_xss_html_encoder_helper_suppression=html_encoder_helper_suppression,
        enable_java_servlet_xss_constant_ternary_suppression=constant_ternary_suppression,
        enable_java_servlet_xss_static_switch_suppression=static_switch_suppression,
        enable_java_servlet_xss_static_if_suppression=static_if_suppression,
    ).scan_text(text, source_path)
    candidates: list[dict[str, Any]] = []
    for finding in findings:
        if finding.rule_id != RULE_ID or SUBTYPE not in finding.evidence:
            continue
        if finding.severity != EXPECTED_SEVERITY or finding.confidence != EXPECTED_CONFIDENCE:
            raise JavaXssObserveError("java_xss_observe_stage_contract_invalid")
        line_hash = LINE_HASH_RE.search(finding.evidence)
        if finding.line_start is None or line_hash is None:
            raise JavaXssObserveError("java_xss_observe_finding_projection_invalid")
        candidates.append(
            {
                "line": finding.line_start,
                "line_hash": line_hash.group(1),
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "detector_subtype": SUBTYPE,
                "raw_returned": False,
            }
        )
    return sorted(candidates, key=canonical_json_bytes)


def _measure_variant(
    corpus: Mapping[str, Any],
    source_root: Path,
    *,
    enabled: bool,
    html_encoder_suppression: bool,
    html_encoder_helper_suppression: bool,
    constant_ternary_suppression: bool,
    static_switch_suppression: bool,
    variant: str,
    static_if_suppression: bool = False,
) -> dict[str, Any]:
    cases = [
        case
        for case in corpus["cases"]
        if case["category"] == "xss" and case["source_path"].endswith(".java")
    ]
    if not cases:
        raise JavaXssObserveError("java_xss_cases_missing")
    counts: Counter[str] = Counter()
    scenario_results: list[dict[str, Any]] = []
    registry: list[dict[str, Any]] = []
    for case in cases:
        case_id = str(case["case_id"])
        source_path = str(case["source_path"])
        path = _regular_file(source_root, source_path)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise JavaXssObserveError("java_xss_source_unreadable") from exc
        candidates = _relevant_candidates(
            text,
            source_path,
            enabled=enabled,
            html_encoder_suppression=html_encoder_suppression,
            html_encoder_helper_suppression=html_encoder_helper_suppression,
            constant_ternary_suppression=constant_ternary_suppression,
            static_switch_suppression=static_switch_suppression,
            static_if_suppression=static_if_suppression,
        )
        present = case["truth"] == "present"
        if present:
            outcome = "tp" if candidates else "fn"
        else:
            outcome = "fp" if candidates else "tn"
        counts[outcome] += 1
        candidate_refs: list[str] = []
        for candidate in candidates:
            reference = _candidate_ref(case_id, int(candidate["line"]), str(candidate["line_hash"]))
            candidate_refs.append(reference)
            registry.append(
                {
                    "candidate_ref": reference,
                    "case_ref": _case_ref(case_id),
                    **candidate,
                }
            )
        scenario_results.append(
            {
                "case_ref": _case_ref(case_id),
                "expected": "vulnerable" if present else "clean",
                "outcome": outcome,
                "candidate_refs": sorted(candidate_refs),
                "raw_returned": False,
            }
        )
    registry.sort(key=canonical_json_bytes)
    scenario_results.sort(key=canonical_json_bytes)
    projection = {
        "variant": variant,
        "scenario_results": scenario_results,
        "candidate_registry": registry,
        "metrics": _metrics(counts),
        "raw_returned": False,
    }
    return {
        **projection,
        "semantic_fingerprint_sha256": _sha256_bytes(canonical_json_bytes(projection)),
    }


def _delta(control: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    before = control["metrics"]["confusion_matrix"]
    after = candidate["metrics"]["confusion_matrix"]
    return {
        "confusion_matrix_delta": {name: int(after[name]) - int(before[name]) for name in ("tp", "fp", "fn", "tn")},
        "recall_delta": round(float(candidate["metrics"]["recall"]) - float(control["metrics"]["recall"]), 6),
        "specificity_delta": round(
            float(candidate["metrics"]["specificity"]) - float(control["metrics"]["specificity"]), 6
        ),
        "raw_returned": False,
    }


def _measure_pair(
    corpus: Mapping[str, Any],
    source_root: Path,
    *,
    hypothesis_id: str,
    statement: str,
    control_enabled: bool,
    control_html_encoder_suppression: bool,
    control_html_encoder_helper_suppression: bool,
    control_constant_ternary_suppression: bool,
    control_static_switch_suppression: bool,
    control_variant: str,
    candidate_enabled: bool,
    candidate_html_encoder_suppression: bool,
    candidate_html_encoder_helper_suppression: bool,
    candidate_constant_ternary_suppression: bool,
    candidate_static_switch_suppression: bool,
    candidate_variant: str,
    control_static_if_suppression: bool = False,
    candidate_static_if_suppression: bool = False,
) -> dict[str, Any]:
    source_integrity_before = _verify_corpus(corpus, source_root)
    runs: list[dict[str, Any]] = []
    for run in (1, 2):
        control = _measure_variant(
            corpus,
            source_root,
            enabled=control_enabled,
            html_encoder_suppression=control_html_encoder_suppression,
            html_encoder_helper_suppression=control_html_encoder_helper_suppression,
            constant_ternary_suppression=control_constant_ternary_suppression,
            static_switch_suppression=control_static_switch_suppression,
            variant=control_variant,
            static_if_suppression=control_static_if_suppression,
        )
        candidate = _measure_variant(
            corpus,
            source_root,
            enabled=candidate_enabled,
            html_encoder_suppression=candidate_html_encoder_suppression,
            html_encoder_helper_suppression=candidate_html_encoder_helper_suppression,
            constant_ternary_suppression=candidate_constant_ternary_suppression,
            static_switch_suppression=candidate_static_switch_suppression,
            variant=candidate_variant,
            static_if_suppression=candidate_static_if_suppression,
        )
        runs.append({"run": run, "control": control, "candidate": candidate, "raw_returned": False})
    source_integrity_after = _verify_corpus(corpus, source_root)
    control_exact = runs[0]["control"]["semantic_fingerprint_sha256"] == runs[1]["control"]["semantic_fingerprint_sha256"]
    candidate_exact = runs[0]["candidate"]["semantic_fingerprint_sha256"] == runs[1]["candidate"]["semantic_fingerprint_sha256"]
    first_control = runs[0]["control"]
    first_candidate = runs[0]["candidate"]
    return {
        "schema": SCHEMA,
        "complete": True,
        "status": STATUS,
        "corpus": {
            "corpus_id": corpus["corpus_id"],
            "language": corpus["language"],
            "category": "xss",
            "case_count": len(first_candidate["scenario_results"]),
            "source_integrity_before": source_integrity_before,
            "source_integrity_after": source_integrity_after,
            "raw_returned": False,
        },
        "hypothesis": {
            "id": hypothesis_id,
            "statement": statement,
            "stage": "observe",
            "warning_promotion_admitted": False,
            "blocking_promotion_admitted": False,
            "raw_returned": False,
        },
        "runs": runs,
        "repeat": {
            "requested": True,
            "performed": True,
            "control_exact": control_exact,
            "candidate_exact": candidate_exact,
            "exact": control_exact and candidate_exact,
            "raw_returned": False,
        },
        "comparison": {
            "control": first_control["metrics"],
            "candidate": first_candidate["metrics"],
            "delta": _delta(first_control, first_candidate),
            "candidate_registry_complete_for_this_observer": True,
            "raw_returned": False,
        },
        "claim_boundary": {
            "public_development_corpus_already_observed": True,
            "bounded_java_servlet_observer_only": True,
            "observed_candidate_stage_only": True,
            "product_block_precision_proven": False,
            "product_recall_proven": False,
            "product_accuracy_proven": False,
            "release_gate_passed": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def measure_h4a(corpus: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Measure the original H4A observer with later suppressions explicitly disabled."""

    return _measure_pair(
        corpus,
        source_root,
        hypothesis_id="H4A",
        statement=(
            "A bounded Java servlet request-to-explicit-HTML-writer observer reduces the measured "
            "Java XSS false-negative count without being promoted to a release hold."
        ),
        control_enabled=False,
        control_html_encoder_suppression=False,
        control_html_encoder_helper_suppression=False,
        control_constant_ternary_suppression=False,
        control_static_switch_suppression=False,
        control_variant="control_observer_disabled",
        candidate_enabled=True,
        candidate_html_encoder_suppression=False,
        candidate_html_encoder_helper_suppression=False,
        candidate_constant_ternary_suppression=False,
        candidate_static_switch_suppression=False,
        candidate_variant="candidate_observe_without_html_encoder_suppression",
    )


def measure_h4b(corpus: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Measure only direct, known HTML-encoder taint suppression on the H4A observer."""

    return _measure_pair(
        corpus,
        source_root,
        hypothesis_id="H4B",
        statement=(
            "Recognizing a direct local call to a known Java HTML encoder reduces H4A observer false "
            "positives without promoting the observer beyond observe."
        ),
        control_enabled=True,
        control_html_encoder_suppression=False,
        control_html_encoder_helper_suppression=False,
        control_constant_ternary_suppression=False,
        control_static_switch_suppression=False,
        control_variant="control_observe_without_html_encoder_suppression",
        candidate_enabled=True,
        candidate_html_encoder_suppression=True,
        candidate_html_encoder_helper_suppression=False,
        candidate_constant_ternary_suppression=False,
        candidate_static_switch_suppression=False,
        candidate_variant="candidate_observe_with_direct_html_encoder_suppression",
    )


def measure_h4c(corpus: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Measure one trivial same-file known-encoder helper summary on the H4B observer."""

    return _measure_pair(
        corpus,
        source_root,
        hypothesis_id="H4C",
        statement=(
            "Summarizing one trivial same-file helper that returns a known Java HTML encoder reduces "
            "H4B observer false positives without promoting the observer beyond observe."
        ),
        control_enabled=True,
        control_html_encoder_suppression=True,
        control_html_encoder_helper_suppression=False,
        control_constant_ternary_suppression=False,
        control_static_switch_suppression=False,
        control_variant="control_observe_with_direct_html_encoder_suppression",
        candidate_enabled=True,
        candidate_html_encoder_suppression=True,
        candidate_html_encoder_helper_suppression=True,
        candidate_constant_ternary_suppression=False,
        candidate_static_switch_suppression=False,
        candidate_variant="candidate_observe_with_trivial_html_encoder_helper_suppression",
    )


def measure_h4d(corpus: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Measure static Java numeric-ternary literal suppression on the H4C observer."""

    return _measure_pair(
        corpus,
        source_root,
        hypothesis_id="H4D",
        statement=(
            "Evaluating a closed Java numeric ternary and one trivial same-file literal-return helper "
            "reduces H4C observer false positives without promoting the observer beyond observe."
        ),
        control_enabled=True,
        control_html_encoder_suppression=True,
        control_html_encoder_helper_suppression=True,
        control_constant_ternary_suppression=False,
        control_static_switch_suppression=False,
        control_variant="control_observe_without_static_ternary_suppression",
        candidate_enabled=True,
        candidate_html_encoder_suppression=True,
        candidate_html_encoder_helper_suppression=True,
        candidate_constant_ternary_suppression=True,
        candidate_static_switch_suppression=False,
        candidate_variant="candidate_observe_with_static_ternary_suppression",
    )


def measure_h4e(corpus: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Measure a closed Java char-switch literal helper summary on the H4D observer."""

    return _measure_pair(
        corpus,
        source_root,
        hypothesis_id="H4E",
        statement=(
            "Summarizing one same-file helper whose closed Java char switch selects a literal result "
            "reduces H4D observer false positives without promoting the observer beyond observe."
        ),
        control_enabled=True,
        control_html_encoder_suppression=True,
        control_html_encoder_helper_suppression=True,
        control_constant_ternary_suppression=True,
        control_static_switch_suppression=False,
        control_variant="control_observe_without_static_switch_suppression",
        candidate_enabled=True,
        candidate_html_encoder_suppression=True,
        candidate_html_encoder_helper_suppression=True,
        candidate_constant_ternary_suppression=True,
        candidate_static_switch_suppression=True,
        candidate_variant="candidate_observe_with_static_switch_suppression",
    )


def measure_h4f(corpus: Mapping[str, Any], source_root: Path) -> dict[str, Any]:
    """Measure a closed Java numeric-if literal helper summary on the H4E observer."""

    return _measure_pair(
        corpus,
        source_root,
        hypothesis_id="H4F",
        statement=(
            "Summarizing one same-file helper whose closed Java numeric if branch selects a literal "
            "result reduces H4E observer false positives without promoting the observer beyond observe."
        ),
        control_enabled=True,
        control_html_encoder_suppression=True,
        control_html_encoder_helper_suppression=True,
        control_constant_ternary_suppression=True,
        control_static_switch_suppression=True,
        control_variant="control_observe_without_static_if_suppression",
        candidate_enabled=True,
        candidate_html_encoder_suppression=True,
        candidate_html_encoder_helper_suppression=True,
        candidate_constant_ternary_suppression=True,
        candidate_static_switch_suppression=True,
        candidate_variant="candidate_observe_with_static_if_suppression",
        control_static_if_suppression=False,
        candidate_static_if_suppression=True,
    )


def _control_hold(error: str, manifest_sha256: str | None, target: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "complete": False,
        "status": "CONTROL_HOLD",
        "control_errors": [error],
        "manifest_sha256": manifest_sha256,
        "target": dict(target) if target is not None else None,
        "claim_boundary": {
            "release_gate_passed": False,
            "product_accuracy_proven": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(dict(value))
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise JavaXssObserveError("java_xss_observe_output_exists") from exc


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one pre-registered Java servlet XSS observe-stage A/B twice without promotion."
    )
    parser.add_argument("--hypothesis", choices=("H4A", "H4B", "H4C", "H4D", "H4E", "H4F"), default="H4A")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--benchmark-java", type=Path, required=True)
    parser.add_argument("--baseline-receipt", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    output_dir = args.output_dir.resolve()
    if output_dir.exists() or not _outside_repository(output_dir):
        raise JavaXssObserveError("java_xss_observe_output_dir_must_be_new_and_external")
    if not _outside_repository(args.baseline_receipt):
        raise JavaXssObserveError("java_xss_observe_baseline_receipt_must_be_external")

    manifest_sha256: str | None = None
    target: Mapping[str, Any] | None = None
    try:
        receipt = _load_canonical_receipt(args.baseline_receipt)
        validate_current_baseline(ROOT, receipt)
        target = capture_target(ROOT)
        manifest, manifest_sha256 = _read_manifest(args.manifest)
        corpus = _validate_manifest(manifest)["java"]
        measurements = {
            "H4A": measure_h4a,
            "H4B": measure_h4b,
            "H4C": measure_h4c,
            "H4D": measure_h4d,
            "H4E": measure_h4e,
            "H4F": measure_h4f,
        }
        report = measurements[args.hypothesis](corpus, args.benchmark_java)
        if capture_target(ROOT) != target:
            raise JavaXssObserveError("java_xss_observe_target_changed_during_measurement")
        report["manifest_sha256"] = manifest_sha256
        report["target"] = dict(target)
        report["execution_binding"] = {
            "baseline_receipt_sha256": receipt["receipt_sha256"],
            "target": dict(target),
            "raw_returned": False,
        }
        report["tool_provenance"] = {
            "measurement_sha256": _sha256_file(Path(__file__).resolve(strict=True)),
            "polyglot_detector_sha256": _sha256_file(
                ROOT / "src" / "k_guard_mcp" / "detectors" / "polyglot.py"
            ),
            "raw_returned": False,
        }
    except (JavaXssObserveError, L1BenchmarkError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = _control_hold(str(exc), manifest_sha256, target)

    output = output_dir / "java-xss-observe-ab-report.json"
    _write_new_json(output, report)
    summary = {
        "complete": report.get("complete") is True,
        "status": report.get("status"),
        "repeat_exact": report.get("repeat", {}).get("exact") is True,
        "output": str(output),
        "raw_returned": False,
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if report.get("complete") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
