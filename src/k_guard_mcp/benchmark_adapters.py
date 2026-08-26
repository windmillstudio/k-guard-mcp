from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from k_guard_mcp.field_validation import FIELD_REVIEW_FIELDS, GROUND_TRUTH_FIELDS, run_field_validation
from k_guard_mcp.guardian import build_validation_guardian_evidence
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.provenance import source_tree_snapshot
from k_guard_mcp.scanner import KGuardScanner
from k_guard_mcp.validation import finding_fingerprint


OWASP_PYTHON_REPOSITORY = "https://github.com/OWASP-Benchmark/BenchmarkPython"
OWASP_CATEGORY_RULES: dict[str, tuple[str, ...]] = {
    "pathtraver": ("WEB_UNTRUSTED_INPUT_TO_FILE_PATH",),
    "sqli": ("WEB_UNTRUSTED_INPUT_TO_SQL",),
    "xss": ("WEB_UNTRUSTED_INPUT_TO_HTML",),
    "cmdi": ("WEB_UNTRUSTED_INPUT_TO_COMMAND", "WEB_UNTRUSTED_INPUT_TO_PROCESS_ARGUMENT"),
    "redirect": ("API_OPEN_REDIRECT_REQUEST_INPUT",),
    "securecookie": ("AUTH_COOKIE_SECURITY_FLAG_DISABLED",),
}
OWASP_CRITICAL_CATEGORIES = {"sqli", "cmdi"}
OWASP_SUPPORTED_RULE_IDS = frozenset(rule for rules in OWASP_CATEGORY_RULES.values() for rule in rules)
_TEST_NAME_RE = re.compile(r"BenchmarkTest\d{5}", re.IGNORECASE)


def run_owasp_python_benchmark(
    repository_path: str | Path,
    output_dir: str | Path,
    *,
    expected_results_path: str | Path | None = None,
) -> dict[str, Any]:
    repository = Path(repository_path).resolve()
    testcode = repository / "testcode"
    expected_path = Path(expected_results_path).resolve() if expected_results_path else repository / "expectedresults-0.1.csv"
    if not testcode.is_dir():
        raise ValueError("OWASP Benchmark Python testcode directory was not found.")
    expected_rows = read_owasp_python_expected_results(expected_path)
    if not expected_rows:
        raise ValueError("OWASP Benchmark Python expected-results CSV contained no cases.")

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    scanner = KGuardScanner()
    primary_result = scanner.scan_workspace(repository, include_flow=True)
    repeat_result = scanner.scan_workspace(repository, include_flow=True)
    app_id = "owasp-benchmark-python-v0.1"
    target_id = "owasp-benchmark-python-testcode"
    started = datetime.now(UTC)
    primary_scored_findings = _owasp_scored_findings(primary_result.findings, expected_rows)
    repeat_scored_findings = _owasp_scored_findings(repeat_result.findings, expected_rows)
    supported_expected = {
        row["test_name"].lower(): set(OWASP_CATEGORY_RULES[row["category"]])
        for row in expected_rows
        if row["category"] in OWASP_CATEGORY_RULES
    }
    unexpected_supported_candidates = sum(
        1
        for finding in primary_scored_findings
        if str((finding.to_dict() if hasattr(finding, "to_dict") else finding).get("rule_id") or "")
        not in supported_expected.get(
            _test_name_from_finding(finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)).lower(),
            set(),
        )
    )
    outside_supported_candidates = (
        sum(
            1
            for finding in primary_result.findings
            if finding.severity in {"critical", "high"}
        )
        - len(primary_scored_findings)
    )
    workspace_snapshot = source_tree_snapshot(repository)
    target_ref = _ref(str(repository))
    primary = _guardian_wrapper(
        primary_scored_findings,
        app_id,
        target_id,
        started.isoformat(),
        scanner=scanner,
        evidence_input_path=expected_path,
        source_snapshot=workspace_snapshot,
        target_ref=target_ref,
    )
    repeat = _guardian_wrapper(
        repeat_scored_findings,
        app_id,
        target_id,
        (started + timedelta(microseconds=2)).isoformat(),
        scanner=scanner,
        evidence_input_path=expected_path,
        source_snapshot=workspace_snapshot,
        target_ref=target_ref,
    )
    primary_path = output / "primary-guardian.json"
    repeat_path = output / "repeat-guardian.json"
    _write_json(primary_path, primary)
    _write_json(repeat_path, repeat)

    revision = _git_revision(repository)
    source_ref = f"{OWASP_PYTHON_REPOSITORY}@{revision or 'unresolved'}#{_sha256_file(expected_path)}"
    ground_truth_path = output / "ground-truth.csv"
    review_path = output / "candidate-review.csv"
    _write_owasp_ground_truth(ground_truth_path, expected_rows, app_id, target_id, source_ref)
    _write_owasp_candidate_reviews(review_path, primary, expected_rows, app_id, target_id)
    validation = run_field_validation(primary_path, repeat_path, ground_truth_path, review_path, profile="benchmark")
    validation_path = output / "benchmark-validation.json"
    _write_json(validation_path, validation)

    score = score_owasp_python_findings(primary, expected_rows)
    report = {
        "schema": "k_guard_owasp_python_benchmark.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "method": "owasp_python_ground_truth_adapter",
        "dataset_role": "public_development_benchmark",
        "raw_free": True,
        "repository_ref": _ref(str(repository)),
        "revision_ref": _ref(revision),
        "expected_results_content_sha256": _sha256_file(expected_path),
        "supported_category_rules": {category: list(rules) for category, rules in sorted(OWASP_CATEGORY_RULES.items())},
        "score": score,
        "all_high_critical_candidate_validation": {
            "verdict_counts": validation.get("verdict_counts", {}),
            "case_counts": validation.get("case_counts", {}),
            "rates": validation.get("rates", {}),
            "evaluation": validation.get("evaluation", {}),
            "metric_contract": validation.get("metric_contract", {}),
            "raw_returned": False,
        },
        "supported_case_candidate_count": len(primary_scored_findings),
        "supported_case_unexpected_rule_candidate_count": unexpected_supported_candidates,
        "outside_supported_case_high_critical_finding_count": outside_supported_candidates,
        "unmapped_high_critical_finding_count": outside_supported_candidates,
        "repeat_reproducibility": validation.get("reproducibility", {}),
        "validation_claim_status": validation.get("claim_status"),
        "artifacts": {
            "primary_guardian": _file_ref(primary_path),
            "repeat_guardian": _file_ref(repeat_path),
            "ground_truth": _file_ref(ground_truth_path),
            "candidate_review": _file_ref(review_path),
            "benchmark_validation": _file_ref(validation_path),
        },
        "claim_boundary": {
            "public_benchmark_only": True,
            "used_for_rule_development_not_blind_holdout": True,
            "unsupported_categories_are_not_counted_as_detected": True,
            "does_not_establish_owned_partner_field_accuracy": True,
            "does_not_establish_business_logic_review": True,
            "raw_returned": False,
        },
    }
    report_path = output / "benchmark-score.json"
    _write_json(report_path, report)
    return report


def read_owasp_python_expected_results(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(handle):
            if not row or not row[0].strip() or row[0].lstrip().startswith("#"):
                continue
            if len(row) < 4:
                raise ValueError("Malformed OWASP expected-results row.")
            test_name = row[0].strip()
            if not re.fullmatch(r"BenchmarkTest\d{5}", test_name):
                raise ValueError("Unexpected OWASP benchmark test name.")
            real_value = row[2].strip().lower()
            if real_value not in {"true", "false"}:
                raise ValueError("OWASP real-vulnerability column must be true or false.")
            rows.append(
                {
                    "test_name": test_name,
                    "category": row[1].strip().lower(),
                    "real_vulnerability": real_value == "true",
                    "cwe": row[3].strip(),
                }
            )
    return rows


def score_owasp_python_findings(guardian_report: dict[str, Any], expected_rows: list[dict[str, Any]]) -> dict[str, Any]:
    expected_by_test = {row["test_name"].lower(): row for row in expected_rows}
    findings_by_test: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in _guardian_findings(guardian_report):
        test_name = _test_name_from_finding(finding)
        if test_name:
            findings_by_test[test_name.lower()].append(finding)

    counts: Counter[str] = Counter()
    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    unsupported: Counter[str] = Counter()
    case_results: list[dict[str, Any]] = []
    for test_key, row in expected_by_test.items():
        category = row["category"]
        if category not in OWASP_CATEGORY_RULES:
            unsupported[category] += 1
            continue
        rules = set(OWASP_CATEGORY_RULES[category])
        matched = [finding for finding in findings_by_test.get(test_key, []) if str(finding.get("rule_id") or "") in rules]
        if row["real_vulnerability"]:
            outcome = "true_positive" if matched else "false_negative"
        else:
            outcome = "false_positive" if matched else "true_negative"
        counts[outcome] += 1
        by_category[category][outcome] += 1
        case_results.append(
            {
                "case_ref": _ref(test_key),
                "category": category,
                "cwe": row["cwe"],
                "expected_vulnerable": row["real_vulnerability"],
                "outcome": outcome,
                "matched_rule_ids": sorted({str(finding.get("rule_id") or "") for finding in matched}),
                "raw_returned": False,
            }
        )
    tp = counts["true_positive"]
    fn = counts["false_negative"]
    fp = counts["false_positive"]
    tn = counts["true_negative"]
    tpr = _rate(tp, tp + fn)
    fpr = _rate(fp, fp + tn)
    return {
        "total_official_case_count": len(expected_rows),
        "supported_case_count": tp + fn + fp + tn,
        "unsupported_case_count": sum(unsupported.values()),
        "supported_category_count": len(by_category),
        "true_positive": tp,
        "false_negative": fn,
        "false_positive": fp,
        "true_negative": tn,
        "recall": tpr,
        "precision": _rate(tp, tp + fp),
        "false_positive_rate": fpr,
        "specificity": _rate(tn, tn + fp),
        "owasp_score": round(tpr - fpr, 6),
        "by_category": {
            category: {
                "case_count": sum(category_counts.values()),
                "true_positive": category_counts["true_positive"],
                "false_negative": category_counts["false_negative"],
                "false_positive": category_counts["false_positive"],
                "true_negative": category_counts["true_negative"],
                "recall": _rate(category_counts["true_positive"], category_counts["true_positive"] + category_counts["false_negative"]),
                "false_positive_rate": _rate(category_counts["false_positive"], category_counts["false_positive"] + category_counts["true_negative"]),
            }
            for category, category_counts in sorted(by_category.items())
        },
        "unsupported_categories": dict(sorted(unsupported.items())),
        "case_results": case_results,
    }


def run_public_app_smoke(path: str | Path) -> dict[str, Any]:
    root = Path(path).resolve()
    scanner = KGuardScanner()
    first = scanner.scan_workspace(root, include_flow=True)
    second = scanner.scan_workspace(root, include_flow=True)
    first_candidates = _dedupe_findings(first.findings)
    second_candidates = _dedupe_findings(second.findings)
    first_refs = {finding_fingerprint(item) for item in first_candidates}
    second_refs = {finding_fingerprint(item) for item in second_candidates}
    high_first = [item for item in first_candidates if str(item.get("severity") or "") in {"critical", "high"}]
    rules = Counter(str(item.get("rule_id") or "") for item in first_candidates)
    artifact_scopes = Counter(str(item.get("artifact_scope") or "workspace_evidence") for item in first_candidates)
    high_artifact_scopes = Counter(
        str(item.get("artifact_scope") or "workspace_evidence") for item in high_first
    )
    union = first_refs | second_refs
    return {
        "schema": "k_guard_public_app_smoke.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "method": "unlabeled_public_app_repeat_scan",
        "raw_free": True,
        "target_ref": _ref(str(root)),
        "finding_count": len(first_candidates),
        "high_critical_count": len(high_first),
        "top_rules": [{"rule_id": rule, "count": count} for rule, count in rules.most_common(20)],
        "artifact_scope_counts": dict(sorted(artifact_scopes.items())),
        "high_critical_artifact_scope_counts": dict(sorted(high_artifact_scopes.items())),
        "reproducibility": {
            "exact_finding_set_match": first_refs == second_refs,
            "finding_jaccard": _rate(len(first_refs & second_refs), len(union)) if union else 1.0,
            "first_finding_count": len(first_refs),
            "second_finding_count": len(second_refs),
        },
        "review_coverage": first.metadata.get("review_coverage", {}),
        "claim_status": "smoke_only_ground_truth_required",
        "claim_boundary": {
            "findings_are_unlabeled": True,
            "cannot_calculate_precision_or_recall": True,
            "does_not_count_as_owned_partner_validation": True,
            "raw_returned": False,
        },
    }


def _guardian_wrapper(
    findings: list[Any],
    app_id: str,
    target_id: str,
    generated_at: str,
    *,
    scanner: KGuardScanner,
    evidence_input_path: str | Path,
    source_snapshot: dict[str, Any],
    target_ref: dict[str, Any],
    allowed_rule_ids: frozenset[str] | None = None,
) -> dict[str, Any]:
    normalized = []
    for finding in findings:
        item = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        if allowed_rule_ids is not None and str(item.get("rule_id") or "") not in allowed_rule_ids:
            continue
        item["app_id"] = app_id
        item["target_id"] = target_id
        normalized.append(item)
    deduped = _dedupe_findings(normalized)
    targets = [
        {
            "app_id": app_id,
            "target_id": target_id,
            "kind": "workspace",
            "target_ref": target_ref,
            "kind_ref": target_ref,
            "locator_ref": target_ref,
            "status": "completed",
            "audit_profile": "public_benchmark",
            "coverage": {"coverage_gap": False, "raw_returned": False},
            "review_evidence": {"source_tree_snapshot": source_snapshot, "raw_returned": False},
            "findings": deduped,
            "rule_ids": sorted({str(item.get("rule_id") or "") for item in deduped}),
        }
    ]
    return build_validation_guardian_evidence(
        method="public_benchmark_scan",
        generated_at=generated_at,
        targets=targets,
        evidence_input_path=evidence_input_path,
        scanner=scanner,
    )


def _owasp_scored_findings(findings: list[Any], expected_rows: list[dict[str, Any]]) -> list[Any]:
    expected = {row["test_name"].lower(): row for row in expected_rows}
    scored: dict[tuple[str, str], Any] = {}
    for finding in findings:
        item = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        test_name = _test_name_from_finding(item)
        case = expected.get(test_name.lower()) if test_name else None
        if not case or case["category"] not in OWASP_CATEGORY_RULES:
            continue
        if str(item.get("severity") or "") not in {"critical", "high"}:
            continue
        rule_id = str(item.get("rule_id") or "")
        if not rule_id:
            continue
        # Keep one deterministic representative per case and rule. This removes
        # duplicate analyzer emissions without hiding unrelated high-severity
        # rules on a supported case; those candidates are reviewed as FP.
        scored.setdefault((test_name.lower(), rule_id), finding)
    return [scored[key] for key in sorted(scored)]


def _write_owasp_ground_truth(
    path: Path,
    expected_rows: list[dict[str, Any]],
    app_id: str,
    target_id: str,
    source_ref: str,
) -> None:
    supported = [row for row in expected_rows if row["category"] in OWASP_CATEGORY_RULES]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        for index, row in enumerate(supported, start=1):
            outcome = "vulnerable" if row["real_vulnerability"] else "clean"
            writer.writerow(
                {
                    "app_id": app_id,
                    "target_id": target_id,
                    "case_id": row["test_name"],
                    "severity": "critical" if row["category"] in OWASP_CRITICAL_CATEGORIES else "high",
                    "expected_outcome": outcome,
                    "expected_rule_ids": "|".join(OWASP_CATEGORY_RULES[row["category"]]),
                    "file": f"testcode/{row['test_name']}.py",
                    "line_start": "",
                    "line_end": "",
                    "stratum": ("top", "mid", "long_tail")[(index - 1) % 3],
                    "split": "development",
                    "source_kind": "public_benchmark",
                    "source_ref": source_ref,
                    "reproduction_count": 2,
                    "reviewer_1": "",
                    "verdict_1": "",
                    "reviewer_2": "",
                    "verdict_2": "",
                    "adjudicator": "",
                    "final_verdict": outcome,
                    "notes": "official OWASP expected result",
                }
            )


def _write_owasp_candidate_reviews(
    path: Path,
    guardian_report: dict[str, Any],
    expected_rows: list[dict[str, Any]],
    app_id: str,
    target_id: str,
) -> None:
    expected = {row["test_name"].lower(): row for row in expected_rows}
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        for finding in _guardian_findings(guardian_report):
            if str(finding.get("severity") or "") not in {"critical", "high"}:
                continue
            test_name = _test_name_from_finding(finding)
            case = expected.get(test_name.lower()) if test_name else None
            rules = set(OWASP_CATEGORY_RULES.get(str(case.get("category")) if case else "", ()))
            verdict = (
                "true_positive"
                if case and case["real_vulnerability"] and str(finding.get("rule_id") or "") in rules
                else "false_positive"
            )
            writer.writerow(
                {
                    "app_id": app_id,
                    "target_id": target_id,
                    "rule_id": finding.get("rule_id", ""),
                    "finding_fingerprint": finding_fingerprint(finding),
                    "reviewer_1": "owasp-ground-truth-adapter",
                    "verdict_1": verdict,
                    "reviewer_2": "",
                    "verdict_2": "",
                    "adjudicator": "",
                    "final_verdict": verdict,
                    "notes": "machine-mapped to official expected result",
                }
            )


def _guardian_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        for finding in target.get("findings", []):
            if isinstance(finding, dict):
                item = dict(finding)
                item.setdefault("app_id", target.get("app_id", ""))
                item.setdefault("target_id", target.get("target_id", ""))
                result.append(item)
    return result


def _dedupe_findings(findings: list[Any]) -> list[dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for finding in findings:
        item = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        result.setdefault(finding_fingerprint(item), item)
    return list(result.values())


def _test_name_from_finding(finding: dict[str, Any]) -> str:
    match = _TEST_NAME_RE.search(str(finding.get("file") or finding.get("url") or ""))
    return match.group(0) if match else ""


def _git_revision(repository: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return ""
    revision = completed.stdout.strip().lower()
    return revision if re.fullmatch(r"[0-9a-f]{40}", revision) else ""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file_ref(path: Path) -> dict[str, Any]:
    return {
        "path_ref": _ref(str(path)),
        "content_sha256": _sha256_file(path),
        "byte_count": path.stat().st_size,
        "raw_returned": False,
    }


def _ref(value: object) -> dict[str, Any]:
    return {"hash": evidence_hash(str(value)), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0
