from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from scripts.run_public_app_campaign import _contains_workspace_path, _run_scan
except ModuleNotFoundError:  # Direct execution places scripts/ rather than the repository root on sys.path.
    from run_public_app_campaign import _contains_workspace_path, _run_scan


ROOT = Path(__file__).resolve().parents[1]
PREREG_SCHEMA = "k_guard_public_holdout_preregistration.v1"
REPORT_SCHEMA = "k_guard_public_holdout_result.v1"
CASE_RE = re.compile(r"BenchmarkTest\d{5}")


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(path: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(path), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "git command failed")
    return completed.stdout.strip()


def _load_cwe89_ground_truth(path: Path) -> dict[str, bool]:
    rows: dict[str, bool] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.reader(line for line in stream if not line.lstrip().startswith("#"))
        for row in reader:
            if len(row) < 4 or row[3].strip() != "89":
                continue
            case_id = row[0].strip()
            if CASE_RE.fullmatch(case_id) is None or case_id in rows:
                raise ValueError(f"invalid or duplicate CWE-89 case: {case_id or 'missing'}")
            label = row[2].strip().lower()
            if label not in {"true", "false"}:
                raise ValueError(f"invalid CWE-89 label: {case_id}")
            rows[case_id] = label == "true"
    return rows


def _case_predictions(report: dict[str, Any], positive_rules: set[str]) -> tuple[set[str], dict[str, list[str]], int]:
    predictions: set[str] = set()
    finding_refs: dict[str, list[str]] = {}
    unmatched = 0
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        if str(finding.get("rule_id") or "") not in positive_rules:
            continue
        if str(finding.get("severity") or "") not in {"critical", "high"}:
            continue
        match = CASE_RE.search(str(finding.get("file") or ""))
        if match is None:
            unmatched += 1
            continue
        case_id = match.group(0)
        predictions.add(case_id)
        canonical = "|".join(
            (
                case_id,
                str(finding.get("rule_id") or ""),
                str(finding.get("line_start") or 0),
                str(finding.get("evidence") or ""),
            )
        )
        finding_refs.setdefault(case_id, []).append(hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20])
    for refs in finding_refs.values():
        refs.sort()
    return predictions, finding_refs, unmatched


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    observed = successes / total
    denominator = 1 + z * z / total
    centre = observed + z * z / (2 * total)
    margin = z * math.sqrt((observed * (1 - observed) + z * z / (4 * total)) / total)
    return round((centre - margin) / denominator, 6)


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _score(
    ground_truth: dict[str, bool],
    predictions: set[str],
    finding_refs: dict[str, list[str]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    confusion = Counter()
    cases: list[dict[str, Any]] = []
    for case_id, vulnerable in sorted(ground_truth.items()):
        predicted = case_id in predictions
        outcome = "tp" if vulnerable and predicted else "fn" if vulnerable else "fp" if predicted else "tn"
        confusion[outcome] += 1
        cases.append(
            {
                "case_id": case_id,
                "expected": "vulnerable" if vulnerable else "clean",
                "predicted": "vulnerable" if predicted else "clean",
                "outcome": outcome,
                "finding_refs": finding_refs.get(case_id, []),
                "raw_returned": False,
            }
        )
    tp, fp, fn, tn = (confusion[name] for name in ("tp", "fp", "fn", "tn"))
    precision_total = tp + fp
    recall_total = tp + fn
    specificity_total = tn + fp
    metrics = {
        "total_cases": len(ground_truth),
        "vulnerable_cases": recall_total,
        "clean_cases": specificity_total,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": _ratio(tp, precision_total),
        "precision_wilson_95_lower": _wilson_lower(tp, precision_total),
        "recall": _ratio(tp, recall_total),
        "recall_wilson_95_lower": _wilson_lower(tp, recall_total),
        "specificity": _ratio(tn, specificity_total),
        "specificity_wilson_95_lower": _wilson_lower(tn, specificity_total),
    }
    return metrics, cases


def _threshold_checks(metrics: dict[str, Any], thresholds: dict[str, Any]) -> dict[str, bool]:
    mapping = {
        "minimum_total_cases": "total_cases",
        "minimum_vulnerable_cases": "vulnerable_cases",
        "minimum_clean_cases": "clean_cases",
        "minimum_precision": "precision",
        "minimum_precision_wilson_95_lower": "precision_wilson_95_lower",
        "minimum_recall": "recall",
        "minimum_recall_wilson_95_lower": "recall_wilson_95_lower",
        "minimum_specificity": "specificity",
        "minimum_specificity_wilson_95_lower": "specificity_wilson_95_lower",
    }
    return {
        threshold: float(metrics[metric]) >= float(thresholds[threshold])
        for threshold, metric in mapping.items()
    }


def run(preregistration: Path, source: Path, output_dir: Path) -> dict[str, Any]:
    prereg = _read_json(preregistration)
    if prereg.get("schema") != PREREG_SCHEMA or prereg.get("status") != "locked_before_checkout_and_scan":
        raise ValueError("holdout preregistration is not locked")
    registered_scanner = str(prereg.get("scanner_revision") or "")
    expected_source = str(prereg.get("source", {}).get("revision") or "")
    positive_rules = set(prereg.get("locked_mapping", {}).get("positive_rule_ids") or [])
    if not positive_rules:
        raise ValueError("holdout positive rules are empty")

    actual_source = _git(source, "rev-parse", "HEAD")
    source_clean = not _git(source, "status", "--porcelain")
    scanner_clean = not _git(ROOT, "status", "--porcelain")
    scanner_source_unchanged = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--quiet", registered_scanner, "HEAD", "--", "src/k_guard_mcp"],
        check=False,
    ).returncode == 0
    if actual_source != expected_source or not source_clean or not scanner_clean or not scanner_source_unchanged:
        raise RuntimeError("holdout source or scanner integrity check failed")

    ground_truth_path = source / "expectedresults-1.2.csv"
    license_path = source / "LICENSE"
    ground_truth = _load_cwe89_ground_truth(ground_truth_path)
    missing_sources = [
        case_id
        for case_id in ground_truth
        if not (source / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode" / f"{case_id}.java").is_file()
    ]
    if missing_sources or not license_path.is_file():
        raise RuntimeError("holdout ground truth, source cases, or license is incomplete")

    output_dir.mkdir(parents=True, exist_ok=True)
    runs: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    for run_number in (1, 2):
        report_path = output_dir / f"benchmarkjava-run{run_number}.json"
        exit_code, duration, report_hash, report = _run_scan(source, report_path)
        if exit_code != 0 or _contains_workspace_path(report, source):
            raise RuntimeError(f"holdout scan run {run_number} failed integrity checks")
        runs.append(
            {
                "run": run_number,
                "exit_code": exit_code,
                "duration_seconds": duration,
                "report_sha256": report_hash,
            }
        )
        reports.append(report)

    exact_repeat = len({run["report_sha256"] for run in runs}) == 1
    first_predictions, finding_refs, unmatched = _case_predictions(reports[0], positive_rules)
    repeat_predictions, repeat_refs, repeat_unmatched = _case_predictions(reports[1], positive_rules)
    prediction_repeat = first_predictions == repeat_predictions and finding_refs == repeat_refs
    metrics, cases = _score(ground_truth, first_predictions, finding_refs)
    thresholds = dict(prereg.get("locked_thresholds") or {})
    checks = _threshold_checks(metrics, thresholds)
    integrity = {
        "preregistration_locked": True,
        "source_revision_matches": actual_source == expected_source,
        "source_worktree_clean": source_clean,
        "scanner_worktree_clean": scanner_clean,
        "scanner_source_unchanged_since_registration": scanner_source_unchanged,
        "ground_truth_and_sources_complete": not missing_sources,
        "minimum_two_runs": len(runs) >= 2,
        "exact_report_repeat": exact_repeat,
        "exact_prediction_repeat": prediction_repeat,
        "workspace_path_redaction": True,
        "unmatched_positive_finding_count_stable": unmatched == repeat_unmatched,
    }
    passed = all(integrity.values()) and all(checks.values())
    result = {
        "schema": REPORT_SCHEMA,
        "holdout_id": prereg.get("holdout_id"),
        "verdict": "pass" if passed else "hold",
        "passed": passed,
        "scanner_revision": registered_scanner,
        "execution_revision": _git(ROOT, "rev-parse", "HEAD"),
        "source": {
            "repository": prereg.get("source", {}).get("repository"),
            "revision": actual_source,
            "ground_truth_sha256": _sha256(ground_truth_path),
            "license_sha256": _sha256(license_path),
        },
        "preregistration_sha256": _sha256(preregistration),
        "positive_rule_ids": sorted(positive_rules),
        "runs": runs,
        "integrity": integrity,
        "metrics": metrics,
        "thresholds": thresholds,
        "threshold_checks": checks,
        "unmatched_positive_finding_count": unmatched,
        "cases": cases,
        "claim_boundary": prereg.get("claim_boundary"),
        "raw_returned": False,
    }
    output = output_dir / "holdout-result.json"
    output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the preregistered OWASP BenchmarkJava CWE-89 holdout once.")
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.preregistration.resolve(), args.source.resolve(), args.output_dir.resolve())
    print(json.dumps({"holdout_id": result["holdout_id"], "verdict": result["verdict"], "metrics": result["metrics"]}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
