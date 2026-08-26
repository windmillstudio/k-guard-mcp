from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme
from k_guard_mcp.scanner import KGuardScanner

MIN_GOVERNANCE_POSITIVE_CASES = 3
MIN_GOVERNANCE_NEGATIVE_CASES = 2
REQUIRED_GOVERNANCE_RULES = {
    "KR_DATA_UNIQUE_IDENTIFIER_CONTROL_GAP",
    "KR_DATA_SENSITIVE_INFORMATION_CONTROL_GAP",
    "KR_DATA_LINKABLE_IDENTIFIER_CONTROL_GAP",
    "KR_DATA_ACCESS_LOG_EVIDENCE_MISSING",
}


def evaluate_fixture_corpus(corpus_path: str | Path, scanner: KGuardScanner | None = None) -> dict[str, Any]:
    path = Path(corpus_path)
    corpus = json.loads(path.read_text(encoding="utf-8"))
    scanner = scanner or KGuardScanner()

    positive_results = []
    hits = 0
    for case_index, case in enumerate(corpus.get("positives", []), start=1):
        result = scanner.scan_text(str(case.get("text", "")), case.get("file", "fixture.txt"))
        rules = sorted({finding.rule_id for finding in result.findings})
        expected_any = list(case.get("expected_any", []))
        passed = any(rule in rules for rule in expected_any)
        hits += int(passed)
        positive_results.append({**_case_ref(case.get("name", "positive"), case_index, "positive"), "passed": passed, "rules": rules, "expected_any": expected_any})

    negative_results = []
    false_positive_cases = 0
    measurable_negatives = 0
    targeted_absence_cases = 0
    for case_index, case in enumerate(corpus.get("negatives", []), start=1):
        result = scanner.scan_text(str(case.get("text", "")), case.get("file", "negative.txt"))
        rules = sorted({finding.rule_id for finding in result.findings})
        expected_absent = list(case.get("expected_absent", []))
        absent_ok = all(rule not in rules for rule in expected_absent)
        measured = "expected_absent" not in case
        if measured:
            measurable_negatives += 1
            false_positive_cases += int(bool(rules))
        else:
            targeted_absence_cases += 1
        negative_results.append({**_case_ref(case.get("name", "negative"), case_index, "negative"), "passed": absent_ok and (not measured or not rules), "rules": rules, "expected_absent": expected_absent})

    positives = len(corpus.get("positives", []))
    recall = hits / positives if positives else 0.0
    false_positive_rate = 0.0 if measurable_negatives == 0 else false_positive_cases / measurable_negatives
    workspace_results = []
    for case_index, case in enumerate(corpus.get("workspace_cases", []), start=1):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for relative_name, content in dict(case.get("files", {})).items():
                relative = Path(str(relative_name))
                if relative.is_absolute() or ".." in relative.parts:
                    continue
                output = root / relative
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(str(content), encoding="utf-8")
            result = scanner.scan_workspace(root, include_flow=bool(case.get("include_flow", False)))
        rules = sorted({finding.rule_id for finding in result.findings})
        expected_any = list(case.get("expected_any", []))
        expected_all = list(case.get("expected_all", []))
        expected_absent = list(case.get("expected_absent", []))
        is_governance_negative = not expected_any and not expected_all and bool(expected_absent)
        emitted_governance_rules = [rule for rule in rules if rule.startswith("KR_DATA_")]
        passed = (
            (not expected_any or any(rule in rules for rule in expected_any))
            and all(rule in rules for rule in expected_all)
            and all(rule not in rules for rule in expected_absent)
            and (not is_governance_negative or not emitted_governance_rules)
        )
        workspace_results.append(
            {
                **_case_ref(case.get("name", "workspace"), case_index, "workspace"),
                "passed": passed,
                "rules": rules,
                "expected_any": expected_any,
                "expected_all": expected_all,
                "expected_absent": expected_absent,
            }
        )
    workspace_positive_results = [item for item in workspace_results if item["expected_any"] or item["expected_all"]]
    workspace_negative_results = [item for item in workspace_results if not item["expected_any"] and not item["expected_all"] and item["expected_absent"]]
    governance_rules = {rule for item in workspace_results for rule in item["rules"] if rule.startswith("KR_DATA_")}
    missing_governance_rules = sorted(REQUIRED_GOVERNANCE_RULES - governance_rules)
    governance_coverage = {
        "required_rules": sorted(REQUIRED_GOVERNANCE_RULES),
        "observed_rules": sorted(governance_rules),
        "missing_required_rules": missing_governance_rules,
        "all_required_rules_observed": not missing_governance_rules,
        "raw_returned": False,
    }
    workspace_contract_passed = (
        len(workspace_positive_results) >= MIN_GOVERNANCE_POSITIVE_CASES
        and len(workspace_negative_results) >= MIN_GOVERNANCE_NEGATIVE_CASES
        and not missing_governance_rules
        and all(item["passed"] for item in workspace_results)
    )
    report = {
        "fixture_ref": {
            "hash": evidence_hash(str(path)),
            "hash_scheme": evidence_hash_scheme(),
            "raw_returned": False,
        },
        "raw_free": True,
        "positive_count": positives,
        "negative_count": len(corpus.get("negatives", [])),
        "measurable_negative_count": measurable_negatives,
        "targeted_absence_case_count": targeted_absence_cases,
        "false_positive_count": false_positive_cases,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "false_positive_rate_denominator": measurable_negatives,
        "false_positive_rate_denominator_name": "measurable_negative_count",
        "thresholds": {
            "minimum_recall": 0.95,
            "maximum_false_positive_rate": 0.2,
            "false_positive_rate_denominator": "measurable_negative_count",
            "minimum_governance_positive_cases": MIN_GOVERNANCE_POSITIVE_CASES,
            "minimum_governance_negative_cases": MIN_GOVERNANCE_NEGATIVE_CASES,
        },
        "workspace_case_count": len(workspace_results),
        "workspace_passed_count": sum(1 for item in workspace_results if item["passed"]),
        "workspace_positive_case_count": len(workspace_positive_results),
        "workspace_negative_case_count": len(workspace_negative_results),
        "workspace_positive_passed_count": sum(1 for item in workspace_positive_results if item["passed"]),
        "workspace_negative_passed_count": sum(1 for item in workspace_negative_results if item["passed"]),
        "passed": recall >= 0.95 and false_positive_rate <= 0.2 and all(item["passed"] for item in negative_results) and workspace_contract_passed,
        "coverage": _coverage_summary(positive_results),
        "governance_coverage": governance_coverage,
        "positives": positive_results,
        "negatives": negative_results,
        "workspace_cases": workspace_results,
    }
    return report


def _case_ref(name: object, index: int, cohort: str) -> dict[str, Any]:
    return {
        "case_index": index,
        "case_ref": evidence_hash(f"{cohort}:{name}"),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _coverage_summary(positive_results: list[dict[str, Any]]) -> dict[str, Any]:
    observed = {rule for item in positive_results for rule in item.get("rules", [])}
    expected = {rule for item in positive_results for rule in item.get("expected_any", [])}
    required_direct = {
        "PII_RRN",
        "PII_FRN",
        "PII_PASSPORT",
        "PII_DRIVER_LICENSE",
        "PII_CI",
        "PII_DI",
        "PII_HEALTH_INSURANCE_ID",
        "PII_BANK_ACCOUNT",
        "PII_CREDIT_CARD",
    }
    required_composite = {
        "KR_COMBO_PERSON_RRN",
        "KR_COMBO_PERSON_BANK_ACCOUNT",
        "KR_COMBO_PERSON_CI",
        "KR_COMBO_MEDICAL_PATIENT_ID",
        "KR_COMBO_SENSITIVE_DIRECT_IDENTIFIER",
    }
    required_org = {
        "KR_ORG_BUSINESS_REGISTRATION",
        "KR_ORG_CORPORATE_REGISTRATION",
    }
    required = required_direct | required_composite | required_org
    return {
        "expected_rule_count": len(expected),
        "observed_rule_count": len(observed),
        "required_direct_unique_rules": sorted(required_direct),
        "required_composite_rules": sorted(required_composite),
        "required_org_rules": sorted(required_org),
        "missing_required_rules": sorted(rule for rule in required if rule not in observed),
        "all_required_rules_observed": required.issubset(observed),
    }


def write_fixture_scoreboard(corpus_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    report = evaluate_fixture_corpus(corpus_path)
    Path(output_path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report
