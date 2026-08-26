from __future__ import annotations

import json
from pathlib import Path

from k_guard_mcp.benchmark_adapters import (
    _owasp_scored_findings,
    read_owasp_python_expected_results,
    run_owasp_python_benchmark,
    run_public_app_smoke,
    score_owasp_python_findings,
)


def _mini_owasp_repo(root: Path, case_count: int = 60) -> Path:
    testcode = root / "testcode"
    testcode.mkdir(parents=True)
    expected = ["# test name, category, real vulnerability, cwe, Benchmark version: test"]
    for index in range(1, case_count + 1):
        test_name = f"BenchmarkTest{index:05d}"
        vulnerable = index <= case_count // 2
        expected.append(f"{test_name},pathtraver,{'true' if vulnerable else 'false'},22")
        body = (
            "from flask import request\n"
            "def handler():\n"
            "    return open(request.args.get('file'), 'r')\n"
            if vulnerable
            else "def handler():\n    return open('safe.txt', 'r')\n"
        )
        (testcode / f"{test_name}.py").write_text(body, encoding="utf-8")
    (root / "expectedresults-0.1.csv").write_text("\n".join(expected) + "\n", encoding="utf-8")
    return root


def test_read_owasp_expected_results_skips_metadata_comment(tmp_path):
    repository = _mini_owasp_repo(tmp_path)

    rows = read_owasp_python_expected_results(repository / "expectedresults-0.1.csv")

    assert len(rows) == 60
    assert rows[0] == {
        "test_name": "BenchmarkTest00001",
        "category": "pathtraver",
        "real_vulnerability": True,
        "cwe": "22",
    }


def test_owasp_score_separates_supported_and_unsupported_categories():
    expected = [
        {"test_name": "BenchmarkTest00001", "category": "pathtraver", "real_vulnerability": True, "cwe": "22"},
        {"test_name": "BenchmarkTest00002", "category": "pathtraver", "real_vulnerability": False, "cwe": "22"},
        {"test_name": "BenchmarkTest00003", "category": "xpathi", "real_vulnerability": True, "cwe": "643"},
    ]
    guardian = {
        "targets": [
            {
                "findings": [
                    {
                        "rule_id": "WEB_UNTRUSTED_INPUT_TO_FILE_PATH",
                        "severity": "high",
                        "file": "testcode/BenchmarkTest00001.py",
                    }
                ]
            }
        ]
    }

    score = score_owasp_python_findings(guardian, expected)

    assert score["supported_case_count"] == 2
    assert score["unsupported_case_count"] == 1
    assert score["recall"] == 1.0
    assert score["false_positive_rate"] == 0.0


def test_owasp_candidate_pack_keeps_unexpected_high_rules_on_supported_cases():
    expected = [
        {"test_name": "BenchmarkTest00001", "category": "pathtraver", "real_vulnerability": True, "cwe": "22"},
        {"test_name": "BenchmarkTest00002", "category": "xpathi", "real_vulnerability": True, "cwe": "643"},
    ]
    findings = [
        {"rule_id": "WEB_UNTRUSTED_INPUT_TO_FILE_PATH", "severity": "high", "file": "testcode/BenchmarkTest00001.py", "line_start": 1},
        {"rule_id": "UNEXPECTED_HIGH_RULE", "severity": "high", "file": "testcode/BenchmarkTest00001.py", "line_start": 2},
        {"rule_id": "UNEXPECTED_HIGH_RULE", "severity": "high", "file": "testcode/BenchmarkTest00001.py", "line_start": 3},
        {"rule_id": "UNEXPECTED_HIGH_RULE", "severity": "high", "file": "testcode/BenchmarkTest00002.py", "line_start": 4},
    ]

    candidates = _owasp_scored_findings(findings, expected)

    assert {(item["file"], item["rule_id"]) for item in candidates} == {
        ("testcode/BenchmarkTest00001.py", "WEB_UNTRUSTED_INPUT_TO_FILE_PATH"),
        ("testcode/BenchmarkTest00001.py", "UNEXPECTED_HIGH_RULE"),
    }


def test_owasp_adapter_builds_reproducible_ground_truth_pack(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "owasp-benchmark-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    repository = _mini_owasp_repo(tmp_path / "benchmark")

    report = run_owasp_python_benchmark(repository, tmp_path / "output")

    assert report["score"]["supported_case_count"] == 60
    assert report["score"]["recall"] == 1.0
    assert report["score"]["false_positive_rate"] == 0.0
    assert report["repeat_reproducibility"]["exact_candidate_set_match"] is True
    assert report["repeat_reproducibility"]["distinct_execution_ids"] is True
    assert report["repeat_reproducibility"]["distinct_execution_attestations"] is True
    assert report["repeat_reproducibility"]["distinct_evidence_bundles"] is True
    assert report["repeat_reproducibility"]["toolchain_contract_match"] is True
    assert report["repeat_reproducibility"]["workspace_source_snapshots_match"] is True
    assert report["repeat_reproducibility"]["guardian_manifest_content_match"] is True
    assert report["repeat_reproducibility"]["target_input_bindings_match"] is True
    assert report["validation_claim_status"] == "public_benchmark_ready"
    validation = json.loads((tmp_path / "output" / "benchmark-validation.json").read_text(encoding="utf-8"))
    checks = {item["name"]: item for item in validation["gate_checks"]}
    assert validation["thresholds"]["min_precision"] == 0.9
    assert validation["thresholds"]["min_precision_confidence_lower"] == 0.8
    assert checks["candidate_precision"]["passed"] is True
    assert checks["candidate_precision_confidence_lower"]["passed"] is True
    assert validation["boundary"]["public_benchmark_does_not_equal_field_validation"] is True
    primary = json.loads((tmp_path / "output" / "primary-guardian.json").read_text(encoding="utf-8"))
    assert primary["validation_execution"]["release_authority"] is False


def test_public_app_smoke_is_explicitly_unlabeled(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "app.py").write_text("def handler():\n    return 'ok'\n", encoding="utf-8")

    report = run_public_app_smoke(app)

    assert report["reproducibility"]["exact_finding_set_match"] is True
    assert report["claim_status"] == "smoke_only_ground_truth_required"
    assert report["claim_boundary"]["cannot_calculate_precision_or_recall"] is True
