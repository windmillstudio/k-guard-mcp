from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from k_guard_mcp.l1_benchmark import L1BenchmarkError, run_l1_baseline, write_l1_baseline_report


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _file_row(root: Path, path: Path) -> dict:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256(path),
        "byte_count": path.stat().st_size,
        "git_blob_sha1": "a" * 40,
        "mode": "100644",
    }


def _corpus(root: Path, *, language: str, cases: list[tuple[str, str, str]]) -> dict:
    suffix = ".java" if language == "java" else ".py"
    prefix = "src/main/java/testcode" if language == "java" else "testcode"
    source_rows = []
    for case_id, category, truth in cases:
        source = root / prefix / f"{case_id}{suffix}"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"// {case_id} {category} {truth}\n", encoding="utf-8")
        source_rows.append(
            {
                "case_id": case_id,
                "category": category,
                "cwe": "CWE-89" if category == "sqli" else "CWE-22",
                "source_bytes": source.stat().st_size,
                "source_path": source.relative_to(root).as_posix(),
                "source_sha256": _sha256(source),
                "truth": truth,
            }
        )
    expected = root / ("expectedresults-1.2.csv" if language == "java" else "expectedresults-0.1.csv")
    expected.write_text("official expected results\n", encoding="utf-8")
    license_path = root / "LICENSE"
    license_path.write_text("license\n", encoding="utf-8")
    files = [_file_row(root, path) for path in sorted(root.rglob("*")) if path.is_file()]
    return {
        "case_set_schema": "fixture",
        "case_set_sha256": "b" * 64,
        "cases": source_rows,
        "commit_tree_sha1": "c" * 40,
        "corpus_id": f"fixture-{language}",
        "expected_results": {
            "path": expected.relative_to(root).as_posix(),
            "sha256": _sha256(expected),
            "byte_count": expected.stat().st_size,
            "row_count": len(cases),
            "unique_case_count": len(cases),
        },
        "language": language,
        "license": {
            "path": "LICENSE",
            "sha256": _sha256(license_path),
            "byte_count": license_path.stat().st_size,
            "spdx": "MIT",
        },
        "repository_origin": "https://example.invalid/fixture.git",
        "revision_sha1": "d" * 40,
        "source_tree": {
            "file_count": len(files),
            "files": files,
            "index_tree_match": True,
            "no_untracked_or_ignored_physical_files": True,
            "physical_bytes_match_git_blobs": True,
            "schema": "k_guard_materialized_source_tree.v1",
            "source_tree_sha256": "e" * 64,
            "source_worktree_clean": True,
            "source_worktree_clean_method": "fixture",
            "total_bytes": sum(row["byte_count"] for row in files),
        },
    }


def _manifest(tmp_path: Path) -> tuple[Path, Path, Path]:
    java_root = tmp_path / "java"
    python_root = tmp_path / "python"
    java = _corpus(
        java_root,
        language="java",
        cases=[
            ("BenchmarkTest00001", "sqli", "present"),
            ("BenchmarkTest00002", "sqli", "absent"),
            ("BenchmarkTest00003", "crypto", "present"),
        ],
    )
    python = _corpus(
        python_root,
        language="python",
        cases=[
            ("BenchmarkTest00011", "pathtraver", "present"),
            ("BenchmarkTest00012", "pathtraver", "absent"),
            ("BenchmarkTest00013", "xpathi", "present"),
        ],
    )
    manifest = {
        "corpora": [java, python],
        "corpus_count": 2,
        "coverage_policy": "all_official_rows_exactly_once",
        "lane": "L1",
        "scanner_output_observed": False,
        "schema": "k_guard_l1_corpus_manifest.v1",
        "status": "locked_before_scan",
        "total_case_count": 6,
        "unsupported_detector_category_policy": "retain_in_denominator",
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return path, java_root, python_root


class _FixtureScanner:
    def scan_workspace(self, root: Path, *, include_flow: bool) -> SimpleNamespace:
        assert include_flow is True
        if root.name == "java":
            findings = [
                {
                    "source": "fixture-scanner",
                    "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                    "severity": "critical",
                    "file": str(root / "src/main/java/testcode/BenchmarkTest00001.java"),
                    "line_start": 1,
                    "line_end": 1,
                },
                {
                    "source": "fixture-scanner",
                    "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                    "severity": "critical",
                    "file": str(root / "src/main/java/testcode/BenchmarkTest00002.java"),
                    "line_start": 1,
                    "line_end": 1,
                },
                {
                    "source": "fixture-scanner",
                    "rule_id": "OUTSIDE_CASE_HIGH",
                    "severity": "high",
                    "file": str(root / "LICENSE"),
                    "line_start": 1,
                    "line_end": 1,
                },
            ]
        else:
            findings = [
                {
                    "source": "fixture-scanner",
                    "rule_id": "WEB_UNTRUSTED_INPUT_TO_FILE_PATH",
                    "severity": "high",
                    "file": str(root / "testcode/BenchmarkTest00011.py"),
                    "line_start": 1,
                    "line_end": 1,
                },
                {
                    "source": "fixture-scanner",
                    "rule_id": "UNMAPPED_HIGH_RULE",
                    "severity": "high",
                    "file": str(root / "testcode/BenchmarkTest00011.py"),
                    "line_start": 1,
                    "line_end": 1,
                },
            ]
        return SimpleNamespace(findings=findings)


def test_l1_baseline_retains_full_denominator_and_unpaired_candidates(tmp_path: Path) -> None:
    manifest, java_root, python_root = _manifest(tmp_path)

    report = run_l1_baseline(
        manifest,
        benchmark_java=java_root,
        benchmark_python=python_root,
        scanner_factory=_FixtureScanner,
        execution_binding={
            "baseline_receipt_sha256": "f" * 64,
            "target": {
                "head_git_oid": "1" * 40,
                "dirty_path_set_sha256": "2" * 64,
                "dirty_worktree_sha256": "3" * 64,
            },
        },
    )

    assert report["complete"] is True
    assert report["status"] == "MEASURED_HOLD"
    assert report["repeat"]["exact"] is True
    aggregate = report["aggregate"]
    assert aggregate["official_denominator"] == {
        "total_case_count": 6,
        "supported_case_count": 4,
        "unsupported_case_count": 2,
        "unsupported_cases_retained": True,
        "full_official_metric_eligible": False,
    }
    assert aggregate["scenario_metrics"]["metrics"]["confusion_matrix"] == {
        "tp": 2,
        "fp": 1,
        "fn": 0,
        "tn": 1,
    }
    assert aggregate["candidate_oracle_coverage"]["unpaired_candidate_count"] == 2
    assert aggregate["candidate_oracle_coverage"]["one_finding_to_one_oracle_complete"] is False
    assert aggregate["candidate_oracle_coverage"]["candidate_precision_eligible"] is False
    assert aggregate["candidate_oracle_coverage"]["labeled_candidate_precision"] == 0.666667
    assert report["gate_eligibility"]["release_gate_passed"] is False
    encoded = json.dumps(report, sort_keys=True)
    assert str(java_root) not in encoded
    assert str(python_root) not in encoded


def test_l1_baseline_fails_closed_when_materialized_source_changes(tmp_path: Path) -> None:
    manifest, java_root, python_root = _manifest(tmp_path)
    source = java_root / "src/main/java/testcode/BenchmarkTest00001.java"
    source.write_text("changed\n", encoding="utf-8")

    report = run_l1_baseline(
        manifest,
        benchmark_java=java_root,
        benchmark_python=python_root,
        scanner_factory=_FixtureScanner,
    )

    assert report["complete"] is False
    assert report["status"] == "CONTROL_HOLD"
    assert report["control_errors"] == ["corpus_tree_content_mismatch"]


def test_l1_baseline_writer_never_overwrites(tmp_path: Path) -> None:
    manifest, java_root, python_root = _manifest(tmp_path)
    report = run_l1_baseline(
        manifest,
        benchmark_java=java_root,
        benchmark_python=python_root,
        scanner_factory=_FixtureScanner,
    )
    output = tmp_path / "evidence" / "l1.json"

    write_l1_baseline_report(report, output)

    with pytest.raises(L1BenchmarkError, match="baseline_output_already_exists"):
        write_l1_baseline_report(report, output)
