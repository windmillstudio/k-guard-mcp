from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "compare_maven_osv_observe_repeats.py"
SPEC = importlib.util.spec_from_file_location("compare_maven_osv_observe_repeats_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = comparison
SPEC.loader.exec_module(comparison)


def _report(*, package_ref: str = "b" * 64, raw_hash: str = "a" * 64) -> dict:
    matches = []
    matches = [
        {
            "package_ref_sha256": package_ref,
            "version_ref_sha256": "c" * 64,
            "ecosystem_ref_sha256": "d" * 64,
            "severity": "critical",
        }
    ]
    def side(count: int, stdout: str) -> dict:
        return {
            "exit_code": 1,
            "result_count": 1,
            "package_count": 1,
            "vulnerability_count": 1,
            "expected_cve_match_count": count,
            "expected_cve_matches": matches if count else [],
            "stdout_sha256": stdout,
        }
    return {
        "schema": "k_guard_maven_osv_observe_ab.v1",
        "hypothesis": {"id": "H5A", "stage": "observe", "warning_promotion_admitted": False, "blocking_promotion_admitted": False},
        "expected_cve": "CVE-2013-7285",
        "complete": True,
        "status": "MEASURED_HOLD",
        "engine": {"version": "2.4.0"},
        "inputs": {"positive_pom": {"sha256": "e" * 64}},
        "execution_binding": {"baseline_receipt_sha256": "f" * 64, "target": {"dirty_worktree_sha256": "0" * 64}},
        "oracle": {"pair_admitted": True},
        "repeat": {"semantic_exact": True},
        "runs": [
            {"positive": side(1, raw_hash), "negative": side(0, raw_hash)},
            {"positive": side(1, raw_hash), "negative": side(0, raw_hash)},
        ],
    }


def test_h5a_repeat_comparison_keeps_raw_variance_visible_without_promoting_maven_sca() -> None:
    first = _report(raw_hash="a" * 64)
    second = _report(raw_hash="b" * 64)
    report = comparison.compare_reports(
        first,
        second,
        first_sha256=hashlib.sha256(comparison._canonical_bytes(first)).hexdigest(),
        second_sha256=hashlib.sha256(comparison._canonical_bytes(second)).hexdigest(),
    )

    assert report["status"] == "FIX_NARROW_ORACLE_ONLY"
    assert report["repeat"] == {
        "semantic_exact": True,
        "raw_osv_output_exact": False,
        "raw_output_variance_blocks_general_maven_sca_promotion": True,
        "raw_returned": False,
    }
    assert report["claim_boundary"]["general_maven_sca_adapter_fixed"] is False
    assert report["claim_boundary"]["blocking_promotion_admitted"] is False


def test_h5a_repeat_comparison_holds_on_a_changed_oracle_projection() -> None:
    first = _report()
    second = _report(package_ref="e" * 64)
    report = comparison.compare_reports(first, second, first_sha256="a" * 64, second_sha256="b" * 64)

    assert report["status"] == "HOLD"
    assert report["repeat"]["semantic_exact"] is False
