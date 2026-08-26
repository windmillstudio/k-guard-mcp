from __future__ import annotations

import json
from pathlib import Path

from k_guard_mcp import guardian
from k_guard_mcp.hashing import evidence_hash_scheme
from k_guard_mcp.provenance import source_tree_snapshot


class _ReportRun:
    def __init__(self, report: dict) -> None:
        self.report = report

    def to_report(self) -> dict:
        return json.loads(json.dumps(self.report))


class _DeepAdapter:
    def __init__(self, **_: object) -> None:
        pass

    def analyze(self, path: str | Path) -> _ReportRun:
        return _ReportRun(
            {
                "schema": "k_guard_analyzer_run.v1",
                "complete": True,
                "control_errors": [],
                "analyzer_subtype": "semgrep-ce-intrafile",
                "profile_name": "semgrep-deep.yml",
                "input_snapshot": source_tree_snapshot(path),
                "findings": [
                    {
                        "rule_id": "k-guard.test.deep-release-blocker",
                        "severity": "high",
                        "confidence": "high",
                        "file": "app.py",
                        "line_start": 1,
                        "line_end": 1,
                        "message": "Deep release blocker",
                        "recommendation": "Fix the deep release blocker.",
                        "analyzer_subtype": "semgrep-ce-intrafile",
                        "fingerprint": "a" * 64,
                        "raw_free": True,
                    }
                ],
                "raw_free": True,
            }
        )


class _ScaAnalyzer:
    def analyze(self, path: str | Path) -> _ReportRun:
        snapshot = source_tree_snapshot(path)
        return _ReportRun(
            {
                "schema": "k_guard_sca_run.v1",
                "complete": True,
                "passed": False,
                "control_errors": [],
                "requested_ecosystems": [],
                "audited_ecosystems": [],
                "adapters": [],
                "input_snapshot": snapshot,
                "inventory": {"manifest_count": 0, "lock_count": 0, "uncovered_manifest_count": 0},
                "counts": {"finding_count": 1},
                "findings": [
                    {
                        "ecosystem": "python",
                        "vulnerability_id": "CVE-2026-99999",
                        "package_ref": {"hash": "b" * 16, "hash_scheme": evidence_hash_scheme(), "raw_returned": False},
                        "installed_version_ref": {"hash": "c" * 16, "hash_scheme": evidence_hash_scheme(), "raw_returned": False},
                        "severity": "critical",
                        "fixed_version_present": True,
                        "fingerprint": "d" * 64,
                        "raw_free": True,
                    }
                ],
                "raw_free": True,
            }
        )


def _manifest(tmp_path: Path) -> Path:
    workspace = tmp_path / "app"
    workspace.mkdir()
    (workspace / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
    manifest = tmp_path / "guardian.csv"
    manifest.write_text(
        "app_id,target_id,kind,locator,authorized,authorization_note,deep_active,session_file,include_flow,fail_on,owner,business_purpose,data_classes,user_scope,public_endpoints,scope_basis,scope_proof_ref,audit_profile,notes\n"
        "app-1,workspace-1,workspace,app,true,local,false,,true,high,team,release review,public_content,public users,,local_workspace,owned fixture,standard,test\n",
        encoding="utf-8",
    )
    return manifest


def test_guardian_merges_deep_and_sca_findings_into_canonical_target_plane(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(guardian, "SemgrepAnalyzerAdapter", _DeepAdapter)
    report = guardian.run_guardian_audit(
        _manifest(tmp_path),
        fail_on_override="high",
        run_sca=True,
        sca_analyzer=_ScaAnalyzer(),
    )

    target = report["targets"][0]
    rules = {finding["rule_id"] for finding in target["findings"]}
    assert "k-guard.test.deep-release-blocker" in rules
    assert "SCA_VULNERABLE_LOCKED_DEPENDENCY" in rules
    assert target["gate"]["passed"] is False
    assert target["summary"]["critical"] == 1
    assert target["summary"]["high"] >= 1
    assert target["review_evidence"]["release_analysis"] == {
        "deep_complete": True,
        "sca_complete": True,
        "merged_finding_count": 2,
        "raw_returned": False,
    }
    assert {item["rule_id"] for item in report["top_rules"]}.issuperset(rules)
    assert {item["rule_id"] for item in report["fix_plan"]}.issuperset(rules)


def test_guardian_marks_omitted_sca_as_unsuppressible_target_coverage_gap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(guardian, "SemgrepAnalyzerAdapter", _DeepAdapter)
    report = guardian.run_guardian_audit(
        _manifest(tmp_path),
        fail_on_override="high",
        run_sca=False,
    )

    target = report["targets"][0]
    sca_gap = next(finding for finding in target["findings"] if finding["rule_id"] == "SCA_COVERAGE_INCOMPLETE")
    assert target["coverage"]["qualification_analysis_gap"] is True
    assert target["coverage"]["coverage_gap"] is True
    assert target["gate"]["passed"] is False
    assert "report_ref=" in sca_gap["evidence"]
