from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path

import pytest

from scripts import ai_public_benchmark_scorecard as scorecard


ROOT = Path(__file__).resolve().parents[1]


def test_scorecard_keeps_benchmark_lanes_and_juliet_runs_separate() -> None:
    report = scorecard.build_scorecard(ROOT)
    lanes = {lane["lane_id"]: lane for lane in report["lanes"]}

    assert report["schema"] == "k_guard_ai_public_benchmark_scorecard.v1"
    assert list(lanes) == [
        "current_korean_synthetic_inspection",
        "current_public_app_replay",
        "historical_owasp_benchmark_python",
        "historical_owasp_benchmarkjava_cwe89",
        "historical_nist_juliet_java_cwe89_first",
        "historical_nist_juliet_java_cwe89_post_tuning_replay",
    ]
    assert report["claim_boundary"]["no_global_tp_fp_fn_or_rate_aggregation"] is True
    assert report["claim_boundary"]["benchmarkjava_hold_is_preserved"] is True
    assert report["claim_boundary"]["juliet_first_result_is_separate_from_post_tuning_replay"] is True
    assert "metrics" not in report
    assert "score" not in report
    assert "true_positive" not in report
    assert scorecard._no_global_aggregation_fields(report) is True
    assert scorecard._no_global_aggregation_fields({**report, "metrics": {}}) is False

    performance = report["performance_evidence"]
    assert performance["evidence_integrity"]["status"] == "PASS"
    assert performance["source_revision"] == "11b3e376cf8c7f954c9a702cfef41c918e8686f6"
    assert performance["corpus_bytes"] == 65536
    assert performance["levels"]["4"]["speedup_vs_1"] == 3.630573
    assert performance["levels"]["4"]["parallel_efficiency_vs_1"] == 0.907643
    assert performance["claim_boundary"]["single_host"] is True
    assert performance["claim_boundary"]["not_production_slo"] is True

    benchmarkjava = lanes["historical_owasp_benchmarkjava_cwe89"]
    assert benchmarkjava["recorded_result"]["recorded_verdict"] == "hold"
    assert benchmarkjava["recorded_result"]["recorded_passed"] is False

    current_public = lanes["current_public_app_replay"]["recorded_result"]["metrics"]
    assert current_public["runs_per_app"] == 2
    assert current_public["total_app_runs"] == 24
    assert current_public["exact_repeat_app_count"] == 12

    benchmark_python = lanes["historical_owasp_benchmark_python"]["recorded_result"]
    assert benchmark_python["validation_claim_status"] == "public_benchmark_ready"
    assert benchmark_python["validation_claim_status_admissible_for_current_claims"] is False
    assert benchmark_python["validation_claim_status_inadmissibility_reason"] == (
        "evidence_integrity_fail"
    )

    first = lanes["historical_nist_juliet_java_cwe89_first"]
    replay = lanes["historical_nist_juliet_java_cwe89_post_tuning_replay"]
    assert first["recorded_result"]["metrics"]["false_negative"] == 30
    assert replay["recorded_result"]["metrics"]["false_negative"] == 0
    assert replay["claim_boundary"]["first_result_remains_the_independent_public_result"] is True
    assert replay["claim_boundary"]["post_tuning_regression_evidence_only"] is True
    assert replay["evidence_role"] == "historical_same_corpus_post_tuning_regression"


def test_scorecard_projection_digest_is_timestamp_independent() -> None:
    first = scorecard.build_scorecard(ROOT)
    second = scorecard.build_scorecard(ROOT)

    assert first["projection_sha256"] == second["projection_sha256"]
    assert first == second
    assert len(first["projection_sha256"]) == 64
    assert first["generated_at"]
    parsed = datetime.fromisoformat(first["generated_at"].replace("Z", "+00:00"))
    assert parsed.tzinfo is not None


def test_source_commit_time_falls_back_explicitly_when_git_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed(*_args: object, **_kwargs: object):
        return scorecard.subprocess.CompletedProcess([], 1, stdout="", stderr="git failed")

    monkeypatch.setattr(scorecard.subprocess, "run", failed)

    assert scorecard._source_commit_time(ROOT) == "unavailable"


def test_public_run_counts_are_derived_from_recorded_rows_and_fail_closed() -> None:
    exact, exact_errors = scorecard._recorded_public_run_metrics(
        {
            "apps": [
                {"runs": [{"run": 1}, {"run": 2}]},
                {"runs": [{"run": 1}, {"run": 2}]},
            ]
        }
    )
    malformed, malformed_errors = scorecard._recorded_public_run_metrics(
        {
            "apps": [
                {"runs": [{"run": 1}, {"run": 2}]},
                {"runs": [{"run": 1}]},
            ]
        }
    )

    assert exact == {"runs_per_app": 2, "total_app_runs": 4}
    assert exact_errors == []
    assert malformed == {"runs_per_app": None, "total_app_runs": 3}
    assert malformed_errors == ["current_public_recorded_run_rows_not_exact_two_per_app"]


def test_scorecard_reports_checked_in_internal_hash_drift_without_rewriting_history() -> None:
    report = scorecard.build_scorecard(ROOT)
    lanes = {lane["lane_id"]: lane for lane in report["lanes"]}

    assert report["evidence_integrity"]["status"] == "FAIL"
    assert lanes["current_korean_synthetic_inspection"]["evidence_integrity"] == {
        "status": "PASS",
        "errors": [],
    }
    assert lanes["current_public_app_replay"]["evidence_integrity"] == {
        "status": "FAIL",
        "errors": [
            "current_public_campaign_analyzer_not_current",
            "current_public_candidates_analyzer_not_current",
            "current_public_probes_analyzer_not_current",
            "current_public_source_revision_package_mismatch",
        ],
    }
    assert lanes["historical_owasp_benchmarkjava_cwe89"]["evidence_integrity"] == {
        "status": "PASS",
        "errors": [],
    }
    assert lanes["historical_nist_juliet_java_cwe89_first"]["evidence_integrity"] == {
        "status": "PASS",
        "errors": [],
    }
    assert "declared_artifact_digest_mismatch:primary_guardian" in lanes[
        "historical_owasp_benchmark_python"
    ]["evidence_integrity"]["errors"]
    assert lanes["historical_nist_juliet_java_cwe89_post_tuning_replay"][
        "evidence_integrity"
    ]["errors"] == ["first_result_digest_mismatch"]


def test_selected_evidence_manifest_verification_fails_closed_on_byte_drift(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    artifact = evidence / "sample.json"
    artifact.write_bytes(b'{"schema":"example.v1"}\n')
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (evidence / "SHA256SUMS").write_text(
        f"{digest}  evidence/sample.json\n",
        encoding="utf-8",
    )

    manifest, errors = scorecard._manifest_index(tmp_path)
    assert errors == []
    assert scorecard._manifest_hash_errors(
        tmp_path,
        manifest,
        [Path("evidence/sample.json")],
    ) == []

    artifact.write_bytes(b'{"schema":"tampered.v1"}\n')
    assert scorecard._manifest_hash_errors(
        tmp_path,
        manifest,
        [Path("evidence/sample.json")],
    ) == ["evidence_manifest_digest_mismatch:evidence/sample.json"]


def test_cli_separates_scorecard_generation_from_strict_admissibility(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scorecard,
        "build_scorecard",
        lambda _root: {"evidence_integrity": {"status": "FAIL"}},
    )
    assert scorecard.main(["--root", str(ROOT)]) == 0
    capsys.readouterr()
    assert scorecard.main(["--root", str(ROOT), "--require-integrity-pass"]) == 1
    capsys.readouterr()


def test_cli_writes_canonical_lf_json(tmp_path: Path) -> None:
    output = tmp_path / "scorecard.json"

    assert scorecard.main(["--root", str(ROOT), "--output", str(output)]) == 0
    payload = output.read_bytes()
    assert payload.endswith(b"\n")
    assert b"\r\n" not in payload


def test_process_scaling_verifier_recomputes_arithmetic_and_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads((ROOT / scorecard.PROCESS_SCALING).read_text(encoding="utf-8"))
    expected_tree = payload["source_binding"]["pre"]["working_package_tree_sha256"]
    expected_runner = payload["source_binding"]["pre"]["runner_sha256"]
    payload["levels"]["4"]["speedup_vs_1"] = 9.0

    monkeypatch.setattr(scorecard, "_json_object", lambda _path: payload)
    monkeypatch.setattr(scorecard, "_git_revision_exists", lambda _root, _revision: True)
    monkeypatch.setattr(scorecard, "_package_tree_sha256_at_revision", lambda _root, _revision: expected_tree)
    monkeypatch.setattr(scorecard, "package_tree_sha256", lambda _path: expected_tree)
    monkeypatch.setattr(scorecard, "_git_blob_sha256", lambda _root, _revision, _relative: expected_runner)

    verified = scorecard._process_scaling_evidence(tmp_path)
    assert verified["evidence_integrity"]["status"] == "FAIL"
    assert "process_scaling_level_4_speedup_arithmetic_invalid" in verified["evidence_integrity"]["errors"]
    assert "process_scaling_report_fingerprint_invalid" in verified["evidence_integrity"]["errors"]
