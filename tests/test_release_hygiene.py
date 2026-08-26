from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from scripts import release_hygiene

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "release_hygiene.py"


def test_release_hygiene_supports_package_import_and_direct_script() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        cwd=SCRIPT_PATH.parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert release_hygiene.PERFORMANCE_V2_SUPPORTED_CLAIM_PREFIX
    assert completed.returncode == 0
    assert "Check K-Guard release worktree hygiene" in completed.stdout


def test_release_hygiene_classifies_expected_paths():
    assert release_hygiene.classify_path("tmp/full-pytest-out.txt") == "generated_noise"
    assert release_hygiene.classify_path("terminals/1.txt") == "generated_noise"
    assert release_hygiene.classify_path("k-guard.sarif") == "generated_noise"
    assert release_hygiene.classify_path("k-guard-self-scan.json") == "generated_noise"
    assert release_hygiene.classify_path("src/k_guard_mcp/server.py") == "release_source"
    assert release_hygiene.classify_path("docs/release-hygiene.md") == "release_source"
    assert release_hygiene.classify_path("benchmark-report.json") == "root_evidence_report"
    assert release_hygiene.classify_path("evidence/public/report.json") == "release_evidence"
    assert release_hygiene.classify_path("submission/RIGHTS.md") == "release_submission"
    assert release_hygiene.classify_path("README.md") == "release_root"
    assert release_hygiene.classify_path("PUBLIC-SNAPSHOT.json") == "release_root"
    assert release_hygiene.classify_path("contest-readiness-report.json") == "root_evidence_report"
    assert release_hygiene.classify_path("contest-readiness-report.md") == "release_root"
    assert release_hygiene.classify_path("THIRD_PARTY_NOTICES.md") == "release_root"
    assert release_hygiene.classify_path("LICENSES/Apache-2.0.txt") == "release_root"


def test_release_hygiene_parses_porcelain_z_status():
    payload = " M README.md\0?? docs/release-hygiene.md\0R  docs/new.md\0docs/old.md\0"

    entries = release_hygiene.parse_porcelain_z(payload)

    assert entries == [
        {"status": " M", "path": "README.md", "category": "release_root"},
        {"status": "??", "path": "docs/release-hygiene.md", "category": "release_source"},
        {"status": "R ", "path": "docs/new.md", "category": "release_source"},
    ]


def test_release_hygiene_default_report_has_release_contract():
    report = release_hygiene.build_report(strict_clean=False)

    assert report["schema"] == "k_guard_release_hygiene.v1"
    assert report["release_boundary"]["publish_rule"]
    assert report["release_boundary"]["blocking_categories"] == [
        "review_required_artifact",
        "unclassified",
        "generated_noise",
    ]
    assert "generated_noise" not in report["git_status"]["categories"]
    assert "review_required_artifact" not in report["git_status"]["categories"]
    assert report["pass_conditions"]["tracking_jsonl_valid"]
    assert report["pass_conditions"]["required_release_files_present"]
    assert report["pass_conditions"]["contest_package_ready_for_release"]
    assert report["pass_conditions"]["current_source_performance_evidence_for_release"]
    assert "current-source performance evidence" in report["release_boundary"]["publish_rule"]


def test_release_authorization_rejects_blocked_and_historical_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(release_hygiene, "ROOT", tmp_path)
    readiness_path = tmp_path / "contest-readiness-report.json"
    performance_path = tmp_path / "benchmark-report.json"
    readiness_path.write_text(
        json.dumps(
            {
                "package_ready": False,
                "submission_ready": False,
                "status": "package_verification_blocked",
            }
        ),
        encoding="utf-8",
    )
    performance_path.write_text(
        json.dumps(
            {
                "schema": "k_guard_performance_benchmark.v2",
                "publication_binding": {
                    "current_public_source_equivalence_claimed": False,
                    "measured_revision_available_in_public_history": False,
                    "scope": release_hygiene.HISTORICAL_PUBLICATION_SCOPE,
                },
            }
        ),
        encoding="utf-8",
    )

    non_release = release_hygiene._release_authorization_status(False)
    release = release_hygiene._release_authorization_status(True)

    assert non_release["contest_readiness"]["valid"] is True
    assert non_release["performance_evidence"]["valid"] is True
    assert release["contest_readiness"]["valid"] is False
    assert release["performance_evidence"]["valid"] is False

    readiness_path.write_text(
        json.dumps(
            {
                "package_ready": True,
                "submission_ready": True,
                "status": "package_ready_field_evidence_pending",
            }
        ),
        encoding="utf-8",
    )
    performance_path.write_text(
        json.dumps({"schema": "k_guard_performance_benchmark.v2", "passed": True}),
        encoding="utf-8",
    )

    authorized = release_hygiene._release_authorization_status(True)
    assert authorized["contest_readiness"]["valid"] is True
    assert authorized["performance_evidence"]["valid"] is True


def test_release_hygiene_strict_clean_fails_with_dirty_entries(monkeypatch):
    monkeypatch.setattr(
        release_hygiene,
        "git_status_entries",
        lambda: [{"status": " M", "path": "README.md", "category": "release_root"}],
    )

    report = release_hygiene.build_report(strict_clean=True)

    assert not report["passed"]
    assert not report["pass_conditions"]["clean_worktree_when_strict"]


def test_release_hygiene_strict_and_tagged_boundaries_activate_release_authorization(
    monkeypatch,
):
    required_values: list[bool] = []

    def authorization(required: bool) -> dict:
        required_values.append(required)
        return {
            "required": required,
            "contest_readiness": {"valid": not required},
            "performance_evidence": {"valid": not required},
        }

    monkeypatch.setattr(release_hygiene, "_release_authorization_status", authorization)

    strict = release_hygiene.build_report(strict_clean=True)
    tagged = release_hygiene.build_report(
        strict_clean=False,
        expected_tag=f"v{strict['version']['pyproject']}",
    )

    assert required_values == [True, True]
    for report in (strict, tagged):
        assert report["pass_conditions"]["contest_package_ready_for_release"] is False
        assert (
            report["pass_conditions"]["current_source_performance_evidence_for_release"]
            is False
        )
        assert report["passed"] is False


def test_release_hygiene_rejects_unclassified_review_artifacts(monkeypatch):
    monkeypatch.setattr(
        release_hygiene,
        "git_status_entries",
        lambda: [{"status": "??", "path": "loose-review.json", "category": "review_required_artifact"}],
    )

    report = release_hygiene.build_report(strict_clean=False)

    assert not report["passed"]
    assert not report["pass_conditions"]["no_review_required_artifacts"]
    assert report["git_status"]["categories"]["review_required_artifact"] == 1


def test_release_hygiene_rejects_generated_noise(monkeypatch):
    monkeypatch.setattr(
        release_hygiene,
        "git_status_entries",
        lambda: [{"status": "??", "path": "tmp/report.json", "category": "generated_noise"}],
    )

    report = release_hygiene.build_report(strict_clean=False)

    assert not report["passed"]
    assert not report["pass_conditions"]["no_generated_noise_in_git_status"]
    assert report["git_status"]["categories"]["generated_noise"] == 1


def test_release_hygiene_rejects_empty_or_failed_evidence_reports():
    assert release_hygiene._evidence_report_semantic_error("license-report.json", {})
    assert release_hygiene._evidence_report_semantic_error(
        "license-report.json",
        {
            "passed": False,
            "component_count": 37,
            "unknown_license_count": 0,
            "review_required_count": 0,
            "unresolved_dependency_count": 0,
            "lock_mismatch_count": 0,
        },
    )
    assert release_hygiene._evidence_report_semantic_error(
        "license-report.json",
        {
            "passed": True,
            "component_count": 37,
            "unknown_license_count": 0,
            "review_required_count": 0,
            "unresolved_dependency_count": 0,
            "lock_mismatch_count": 0,
        },
    ) is None
    assert release_hygiene._evidence_report_semantic_error(
        "contest-readiness-report.json",
        {
            "schema": "k_guard_contest_readiness.v3",
            "package_ready": True,
            "submission_ready": True,
            "award_evidence_ready": False,
            "status": "package_ready_field_evidence_pending",
            "internal_checks": {"package": True},
            "external_checks": {"field": False},
            "blockers": ["field"],
        },
    ) is None
    assert release_hygiene._evidence_report_semantic_error(
        "contest-readiness-report.json",
        {
            "schema": "k_guard_contest_readiness.v3",
            "submission_ready": True,
            "package_ready": False,
            "award_evidence_ready": False,
            "status": "submission_ready_external_evidence_pending",
            "internal_checks": {"package": False},
            "external_checks": {"field": False},
            "blockers": ["package", "field"],
        },
    ) is not None

    blocked = {
        "schema": "k_guard_contest_readiness.v3",
        "package_ready": False,
        "submission_ready": False,
        "award_evidence_ready": False,
        "status": "package_verification_blocked",
        "internal_checks": {"package": False, "docs": True},
        "external_checks": {"field": False},
        "blockers": ["package", "field"],
    }
    assert release_hygiene._evidence_report_semantic_error(
        "contest-readiness-report.json", blocked
    ) is None


def test_release_hygiene_requires_full_v2_performance_evidence():
    quick = {
        "schema": "k_guard_performance_benchmark.v2",
        "profile": "quick_ci",
        "slo": {"all_met": True, "synthetic_throughput_met": True},
    }
    assert "contest_full" in release_hygiene._evidence_report_semantic_error("benchmark-report.json", quick)

    section = {"fingerprints_stable": True, "all_candidates_complete": True}
    payload = {
        "schema": "k_guard_performance_benchmark.v2",
        "profile": "contest_full",
        "passed": True,
        "raw_free": True,
        "protocol": {
            "single_host": True,
            "scaling_mib": [10, 50, 100],
            "concurrency_levels": [1, 4, 8],
            "cold_samples": 20,
            "warm_samples": 20,
            "scaling_samples_per_size": 5,
            "concurrency_jobs_per_level": 16,
            "percentile_method": "nearest_rank",
            "small_sample_p95_interpretation": release_hygiene.PERFORMANCE_V2_SMALL_SAMPLE_P95_INTERPRETATION,
            "concurrency_mechanism": "ThreadPoolExecutor inside one CPython process; test",
            "process_level_scaling_measured": False,
            "corpus_signal_profile": "synthetic all-benign low-signal; test",
            "cold_definition": "fresh_process_cold; test",
            "warm_definition": "persistent_process_and_scanner_warm; test",
        },
        "source_binding": {
            "pre_run_clean": True,
            "head_unchanged": True,
            "package_tree_unchanged": True,
            "runner_unchanged": True,
            "source_unchanged": True,
            "working_tree_matches_head_package": True,
            "runner_matches_head": True,
            "pre": {
                "working_package_tree_sha256": release_hygiene.package_tree_sha256(
                    release_hygiene.ROOT / "src" / "k_guard_mcp"
                ),
                "runner_sha256": hashlib.sha256(
                    (release_hygiene.ROOT / "scripts" / "benchmark.py").read_bytes()
                ).hexdigest(),
            },
        },
        "environment": {
            "python_implementation": "CPython",
            "python_version": "3.11.0",
            "python_executable_sha256": "1" * 64,
            "os_system": "TestOS",
            "os_version": "test-build",
            "machine": "test",
            "logical_cpu_count": 8,
            "installed_distribution_set_sha256": "2" * 64,
            "peak_memory_backend": "fake",
            "raw_free": True,
        },
        "acceptance": {
            "all_met": True,
            "checks": {name: True for name in release_hygiene.PERFORMANCE_V2_ACCEPTANCE_CHECKS},
        },
        "cold": dict(section),
        "warm": dict(section),
        "warm_vs_cold": {
            "p50_seconds_delta": 0.1,
            "p50_ratio": 1.1,
            "peak_rss_bytes_delta": 1024,
            "persistent_scanner_reuse_beyond_20_scans_measured": False,
        },
        "scaling": {key: dict(section) for key in ("10", "50", "100")},
        "concurrency": {key: dict(section) for key in ("1", "4", "8")},
        "claim_boundary": {
            "supported_claim": release_hygiene.PERFORMANCE_V2_SUPPORTED_CLAIM_PREFIX,
            "not_field_accuracy": True,
            "not_third_party_comparison": True,
            "not_hardware_normalized": True,
            "not_cold_disk_or_cold_cache": True,
            "one_reported_environment_only": True,
            "synthetic_inputs": True,
            "all_benign_low_signal_inputs": True,
            "not_finding_dense_scaling": True,
            "empty_result_digest_has_limited_discriminating_power": True,
            "not_process_level_scaling": True,
            "raw_free": True,
        },
    }
    payload["report_fingerprint_sha256"] = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    assert release_hygiene._evidence_report_semantic_error("benchmark-report.json", payload) is None

    historical = json.loads(json.dumps(payload))
    measured_revision = "7" * 40
    package_hash = historical["source_binding"]["pre"]["working_package_tree_sha256"]
    runner_hash = historical["source_binding"]["pre"]["runner_sha256"]
    historical["publication_binding"] = {
        "current_public_source_equivalence_claimed": False,
        "measured_revision_available_in_public_history": False,
        "scope": release_hygiene.HISTORICAL_PUBLICATION_SCOPE,
    }
    historical["source_binding"].update(
        {
            "git_head": measured_revision,
            "measured_git_head": measured_revision,
            "post": {
                "clean": True,
                "git_head": measured_revision,
                "working_package_tree_sha256": package_hash,
                "head_package_tree_sha256": package_hash,
                "runner_sha256": runner_hash,
                "head_runner_sha256": runner_hash,
            },
        }
    )
    historical["source_binding"]["pre"].update(
        {
            "clean": True,
            "git_head": measured_revision,
            "head_package_tree_sha256": package_hash,
            "head_runner_sha256": runner_hash,
        }
    )
    historical["report_fingerprint_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in historical.items() if key != "report_fingerprint_sha256"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert release_hygiene._evidence_report_semantic_error(
        "benchmark-report.json", historical
    ) is None

    historical["publication_binding"]["current_public_source_equivalence_claimed"] = True
    assert "historical public-snapshot" in release_hygiene._evidence_report_semantic_error(
        "benchmark-report.json", historical
    )

    wrong_scope = json.loads(json.dumps(payload))
    wrong_scope["claim_boundary"]["supported_claim"] = "generic scanner capacity"
    wrong_scope["report_fingerprint_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in wrong_scope.items() if key != "report_fingerprint_sha256"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert "supported_claim" in release_hygiene._evidence_report_semantic_error(
        "benchmark-report.json", wrong_scope
    )

    missing_p95 = json.loads(json.dumps(payload))
    missing_p95["protocol"].pop("small_sample_p95_interpretation")
    missing_p95["report_fingerprint_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in missing_p95.items() if key != "report_fingerprint_sha256"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert "protocol" in release_hygiene._evidence_report_semantic_error(
        "benchmark-report.json", missing_p95
    )

    payload["source_binding"]["runner_matches_head"] = False
    assert "source binding" in release_hygiene._evidence_report_semantic_error("benchmark-report.json", payload)


def test_release_hygiene_detects_gitignored_build_outputs(tmp_path, monkeypatch):
    monkeypatch.setattr(release_hygiene, "ROOT", tmp_path)
    (tmp_path / "src" / "k_guard_mcp.egg-info").mkdir(parents=True)
    (tmp_path / "build").mkdir()

    status = release_hygiene._ignored_release_artifacts_status()

    assert status["valid"] is False
    assert status["present"] == ["build", "src/k_guard_mcp.egg-info"]


def test_release_hygiene_validates_evidence_hash_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(release_hygiene, "ROOT", tmp_path)
    artifact = tmp_path / "evidence" / "public" / "report.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"passed": true}\n', encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (tmp_path / "evidence" / "SHA256SUMS").write_text(
        f"{digest}  evidence/public/report.json\n",
        encoding="utf-8",
    )

    assert release_hygiene._evidence_tree_status()["valid"] is True

    artifact.write_text('{"passed": false}\n', encoding="utf-8")
    status = release_hygiene._evidence_tree_status()
    assert status["valid"] is False
    assert status["errors"] == ["digest mismatch: evidence/public/report.json"]


def test_release_tag_must_exactly_match_project_version() -> None:
    assert release_hygiene._release_tag_status("v0.1.0", "0.1.0")["valid"] is True
    assert release_hygiene._release_tag_status("v9.9.9", "0.1.0")["valid"] is False
    assert release_hygiene._release_tag_status(None, "0.1.0")["required"] is False


def test_strict_package_byte_check_detects_clean_filter_differences(tmp_path, monkeypatch) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    source = tmp_path / "src" / "k_guard_mcp" / "contract.json"
    source.parent.mkdir(parents=True)
    source.write_bytes(b'{\n  "ok": true\n}\n')
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    monkeypatch.setattr(release_hygiene, "ROOT", tmp_path)

    assert release_hygiene._package_input_byte_status()["valid"] is True

    source.write_bytes(b'{\r\n  "ok": true\r\n}\r\n')
    status = release_hygiene._package_input_byte_status()
    assert status["valid"] is False
    assert status["mismatches"] == ["src/k_guard_mcp/contract.json"]
