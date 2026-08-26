from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "benchmark.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("performance_benchmark", SCRIPT_PATH)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def _sample(total_bytes: int, elapsed: float = 1.0) -> dict[str, object]:
    return {
        "elapsed_seconds": elapsed,
        "total_bytes": total_bytes,
        "peak_rss_bytes": 64 * 1024 * 1024,
        "candidate_set_complete": True,
        "unscanned_candidate_count": 0,
        "oversized_candidate_count": 0,
        "result_fingerprint_sha256": "a" * 64,
        "raw_free": True,
    }


def test_exact_corpus_is_byte_exact_bounded_and_content_bound(tmp_path):
    report = benchmark._build_exact_corpus(tmp_path / "corpus", 4097, max_file_bytes=1024)

    assert report["total_bytes"] == 4097
    assert report["file_count"] == 5
    assert report["maximum_file_bytes"] == 1024
    assert report["candidate_set_complete"] is True
    assert len(report["candidate_content_set_sha256"]) == 64


def test_tiny_real_sample_reports_complete_coverage_and_peak_rss(tmp_path):
    corpus = benchmark._build_exact_corpus(tmp_path / "tiny", 4096, max_file_bytes=1024)

    sample = benchmark._scan_once(Path(corpus["path"]))

    assert sample["total_bytes"] == 4096
    assert sample["candidate_set_complete"] is True
    assert sample["unscanned_candidate_count"] == 0
    assert sample["peak_rss_bytes"] > 0
    assert len(sample["result_fingerprint_sha256"]) == 64
    assert sample["raw_free"] is True


def test_nearest_rank_and_repeat_fingerprint_are_deterministic():
    assert benchmark._nearest_rank([5.0, 1.0, 4.0, 2.0, 3.0], 0.50) == 3.0
    assert benchmark._nearest_rank([5.0, 1.0, 4.0, 2.0, 3.0], 0.95) == 5.0

    report = benchmark._series_summary([_sample(benchmark.MIB, value) for value in (3.0, 1.0, 2.0)], benchmark.MIB)

    assert report["p50_seconds"] == 2.0
    assert report["p95_seconds"] == 3.0
    assert report["fingerprints_stable"] is True
    assert report["all_candidates_complete"] is True


def test_quick_synthetic_edge_cap_tracks_the_active_analyzer_limits(monkeypatch):
    class FakeAstTaint:
        max_js_ts_edges_per_file = 11

    class FakeFlowAnalyzer:
        max_edges_per_file = 7
        ast_taint = FakeAstTaint()

    class FakeFlowMap:
        edges = [None] * (240 * 18)
        nodes = []

    class FakeResult:
        findings = []
        flow_map = FakeFlowMap()

    class FakeScanner:
        flow_analyzer = FakeFlowAnalyzer()

        def scan_workspace(self, _root):
            return FakeResult()

    monkeypatch.setattr(benchmark, "KGuardScanner", FakeScanner)

    report = benchmark._benchmark_synthetic_repo()

    assert report["maximum_heuristic_flow_edges_per_file"] == 7
    assert report["maximum_js_ts_taint_edges_per_file"] == 11
    assert report["maximum_flow_edges_per_file"] == 18
    assert report["maximum_flow_edges"] == 240 * 18
    assert report["edge_cap_met"] is True


def test_concurrency_worker_uses_fake_scan_without_product_work(monkeypatch, tmp_path):
    calls = []

    def fake_scan(_corpus):
        calls.append(1)
        return _sample(17, 0.001)

    monkeypatch.setattr(benchmark, "_scan_once", fake_scan)
    payload = benchmark._worker_payload("concurrency", tmp_path, repeats=1, warmup=0, concurrency=1, jobs=3)

    assert len(calls) == 3
    assert len(payload["samples"]) == 3
    assert payload["batch_elapsed_seconds"] >= 0
    assert payload["raw_free"] is True


def test_contest_profile_orchestrates_exact_protocol_with_fake_workers(tmp_path):
    byte_sizes: dict[str, int] = {}

    def fake_corpus(path, target_bytes):
        path.mkdir()
        byte_sizes[str(path)] = target_bytes
        return {
            "path": str(path),
            "total_bytes": target_bytes,
            "file_count": max(1, target_bytes // benchmark.CORPUS_FILE_BYTES),
            "maximum_file_bytes": min(target_bytes, benchmark.CORPUS_FILE_BYTES),
            "candidate_set_complete": True,
            "candidate_path_set_sha256": "b" * 64,
            "candidate_content_set_sha256": "c" * 64,
            "raw_free": True,
        }

    def fake_worker(mode, corpus, **kwargs):
        total_bytes = byte_sizes[str(corpus)]
        elapsed = total_bytes / benchmark.MIB
        if mode == "series":
            count = kwargs["repeats"]
            return {"samples": [_sample(total_bytes, elapsed) for _ in range(count)], "raw_free": True}
        return {
            "samples": [_sample(total_bytes, 1.0) for _ in range(kwargs["jobs"])],
            "batch_elapsed_seconds": 2.0,
            "raw_free": True,
        }

    snapshot = {
        "git_head": "d" * 40,
        "clean": True,
        "working_package_tree_sha256": "e" * 64,
        "head_package_tree_sha256": "e" * 64,
        "runner_sha256": "f" * 64,
        "head_runner_sha256": "f" * 64,
        "raw_free": True,
    }
    runtime = {
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
    }

    report = benchmark._contest_report(
        tmp_path,
        invoke_worker=fake_worker,
        corpus_builder=fake_corpus,
        source_snapshot=lambda _root: dict(snapshot),
        runtime_fingerprint=lambda: dict(runtime),
    )

    assert report["schema"] == benchmark.SCHEMA
    assert report["profile"] == benchmark.PROFILE_CONTEST
    assert report["protocol"]["scaling_mib"] == [10, 50, 100]
    assert report["protocol"]["concurrency_levels"] == [1, 4, 8]
    assert report["protocol"]["process_level_scaling_measured"] is False
    assert "one CPython process" in report["protocol"]["concurrency_mechanism"]
    assert report["cold"]["sample_count"] == 20
    assert report["warm"]["sample_count"] == 20
    assert report["scaling"]["100"]["sample_count"] == 5
    assert report["concurrency"]["8"]["sample_count"] == 16
    assert report["concurrency_interpretation"] == {
        "observation_scope": "this contest_full run only; no generalized concurrency gain is claimed",
        "level_1_p50_seconds": report["concurrency"]["1"]["p50_seconds"],
        "level_1_max_seconds": report["concurrency"]["1"]["max_seconds"],
        "level_1_baseline_may_be_depressed": True,
    }
    assert report["warm_vs_cold"]["persistent_scanner_reuse_beyond_20_scans_measured"] is False
    assert report["claim_boundary"]["not_finding_dense_scaling"] is True
    assert report["claim_boundary"]["empty_result_digest_has_limited_discriminating_power"] is True
    assert "limited discriminating power" in report["protocol"]["result_fingerprint_interpretation"]
    assert report["acceptance"]["all_met"] is True
    assert report["passed"] is True
    assert len(report["report_fingerprint_sha256"]) == 64


def test_report_writer_uses_canonical_lf_bytes(tmp_path):
    output = tmp_path / "benchmark-report.json"

    benchmark._write_report(output, {"schema": benchmark.SCHEMA, "note": "한국어"})

    payload = output.read_bytes()
    assert payload.endswith(b"\n")
    assert b"\r\n" not in payload


def _process_snapshot() -> dict[str, object]:
    return {
        "git_head": "d" * 40,
        "clean": True,
        "working_package_tree_sha256": "e" * 64,
        "head_package_tree_sha256": "e" * 64,
        "runner_sha256": "f" * 64,
        "head_runner_sha256": "f" * 64,
        "raw_free": True,
    }


def _process_runtime() -> dict[str, object]:
    return {
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
    }


def _process_corpus(path: Path, target_bytes: int, **overrides: object) -> dict[str, object]:
    path.mkdir()
    corpus_file = path / "capacity_0000.py"
    corpus_file.write_bytes(b"x" * target_bytes)
    inventory = benchmark.file_inventory_fingerprint(path, [corpus_file])
    payload: dict[str, object] = {
        "path": str(path),
        "total_bytes": target_bytes,
        "file_count": 1,
        "maximum_file_bytes": target_bytes,
        "candidate_set_complete": True,
        "candidate_path_set_sha256": inventory["candidate_path_set_sha256"],
        "candidate_content_set_sha256": inventory["candidate_content_set_sha256"],
        "raw_free": True,
    }
    payload.update(overrides)
    return payload


def _isolated_job(total_bytes: int, reference: str, **sample_overrides: object) -> dict[str, object]:
    sample = _sample(total_bytes, 0.01)
    sample.update(sample_overrides)
    return {
        "mode": "isolated_job",
        "scanner_instance_reused": False,
        "samples": [sample],
        "child_process_reference": reference,
        "raw_free": True,
    }


def _run_process_report(tmp_path, invoke, corpus_builder=None):
    return benchmark._process_scaling_report(
        tmp_path,
        invoke_isolated_job=invoke,
        corpus_builder=corpus_builder or _process_corpus,
        source_snapshot=lambda _root: dict(_process_snapshot()),
        runtime_fingerprint=lambda: dict(_process_runtime()),
    )


def test_historical_benchmark_report_name_is_detected():
    assert benchmark._is_historical_benchmark_report(Path("benchmark-report.json")) is True
    assert benchmark._is_historical_benchmark_report(Path("out") / "benchmark-report.json") is True
    assert benchmark._is_historical_benchmark_report(Path("target-grade-process-scaling.json")) is False


def test_isolated_job_worker_uses_fake_scan_without_thread_pool(monkeypatch, tmp_path):
    calls = []

    def fake_scan(_corpus):
        calls.append(1)
        return _sample(17, 0.001)

    def boom(*_args, **_kwargs):
        raise AssertionError("isolated_job must not use ThreadPoolExecutor")

    monkeypatch.setattr(benchmark, "_scan_once", fake_scan)
    monkeypatch.setattr(benchmark, "ThreadPoolExecutor", boom)
    payload = benchmark._worker_payload("isolated_job", tmp_path, repeats=1, warmup=0, concurrency=1, jobs=1)
    again = benchmark._worker_payload("isolated_job", tmp_path, repeats=1, warmup=0, concurrency=1, jobs=1)

    assert calls == [1, 1]
    assert payload["mode"] == "isolated_job"
    assert payload["scanner_instance_reused"] is False
    assert payload["raw_free"] is True
    assert len(payload["samples"]) == 1
    assert len(payload["child_process_reference"]) == 64
    assert payload["child_process_reference"] == again["child_process_reference"]


def test_invoke_isolated_job_spawns_fresh_subprocess(monkeypatch, tmp_path):
    recorded = {}

    class Result:
        returncode = 0
        stdout = benchmark._canonical_json(_isolated_job(32, "a" * 64))

    def fake_run(command, **_kwargs):
        recorded["command"] = command
        return Result()

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)
    payload = benchmark._spawn_isolated_child_job(tmp_path)

    assert recorded["command"][0] == sys.executable
    assert "--_worker-mode" in recorded["command"]
    assert "isolated_job" in recorded["command"]
    assert payload["child_process_reference"] == "a" * 64


def test_process_scaling_cli_requires_explicit_non_historical_output(capsys, tmp_path):
    with pytest.raises(SystemExit):
        benchmark.main(["--target-grade-process-scaling"])
    assert "explicit --output" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        benchmark.main(["--target-grade-process-scaling", "--output", "benchmark-report.json"])
    assert "benchmark-report.json" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        benchmark.main(["--target-grade-process-scaling", "--output", str(tmp_path / "benchmark-report.json")])
    assert "benchmark-report.json" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        benchmark.main(["--target-grade-process-scaling", "--profile", "contest", "--output", str(tmp_path / "ok.json")])
    assert "separate from --profile" in capsys.readouterr().err


def test_process_scaling_cli_writes_explicit_output_and_skips_historical(tmp_path, monkeypatch):
    output = tmp_path / "target-grade-process-scaling.json"
    historical = tmp_path / "benchmark-report.json"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_process_scaling_report",
        lambda _root: {"passed": True, "profile": benchmark.PROFILE_PROCESS, "raw_free": True},
    )
    monkeypatch.setattr(benchmark, "_quick_report", lambda _root: (_ for _ in ()).throw(AssertionError("quick")))
    monkeypatch.setattr(benchmark, "_contest_report", lambda _root: (_ for _ in ()).throw(AssertionError("contest")))

    assert benchmark.main(["--target-grade-process-scaling", "--output", str(output)]) == 0
    assert output.is_file()
    assert historical.exists() is False


def test_quick_profile_default_output_remains_historical(tmp_path, monkeypatch):
    written: list[Path] = []
    monkeypatch.setattr(benchmark, "_quick_report", lambda _root: {"slo": {"all_met": True}})
    monkeypatch.setattr(benchmark, "_write_report", lambda path, _report: written.append(path))

    assert benchmark.main([]) == 0
    assert written == [Path(benchmark.HISTORICAL_BENCHMARK_REPORT)]


def test_quick_report_separates_functional_invariants_from_timing(monkeypatch, tmp_path):
    monkeypatch.setattr(
        benchmark,
        "_benchmark_synthetic_repo",
        lambda: {
            "mb_per_second": 0.1,
            "elapsed_seconds": 100.0,
            "edge_cap_met": True,
            "file_count": 1,
            "total_mb": 1.0,
            "finding_count": 0,
            "flow_nodes": 1,
            "flow_edges": 1,
        },
    )
    monkeypatch.setattr(benchmark, "_benchmark_polyglot_repo", lambda: {"elapsed_seconds": 100.0})
    monkeypatch.setattr(benchmark, "_benchmark_product_source", lambda _root: {"elapsed_seconds": 100.0})
    monkeypatch.setattr(benchmark, "_workspace_archive_diagnostic", lambda _root: {})

    report = benchmark._quick_report(tmp_path)

    assert report["slo"]["all_met"] is False
    assert report["functional_invariants"] == {
        "all_met": True,
        "checks": {"synthetic_flow_edge_cap_met": True},
    }


def test_record_only_ignores_timing_failure_but_enforces_functional_invariants(tmp_path, monkeypatch):
    report = {
        "slo": {"all_met": False},
        "functional_invariants": {
            "all_met": True,
            "checks": {"synthetic_flow_edge_cap_met": True},
        },
        "raw_free": True,
    }
    monkeypatch.setattr(benchmark, "_quick_report", lambda _root: dict(report))

    output = tmp_path / "benchmark-ci.json"
    assert benchmark.main(["--record-only", "--output", str(output)]) == 0
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["slo"]["all_met"] is False
    assert written["measurement_policy"] == {
        "timing_slo_enforced": False,
        "functional_invariants_enforced": True,
        "reason": "shared hosted runners are not hardware-normalized",
    }

    report["slo"]["all_met"] = True
    report["functional_invariants"]["all_met"] = False
    report["functional_invariants"]["checks"]["synthetic_flow_edge_cap_met"] = False
    assert benchmark.main(["--record-only", "--output", str(output)]) == 1


def test_record_only_requires_explicit_nonhistorical_quick_output(tmp_path, capsys):
    output = tmp_path / "benchmark-ci.json"

    with pytest.raises(SystemExit):
        benchmark.main(["--record-only"])
    assert "requires an explicit --output" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        benchmark.main(["--record-only", "--output", "benchmark-report.json"])
    assert "must not write benchmark-report.json" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        benchmark.main(["--record-only", "--profile", "contest", "--output", str(output)])
    assert "only valid with the quick profile" in capsys.readouterr().err

    with pytest.raises(SystemExit):
        benchmark.main(["--record-only", "--target-grade-process-scaling", "--output", str(output)])
    assert "not valid with --target-grade-process-scaling" in capsys.readouterr().err


def test_process_scaling_report_records_isolated_child_metrics(tmp_path):
    counter = {"n": 0}

    def fake_job(_corpus):
        counter["n"] += 1
        return _isolated_job(benchmark.PROCESS_SCALING_BYTES, f"{counter['n']:064x}")

    report = _run_process_report(tmp_path, fake_job)

    assert report["schema"] == benchmark.PROCESS_SCHEMA
    assert report["profile"] == benchmark.PROFILE_PROCESS
    assert report["raw_free"] is True
    assert report["passed"] is True
    assert report["protocol"]["process_level_scaling_measured"] is True
    assert report["protocol"]["process_pool_executor_used"] is False
    assert report["protocol"]["thread_only_scan_lane"] is False
    assert report["protocol"]["contest_full_concurrency_lane_separate"] is True
    assert "ProcessPoolExecutor" in report["protocol"]["isolation"]
    assert "ThreadPoolExecutor" in report["protocol"]["contest_full_concurrency_mechanism"]
    assert report["corpus_binding"]["total_bytes"] == benchmark.PROCESS_SCALING_BYTES
    assert len(report["corpus_binding"]["candidate_content_set_sha256"]) == 64
    assert report["source_binding"]["source_unchanged"] is True
    assert report["claim_boundary"]["single_host"] is True
    assert report["claim_boundary"]["synthetic_inputs"] is True
    assert report["claim_boundary"]["all_benign_low_signal_inputs"] is True
    assert report["claim_boundary"]["not_production_slo"] is True
    assert report["claim_boundary"]["not_field_accuracy"] is True
    assert report["claim_boundary"]["not_third_party_comparison"] is True
    assert report["claim_boundary"]["not_hardware_normalized"] is True
    assert report["claim_boundary"]["not_finding_dense_scaling"] is True
    assert counter["n"] == len(benchmark.PROCESS_SCALING_LEVELS) * benchmark.PROCESS_SCALING_JOBS
    assert list(report["levels"]) == ["1", "2", "4"]
    assert report["levels"]["1"]["speedup_vs_1"] == 1.0
    assert report["levels"]["1"]["parallel_efficiency_vs_1"] == 1.0
    for level in benchmark.PROCESS_SCALING_LEVELS:
        row = report["levels"][str(level)]
        assert row["level"] == level
        assert row["jobs"] == benchmark.PROCESS_SCALING_JOBS
        assert row["sample_count"] == benchmark.PROCESS_SCALING_JOBS
        assert row["batch_elapsed_seconds"] >= 0
        assert row["aggregate_jobs_per_second"] is not None
        assert row["aggregate_mib_per_second"] is not None
        assert row["speedup_vs_1"] is not None
        assert row["parallel_efficiency_vs_1"] is not None
        assert row["unique_child_process_references"] is True
        assert row["unique_child_process_reference_count"] == benchmark.PROCESS_SCALING_JOBS
        assert len(row["child_process_references"]) == benchmark.PROCESS_SCALING_JOBS
        assert row["raw_free"] is True
    all_refs = [ref for row in report["levels"].values() for ref in row["child_process_references"]]
    assert len(set(all_refs)) == len(all_refs)
    assert len(report["report_fingerprint_sha256"]) == 64


def test_process_scaling_fails_closed_on_malformed_worker_output(tmp_path):
    report = _run_process_report(tmp_path, lambda _corpus: {"not": "a worker"})

    assert report["passed"] is False
    assert report["acceptance"]["checks"]["worker_outputs_well_formed"] is False


def test_process_scaling_fails_closed_on_duplicate_child_reference(tmp_path):
    report = _run_process_report(tmp_path, lambda _corpus: _isolated_job(benchmark.PROCESS_SCALING_BYTES, "a" * 64))

    assert report["passed"] is False
    assert report["acceptance"]["checks"]["unique_child_process_references"] is False


def test_process_scaling_fails_closed_on_byte_mismatch(tmp_path):
    counter = {"n": 0}

    def fake_job(_corpus):
        counter["n"] += 1
        return _isolated_job(1, f"{counter['n']:064x}")

    report = _run_process_report(tmp_path, fake_job)

    assert report["passed"] is False
    assert report["acceptance"]["checks"]["exact_corpus_bytes"] is False


def test_process_scaling_fails_closed_on_hash_mismatch(tmp_path):
    def fake_corpus(path, target_bytes):
        payload = benchmark._build_exact_corpus(path, target_bytes)
        payload["candidate_content_set_sha256"] = "0" * 64
        return payload

    counter = {"n": 0}

    def fake_job(_corpus):
        counter["n"] += 1
        return _isolated_job(benchmark.PROCESS_SCALING_BYTES, f"{counter['n']:064x}")

    report = _run_process_report(tmp_path, fake_job, corpus_builder=fake_corpus)

    assert report["passed"] is False
    assert report["acceptance"]["checks"]["candidate_content_set_matches_inventory"] is False
    assert report["acceptance"]["checks"]["candidate_content_set_bound"] is True


def test_process_scaling_fails_closed_on_incomplete_coverage(tmp_path):
    counter = {"n": 0}

    def fake_job(_corpus):
        counter["n"] += 1
        return _isolated_job(
            benchmark.PROCESS_SCALING_BYTES,
            f"{counter['n']:064x}",
            candidate_set_complete=False,
            unscanned_candidate_count=1,
        )

    report = _run_process_report(tmp_path, fake_job)

    assert report["passed"] is False
    assert report["acceptance"]["checks"]["complete_candidate_coverage"] is False


def test_process_scaling_fails_closed_on_result_variance(tmp_path):
    counter = {"n": 0}

    def fake_job(_corpus):
        counter["n"] += 1
        fingerprint = ("a" if counter["n"] == 1 else "b") * 64
        return _isolated_job(
            benchmark.PROCESS_SCALING_BYTES,
            f"{counter['n']:064x}",
            result_fingerprint_sha256=fingerprint,
        )

    report = _run_process_report(tmp_path, fake_job)

    assert report["passed"] is False
    assert report["acceptance"]["checks"]["result_fingerprint_invariance"] is False


def test_process_scaling_fails_closed_on_cross_level_result_variance(tmp_path):
    counter = {"n": 0}

    def fake_job(_corpus):
        counter["n"] += 1
        level_batch = (counter["n"] - 1) // benchmark.PROCESS_SCALING_JOBS
        fingerprint = chr(ord("a") + level_batch) * 64
        return _isolated_job(
            benchmark.PROCESS_SCALING_BYTES,
            f"{counter['n']:064x}",
            result_fingerprint_sha256=fingerprint,
        )

    report = _run_process_report(tmp_path, fake_job)

    assert all(row["fingerprints_stable"] is True for row in report["levels"].values())
    assert report["passed"] is False
    assert report["acceptance"]["checks"]["result_fingerprint_invariance"] is False
