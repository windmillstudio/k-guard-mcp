from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import metadata
from pathlib import Path
from typing import Any, Callable

from evidence_tree import package_tree_sha256, package_tree_sha256_at_revision
from k_guard_mcp.collector import collect_candidate_files, collect_files, file_inventory_fingerprint
from k_guard_mcp.scanner import KGuardScanner


SCHEMA = "k_guard_performance_benchmark.v2"
PROCESS_SCHEMA = "k_guard_target_grade_process_scaling.v1"
PROFILE_QUICK = "quick_ci"
PROFILE_CONTEST = "contest_full"
PROFILE_PROCESS = "target_grade_process_scaling"
HISTORICAL_BENCHMARK_REPORT = "benchmark-report.json"
MIB = 1024 * 1024
LATENCY_MIB = 1
COLD_SAMPLES = 20
WARMUP_SAMPLES = 1
WARM_SAMPLES = 20
SCALING_MIB = (10, 50, 100)
SCALING_SAMPLES = 5
CONCURRENCY_LEVELS = (1, 4, 8)
CONCURRENCY_JOBS = 16
PROCESS_SCALING_LEVELS = (1, 2, 4)
PROCESS_SCALING_JOBS = 4
PROCESS_SCALING_BYTES = 64 * 1024
CORPUS_FILE_BYTES = 256 * 1024
WORKER_TIMEOUT_SECONDS = 420
WORKER_BOOT_NS = time.time_ns()
PRODUCT_SOURCE_DIRECTORIES = ("src", "scripts", "tests", "examples", ".github", "benchmarks", "docs")
PRODUCT_SOURCE_FILES = (
    "pyproject.toml",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "THIRD_PARTY_NOTICES.md",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run K-Guard's deterministic single-host performance qualification.")
    parser.add_argument("--profile", choices=("quick", "contest"), default="quick")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--target-grade-process-scaling",
        action="store_true",
        help="Measure isolated child-process scaling. Requires --output and never writes benchmark-report.json.",
    )
    parser.add_argument("--_worker-mode", choices=("series", "concurrency", "isolated_job"), help=argparse.SUPPRESS)
    parser.add_argument("--_corpus", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--_repeats", type=int, default=1, help=argparse.SUPPRESS)
    parser.add_argument("--_warmup", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--_concurrency", type=int, default=1, help=argparse.SUPPRESS)
    parser.add_argument("--_jobs", type=int, default=1, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args._worker_mode:
        if args._corpus is None:
            parser.error("--_corpus is required in worker mode")
        payload = _worker_payload(
            args._worker_mode,
            args._corpus,
            repeats=args._repeats,
            warmup=args._warmup,
            concurrency=args._concurrency,
            jobs=args._jobs,
        )
        print(_canonical_json(payload))
        return 0

    if args.target_grade_process_scaling:
        if args.profile != "quick":
            parser.error("--target-grade-process-scaling is separate from --profile contest|quick")
        if args.output is None:
            parser.error("--target-grade-process-scaling requires an explicit --output path")
        if _is_historical_benchmark_report(args.output):
            parser.error("--target-grade-process-scaling must not write benchmark-report.json")
        report = _process_scaling_report(Path.cwd())
        passed = report["passed"] is True
        _write_report(args.output, report)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if passed else 1

    output = args.output if args.output is not None else Path(HISTORICAL_BENCHMARK_REPORT)
    report = _contest_report(Path.cwd()) if args.profile == "contest" else _quick_report(Path.cwd())
    passed = report["passed"] is True if args.profile == "contest" else report["slo"]["all_met"] is True
    _write_report(output, report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if passed else 1


def _quick_report(root: Path) -> dict[str, Any]:
    synthetic = _benchmark_synthetic_repo()
    polyglot = _benchmark_polyglot_repo()
    self_repo = _benchmark_product_source(root)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "profile": PROFILE_QUICK,
        "raw_free": True,
        "primary": synthetic,
        "scenarios": [synthetic, polyglot, self_repo],
        "workspace_archive_diagnostic": _workspace_archive_diagnostic(root),
        "scope_contract": {
            "self_slo_scope": "versioned product source, verification scripts, tests, examples, CI, and product documentation",
            "archival_paths_excluded_from_timing_slo": ["evidence", "submission", "generated root reports"],
            "archive_still_reported": True,
            "thresholds_unchanged": True,
        },
        "claim_boundary": _claim_boundary(),
        "slo": {
            "minimum_mb_per_second": 0.5,
            "synthetic_throughput_met": synthetic["mb_per_second"] >= 0.5,
            "polyglot_completed": polyglot["elapsed_seconds"] <= 30,
            "self_product_source_completed": self_repo["elapsed_seconds"] <= 30,
            "self_repository_completed": self_repo["elapsed_seconds"] <= 30,
        },
    }
    report["slo"]["all_met"] = bool(
        report["slo"]["synthetic_throughput_met"]
        and report["slo"]["polyglot_completed"]
        and report["slo"]["self_repository_completed"]
        and synthetic["edge_cap_met"]
    )
    report.update({key: synthetic[key] for key in ("file_count", "total_mb", "elapsed_seconds", "mb_per_second", "finding_count", "flow_nodes", "flow_edges")})
    return report


def _contest_report(
    root: Path,
    *,
    invoke_worker: Callable[..., dict[str, Any]] | None = None,
    corpus_builder: Callable[..., dict[str, Any]] | None = None,
    source_snapshot: Callable[[Path], dict[str, Any]] | None = None,
    runtime_fingerprint: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    invoke = invoke_worker or _invoke_worker
    build_corpus = corpus_builder or _build_exact_corpus
    snapshot = source_snapshot or _source_snapshot
    pre = snapshot(root)
    runtime = (runtime_fingerprint or _runtime_fingerprint)()
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        latency = build_corpus(base / "latency", LATENCY_MIB * MIB)
        cold_rows: list[dict[str, Any]] = []
        for _ in range(COLD_SAMPLES):
            started = time.perf_counter_ns()
            worker = invoke("series", Path(latency["path"]), repeats=1, warmup=0)
            row = dict(worker["samples"][0])
            row["end_to_end_seconds"] = round((time.perf_counter_ns() - started) / 1_000_000_000, 6)
            cold_rows.append(row)
        warm_worker = invoke("series", Path(latency["path"]), repeats=WARM_SAMPLES, warmup=WARMUP_SAMPLES)

        scaling: dict[str, Any] = {}
        scaling_corpora: dict[int, dict[str, Any]] = {}
        for size_mib in SCALING_MIB:
            corpus = build_corpus(base / f"scale-{size_mib}", size_mib * MIB)
            scaling_corpora[size_mib] = corpus
            rows: list[dict[str, Any]] = []
            for _ in range(SCALING_SAMPLES):
                rows.extend(invoke("series", Path(corpus["path"]), repeats=1, warmup=0)["samples"])
            scaling[str(size_mib)] = _series_summary(rows, size_mib * MIB)

        concurrency: dict[str, Any] = {}
        for level in CONCURRENCY_LEVELS:
            payload = invoke("concurrency", Path(latency["path"]), concurrency=level, jobs=CONCURRENCY_JOBS)
            summary = _series_summary(payload["samples"], LATENCY_MIB * MIB)
            summary.update(
                level=level,
                jobs=CONCURRENCY_JOBS,
                batch_elapsed_seconds=payload["batch_elapsed_seconds"],
                aggregate_jobs_per_second=round(CONCURRENCY_JOBS / payload["batch_elapsed_seconds"], 6),
                aggregate_mib_per_second=round(CONCURRENCY_JOBS * LATENCY_MIB / payload["batch_elapsed_seconds"], 6),
            )
            concurrency[str(level)] = summary

    post = snapshot(root)
    source_binding = {
        "git_head": pre["git_head"],
        "measured_git_head": pre["git_head"],
        "measured_revision_definition": "the clean source revision measured before report serialization; a later evidence-only commit may contain this report",
        "pre_run_clean": pre["clean"],
        "pre": pre,
        "post": post,
        "head_unchanged": pre["git_head"] == post["git_head"],
        "package_tree_unchanged": pre["working_package_tree_sha256"] == post["working_package_tree_sha256"],
        "runner_unchanged": pre["runner_sha256"] == post["runner_sha256"],
        "source_unchanged": pre == post,
        "working_tree_matches_head_package": pre["working_package_tree_sha256"] == pre["head_package_tree_sha256"],
        "runner_matches_head": pre["runner_sha256"] == pre["head_runner_sha256"],
        "raw_free": True,
    }
    cold = _series_summary(cold_rows, LATENCY_MIB * MIB, end_to_end=True)
    warm = _series_summary(warm_worker["samples"], LATENCY_MIB * MIB)
    c1 = concurrency["1"]["aggregate_mib_per_second"]
    for level in CONCURRENCY_LEVELS:
        row = concurrency[str(level)]
        row["speedup_vs_1"] = round(row["aggregate_mib_per_second"] / c1, 6) if c1 else None
        row["parallel_efficiency_vs_1"] = round(row["aggregate_mib_per_second"] / (c1 * level), 6) if c1 else None

    sections = [cold, warm, *scaling.values(), *concurrency.values()]
    stable = all(section["fingerprints_stable"] for section in sections)
    sample_complete = all(section["all_exact_bytes"] and section["all_candidates_complete"] for section in sections)
    exact = latency["total_bytes"] == LATENCY_MIB * MIB and all(scaling_corpora[size]["total_bytes"] == size * MIB for size in SCALING_MIB)
    corpus_complete = latency["candidate_set_complete"] is True and all(scaling_corpora[size]["candidate_set_complete"] is True for size in SCALING_MIB)
    checks = {
        "source_pre_run_clean": source_binding["pre_run_clean"] is True,
        "source_unchanged": source_binding["source_unchanged"] is True,
        "source_matches_head": source_binding["working_tree_matches_head_package"] is True and source_binding["runner_matches_head"] is True,
        "exact_corpus_bytes": exact,
        "complete_candidate_coverage": corpus_complete and sample_complete,
        "all_benign_result_invariance_observed": stable,
        "warm_1mib_p95_at_most_5s": warm["p95_seconds"] <= 5,
        "fresh_process_cold_end_to_end_p95_at_most_8s": cold["end_to_end_p95_seconds"] <= 8,
        "scaling_p50_throughput_at_least_0_5_mib_s": all(scaling[str(size)]["p50_mib_per_second"] >= 0.5 for size in SCALING_MIB),
        "each_100mib_sample_at_most_300s": scaling["100"]["max_seconds"] <= 300,
        "100mib_peak_rss_at_most_2gib": scaling["100"]["peak_rss_bytes"] <= 2 * 1024 * 1024 * 1024,
        "10_to_100mib_p50_time_ratio_at_most_15": scaling["100"]["p50_seconds"] / scaling["10"]["p50_seconds"] <= 15,
        "concurrency_4_and_8_retain_70pct_single_worker_throughput": all(concurrency[str(level)]["aggregate_mib_per_second"] >= 0.70 * c1 for level in (4, 8)),
    }
    report = {
        "schema": SCHEMA,
        "profile": PROFILE_CONTEST,
        "raw_free": True,
        "passed": all(checks.values()),
        "protocol": {
            "single_host": True,
            "latency_corpus_mib": LATENCY_MIB,
            "cold_definition": "fresh_process_cold; process and scanner are new, filesystem cache is not purged",
            "warm_definition": "persistent_process_and_scanner_warm; one scanner instance is reused after one discarded warmup",
            "cold_samples": COLD_SAMPLES,
            "warmup_samples_discarded": WARMUP_SAMPLES,
            "warm_samples": WARM_SAMPLES,
            "scaling_mib": list(SCALING_MIB),
            "scaling_samples_per_size": SCALING_SAMPLES,
            "concurrency_levels": list(CONCURRENCY_LEVELS),
            "concurrency_jobs_per_level": CONCURRENCY_JOBS,
            "concurrency_mechanism": "ThreadPoolExecutor inside one CPython process; CPU-bound scanning remains subject to the GIL",
            "process_level_scaling_measured": False,
            "maximum_corpus_file_bytes": CORPUS_FILE_BYTES,
            "percentile_method": "nearest_rank",
            "small_sample_p95_interpretation": "p95 equals the observed maximum for scaling n=5 and concurrency n=16",
            "corpus_signal_profile": "synthetic all-benign low-signal repeated comments; no finding-dense scaling lane",
            "result_fingerprint_interpretation": "stable digests on this empty-finding corpus have limited discriminating power and do not establish finding-bearing result invariance",
        },
        "environment": runtime,
        "source_binding": source_binding,
        "corpus_bindings": {
            "latency": _public_corpus_binding(latency),
            "scaling": {str(size): _public_corpus_binding(scaling_corpora[size]) for size in SCALING_MIB},
        },
        "cold": cold,
        "warm": warm,
        "warm_vs_cold": {
            "p50_seconds_delta": round(warm["p50_seconds"] - cold["p50_seconds"], 6),
            "p50_ratio": round(warm["p50_seconds"] / cold["p50_seconds"], 6),
            "peak_rss_bytes_delta": warm["peak_rss_bytes"] - cold["peak_rss_bytes"],
            "persistent_scanner_reuse_beyond_20_scans_measured": False,
        },
        "scaling": scaling,
        "concurrency": concurrency,
        "concurrency_interpretation": {
            "observation_scope": "this contest_full run only; no generalized concurrency gain is claimed",
            "level_1_p50_seconds": concurrency["1"]["p50_seconds"],
            "level_1_max_seconds": concurrency["1"]["max_seconds"],
            "level_1_baseline_may_be_depressed": True,
        },
        "acceptance": {"all_met": all(checks.values()), "checks": checks},
        "claim_boundary": _claim_boundary(),
    }
    report["report_fingerprint_sha256"] = _sha256_json(report)
    return report


def _worker_payload(mode: str, corpus: Path, *, repeats: int, warmup: int, concurrency: int, jobs: int) -> dict[str, Any]:
    if mode == "series":
        if repeats <= 0 or warmup < 0:
            raise ValueError("series counts must be positive")
        scanner = KGuardScanner()
        for _ in range(warmup):
            _scan_once(corpus, scanner=scanner)
        return {
            "mode": mode,
            "scanner_instance_reused": True,
            "samples": [_scan_once(corpus, scanner=scanner) for _ in range(repeats)],
            "raw_free": True,
        }
    if mode == "isolated_job":
        sample = _scan_once(corpus)
        return {
            "mode": mode,
            "scanner_instance_reused": False,
            "samples": [sample],
            "child_process_reference": _child_process_reference(),
            "raw_free": True,
        }
    if concurrency not in CONCURRENCY_LEVELS or jobs <= 0:
        raise ValueError("unsupported concurrency protocol")
    started = time.perf_counter_ns()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_scan_once, corpus) for _ in range(jobs)]
        rows = [future.result() for future in as_completed(futures)]
    elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
    rows.sort(key=lambda row: (row["result_fingerprint_sha256"], row["elapsed_seconds"]))
    return {"mode": mode, "samples": rows, "batch_elapsed_seconds": round(elapsed, 6), "raw_free": True}


def _invoke_worker(mode: str, corpus: Path, **kwargs: int) -> dict[str, Any]:
    command = [sys.executable, str(Path(__file__).resolve()), "--_worker-mode", mode, "--_corpus", str(corpus)]
    option_names = {"repeats": "--_repeats", "warmup": "--_warmup", "concurrency": "--_concurrency", "jobs": "--_jobs"}
    for key, value in kwargs.items():
        command.extend((option_names[key], str(value)))
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=WORKER_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("performance worker failed")
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict) or payload.get("raw_free") is not True:
        raise RuntimeError("performance worker returned an invalid envelope")
    return payload


def _is_historical_benchmark_report(path: Path) -> bool:
    return Path(path).name.casefold() == HISTORICAL_BENCHMARK_REPORT.casefold()


def _looks_like_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _child_process_reference() -> str:
    return _sha256_json({"boot_ns": WORKER_BOOT_NS, "isolated": True, "pid": os.getpid()})


def _spawn_isolated_child_job(corpus: Path) -> dict[str, Any]:
    return _invoke_worker("isolated_job", corpus)


def _validate_isolated_job_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError("malformed isolated job payload")
    if payload.get("raw_free") is not True:
        raise RuntimeError("isolated job payload is not raw-free")
    if payload.get("mode") != "isolated_job":
        raise RuntimeError("isolated job payload mode is invalid")
    if payload.get("scanner_instance_reused") is not False:
        raise RuntimeError("isolated job reused a scanner instance")
    reference = payload.get("child_process_reference")
    if not _looks_like_sha256(reference):
        raise RuntimeError("isolated job missing child process reference")
    samples = payload.get("samples")
    if not isinstance(samples, list) or len(samples) != 1 or not isinstance(samples[0], dict):
        raise RuntimeError("malformed isolated job samples")
    sample = samples[0]
    if sample.get("raw_free") is not True:
        raise RuntimeError("isolated job sample is not raw-free")
    fingerprint = sample.get("result_fingerprint_sha256")
    if not _looks_like_sha256(fingerprint):
        raise RuntimeError("isolated job sample fingerprint is malformed")
    try:
        int(sample["total_bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("isolated job sample bytes are malformed") from exc
    return payload


def _candidate_content_binding_matches(corpus: dict[str, Any]) -> bool:
    digest = corpus.get("candidate_content_set_sha256")
    if not _looks_like_sha256(digest):
        return False
    raw_path = corpus.get("path")
    if not raw_path:
        return False
    root = Path(raw_path)
    if not root.is_dir():
        return False
    files = collect_candidate_files(root)
    if not files:
        return False
    inventory = file_inventory_fingerprint(root, files)
    return inventory["candidate_content_set_sha256"] == digest


def _corpus_files_match_declared_bytes(corpus: dict[str, Any]) -> bool:
    try:
        declared = int(corpus["total_bytes"])
    except (KeyError, TypeError, ValueError):
        return False
    raw_path = corpus.get("path")
    if not raw_path:
        return False
    root = Path(raw_path)
    if not root.is_dir():
        return False
    files = collect_candidate_files(root)
    if not files:
        return False
    return sum(path.stat().st_size for path in files) == declared


def _process_level_summary(
    payloads: list[dict[str, Any]],
    *,
    level: int,
    jobs: int,
    total_bytes: int,
    batch_elapsed_seconds: float,
) -> dict[str, Any]:
    if len(payloads) != jobs:
        raise RuntimeError("incomplete isolated job coverage")
    references: list[str] = []
    samples: list[dict[str, Any]] = []
    for payload in payloads:
        validated = _validate_isolated_job_payload(payload)
        references.append(str(validated["child_process_reference"]))
        samples.append(validated["samples"][0])
    fingerprints = sorted({str(sample["result_fingerprint_sha256"]) for sample in samples})
    elapsed = batch_elapsed_seconds
    mib = total_bytes / MIB
    return {
        "level": level,
        "jobs": jobs,
        "sample_count": len(samples),
        "batch_elapsed_seconds": round(elapsed, 6),
        "aggregate_jobs_per_second": round(jobs / elapsed, 6) if elapsed else None,
        "aggregate_mib_per_second": round((jobs * mib) / elapsed, 6) if elapsed else None,
        "child_process_references": sorted(references),
        "unique_child_process_reference_count": len(set(references)),
        "unique_child_process_references": len(set(references)) == len(references),
        "result_fingerprints_sha256": fingerprints,
        "fingerprints_stable": len(fingerprints) == 1,
        "all_exact_bytes": all(int(sample["total_bytes"]) == total_bytes for sample in samples),
        "all_candidates_complete": all(
            sample.get("candidate_set_complete") is True
            and int(sample.get("unscanned_candidate_count", -1)) == 0
            and int(sample.get("oversized_candidate_count", -1)) == 0
            for sample in samples
        ),
        "raw_free": all(payload.get("raw_free") is True and sample.get("raw_free") is True for payload, sample in zip(payloads, samples, strict=True)),
    }


def _measure_isolated_child_levels(
    corpus: dict[str, Any],
    *,
    invoke_isolated_job: Callable[[Path], dict[str, Any]],
) -> dict[str, Any]:
    corpus_path = Path(corpus["path"])
    total_bytes = int(corpus["total_bytes"])
    levels: dict[str, Any] = {}
    for level in PROCESS_SCALING_LEVELS:
        started = time.perf_counter_ns()
        # Parent only coordinates subprocess (or injected) launches. Each measured
        # job is a fresh isolated_job invocation, not a reused process pool worker.
        with ThreadPoolExecutor(max_workers=level) as pool:
            futures = [pool.submit(invoke_isolated_job, corpus_path) for _ in range(PROCESS_SCALING_JOBS)]
            payloads = [future.result() for future in as_completed(futures)]
        elapsed = max((time.perf_counter_ns() - started) / 1_000_000_000, 1e-9)
        levels[str(level)] = _process_level_summary(
            payloads,
            level=level,
            jobs=PROCESS_SCALING_JOBS,
            total_bytes=total_bytes,
            batch_elapsed_seconds=elapsed,
        )
    baseline = levels["1"]["aggregate_jobs_per_second"]
    for level in PROCESS_SCALING_LEVELS:
        row = levels[str(level)]
        jobs_per_second = row["aggregate_jobs_per_second"]
        if level == 1 and not baseline:
            row["speedup_vs_1"] = 1.0
            row["parallel_efficiency_vs_1"] = 1.0
            continue
        if not baseline or not jobs_per_second:
            row["speedup_vs_1"] = None
            row["parallel_efficiency_vs_1"] = None
            continue
        speedup = round(jobs_per_second / baseline, 6)
        row["speedup_vs_1"] = speedup
        row["parallel_efficiency_vs_1"] = round(speedup / level, 6)
    return levels


def _process_claim_boundary() -> dict[str, Any]:
    return {
        "supported_claim": "single-host isolated-child process scaling on a synthetic all-benign low-signal corpus",
        "single_host": True,
        "synthetic_inputs": True,
        "all_benign_low_signal_inputs": True,
        "not_production_slo": True,
        "not_field_accuracy": True,
        "not_third_party_comparison": True,
        "not_hardware_normalized": True,
        "not_finding_dense_scaling": True,
        "not_contest_full_threadpool_lane": True,
        "one_reported_environment_only": True,
        "raw_free": True,
    }


def _process_scaling_report(
    root: Path,
    *,
    invoke_isolated_job: Callable[[Path], dict[str, Any]] | None = None,
    corpus_builder: Callable[..., dict[str, Any]] | None = None,
    source_snapshot: Callable[[Path], dict[str, Any]] | None = None,
    runtime_fingerprint: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    invoke = invoke_isolated_job or _spawn_isolated_child_job
    build_corpus = corpus_builder or _build_exact_corpus
    snapshot = source_snapshot or _source_snapshot
    pre = snapshot(root)
    runtime = (runtime_fingerprint or _runtime_fingerprint)()
    levels: dict[str, Any] = {}
    corpus: dict[str, Any] | None = None
    well_formed = True
    files_match_declared = False
    content_matches = False
    with tempfile.TemporaryDirectory() as tmp:
        try:
            corpus = build_corpus(Path(tmp) / "process-scale", PROCESS_SCALING_BYTES)
            files_match_declared = _corpus_files_match_declared_bytes(corpus)
            content_matches = _candidate_content_binding_matches(corpus)
            levels = _measure_isolated_child_levels(corpus, invoke_isolated_job=invoke)
        except (RuntimeError, ValueError, TypeError, KeyError, json.JSONDecodeError, OSError, subprocess.SubprocessError):
            well_formed = False
    post = snapshot(root)
    source_binding = {
        "git_head": pre["git_head"],
        "measured_git_head": pre["git_head"],
        "measured_revision_definition": "the clean source revision measured before report serialization; a later evidence-only commit may contain this report",
        "pre_run_clean": pre["clean"],
        "pre": pre,
        "post": post,
        "head_unchanged": pre["git_head"] == post["git_head"],
        "package_tree_unchanged": pre["working_package_tree_sha256"] == post["working_package_tree_sha256"],
        "runner_unchanged": pre["runner_sha256"] == post["runner_sha256"],
        "source_unchanged": pre == post,
        "working_tree_matches_head_package": pre["working_package_tree_sha256"] == pre["head_package_tree_sha256"],
        "runner_matches_head": pre["runner_sha256"] == pre["head_runner_sha256"],
        "raw_free": True,
    }
    level_rows = [levels[str(level)] for level in PROCESS_SCALING_LEVELS if str(level) in levels]
    all_references = [reference for row in level_rows for reference in row["child_process_references"]]
    corpus_bytes_exact = (
        corpus is not None
        and int(corpus["total_bytes"]) == PROCESS_SCALING_BYTES
        and files_match_declared
        and all(row["all_exact_bytes"] is True for row in level_rows)
    )
    content_bound = corpus is not None and _looks_like_sha256(corpus.get("candidate_content_set_sha256"))
    coverage_complete = (
        corpus is not None
        and corpus.get("candidate_set_complete") is True
        and bool(level_rows)
        and all(row["all_candidates_complete"] is True for row in level_rows)
    )
    all_result_fingerprints = {
        fingerprint
        for row in level_rows
        for fingerprint in row["result_fingerprints_sha256"]
    }
    fingerprints_stable = (
        bool(level_rows)
        and all(row["fingerprints_stable"] is True for row in level_rows)
        and len(all_result_fingerprints) == 1
    )
    unique_references = (
        bool(all_references)
        and len(all_references) == len(PROCESS_SCALING_LEVELS) * PROCESS_SCALING_JOBS
        and len(set(all_references)) == len(all_references)
        and all(row["unique_child_process_references"] is True for row in level_rows)
    )
    raw_free = (
        True
        and (corpus is None or corpus.get("raw_free") is True)
        and all(row.get("raw_free") is True for row in level_rows)
        and source_binding["raw_free"] is True
        and runtime.get("raw_free") is True
    )
    checks = {
        "worker_outputs_well_formed": well_formed and len(level_rows) == len(PROCESS_SCALING_LEVELS),
        "source_unchanged": source_binding["source_unchanged"] is True,
        "exact_corpus_bytes": corpus_bytes_exact,
        "candidate_content_set_bound": content_bound,
        "candidate_content_set_matches_inventory": content_matches,
        "complete_candidate_coverage": coverage_complete,
        "result_fingerprint_invariance": fingerprints_stable,
        "unique_child_process_references": unique_references,
        "measured_levels_1_2_4": [row.get("level") for row in level_rows] == list(PROCESS_SCALING_LEVELS),
        "raw_free": raw_free,
    }
    passed = all(checks.values())
    report = {
        "schema": PROCESS_SCHEMA,
        "profile": PROFILE_PROCESS,
        "raw_free": True,
        "passed": passed,
        "protocol": {
            "single_host": True,
            "process_scaling_levels": list(PROCESS_SCALING_LEVELS),
            "jobs_per_level": PROCESS_SCALING_JOBS,
            "corpus_bytes": PROCESS_SCALING_BYTES,
            "isolation": "fresh CPython child process per measured job via subprocess.run; no ProcessPoolExecutor and no process-pool worker reuse",
            "parent_coordination": "bounded concurrent subprocess launches; scanning does not run on ThreadPoolExecutor",
            "contest_full_concurrency_lane_separate": True,
            "contest_full_concurrency_mechanism": "ThreadPoolExecutor inside one CPython process; CPU-bound scanning remains subject to the GIL",
            "process_pool_executor_used": False,
            "thread_only_scan_lane": False,
            "process_level_scaling_measured": True,
            "child_process_reference_kind": "sha256 of pid plus process boot timestamp; pid and paths are not returned",
            "corpus_signal_profile": "synthetic all-benign low-signal repeated comments; no finding-dense scaling lane",
            "result_fingerprint_interpretation": "stable digests on this empty-finding corpus have limited discriminating power and do not establish finding-bearing result invariance",
            "raw_free": True,
        },
        "environment": runtime,
        "source_binding": source_binding,
        "corpus_binding": _public_corpus_binding(corpus) if corpus is not None else None,
        "levels": levels,
        "acceptance": {"all_met": passed, "checks": checks},
        "claim_boundary": _process_claim_boundary(),
    }
    report["report_fingerprint_sha256"] = _sha256_json(report)
    return report


def _scan_once(corpus: Path, *, scanner: KGuardScanner | None = None) -> dict[str, Any]:
    files = collect_candidate_files(corpus)
    total_bytes = sum(path.stat().st_size for path in files)
    peak_before = _peak_rss_bytes()
    started = time.perf_counter_ns()
    result = (scanner or KGuardScanner()).scan_workspace(corpus)
    elapsed = (time.perf_counter_ns() - started) / 1_000_000_000
    peak_after = _peak_rss_bytes()
    inventory = result.metadata.get("review_coverage", {}).get("inventory", {})
    return {
        "elapsed_seconds": round(elapsed, 6),
        "total_bytes": total_bytes,
        "peak_rss_bytes": peak_after,
        "peak_rss_growth_bytes": max(0, peak_after - peak_before),
        "candidate_count": len(files),
        "reviewed_candidate_count": inventory.get("reviewed_candidate_count"),
        "unscanned_candidate_count": inventory.get("unscanned_candidate_count"),
        "oversized_candidate_count": inventory.get("oversized_candidate_count"),
        "candidate_set_complete": inventory.get("candidate_set_complete"),
        "full_semantic_candidate_set_complete": inventory.get("full_semantic_candidate_set_complete"),
        **_result_projection(result),
        "raw_free": True,
    }


def _result_projection(result: Any) -> dict[str, Any]:
    rules = Counter(str(finding.rule_id) for finding in result.findings)
    projection = {
        "finding_count": len(result.findings),
        "flow_node_count": len(result.flow_map.nodes) if result.flow_map else 0,
        "flow_edge_count": len(result.flow_map.edges) if result.flow_map else 0,
        "rule_id_multiset_sha256": _sha256_json(sorted(rules.items())),
    }
    projection["result_fingerprint_sha256"] = _sha256_json(projection)
    return projection


def _build_exact_corpus(root: Path, target_bytes: int, *, max_file_bytes: int = CORPUS_FILE_BYTES) -> dict[str, Any]:
    if target_bytes <= 0 or max_file_bytes <= 0 or max_file_bytes > CORPUS_FILE_BYTES:
        raise ValueError("invalid exact corpus size")
    root.mkdir(parents=True, exist_ok=False)
    remaining = target_bytes
    index = 0
    line = b"// k-guard deterministic low-signal capacity payload 0123456789abcdef\n"
    while remaining:
        size = min(max_file_bytes, remaining)
        (root / f"capacity_{index:04d}.ts").write_bytes((line * ((size // len(line)) + 1))[:size])
        remaining -= size
        index += 1
    files = collect_candidate_files(root)
    inventory = file_inventory_fingerprint(root, files)
    return {
        "path": str(root),
        "total_bytes": sum(path.stat().st_size for path in files),
        "file_count": len(files),
        "maximum_file_bytes": max(path.stat().st_size for path in files),
        "candidate_set_complete": inventory["content_fingerprint_complete"],
        "candidate_path_set_sha256": inventory["candidate_path_set_sha256"],
        "candidate_content_set_sha256": inventory["candidate_content_set_sha256"],
        "raw_free": True,
    }


def _public_corpus_binding(corpus: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in corpus.items() if key != "path"}


def _nearest_rank(values: list[float], quantile: float) -> float:
    if not values or not 0 < quantile <= 1:
        raise ValueError("nearest-rank requires samples and 0 < quantile <= 1")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def _series_summary(rows: list[dict[str, Any]], total_bytes: int, *, end_to_end: bool = False) -> dict[str, Any]:
    if not rows:
        raise ValueError("samples required")
    seconds = [float(row["elapsed_seconds"]) for row in rows]
    p50 = _nearest_rank(seconds, 0.50)
    p95 = _nearest_rank(seconds, 0.95)
    fingerprints = sorted({str(row["result_fingerprint_sha256"]) for row in rows})
    summary: dict[str, Any] = {
        "sample_count": len(rows),
        "p50_seconds": round(p50, 6),
        "p95_seconds": round(p95, 6),
        "max_seconds": round(max(seconds), 6),
        "p50_mib_per_second": round((total_bytes / MIB) / p50, 6) if p50 else None,
        "peak_rss_bytes": max(int(row["peak_rss_bytes"]) for row in rows),
        "result_fingerprints_sha256": fingerprints,
        "repeat_fingerprint_sha256": _sha256_json([str(row["result_fingerprint_sha256"]) for row in rows]),
        "fingerprints_stable": len(fingerprints) == 1,
        "all_exact_bytes": all(int(row["total_bytes"]) == total_bytes for row in rows),
        "all_candidates_complete": all(
            row.get("candidate_set_complete") is True
            and int(row.get("unscanned_candidate_count", -1)) == 0
            and int(row.get("oversized_candidate_count", -1)) == 0
            for row in rows
        ),
        "raw_free": True,
    }
    if end_to_end:
        values = [float(row["end_to_end_seconds"]) for row in rows]
        summary["end_to_end_p50_seconds"] = round(_nearest_rank(values, 0.50), 6)
        summary["end_to_end_p95_seconds"] = round(_nearest_rank(values, 0.95), 6)
    return summary


def _peak_rss_bytes() -> int:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        ok = psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        if not ok:
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)
    import resource

    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if sys.platform == "darwin" else value * 1024


def _memory_backend() -> str:
    return "windows_peak_working_set" if os.name == "nt" else ("darwin_ru_maxrss_bytes" if sys.platform == "darwin" else "posix_ru_maxrss_kib")


def _runtime_fingerprint() -> dict[str, Any]:
    distributions = sorted(f"{(item.metadata.get('Name') or '').casefold()}=={item.version}" for item in metadata.distributions())
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_cache_tag": sys.implementation.cache_tag,
        "python_executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "os_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "installed_distribution_count": len(distributions),
        "installed_distribution_set_sha256": _sha256_json(distributions),
        "peak_memory_backend": _memory_backend(),
        "hostname_returned": False,
        "absolute_path_returned": False,
        "raw_free": True,
    }


def _source_snapshot(root: Path) -> dict[str, Any]:
    head = _git(root, "rev-parse", "HEAD")
    runner = Path(__file__).resolve()
    head_runner = subprocess.run(["git", "show", f"{head}:scripts/benchmark.py"], cwd=root, capture_output=True, check=True).stdout
    locks = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ("requirements-build.lock", "requirements-evidence.lock")
    }
    return {
        "git_head": head,
        "clean": _git(root, "status", "--porcelain") == "",
        "package_tree_hash_schema": "k_guard_package_tree_sha256.v2",
        "working_package_tree_sha256": package_tree_sha256(root / "src/k_guard_mcp"),
        "head_package_tree_sha256": package_tree_sha256_at_revision(root, head),
        "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
        "head_runner_sha256": hashlib.sha256(head_runner).hexdigest(),
        "lock_sha256": locks,
        "raw_free": True,
    }


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def _claim_boundary() -> dict[str, Any]:
    return {
        "supported_claim": "single-host scanner capacity on the contest_full synthetic all-benign low-signal protocol",
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
    }


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.write_bytes(rendered.encode("utf-8"))


def _benchmark_synthetic_repo() -> dict[str, object]:
    file_count = 240
    lines_per_file = 180
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        total_bytes = 0
        sample = "export async function POST(req) {\n  const email = await req.body.email;\n  console.log(email);\n  return Response.json({ ok: true });\n}\n"
        for idx in range(file_count):
            content = (sample + f"// benign line {idx}\n") * lines_per_file
            path = root / f"route_{idx}.ts"
            path.write_text(content, encoding="utf-8")
            total_bytes += len(content.encode("utf-8"))
        start = time.perf_counter()
        result = KGuardScanner().scan_workspace(root)
        elapsed = time.perf_counter() - start
    mb = total_bytes / MIB
    flow_edges = len(result.flow_map.edges) if result.flow_map else 0
    maximum_flow_edges = file_count * 80
    return {
        "name": "synthetic_typescript_routes",
        "file_count": file_count,
        "total_mb": round(mb, 3),
        "elapsed_seconds": round(elapsed, 3),
        "mb_per_second": round(mb / elapsed, 3) if elapsed else None,
        "finding_count": len(result.findings),
        "flow_nodes": len(result.flow_map.nodes) if result.flow_map else 0,
        "flow_edges": flow_edges,
        "maximum_flow_edges": maximum_flow_edges,
        "edge_cap_met": flow_edges <= maximum_flow_edges,
    }


def _benchmark_existing_repo(root: Path, name: str) -> dict[str, object]:
    files = collect_files(root)
    total_bytes = sum(path.stat().st_size for path in files)
    start = time.perf_counter()
    result = KGuardScanner().scan_workspace(root)
    elapsed = time.perf_counter() - start
    mb = total_bytes / MIB
    return {
        "name": name,
        "file_count": len(files),
        "total_mb": round(mb, 3),
        "elapsed_seconds": round(elapsed, 3),
        "mb_per_second": round(mb / elapsed, 3) if elapsed else None,
        "finding_count": len(result.findings),
        "flow_nodes": len(result.flow_map.nodes) if result.flow_map else 0,
        "flow_edges": len(result.flow_map.edges) if result.flow_map else 0,
    }


def _benchmark_product_source(root: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "product-source"
        staged.mkdir()
        staged_items: list[str] = []
        for relative in PRODUCT_SOURCE_DIRECTORIES:
            source = root / relative
            if source.exists():
                shutil.copytree(source, staged / relative)
                staged_items.append(relative)
        for relative in PRODUCT_SOURCE_FILES:
            source = root / relative
            if source.is_file():
                shutil.copy2(source, staged / relative)
                staged_items.append(relative)
        report = _benchmark_existing_repo(staged, "self_product_source_tree")
    report["scope_items"] = staged_items
    report["scope_is_staged_copy"] = True
    return report


def _workspace_archive_diagnostic(root: Path) -> dict[str, object]:
    files = collect_candidate_files(root)
    total_bytes = 0
    unreadable = 0
    for path in files:
        try:
            total_bytes += path.stat().st_size
        except OSError:
            unreadable += 1
    return {
        "candidate_file_count": len(files),
        "total_mb": round(total_bytes / MIB, 3),
        "unreadable_metadata_count": unreadable,
        "timed_as_performance_slo": False,
    }


def _benchmark_polyglot_repo() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        samples = {
            "app/routes/user.ts": "export async function POST(req) { const email = await req.body.email; console.log(email); return Response.json({ok:true}); }\n",
            "api/users.py": "def handler(request):\n    phone = request.json.get('phone')\n    print(phone)\n    return {'ok': True}\n",
            "config/.env.example": "DATABASE_URL=postgres://alice:example@localhost/app\nNEXT_PUBLIC_API_URL=http://localhost:3000\n",
            "infra/compose.yaml": "services:\n  app:\n    environment:\n      debug: 'false'\n",
            "README.md": "# Sample service\n\nThis repository imitates a small polyglot web service.\n",
        }
        total_bytes = 0
        for relative, content in samples.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            repeated = content * 400
            path.write_text(repeated, encoding="utf-8")
            total_bytes += len(repeated.encode("utf-8"))
        start = time.perf_counter()
        result = KGuardScanner().scan_workspace(root)
        elapsed = time.perf_counter() - start
    mb = total_bytes / MIB
    return {
        "name": "polyglot_real_world_shaped_repo",
        "file_count": len(samples),
        "total_mb": round(mb, 3),
        "elapsed_seconds": round(elapsed, 3),
        "mb_per_second": round(mb / elapsed, 3) if elapsed else None,
        "finding_count": len(result.findings),
        "flow_nodes": len(result.flow_map.nodes) if result.flow_map else 0,
        "flow_edges": len(result.flow_map.edges) if result.flow_map else 0,
    }


if __name__ == "__main__":
    raise SystemExit(main())
