from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from contest_readiness import _current_public_replay_status
from evidence_tree import (
    TREE_HASH_SCHEMA,
    package_tree_sha256,
)


SCHEMA = "k_guard_ai_public_benchmark_scorecard.v1"
PROCESS_SCALING = Path("evidence/qualification/target-grade-process-scaling-r1.json")
EVIDENCE_MANIFEST = Path("evidence/SHA256SUMS")
CURRENT_PUBLIC_MANIFEST = Path("evidence/public/development-apps-12-v3-manifest.json")
CURRENT_PUBLIC_ROOT = Path("evidence/public/current-source-replay-v1")
KOREAN_MANIFEST = Path("evidence/holdout/korean-sensitive-org-v1.cjson")
KOREAN_REPORT = Path("evidence/holdout/korean-sensitive-org-v1-report.json")
OWASP_PYTHON_ROOT = Path("evidence/public/owasp-benchmark-python-f1291485")
HOLDOUT_ROOT = Path("evidence/public/holdout")
BENCHMARKJAVA_PREREGISTRATION = HOLDOUT_ROOT / "benchmarkjava-cwe89-preregistration.json"
BENCHMARKJAVA_FIRST_RESULT = HOLDOUT_ROOT / "benchmarkjava-cwe89-first-result.json"
JULIET_PREREGISTRATION = HOLDOUT_ROOT / "juliet-java-cwe89-preregistration.json"
JULIET_FIRST_RESULT = HOLDOUT_ROOT / "juliet-java-cwe89-first-result.json"
JULIET_REPLAY = HOLDOUT_ROOT / "juliet-java-cwe89-remediation-replay.json"
FULL_SHA256 = re.compile(r"[0-9a-f]{64}")
FULL_REVISION = re.compile(r"[0-9a-f]{40}")
REDACTED_REF = re.compile(r"[0-9a-f]{16}")
GLOBAL_AGGREGATE_KEYS = frozenset(
    {
        "metrics",
        "score",
        "true_positive",
        "false_positive",
        "false_negative",
        "true_negative",
        "recall",
        "precision",
        "specificity",
        "false_positive_rate",
        "accuracy",
    }
)
PACKAGE_TEXT_SUFFIXES = {
    ".cs",
    ".go",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".md",
    ".php",
    ".py",
    ".rb",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}


class ScorecardError(RuntimeError):
    pass


def _source_commit_time(root: Path) -> str:
    try:
        completed = subprocess.run(
            _git_command(
                root,
                "log",
                "-1",
                "--format=%cI",
                "--",
                "scripts/ai_public_benchmark_scorecard.py",
                "scripts/contest_readiness.py",
                "src/k_guard_mcp",
            ),
            cwd=root,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        return "unavailable"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "unavailable"
    return value if parsed.tzinfo is not None else "unavailable"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ScorecardError(f"unreadable_json:{path.as_posix()}") from error
    if not isinstance(payload, dict):
        raise ScorecardError(f"json_object_required:{path.as_posix()}")
    return payload


def _manifest_index(root: Path) -> tuple[dict[str, str], list[str]]:
    path = root / EVIDENCE_MANIFEST
    errors: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {}, ["evidence_manifest_unreadable"]
    index: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9a-f]{64})  (evidence/[^\x00\r\n]+)", line)
        if match is None:
            errors.append(f"evidence_manifest_row_invalid:{line_number}")
            continue
        digest, relative = match.groups()
        pure = Path(relative)
        if (
            "\\" in relative
            or pure.is_absolute()
            or ".." in pure.parts
            or relative == EVIDENCE_MANIFEST.as_posix()
            or relative in index
        ):
            errors.append(f"evidence_manifest_path_invalid:{line_number}")
            continue
        index[relative] = digest
    return index, sorted(errors)


def _manifest_hash_errors(
    root: Path,
    index: dict[str, str],
    relatives: Iterable[Path],
) -> list[str]:
    errors: list[str] = []
    for relative in sorted({path.as_posix() for path in relatives}):
        path = root / relative
        if not path.is_file():
            errors.append(f"evidence_file_missing:{relative}")
            continue
        expected = index.get(relative)
        if expected is None:
            errors.append(f"evidence_manifest_entry_missing:{relative}")
        elif _sha256(path) != expected:
            errors.append(f"evidence_manifest_digest_mismatch:{relative}")
    return errors


def _git_revision_exists(root: Path, revision: object) -> bool:
    if not isinstance(revision, str) or FULL_REVISION.fullmatch(revision) is None:
        return False
    try:
        completed = subprocess.run(
            _git_command(root, "cat-file", "-e", f"{revision}^{{commit}}"),
            cwd=root,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _git_blob_sha256(root: Path, revision: str, relative: str) -> str | None:
    try:
        completed = subprocess.run(
            _git_command(root, "show", f"{revision}:{relative}"),
            cwd=root,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return hashlib.sha256(completed.stdout).hexdigest() if completed.returncode == 0 else None


def _git_command(root: Path, *arguments: str) -> list[str]:
    # Worktrees used by CI may be materialized by a sandbox identity. Scoping
    # safe.directory to this read-only invocation avoids mutating user config.
    safe_root = root.resolve().as_posix()
    return ["git", "-c", f"safe.directory={safe_root}", *arguments]


def _package_tree_sha256_at_revision(root: Path, revision: str) -> str:
    prefix = "src/k_guard_mcp"
    try:
        listing = subprocess.run(
            _git_command(root, "ls-tree", "-r", "-z", revision, "--", prefix),
            cwd=root,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("revision cannot be resolved") from error
    if listing.returncode != 0:
        raise ValueError("revision cannot be resolved")

    entries: list[tuple[str, bytes]] = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            _mode, object_type, object_id = metadata.split(b" ", 2)
            tracked = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("unexpected git tree record") from error
        if object_type != b"blob" or not tracked.startswith(prefix + "/"):
            continue
        relative = Path(tracked[len(prefix) + 1 :])
        if "__pycache__" in relative.parts or relative.suffix.casefold() in {".pyc", ".pyo"}:
            continue
        try:
            blob = subprocess.run(
                _git_command(root, "cat-file", "blob", object_id.decode("ascii")),
                cwd=root,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as error:
            raise ValueError(f"package blob cannot be read: {tracked}") from error
        if blob.returncode != 0:
            raise ValueError(f"package blob cannot be read: {tracked}")
        content = blob.stdout
        if relative.suffix.casefold() in PACKAGE_TEXT_SUFFIXES:
            content = content.replace(b"\r\n", b"\n")
        entries.append((relative.as_posix(), content))
    if not entries:
        raise ValueError("package tree contains no files")

    digest = hashlib.sha256()
    digest.update((TREE_HASH_SCHEMA + "\0").encode("ascii"))
    for relative, content in sorted(entries):
        relative_bytes = relative.encode("utf-8")
        digest.update(len(relative_bytes).to_bytes(4, "big"))
        digest.update(relative_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _schema_error(payload: dict[str, Any], expected: str) -> list[str]:
    return [] if payload.get("schema") == expected else [f"schema_invalid:{expected}"]


def _integrity(errors: Iterable[str]) -> dict[str, object]:
    normalized = sorted(set(errors))
    return {
        "status": "PASS" if not normalized else "FAIL",
        "errors": normalized,
    }


def _summary_metrics(metrics: object) -> dict[str, object]:
    if not isinstance(metrics, dict):
        return {}
    allowed = (
        "total_official_case_count",
        "supported_case_count",
        "unsupported_case_count",
        "supported_category_count",
        "case_count",
        "positive_case_count",
        "negative_case_count",
        "passed_count",
        "failed_count",
        "total_cases",
        "vulnerable_cases",
        "clean_cases",
        "total_units",
        "vulnerable_units",
        "clean_units",
        "true_positive",
        "false_negative",
        "false_positive",
        "true_negative",
        "recall",
        "precision",
        "specificity",
        "false_positive_rate",
        "accuracy",
    )
    return {name: metrics[name] for name in allowed if name in metrics}


def _lane(
    lane_id: str,
    role: str,
    paths: Iterable[Path],
    manifest: dict[str, str],
    root: Path,
    errors: Iterable[str],
    recorded_result: dict[str, object],
    claim_boundary: object,
) -> dict[str, object]:
    all_errors = [*errors, *_manifest_hash_errors(root, manifest, paths)]
    boundary = claim_boundary if isinstance(claim_boundary, (dict, str)) else {}
    return {
        "lane_id": lane_id,
        "evidence_role": role,
        "evidence_integrity": _integrity(all_errors),
        "recorded_result": recorded_result,
        "claim_boundary": boundary,
        "raw_returned": False,
    }


def _korean_lane(root: Path, manifest: dict[str, str]) -> dict[str, object]:
    evidence_paths = (KOREAN_MANIFEST, KOREAN_REPORT)
    errors: list[str] = []
    try:
        source_manifest = _json_object(root / KOREAN_MANIFEST)
        report = _json_object(root / KOREAN_REPORT)
    except ScorecardError as error:
        return _lane(
            "current_korean_synthetic_inspection",
            "current_evaluator_authored_post_implementation_synthetic_inspection",
            evidence_paths,
            manifest,
            root,
            [str(error)],
            {},
            {},
        )
    errors.extend(_schema_error(source_manifest, "k_guard_korean_sensitive_org_holdout_manifest.v1"))
    errors.extend(_schema_error(report, "k_guard_korean_sensitive_org_holdout_report.v1"))
    report_manifest = report.get("manifest") if isinstance(report.get("manifest"), dict) else {}
    if report_manifest.get("schema") != source_manifest.get("schema"):
        errors.append("manifest_schema_binding_mismatch")
    if report_manifest.get("sha256") != _sha256(root / KOREAN_MANIFEST):
        errors.append("manifest_digest_binding_mismatch")

    binding = report.get("source_binding") if isinstance(report.get("source_binding"), dict) else {}
    revision = binding.get("git_head")
    current_package_hash = package_tree_sha256(root / "src" / "k_guard_mcp")
    if binding.get("package_tree_hash_schema") != TREE_HASH_SCHEMA:
        errors.append("package_tree_hash_schema_invalid")
    if not _git_revision_exists(root, revision):
        errors.append("source_revision_unresolvable")
    else:
        try:
            revision_hash = _package_tree_sha256_at_revision(root, str(revision))
        except (OSError, ValueError):
            errors.append("source_revision_package_hash_unavailable")
        else:
            if revision_hash != binding.get("git_head_package_tree_sha256"):
                errors.append("source_revision_package_hash_mismatch")
    if current_package_hash != binding.get("working_package_tree_sha256"):
        errors.append("working_package_hash_mismatch")
    if binding.get("working_package_tree_matches_head") is not True:
        errors.append("working_package_tree_not_bound")
    for row in binding.get("source_files", []):
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            errors.append("source_file_binding_invalid")
            continue
        relative = str(row["path"])
        path = root / relative
        if not path.is_file() or _sha256(path) != row.get("sha256"):
            errors.append(f"source_file_digest_mismatch:{relative}")
        if isinstance(revision, str) and _git_blob_sha256(root, revision, relative) != row.get("head_sha256"):
            errors.append(f"source_file_revision_digest_mismatch:{relative}")
        if row.get("working_matches_head") is not True:
            errors.append(f"source_file_not_bound:{relative}")
    if report.get("passed") is not True or report.get("raw_returned") is not False:
        errors.append("recorded_result_contract_invalid")
    return _lane(
        "current_korean_synthetic_inspection",
        "current_evaluator_authored_post_implementation_synthetic_inspection",
        evidence_paths,
        manifest,
        root,
        errors,
        {
            "recorded_passed": report.get("passed"),
            "metrics": _summary_metrics(report.get("metrics")),
        },
        report.get("claim_boundary"),
    )


def _recorded_public_run_metrics(campaign: dict[str, Any]) -> tuple[dict[str, object], list[str]]:
    app_rows = campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    run_lists = [
        row.get("runs") if isinstance(row, dict) and isinstance(row.get("runs"), list) else []
        for row in app_rows
    ]
    run_counts = [len(runs) for runs in run_lists]
    exact_two_per_app = bool(app_rows) and all(
        len(runs) == 2
        and all(isinstance(run, dict) for run in runs)
        and {run.get("run") for run in runs} == {1, 2}
        for runs in run_lists
    )
    metrics: dict[str, object] = {
        "runs_per_app": 2 if exact_two_per_app else None,
        "total_app_runs": sum(run_counts),
    }
    errors = [] if exact_two_per_app else ["current_public_recorded_run_rows_not_exact_two_per_app"]
    return metrics, errors


def _current_public_lane(root: Path, manifest: dict[str, str]) -> dict[str, object]:
    paths = [
        CURRENT_PUBLIC_MANIFEST,
        CURRENT_PUBLIC_ROOT / "campaign.json",
        CURRENT_PUBLIC_ROOT / "candidate-queue.json",
        CURRENT_PUBLIC_ROOT / "reference-probes.json",
    ]
    report_root = root / CURRENT_PUBLIC_ROOT / "reports"
    if report_root.is_dir():
        paths.extend(
            path.relative_to(root)
            for path in report_root.iterdir()
            if path.is_file()
        )
    errors: list[str] = []
    try:
        campaign = _json_object(root / CURRENT_PUBLIC_ROOT / "campaign.json")
        probes = _json_object(root / CURRENT_PUBLIC_ROOT / "reference-probes.json")
        current_package_hash = package_tree_sha256(root / "src" / "k_guard_mcp")
        metrics, validation_errors = _current_public_replay_status(
            root / CURRENT_PUBLIC_ROOT,
            current_package_hash,
            root,
        )
        errors.extend(validation_errors)
        recorded_run_metrics, recorded_run_errors = _recorded_public_run_metrics(campaign)
        metrics = {**metrics, **recorded_run_metrics}
        errors.extend(recorded_run_errors)
        revision = campaign.get("source_revision")
        if "current_public_source_revision_unresolvable" in errors and isinstance(revision, str):
            try:
                independently_verified = (
                    _git_revision_exists(root, revision)
                    and _package_tree_sha256_at_revision(root, revision) == current_package_hash
                )
            except (OSError, ValueError):
                independently_verified = False
            if independently_verified:
                errors.remove("current_public_source_revision_unresolvable")
    except (OSError, ScorecardError, ValueError) as error:
        campaign = {}
        probes = {}
        metrics = {}
        errors.append(f"current_public_validation_failed:{type(error).__name__}")
    return _lane(
        "current_public_app_replay",
        "current_public_development_replay",
        paths,
        manifest,
        root,
        errors,
        {
            "metrics": metrics,
            "source_revision": campaign.get("source_revision"),
        },
        {
            "campaign": campaign.get("claim_boundary", {}),
            "selected_probe_metric": probes.get("claim_boundary", ""),
        },
    )


def _redacted_ref_valid(value: object) -> bool:
    return (
        isinstance(value, dict)
        and REDACTED_REF.fullmatch(str(value.get("hash") or "")) is not None
        and value.get("hash_scheme") == "hmac-sha256:operator-keyed:len16"
        and value.get("raw_returned") is False
    )


def _owasp_python_lane(root: Path, manifest: dict[str, str]) -> dict[str, object]:
    files = {
        "primary_guardian": OWASP_PYTHON_ROOT / "primary-guardian.json",
        "repeat_guardian": OWASP_PYTHON_ROOT / "repeat-guardian.json",
        "ground_truth": OWASP_PYTHON_ROOT / "ground-truth.csv",
        "candidate_review": OWASP_PYTHON_ROOT / "candidate-review.csv",
        "benchmark_validation": OWASP_PYTHON_ROOT / "benchmark-validation.json",
    }
    score_path = OWASP_PYTHON_ROOT / "benchmark-score.json"
    paths = [score_path, *files.values()]
    errors: list[str] = []
    try:
        score = _json_object(root / score_path)
    except ScorecardError as error:
        score = {}
        errors.append(str(error))
    errors.extend(_schema_error(score, "k_guard_owasp_python_benchmark.v1"))
    if not _redacted_ref_valid(score.get("repository_ref")):
        errors.append("repository_ref_invalid")
    if not _redacted_ref_valid(score.get("revision_ref")):
        errors.append("revision_ref_invalid")
    artifacts = score.get("artifacts") if isinstance(score.get("artifacts"), dict) else {}
    for name, relative in files.items():
        binding = artifacts.get(name) if isinstance(artifacts.get(name), dict) else {}
        path = root / relative
        if not path.is_file():
            continue
        if binding.get("content_sha256") != _sha256(path):
            errors.append(f"declared_artifact_digest_mismatch:{name}")
        if binding.get("byte_count") != path.stat().st_size:
            errors.append(f"declared_artifact_size_mismatch:{name}")
        if binding.get("raw_returned") is not False:
            errors.append(f"declared_artifact_raw_contract_invalid:{name}")
    candidate = (
        score.get("all_high_critical_candidate_validation")
        if isinstance(score.get("all_high_critical_candidate_validation"), dict)
        else {}
    )
    lane = _lane(
        "historical_owasp_benchmark_python",
        "historical_public_development_benchmark",
        paths,
        manifest,
        root,
        errors,
        {
            "official_supported_case_score": _summary_metrics(score.get("score")),
            "all_high_critical_candidate_validation": {
                "verdict_counts": candidate.get("verdict_counts", {}),
                "rates": candidate.get("rates", {}),
            },
            "validation_claim_status": score.get("validation_claim_status"),
        },
        {
            **(score.get("claim_boundary") if isinstance(score.get("claim_boundary"), dict) else {}),
            "source_revision_is_operator_keyed_redacted_reference": True,
            "source_revision_not_resolvable_from_scorecard": True,
        },
    )
    integrity_failed = lane["evidence_integrity"]["status"] == "FAIL"
    lane["recorded_result"]["validation_claim_status_admissible_for_current_claims"] = False
    lane["recorded_result"]["validation_claim_status_inadmissibility_reason"] = (
        "evidence_integrity_fail"
        if integrity_failed
        else "historical_lane_not_a_current_claim"
    )
    return lane


def _revision_errors(root: Path, revisions: dict[str, object]) -> list[str]:
    return [
        f"source_revision_unresolvable:{name}"
        for name, revision in revisions.items()
        if not _git_revision_exists(root, revision)
    ]


def _benchmarkjava_lane(root: Path, manifest: dict[str, str]) -> dict[str, object]:
    paths = (BENCHMARKJAVA_PREREGISTRATION, BENCHMARKJAVA_FIRST_RESULT)
    errors: list[str] = []
    try:
        preregistration = _json_object(root / BENCHMARKJAVA_PREREGISTRATION)
        result = _json_object(root / BENCHMARKJAVA_FIRST_RESULT)
    except ScorecardError as error:
        preregistration, result = {}, {}
        errors.append(str(error))
    errors.extend(_schema_error(preregistration, "k_guard_public_holdout_preregistration.v1"))
    errors.extend(_schema_error(result, "k_guard_public_holdout_result.v1"))
    preregistration_path = root / BENCHMARKJAVA_PREREGISTRATION
    if (
        preregistration_path.is_file()
        and result.get("preregistration_sha256") != _sha256(preregistration_path)
    ):
        errors.append("preregistration_digest_mismatch")
    if preregistration.get("holdout_id") != result.get("holdout_id"):
        errors.append("holdout_id_mismatch")
    if preregistration.get("scanner_revision") != result.get("scanner_revision"):
        errors.append("scanner_revision_mismatch")
    errors.extend(
        _revision_errors(
            root,
            {
                "scanner": result.get("scanner_revision"),
                "execution": result.get("execution_revision"),
            },
        )
    )
    integrity = result.get("integrity") if isinstance(result.get("integrity"), dict) else {}
    if not integrity or any(value is not True for value in integrity.values()):
        errors.append("recorded_integrity_not_all_true")
    if result.get("verdict") != "hold" or result.get("passed") is not False:
        errors.append("benchmarkjava_hold_not_preserved")
    return _lane(
        "historical_owasp_benchmarkjava_cwe89",
        "historical_public_preregistered_first_result",
        paths,
        manifest,
        root,
        errors,
        {
            "recorded_verdict": result.get("verdict"),
            "recorded_passed": result.get("passed"),
            "metrics": _summary_metrics(result.get("metrics")),
            "scanner_revision": result.get("scanner_revision"),
            "execution_revision": result.get("execution_revision"),
        },
        result.get("claim_boundary"),
    )


def _juliet_lanes(root: Path, manifest: dict[str, str]) -> tuple[dict[str, object], dict[str, object]]:
    first_paths = (JULIET_PREREGISTRATION, JULIET_FIRST_RESULT)
    replay_paths = (JULIET_FIRST_RESULT, JULIET_REPLAY)
    first_errors: list[str] = []
    replay_errors: list[str] = []
    try:
        preregistration = _json_object(root / JULIET_PREREGISTRATION)
        first = _json_object(root / JULIET_FIRST_RESULT)
        replay = _json_object(root / JULIET_REPLAY)
    except ScorecardError as error:
        preregistration, first, replay = {}, {}, {}
        first_errors.append(str(error))
        replay_errors.append(str(error))
    first_errors.extend(_schema_error(preregistration, "k_guard_public_holdout_preregistration.v1"))
    first_errors.extend(_schema_error(first, "k_guard_juliet_java_holdout_result.v1"))
    replay_errors.extend(_schema_error(replay, "k_guard_juliet_java_remediation_replay.v1"))
    preregistration_path = root / JULIET_PREREGISTRATION
    if (
        preregistration_path.is_file()
        and first.get("preregistration_sha256") != _sha256(preregistration_path)
    ):
        first_errors.append("preregistration_digest_mismatch")
    if preregistration.get("holdout_id") != first.get("holdout_id"):
        first_errors.append("holdout_id_mismatch")
    if preregistration.get("scanner_revision") != first.get("scanner_revision"):
        first_errors.append("scanner_revision_mismatch")
    first_errors.extend(
        _revision_errors(
            root,
            {
                "scanner": first.get("scanner_revision"),
                "execution": first.get("execution_revision"),
            },
        )
    )
    first_integrity = first.get("integrity") if isinstance(first.get("integrity"), dict) else {}
    if not first_integrity or any(value is not True for value in first_integrity.values()):
        first_errors.append("recorded_integrity_not_all_true")
    if first.get("verdict") != "pass" or first.get("passed") is not True:
        first_errors.append("juliet_first_result_contract_invalid")

    replay_errors.extend(_revision_errors(root, {"execution": replay.get("execution_revision")}))
    first_binding = replay.get("first_result") if isinstance(replay.get("first_result"), dict) else {}
    first_result_path = root / JULIET_FIRST_RESULT
    if first_result_path.is_file() and first_binding.get("sha256") != _sha256(first_result_path):
        replay_errors.append("first_result_digest_mismatch")
    if first_binding.get("scanner_revision") != first.get("scanner_revision"):
        replay_errors.append("first_result_scanner_revision_mismatch")
    if first_binding.get("metrics") != first.get("metrics"):
        replay_errors.append("first_result_metrics_binding_mismatch")
    first_source = first.get("source") if isinstance(first.get("source"), dict) else {}
    replay_source = replay.get("source") if isinstance(replay.get("source"), dict) else {}
    if (
        replay.get("archive_sha256") != first_source.get("archive_sha256")
        or replay_source.get("archive_sha256") != first_source.get("archive_sha256")
    ):
        replay_errors.append("source_archive_binding_mismatch")
    boundary = replay.get("claim_boundary") if isinstance(replay.get("claim_boundary"), dict) else {}
    if (
        replay.get("verdict") != "pass"
        or replay.get("passed") is not True
        or replay.get("exact_worker_repeat") is not True
        or boundary.get("first_result_remains_the_independent_public_result") is not True
        or boundary.get("post_tuning_regression_evidence_only") is not True
        or boundary.get("not_an_independent_holdout") is not True
    ):
        replay_errors.append("juliet_replay_boundary_invalid")

    first_lane = _lane(
        "historical_nist_juliet_java_cwe89_first",
        "historical_public_preregistered_first_result",
        first_paths,
        manifest,
        root,
        first_errors,
        {
            "recorded_verdict": first.get("verdict"),
            "recorded_passed": first.get("passed"),
            "metrics": _summary_metrics(first.get("metrics")),
            "scanner_revision": first.get("scanner_revision"),
            "execution_revision": first.get("execution_revision"),
        },
        first.get("claim_boundary"),
    )
    replay_lane = _lane(
        "historical_nist_juliet_java_cwe89_post_tuning_replay",
        "historical_same_corpus_post_tuning_regression",
        replay_paths,
        manifest,
        root,
        replay_errors,
        {
            "recorded_verdict": replay.get("verdict"),
            "recorded_passed": replay.get("passed"),
            "metrics": _summary_metrics(replay.get("metrics")),
            "execution_revision": replay.get("execution_revision"),
            "first_result_metrics": _summary_metrics(first_binding.get("metrics")),
        },
        replay.get("claim_boundary"),
    )
    return first_lane, replay_lane


def _no_global_aggregation_fields(document: dict[str, object]) -> bool:
    return GLOBAL_AGGREGATE_KEYS.isdisjoint(document)


def _process_scaling_evidence(root: Path) -> dict[str, object]:
    errors: list[str] = []
    path = root / PROCESS_SCALING
    try:
        report = _json_object(path)
    except ScorecardError as error:
        report = {}
        errors.append(str(error))
    if report.get("schema") != "k_guard_target_grade_process_scaling.v1":
        errors.append("process_scaling_schema_invalid")
    if report.get("passed") is not True or report.get("raw_free") is not True:
        errors.append("process_scaling_result_invalid")
    acceptance = report.get("acceptance") if isinstance(report.get("acceptance"), dict) else {}
    checks = acceptance.get("checks") if isinstance(acceptance.get("checks"), dict) else {}
    if acceptance.get("all_met") is not True or not checks or any(value is not True for value in checks.values()):
        errors.append("process_scaling_acceptance_invalid")
    source = report.get("source_binding") if isinstance(report.get("source_binding"), dict) else {}
    revision = str(source.get("git_head") or "")
    expected_tree = str(source.get("pre", {}).get("working_package_tree_sha256") or "") if isinstance(source.get("pre"), dict) else ""
    if not _git_revision_exists(root, revision):
        errors.append("process_scaling_revision_unresolvable")
    else:
        try:
            if _package_tree_sha256_at_revision(root, revision) != expected_tree:
                errors.append("process_scaling_revision_tree_mismatch")
        except (OSError, ValueError):
            errors.append("process_scaling_revision_tree_unavailable")
    if package_tree_sha256(root / "src" / "k_guard_mcp") != expected_tree:
        errors.append("process_scaling_working_tree_mismatch")
    corpus = report.get("corpus_binding") if isinstance(report.get("corpus_binding"), dict) else {}
    if corpus.get("total_bytes") != 65536 or corpus.get("file_count") != 1:
        errors.append("process_scaling_corpus_contract_invalid")
    for field in ("candidate_content_set_sha256", "candidate_path_set_sha256"):
        if not FULL_SHA256.fullmatch(str(corpus.get(field) or "")):
            errors.append(f"process_scaling_corpus_{field}_invalid")
    if corpus.get("candidate_set_complete") is not True or corpus.get("raw_free") is not True:
        errors.append("process_scaling_corpus_completeness_invalid")
    source_pre = source.get("pre") if isinstance(source.get("pre"), dict) else {}
    source_post = source.get("post") if isinstance(source.get("post"), dict) else {}
    runner_digest = str(source_pre.get("runner_sha256") or "")
    expected_runner_digest = _git_blob_sha256(root, revision, "scripts/benchmark.py") if revision else None
    runner_values = {
        runner_digest,
        str(source_pre.get("head_runner_sha256") or ""),
        str(source_post.get("runner_sha256") or ""),
        str(source_post.get("head_runner_sha256") or ""),
    }
    if (
        len(runner_values) != 1
        or not FULL_SHA256.fullmatch(runner_digest)
        or expected_runner_digest != runner_digest
        or source.get("runner_matches_head") is not True
        or source.get("runner_unchanged") is not True
    ):
        errors.append("process_scaling_runner_binding_invalid")
    fingerprinted = dict(report)
    recorded_fingerprint = str(fingerprinted.pop("report_fingerprint_sha256", ""))
    computed_fingerprint = hashlib.sha256(
        json.dumps(fingerprinted, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if recorded_fingerprint != computed_fingerprint:
        errors.append("process_scaling_report_fingerprint_invalid")
    boundary = report.get("claim_boundary") if isinstance(report.get("claim_boundary"), dict) else {}
    for field in (
        "single_host",
        "synthetic_inputs",
        "all_benign_low_signal_inputs",
        "not_production_slo",
        "not_field_accuracy",
        "not_finding_dense_scaling",
        "not_hardware_normalized",
        "not_third_party_comparison",
    ):
        if boundary.get(field) is not True:
            errors.append(f"process_scaling_boundary_invalid:{field}")
    levels = report.get("levels") if isinstance(report.get("levels"), dict) else {}
    level_projection: dict[str, object] = {}
    base_jobs_per_second: float | None = None
    all_child_refs: list[str] = []
    all_result_fingerprints: set[str] = set()
    for level in ("1", "2", "4"):
        row = levels.get(level) if isinstance(levels.get(level), dict) else {}
        for field in ("aggregate_jobs_per_second", "speedup_vs_1", "parallel_efficiency_vs_1"):
            if not isinstance(row.get(field), (int, float)) or isinstance(row.get(field), bool):
                errors.append(f"process_scaling_level_{level}_{field}_invalid")
        jobs = row.get("jobs")
        samples = row.get("sample_count")
        elapsed = row.get("batch_elapsed_seconds")
        jobs_per_second = row.get("aggregate_jobs_per_second")
        mib_per_second = row.get("aggregate_mib_per_second")
        if jobs != 4 or samples != 4 or row.get("level") != int(level):
            errors.append(f"process_scaling_level_{level}_sample_contract_invalid")
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool) or elapsed <= 0:
            errors.append(f"process_scaling_level_{level}_elapsed_invalid")
        elif isinstance(jobs_per_second, (int, float)) and not isinstance(jobs_per_second, bool):
            # The report publishes elapsed and rates rounded to six decimals, so
            # recomputation from the published elapsed value needs a 1e-5 envelope.
            if abs(float(jobs_per_second) - round(4.0 / float(elapsed), 6)) > 0.00001:
                errors.append(f"process_scaling_level_{level}_jobs_per_second_arithmetic_invalid")
            expected_mib = round((4.0 * 65536.0 / (1024.0 * 1024.0)) / float(elapsed), 6)
            if not isinstance(mib_per_second, (int, float)) or abs(float(mib_per_second) - expected_mib) > 0.00001:
                errors.append(f"process_scaling_level_{level}_mib_per_second_arithmetic_invalid")
        if level == "1" and isinstance(jobs_per_second, (int, float)):
            base_jobs_per_second = float(jobs_per_second)
        if base_jobs_per_second and isinstance(jobs_per_second, (int, float)):
            expected_speedup = round(float(jobs_per_second) / base_jobs_per_second, 6)
            expected_efficiency = round(expected_speedup / int(level), 6)
            if abs(float(row.get("speedup_vs_1") or 0) - expected_speedup) > 0.000001:
                errors.append(f"process_scaling_level_{level}_speedup_arithmetic_invalid")
            if abs(float(row.get("parallel_efficiency_vs_1") or 0) - expected_efficiency) > 0.000001:
                errors.append(f"process_scaling_level_{level}_efficiency_arithmetic_invalid")
        for field in (
            "all_exact_bytes",
            "all_candidates_complete",
            "fingerprints_stable",
            "unique_child_process_references",
            "raw_free",
        ):
            if row.get(field) is not True:
                errors.append(f"process_scaling_level_{level}_{field}_invalid")
        child_refs = row.get("child_process_references") if isinstance(row.get("child_process_references"), list) else []
        if (
            len(child_refs) != 4
            or row.get("unique_child_process_reference_count") != 4
            or len(set(child_refs)) != 4
            or any(not FULL_SHA256.fullmatch(str(value)) for value in child_refs)
        ):
            errors.append(f"process_scaling_level_{level}_child_references_invalid")
        all_child_refs.extend(str(value) for value in child_refs)
        fingerprints = row.get("result_fingerprints_sha256") if isinstance(row.get("result_fingerprints_sha256"), list) else []
        if len(fingerprints) != 1 or any(not FULL_SHA256.fullmatch(str(value)) for value in fingerprints):
            errors.append(f"process_scaling_level_{level}_result_fingerprints_invalid")
        all_result_fingerprints.update(str(value) for value in fingerprints)
        level_projection[level] = {
            "aggregate_jobs_per_second": row.get("aggregate_jobs_per_second"),
            "speedup_vs_1": row.get("speedup_vs_1"),
            "parallel_efficiency_vs_1": row.get("parallel_efficiency_vs_1"),
            "all_exact_bytes": row.get("all_exact_bytes"),
            "all_candidates_complete": row.get("all_candidates_complete"),
            "fingerprints_stable": row.get("fingerprints_stable"),
        }
    if len(all_child_refs) != 12 or len(set(all_child_refs)) != 12:
        errors.append("process_scaling_child_references_not_globally_unique")
    if len(all_result_fingerprints) != 1:
        errors.append("process_scaling_result_fingerprint_invariance_invalid")
    return {
        "evidence_integrity": _integrity(errors),
        "artifact": {
            "locator": PROCESS_SCALING.as_posix(),
            "sha256": _sha256(path) if path.is_file() else None,
            "size_bytes": path.stat().st_size if path.is_file() else None,
        },
        "source_revision": revision or None,
        "package_tree_sha256": expected_tree or None,
        "corpus_bytes": corpus.get("total_bytes"),
        "levels": level_projection,
        "claim_boundary": boundary,
        "raw_returned": False,
    }


def build_scorecard(root: Path = ROOT) -> dict[str, object]:
    root = root.resolve()
    manifest, manifest_errors = _manifest_index(root)
    lanes = [
        _korean_lane(root, manifest),
        _current_public_lane(root, manifest),
        _owasp_python_lane(root, manifest),
        _benchmarkjava_lane(root, manifest),
        *_juliet_lanes(root, manifest),
    ]
    lane_errors = [
        f"{lane['lane_id']}:{error}"
        for lane in lanes
        for error in lane["evidence_integrity"]["errors"]
    ]
    process_scaling = _process_scaling_evidence(root)
    process_errors = [
        f"target_grade_process_scaling:{error}"
        for error in process_scaling["evidence_integrity"]["errors"]
    ]
    evidence_integrity = _integrity([*manifest_errors, *lane_errors, *process_errors])
    lanes_by_id = {lane["lane_id"]: lane for lane in lanes}
    benchmarkjava = lanes_by_id["historical_owasp_benchmarkjava_cwe89"]
    juliet_first = lanes_by_id["historical_nist_juliet_java_cwe89_first"]
    juliet_replay = lanes_by_id["historical_nist_juliet_java_cwe89_post_tuning_replay"]
    emitted_document: dict[str, object] = {
        "schema": SCHEMA,
        "evidence_integrity": evidence_integrity,
        "lanes": lanes,
        "performance_evidence": process_scaling,
        "raw_returned": False,
    }
    claim_boundary = {
        "lanes_are_reported_separately": True,
        "no_global_tp_fp_fn_or_rate_aggregation": _no_global_aggregation_fields(
            emitted_document
        ),
        "current_and_historical_evidence_are_not_equated": True,
        "benchmarkjava_hold_is_preserved": (
            benchmarkjava["recorded_result"].get("recorded_verdict") == "hold"
            and benchmarkjava["recorded_result"].get("recorded_passed") is False
        ),
        "juliet_first_result_is_separate_from_post_tuning_replay": (
            juliet_first["evidence_role"] == "historical_public_preregistered_first_result"
            and juliet_replay["evidence_role"] == "historical_same_corpus_post_tuning_regression"
            and juliet_replay["claim_boundary"].get("first_result_remains_the_independent_public_result")
            is True
        ),
        "not_an_ai_model_quality_benchmark": True,
        "not_owned_or_partner_field_accuracy": True,
        "does_not_grant_release_authority": True,
        "does_not_prove_award_readiness": True,
    }
    projection = {
        **emitted_document,
        "claim_boundary": claim_boundary,
    }
    projection_sha256 = hashlib.sha256(
        json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        **projection,
        "generated_at": _source_commit_time(root),
        "generated_at_definition": "latest scorecard/current-replay/analyzer source commit timestamp; stable across evidence-only commits",
        "projection_sha256": projection_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify and summarize K-Guard public benchmark evidence without cross-lane aggregation."
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-integrity-pass",
        action="store_true",
        help="Return exit code 1 when any selected evidence is inadmissible.",
    )
    args = parser.parse_args(argv)
    scorecard = build_scorecard(args.root)
    serialized = json.dumps(scorecard, ensure_ascii=False, indent=2) + "\n"
    if args.output is None:
        print(serialized, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(serialized.encode("utf-8"))
    if args.require_integrity_pass and scorecard["evidence_integrity"]["status"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
