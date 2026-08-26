from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from k_guard_mcp.release_policy import (
    AUTOMATIC_RELEASE_RULES,
    RELEASE_BLOCKING_POLICY,
    automatic_release_rules_for_policy,
    release_hold_counts,
)

try:
    from scripts.evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256
    from scripts.holdout_integrity import (
        PROTOCOL_RECOVERY_REPLAY_STATUS,
        normalize_github_repository,
        protocol_recovery_qualification_boundary,
        validate_v4_preregistration,
    )
    from scripts.holdout_protocol import (
        NATIVE_RUNTIME_LOCK_GUARD,
        NATIVE_RUNTIME_PREWARM_GUARD,
        PROTOCOL_SCHEMA,
        RUNTIME_OBJECT_ATTESTATION_GUARD,
        RUNTIME_NOTIFICATION_CLASSIFIER,
        capture_runtime_environment,
        source_metadata_by_repository,
        validate_bound_protocol,
        verify_protocol_execution,
    )
    from scripts.holdout_source_materialization import (
        BLOB_EXACT_CLEAN_METHOD,
        GIT_MATERIALIZATION_SCHEMA,
        build_git_materialization_receipt,
    )
    from scripts.run_public_app_campaign import (
        ROOT,
        ScanTimeoutError,
        _candidate_rows,
        _eligible_release_blocking_findings,
        _finding_counts,
        _git,
        _json,
        _release_blocking_findings,
        _run_scan,
        _supported_file_count,
        _write_report,
    )
except ModuleNotFoundError:
    from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256
    from holdout_integrity import (
        PROTOCOL_RECOVERY_REPLAY_STATUS,
        normalize_github_repository,
        protocol_recovery_qualification_boundary,
        validate_v4_preregistration,
    )
    from holdout_protocol import (
        NATIVE_RUNTIME_LOCK_GUARD,
        NATIVE_RUNTIME_PREWARM_GUARD,
        PROTOCOL_SCHEMA,
        RUNTIME_OBJECT_ATTESTATION_GUARD,
        RUNTIME_NOTIFICATION_CLASSIFIER,
        capture_runtime_environment,
        source_metadata_by_repository,
        validate_bound_protocol,
        verify_protocol_execution,
    )
    from holdout_source_materialization import (
        BLOB_EXACT_CLEAN_METHOD,
        GIT_MATERIALIZATION_SCHEMA,
        build_git_materialization_receipt,
    )
    from run_public_app_campaign import (
        ROOT,
        ScanTimeoutError,
        _candidate_rows,
        _eligible_release_blocking_findings,
        _finding_counts,
        _git,
        _json,
        _release_blocking_findings,
        _run_scan,
        _supported_file_count,
        _write_report,
    )


PREREGISTRATION_SCHEMA = "k_guard_public_field_preregistration.v1"
CAMPAIGN_SCHEMA = "k_guard_public_field_campaign.v1"
QUEUE_SCHEMA = "k_guard_public_field_candidate_queue.v1"
ALLOWED_STRATA = {"top", "mid", "long_tail"}
CANDIDATE_SELECTION_MODES = {"quota_three_per_app", "all_eligible_release_blockers"}
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
TREE_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_current_execution_protocol(protocol: dict[str, Any]) -> None:
    manifest = protocol.get("manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != PROTOCOL_SCHEMA
        or manifest.get("release_blocking_policy") != RELEASE_BLOCKING_POLICY
        or manifest.get("automatic_release_rule_ids")
        != sorted(AUTOMATIC_RELEASE_RULES)
    ):
        raise RuntimeError(
            "new v4 qualification execution requires the current protocol and release policy"
        )


def _compress_report_artifact(report_path: Path) -> tuple[Path, str]:
    compressed = gzip.compress(report_path.read_bytes(), compresslevel=9, mtime=0)
    artifact_path = report_path.with_suffix(report_path.suffix + ".gz")
    artifact_path.write_bytes(compressed)
    report_path.unlink()
    return artifact_path, hashlib.sha256(compressed).hexdigest()


def _validate_preregistration(
    payload: dict[str, Any],
    preregistration_path: Path | None = None,
) -> None:
    if payload.get("schema") != PREREGISTRATION_SCHEMA:
        raise ValueError(f"preregistration schema must be {PREREGISTRATION_SCHEMA}")
    if payload.get("status") not in {
        "locked_before_scanner_execution",
        "locked_before_remediation_replay",
        PROTOCOL_RECOVERY_REPLAY_STATUS,
    }:
        raise ValueError("preregistration must be locked before execution")
    expected_tree = str(payload.get("analyzer_package_tree_sha256") or "")
    if TREE_HASH_RE.fullmatch(expected_tree) is None:
        raise ValueError("invalid analyzer package tree hash")
    apps = payload.get("apps")
    if not isinstance(apps, list) or len(apps) < 12:
        raise ValueError("field corpus must contain at least 12 apps")
    names: set[str] = set()
    strata: Counter[str] = Counter()
    for row in apps:
        if not isinstance(row, dict):
            raise ValueError("invalid app row")
        name = str(row.get("app") or "")
        if not name or name in names:
            raise ValueError(f"invalid or duplicate app name: {name or 'missing'}")
        names.add(name)
        if not row.get("repository") or not row.get("local_dir"):
            raise ValueError(f"missing repository binding: {name}")
        if REVISION_RE.fullmatch(str(row.get("commit") or "")) is None:
            raise ValueError(f"invalid app commit: {name}")
        stratum = str(row.get("stratum") or "")
        if stratum not in ALLOWED_STRATA:
            raise ValueError(f"invalid app stratum: {name}")
        strata[stratum] += 1
    locked = payload.get("locked_thresholds") if isinstance(payload.get("locked_thresholds"), dict) else {}
    minimum_app_count = locked.get("minimum_app_count")
    if (
        not isinstance(minimum_app_count, int)
        or isinstance(minimum_app_count, bool)
        or minimum_app_count < 12
        or len(apps) < minimum_app_count
    ):
        raise ValueError("field corpus does not meet the locked minimum_app_count")
    minimum_stratum = int(locked.get("minimum_stratum_count") or 0)
    if minimum_stratum < 1 or any(strata[value] < minimum_stratum for value in ALLOWED_STRATA):
        raise ValueError("stratified corpus does not meet the locked minimum")
    execution = payload.get("locked_execution") if isinstance(payload.get("locked_execution"), dict) else {}
    selection_mode = str(execution.get("candidate_selection_mode") or "quota_three_per_app")
    if selection_mode not in CANDIDATE_SELECTION_MODES:
        raise ValueError("candidate selection mode is invalid")
    qualification_contract = payload.get("qualification_contract")
    if qualification_contract in {
        "release_blocker_actionability_v2",
        "release_blocker_actionability_v3",
        "release_blocker_actionability_v4",
    }:
        locked_policy = execution.get("release_blocking_policy")
        if (
            locked_policy is not None
            and automatic_release_rules_for_policy(str(locked_policy)) is None
        ):
            raise ValueError("release blocking policy is unknown")
        release_registration = payload.get("status") in {
            "locked_before_scanner_execution",
            PROTOCOL_RECOVERY_REPLAY_STATUS,
        }
        if release_registration and (
            locked_policy is None
            or automatic_release_rules_for_policy(str(locked_policy)) is None
        ):
            raise ValueError("new release qualification requires an explicit release blocking policy")
        required = {
            "minimum_blocker_candidates": 100,
            "minimum_blocker_actionability": 0.9,
            "minimum_blocker_actionability_wilson_95_lower": 0.8,
            "required_exact_repeat_rate": 1.0,
            "required_candidate_sample_coverage": 1.0,
            "required_candidate_label_coverage": 1.0,
        }
        if selection_mode != "all_eligible_release_blockers":
            raise ValueError("release qualification requires a blocker census")
        for key, minimum in required.items():
            value = locked.get(key)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < minimum:
                raise ValueError(f"release qualification threshold is too weak: {key}")
        if qualification_contract in {"release_blocker_actionability_v3", "release_blocker_actionability_v4"}:
            app_level_required = {
                "minimum_apps_with_blocker_candidates": 20,
                "minimum_fully_actionable_app_rate": 0.9,
                "minimum_fully_actionable_app_wilson_95_lower": 0.8,
            }
            for key, minimum in app_level_required.items():
                value = locked.get(key)
                if not isinstance(value, (int, float)) or isinstance(value, bool) or value < minimum:
                    raise ValueError(f"release qualification app-level threshold is too weak: {key}")
            if len(apps) < int(locked["minimum_apps_with_blocker_candidates"]):
                raise ValueError("field corpus cannot satisfy the locked candidate-bearing app minimum")
        if locked.get("maximum_unlocatable_release_blockers") != 0:
            raise ValueError(
                "release qualification requires maximum_unlocatable_release_blockers=0"
            )
        if release_registration:
            diversity_minimums = {
                "minimum_distinct_blocker_rule_ids": 4,
                "minimum_apps_with_blocker_candidates": (
                    20 if qualification_contract == "release_blocker_actionability_v3" else 12
                ),
                "minimum_strata_with_blocker_candidates": 3,
            }
            for key, minimum in diversity_minimums.items():
                value = locked.get(key)
                if not isinstance(value, (int, float)) or isinstance(value, bool) or value < minimum:
                    raise ValueError(f"release qualification diversity threshold is too weak: {key}")
            maximum_rule_share = locked.get("maximum_single_rule_candidate_share")
            if (
                not isinstance(maximum_rule_share, (int, float))
                or isinstance(maximum_rule_share, bool)
                or maximum_rule_share > 0.5
                or maximum_rule_share < 0
            ):
                raise ValueError(
                    "release qualification requires maximum_single_rule_candidate_share<=0.5"
                )
        if qualification_contract == "release_blocker_actionability_v4":
            if payload.get("status") == "locked_before_remediation_replay":
                raise ValueError(
                    "v4 protocol recovery must use the nonqualifying recovery replay status"
                )
            if execution.get("exact_fresh_process_runs_per_app") != 2:
                raise ValueError("v4 holdout requires exactly two fresh-process runs per app")
            if execution.get("retry_count") != 0:
                raise ValueError("v4 holdout retries must be disabled")
            if execution.get("candidate_selection_mode") != "all_eligible_release_blockers":
                raise ValueError("v4 holdout requires a complete blocker census")
            validate_v4_preregistration(payload, preregistration_path)
            assert preregistration_path is not None
            validate_bound_protocol(payload, preregistration_path)
    if payload.get("raw_returned") is not False:
        raise ValueError("raw evidence boundary must be explicit")


def _preflight_v4_sources(
    preregistration: dict[str, Any],
    apps_root: Path,
    source_metadata: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    resolved_apps_root = apps_root.resolve(strict=True)
    preflight: dict[str, dict[str, Any]] = {}
    for app in preregistration.get("apps", []):
        if not isinstance(app, dict):
            raise ValueError("invalid app row")
        name = str(app.get("app") or "")
        workspace = (resolved_apps_root / str(app.get("local_dir") or name)).resolve()
        if not workspace.is_relative_to(resolved_apps_root):
            raise RuntimeError(f"source workspace escapes the preregistered apps root for {name}")
        if not workspace.is_dir():
            raise FileNotFoundError(workspace)
        actual_commit = _git("rev-parse", "HEAD", cwd=workspace)
        if actual_commit != app.get("commit"):
            raise RuntimeError(f"commit mismatch for {name}: {actual_commit}")
        expected_repository_id = normalize_github_repository(
            str(app.get("repository") or "")
        )
        if expected_repository_id is None:
            raise RuntimeError(f"source repository is invalid for {name}")
        origin_repository_id = normalize_github_repository(
            _git("remote", "get-url", "origin", cwd=workspace)
        )
        if origin_repository_id != expected_repository_id:
            raise RuntimeError(f"source origin does not match preregistration for {name}")
        metadata = source_metadata.get(expected_repository_id)
        if metadata is None:
            raise RuntimeError(f"source metadata is missing for {name}")
        actual_commit_tree = _git("rev-parse", "HEAD^{tree}", cwd=workspace)
        if actual_commit_tree != metadata.get("commit_tree") or actual_commit_tree != app.get(
            "commit_tree"
        ):
            raise RuntimeError(f"source commit tree does not match preregistration for {name}")
        source_receipt = build_git_materialization_receipt(
            workspace,
            expected_repository_id=expected_repository_id,
            expected_commit=actual_commit,
            expected_tree=actual_commit_tree,
        )
        if (
            source_receipt.get("schema") != GIT_MATERIALIZATION_SCHEMA
            or source_receipt.get("source_worktree_clean") is not True
            or source_receipt.get("source_worktree_clean_method")
            != BLOB_EXACT_CLEAN_METHOD
            or source_receipt.get("physical_bytes_match_git_blobs") is not True
            or source_receipt.get("index_tree_match") is not True
        ):
            raise RuntimeError(f"blob-exact source receipt is missing for {name}")
        preflight[name] = {
            "workspace": workspace,
            "actual_commit": actual_commit,
            "expected_repository_id": expected_repository_id,
            "origin_repository_id": origin_repository_id,
            "actual_commit_tree": actual_commit_tree,
            "source_receipt": source_receipt,
        }
    return preflight


def run_campaign(
    preregistration_path: Path,
    apps_root: Path,
    output_dir: Path,
    *,
    runs: int = 2,
    candidates_per_app: int | None = 3,
    scanner_python: Path | None = None,
) -> dict[str, Any]:
    if runs < 2:
        raise ValueError("at least two fresh-process runs are required")
    preregistration = _json(preregistration_path)
    _validate_preregistration(preregistration, preregistration_path)
    locked_execution = (
        preregistration.get("locked_execution")
        if isinstance(preregistration.get("locked_execution"), dict)
        else {}
    )
    if (
        preregistration.get("qualification_contract")
        in {
            "release_blocker_actionability_v2",
            "release_blocker_actionability_v3",
            "release_blocker_actionability_v4",
        }
        and locked_execution.get("release_blocking_policy")
        != RELEASE_BLOCKING_POLICY
    ):
        raise RuntimeError("campaign execution requires the current release blocking policy")
    selection_mode = str(locked_execution.get("candidate_selection_mode") or "quota_three_per_app")
    is_v4 = preregistration.get("qualification_contract") == "release_blocker_actionability_v4"
    qualification_boundary = protocol_recovery_qualification_boundary(
        preregistration
    )
    if is_v4 and scanner_python is None:
        raise ValueError("v4 holdout requires the preregistered isolated scanner Python")
    if is_v4 and runs != int(locked_execution["exact_fresh_process_runs_per_app"]):
        raise ValueError("execution runs do not match the preregistered exact run count")
    if selection_mode == "all_eligible_release_blockers":
        if candidates_per_app is not None:
            raise ValueError("all-candidate preregistration requires the census execution mode")
    elif candidates_per_app != 3:
        raise ValueError("quota preregistration requires exactly three candidates per app")
    timeout_value = locked_execution.get("per_scan_timeout_seconds")
    if not isinstance(timeout_value, (int, float)) or isinstance(timeout_value, bool) or timeout_value <= 0:
        raise ValueError("new field campaigns require a positive preregistered per_scan_timeout_seconds")
    timeout_seconds = float(timeout_value)
    if _git("status", "--porcelain"):
        raise RuntimeError("tracked scanner worktree must be clean before public field execution")
    if is_v4 and output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError("v4 holdout output directory must be empty before execution")
    if is_v4 and output_dir.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("v4 holdout live output must remain outside the monitored protocol repository")

    protocol: dict[str, Any] | None = None
    protocol_execution: dict[str, Any] | None = None
    source_metadata: dict[str, dict[str, Any]] = {}
    if is_v4:
        protocol = validate_bound_protocol(preregistration, preregistration_path)
        _require_current_execution_protocol(protocol)
        integrity_contract = validate_v4_preregistration(
            preregistration,
            preregistration_path,
        )
        holdout_integrity = preregistration["holdout_integrity"]
        exclusion_path = (
            preregistration_path.resolve().parent
            / Path(str(holdout_integrity["exclusion_snapshot_path"]))
        ).resolve()
        extra_committed_paths = [
            exclusion_path,
            integrity_contract["discovery_path"],
            integrity_contract["qualification_path"],
        ]
        replay_manifest_path = integrity_contract.get("replay_manifest_path")
        if isinstance(replay_manifest_path, Path):
            extra_committed_paths.append(replay_manifest_path)
        protocol_execution = verify_protocol_execution(
            ROOT,
            preregistration_path,
            protocol,
            scanner_python=scanner_python.resolve(strict=True),
            extra_committed_paths=tuple(extra_committed_paths),
        )
        source_metadata = source_metadata_by_repository(protocol)

    source_revision = (
        str(protocol_execution["execution_revision"])
        if protocol_execution is not None
        else _git("rev-parse", "HEAD")
    )
    analyzer_tree = package_tree_sha256(ROOT / "src" / "k_guard_mcp")
    if analyzer_tree != preregistration.get("analyzer_package_tree_sha256"):
        raise RuntimeError("analyzer package tree does not match the preregistration")

    source_preflight: dict[str, dict[str, Any]] = {}
    if is_v4:
        source_preflight = _preflight_v4_sources(
            preregistration,
            apps_root,
            source_metadata,
        )

    report_dir = output_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    receipt_dir = output_dir / "runtime-receipts"
    source_receipt_dir = output_dir / "source-receipts"
    if is_v4:
        receipt_dir.mkdir(parents=True, exist_ok=True)
        source_receipt_dir.mkdir(parents=True, exist_ok=True)
        for app in preregistration.get("apps", []):
            name = str(app["app"])
            source_receipt_path = source_receipt_dir / f"{name}.json"
            if source_receipt_path.exists():
                raise RuntimeError(f"source receipt already exists for {name}")
            source_preflight[name]["source_receipt_path"] = source_receipt_path
            source_preflight[name]["source_receipt_hash"] = _write_report(
                source_receipt_path,
                source_preflight[name]["source_receipt"],
            )
    app_rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    require_origin_binding = is_v4
    for app in preregistration.get("apps", []):
        if not isinstance(app, dict):
            raise ValueError("invalid app row")
        name = str(app.get("app") or "")
        origin_repository_id: str | None = None
        origin_repository_match: bool | None = None
        actual_commit_tree: str | None = None
        commit_tree_match: bool | None = None
        source_receipt_path: Path | None = None
        source_receipt_hash: str | None = None
        source_receipt: dict[str, Any] | None = None
        if require_origin_binding:
            bound_source = source_preflight[name]
            workspace = bound_source["workspace"]
            actual_commit = bound_source["actual_commit"]
            expected_repository_id = bound_source["expected_repository_id"]
            origin_repository_id = bound_source["origin_repository_id"]
            origin_repository_match = True
            actual_commit_tree = bound_source["actual_commit_tree"]
            commit_tree_match = True
            source_receipt = bound_source["source_receipt"]
            source_receipt_path = bound_source["source_receipt_path"]
            source_receipt_hash = bound_source["source_receipt_hash"]
        else:
            workspace = (apps_root / str(app.get("local_dir") or name)).resolve()
            if not workspace.is_dir():
                raise FileNotFoundError(workspace)
            actual_commit = _git("rev-parse", "HEAD", cwd=workspace)
            if actual_commit != app.get("commit"):
                raise RuntimeError(f"commit mismatch for {name}: {actual_commit}")
            expected_repository_id = normalize_github_repository(
                str(app.get("repository") or "")
            )

        repeated: list[dict[str, Any]] = []
        first_report: dict[str, Any] | None = None
        for run_number in range(1, runs + 1):
            report_path = report_dir / f"{name}-run{run_number}.json"
            receipt_path = receipt_dir / f"{name}-run{run_number}.json"
            try:
                exit_code, duration, report_hash, report = _run_scan(
                    workspace,
                    report_path,
                    timeout_seconds=timeout_seconds,
                    python_executable=scanner_python,
                    isolated=is_v4,
                    runtime_launcher=(ROOT / "scripts" / "holdout_scan_launcher.py") if is_v4 else None,
                    runtime_probe=(ROOT / "scripts" / "holdout_runtime_probe.py") if is_v4 else None,
                    source_probe=(
                        ROOT / "scripts" / "holdout_source_materialization.py"
                    )
                    if is_v4
                    else None,
                    expected_source_tree_sha256=(
                        str(source_receipt["source_tree_sha256"])
                        if source_receipt is not None
                        else None
                    ),
                    expected_source_file_count=(
                        int(source_receipt["file_count"])
                        if source_receipt is not None
                        else None
                    ),
                    expected_runtime=protocol["runtime_path"] if protocol is not None else None,
                    execution_receipt=receipt_path if is_v4 else None,
                )
            except ScanTimeoutError:
                failure = {
                    "schema": "k_guard_public_field_campaign_failure.v1",
                    "campaign_id": preregistration.get("campaign_id"),
                    "source_revision": source_revision,
                    "analyzer_package_tree_sha256": analyzer_tree,
                    "verdict": "hold",
                    "blocker": "per_scan_timeout_exceeded",
                    "app": name,
                    "run": run_number,
                    "timeout_seconds": timeout_seconds,
                    "completed_app_count": len(app_rows),
                    "claim_boundary": preregistration.get("claim_boundary", {}),
                    "qualification_boundary": qualification_boundary,
                    "raw_returned": False,
                }
                _write_report(output_dir / "campaign-failure.json", failure)
                raise
            repeated.append(
                {
                    "run": run_number,
                    "exit_code": exit_code,
                    "duration_seconds": duration,
                    "report_sha256": report_hash,
                }
            )
            if is_v4:
                receipt_payload = _json(receipt_path)
                repeated[-1].update(
                    {
                        "runtime_receipt_path": receipt_path.relative_to(output_dir).as_posix(),
                        "runtime_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
                        "runtime_mutation_guard": "windows_read_directory_changes_overlapped_v2",
                        "runtime_notification_classifier": RUNTIME_NOTIFICATION_CLASSIFIER,
                        "native_runtime_lock_guard": NATIVE_RUNTIME_LOCK_GUARD,
                        "native_runtime_prewarm_guard": (
                            NATIVE_RUNTIME_PREWARM_GUARD
                        ),
                        "runtime_object_attestation_guard": (
                            RUNTIME_OBJECT_ATTESTATION_GUARD
                        ),
                        "source_tree_sha256": receipt_payload.get(
                            "pre_source_tree_sha256"
                        ),
                        "source_mutation_observed": receipt_payload.get(
                            "source_mutation_observed"
                        ),
                        "raw_report_sha256": receipt_payload.get("output_sha256"),
                    }
                )
                artifact_path, artifact_hash = _compress_report_artifact(report_path)
                repeated[-1].update(
                    {
                        "report_artifact_path": artifact_path.relative_to(output_dir).as_posix(),
                        "report_artifact_sha256": artifact_hash,
                        "report_artifact_encoding": "canonical-json+gzip-mtime-zero",
                    }
                )
            first_report = first_report or report
        hashes = {row["report_sha256"] for row in repeated}
        if len(hashes) != 1 or any(row["exit_code"] != 0 for row in repeated):
            raise RuntimeError(f"non-reproducible or failed scan for {name}")

        assert first_report is not None
        report_hash = repeated[0]["report_sha256"]
        selected = _candidate_rows(name, report_hash, first_report, candidates_per_app)
        available = len(_release_blocking_findings(first_report))
        eligible = len(_eligible_release_blocking_findings(first_report))
        threshold_findings = [
            finding
            for finding in first_report.get("findings", [])
            if isinstance(finding, dict) and finding.get("severity") in {"critical", "high"}
        ]
        lane_counts = release_hold_counts(threshold_findings, "high")
        lane_counts["supporting_review_high_critical_count"] = (
            len(threshold_findings) - lane_counts["blocking_count"]
        )
        candidates.extend(selected)
        app_rows.append(
            {
                "app": name,
                "stratum": app.get("stratum"),
                "language": app.get("language"),
                "stars_at_registration": app.get("stars_at_registration"),
                "repository": app.get("repository"),
                "repository_id": expected_repository_id,
                "origin_repository_id": origin_repository_id,
                "origin_repository_match": origin_repository_match,
                "github_node_id": app.get("github_node_id"),
                "default_branch": app.get("default_branch"),
                "is_fork": app.get("is_fork"),
                "fork_parent_repository_id": app.get("fork_parent_repository_id"),
                "archived": app.get("archived"),
                "commit": actual_commit,
                "commit_tree": actual_commit_tree,
                "commit_tree_match": commit_tree_match,
                "license_spdx": app.get("license_spdx"),
                "source_worktree_clean": True,
                "source_materialization_receipt_path": (
                    source_receipt_path.relative_to(output_dir).as_posix()
                    if source_receipt_path is not None
                    else None
                ),
                "source_materialization_receipt_sha256": source_receipt_hash,
                "source_materialization_schema": (
                    source_receipt.get("schema") if source_receipt is not None else None
                ),
                "source_tree_sha256": (
                    source_receipt.get("source_tree_sha256")
                    if source_receipt is not None
                    else None
                ),
                "source_total_bytes": (
                    source_receipt.get("total_bytes") if source_receipt is not None else None
                ),
                "tracked_files": (
                    source_receipt.get("file_count")
                    if source_receipt is not None
                    else len(_git("ls-files", cwd=workspace).splitlines())
                ),
                "supported_files": _supported_file_count(first_report),
                "finding_counts": _finding_counts(first_report),
                "available_release_blocking_findings": available,
                "eligible_release_blocking_findings": eligible,
                "unlocatable_release_blocking_findings": available - eligible,
                "sampled_release_blocking_candidates": len(selected),
                "release_lane_counts": lane_counts,
                "runs": repeated,
                "exact_repeat": True,
            }
        )

    post_execution_runtime_verified: bool | None = None
    if is_v4:
        assert protocol is not None and scanner_python is not None
        post_execution_runtime = capture_runtime_environment(
            scanner_python,
            ROOT / "scripts" / "holdout_runtime_probe.py",
            protocol["runtime_environment"].get("scanner_scaffold"),
        )
        post_execution_runtime_verified = post_execution_runtime == protocol["runtime_environment"]
        if not post_execution_runtime_verified:
            raise RuntimeError("isolated scanner runtime changed during the holdout execution")

    claim_boundary = preregistration.get("claim_boundary", {})
    snapshot_path = output_dir / "preregistration.snapshot.json"
    if is_v4:
        snapshot_bytes = preregistration_path.read_bytes()
        snapshot_path.write_bytes(snapshot_bytes)
        preregistration_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
    else:
        preregistration_sha256 = _write_report(snapshot_path, preregistration)
    campaign = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": preregistration.get("campaign_id"),
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": analyzer_tree,
        "analyzer_package_tree_hash_schema": TREE_HASH_SCHEMA,
        "preregistration_path": snapshot_path.name,
        "preregistration_sha256": preregistration_sha256,
        "tracked_worktree_clean": True,
        "holdout_protocol": protocol_execution,
        "execution_boundary": {
            "application_code_executed": False,
            "static_local_source_scan_only": True,
            "fresh_process_per_run": True,
            "minimum_runs_per_app": runs,
            "exact_runs_per_app": runs if is_v4 else None,
            "retry_count": 0 if is_v4 else None,
            "per_scan_timeout_seconds": timeout_seconds,
            "report_path_normalization": "absolute workspace prefix replaced with <workspace>",
            "scanner_python_isolated": is_v4,
            "python_no_site_startup": is_v4,
            "scanner_python_sha256": (
                protocol_execution.get("scanner_python_sha256")
                if protocol_execution is not None
                else None
            ),
            "post_execution_runtime_verified": post_execution_runtime_verified,
            "runtime_mutation_guard": (
                protocol_execution.get("runtime_mutation_guard")
                if protocol_execution is not None
                else None
            ),
            "runtime_notification_classifier": (
                protocol_execution.get("runtime_notification_classifier")
                if protocol_execution is not None
                else None
            ),
            "native_runtime_lock_guard": (
                protocol_execution.get("native_runtime_lock_guard")
                if protocol_execution is not None
                else None
            ),
            "native_runtime_prewarm_guard": (
                protocol_execution.get("native_runtime_prewarm_guard")
                if protocol_execution is not None
                else None
            ),
            "runtime_object_attestation_guard": (
                protocol_execution.get("runtime_object_attestation_guard")
                if protocol_execution is not None
                else None
            ),
            "runtime_actual_mutation_event_count_required": 0 if is_v4 else None,
            "runtime_launcher_sha256": (
                protocol_execution.get("runtime_launcher_sha256")
                if protocol_execution is not None
                else None
            ),
            "runtime_probe_sha256": (
                protocol_execution.get("runtime_probe_sha256")
                if protocol_execution is not None
                else None
            ),
            "source_materialization_probe_sha256": (
                protocol_execution.get("source_materialization_probe_sha256")
                if protocol_execution is not None
                else None
            ),
            "git_blob_exact_materialization_required": is_v4,
            "source_pre_post_tree_match_required": is_v4,
            "source_mutation_event_count_required": 0 if is_v4 else None,
            "independent_git_verifier_sha256": (
                protocol_execution.get("independent_git_verifier_sha256")
                if protocol_execution is not None
                else None
            ),
            "independent_git_verification_post_campaign_required": is_v4,
        },
        "release_decision_contract": {
            "blocking_policy": RELEASE_BLOCKING_POLICY,
            "actionability_population": "release_blocking",
            "manual_review_hold_is_fail_closed": True,
            "policy_integrity_hold_is_fail_closed": True,
            "release_qualification_allowed": not bool(
                qualification_boundary
            ),
        },
        "apps": app_rows,
        "claim_boundary": claim_boundary,
        "qualification_boundary": qualification_boundary,
        "raw_returned": False,
    }
    queue = {
        "schema": QUEUE_SCHEMA,
        "campaign_id": preregistration.get("campaign_id"),
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": analyzer_tree,
        "holdout_protocol_manifest_sha256": (
            protocol_execution.get("protocol_manifest_sha256")
            if protocol_execution is not None
            else None
        ),
        "candidate_population": {
            "blocking_policy": RELEASE_BLOCKING_POLICY,
            "lane": "release_blocking",
            "meaning": "high-confidence automatic release blockers only",
            "manual_review_holds_excluded_from_actionability_denominator": True,
            "policy_integrity_holds_excluded_from_actionability_denominator": True,
            "excluded_holds_still_fail_closed": True,
            "release_qualification_allowed": not bool(
                qualification_boundary
            ),
        },
        "selection": (
            "Every policy-defined high/critical release blocker with an exact source location."
            if selection_mode == "all_eligible_release_blockers"
            else "Up to three deterministic policy-defined release-blocking candidates per app; "
            "prefer distinct rule IDs, then distinct rule/file pairs, then severity/path/line/rule order."
        ),
        "sampling": {
            "mode": selection_mode,
            "target_per_app": candidates_per_app,
            "sample_all_available_when_below_target": selection_mode == "quota_three_per_app",
            "available_by_app": {row["app"]: row["eligible_release_blocking_findings"] for row in app_rows},
            "all_release_blockers_by_app": {
                row["app"]: row["available_release_blocking_findings"] for row in app_rows
            },
            "unlocatable_by_app": {
                row["app"]: row["unlocatable_release_blocking_findings"] for row in app_rows
            },
            "sampled_by_app": {row["app"]: row["sampled_release_blocking_candidates"] for row in app_rows},
        },
        "candidates": candidates,
        "claim_boundary": claim_boundary,
        "qualification_boundary": qualification_boundary,
        "raw_returned": False,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_report(output_dir / "campaign.json", campaign)
    _write_report(output_dir / "candidate-queue.json", queue)
    print(
        json.dumps(
            {
                "campaign_id": campaign["campaign_id"],
                "apps": len(app_rows),
                "candidates": len(candidates),
                "exact_repeat_apps": sum(row["exact_repeat"] is True for row in app_rows),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return campaign


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a preregistered public field-like source campaign.")
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--apps-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--scanner-python", type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--candidates-per-app", type=int, default=3)
    selection.add_argument("--all-candidates", action="store_true")
    args = parser.parse_args()
    run_campaign(
        args.preregistration.resolve(),
        args.apps_root.resolve(),
        args.output_dir.resolve(),
        runs=args.runs,
        candidates_per_app=None if args.all_candidates else args.candidates_per_app,
        scanner_python=args.scanner_python,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
