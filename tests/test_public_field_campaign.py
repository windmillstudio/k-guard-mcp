from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = _load("run_public_field_campaign", ROOT / "scripts" / "run_public_field_campaign.py")
scorer = _load("public_field_effectiveness", ROOT / "scripts" / "public_field_effectiveness.py")


def test_new_execution_rejects_legacy_protocol_even_when_historical_reader_accepts_it() -> None:
    runner._require_current_execution_protocol(
        {
            "manifest": {
                "schema": runner.PROTOCOL_SCHEMA,
                "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
                "automatic_release_rule_ids": sorted(runner.AUTOMATIC_RELEASE_RULES),
            }
        }
    )

    with pytest.raises(RuntimeError, match="current protocol and release policy"):
        runner._require_current_execution_protocol(
            {"manifest": {"schema": "k_guard_holdout_protocol.v1"}}
        )
    with pytest.raises(RuntimeError, match="current protocol and release policy"):
        runner._require_current_execution_protocol(
            {"manifest": {"schema": "k_guard_holdout_protocol.v2"}}
        )
    with pytest.raises(RuntimeError, match="current protocol and release policy"):
        runner._require_current_execution_protocol(
            {"manifest": {"schema": "k_guard_holdout_protocol.v4"}}
        )


def test_v4_campaign_preflights_every_source_before_outputs_or_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer_tree = "a" * 64
    apps = []
    source_metadata = {}
    commits: dict[str, str] = {}
    trees: dict[str, str] = {}
    repositories: dict[str, str] = {}
    apps_root = tmp_path / "apps"
    apps_root.mkdir()
    for index in range(12):
        name = f"app-{index}"
        repository_id = f"example/{name}"
        commit = f"{index + 1:040x}"
        tree = f"{index + 101:040x}"
        (apps_root / name).mkdir()
        apps.append(
            {
                "app": name,
                "local_dir": name,
                "repository": f"https://github.com/{repository_id}.git",
                "repository_id": repository_id,
                "commit": commit,
                "commit_tree": tree,
            }
        )
        source_metadata[repository_id] = {"commit_tree": tree}
        commits[name] = commit
        trees[name] = tree
        repositories[name] = repository_id
    preregistration = {
        "schema": runner.PREREGISTRATION_SCHEMA,
        "campaign_id": "preflight-fixture",
        "qualification_contract": "release_blocker_actionability_v4",
        "analyzer_package_tree_sha256": analyzer_tree,
        "locked_execution": {
            "candidate_selection_mode": "all_eligible_release_blockers",
            "exact_fresh_process_runs_per_app": 2,
            "per_scan_timeout_seconds": 30,
            "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
        },
        "holdout_integrity": {"exclusion_snapshot_path": "exclusions.json"},
        "apps": apps,
    }
    preregistration_path = tmp_path / "preregistration.json"
    preregistration_path.write_text("{}\n", encoding="utf-8")
    scanner_python = tmp_path / "scanner-python.exe"
    scanner_python.write_bytes(b"fixture")
    output_dir = tmp_path / "live-output"
    scan_calls = 0
    receipt_calls = 0

    def fake_git(*args: str, cwd: Path | None = None) -> str:
        if args == ("status", "--porcelain"):
            return ""
        assert cwd is not None
        name = cwd.name
        if args == ("rev-parse", "HEAD"):
            return commits[name]
        if args == ("rev-parse", "HEAD^{tree}"):
            return trees[name]
        if args == ("remote", "get-url", "origin"):
            return f"https://github.com/{repositories[name]}.git"
        raise AssertionError(args)

    def fake_receipt(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal receipt_calls
        receipt_calls += 1
        if receipt_calls == len(apps):
            raise ValueError("late source invalid")
        return {
            "schema": runner.GIT_MATERIALIZATION_SCHEMA,
            "source_worktree_clean": True,
            "source_worktree_clean_method": runner.BLOB_EXACT_CLEAN_METHOD,
            "physical_bytes_match_git_blobs": True,
            "index_tree_match": True,
        }

    def fake_scan(*_args: Any, **_kwargs: Any) -> None:
        nonlocal scan_calls
        scan_calls += 1

    monkeypatch.setattr(runner, "_json", lambda _path: preregistration)
    monkeypatch.setattr(runner, "_validate_preregistration", lambda *_args: None)
    monkeypatch.setattr(runner, "_git", fake_git)
    monkeypatch.setattr(
        runner,
        "validate_bound_protocol",
        lambda *_args: {
            "manifest": {
                "schema": runner.PROTOCOL_SCHEMA,
                "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
                "automatic_release_rule_ids": sorted(runner.AUTOMATIC_RELEASE_RULES),
            },
            "runtime_path": tmp_path / "runtime.json",
        },
    )
    monkeypatch.setattr(
        runner,
        "validate_v4_preregistration",
        lambda *_args: {
            "discovery_path": tmp_path / "discovery.json",
            "qualification_path": tmp_path / "qualification.json",
        },
    )
    monkeypatch.setattr(
        runner,
        "verify_protocol_execution",
        lambda *_args, **_kwargs: {"execution_revision": "b" * 40},
    )
    monkeypatch.setattr(runner, "source_metadata_by_repository", lambda _protocol: source_metadata)
    monkeypatch.setattr(runner, "package_tree_sha256", lambda _path: analyzer_tree)
    monkeypatch.setattr(runner, "build_git_materialization_receipt", fake_receipt)
    monkeypatch.setattr(runner, "_run_scan", fake_scan)

    with pytest.raises(ValueError, match="late source invalid"):
        runner.run_campaign(
            preregistration_path,
            apps_root,
            output_dir,
            runs=2,
            candidates_per_app=None,
            scanner_python=scanner_python,
        )

    assert receipt_calls == len(apps)
    assert scan_calls == 0
    assert not output_dir.exists()


def test_protocol_recovery_replay_runs_real_campaign_output_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer_tree = "a" * 64
    apps_root = tmp_path / "apps"
    apps_root.mkdir()
    apps = []
    for index in range(12):
        name = f"app-{index}"
        workspace = apps_root / name
        workspace.mkdir()
        apps.append(
            {
                "app": name,
                "local_dir": name,
                "stratum": ("top", "mid", "long_tail")[index % 3],
                "repository": f"https://github.com/example/{name}.git",
                "repository_id": f"example/{name}",
                "commit": f"{index + 1:040x}",
                "commit_tree": f"{index + 101:040x}",
            }
        )
    prior_manifest = tmp_path / "prior-execution-manifest.json"
    prior_manifest.write_text("{}\n", encoding="utf-8")
    prior_hash = hashlib.sha256(prior_manifest.read_bytes()).hexdigest()
    preregistration = {
        "schema": runner.PREREGISTRATION_SCHEMA,
        "campaign_id": "protocol-recovery-fixture",
        "status": runner.PROTOCOL_RECOVERY_REPLAY_STATUS,
        "qualification_contract": "release_blocker_actionability_v4",
        "analyzer_package_tree_sha256": analyzer_tree,
        "locked_execution": {
            "candidate_selection_mode": "all_eligible_release_blockers",
            "exact_fresh_process_runs_per_app": 2,
            "per_scan_timeout_seconds": 30,
            "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
        },
        "holdout_integrity": {
            "exclusion_snapshot_path": "exclusions.json",
        },
        "replay_provenance": {
            "superseded_campaign_id": "prior-fixture",
            "prior_execution_manifest_sha256": prior_hash,
        },
        "apps": apps,
        "claim_boundary": {"fixture": True},
    }
    preregistration_path = tmp_path / "preregistration.json"
    _write(preregistration_path, preregistration)
    exclusion_path = tmp_path / "exclusions.json"
    discovery_path = tmp_path / "discovery.json"
    qualification_path = tmp_path / "qualification.json"
    for path in (exclusion_path, discovery_path, qualification_path):
        path.write_text("{}\n", encoding="utf-8")
    scanner_python = tmp_path / "scanner-python.exe"
    scanner_python.write_bytes(b"fixture")
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text("{}\n", encoding="utf-8")
    runtime_environment = {"fixture": "runtime"}
    protocol_payload = {
        "manifest": {
            "schema": runner.PROTOCOL_SCHEMA,
            "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
            "automatic_release_rule_ids": sorted(runner.AUTOMATIC_RELEASE_RULES),
        },
        "runtime_path": runtime_path,
        "runtime_environment": runtime_environment,
    }
    protocol_execution = {
        "execution_revision": "b" * 40,
        "protocol_manifest_sha256": "c" * 64,
        "scanner_python_sha256": "d" * 64,
        "runtime_mutation_guard": "fixture-runtime-guard",
        "runtime_notification_classifier": "fixture-classifier",
        "native_runtime_lock_guard": "fixture-lock",
        "native_runtime_prewarm_guard": "fixture-prewarm",
        "runtime_object_attestation_guard": "fixture-attestation",
        "runtime_launcher_sha256": "e" * 64,
        "runtime_probe_sha256": "f" * 64,
        "source_materialization_probe_sha256": "1" * 64,
        "independent_git_verifier_sha256": "2" * 64,
        "tracked_artifacts_committed_at_execution_head": [
            {
                "path": prior_manifest.name,
                "sha256": prior_hash,
            }
        ],
    }
    verified_extra_paths: tuple[Path, ...] = ()

    def fake_json(path: Path) -> dict[str, Any]:
        if path.resolve() == preregistration_path.resolve():
            return preregistration
        return json.loads(path.read_text(encoding="utf-8"))

    def fake_preflight(
        _preregistration: dict[str, Any],
        root: Path,
        _source_metadata: dict[str, dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        return {
            app["app"]: {
                "workspace": (root / app["local_dir"]).resolve(),
                "actual_commit": app["commit"],
                "expected_repository_id": app["repository_id"],
                "origin_repository_id": app["repository_id"],
                "actual_commit_tree": app["commit_tree"],
                "source_receipt": {
                    "schema": runner.GIT_MATERIALIZATION_SCHEMA,
                    "source_tree_sha256": f"{index + 10:064x}",
                    "file_count": 1,
                    "total_bytes": 10,
                },
            }
            for index, app in enumerate(apps)
        }

    def fake_verify(
        *_args: Any,
        extra_committed_paths: tuple[Path, ...],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        nonlocal verified_extra_paths
        verified_extra_paths = extra_committed_paths
        return protocol_execution

    def fake_scan(
        workspace: Path,
        report_path: Path,
        **kwargs: Any,
    ) -> tuple[int, float, str, dict[str, Any]]:
        report = {
            "findings": [
                {
                    "rule_id": "CONFIG_CSP_UNSAFE_EVAL",
                    "severity": "high",
                    "confidence": "high",
                    "file": f"{workspace}/.github/workflows/ci.yml",
                    "line_start": 1,
                    "artifact_scope": "configuration",
                    "evidence": (
                        "detector_subtype=mutable_action "
                        "line_hash=0123456789abcdef raw_returned=false"
                    ),
                    "source": "config",
                }
            ],
            "metadata": {
                "review_coverage": {
                    "inventory": {"supported_file_count": 1}
                }
            },
        }
        report_hash = runner._write_report(report_path, report)
        receipt_path = kwargs["execution_receipt"]
        _write(
            receipt_path,
            {
                "pre_source_tree_sha256": kwargs[
                    "expected_source_tree_sha256"
                ],
                "source_mutation_observed": False,
                "output_sha256": report_hash,
            },
        )
        return 0, 0.01, report_hash, report

    monkeypatch.setattr(runner, "_json", fake_json)
    monkeypatch.setattr(runner, "_validate_preregistration", lambda *_args: None)
    monkeypatch.setattr(
        runner,
        "_git",
        lambda *args, **_kwargs: "" if args == ("status", "--porcelain") else pytest.fail(args),
    )
    monkeypatch.setattr(
        runner,
        "validate_bound_protocol",
        lambda *_args: protocol_payload,
    )
    monkeypatch.setattr(
        runner,
        "validate_v4_preregistration",
        lambda *_args: {
            "discovery_path": discovery_path,
            "qualification_path": qualification_path,
            "replay_manifest_path": prior_manifest,
        },
    )
    monkeypatch.setattr(runner, "verify_protocol_execution", fake_verify)
    monkeypatch.setattr(
        runner,
        "source_metadata_by_repository",
        lambda _protocol: {},
    )
    monkeypatch.setattr(
        runner,
        "package_tree_sha256",
        lambda _path: analyzer_tree,
    )
    monkeypatch.setattr(runner, "_preflight_v4_sources", fake_preflight)
    monkeypatch.setattr(runner, "_run_scan", fake_scan)
    monkeypatch.setattr(
        runner,
        "capture_runtime_environment",
        lambda *_args: runtime_environment,
    )

    output_dir = tmp_path / "campaign-output"
    campaign = runner.run_campaign(
        preregistration_path,
        apps_root,
        output_dir,
        runs=2,
        candidates_per_app=None,
        scanner_python=scanner_python,
    )
    queue = json.loads(
        (output_dir / "candidate-queue.json").read_text(encoding="utf-8")
    )
    expected_boundary = runner.protocol_recovery_qualification_boundary(
        preregistration
    )

    assert campaign["qualification_boundary"] == expected_boundary
    assert queue["qualification_boundary"] == expected_boundary
    snapshot_path = output_dir / campaign["preregistration_path"]
    assert snapshot_path == output_dir / "preregistration.snapshot.json"
    assert snapshot_path.read_bytes() == preregistration_path.read_bytes()
    assert campaign["preregistration_sha256"] == hashlib.sha256(
        snapshot_path.read_bytes()
    ).hexdigest()
    assert (
        campaign["release_decision_contract"][
            "release_qualification_allowed"
        ]
        is False
    )
    assert (
        queue["candidate_population"]["release_qualification_allowed"]
        is False
    )
    assert prior_manifest in verified_extra_paths
    assert any(
        row["sha256"] == prior_hash
        for row in campaign["holdout_protocol"][
            "tracked_artifacts_committed_at_execution_head"
        ]
    )
    assert len(campaign["apps"]) == len(apps)
    assert len(queue["candidates"]) == len(apps)


def test_v4_source_preflight_rejects_workspace_escape_before_git_or_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apps_root = tmp_path / "apps"
    apps_root.mkdir()
    (tmp_path / "outside").mkdir()
    preregistration = {
        "apps": [
            {
                "app": "escape",
                "local_dir": "../outside",
                "repository": "https://github.com/example/escape.git",
                "commit": "a" * 40,
                "commit_tree": "b" * 40,
            }
        ]
    }

    monkeypatch.setattr(
        runner,
        "_git",
        lambda *_args, **_kwargs: pytest.fail("git must not run for an escaped workspace"),
    )
    monkeypatch.setattr(
        runner,
        "build_git_materialization_receipt",
        lambda *_args, **_kwargs: pytest.fail(
            "receipt capture must not run for an escaped workspace"
        ),
    )

    with pytest.raises(RuntimeError, match="escapes the preregistered apps root"):
        runner._preflight_v4_sources(preregistration, apps_root, {})


def test_v4_source_preflight_requires_explicit_clean_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    apps_root = tmp_path / "apps"
    workspace = apps_root / "app"
    workspace.mkdir(parents=True)
    repository_id = "example/app"
    commit = "a" * 40
    tree = "b" * 40
    preregistration = {
        "apps": [
            {
                "app": "app",
                "local_dir": "app",
                "repository": f"https://github.com/{repository_id}.git",
                "commit": commit,
                "commit_tree": tree,
            }
        ]
    }

    def fake_git(*args: str, cwd: Path | None = None) -> str:
        assert cwd == workspace.resolve()
        if args == ("rev-parse", "HEAD"):
            return commit
        if args == ("rev-parse", "HEAD^{tree}"):
            return tree
        if args == ("remote", "get-url", "origin"):
            return f"https://github.com/{repository_id}.git"
        raise AssertionError(args)

    monkeypatch.setattr(runner, "_git", fake_git)
    monkeypatch.setattr(
        runner,
        "build_git_materialization_receipt",
        lambda *_args, **_kwargs: {},
    )

    with pytest.raises(RuntimeError, match="blob-exact source receipt is missing"):
        runner._preflight_v4_sources(
            preregistration,
            apps_root,
            {repository_id: {"commit_tree": tree}},
        )


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _fixture(
    tmp_path: Path,
    *,
    false_positives: int = 0,
    benign: int = 0,
) -> tuple[Path, Path]:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    tree_hash = "a" * 64
    campaign_id = "field-16"
    strata = ["top"] * 6 + ["mid"] * 4 + ["long_tail"] * 6
    preregistration = {
        "schema": scorer.PREREGISTRATION_SCHEMA,
        "campaign_id": campaign_id,
        "status": "locked_before_scanner_execution",
        "analyzer_package_tree_sha256": tree_hash,
        "apps": [
            {
                "app": f"app-{index}",
                "local_dir": f"app-{index}",
                "stratum": stratum,
                "repository": f"https://example.invalid/app-{index}.git",
                "commit": f"{index + 1:040x}",
            }
            for index, stratum in enumerate(strata)
        ],
        "locked_thresholds": {
            "minimum_app_count": 16,
            "minimum_stratum_count": 4,
            "minimum_blocker_candidates": 12,
            "required_exact_repeat_rate": 1.0,
            "required_candidate_sample_coverage": 1.0,
            "required_candidate_label_coverage": 1.0,
            "minimum_reviewer_unanimous_rate": 0.75,
            "maximum_inconclusive_rate": 0.1,
            "minimum_blocker_actionability": 0.75,
            "minimum_blocker_actionability_wilson_95_lower": 0.6,
        },
        "claim_boundary": {"candidate_precision_only": True},
        "raw_returned": False,
    }
    preregistration_path = tmp_path / "preregistration.json"
    _write(preregistration_path, preregistration)

    app_rows = []
    candidates = []
    labels = []
    reviewers = [
        {"reviewer_alias": alias, "reviewer_ref": f"sha256:{hashlib.sha256(alias.encode()).hexdigest()}"}
        for alias in ("one", "two", "three")
    ]
    for index, stratum in enumerate(strata):
        app = f"app-{index}"
        report_hash = hashlib.sha256(app.encode()).hexdigest()
        app_rows.append(
            {
                "app": app,
                "stratum": stratum,
                "runs": [
                    {"run": 1, "exit_code": 0, "report_sha256": report_hash},
                    {"run": 2, "exit_code": 0, "report_sha256": report_hash},
                ],
                "exact_repeat": True,
            }
        )
        candidate_id = f"candidate-{index}"
        candidate = {
            "candidate_id": candidate_id,
            "redacted_fingerprint": f"sha256-truncated:{hashlib.sha256(candidate_id.encode()).hexdigest()[:20]}",
            "app": app,
            "severity": "high",
            "confidence": "high",
            "rule_id": "TEST_RULE",
            "detector_subtype": "fixture",
            "source_location": "app.py:1",
            "artifact_scope": "runtime",
            "scan_report_sha256": report_hash,
            "raw_returned": False,
        }
        candidates.append(candidate)
        if index < false_positives:
            label = "false_positive"
        elif index < false_positives + benign:
            label = "benign"
        else:
            label = "true_positive"
        labels.append(
            {
                **candidate,
                "label": label,
                "agreement": "unanimous",
                "reviews": [
                    {"reviewer_ref": row["reviewer_ref"], "label": label, "rationale": "source context checked"}
                    for row in reviewers
                ],
            }
        )

    _write(
        evidence / "campaign.json",
        {
            "schema": scorer.CAMPAIGN_SCHEMA,
            "campaign_id": campaign_id,
            "source_revision": "b" * 40,
            "analyzer_package_tree_sha256": tree_hash,
            "apps": app_rows,
            "raw_returned": False,
        },
    )
    _write(
        evidence / "candidate-queue.json",
        {
            "schema": scorer.QUEUE_SCHEMA,
            "campaign_id": campaign_id,
            "source_revision": "b" * 40,
            "analyzer_package_tree_sha256": tree_hash,
            "sampling": {
                "target_per_app": 3,
                "available_by_app": {row["app"]: 1 for row in app_rows},
                "sampled_by_app": {row["app"]: 1 for row in app_rows},
            },
            "candidates": candidates,
            "raw_returned": False,
        },
    )
    _write(
        evidence / "candidate-labels.json",
        {
            "schema": scorer.LABEL_SCHEMA,
            "campaign_id": campaign_id,
            "source_revision": "b" * 40,
            "analyzer_package_tree_sha256": tree_hash,
            "reviewers": reviewers,
            "candidates": labels,
            "raw_returned": False,
        },
    )
    return evidence, preregistration_path


def test_checked_in_preregistrations_are_valid_and_stratified() -> None:
    for name in (
        "public-vibe-apps-16-preregistration.json",
        "public-vibe-apps-16-remediation-preregistration.json",
        "public-vibe-apps-16-remediation-r2-preregistration.json",
        "public-vibe-apps-16-precision-r4-preregistration.json",
        "public-vibe-apps-16-precision-r5-preregistration.json",
    ):
        payload = json.loads((ROOT / "evidence" / "public" / name).read_text(encoding="utf-8"))
        runner._validate_preregistration(payload)


def test_preregistration_rejects_duplicate_app_names_before_execution(
    tmp_path: Path,
) -> None:
    _evidence, preregistration = _fixture(tmp_path)
    payload = json.loads(preregistration.read_text(encoding="utf-8"))
    payload["apps"][1]["app"] = payload["apps"][0]["app"]

    with pytest.raises(ValueError, match="invalid or duplicate app name"):
        runner._validate_preregistration(payload)


def test_field_effectiveness_passes_complete_unanimous_fixture(tmp_path: Path) -> None:
    evidence, preregistration = _fixture(tmp_path)
    status = scorer.build_status(evidence, preregistration)
    assert status["integrity_passed"] is True
    assert status["qualified"] is True
    assert status["metrics"]["app_count"] == 16
    assert status["metrics"]["blocker_actionability_wilson_95_lower"] > 0.6


def test_field_effectiveness_holds_when_wilson_bound_is_too_low(tmp_path: Path) -> None:
    evidence, preregistration = _fixture(tmp_path, false_positives=4)
    status = scorer.build_status(evidence, preregistration)
    assert status["integrity_passed"] is True
    assert status["metrics"]["adjudicated_precision_tp_fp_only"] == 0.75
    assert status["metrics"]["blocker_actionability"] == 0.75
    assert status["qualified"] is False
    assert "blocker_actionability_wilson_lower_below_locked_minimum" in status["blockers"]


def test_field_effectiveness_counts_benign_blockers_against_release_actionability(
    tmp_path: Path,
) -> None:
    evidence, preregistration = _fixture(tmp_path, benign=4)

    status = scorer.build_status(evidence, preregistration)

    assert status["metrics"]["adjudicated_precision_tp_fp_only"] == 1.0
    assert status["metrics"]["blocker_actionability"] == 0.75
    assert status["metrics"]["non_actionable_blocker_count"] == 4
    assert status["qualified"] is False
    assert "blocker_actionability_wilson_lower_below_locked_minimum" in status["blockers"]


def test_field_effectiveness_app_level_gate_prevents_within_app_pseudoreplication(
    tmp_path: Path,
) -> None:
    evidence, preregistration = _fixture(tmp_path, false_positives=1)
    queue_path = evidence / "candidate-queue.json"
    labels_path = evidence / "candidate-labels.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    candidate_template = queue["candidates"][1]
    label_template = labels["candidates"][1]
    for index in range(84):
        candidate_id = f"candidate-extra-{index}"
        candidate = {
            **candidate_template,
            "candidate_id": candidate_id,
            "redacted_fingerprint": (
                f"sha256-truncated:{hashlib.sha256(candidate_id.encode()).hexdigest()[:20]}"
            ),
            "source_location": f"app.py:{index + 2}",
        }
        queue["candidates"].append(candidate)
        labels["candidates"].append(
            {
                **label_template,
                **candidate,
                "label": "true_positive",
                "agreement": "unanimous",
            }
        )
    queue["sampling"].update(
        {
            "mode": "all_eligible_release_blockers",
            "target_per_app": None,
            "available_by_app": {
                f"app-{index}": 85 if index == 1 else 1 for index in range(16)
            },
            "sampled_by_app": {
                f"app-{index}": 85 if index == 1 else 1 for index in range(16)
            },
        }
    )
    _write(queue_path, queue)
    _write(labels_path, labels)
    prereg = json.loads(preregistration.read_text(encoding="utf-8"))
    prereg["locked_thresholds"].update(
        {
            "minimum_fully_actionable_app_rate": 0.9,
            "minimum_fully_actionable_app_wilson_95_lower": 0.8,
        }
    )
    _write(preregistration, prereg)

    status = scorer.build_status(evidence, preregistration)

    assert status["metrics"]["candidate_count"] == 100
    assert status["metrics"]["blocker_actionability"] == 0.99
    assert status["metrics"]["blocker_actionability_wilson_95_lower"] > 0.9
    assert status["metrics"]["fully_actionable_blocker_app_count"] == 15
    assert status["metrics"]["fully_actionable_blocker_app_rate"] == 0.9375
    assert status["metrics"]["fully_actionable_blocker_app_wilson_95_lower"] == 0.716713
    assert "fully_actionable_app_wilson_lower_below_locked_minimum" in status["blockers"]


def test_field_effectiveness_census_holds_on_unlocatable_release_blocker(tmp_path: Path) -> None:
    evidence, preregistration = _fixture(tmp_path)
    queue_path = evidence / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["sampling"].update(
        {
            "mode": "all_eligible_release_blockers",
            "target_per_app": None,
            "unlocatable_by_app": {
                f"app-{index}": 1 if index == 0 else 0 for index in range(16)
            },
        }
    )
    _write(queue_path, queue)
    prereg = json.loads(preregistration.read_text(encoding="utf-8"))
    prereg["locked_thresholds"]["maximum_unlocatable_release_blockers"] = 0
    _write(preregistration, prereg)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is True
    assert status["metrics"]["candidate_sampling_mode"] == "all_eligible_release_blockers"
    assert status["metrics"]["unlocatable_release_blocker_count"] == 1
    assert "unlocatable_release_blockers_above_locked_maximum" in status["blockers"]


def test_field_effectiveness_binds_census_metadata_to_campaign_population(tmp_path: Path) -> None:
    evidence, preregistration = _fixture(tmp_path)
    campaign_path = evidence / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    for row in campaign["apps"]:
        row.update(
            {
                "available_release_blocking_findings": 1,
                "eligible_release_blocking_findings": 1,
                "unlocatable_release_blocking_findings": 0,
            }
        )
    _write(campaign_path, campaign)
    queue_path = evidence / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["sampling"].update(
        {
            "mode": "all_eligible_release_blockers",
            "target_per_app": None,
            "all_release_blockers_by_app": {f"app-{index}": 1 for index in range(16)},
            "unlocatable_by_app": {f"app-{index}": 0 for index in range(16)},
        }
    )
    queue["sampling"]["all_release_blockers_by_app"]["app-0"] = 2
    _write(queue_path, queue)

    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "candidate_population_binding_invalid:app-0" in status["validation_errors"]


def test_release_qualification_preregistration_cannot_lower_locked_accuracy_contract(
    tmp_path: Path,
) -> None:
    _evidence, preregistration = _fixture(tmp_path)
    payload = json.loads(preregistration.read_text(encoding="utf-8"))
    payload["qualification_contract"] = "release_blocker_actionability_v3"
    payload["apps"].extend(
        {
            **payload["apps"][index],
            "app": f"app-{16 + index}",
            "local_dir": f"app-{16 + index}",
            "repository": f"https://example.invalid/app-{16 + index}.git",
            "commit": f"{17 + index:040x}",
        }
        for index in range(4)
    )
    payload["locked_execution"] = {
        "candidate_selection_mode": "all_eligible_release_blockers",
        "release_blocking_policy": runner.RELEASE_BLOCKING_POLICY,
    }
    payload["locked_thresholds"].update(
        {
            "minimum_blocker_candidates": 100,
            "minimum_blocker_actionability": 0.9,
            "minimum_blocker_actionability_wilson_95_lower": 0.8,
            "maximum_unlocatable_release_blockers": 0,
            "minimum_distinct_blocker_rule_ids": 4,
            "minimum_apps_with_blocker_candidates": 20,
            "minimum_fully_actionable_app_rate": 0.9,
            "minimum_fully_actionable_app_wilson_95_lower": 0.8,
            "minimum_strata_with_blocker_candidates": 3,
            "maximum_single_rule_candidate_share": 0.5,
        }
    )

    runner._validate_preregistration(payload)
    payload["locked_thresholds"]["minimum_blocker_actionability"] = 0.89

    with pytest.raises(ValueError, match="minimum_blocker_actionability"):
        runner._validate_preregistration(payload)

    payload["locked_thresholds"]["minimum_blocker_actionability"] = 0.9
    payload["locked_thresholds"]["minimum_fully_actionable_app_wilson_95_lower"] = 0.79

    with pytest.raises(ValueError, match="minimum_fully_actionable_app_wilson_95_lower"):
        runner._validate_preregistration(payload)


def test_new_release_qualification_requires_frozen_release_lane_policy(tmp_path: Path) -> None:
    _evidence, preregistration = _fixture(tmp_path)
    payload = json.loads(preregistration.read_text(encoding="utf-8"))
    payload["qualification_contract"] = "release_blocker_actionability_v2"
    payload["locked_execution"] = {
        "candidate_selection_mode": "all_eligible_release_blockers",
    }
    payload["locked_thresholds"].update(
        {
            "minimum_blocker_candidates": 100,
            "minimum_blocker_actionability": 0.9,
            "minimum_blocker_actionability_wilson_95_lower": 0.8,
            "maximum_unlocatable_release_blockers": 0,
            "minimum_distinct_blocker_rule_ids": 4,
            "minimum_apps_with_blocker_candidates": 12,
            "minimum_strata_with_blocker_candidates": 3,
            "maximum_single_rule_candidate_share": 0.5,
        }
    )

    with pytest.raises(ValueError, match="explicit release blocking policy"):
        runner._validate_preregistration(payload)


def test_effectiveness_binds_preregistered_release_lane_policy(tmp_path: Path) -> None:
    evidence, preregistration = _fixture(tmp_path)
    prereg = json.loads(preregistration.read_text(encoding="utf-8"))
    prereg["locked_execution"] = {"release_blocking_policy": runner.RELEASE_BLOCKING_POLICY}
    _write(preregistration, prereg)

    campaign_path = evidence / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    campaign["release_decision_contract"] = {
        "blocking_policy": runner.RELEASE_BLOCKING_POLICY
    }
    _write(campaign_path, campaign)

    queue_path = evidence / "candidate-queue.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue["candidate_population"] = {
        "blocking_policy": runner.RELEASE_BLOCKING_POLICY,
        "lane": "release_blocking",
        "excluded_holds_still_fail_closed": True,
    }
    _write(queue_path, queue)

    assert scorer.build_status(evidence, preregistration)["integrity_passed"] is True

    queue["candidate_population"]["excluded_holds_still_fail_closed"] = False
    _write(queue_path, queue)
    status = scorer.build_status(evidence, preregistration)

    assert status["integrity_passed"] is False
    assert "release_blocking_policy_binding_invalid" in status["validation_errors"]


def test_effectiveness_rejects_single_rule_candidate_monoculture(tmp_path: Path) -> None:
    evidence, preregistration = _fixture(tmp_path)
    prereg = json.loads(preregistration.read_text(encoding="utf-8"))
    prereg["locked_thresholds"].update(
        {
            "minimum_distinct_blocker_rule_ids": 4,
            "minimum_apps_with_blocker_candidates": 12,
            "minimum_strata_with_blocker_candidates": 3,
            "maximum_single_rule_candidate_share": 0.5,
        }
    )
    _write(preregistration, prereg)

    status = scorer.build_status(evidence, preregistration)

    assert status["metrics"]["distinct_blocker_rule_count"] == 1
    assert status["metrics"]["apps_with_blocker_candidates"] == 16
    assert status["metrics"]["strata_with_blocker_candidates"] == ["long_tail", "mid", "top"]
    assert status["metrics"]["single_rule_candidate_share"] == 1.0
    assert "blocker_rule_diversity_below_locked_minimum" in status["blockers"]
    assert "single_rule_candidate_share_above_locked_maximum" in status["blockers"]
