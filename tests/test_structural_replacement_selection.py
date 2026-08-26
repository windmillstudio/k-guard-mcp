from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


integrity = _load(
    "holdout_integrity_structural_replacement_test",
    ROOT / "scripts" / "holdout_integrity.py",
)
builder = _load(
    "build_structural_replacement_selection_test",
    ROOT / "scripts" / "build_structural_replacement_selection.py",
)


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _candidate(
    repository_id: str,
    *,
    stratum: str,
    stars: int,
    commit_char: str,
) -> dict:
    owner, name = repository_id.split("/")
    return {
        "full_name": f"{owner}/{name}",
        "repository_id": repository_id,
        "clone_url": f"https://github.com/{owner}/{name}.git",
        "local_dir": f"{owner}--{name}",
        "commit": commit_char * 40,
        "stars": stars,
        "stratum": stratum,
        "language": "Python",
        "license_spdx": "MIT",
        "default_branch": "main",
        "fork": False,
        "archived": False,
        "disabled": False,
        "origin": f"https://github.com/{owner}/{name}.git",
    }


def _fixture(tmp_path: Path) -> dict[str, Path | dict]:
    previous_root = tmp_path / "v7"
    current_root = tmp_path / "v8"
    candidate_path = current_root / "candidate-pool.json"
    discovery_path = current_root / "structural-preflight.json"
    candidates = sorted(
        [
            _candidate("new/long-a", stratum="long_tail", stars=1, commit_char="a"),
            _candidate("new/long-b", stratum="long_tail", stars=2, commit_char="b"),
            _candidate("new/mid-a", stratum="mid", stars=10, commit_char="c"),
            _candidate("new/mid-b", stratum="mid", stars=11, commit_char="d"),
            _candidate("old/long", stratum="long_tail", stars=1, commit_char="e"),
            _candidate("old/mid", stratum="mid", stars=10, commit_char="f"),
        ],
        key=lambda row: row["repository_id"],
    )
    candidate_pool = {
        "schema": "k_guard_independent_candidate_pool.v1",
        "generated_without_k_guard": True,
        "candidate_count": len(candidates),
        "selection_boundary": {
            "scanner_output_observed": False,
            "k_guard_imported": False,
            "k_guard_executed": False,
        },
        "candidates": candidates,
        "raw_returned": False,
    }
    discovery_apps = [
        {
            "repository_id": row["repository_id"],
            "stars": row["stars"],
            "stratum": row["stratum"],
            "files_read": 1,
            "bytes_read": 10,
            "estimated_candidate_count": (
                3 if row["repository_id"] == "old/long" else 0
            ),
            "estimated_rule_counts": (
                {"CONFIG_GHA_MUTABLE_ACTION_REF": 3}
                if row["repository_id"] == "old/long"
                else {}
            ),
        }
        for row in candidates
    ]
    discovery = {
        "schema": integrity.DISCOVERY_POOL_SCHEMA,
        "population_role": integrity.DISCOVERY_POOL_ROLE,
        "qualification_authority": False,
        "qualification_thresholds_apply": False,
        "qualification_population_artifact": "selected-corpus.json",
        "independence": {
            "k_guard_executed": False,
            "k_guard_imported": False,
            "not_a_k_guard_result": True,
            "scanner_output_observed": False,
        },
        "candidate_repository_count": len(discovery_apps),
        "apps": discovery_apps,
        "raw_returned": False,
    }
    _write(candidate_path, candidate_pool)
    _write(discovery_path, discovery)

    selected_apps = [
        {
            "app": "old--long",
            "commit": "e" * 40,
            "default_branch": "main",
            "language": "Python",
            "license_spdx": "MIT",
            "local_dir": "old--long",
            "repository": "https://github.com/old/long.git",
            "repository_id": "old/long",
            "selection_reason": "previous",
            "stars_at_selection": 1,
            "stratum": "long_tail",
        },
        {
            "app": "old--mid",
            "commit": "f" * 40,
            "default_branch": "main",
            "language": "Python",
            "license_spdx": "MIT",
            "local_dir": "old--mid",
            "repository": "https://github.com/old/mid.git",
            "repository_id": "old/mid",
            "selection_reason": "previous",
            "stars_at_selection": 10,
            "stratum": "mid",
        },
    ]
    previous_selected = {
        "schema": integrity.QUALIFICATION_POPULATION_SCHEMA,
        "population_role": integrity.QUALIFICATION_POPULATION_ROLE,
        "qualification_authority": True,
        "qualification_thresholds_apply": True,
        "discovery_population_artifact": "structural-preflight.json",
        "bindings": {
            "structural_preflight_sha256": integrity.sha256_file(discovery_path)
        },
        "selection": {
            "stratum_counts": {"long_tail": 1, "mid": 1},
        },
        "exclusions": {},
        "repository_count": 2,
        "repository_set_sha256": integrity.repository_set_sha256(
            ["old/long", "old/mid"]
        ),
        "apps": selected_apps,
        "preflight_only_expected_population": {
            "estimated_apps_with_candidates": 1,
            "estimated_candidate_count": 3,
            "estimated_distinct_rule_count": 1,
            "estimated_maximum_single_rule_share": 1.0,
            "estimated_rule_counts": {"CONFIG_GHA_MUTABLE_ACTION_REF": 3},
            "estimated_strata_with_candidates": ["long_tail"],
            "not_a_k_guard_result": True,
        },
        "raw_returned": False,
    }
    previous_apps = [
        {
            **row,
            "archived": False,
            "commit_tree": char * 40,
            "fork_parent_repository_id": None,
            "github_node_id": f"R_{index}",
            "is_fork": False,
            "stars_at_registration": row["stars_at_selection"],
        }
        for index, (row, char) in enumerate(
            zip(selected_apps, ("1", "2"), strict=True),
            start=1,
        )
    ]
    previous_preregistration = {
        "campaign_id": "campaign-v7",
        "apps": previous_apps,
        "locked_thresholds": {"minimum_app_count": 2},
        "locked_review": {"required_reviewer_count": 3},
        "locked_execution": {"runs_per_app": 2},
        "label_contract": {"labels": ["true_positive"]},
        "claim_boundary": {"public_repositories_only": True},
        "qualification_contract": {"decision": "all_gates"},
    }
    previous_selected_path = previous_root / "selected-corpus.json"
    previous_preregistration_path = previous_root / "preregistration.json"
    _write(previous_selected_path, previous_selected)
    _write(previous_preregistration_path, previous_preregistration)

    spec = {
        "schema": builder.REPLACEMENT_SPEC_SCHEMA,
        "scanner_execution_before_replacement": False,
        "scanner_output_seen_before_replacement": False,
        "replacements": [
            {
                "removed_repository_id": "old/long",
                "added_repository_id": "new/long-a",
                "unsupported_git_entries": [
                    {
                        "mode": "160000",
                        "path": "vendor/app",
                        "subtype": "submodule",
                    }
                ],
                "application_screening": {
                    "verdict": "deployable_intentionally_vulnerable_application",
                    "evidence_paths": ["README.md", "Dockerfile"],
                    "scanner_output_observed": False,
                },
            },
            {
                "removed_repository_id": "old/mid",
                "added_repository_id": "new/mid-a",
                "unsupported_git_entries": [
                    {
                        "mode": "120000",
                        "path": "static/fonts",
                        "subtype": "symlink",
                    }
                ],
                "application_screening": {
                    "verdict": "deployable_intentionally_vulnerable_application",
                    "evidence_paths": ["README.md", "docker-compose.yml"],
                    "scanner_output_observed": False,
                },
            },
        ],
        "raw_returned": False,
    }
    spec_path = current_root / "replacement-spec.json"
    _write(spec_path, spec)
    return {
        "current_root": current_root,
        "candidate_path": candidate_path,
        "candidate_pool": candidate_pool,
        "discovery_path": discovery_path,
        "previous_selected_path": previous_selected_path,
        "previous_selected": previous_selected,
        "previous_preregistration_path": previous_preregistration_path,
        "previous_preregistration": previous_preregistration,
        "spec_path": spec_path,
        "spec": spec,
    }


def _build(paths: dict[str, Path | dict]) -> tuple[dict, dict]:
    return builder.build_replacement_selection(
        previous_selected_path=paths["previous_selected_path"],
        previous_preregistration_path=paths["previous_preregistration_path"],
        candidate_pool_path=paths["candidate_path"],
        structural_preflight_path=paths["discovery_path"],
        replacement_spec_path=paths["spec_path"],
        new_evidence_contract_revision="9" * 40,
        superseded_preregistration_relative="../v7/preregistration.json",
        superseded_selected_relative="../v7/selected-corpus.json",
    )


def test_builder_uses_first_same_stratum_reserves_and_binds_migration(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    selected, migration = _build(paths)

    assert [row["repository_id"] for row in selected["apps"]] == [
        "new/long-a",
        "new/mid-a",
    ]
    assert selected["selection"]["stratum_counts"] == {
        "long_tail": 1,
        "mid": 1,
    }
    assert selected["preflight_only_expected_population"][
        "estimated_candidate_count"
    ] == 0
    assert selected["selection_migration"] == migration
    assert migration["replacement_policy"] == builder.REPLACEMENT_POLICY
    assert migration["scanner_output_seen_before_migration"] is False

    current_apps = []
    for index, row in enumerate(selected["apps"], start=1):
        candidate = next(
            candidate
            for candidate in paths["candidate_pool"]["candidates"]
            if candidate["repository_id"] == row["repository_id"]
        )
        current_apps.append(
            {
                **row,
                "archived": False,
                "commit_tree": str(index + 2) * 40,
                "fork_parent_repository_id": None,
                "github_node_id": f"R_new_{index}",
                "is_fork": False,
                "stars_at_registration": candidate["stars"],
            }
        )
    current = copy.deepcopy(paths["previous_preregistration"])
    current["campaign_id"] = "campaign-v8"
    current["apps"] = current_apps
    current["registration_migration"] = migration
    integrity._validate_preexecution_structural_replacement(
        current,
        paths["current_root"],
        {
            "qualification": selected,
            "discovery_path": paths["discovery_path"],
        },
    )


def test_builder_rejects_skipping_an_earlier_same_stratum_reserve(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    spec = copy.deepcopy(paths["spec"])
    spec["replacements"][0]["added_repository_id"] = "new/long-b"
    _write(paths["spec_path"], spec)

    with pytest.raises(ValueError, match="skipped an earlier"):
        _build(paths)


def test_migration_validator_rejects_locked_contract_changes(
    tmp_path: Path,
) -> None:
    paths = _fixture(tmp_path)
    selected, migration = _build(paths)
    current = copy.deepcopy(paths["previous_preregistration"])
    current["campaign_id"] = "campaign-v8"
    current["locked_thresholds"] = {"minimum_app_count": 1}
    current["apps"] = []
    for index, row in enumerate(selected["apps"], start=1):
        candidate = next(
            candidate
            for candidate in paths["candidate_pool"]["candidates"]
            if candidate["repository_id"] == row["repository_id"]
        )
        current["apps"].append(
            {
                **row,
                "archived": False,
                "commit_tree": str(index + 2) * 40,
                "fork_parent_repository_id": None,
                "github_node_id": f"R_new_{index}",
                "is_fork": False,
                "stars_at_registration": candidate["stars"],
            }
        )
    current["registration_migration"] = migration

    with pytest.raises(ValueError, match="changed a locked contract"):
        integrity._validate_preexecution_structural_replacement(
            current,
            paths["current_root"],
            {
                "qualification": selected,
                "discovery_path": paths["discovery_path"],
            },
        )
