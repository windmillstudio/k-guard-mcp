from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from scripts.holdout_integrity import (
        DISCOVERY_POOL_ROLE,
        DISCOVERY_POOL_SCHEMA,
        QUALIFICATION_POPULATION_ROLE,
        QUALIFICATION_POPULATION_SCHEMA,
        normalize_github_repository,
        repository_set_sha256,
        sha256_file,
    )
except ModuleNotFoundError:
    from holdout_integrity import (
        DISCOVERY_POOL_ROLE,
        DISCOVERY_POOL_SCHEMA,
        QUALIFICATION_POPULATION_ROLE,
        QUALIFICATION_POPULATION_SCHEMA,
        normalize_github_repository,
        repository_set_sha256,
        sha256_file,
    )


REPLACEMENT_SPEC_SCHEMA = "k_guard_structural_replacement_spec.v1"
REPLACEMENT_MIGRATION_SCHEMA = "k_guard_preexecution_structural_replacement.v1"
REPLACEMENT_POLICY = (
    "first_unselected_candidate_in_candidate_pool_order_within_same_stratum_v1"
)
REPLACEMENT_SELECTION_REASON = (
    "preexecution_structural_replacement_deployable_intentionally_vulnerable_application"
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
UNSUPPORTED_GIT_MODES = {"120000", "160000"}


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _load_object(path: Path, *, label: str) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _candidate_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        payload.get("schema") != "k_guard_independent_candidate_pool.v1"
        or payload.get("generated_without_k_guard") is not True
        or payload.get("raw_returned") is not False
    ):
        raise ValueError("candidate pool contract is invalid")
    boundary = payload.get("selection_boundary")
    if not isinstance(boundary, dict) or any(
        boundary.get(key) is not expected
        for key, expected in {
            "scanner_output_observed": False,
            "k_guard_imported": False,
            "k_guard_executed": False,
        }.items()
    ):
        raise ValueError("candidate pool independence boundary is invalid")
    rows = payload.get("candidates")
    if not isinstance(rows, list) or not rows:
        raise ValueError("candidate pool is empty")
    repository_ids: list[str] = []
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("candidate pool row is invalid")
        repository_id = str(row.get("repository_id") or "")
        if normalize_github_repository(repository_id) != repository_id:
            raise ValueError("candidate pool repository identity is invalid")
        if (
            REVISION_RE.fullmatch(str(row.get("commit") or "")) is None
            or not str(row.get("local_dir") or "")
            or not str(row.get("stratum") or "")
            or normalize_github_repository(str(row.get("origin") or ""))
            != repository_id
            or row.get("fork") is not False
            or row.get("archived") is not False
            or row.get("disabled") is not False
        ):
            raise ValueError(f"candidate pool source is ineligible: {repository_id}")
        stars = row.get("stars")
        if not isinstance(stars, int) or isinstance(stars, bool) or stars < 0:
            raise ValueError(f"candidate pool star count is invalid: {repository_id}")
        repository_ids.append(repository_id)
        normalized.append(row)
    if len(repository_ids) != len(set(repository_ids)):
        raise ValueError("candidate pool repositories must be unique")
    if payload.get("candidate_count") != len(normalized):
        raise ValueError("candidate pool count is invalid")
    return normalized


def _discovery_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if (
        payload.get("schema") != DISCOVERY_POOL_SCHEMA
        or payload.get("population_role") != DISCOVERY_POOL_ROLE
        or payload.get("qualification_authority") is not False
        or payload.get("qualification_thresholds_apply") is not False
        or payload.get("raw_returned") is not False
    ):
        raise ValueError("structural preflight contract is invalid")
    independence = payload.get("independence")
    if not isinstance(independence, dict) or any(
        independence.get(key) is not expected
        for key, expected in {
            "k_guard_executed": False,
            "k_guard_imported": False,
            "not_a_k_guard_result": True,
            "scanner_output_observed": False,
        }.items()
    ):
        raise ValueError("structural preflight independence boundary is invalid")
    rows = payload.get("apps")
    if not isinstance(rows, list) or not rows:
        raise ValueError("structural preflight is empty")
    repository_ids = [
        str(row.get("repository_id") or "") if isinstance(row, dict) else ""
        for row in rows
    ]
    if repository_ids != sorted(set(repository_ids)):
        raise ValueError("structural preflight repositories must be unique and sorted")
    return rows


def _projection(
    repository_ids: list[str],
    discovery_by_repository: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    rule_counts: Counter[str] = Counter()
    apps_with_candidates = 0
    strata_with_candidates: set[str] = set()
    for repository_id in repository_ids:
        row = discovery_by_repository[repository_id]
        estimated_rule_counts = row.get("estimated_rule_counts")
        if not isinstance(estimated_rule_counts, dict):
            raise ValueError("structural preflight rule counts are invalid")
        normalized_counts: dict[str, int] = {}
        for rule_id, count_value in estimated_rule_counts.items():
            rule_name = str(rule_id or "")
            if (
                not rule_name
                or not isinstance(count_value, int)
                or isinstance(count_value, bool)
                or count_value < 0
            ):
                raise ValueError("structural preflight rule count is invalid")
            if count_value:
                normalized_counts[rule_name] = count_value
                rule_counts[rule_name] += count_value
        estimated_count = row.get("estimated_candidate_count")
        if (
            not isinstance(estimated_count, int)
            or isinstance(estimated_count, bool)
            or estimated_count < 0
            or estimated_count != sum(normalized_counts.values())
        ):
            raise ValueError("structural preflight candidate count is invalid")
        if estimated_count:
            apps_with_candidates += 1
            strata_with_candidates.add(str(row.get("stratum") or ""))
    candidate_count = sum(rule_counts.values())
    maximum_share = (
        max(rule_counts.values()) / candidate_count
        if candidate_count and rule_counts
        else 0.0
    )
    return {
        "estimated_apps_with_candidates": apps_with_candidates,
        "estimated_candidate_count": candidate_count,
        "estimated_distinct_rule_count": len(rule_counts),
        "estimated_maximum_single_rule_share": round(maximum_share, 6),
        "estimated_rule_counts": dict(sorted(rule_counts.items())),
        "estimated_strata_with_candidates": sorted(strata_with_candidates),
        "not_a_k_guard_result": True,
    }


def build_replacement_selection(
    *,
    previous_selected_path: Path,
    previous_preregistration_path: Path,
    candidate_pool_path: Path,
    structural_preflight_path: Path,
    replacement_spec_path: Path,
    new_evidence_contract_revision: str,
    superseded_preregistration_relative: str,
    superseded_selected_relative: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if REVISION_RE.fullmatch(new_evidence_contract_revision) is None:
        raise ValueError("new evidence contract revision must be a full commit SHA")
    previous_selected = _load_object(previous_selected_path, label="previous selection")
    previous_preregistration = _load_object(
        previous_preregistration_path,
        label="previous preregistration",
    )
    candidate_pool = _load_object(candidate_pool_path, label="candidate pool")
    discovery = _load_object(structural_preflight_path, label="structural preflight")
    spec = _load_object(replacement_spec_path, label="replacement spec")

    if (
        previous_selected.get("schema") != QUALIFICATION_POPULATION_SCHEMA
        or previous_selected.get("population_role") != QUALIFICATION_POPULATION_ROLE
        or previous_selected.get("qualification_authority") is not True
        or previous_selected.get("qualification_thresholds_apply") is not True
        or previous_selected.get("raw_returned") is not False
    ):
        raise ValueError("previous qualification population contract is invalid")
    previous_apps = previous_selected.get("apps")
    if not isinstance(previous_apps, list) or not previous_apps:
        raise ValueError("previous qualification population is empty")
    previous_by_repository = {
        str(row.get("repository_id") or ""): row
        for row in previous_apps
        if isinstance(row, dict)
    }
    if len(previous_by_repository) != len(previous_apps):
        raise ValueError("previous qualification repositories must be unique")
    previous_registered_apps = previous_preregistration.get("apps")
    if not isinstance(previous_registered_apps, list):
        raise ValueError("previous preregistration apps are invalid")
    previous_registered_by_repository = {
        str(row.get("repository_id") or ""): row
        for row in previous_registered_apps
        if isinstance(row, dict)
    }
    if set(previous_registered_by_repository) != set(previous_by_repository):
        raise ValueError("previous selection and preregistration repositories differ")

    candidates = _candidate_rows(candidate_pool)
    candidate_by_repository = {
        str(row["repository_id"]): row for row in candidates
    }
    discovery_rows = _discovery_rows(discovery)
    discovery_by_repository = {
        str(row["repository_id"]): row for row in discovery_rows
    }
    if set(candidate_by_repository) != set(discovery_by_repository):
        raise ValueError("candidate pool and structural preflight repository sets differ")
    if previous_selected.get("bindings", {}).get(
        "structural_preflight_sha256"
    ) != sha256_file(structural_preflight_path):
        raise ValueError("previous selection is not bound to the structural preflight")

    if (
        spec.get("schema") != REPLACEMENT_SPEC_SCHEMA
        or spec.get("scanner_execution_before_replacement") is not False
        or spec.get("scanner_output_seen_before_replacement") is not False
        or spec.get("raw_returned") is not False
    ):
        raise ValueError("replacement spec boundary is invalid")
    replacement_rows = spec.get("replacements")
    if not isinstance(replacement_rows, list) or not replacement_rows:
        raise ValueError("replacement spec is empty")

    old_ids = set(previous_by_repository)
    removed_ids: set[str] = set()
    added_ids: set[str] = set()
    normalized_replacements: list[dict[str, Any]] = []
    for replacement in replacement_rows:
        if not isinstance(replacement, dict):
            raise ValueError("replacement row is invalid")
        removed_id = str(replacement.get("removed_repository_id") or "")
        added_id = str(replacement.get("added_repository_id") or "")
        if (
            removed_id not in previous_by_repository
            or added_id not in candidate_by_repository
            or added_id in old_ids
            or removed_id in removed_ids
            or added_id in added_ids
        ):
            raise ValueError("replacement repository mapping is invalid")
        removed_app = previous_by_repository[removed_id]
        registered_removed_app = previous_registered_by_repository[removed_id]
        added_candidate = candidate_by_repository[added_id]
        stratum = str(removed_app.get("stratum") or "")
        if (
            not stratum
            or added_candidate.get("stratum") != stratum
            or discovery_by_repository[added_id].get("stratum") != stratum
        ):
            raise ValueError("replacement must preserve the GitHub star stratum")

        unsupported_entries = replacement.get("unsupported_git_entries")
        if not isinstance(unsupported_entries, list) or not unsupported_entries:
            raise ValueError("replacement must identify unsupported Git entries")
        normalized_entries: list[dict[str, str]] = []
        for entry in unsupported_entries:
            if not isinstance(entry, dict):
                raise ValueError("unsupported Git entry evidence is invalid")
            mode = str(entry.get("mode") or "")
            path = str(entry.get("path") or "")
            subtype = str(entry.get("subtype") or "")
            if (
                mode not in UNSUPPORTED_GIT_MODES
                or subtype
                not in {
                    "symlink",
                    "submodule",
                }
                or not path
                or path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise ValueError("unsupported Git entry evidence is invalid")
            normalized_entries.append(
                {
                    "mode": mode,
                    "path": path,
                    "subtype": subtype,
                }
            )
        screening = replacement.get("application_screening")
        evidence_paths = (
            screening.get("evidence_paths") if isinstance(screening, dict) else None
        )
        if (
            not isinstance(screening, dict)
            or screening.get("verdict")
            != "deployable_intentionally_vulnerable_application"
            or screening.get("scanner_output_observed") is not False
            or not isinstance(evidence_paths, list)
            or not evidence_paths
            or any(
                not isinstance(path, str)
                or not path
                or path.startswith("/")
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
                for path in evidence_paths
            )
        ):
            raise ValueError("replacement application screening is invalid")

        removed_ids.add(removed_id)
        added_ids.add(added_id)
        normalized_replacements.append(
            {
                "removed_repository_id": removed_id,
                "removed_commit": str(registered_removed_app.get("commit") or ""),
                "removed_commit_tree": str(
                    registered_removed_app.get("commit_tree") or ""
                ),
                "added_repository_id": added_id,
                "added_commit": str(added_candidate.get("commit") or ""),
                "stratum": stratum,
                "unsupported_git_entries": normalized_entries,
                "application_screening": {
                    "verdict": screening["verdict"],
                    "evidence_paths": list(evidence_paths),
                    "scanner_output_observed": False,
                },
            }
        )

    replacements_by_stratum: dict[str, list[dict[str, Any]]] = {}
    for row in normalized_replacements:
        replacements_by_stratum.setdefault(str(row["stratum"]), []).append(row)
    for stratum, rows in replacements_by_stratum.items():
        rows.sort(key=lambda row: str(row["removed_repository_id"]))
        expected = [
            str(candidate["repository_id"])
            for candidate in candidates
            if candidate.get("stratum") == stratum
            and candidate.get("repository_id") not in old_ids
        ][: len(rows)]
        actual = [str(row["added_repository_id"]) for row in rows]
        if actual != expected:
            raise ValueError(
                f"replacement skipped an earlier unselected {stratum} candidate"
            )

    selected = copy.deepcopy(previous_selected)
    replacement_apps: list[dict[str, Any]] = []
    for added_id in added_ids:
        candidate = candidate_by_repository[added_id]
        replacement_apps.append(
            {
                "app": str(candidate["local_dir"]),
                "commit": str(candidate["commit"]),
                "default_branch": str(candidate["default_branch"]),
                "language": candidate.get("language"),
                "license_spdx": candidate.get("license_spdx"),
                "local_dir": str(candidate["local_dir"]),
                "repository": str(candidate["origin"]),
                "repository_id": added_id,
                "selection_reason": REPLACEMENT_SELECTION_REASON,
                "stars_at_selection": int(candidate["stars"]),
                "stratum": str(candidate["stratum"]),
            }
        )
    selected_apps = [
        copy.deepcopy(row)
        for row in previous_apps
        if str(row.get("repository_id") or "") not in removed_ids
    ]
    selected_apps.extend(replacement_apps)
    selected_apps.sort(key=lambda row: str(row["repository_id"]))
    selected_ids = [str(row["repository_id"]) for row in selected_apps]
    if len(selected_ids) != len(old_ids) or len(selected_ids) != len(set(selected_ids)):
        raise ValueError("replacement selection changed the qualification population size")

    previous_strata = Counter(str(row.get("stratum") or "") for row in previous_apps)
    selected_strata = Counter(str(row.get("stratum") or "") for row in selected_apps)
    if selected_strata != previous_strata:
        raise ValueError("replacement selection changed the stratum counts")

    migration = {
        "schema": REPLACEMENT_MIGRATION_SCHEMA,
        "reason": (
            "three preregistered repositories failed regular-file Git tree eligibility "
            "before any scanner execution"
        ),
        "replacement_policy": REPLACEMENT_POLICY,
        "supersedes_campaign_id": str(
            previous_preregistration.get("campaign_id") or ""
        ),
        "superseded_preregistration_path": superseded_preregistration_relative,
        "superseded_preregistration_sha256": sha256_file(
            previous_preregistration_path
        ),
        "superseded_selected_corpus_path": superseded_selected_relative,
        "superseded_selected_corpus_sha256": sha256_file(previous_selected_path),
        "candidate_pool_artifact": candidate_pool_path.name,
        "candidate_pool_sha256": sha256_file(candidate_pool_path),
        "structural_preflight_artifact": structural_preflight_path.name,
        "structural_preflight_sha256": sha256_file(structural_preflight_path),
        "new_evidence_contract_revision": new_evidence_contract_revision,
        "scanner_execution_before_migration": False,
        "scanner_output_seen_before_migration": False,
        "superseded_report_count": 0,
        "superseded_runtime_receipt_count": 0,
        "superseded_source_receipt_count": 0,
        "source_selection_changed": True,
        "repository_set_changed": True,
        "stratum_counts_changed": False,
        "locked_thresholds_changed": False,
        "locked_review_changed": False,
        "replacement_count": len(normalized_replacements),
        "replacements": sorted(
            normalized_replacements,
            key=lambda row: str(row["removed_repository_id"]),
        ),
        "raw_returned": False,
    }

    selected["apps"] = selected_apps
    selected["repository_count"] = len(selected_ids)
    selected["repository_set_sha256"] = repository_set_sha256(selected_ids)
    selected["preflight_only_expected_population"] = _projection(
        selected_ids,
        discovery_by_repository,
    )
    selected.setdefault("bindings", {})["candidate_pool_sha256"] = sha256_file(
        candidate_pool_path
    )
    selected["bindings"]["structural_preflight_sha256"] = sha256_file(
        structural_preflight_path
    )
    selected["selection"]["stratum_counts"] = dict(sorted(selected_strata.items()))
    selected.setdefault("exclusions", {})[
        "unsupported_git_tree_entry_screening"
    ] = sorted(removed_ids)
    selected["selection_migration"] = migration
    return selected, migration


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Replace pre-execution Git-tree-ineligible holdout sources without "
            "observing K-Guard output."
        )
    )
    parser.add_argument("--previous-selected", type=Path, required=True)
    parser.add_argument("--previous-preregistration", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--structural-preflight", type=Path, required=True)
    parser.add_argument("--replacement-spec", type=Path, required=True)
    parser.add_argument("--new-evidence-contract-revision", required=True)
    parser.add_argument("--superseded-preregistration-relative", required=True)
    parser.add_argument("--superseded-selected-relative", required=True)
    parser.add_argument("--output-selected", type=Path, required=True)
    parser.add_argument("--output-migration", type=Path, required=True)
    args = parser.parse_args()

    selected, migration = build_replacement_selection(
        previous_selected_path=args.previous_selected,
        previous_preregistration_path=args.previous_preregistration,
        candidate_pool_path=args.candidate_pool,
        structural_preflight_path=args.structural_preflight,
        replacement_spec_path=args.replacement_spec,
        new_evidence_contract_revision=args.new_evidence_contract_revision,
        superseded_preregistration_relative=args.superseded_preregistration_relative,
        superseded_selected_relative=args.superseded_selected_relative,
    )
    args.output_selected.parent.mkdir(parents=True, exist_ok=True)
    args.output_migration.parent.mkdir(parents=True, exist_ok=True)
    args.output_selected.write_bytes(_canonical_bytes(selected))
    args.output_migration.write_bytes(_canonical_bytes(migration))
    print(
        json.dumps(
            {
                "schema": migration["schema"],
                "replacement_count": migration["replacement_count"],
                "repository_set_sha256": selected["repository_set_sha256"],
                "raw_returned": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
