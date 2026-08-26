from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


HOLDOUT_EXCLUSION_SCHEMA = "k_guard_holdout_exclusions.v1"
DISCOVERY_POOL_SCHEMA = "k_guard_independent_structural_preflight.v1"
QUALIFICATION_POPULATION_SCHEMA = "k_guard_independent_holdout_selection.v1"
DISCOVERY_POOL_ROLE = "discovery_pool_only"
QUALIFICATION_POPULATION_ROLE = "locked_qualification_population"
PROTOCOL_RECOVERY_REPLAY_STATUS = "locked_before_protocol_recovery_replay"
PROTOCOL_RECOVERY_REPLAY_SCHEMA = "k_guard_protocol_recovery_replay.v1"
PRIOR_EXECUTION_MANIFEST_SCHEMA = "k_guard_prior_campaign_execution_manifest.v1"
QUALIFICATION_BOUNDARY_SCHEMA = "k_guard_holdout_qualification_boundary.v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_ID_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
V4_REVIEW_VENDORS = ["anthropic", "openai", "xai"]
STRUCTURAL_REPLACEMENT_MIGRATION_SCHEMA = (
    "k_guard_preexecution_structural_replacement.v1"
)
STRUCTURAL_REPLACEMENT_POLICY = (
    "first_unselected_candidate_in_candidate_pool_order_within_same_stratum_v1"
)
STRUCTURAL_REPLACEMENT_SELECTION_REASON = (
    "preexecution_structural_replacement_deployable_intentionally_vulnerable_application"
)
UNSUPPORTED_GIT_TREE_MODES = {"120000", "160000"}
V4_REQUIRED_CLAIM_BOUNDARY = {
    "public_repositories_only": True,
    "owned_or_partner_scope": False,
    "commercial_release_authority": False,
    "field_prevalence_estimate": False,
    "risk_enriched_challenge_set": True,
    "static_source_actionability_only": True,
    "full_app_recall_measured": False,
    "runtime_exploitability_measured": False,
    "pristine_blind_holdout": False,
    "cross_vendor_ai_review": True,
    "not_human_review": True,
    "independent_git_execution_attested": False,
    "external_signed_git_provenance_required_for_contest_go": True,
}


def normalize_github_repository(value: str) -> str | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    if candidate.startswith("git@github.com:"):
        candidate = candidate[len("git@github.com:") :]
    elif "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.hostname is None or parsed.hostname.casefold() not in {"github.com", "www.github.com"}:
            return None
        candidate = parsed.path.strip("/")
    else:
        candidate = candidate.strip("/")
    if candidate.casefold().endswith(".git"):
        candidate = candidate[:-4]
    parts = candidate.split("/")
    if len(parts) != 2:
        return None
    repository_id = "/".join(parts).casefold()
    return repository_id if REPOSITORY_ID_RE.fullmatch(repository_id) else None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_set_sha256(repository_ids: list[str] | set[str]) -> str:
    encoded = json.dumps(
        sorted(set(repository_ids)),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _star_stratum(value: Any) -> str | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    if value < 10:
        return "long_tail"
    if value < 100:
        return "mid"
    return "top"


def load_exclusion_snapshot(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != HOLDOUT_EXCLUSION_SCHEMA:
        raise ValueError("holdout exclusion snapshot schema is invalid")
    source_revision = str(payload.get("source_revision") or "")
    if REVISION_RE.fullmatch(source_revision) is None:
        raise ValueError("holdout exclusion source revision is invalid")
    rows = payload.get("repositories")
    if not isinstance(rows, list) or not rows:
        raise ValueError("holdout exclusion snapshot is empty")
    repository_ids: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("holdout exclusion row is invalid")
        repository_id = str(row.get("repository_id") or "")
        if normalize_github_repository(repository_id) != repository_id:
            raise ValueError(f"holdout exclusion repository is invalid: {repository_id or 'missing'}")
        evidence_paths = row.get("evidence_paths")
        if not isinstance(evidence_paths, list) or not evidence_paths or any(
            not isinstance(value, str) or not value.startswith("evidence/") for value in evidence_paths
        ):
            raise ValueError(f"holdout exclusion provenance is invalid: {repository_id}")
        repository_ids.append(repository_id)
    if repository_ids != sorted(set(repository_ids)):
        raise ValueError("holdout exclusion repositories must be unique and sorted")
    if int(payload.get("repository_count") or 0) != len(repository_ids):
        raise ValueError("holdout exclusion repository count is invalid")
    if payload.get("repository_set_sha256") != repository_set_sha256(repository_ids):
        raise ValueError("holdout exclusion repository set hash is invalid")
    if payload.get("raw_returned") is not False:
        raise ValueError("holdout exclusion raw evidence boundary is invalid")
    return payload


def _load_bound_json_artifact(
    preregistration_root: Path,
    relative_value: Any,
    expected_sha256: Any,
    *,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    relative = Path(str(relative_value or ""))
    if not relative.name or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"v4 holdout {label} path is invalid")
    current = preregistration_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"v4 holdout {label} path contains a symlink")
    candidate = (preregistration_root / relative).resolve()
    if (
        not candidate.is_relative_to(preregistration_root)
        or not candidate.is_file()
        or candidate.is_symlink()
    ):
        raise ValueError(f"v4 holdout {label} artifact is missing")
    expected_hash = str(expected_sha256 or "")
    if SHA256_RE.fullmatch(expected_hash) is None or sha256_file(candidate) != expected_hash:
        raise ValueError(f"v4 holdout {label} hash is invalid")
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"v4 holdout {label} artifact is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"v4 holdout {label} artifact must be an object")
    return candidate, payload


def _load_sibling_bound_json_artifact(
    preregistration_root: Path,
    relative_value: Any,
    expected_sha256: Any,
    *,
    label: str,
) -> tuple[Path, dict[str, Any]]:
    relative = Path(str(relative_value or ""))
    if (
        len(relative.parts) != 3
        or relative.parts[0] != ".."
        or any(part in {"", ".", ".."} for part in relative.parts[1:])
        or relative.is_absolute()
    ):
        raise ValueError(f"v4 holdout {label} sibling path is invalid")
    evidence_root = preregistration_root.parent.resolve()
    sibling_root = preregistration_root.parent / relative.parts[1]
    if sibling_root.is_symlink():
        raise ValueError(f"v4 holdout {label} sibling path contains a symlink")
    candidate = (preregistration_root / relative).resolve()
    if (
        candidate.parent.parent != evidence_root
        or not candidate.is_file()
        or candidate.is_symlink()
    ):
        raise ValueError(f"v4 holdout {label} sibling artifact is missing")
    expected_hash = str(expected_sha256 or "")
    if SHA256_RE.fullmatch(expected_hash) is None or sha256_file(candidate) != expected_hash:
        raise ValueError(f"v4 holdout {label} sibling hash is invalid")
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"v4 holdout {label} sibling artifact is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"v4 holdout {label} sibling artifact must be an object")
    return candidate, payload


def protocol_recovery_qualification_boundary(
    payload: dict[str, Any],
) -> dict[str, Any]:
    if payload.get("status") != PROTOCOL_RECOVERY_REPLAY_STATUS:
        return {}
    replay = (
        payload.get("replay_provenance")
        if isinstance(payload.get("replay_provenance"), dict)
        else {}
    )
    return {
        "schema": QUALIFICATION_BOUNDARY_SCHEMA,
        "mode": "protocol_recovery_replay",
        "qualification_eligible": False,
        "release_claim_allowed": False,
        "evidence_use": "development_baseline_only",
        "fresh_unseen_holdout_required_for_go": True,
        "prior_candidate_content_exposure_assumed": True,
        "superseded_campaign_id": replay.get("superseded_campaign_id"),
        "prior_execution_manifest_sha256": replay.get(
            "prior_execution_manifest_sha256"
        ),
    }


def _validate_protocol_recovery_replay(
    payload: dict[str, Any],
    preregistration_root: Path,
) -> tuple[Path, dict[str, Any]] | None:
    status = payload.get("status")
    replay = payload.get("replay_provenance")
    if status != PROTOCOL_RECOVERY_REPLAY_STATUS:
        if replay is not None:
            raise ValueError(
                "v4 qualification holdout cannot carry protocol recovery replay provenance"
            )
        return None
    if payload.get("qualification_contract") != "release_blocker_actionability_v4":
        raise ValueError("protocol recovery replay requires the v4 qualification contract")
    if not isinstance(replay, dict):
        raise ValueError("protocol recovery replay provenance is missing")
    required_replay_values = {
        "schema": PROTOCOL_RECOVERY_REPLAY_SCHEMA,
        "mode": "protocol_recovery_replay",
        "qualifying_holdout": False,
        "release_claim_allowed": False,
        "evidence_use": "development_baseline_only",
        "source_population_reused": True,
        "prior_scanner_execution": True,
        "prior_scanner_output_seen": True,
        "prior_candidate_content_exposure_assumed": True,
        "candidate_labels_created": False,
        "effectiveness_status_created": False,
        "analyzer_change_informed_by_prior_execution": True,
        "detector_rules_changed_after_observation": False,
        "release_policy_changed_after_observation": False,
        "final_unseen_holdout_required_for_go": True,
        "raw_returned": False,
    }
    for key, expected in required_replay_values.items():
        if replay.get(key) != expected:
            raise ValueError(
                f"protocol recovery replay provenance is invalid: {key}"
            )
    superseded_campaign_id = str(replay.get("superseded_campaign_id") or "")
    if (
        not superseded_campaign_id
        or superseded_campaign_id == str(payload.get("campaign_id") or "")
    ):
        raise ValueError("protocol recovery replay superseded campaign is invalid")
    manifest_path, manifest = _load_bound_json_artifact(
        preregistration_root,
        replay.get("prior_execution_manifest_path"),
        replay.get("prior_execution_manifest_sha256"),
        label="prior execution manifest",
    )
    required_manifest_values = {
        "schema": PRIOR_EXECUTION_MANIFEST_SCHEMA,
        "source_campaign_id": superseded_campaign_id,
        "target_campaign_id": payload.get("campaign_id"),
        "source_population_reused": True,
        "prior_scanner_execution": True,
        "prior_scanner_output_seen": True,
        "prior_candidate_content_exposure_assumed": True,
        "candidate_labels_created": False,
        "effectiveness_status_created": False,
        "analyzer_change_informed_by_prior_execution": True,
        "detector_rules_changed_after_observation": False,
        "release_policy_changed_after_observation": False,
        "raw_returned": False,
    }
    for key, expected in required_manifest_values.items():
        if manifest.get(key) != expected:
            raise ValueError(
                f"protocol recovery prior execution manifest is invalid: {key}"
            )
    integrity = (
        payload.get("holdout_integrity")
        if isinstance(payload.get("holdout_integrity"), dict)
        else {}
    )
    apps = payload.get("apps") if isinstance(payload.get("apps"), list) else []
    if (
        manifest.get("source_repository_set_sha256")
        != integrity.get("repository_set_sha256")
        or manifest.get("app_count") != len(apps)
    ):
        raise ValueError(
            "protocol recovery prior execution source population binding is invalid"
        )
    attempts = (
        manifest.get("attempts")
        if isinstance(manifest.get("attempts"), list)
        else []
    )
    if not attempts or manifest.get("attempt_count") != len(attempts):
        raise ValueError("protocol recovery prior execution attempts are invalid")
    attempt_ids: set[str] = set()
    totals = Counter()
    for row in attempts:
        if not isinstance(row, dict):
            raise ValueError("protocol recovery prior execution attempt row is invalid")
        attempt_id = str(row.get("attempt_id") or "")
        if not attempt_id or attempt_id in attempt_ids:
            raise ValueError(
                "protocol recovery prior execution attempt identity is invalid"
            )
        attempt_ids.add(attempt_id)
        for field in (
            "output_tree_sha256",
            "artifact_inventory_sha256",
        ):
            if SHA256_RE.fullmatch(str(row.get(field) or "")) is None:
                raise ValueError(
                    f"protocol recovery prior execution attempt hash is invalid: {field}"
                )
        for field in (
            "report_count",
            "source_receipt_count",
            "runtime_receipt_count",
        ):
            value = row.get(field)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(
                    f"protocol recovery prior execution attempt count is invalid: {field}"
                )
            totals[field] += value
        if (
            row.get("candidate_labels_present") is not False
            or row.get("effectiveness_status_present") is not False
            or row.get("raw_returned") is not False
        ):
            raise ValueError(
                "protocol recovery prior execution attempt boundary is invalid"
            )
    aggregate = (
        manifest.get("aggregate")
        if isinstance(manifest.get("aggregate"), dict)
        else {}
    )
    if (
        totals["report_count"] < 1
        or totals["source_receipt_count"] < 1
        or totals["runtime_receipt_count"] < 1
        or aggregate.get("report_count") != totals["report_count"]
        or aggregate.get("source_receipt_count") != totals["source_receipt_count"]
        or aggregate.get("runtime_receipt_count") != totals["runtime_receipt_count"]
        or aggregate.get("scanner_output_observed") is not True
        or aggregate.get("candidate_labels_present") is not False
        or aggregate.get("effectiveness_status_present") is not False
    ):
        raise ValueError(
            "protocol recovery prior execution aggregate is invalid"
        )
    return manifest_path, manifest


def _nonnegative_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"v4 holdout {label} is invalid")
    return value


def _exact_maximum_single_rule_share(rule_counts: dict[str, int]) -> float:
    candidate_count = sum(rule_counts.values())
    return max(rule_counts.values()) / candidate_count if candidate_count and rule_counts else 0.0


def _preflight_projection(
    rows: list[Any],
    *,
    label: str,
) -> tuple[list[str], dict[str, dict[str, Any]], dict[str, Any]]:
    repository_ids: list[str] = []
    by_repository: dict[str, dict[str, Any]] = {}
    rule_counts: Counter[str] = Counter()
    apps_with_candidates = 0
    strata_with_candidates: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"v4 holdout {label} row is invalid")
        repository_id = str(row.get("repository_id") or "")
        if normalize_github_repository(repository_id) != repository_id:
            raise ValueError(f"v4 holdout {label} repository is invalid")
        if repository_id in by_repository:
            raise ValueError(f"v4 holdout {label} repositories must be unique")
        estimated_rule_counts = row.get("estimated_rule_counts")
        if not isinstance(estimated_rule_counts, dict):
            raise ValueError(f"v4 holdout {label} rule counts are invalid")
        normalized_rule_counts: dict[str, int] = {}
        for rule_id, count_value in estimated_rule_counts.items():
            rule_name = str(rule_id or "")
            if not rule_name:
                raise ValueError(f"v4 holdout {label} rule id is invalid")
            count = _nonnegative_integer(
                count_value,
                label=f"{label} rule count",
            )
            if count:
                normalized_rule_counts[rule_name] = count
                rule_counts[rule_name] += count
        estimated_count = _nonnegative_integer(
            row.get("estimated_candidate_count"),
            label=f"{label} candidate count",
        )
        if estimated_count != sum(normalized_rule_counts.values()):
            raise ValueError(f"v4 holdout {label} candidate projection is inconsistent")
        if estimated_count:
            apps_with_candidates += 1
            stratum = str(row.get("stratum") or "")
            if not stratum:
                raise ValueError(f"v4 holdout {label} candidate stratum is invalid")
            strata_with_candidates.add(stratum)
        repository_ids.append(repository_id)
        by_repository[repository_id] = row

    candidate_count = sum(rule_counts.values())
    maximum_share = round(_exact_maximum_single_rule_share(rule_counts), 6)
    return repository_ids, by_repository, {
        "estimated_apps_with_candidates": apps_with_candidates,
        "estimated_candidate_count": candidate_count,
        "estimated_distinct_rule_count": len(rule_counts),
        "estimated_maximum_single_rule_share": maximum_share,
        "estimated_rule_counts": dict(sorted(rule_counts.items())),
        "estimated_strata_with_candidates": sorted(strata_with_candidates),
    }


def _validate_v4_selection_contract(
    payload: dict[str, Any],
    preregistration_root: Path,
    repository_ids: list[str],
) -> dict[str, Any]:
    selection = payload.get("selection")
    if not isinstance(selection, dict):
        raise ValueError("v4 holdout selection contract is missing")
    discovery_name = str(selection.get("discovery_population_artifact") or "")
    qualification_name = str(selection.get("qualification_population_artifact") or "")
    if (
        not discovery_name
        or not qualification_name
        or discovery_name == qualification_name
        or selection.get("estimated_population_artifact") != qualification_name
        or selection.get("qualification_thresholds_apply_only_to") != qualification_name
        or selection.get("discovery_pool_has_no_qualification_authority") is not True
    ):
        raise ValueError("v4 holdout selection population roles are invalid")

    discovery_path, discovery = _load_bound_json_artifact(
        preregistration_root,
        discovery_name,
        selection.get("discovery_population_sha256"),
        label="discovery population",
    )
    qualification_path, qualification = _load_bound_json_artifact(
        preregistration_root,
        qualification_name,
        selection.get("qualification_population_sha256"),
        label="qualification population",
    )

    if (
        discovery.get("schema") != DISCOVERY_POOL_SCHEMA
        or discovery.get("population_role") != DISCOVERY_POOL_ROLE
        or discovery.get("qualification_authority") is not False
        or discovery.get("qualification_thresholds_apply") is not False
        or discovery.get("qualification_population_artifact") != qualification_name
        or discovery.get("raw_returned") is not False
    ):
        raise ValueError("v4 holdout discovery population authority is invalid")
    discovery_independence = discovery.get("independence")
    if not isinstance(discovery_independence, dict) or any(
        discovery_independence.get(key) is not expected
        for key, expected in {
            "k_guard_executed": False,
            "k_guard_imported": False,
            "not_a_k_guard_result": True,
            "scanner_output_observed": False,
        }.items()
    ):
        raise ValueError("v4 holdout discovery population independence is invalid")
    discovery_rows = discovery.get("apps")
    if not isinstance(discovery_rows, list) or not discovery_rows:
        raise ValueError("v4 holdout discovery population is empty")
    discovery_ids, discovery_by_repository, discovery_projection = _preflight_projection(
        discovery_rows,
        label="discovery population",
    )
    if discovery_ids != sorted(discovery_ids):
        raise ValueError("v4 holdout discovery population must be sorted")
    discovery_summary = {
        "candidate_repository_count": len(discovery_ids),
        **{
            key: discovery_projection[key]
            for key in (
                "estimated_apps_with_candidates",
                "estimated_candidate_count",
                "estimated_distinct_rule_count",
                "estimated_maximum_single_rule_share",
                "estimated_rule_counts",
            )
        },
    }
    if any(discovery.get(key) != value for key, value in discovery_summary.items()):
        raise ValueError("v4 holdout discovery population projection is inconsistent")

    if (
        qualification.get("schema") != QUALIFICATION_POPULATION_SCHEMA
        or qualification.get("population_role") != QUALIFICATION_POPULATION_ROLE
        or qualification.get("qualification_authority") is not True
        or qualification.get("qualification_thresholds_apply") is not True
        or qualification.get("discovery_population_artifact") != discovery_name
        or qualification.get("raw_returned") is not False
    ):
        raise ValueError("v4 holdout qualification population authority is invalid")
    qualification_independence = qualification.get("independence")
    if not isinstance(qualification_independence, dict) or any(
        qualification_independence.get(key) is not expected
        for key, expected in {
            "k_guard_executed": False,
            "k_guard_imported": False,
            "not_a_k_guard_result": True,
            "scanner_output_observed": False,
            "selection_locked_before_scanner_execution": True,
        }.items()
    ):
        raise ValueError("v4 holdout qualification population independence is invalid")
    bindings = qualification.get("bindings")
    if (
        not isinstance(bindings, dict)
        or bindings.get("structural_preflight_sha256") != sha256_file(discovery_path)
    ):
        raise ValueError("v4 holdout qualification discovery binding is invalid")

    qualification_apps = qualification.get("apps")
    if not isinstance(qualification_apps, list) or not qualification_apps:
        raise ValueError("v4 holdout qualification population is empty")
    qualification_ids = [
        str(row.get("repository_id") or "") if isinstance(row, dict) else ""
        for row in qualification_apps
    ]
    if qualification_ids != repository_ids:
        raise ValueError("v4 holdout qualification population does not match preregistration")
    if (
        qualification.get("repository_count") != len(repository_ids)
        or qualification.get("repository_set_sha256") != repository_set_sha256(repository_ids)
    ):
        raise ValueError("v4 holdout qualification repository binding is invalid")

    preregistration_apps = payload.get("apps")
    assert isinstance(preregistration_apps, list)
    for selected_app, registered_app in zip(qualification_apps, preregistration_apps, strict=True):
        if not isinstance(selected_app, dict) or not isinstance(registered_app, dict):
            raise ValueError("v4 holdout qualification app row is invalid")
        for key in ("app", "local_dir", "stratum", "repository_id", "commit"):
            if selected_app.get(key) != registered_app.get(key):
                raise ValueError(f"v4 holdout qualification app binding is invalid: {key}")
        if normalize_github_repository(str(selected_app.get("repository") or "")) != normalize_github_repository(
            str(registered_app.get("repository") or "")
        ):
            raise ValueError("v4 holdout qualification repository URL binding is invalid")

    selected_preflight_rows: list[dict[str, Any]] = []
    for index, repository_id in enumerate(qualification_ids):
        row = discovery_by_repository.get(repository_id)
        if row is None:
            raise ValueError("v4 holdout qualification population is outside discovery pool")
        selected_app = qualification_apps[index]
        assert isinstance(selected_app, dict)
        if row.get("stratum") != selected_app.get("stratum"):
            raise ValueError("v4 holdout qualification stratum projection is inconsistent")
        selected_preflight_rows.append(row)
    _, _, qualification_projection = _preflight_projection(
        selected_preflight_rows,
        label="qualification population",
    )
    expected_population = qualification.get("preflight_only_expected_population")
    if (
        not isinstance(expected_population, dict)
        or expected_population.get("not_a_k_guard_result") is not True
        or any(
            expected_population.get(key) != value
            for key, value in qualification_projection.items()
        )
    ):
        raise ValueError("v4 holdout qualification population projection is inconsistent")

    thresholds = payload.get("locked_thresholds")
    assert isinstance(thresholds, dict)
    minimum_app_count = _nonnegative_integer(
        thresholds.get("minimum_app_count"),
        label="minimum app count",
    )
    if len(repository_ids) < minimum_app_count:
        raise ValueError("v4 holdout qualification population is below minimum_app_count")
    threshold_checks = (
        ("minimum_blocker_candidates", "estimated_candidate_count"),
        ("minimum_apps_with_blocker_candidates", "estimated_apps_with_candidates"),
        ("minimum_distinct_blocker_rule_ids", "estimated_distinct_rule_count"),
        ("minimum_strata_with_blocker_candidates", "estimated_strata_with_candidates"),
    )
    for threshold_key, projection_key in threshold_checks:
        minimum = _nonnegative_integer(thresholds.get(threshold_key), label=threshold_key)
        actual_value = qualification_projection[projection_key]
        actual = len(actual_value) if isinstance(actual_value, list) else actual_value
        if actual < minimum:
            raise ValueError(
                f"v4 holdout qualification population cannot satisfy {threshold_key}"
            )
    maximum_share = thresholds.get("maximum_single_rule_candidate_share")
    if (
        not isinstance(maximum_share, (int, float))
        or isinstance(maximum_share, bool)
        or _exact_maximum_single_rule_share(
            qualification_projection["estimated_rule_counts"]
        )
        > maximum_share
    ):
        raise ValueError(
            "v4 holdout qualification population exceeds maximum_single_rule_candidate_share"
        )

    return {
        "discovery_path": discovery_path,
        "qualification_path": qualification_path,
        "discovery": discovery,
        "qualification": qualification,
        "qualification_projection": qualification_projection,
    }


def _validate_preexecution_structural_replacement(
    payload: dict[str, Any],
    preregistration_root: Path,
    selection_contract: dict[str, Any],
) -> None:
    migration = payload.get("registration_migration")
    if (
        not isinstance(migration, dict)
        or migration.get("schema") != STRUCTURAL_REPLACEMENT_MIGRATION_SCHEMA
    ):
        return
    required_flags = {
        "scanner_execution_before_migration": False,
        "scanner_output_seen_before_migration": False,
        "source_selection_changed": True,
        "repository_set_changed": True,
        "stratum_counts_changed": False,
        "locked_thresholds_changed": False,
        "locked_review_changed": False,
        "raw_returned": False,
    }
    if any(migration.get(key) is not expected for key, expected in required_flags.items()):
        raise ValueError("v4 holdout structural replacement flags are invalid")
    if (
        migration.get("replacement_policy") != STRUCTURAL_REPLACEMENT_POLICY
        or any(
            migration.get(key) != 0
            for key in (
                "superseded_report_count",
                "superseded_runtime_receipt_count",
                "superseded_source_receipt_count",
            )
        )
        or REVISION_RE.fullmatch(
            str(migration.get("new_evidence_contract_revision") or "")
        )
        is None
    ):
        raise ValueError("v4 holdout structural replacement boundary is invalid")

    _, previous = _load_sibling_bound_json_artifact(
        preregistration_root,
        migration.get("superseded_preregistration_path"),
        migration.get("superseded_preregistration_sha256"),
        label="superseded preregistration",
    )
    _, previous_selected = _load_sibling_bound_json_artifact(
        preregistration_root,
        migration.get("superseded_selected_corpus_path"),
        migration.get("superseded_selected_corpus_sha256"),
        label="superseded qualification population",
    )
    candidate_path, candidate_pool = _load_bound_json_artifact(
        preregistration_root,
        migration.get("candidate_pool_artifact"),
        migration.get("candidate_pool_sha256"),
        label="structural replacement candidate pool",
    )
    if (
        migration.get("structural_preflight_artifact")
        != selection_contract["discovery_path"].name
        or migration.get("structural_preflight_sha256")
        != sha256_file(selection_contract["discovery_path"])
        or migration.get("supersedes_campaign_id") != previous.get("campaign_id")
    ):
        raise ValueError("v4 holdout structural replacement provenance is invalid")
    immutable_fields = (
        "locked_thresholds",
        "locked_review",
        "locked_execution",
        "label_contract",
        "claim_boundary",
        "qualification_contract",
    )
    if any(payload.get(field) != previous.get(field) for field in immutable_fields):
        raise ValueError("v4 holdout structural replacement changed a locked contract")

    previous_apps = previous.get("apps")
    current_apps = payload.get("apps")
    previous_selected_apps = previous_selected.get("apps")
    qualification = selection_contract["qualification"]
    if (
        not isinstance(previous_apps, list)
        or not isinstance(current_apps, list)
        or not isinstance(previous_selected_apps, list)
        or previous_selected.get("schema") != QUALIFICATION_POPULATION_SCHEMA
        or qualification.get("selection_migration") != migration
        or qualification.get("bindings", {}).get("candidate_pool_sha256")
        != sha256_file(candidate_path)
    ):
        raise ValueError("v4 holdout structural replacement population binding is invalid")

    previous_by_repository = {
        str(row.get("repository_id") or ""): row
        for row in previous_apps
        if isinstance(row, dict)
    }
    current_by_repository = {
        str(row.get("repository_id") or ""): row
        for row in current_apps
        if isinstance(row, dict)
    }
    previous_selected_by_repository = {
        str(row.get("repository_id") or ""): row
        for row in previous_selected_apps
        if isinstance(row, dict)
    }
    if (
        len(previous_by_repository) != len(previous_apps)
        or len(current_by_repository) != len(current_apps)
        or set(previous_selected_by_repository) != set(previous_by_repository)
    ):
        raise ValueError("v4 holdout structural replacement repositories are invalid")
    removed_ids = set(previous_by_repository) - set(current_by_repository)
    added_ids = set(current_by_repository) - set(previous_by_repository)
    if (
        not removed_ids
        or len(removed_ids) != len(added_ids)
        or len(current_by_repository) != len(previous_by_repository)
    ):
        raise ValueError("v4 holdout structural replacement set difference is invalid")

    if (
        candidate_pool.get("schema") != "k_guard_independent_candidate_pool.v1"
        or candidate_pool.get("generated_without_k_guard") is not True
        or candidate_pool.get("raw_returned") is not False
    ):
        raise ValueError("v4 holdout structural replacement candidate pool is invalid")
    candidate_boundary = candidate_pool.get("selection_boundary")
    if not isinstance(candidate_boundary, dict) or any(
        candidate_boundary.get(key) is not expected
        for key, expected in {
            "scanner_output_observed": False,
            "k_guard_imported": False,
            "k_guard_executed": False,
        }.items()
    ):
        raise ValueError("v4 holdout structural replacement candidate boundary is invalid")
    candidate_rows = candidate_pool.get("candidates")
    if not isinstance(candidate_rows, list) or not candidate_rows:
        raise ValueError("v4 holdout structural replacement candidate pool is empty")
    candidate_ids = [
        str(row.get("repository_id") or "") if isinstance(row, dict) else ""
        for row in candidate_rows
    ]
    if (
        len(candidate_ids) != len(set(candidate_ids))
        or candidate_pool.get("candidate_count") != len(candidate_rows)
    ):
        raise ValueError("v4 holdout structural replacement candidate order is invalid")
    candidate_by_repository = {
        str(row["repository_id"]): row
        for row in candidate_rows
        if isinstance(row, dict)
    }

    replacements = migration.get("replacements")
    if (
        not isinstance(replacements, list)
        or migration.get("replacement_count") != len(replacements)
        or len(replacements) != len(removed_ids)
    ):
        raise ValueError("v4 holdout structural replacement rows are invalid")
    mapped_removed: set[str] = set()
    mapped_added: set[str] = set()
    replacements_by_stratum: dict[str, list[dict[str, Any]]] = {}
    for replacement in replacements:
        if not isinstance(replacement, dict):
            raise ValueError("v4 holdout structural replacement row is invalid")
        removed_id = str(replacement.get("removed_repository_id") or "")
        added_id = str(replacement.get("added_repository_id") or "")
        if (
            removed_id not in removed_ids
            or added_id not in added_ids
            or removed_id in mapped_removed
            or added_id in mapped_added
            or added_id not in candidate_by_repository
        ):
            raise ValueError("v4 holdout structural replacement mapping is invalid")
        removed_app = previous_by_repository[removed_id]
        added_app = current_by_repository[added_id]
        candidate = candidate_by_repository[added_id]
        stratum = str(replacement.get("stratum") or "")
        if (
            removed_app.get("stratum") != stratum
            or added_app.get("stratum") != stratum
            or candidate.get("stratum") != stratum
            or replacement.get("removed_commit") != removed_app.get("commit")
            or replacement.get("removed_commit_tree") != removed_app.get("commit_tree")
            or replacement.get("added_commit") != added_app.get("commit")
            or replacement.get("added_commit") != candidate.get("commit")
            or added_app.get("selection_reason")
            != STRUCTURAL_REPLACEMENT_SELECTION_REASON
            or added_app.get("local_dir") != candidate.get("local_dir")
            or _star_stratum(added_app.get("stars_at_registration")) != stratum
            or _star_stratum(candidate.get("stars")) != stratum
            or normalize_github_repository(str(added_app.get("repository") or ""))
            != added_id
        ):
            raise ValueError("v4 holdout structural replacement source binding is invalid")
        unsupported_entries = replacement.get("unsupported_git_entries")
        if not isinstance(unsupported_entries, list) or not unsupported_entries:
            raise ValueError("v4 holdout structural replacement Git evidence is missing")
        for entry in unsupported_entries:
            if (
                not isinstance(entry, dict)
                or entry.get("mode") not in UNSUPPORTED_GIT_TREE_MODES
                or entry.get("subtype") not in {"symlink", "submodule"}
                or not str(entry.get("path") or "")
            ):
                raise ValueError("v4 holdout structural replacement Git evidence is invalid")
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
        ):
            raise ValueError("v4 holdout structural replacement screening is invalid")
        mapped_removed.add(removed_id)
        mapped_added.add(added_id)
        replacements_by_stratum.setdefault(stratum, []).append(replacement)

    if mapped_removed != removed_ids or mapped_added != added_ids:
        raise ValueError("v4 holdout structural replacement mapping is incomplete")
    previous_ids = set(previous_by_repository)
    for stratum, rows in replacements_by_stratum.items():
        expected = [
            repository_id
            for repository_id, candidate in zip(
                candidate_ids,
                candidate_rows,
                strict=True,
            )
            if isinstance(candidate, dict)
            and candidate.get("stratum") == stratum
            and repository_id not in previous_ids
        ][: len(rows)]
        actual = [
            str(row["added_repository_id"])
            for row in sorted(
                rows,
                key=lambda row: str(row["removed_repository_id"]),
            )
        ]
        if actual != expected:
            raise ValueError("v4 holdout structural replacement skipped a reserve candidate")
    if qualification.get("exclusions", {}).get(
        "unsupported_git_tree_entry_screening"
    ) != sorted(removed_ids):
        raise ValueError("v4 holdout structural replacement exclusion ledger is invalid")


def validate_v4_preregistration(
    payload: dict[str, Any],
    preregistration_path: Path | None,
) -> dict[str, Any]:
    if preregistration_path is None:
        raise ValueError("v4 holdout validation requires the preregistration path")
    if payload.get("status") not in {
        "locked_before_scanner_execution",
        PROTOCOL_RECOVERY_REPLAY_STATUS,
    }:
        raise ValueError(
            "v4 holdout must be locked before qualification execution or recovery replay"
        )
    preregistration_root = preregistration_path.resolve().parent
    integrity = payload.get("holdout_integrity")
    if not isinstance(integrity, dict):
        raise ValueError("v4 holdout integrity contract is missing")
    required_flags = {
        "source_selection_locked_before_scanner_execution": True,
        "scanner_output_seen_during_selection": False,
        "k_guard_imported_by_preflight": False,
        "development_or_prior_campaign_overlap_allowed": False,
    }
    for key, expected in required_flags.items():
        if integrity.get(key) is not expected:
            raise ValueError(f"v4 holdout integrity flag is invalid: {key}")
    if integrity.get("repository_overlap_count") != 0:
        raise ValueError("v4 holdout repository overlap must be zero")
    locked_review = payload.get("locked_review")
    if (
        not isinstance(locked_review, dict)
        or locked_review.get("required_reviewer_count") != 3
        or locked_review.get("required_vendors") != V4_REVIEW_VENDORS
        or locked_review.get("independent_sessions") is not True
        or locked_review.get("individual_inconclusive_allowed") is not False
        or locked_review.get("review_method") != "external_ai_source_context_review"
    ):
        raise ValueError("v4 holdout cross-vendor review contract is invalid")
    thresholds = payload.get("locked_thresholds") if isinstance(payload.get("locked_thresholds"), dict) else {}
    if (
        float(thresholds.get("minimum_reviewer_unanimous_rate") or 0) < 0.9
        or thresholds.get("maximum_inconclusive_rate") != 0.0
        or thresholds.get("maximum_individual_inconclusive_rate") != 0.0
    ):
        raise ValueError("v4 holdout reviewer thresholds are too weak")
    claim_boundary = payload.get("claim_boundary")
    if not isinstance(claim_boundary, dict) or any(
        claim_boundary.get(key) is not expected
        for key, expected in V4_REQUIRED_CLAIM_BOUNDARY.items()
    ):
        raise ValueError("v4 holdout claim boundary is invalid")
    replay_contract = _validate_protocol_recovery_replay(
        payload,
        preregistration_root,
    )

    relative = Path(str(integrity.get("exclusion_snapshot_path") or ""))
    if not relative.name or relative.is_absolute() or ".." in relative.parts:
        raise ValueError("v4 holdout exclusion snapshot path is invalid")
    current = preregistration_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("v4 holdout exclusion snapshot path contains a symlink")
    snapshot_path = (preregistration_root / relative).resolve()
    if (
        not snapshot_path.is_relative_to(preregistration_root)
        or not snapshot_path.is_file()
        or snapshot_path.is_symlink()
    ):
        raise ValueError("v4 holdout exclusion snapshot is missing")
    expected_hash = str(integrity.get("exclusion_snapshot_sha256") or "")
    if SHA256_RE.fullmatch(expected_hash) is None or sha256_file(snapshot_path) != expected_hash:
        raise ValueError("v4 holdout exclusion snapshot hash is invalid")
    snapshot = load_exclusion_snapshot(snapshot_path)
    if integrity.get("prior_evidence_source_revision") != snapshot.get("source_revision"):
        raise ValueError("v4 holdout prior evidence revision binding is invalid")

    apps = payload.get("apps") if isinstance(payload.get("apps"), list) else []
    repository_ids: list[str] = []
    for app in apps:
        if not isinstance(app, dict):
            raise ValueError("v4 holdout app row is invalid")
        repository_id = normalize_github_repository(str(app.get("repository") or ""))
        if repository_id is None or app.get("repository_id") != repository_id:
            raise ValueError("v4 holdout repository identity binding is invalid")
        if app.get("is_fork") is not False or app.get("archived") is not False:
            raise ValueError(f"v4 holdout source must be active and non-fork: {repository_id}")
        repository_ids.append(repository_id)
    if len(repository_ids) != len(set(repository_ids)):
        raise ValueError("v4 holdout repositories must be unique")
    excluded = {str(row["repository_id"]) for row in snapshot["repositories"]}
    overlap = sorted(set(repository_ids) & excluded)
    if overlap:
        raise ValueError("v4 holdout overlaps prior evidence: " + ",".join(overlap))
    if integrity.get("repository_count") != len(repository_ids):
        raise ValueError("v4 holdout repository count binding is invalid")
    if integrity.get("repository_set_sha256") != repository_set_sha256(repository_ids):
        raise ValueError("v4 holdout repository set hash is invalid")
    selection_contract = _validate_v4_selection_contract(
        payload,
        preregistration_root,
        repository_ids,
    )
    _validate_preexecution_structural_replacement(
        payload,
        preregistration_root,
        selection_contract,
    )
    result = {
        "repository_ids": repository_ids,
        "snapshot": snapshot,
        "snapshot_path": snapshot_path,
        **selection_contract,
    }
    if replay_contract is not None:
        result.update(
            {
                "replay_manifest_path": replay_contract[0],
                "replay_manifest": replay_contract[1],
                "qualification_boundary": (
                    protocol_recovery_qualification_boundary(payload)
                ),
            }
        )
    return result
