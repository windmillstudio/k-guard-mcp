from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve(strict=True).parents[1]
SOURCE_ROOT = ROOT / "src"
SCRIPTS_ROOT = ROOT / "scripts"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from evidence_tree import package_tree_sha256
from k_guard_mcp.release_policy import (
    RELEASE_BLOCKING_POLICY,
    automatic_release_rules_for_policy,
)


SOURCE_SCHEMA = "k_guard_public_field_preregistration.v1"
DEVELOPMENT_REPLAY_CONTRACT = "development_policy_replay_v1"
ALLOWED_SOURCE_STATUSES = frozenset(
    {
        "locked_before_scanner_execution",
        "locked_before_remediation_replay",
    }
)
SHA256_HEX_LENGTH = 64


class DerivationError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.resolve(strict=True).read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.resolve(strict=True).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DerivationError("source_preregistration_unreadable") from exc
    if not isinstance(value, dict):
        raise DerivationError("source_preregistration_not_object")
    return value


def _git_head(repository_root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_root.resolve(strict=True),
        check=False,
        capture_output=True,
        text=True,
    )
    head = result.stdout.strip()
    if result.returncode != 0 or len(head) != 40:
        raise DerivationError("current_repository_head_unavailable")
    return head


def current_analyzer_binding(repository_root: Path) -> dict[str, str]:
    root = repository_root.resolve(strict=True)
    return {
        "head_git_oid": _git_head(root),
        "analyzer_package_tree_sha256": package_tree_sha256(root / "src" / "k_guard_mcp"),
        "release_blocking_policy": RELEASE_BLOCKING_POLICY,
    }


def validate_source_preregistration(payload: dict[str, Any]) -> None:
    if payload.get("schema") != SOURCE_SCHEMA:
        raise DerivationError("source_schema_invalid")
    if payload.get("status") not in ALLOWED_SOURCE_STATUSES:
        raise DerivationError("source_status_not_locked")
    if payload.get("raw_returned") is not False:
        raise DerivationError("source_raw_boundary_invalid")
    apps = payload.get("apps")
    if not isinstance(apps, list) or len(apps) < 12:
        raise DerivationError("source_app_population_invalid")
    identities: set[tuple[str, str, str]] = set()
    for app in apps:
        if not isinstance(app, dict):
            raise DerivationError("source_app_invalid")
        identity = (
            str(app.get("app") or ""),
            str(app.get("repository") or ""),
            str(app.get("commit") or ""),
        )
        if not all(identity) or len(identity[2]) != 40 or identity in identities:
            raise DerivationError("source_app_identity_invalid")
        identities.add(identity)


def derive_payload(
    source: dict[str, Any],
    *,
    source_preregistration_sha256: str,
    campaign_id: str,
    registered_date: str,
    binding: dict[str, str],
) -> dict[str, Any]:
    validate_source_preregistration(source)
    if (
        not campaign_id
        or not registered_date
        or len(source_preregistration_sha256) != SHA256_HEX_LENGTH
        or automatic_release_rules_for_policy(binding.get("release_blocking_policy", "")) is None
        or len(binding.get("head_git_oid", "")) != 40
        or len(binding.get("analyzer_package_tree_sha256", "")) != SHA256_HEX_LENGTH
    ):
        raise DerivationError("derivation_input_invalid")

    derived = copy.deepcopy(source)
    source_campaign_id = str(source.get("campaign_id") or "")
    source_execution = source.get("locked_execution")
    if not isinstance(source_execution, dict):
        raise DerivationError("source_execution_contract_invalid")
    timeout = source_execution.get("per_scan_timeout_seconds")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise DerivationError("source_timeout_invalid")

    selection = copy.deepcopy(source.get("selection"))
    if not isinstance(selection, dict):
        raise DerivationError("source_selection_invalid")
    selection["development_replay"] = {
        "source_campaign_id": source_campaign_id,
        "source_preregistration_sha256": source_preregistration_sha256,
        "source_corpus_already_observed": True,
        "source_commits_preserved": True,
        "current_policy_rebound_explicitly": True,
        "not_a_disjoint_holdout": True,
        "raw_returned": False,
    }

    execution = copy.deepcopy(source_execution)
    execution.update(
        {
            "candidate_selection_mode": "all_eligible_release_blockers",
            "exact_fresh_process_runs_per_app": 2,
            "retry_count": 0,
            "release_blocking_policy": binding["release_blocking_policy"],
            "per_scan_timeout_seconds": timeout,
        }
    )

    derived.update(
        {
            "campaign_id": campaign_id,
            "status": "locked_before_remediation_replay",
            "registered_date": registered_date,
            "qualification_contract": DEVELOPMENT_REPLAY_CONTRACT,
            "source_revision_before_registration_commit": binding["head_git_oid"],
            "analyzer_package_tree_sha256": binding["analyzer_package_tree_sha256"],
            "selection": selection,
            "locked_execution": execution,
            "claim_boundary": {
                "development_replay_only": True,
                "source_corpus_already_observed": True,
                "disjoint_preregistered_holdout": False,
                "may_qualify_release": False,
                "may_change_locked_release_thresholds": False,
                "may_replace_final_h100": False,
                "raw_returned": False,
            },
            "derivation": {
                "schema": "k_guard_development_policy_replay_derivation.v1",
                "source_preregistration_sha256": source_preregistration_sha256,
                "source_campaign_id": source_campaign_id,
                "current_repository_head_git_oid": binding["head_git_oid"],
                "current_release_blocking_policy": binding["release_blocking_policy"],
                "raw_returned": False,
            },
            "raw_returned": False,
        }
    )
    validate_derived_payload(
        derived,
        source=source,
        source_preregistration_sha256=source_preregistration_sha256,
        binding=binding,
    )
    return derived


def validate_derived_payload(
    payload: dict[str, Any],
    *,
    source: dict[str, Any],
    source_preregistration_sha256: str,
    binding: dict[str, str],
) -> None:
    if (
        payload.get("schema") != SOURCE_SCHEMA
        or payload.get("qualification_contract") != DEVELOPMENT_REPLAY_CONTRACT
        or payload.get("status") != "locked_before_remediation_replay"
        or payload.get("raw_returned") is not False
    ):
        raise DerivationError("derived_contract_invalid")
    if payload.get("apps") != source.get("apps"):
        raise DerivationError("derived_corpus_changed")
    if payload.get("locked_thresholds") != source.get("locked_thresholds"):
        raise DerivationError("derived_thresholds_changed")
    if payload.get("analyzer_package_tree_sha256") != binding["analyzer_package_tree_sha256"]:
        raise DerivationError("derived_analyzer_binding_invalid")
    execution = payload.get("locked_execution")
    if not isinstance(execution, dict) or execution.get("release_blocking_policy") != binding[
        "release_blocking_policy"
    ]:
        raise DerivationError("derived_policy_binding_invalid")
    if automatic_release_rules_for_policy(str(execution["release_blocking_policy"])) is None:
        raise DerivationError("derived_policy_unknown")
    boundary = payload.get("claim_boundary")
    derivation = payload.get("derivation")
    selection = payload.get("selection")
    if (
        not isinstance(boundary, dict)
        or boundary.get("development_replay_only") is not True
        or boundary.get("may_qualify_release") is not False
        or not isinstance(derivation, dict)
        or derivation.get("source_preregistration_sha256") != source_preregistration_sha256
        or not isinstance(selection, dict)
        or not isinstance(selection.get("development_replay"), dict)
        or selection["development_replay"].get("source_corpus_already_observed") is not True
    ):
        raise DerivationError("derived_boundary_invalid")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive a nonqualifying current-policy replay registration from an exposed field corpus."
    )
    parser.add_argument("--source-preregistration", type=Path, required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--registered-date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source_path = args.source_preregistration.resolve(strict=True)
    output_path = args.output.resolve()
    if output_path.exists():
        raise SystemExit("output_path_already_exists")
    source = read_json(source_path)
    binding = current_analyzer_binding(ROOT)
    derived = derive_payload(
        source,
        source_preregistration_sha256=sha256_file(source_path),
        campaign_id=args.campaign_id,
        registered_date=args.registered_date,
        binding=binding,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json_bytes(derived))
    print(
        json.dumps(
            {
                "campaign_id": derived["campaign_id"],
                "qualification_contract": derived["qualification_contract"],
                "release_blocking_policy": derived["locked_execution"]["release_blocking_policy"],
                "raw_returned": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
