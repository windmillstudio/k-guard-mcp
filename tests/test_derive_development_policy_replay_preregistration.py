from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "derive_development_policy_replay_preregistration.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("development_policy_replay", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_payload() -> dict:
    apps = [
        {
            "app": f"app-{index}",
            "repository": f"https://github.com/example/app-{index}.git",
            "local_dir": f"app-{index}",
            "commit": f"{index:040x}",
            "stratum": ("top", "mid", "long_tail")[index % 3],
        }
        for index in range(12)
    ]
    return {
        "schema": "k_guard_public_field_preregistration.v1",
        "campaign_id": "legacy-r4",
        "status": "locked_before_remediation_replay",
        "qualification_contract": "release_blocker_actionability_v3",
        "analyzer_package_tree_sha256": "a" * 64,
        "apps": apps,
        "locked_thresholds": {"minimum_app_count": 12},
        "locked_execution": {
            "candidate_selection_mode": "all_eligible_release_blockers",
            "per_scan_timeout_seconds": 60,
            "release_blocking_policy": "k_guard_release_lanes_v3",
        },
        "selection": {"method": "pre-registered"},
        "raw_returned": False,
    }


def _binding() -> dict[str, str]:
    return {
        "head_git_oid": "b" * 40,
        "analyzer_package_tree_sha256": "c" * 64,
        "release_blocking_policy": "k_guard_release_lanes_v6",
    }


def test_derivation_preserves_population_and_thresholds_but_forbids_qualification():
    module = _load_module()
    source = _source_payload()

    derived = module.derive_payload(
        source,
        source_preregistration_sha256="d" * 64,
        campaign_id="current-policy-development-r1",
        registered_date="2026-07-22",
        binding=_binding(),
    )

    assert derived["apps"] == source["apps"]
    assert derived["locked_thresholds"] == source["locked_thresholds"]
    assert derived["qualification_contract"] == module.DEVELOPMENT_REPLAY_CONTRACT
    assert derived["claim_boundary"]["development_replay_only"] is True
    assert derived["claim_boundary"]["may_qualify_release"] is False
    assert derived["locked_execution"]["release_blocking_policy"] == "k_guard_release_lanes_v6"
    assert derived["locked_execution"]["candidate_selection_mode"] == "all_eligible_release_blockers"


def test_derivation_rejects_mutated_population_after_building():
    module = _load_module()
    source = _source_payload()
    derived = module.derive_payload(
        source,
        source_preregistration_sha256="d" * 64,
        campaign_id="current-policy-development-r1",
        registered_date="2026-07-22",
        binding=_binding(),
    )
    derived["apps"][0]["commit"] = "e" * 40

    with pytest.raises(module.DerivationError, match="derived_corpus_changed"):
        module.validate_derived_payload(
            derived,
            source=source,
            source_preregistration_sha256="d" * 64,
            binding=_binding(),
        )


def test_derivation_rejects_unknown_current_policy():
    module = _load_module()

    with pytest.raises(module.DerivationError, match="derivation_input_invalid"):
        module.derive_payload(
            _source_payload(),
            source_preregistration_sha256="d" * 64,
            campaign_id="current-policy-development-r1",
            registered_date="2026-07-22",
            binding={
                **_binding(),
                "release_blocking_policy": "unknown-policy",
            },
        )
