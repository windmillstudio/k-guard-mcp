from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from k_guard_mcp.public_lineage import canonical_json_bytes
from scripts.verify_l4_selection_pair import (
    PAIR_SCHEMA,
    verify_selection_pair,
)


LIVE_REPLAY_CONFIG_ENV = "K_GUARD_L4_LIVE_REPLAY_CONFIG"
LIVE_REPLAY_CONFIG_SCHEMA = "k_guard_l4_live_replay_config.v1"
_CONFIG_FIELDS = {
    "schema",
    "expected_git_commit",
    "expected_pair_sha256",
    "first",
    "second",
    "candidate_pool",
    "artifact_root",
    "source_receipts",
    "source_checkouts",
    "capture_root",
    "existing_41",
    "prior_evidence_105",
    "source_verifier",
    "expected_verification",
}
_BINDING_FIELDS = {
    "candidate_manifest_sha256",
    "source_verifier_sha256",
    "github_metadata_query_sha256",
    "capture_manifest_sha256",
    "capture_implementation_sha256",
    "candidate_materializer_sha256",
    "selection_implementation_sha256",
    "selection_cli_sha256",
}


def _configured_path(config: dict[str, object], field: str) -> Path:
    value = config.get(field)
    assert isinstance(value, str) and value
    return Path(value)


@pytest.mark.skipif(
    not os.environ.get(LIVE_REPLAY_CONFIG_ENV),
    reason=f"set {LIVE_REPLAY_CONFIG_ENV} for the release-only live replay",
)
def test_unstubbed_live_l4_replay_matches_bound_pair() -> None:
    config_path = Path(os.environ[LIVE_REPLAY_CONFIG_ENV])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert isinstance(config, dict)
    assert set(config) == _CONFIG_FIELDS
    assert config["schema"] == LIVE_REPLAY_CONFIG_SCHEMA

    repository_root = Path(__file__).resolve().parents[1]
    head = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert head == config["expected_git_commit"]

    expected_path = _configured_path(config, "expected_verification")
    expected_raw = expected_path.read_bytes()
    assert hashlib.sha256(expected_raw).hexdigest() == config[
        "expected_pair_sha256"
    ]
    expected = json.loads(expected_raw.decode("utf-8"))
    assert expected_raw == canonical_json_bytes(expected)
    assert expected["schema"] == PAIR_SCHEMA
    assert expected["evidence_gate"] == "PASS"
    bindings = expected["bindings"]
    assert isinstance(bindings, dict)
    assert set(bindings) == _BINDING_FIELDS

    actual = verify_selection_pair(
        first=_configured_path(config, "first"),
        second=_configured_path(config, "second"),
        candidate_pool=_configured_path(config, "candidate_pool"),
        artifact_root=_configured_path(config, "artifact_root"),
        source_receipts=_configured_path(config, "source_receipts"),
        source_checkouts=_configured_path(config, "source_checkouts"),
        capture_root=_configured_path(config, "capture_root"),
        existing_41=_configured_path(config, "existing_41"),
        prior_evidence_105=_configured_path(config, "prior_evidence_105"),
        source_verifier=_configured_path(config, "source_verifier"),
        expected_seed_sha256=expected["seed_sha256"],
        expected_candidate_manifest_sha256=bindings[
            "candidate_manifest_sha256"
        ],
        expected_source_verifier_sha256=bindings["source_verifier_sha256"],
        expected_github_query_sha256=bindings[
            "github_metadata_query_sha256"
        ],
        expected_capture_manifest_sha256=bindings[
            "capture_manifest_sha256"
        ],
        expected_capture_implementation_sha256=bindings[
            "capture_implementation_sha256"
        ],
        expected_candidate_materializer_sha256=bindings[
            "candidate_materializer_sha256"
        ],
        expected_selection_implementation_sha256=bindings[
            "selection_implementation_sha256"
        ],
        expected_selection_cli_sha256=bindings["selection_cli_sha256"],
        verification_implementation_sha256=expected[
            "verification_implementation_sha256"
        ],
    )

    assert canonical_json_bytes(actual) == expected_raw
    assert actual["materialization_rejection_source_recompute_count"] == actual[
        "materialization_rejection_count"
    ]
    assert actual["candidate_pool_recomputed"] is True
    assert actual["physical_source_recomputed"] is True
