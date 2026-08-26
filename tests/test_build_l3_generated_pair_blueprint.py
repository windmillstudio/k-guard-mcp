from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import (
    GENERATOR_PROFILES,
    REPOSITORY_ROOT,
    REQUIRED_COVERAGE_TAGS,
    build_blueprint,
    load_blueprint,
    validate_blueprint,
    write_blueprint,
)


def test_blueprint_is_deterministic_and_balanced() -> None:
    first = build_blueprint()
    second = build_blueprint()

    assert first == second
    assert first["slot_count"] == 60
    assert first["plane_counts"] == {"site": 15, "api": 15, "data": 15, "operations": 15}
    assert {slot["plane"] for slot in first["slots"]} == {"site", "api", "data", "operations"}
    assert {tag for slot in first["slots"] for tag in slot["coverage_tags"]} == REQUIRED_COVERAGE_TAGS
    assert {slot["generator_profile"] for slot in first["slots"]} == set(GENERATOR_PROFILES)
    assert sum(slot["severity"] == "critical" for slot in first["slots"]) == 16
    assert validate_blueprint(first) == first


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value["slots"].pop(), "blueprint_hash_mismatch"),
        (lambda value: value["slots"][0].update(scanner_output_absent_at_seal=False), "blueprint_hash_mismatch"),
        (lambda value: value["slots"][0].update(slot_id="site-16"), "blueprint_hash_mismatch"),
        (lambda value: value["slots"][0].update(generator_profile="external-live-model"), "blueprint_hash_mismatch"),
        (lambda value: value["claim_boundary"].update(release_gate_passed=True), "blueprint_hash_mismatch"),
    ],
)
def test_blueprint_fails_closed_on_tamper(mutate, message: str) -> None:
    blueprint = copy.deepcopy(build_blueprint())
    mutate(blueprint)

    with pytest.raises(ValueError, match=message):
        validate_blueprint(blueprint)


def test_blueprint_rejects_hash_valid_quota_drift() -> None:
    blueprint = copy.deepcopy(build_blueprint())
    blueprint["slots"][0]["severity"] = "critical"
    unsigned = dict(blueprint)
    unsigned.pop("blueprint_sha256")
    from scripts.build_l3_generated_pair_blueprint import _domain_hash

    blueprint["blueprint_sha256"] = _domain_hash(b"k_guard_l3_generated_pair_blueprint.v1\0", unsigned)

    with pytest.raises(ValueError, match="blueprint_critical_quota_drift"):
        validate_blueprint(blueprint)


def test_write_load_and_overwrite_refusal(tmp_path) -> None:
    output = tmp_path / "evidence" / "blueprint.json"
    expected = write_blueprint(output)

    assert load_blueprint(output) == expected
    with pytest.raises(ValueError, match="refusing_to_overwrite_blueprint"):
        write_blueprint(output)


def test_write_refuses_repository_output() -> None:
    with pytest.raises(ValueError, match="blueprint_output_must_be_external"):
        write_blueprint(REPOSITORY_ROOT / "blueprint.json")
