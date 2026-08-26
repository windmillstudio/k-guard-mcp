from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_crapi_vehicle_bola.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_crapi_vehicle_bola_replay", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
crapi = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = crapi
SPEC.loader.exec_module(crapi)


def _driver_result(*, mode: str, expected_status: int) -> dict[str, object]:
    positive = mode == "positive"
    return {
        "schema": crapi.DRIVER_RESULT_SCHEMA,
        "mode": mode,
        "expected_status": expected_status,
        "observed_status": expected_status,
        "token_present": True,
        "actor_target_distinct": True,
        "response_object_observed": positive,
        "target_field_shape_observed": positive,
        "target_location_field_observed": positive,
        "target_full_name_field_observed": positive,
        "target_email_field_observed": positive,
        "target_response_absent": not positive,
        "driver_error_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _isolation() -> dict[str, object]:
    return {"passed": True, "raw_returned": False}


def _cleanup() -> dict[str, object]:
    return {"attempted": True, "removed": True, "raw_returned": False}


def test_negative_controller_patch_is_exactly_once_and_preserves_input() -> None:
    original = crapi.ORIGINAL_CONTROLLER_METHOD
    patched, control = crapi._negative_controller_patch(original)

    assert original == crapi.ORIGINAL_CONTROLLER_METHOD
    assert patched != original
    assert patched.count(crapi.PATCHED_CONTROLLER_METHOD) == 1
    assert control["marker_count"] == 1
    assert control["replacement_count"] == 1
    assert control["source_checkout_mutated"] is False


@pytest.mark.parametrize(
    "controller,error",
    [
        (b"not the controller method", "negative_patch_anchor_ambiguous"),
        (
            crapi.ORIGINAL_CONTROLLER_METHOD + crapi.ORIGINAL_CONTROLLER_METHOD,
            "negative_patch_anchor_ambiguous",
        ),
        (crapi.PATCHED_CONTROLLER_METHOD, "negative_patch_anchor_ambiguous"),
    ],
)
def test_negative_controller_patch_rejects_non_single_source_anchor(
    controller: bytes, error: str
) -> None:
    with pytest.raises(crapi.RuntimeContractError, match=error):
        crapi._negative_controller_patch(controller)


def test_driver_parser_enforces_mode_specific_structural_result() -> None:
    positive = _driver_result(mode="positive", expected_status=200)
    output = (
        b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:"
        + json.dumps(positive, sort_keys=True).encode("utf-8")
        + b"\n"
    )
    assert crapi._parse_driver_result(output, mode="positive", expected_status=200)["passed"] is True

    negative = _driver_result(mode="negative", expected_status=403)
    negative["target_response_absent"] = False
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(negative).encode("utf-8")
    with pytest.raises(crapi.RuntimeContractError, match="driver_negative_observation_invalid"):
        crapi._parse_driver_result(output, mode="negative", expected_status=403)

    generic_error = _driver_result(mode="negative", expected_status=403)
    generic_error["response_object_observed"] = True
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(generic_error).encode("utf-8")
    assert crapi._parse_driver_result(output, mode="negative", expected_status=403)["passed"] is True

    valid_negative = _driver_result(mode="negative", expected_status=403)
    valid_output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(valid_negative).encode("utf-8")
    with pytest.raises(crapi.RuntimeContractError, match="driver_marker_invalid"):
        crapi._parse_driver_result(valid_output + b"\nunexpected\n", mode="negative", expected_status=403)


def test_driver_failure_parser_returns_only_allowlisted_raw_free_code() -> None:
    failed = _driver_result(mode="negative", expected_status=403)
    failed["passed"] = False
    failed["observed_status"] = None
    failed["token_present"] = False
    failed["actor_target_distinct"] = True
    failed["target_response_absent"] = False
    failed["driver_error_code"] = "fixture_login_failed"
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(failed).encode("utf-8")
    assert (
        crapi._parse_driver_failure_code(output, mode="negative", expected_status=403)
        == "fixture_login_failed"
    )

    failed["driver_error_code"] = None
    failed["observed_status"] = 200
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(failed).encode("utf-8")
    assert (
        crapi._parse_driver_failure_code(output, mode="negative", expected_status=403)
        == "unexpected_status_200"
    )

    failed["observed_status"] = 403
    failed["token_present"] = True
    failed["target_response_absent"] = False
    failed["target_field_shape_observed"] = True
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(failed).encode("utf-8")
    assert (
        crapi._parse_driver_failure_code(output, mode="negative", expected_status=403)
        == "unexpected_target_response_shape"
    )

    failed["observed_status"] = None
    failed["target_field_shape_observed"] = False
    failed["target_response_absent"] = True
    failed["target_location_field_observed"] = False
    failed["target_full_name_field_observed"] = False
    failed["target_email_field_observed"] = False
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(failed).encode("utf-8")
    assert (
        crapi._parse_driver_failure_code(output, mode="negative", expected_status=403)
        == "unexpected_outcome"
    )

    failed["driver_error_code"] = "not safe: raw value"
    output = b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" + json.dumps(failed).encode("utf-8")
    with pytest.raises(crapi.RuntimeContractError, match="driver_failure_code_invalid"):
        crapi._parse_driver_failure_code(output, mode="negative", expected_status=403)


def test_driver_script_keeps_fixture_values_out_of_terminal_result_source() -> None:
    raw = crapi.DRIVER_SCRIPT.encode("utf-8")
    assert b"adam007@example.com" not in raw
    assert b"cd515c12-0fc1-48ae-8b61-9230b70a845b" not in raw
    assert b"K_GUARD_CRAPI_VEHICLE_BOLA_RESULT:" in raw


def test_container_isolation_rejects_host_exposure_and_missing_hardening() -> None:
    inspect = {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Tmpfs": dict(crapi.APP_TMPFS),
            "Memory": crapi.APP_MEMORY_BYTES,
            "NanoCpus": crapi.APP_NANO_CPUS,
            "PidsLimit": crapi.APP_PIDS_LIMIT,
            "PortBindings": {},
            "Binds": None,
            "NetworkMode": "isolated",
            "Privileged": False,
        },
        "Config": {"User": crapi.APP_USER},
        "NetworkSettings": {"Ports": {"5432/tcp": None}, "Networks": {"isolated": {}}},
        "Mounts": [],
    }
    result = crapi._container_isolation(
        inspect,
        expected_user=crapi.APP_USER,
        expected_tmpfs=crapi.APP_TMPFS,
        expected_memory=crapi.APP_MEMORY_BYTES,
        expected_nano_cpus=crapi.APP_NANO_CPUS,
        expected_pids_limit=crapi.APP_PIDS_LIMIT,
        expected_network="isolated",
    )
    assert result["passed"] is True

    inspect["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostPort": "8080"}]}
    assert (
        crapi._container_isolation(
            inspect,
            expected_user=crapi.APP_USER,
            expected_tmpfs=crapi.APP_TMPFS,
            expected_memory=crapi.APP_MEMORY_BYTES,
            expected_nano_cpus=crapi.APP_NANO_CPUS,
            expected_pids_limit=crapi.APP_PIDS_LIMIT,
            expected_network="isolated",
        )["passed"]
        is False
    )


def test_postgres_creation_cleans_up_when_isolation_rejects(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cleaned: list[str] = []
    monkeypatch.setattr(
        crapi,
        "_docker",
        lambda *args, **kwargs: crapi.CommandResult(0, b"", b"", False, False),
    )
    monkeypatch.setattr(crapi, "_container_id", lambda *args, **kwargs: "a" * 12)
    monkeypatch.setattr(crapi, "_inspect_container", lambda *args, **kwargs: {})
    monkeypatch.setattr(crapi, "_container_isolation", lambda *args, **kwargs: {"passed": False})
    monkeypatch.setattr(
        crapi,
        "_cleanup_container",
        lambda container_id, *, work_root, label: cleaned.append(container_id) or _cleanup(),
    )

    with pytest.raises(crapi.RuntimeContractError, match="postgres_isolation_invalid"):
        crapi._create_postgres_container(network="isolated", work_root=tmp_path)

    assert cleaned == ["a" * 12]


def test_live_run_passes_ephemeral_database_secret_without_receipting_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database_secret = "database-secret-must-not-appear-in-receipt"
    expected_result = _driver_result(mode="positive", expected_status=200)
    app_secret_seen: list[str] = []

    monkeypatch.setattr(crapi, "_create_network", lambda *, work_root: ("network", {"internal": True, "driver": True, "raw_returned": False}))
    monkeypatch.setattr(
        crapi,
        "_create_postgres_container",
        lambda *, network, work_root: ("postgres", _isolation(), database_secret),
    )
    monkeypatch.setattr(crapi, "_wait_for_postgres", lambda *args, **kwargs: {"ready": True, "raw_returned": False})

    def create_app(app_image: object, *, network: str, database_secret: str, work_root: Path) -> tuple[str, dict[str, object]]:
        app_secret_seen.append(database_secret)
        return "application", _isolation()

    monkeypatch.setattr(crapi, "_create_app_container", create_app)
    monkeypatch.setattr(crapi, "_wait_for_application", lambda *args, **kwargs: {"ready": True, "raw_returned": False})
    monkeypatch.setattr(crapi, "_create_driver_container", lambda *args, **kwargs: ("driver", _isolation()))
    monkeypatch.setattr(
        crapi,
        "_docker",
        lambda *args, **kwargs: crapi.CommandResult(0, b"driver", b"", False, False),
    )
    monkeypatch.setattr(crapi, "_parse_driver_result", lambda *args, **kwargs: expected_result)
    monkeypatch.setattr(crapi, "_inspect_container", lambda *args, **kwargs: {"State": {"ExitCode": 0}})
    monkeypatch.setattr(crapi, "_app_logs_sha256", lambda *args, **kwargs: "a" * 64)
    monkeypatch.setattr(crapi, "_cleanup_container", lambda *args, **kwargs: _cleanup())
    monkeypatch.setattr(crapi, "_cleanup_network", lambda *args, **kwargs: _cleanup())

    result = crapi._live_run_bound(
        {"app_image_id": "sha256:" + "1" * 64, "app_image_contract_sha256": "2" * 64},
        {"driver_sha256": "3" * 64},
        {"reference": crapi.POSTGRES_IMAGE_REF, "image_id": "sha256:" + "4" * 64, "raw_returned": False},
        mode="positive",
        expected_status=200,
        work_root=tmp_path,
        timeout=60,
    )

    assert app_secret_seen == [database_secret]
    assert result["cleanup"]["postgres"]["removed"] is True
    assert result["cleanup"]["network"]["removed"] is True
    assert database_secret not in crapi.canonical_json_bytes(result).decode("utf-8")
