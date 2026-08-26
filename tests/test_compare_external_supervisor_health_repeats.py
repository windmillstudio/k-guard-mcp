from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path


COMPARATOR_SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_external_supervisor_health_repeats.py"
COMPARATOR_SPEC = importlib.util.spec_from_file_location("compare_external_supervisor_health_repeats_test", COMPARATOR_SCRIPT)
assert COMPARATOR_SPEC is not None and COMPARATOR_SPEC.loader is not None
comparison = importlib.util.module_from_spec(COMPARATOR_SPEC)
COMPARATOR_SPEC.loader.exec_module(comparison)

HEALTH_SCRIPT = Path(__file__).parents[1] / "scripts" / "check_external_supervisor_health.py"
HEALTH_SPEC = importlib.util.spec_from_file_location("compare_external_supervisor_health_health_test", HEALTH_SCRIPT)
assert HEALTH_SPEC is not None and HEALTH_SPEC.loader is not None
health = importlib.util.module_from_spec(HEALTH_SPEC)
HEALTH_SPEC.loader.exec_module(health)


def _response_for(provider: str) -> str:
    terminal = json.dumps(health.EXPECTED_TERMINAL_DECISION, separators=(",", ":"))
    if provider == "claude":
        return json.dumps({"result": terminal})
    if provider == "grok":
        return json.dumps({"text": terminal})
    return json.dumps({"type": "run_result", "text": terminal})


def _runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
    provider = "claude" if "claude-opus-5" in command else "grok" if "grok-4.6" in command else "glm"
    return subprocess.CompletedProcess(command, 0, stdout=_response_for(provider), stderr="")


def _receipt(generated_at: str) -> dict[str, object]:
    return health.run_health_check(
        {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=_runner,
        generated_at=generated_at,
    )


def _write(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(comparison.canonical_json_bytes(value))


def _legacy_receipt(generated_at: str) -> dict[str, object]:
    receipt = _receipt(generated_at)
    receipt["schema"] = health.PREVIOUS_SCHEMA
    receipt["lanes"] = [
        {
            "provider": lane["provider"],
            "model": lane["model"],
            "invocation_profile": lane["invocation_profile"],
            "status": "HEALTHY",
            "blocked_reason": None,
            "exit_code": 0,
            "terminal_response_valid": True,
            "raw_returned": False,
        }
        for lane in health.PREVIOUS_LANES
    ]
    receipt["measurement_fingerprint_sha256"] = health.health_measurement_fingerprint(receipt)
    return receipt


def test_same_healthy_receipts_are_semantically_equal_despite_generation_time(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    _write(first, _receipt("2026-07-25T00:00:00+00:00"))
    _write(second, _receipt("2026-07-25T00:01:00+00:00"))

    result = comparison.compare_runs(first, second)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["failure_reasons"] == []
    assert result["raw_returned"] is False


def test_unhealthy_lane_is_fail_closed_even_when_receipt_is_canonical(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    unhealthy = _receipt("2026-07-25T00:00:00+00:00")
    unhealthy["all_required_lanes_healthy"] = False
    unhealthy["overall_status"] = "BLOCKED"
    unhealthy["lanes"][0]["status"] = "BLOCKED"
    unhealthy["lanes"][0]["blocked_reason"] = "BLOCKED_PROVIDER"
    unhealthy["lanes"][0]["exit_code"] = None
    unhealthy["lanes"][0]["terminal_response_valid"] = False
    unhealthy["measurement_fingerprint_sha256"] = health.health_measurement_fingerprint(unhealthy)
    _write(first, unhealthy)
    _write(second, _receipt("2026-07-25T00:01:00+00:00"))

    result = comparison.compare_runs(first, second)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False
    assert "first:health_unhealthy" in result["failure_reasons"]
    assert "first:lane_invalid:claude" in result["failure_reasons"]


def test_tampered_fingerprint_is_fail_closed(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    tampered = _receipt("2026-07-25T00:00:00+00:00")
    tampered["measurement_fingerprint_sha256"] = "0" * 64
    _write(first, tampered)
    _write(second, _receipt("2026-07-25T00:01:00+00:00"))

    result = comparison.compare_runs(first, second)

    assert result["status"] == "HOLD"
    assert "first:fingerprint_invalid" in result["failure_reasons"]


def test_legacy_v1_three_lane_pairs_remain_valid_but_cannot_mix_with_v2(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    current = tmp_path / "current.json"
    _write(first, _legacy_receipt("2026-07-25T00:00:00+00:00"))
    _write(second, _legacy_receipt("2026-07-25T00:01:00+00:00"))
    _write(current, _receipt("2026-08-23T00:00:00+00:00"))

    assert comparison.compare_runs(first, second)["status"] == "FIX"
    mixed = comparison.compare_runs(second, current)
    assert mixed["status"] == "HOLD"
    assert "health_semantic_difference" in mixed["failure_reasons"]


def test_write_refuses_repository_or_existing_output(tmp_path: Path) -> None:
    result = {"schema": comparison.SCHEMA, "raw_returned": False}
    output = tmp_path / "comparison.json"
    comparison.write_result(output, result)

    try:
        comparison.write_result(output, result)
    except ValueError as exc:
        assert "new and outside" in str(exc)
    else:
        raise AssertionError("existing output was accepted")
