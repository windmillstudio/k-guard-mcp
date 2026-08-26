from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "check_external_supervisor_health.py"
SPEC = importlib.util.spec_from_file_location("check_external_supervisor_health_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)


def _response_for(provider: str) -> str:
    terminal = json.dumps(health.EXPECTED_TERMINAL_DECISION, separators=(",", ":"))
    if provider == "claude":
        return json.dumps({"result": terminal})
    if provider == "grok":
        return json.dumps({"text": terminal})
    return "\n".join(
        (
            json.dumps({"type": "agent_event", "event": {"type": "content_start", "contentType": "reasoning"}}),
            json.dumps({"type": "run_result", "finishReason": "stop", "text": terminal}),
        )
    )


def _provider_from_command(command: list[str]) -> str:
    if "claude-opus-5" in command:
        return "claude"
    if "grok-4.6" in command:
        return "grok"
    if "cline-pass/glm-5.2" in command:
        return "glm"
    raise AssertionError("unrecognized supervisor command")


def _healthy_runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, 0, stdout=_response_for(_provider_from_command(command)), stderr="")


def test_build_commands_pin_models_and_use_source_free_health_contracts(monkeypatch: pytest.MonkeyPatch) -> None:
    resolved = {
        "claude.exe": "C:/tools/claude.cmd",
        "grok.exe": "C:/tools/grok.exe",
        "cline.exe": "C:/tools/cline.cmd",
    }
    monkeypatch.setattr(health, "resolve_supervisor_executable", lambda value, **_: resolved[value])
    claude = health.build_command("claude", "claude.exe", timeout_seconds=30)
    grok = health.build_command("grok", "grok.exe", timeout_seconds=30)
    glm = health.build_command("glm", "cline.exe", timeout_seconds=30)

    assert claude[0] == "C:/tools/claude.cmd"
    assert "claude-opus-5" in claude
    assert {"--no-session-persistence", "--permission-mode", "plan"} <= set(claude)
    assert "--tools" not in claude
    assert "grok-4.6" in grok
    assert grok[grok.index("--reasoning-effort") + 1] == "xhigh"
    assert grok[0] == "C:/tools/grok.exe"
    assert {"--disable-web-search", "--no-subagents", "--no-memory", "--no-plan"} <= set(grok)
    assert "--tools" in grok and grok[grok.index("--tools") + 1] == ""
    assert "cline-pass/glm-5.2" in glm
    assert glm[0] == "C:/tools/cline.cmd"
    assert glm[glm.index("--auto-approve") + 1] == "false"
    assert "--plan" in glm
    assert "--system" in glm
    glm_system = glm[glm.index("--system") + 1]
    assert json.dumps(health.EXPECTED_TERMINAL_DECISION, separators=(",", ":")) in glm_system
    assert "Do not use tools, make a plan, or explain." in glm_system
    assert "source-free health check" in glm_system


def test_health_receipt_is_availability_only_and_raw_free() -> None:
    receipt = health.run_health_check(
        {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=_healthy_runner,
        generated_at="2026-07-22T00:00:00+00:00",
    )

    assert receipt["schema"] == health.SCHEMA
    assert receipt["all_required_lanes_healthy"] is True
    assert receipt["overall_status"] == "HEALTHY"
    assert receipt["approval"] is False
    assert receipt["review_receipt_eligible"] is False
    assert receipt["raw_returned"] is False
    assert receipt["measurement_fingerprint_sha256"] == health.health_measurement_fingerprint(receipt)
    assert [lane["provider"] for lane in receipt["lanes"]] == ["claude", "grok"]
    assert all(lane["status"] == "HEALTHY" and lane["raw_returned"] is False for lane in receipt["lanes"])
    assert receipt["claim_boundary"]["does_not_approve_field_fix"] is True
    assert receipt["claim_boundary"]["does_not_replace_supervisor_review_receipts"] is True


def test_measurement_fingerprint_ignores_generation_time_only() -> None:
    first = health.run_health_check(
        {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=_healthy_runner,
        generated_at="2026-07-22T00:00:00+00:00",
    )
    second = health.run_health_check(
        {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=_healthy_runner,
        generated_at="2026-07-22T00:01:00+00:00",
    )

    assert first["measurement_fingerprint_sha256"] == second["measurement_fingerprint_sha256"]


def test_cline_parser_ignores_reasoning_and_requires_one_terminal_result() -> None:
    assert health._terminal_decision("glm", _response_for("glm")) == health.EXPECTED_TERMINAL_DECISION
    duplicated = _response_for("glm") + "\n" + json.dumps(
        {"type": "run_result", "text": json.dumps(health.EXPECTED_TERMINAL_DECISION)}
    )
    assert health._terminal_decision("glm", duplicated) is None


def test_current_health_contract_keeps_extra_terminal_json_blocked() -> None:
    extra = dict(health.EXPECTED_TERMINAL_DECISION)
    extra["extra"] = True
    assert health._terminal_decision("grok", json.dumps({"text": json.dumps(extra)})) == extra
    assert health._terminal_decision("grok", json.dumps({"text": "```json\n{}\n```"})) is None

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        provider = _provider_from_command(command)
        stdout = (
            json.dumps({"text": json.dumps(extra)})
            if provider == "grok"
            else _response_for(provider)
        )
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    receipt = health.run_health_check(
        {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=runner,
        generated_at="2026-07-25T00:00:00+00:00",
    )

    grok_lane = next(lane for lane in receipt["lanes"] if lane["provider"] == "grok")
    assert receipt["overall_status"] == "BLOCKED"
    assert grok_lane["status"] == "BLOCKED"
    assert grok_lane["terminal_response_valid"] is True


def test_failed_response_is_blocked_without_raw_provider_text() -> None:
    def malformed_runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 17, stdout="credential unavailable", stderr="")

    receipt = health.run_health_check(
        {"claude": "claude.exe", "grok": "grok.exe", "glm": "cline.exe"},
        timeout_seconds=30,
        runner=malformed_runner,
        generated_at="2026-07-22T00:00:00+00:00",
    )

    assert receipt["all_required_lanes_healthy"] is False
    assert {lane["blocked_reason"] for lane in receipt["lanes"]} == {"BLOCKED_AUTH"}
    assert "credential unavailable" not in json.dumps(receipt)


def test_health_error_classifier_does_not_misread_authority_as_authentication() -> None:
    assert health._blocked_reason("invalid authority evidence", "") == "BLOCKED_PROVIDER"


def test_write_receipt_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "health.json"
    health.write_receipt(output, {"schema": health.SCHEMA, "raw_returned": False})

    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == health.SCHEMA
    with pytest.raises(ValueError, match="refusing to overwrite"):
        health.write_receipt(output, {"schema": health.SCHEMA, "raw_returned": False})
